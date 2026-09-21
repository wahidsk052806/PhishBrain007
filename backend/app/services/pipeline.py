"""Analysis pipeline orchestration.

Wires together the deterministic analyzers, the ML prefilter, the local LLM
assessment, the scoring engine, SOC event generation and persistence/cache.
Designed to never raise: any failing/slow layer is recorded in `degraded`
and the pipeline still returns a best-effort AnalysisResult.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.analyzers.domain.intelligence import analyze_domain
from app.analyzers.email.analyzer import analyze_email
from app.analyzers.url.features import analyze_url
from app.analyzers.webpage.analyzer import analyze_webpage, build_llm_page_digest, fetch_page
from app.analyzers.webpage.visual import analyze_visual
from app.cache.store import get_cache
from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.security import SSRFBlockedError, sanitize_html_to_text
from app.db.repository import save_analysis
from app.llm.ollama_client import get_llm_assessment
from app.ml.prefilter import get_prefilter
from app.schemas.analysis import AnalysisResult, LayerEvidence, PrefilterEvidence, RiskLevel
from app.scoring.engine import score_analysis
from app.soc.events import build_soc_event

logger = get_logger(__name__)


def _cache_key(kind: str, payload: dict | None = None, target: str = "") -> str:
    """Stable cache key covering the *whole* request, not just the target.

    `fetch_page`, `dom_summary` and the email fields each change what the
    pipeline actually does, so keying on the target alone let a cached
    url+domain-only result answer a later request that asked for a page fetch —
    the scan then came back with no webpage evidence and no visual comparison,
    with nothing in `degraded` to explain it. The digest is sha256 rather than
    `hash()`, which is salted per process and so does not survive a restart.
    """
    material = json.dumps(payload if payload is not None else {"target": target},
                          sort_keys=True, default=str)
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]
    return f"phishbrain:analysis:{kind}:{digest}"


async def _run_with_timeout(coro, timeout: float, layer_name: str, degraded: list[str]):
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        degraded.append(f"{layer_name}.timeout")
        return None
    except SSRFBlockedError as exc:
        degraded.append(f"{layer_name}.blocked")
        logger.info("Layer blocked by SSRF guard", extra={"extra_fields": {"layer": layer_name, "error": str(exc)}})
        return None
    except Exception as exc:  # noqa: BLE001
        degraded.append(f"{layer_name}.error")
        logger.warning("Layer failed", extra={"extra_fields": {"layer": layer_name, "error": str(exc)}})
        return None


def _prefilter_features(layers: dict[str, LayerEvidence], url: str | None = None) -> dict:
    url_details = layers.get("url").details if layers.get("url") else {}
    return {
        # Raw URL so a trained model can compute the lexical features it was
        # trained on (see app.ml.prefilter).
        "url_risk": layers["url"].risk_score if layers.get("url") else 0.0,
        "domain_risk": layers["domain"].risk_score if layers.get("domain") else 0.0,
        "email_risk": layers["email"].risk_score if layers.get("email") else 0.0,
        "webpage_risk": layers["webpage"].risk_score if layers.get("webpage") else 0.0,
        "is_ip_host": url_details.get("is_ip_host", False),
        "is_https": url_details.get("is_https", True),
        "suspicious_tld": url_details.get("suspicious_tld", False),
        "is_punycode": url_details.get("is_punycode", False),
        "homograph_suspected": url_details.get("homograph_suspected", False),
        "url": url,
    }


async def _attach_visual_evidence(
    url: str,
    layer: LayerEvidence,
    timeout: float,
    degraded: list[str],
    screenshot_base64: str | None = None,
) -> None:
    """Best-effort screenshot / perceptual-hash brand-clone check.

    The outcome is attached to the webpage layer's `details` (the dashboard
    reads `visual_similarity_score` / `possible_brand` / `visual_indicators`
    from there). This never raises: Playwright may not be installed, the
    screenshot may fail, or the page may block capture — in which case the
    layer records why visual evidence is absent rather than guessing.
    """
    favicon_url = None
    if isinstance(layer.details.get("favicon"), str):
        favicon_url = layer.details["favicon"]

    try:
        # A caller-supplied screenshot (the browser extension captures the tab)
        # is used when present; otherwise the layer drives Playwright itself.
        visual = await asyncio.wait_for(
            analyze_visual(url, screenshot_base64=screenshot_base64, favicon_url=favicon_url),
            timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001
        degraded.append("visual.error")
        layer.details["visual_indicators"] = [f"Visual comparison failed: {exc}"]
        return

    if not isinstance(visual, dict):
        layer.details["visual_indicators"] = ["Visual comparison returned no result."]
        return

    if visual.get("status") != "ok":
        reason = visual.get("reason")
        layer.details["visual_indicators"] = [
            reason or "Visual comparison unavailable (screenshot could not be captured)."
        ]
        return

    distance = visual.get("hash_distance")
    similarity = None
    if isinstance(distance, (int, float)):
        similarity = round(max(0.0, 1.0 - float(distance) / 64.0), 3)
    layer.details["visual_similarity_score"] = similarity
    layer.details["possible_brand"] = visual.get("closest_brand")

    icon = visual.get("icon") if isinstance(visual.get("icon"), dict) else {}
    notes: list[str] = []

    if icon.get("matched"):
        layer.details["brand_icon_match"] = {
            "brand": icon.get("closest_brand"),
            "hash_distance": icon.get("hash_distance"),
            "runner_up_brand": icon.get("runner_up_brand"),
            "runner_up_distance": icon.get("runner_up_distance"),
        }
        notes.append(
            f"Page serves the {icon.get('closest_brand')} brand icon "
            f"(hash distance {icon.get('hash_distance')}; distinct brands are 20+ bits apart)."
        )
    elif icon.get("status") == "ok":
        notes.append(
            "Page icon does not match any known brand "
            f"(closest {icon.get('closest_brand') or 'unknown'} at {icon.get('hash_distance')} bits)."
        )
    elif favicon_url:
        notes.append(f"Page icon could not be compared: {icon.get('reason')}")

    if visual.get("ambiguous"):
        notes.append(
            "Screenshot comparison was inconclusive: the closest brands "
            f"(distance {visual.get('hash_distance')} vs {visual.get('runner_up_distance')}) "
            "are too close together to attribute a brand."
        )
    elif isinstance(distance, (int, float)):
        notes.append(
            "Screenshot perceptual-hash comparison against the local reference set "
            f"({visual.get('reference_count', 0)} reference images; hash distance {distance}; "
            "a distance <=10 counts as a match)."
        )

    if visual.get("screenshot_reason"):
        notes.append(str(visual["screenshot_reason"]))

    layer.details["visual_indicators"] = notes or ["Visual comparison produced no usable evidence."]


async def run_analysis(
    input_type: str,
    target: str,
    *,
    url: str | None = None,
    email_fields: dict | None = None,
    html: str | None = None,
    dom_summary: str | None = None,
    fetch_page_flag: bool = False,
    screenshot_base64: str | None = None,
    raw_input: dict | None = None,
    skip_llm: bool = False,
) -> AnalysisResult:
    """Run the full multi-layer phishing analysis pipeline for a URL, email,
    or webpage input and persist/cache the result."""
    settings = get_settings()
    start = time.monotonic()
    marks: dict[str, float] = {}

    def mark(name: str, since: float) -> float:
        """Record a phase duration (ms) and return a fresh start mark."""
        now = time.monotonic()
        marks[name] = round((now - since) * 1000, 1)
        return now

    degraded: list[str] = []
    layers: dict[str, LayerEvidence] = {}

    cache = get_cache()
    cache_key = _cache_key(input_type, raw_input, target)
    cached = cache.get_json(cache_key)
    if cached:
        try:
            return AnalysisResult.model_validate(cached)
        except Exception:  # noqa: BLE001
            pass

    overall_deadline = settings.ANALYSIS_TIMEOUT_SECONDS
    per_layer_timeout = max(2.0, overall_deadline / 2)

    hostname = urlparse(url).hostname if url else None
    phase = start

    if url:
        try:
            layers["url"] = analyze_url(url)
        except Exception as exc:  # noqa: BLE001
            degraded.append("url.error")
            logger.warning("URL layer failed", extra={"extra_fields": {"error": str(exc)}})
    phase = mark("url_ms", phase)

    # Fetch the page exactly once. It is needed by two consumers — the webpage
    # layer and the LLM's view of the page — and the fetch used to happen
    # *inside* the webpage layer, so a live URL scan handed the LLM no page
    # content at all and it assessed the URL string by itself. Sharing one fetch
    # also avoids paying for the page twice.
    prefetch_attempted = bool(url and html is None and fetch_page_flag and dom_summary is None)
    prefetched_html = html
    if prefetch_attempted:
        prefetched = await _run_with_timeout(
            fetch_page(url, timeout=per_layer_timeout, max_bytes=settings.MAX_FETCH_BYTES),
            per_layer_timeout,
            "webpage.fetch",
            degraded,
        )
        fetched_html, fetch_degraded = prefetched if prefetched else (None, [])
        prefetched_html = fetched_html
        degraded.extend(fetch_degraded)
    phase = mark("fetch_ms", phase)

    if email_fields:
        try:
            layers["email"] = analyze_email(
                sender=email_fields.get("sender", ""),
                reply_to=email_fields.get("reply_to"),
                display_name=email_fields.get("display_name"),
                subject=email_fields.get("subject", ""),
                body=email_fields.get("body", ""),
                links=email_fields.get("links") or [],
                raw_headers=email_fields.get("raw_headers"),
                has_attachments=email_fields.get("has_attachments", False),
            )
        except Exception as exc:  # noqa: BLE001
            degraded.append("email.error")
            logger.warning("Email layer failed", extra={"extra_fields": {"error": str(exc)}})

    # Domain lookups and webpage analysis are independent, so overlapping them
    # takes the shorter of the two off the critical path entirely.
    concurrent_layers = []
    if hostname:
        concurrent_layers.append(
            _run_with_timeout(
                analyze_domain(hostname, timeout=per_layer_timeout), per_layer_timeout, "domain", degraded
            )
        )
    if url and (prefetched_html is not None or dom_summary is not None or prefetch_attempted):
        concurrent_layers.append(
            _run_with_timeout(
                analyze_webpage(
                    url,
                    html_content=prefetched_html,
                    dom_summary=dom_summary,
                    # The fetch already happened above (or was deliberately not
                    # requested), so the layer must not fetch the page again.
                    fetch_page_flag=False,
                    timeout=per_layer_timeout,
                ),
                per_layer_timeout,
                "webpage",
                degraded,
            )
        )

    gathered_layers = await asyncio.gather(*concurrent_layers) if concurrent_layers else []
    phase = mark("layers_ms", phase)
    for evidence in gathered_layers:
        if evidence is None:
            continue
        layers[evidence.layer] = evidence
        if evidence.layer == "webpage" and evidence.unavailable:
            degraded.append("webpage.unavailable")

    layer_list = list(layers.values())
    phase = mark("collect_ms", phase)

    prefilter = get_prefilter()
    prefilter_result = prefilter.score(_prefilter_features(layers, url))
    if not prefilter_result.get("model_trained"):
        degraded.append("ml.deterministic_fallback")

    top_indicators: list[str] = []
    for layer in layer_list:
        top_indicators.extend(layer.indicators)

    deterministic_evidence = {
        "prefilter_score": prefilter_result["score"],
        "prefilter_method": prefilter_result["method"],
        "top_indicators": top_indicators,
        "layers": {l.layer: l.risk_score for l in layer_list},
    }

    email_summary = None
    if email_fields:
        email_summary = sanitize_html_to_text(
            f"Subject: {email_fields.get('subject', '')}\n{email_fields.get('body', '')}"
        )
    webpage_summary = None
    if prefetched_html:
        # A compact, security-relevant digest rather than raw prose: it is a
        # better signal and prefill time is what the scan actually waits on.
        webpage_summary = build_llm_page_digest(
            prefetched_html, url or target, max_chars=settings.LLM_WEBPAGE_SUMMARY_CHARS
        )
    elif dom_summary:
        webpage_summary = dom_summary[: settings.LLM_WEBPAGE_SUMMARY_CHARS]

    llm_assessment = None

    async def _run_llm_layer() -> None:
        nonlocal llm_assessment
        try:
            llm_assessment, llm_degraded = await asyncio.wait_for(
                get_llm_assessment(url, email_summary, webpage_summary, deterministic_evidence),
                timeout=overall_deadline,
            )
            if llm_degraded:
                degraded.append("llm.deterministic_fallback")
        except asyncio.TimeoutError:
            degraded.append("llm.timeout")
        except Exception as exc:  # noqa: BLE001
            degraded.append("llm.error")
            logger.warning("LLM layer failed", extra={"extra_fields": {"error": str(exc)}})

    # The screenshot capture (Playwright launch + render) and the LLM verdict
    # are independent of one another; running them together instead of in
    # sequence is worth roughly the whole screenshot time per scan.
    async def _timed(name: str, coro) -> None:
        started = time.monotonic()
        try:
            await coro
        finally:
            marks[name] = round((time.monotonic() - started) * 1000, 1)

    concurrent_tail = []
    if url and "webpage" in layers:
        concurrent_tail.append(
            _timed(
                "visual_ms",
                _attach_visual_evidence(
                    url, layers["webpage"], per_layer_timeout, degraded, screenshot_base64
                ),
            )
        )
    if not skip_llm:
        concurrent_tail.append(_timed("llm_ms", _run_llm_layer()))
    if concurrent_tail:
        # Deliberately sequential. Both the screenshot (Chromium render) and the
        # verdict (llama.cpp inference) are CPU-bound, and running them together
        # on a small CI/desktop box starves both: measured in-server at 4 cores,
        # concurrent gave 47.8s LLM + 52.7s visual for a 53.9s phase, against
        # ~18s + ~8s when each had the machine to itself. Overlapping them
        # saved nothing and cost ~30s.
        for step in concurrent_tail:
            await step
    phase = mark("llm_visual_ms", phase)

    scoring = score_analysis(
        layer_list,
        llm_assessment,
        degraded,
        prefilter_score=prefilter_result["score"],
        prefilter_model_trained=bool(prefilter_result.get("model_trained")),
    )

    if prefilter_result.get("model_trained"):
        prefilter_note = (
            f"CatBoost prefilter contributed {scoring['prefilter_weight']:.0%} of the base score."
            if scoring["prefilter_blended"]
            else "Trained CatBoost prefilter available but not blended for this input."
        )
    else:
        prefilter_note = (
            "No trained CatBoost model on disk; the deterministic feature-weighted "
            "fallback was used and deliberately excluded from the score."
        )
    prefilter_evidence = PrefilterEvidence(
        model_trained=bool(prefilter_result.get("model_trained")),
        score=(
            round(float(prefilter_result["score"]), 2)
            if prefilter_result.get("model_trained") and prefilter_result.get("score") is not None
            else None
        ),
        method=str(prefilter_result.get("method", "")),
        weight=scoring["prefilter_weight"],
        blended=bool(scoring["prefilter_blended"]),
        note=prefilter_note,
        layer_score=scoring["layer_score"],
    )

    analysis_id = str(uuid.uuid4())
    soc_event = build_soc_event(
        analysis_id=analysis_id,
        target=target,
        threat_score=scoring["threat_score"],
        risk_level=scoring["risk_level"],
        indicators=scoring["indicators"],
        degraded=degraded,
        prefilter=prefilter_evidence,
    )

    marks["score_ms"] = round((time.monotonic() - phase) * 1000, 1)
    latency_ms = (time.monotonic() - start) * 1000
    marks["total_ms"] = round(latency_ms, 1)

    result = AnalysisResult(
        analysis_id=analysis_id,
        created_at=datetime.now(timezone.utc),
        input_type=input_type,
        target=target,
        threat_score=scoring["threat_score"],
        risk_level=scoring["risk_level"],
        confidence=scoring["confidence"],
        indicators=scoring["indicators"],
        layer_evidence=layer_list,
        prefilter=prefilter_evidence,
        llm_assessment=llm_assessment,
        explanation=scoring["explanation"],
        recommended_action=scoring["recommended_action"],
        soc_event=soc_event,
        latency_ms=round(latency_ms, 2),
        timings=marks,
        degraded=degraded,
        demo=False,
    )

    save_analysis(result, raw_input=raw_input)
    cache.set_json(cache_key, result.model_dump(mode="json"))

    return result
