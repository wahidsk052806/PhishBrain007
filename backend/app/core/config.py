"""Application configuration loaded from environment variables / .env file."""
from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon", "facebook",
    "netflix", "bankofamerica", "chase", "wellsfargo", "dropbox",
    "linkedin", "instagram", "docusign", "adobe", "outlook", "office365",
]

DEFAULT_SCHEMES = ["http", "https"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_ENV: str = Field(default="development")
    BACKEND_HOST: str = Field(default="0.0.0.0")
    BACKEND_PORT: int = Field(default=8000)

    DATABASE_URL: str = Field(default="sqlite:///./phishbrain.db")
    CACHE_URL: str = Field(default="redis://localhost:6379/0")

    LLM_PROVIDER: str = Field(default="ollama")
    OLLAMA_BASE_URL: str = Field(default="http://localhost:11434")
    # llama3.2:3b is the default because it is the largest model that answers a
    # full scan acceptably on the hardware this project documents (4 CPU / 8 GB).
    # Measured on that box, warm: ~19 s for one verdict. llama3.1:8b needs
    # ~4.9 GB resident and took ~293 s for the same request there, so it is an
    # opt-in for 16 GB machines rather than the out-of-the-box model.
    OLLAMA_MODEL: str = Field(default="llama3.2:3b")

    # Budget for the network-only layers (page fetch, RDAP/DNS/TLS, DOM read).
    ANALYSIS_TIMEOUT_SECONDS: float = Field(default=20.0)
    CACHE_TTL_SECONDS: int = Field(default=3600)

    # How long one LLM verdict may take, measured from the moment the request
    # reaches Ollama. Deliberately separate from ANALYSIS_TIMEOUT_SECONDS: a
    # CPU model needs far longer to answer than a HTTP fetch needs to time out,
    # and sharing the 20 s network budget is what made every scan report
    # "the model did not answer within the scan deadline" (the request was
    # cancelled mid-generation, and each cancel also aborted Ollama's load).
    #
    # Sized from measurement, not taste: on a 4 vCPU / 8 GB Docker host a real
    # scan prompt is ~640 tokens at ~10 tokens/s of prompt processing plus ~80
    # generated tokens at ~4 tokens/s, i.e. ~95-100 s end to end with the model
    # already resident. 90 s cut it off during prompt processing (progress 0.83)
    # and reported the LLM as unavailable; 150 s leaves headroom for a slower
    # box or a longer page summary.
    LLM_TIMEOUT_SECONDS: float = Field(default=150.0, ge=5.0)
    # Loading the weights is a one-off cost paid by the warm-up, not by a scan.
    # 8B on 4 cores measured ~97 s; a cold 3B ~19 s. Generous on purpose — a
    # timeout here cancels the load, so the model would never become resident.
    LLM_WARMUP_TIMEOUT_SECONDS: float = Field(default=300.0, ge=10.0)

    # How much of the fetched page is handed to the LLM. The page text is
    # untrusted and prompt size dominates CPU inference time, so this is a
    # deliberate cap rather than "as much as we downloaded".
    LLM_WEBPAGE_SUMMARY_CHARS: int = Field(default=1200, ge=0)
    # Cap the generated response. The schema needs ~100-120 tokens; letting a
    # small CPU model ramble to 2000 tokens was most of a scan's wall-clock time.
    #
    # Measured on the documented 4-core box with `llama3.2:3b`: a complete,
    # valid SAFE verdict is 82-83 tokens, generated at ~6.8 tokens/s. The old
    # 320 cap was therefore ~47 s of generation in the worst case, on a scan
    # whose whole deterministic half takes ~2 s — which is why the model, not
    # the analysis, dominated the latency. 160 keeps >2x headroom over the
    # measured response and bounds a scan to ~24 s of generation.
    LLM_NUM_PREDICT: int = Field(default=160, ge=16)

    # The model's adjustment is clamped to +/-LLM_ADJUSTMENT_CLAMP (15), so when
    # the deterministic base score is far enough from a risk boundary that no
    # legal adjustment can cross one, the verdict is already fixed: running a 3B
    # model for ~20 s cannot change it. Skipping is recorded as `llm.not_needed`
    # in `degraded` (it is never silent) and exempted from the confidence
    # penalty, because it is a decision, not a failure. Set to false to make the
    # model a second opinion on every scan.
    LLM_SKIP_WHEN_DECISIVE: bool = Field(default=True)
    # Keep the model resident between scans. Without this, Ollama unloads it
    # after its default idle window and the next scan pays a cold start that is
    # many times the inference cost itself.
    LLM_KEEP_ALIVE: str = Field(default="30m")
    # How many scans may use the two CPU-bound layers at the same time, and how
    # long a request waits for a slot before it finishes without that layer.
    #
    # A 4-core host cannot run three Chromium renders and three llama.cpp
    # generations at once: without a ceiling every concurrent scan exceeded its
    # own deadline and reported "the model did not answer", i.e. a working
    # server looked broken. One slot each, a short queue, and a clearly labelled
    # `llm.busy` / `visual.busy` skip is the honest behaviour for a shared box.
    # Raise these only with the CPU to back them.
    MAX_CONCURRENT_LLM_SCANS: int = Field(default=1, ge=1)
    MAX_CONCURRENT_VISUAL_SCANS: int = Field(default=1, ge=1)
    SCAN_QUEUE_TIMEOUT_SECONDS: float = Field(default=20.0, ge=0.0)

    # Load the model into memory at startup instead of during the first scan.
    # Loading costs ~30 s of CPU on a 4-core box, which the first request would
    # otherwise pay for; set to false on a memory-constrained deployment where
    # holding the model resident is not acceptable.
    LLM_WARMUP_ON_STARTUP: bool = Field(default=True)
    # Ollama defaults to a large context; on CPU a 4k window is markedly faster
    # and is ample for a URL plus a capped page summary.
    LLM_NUM_CTX: int = Field(default=4096, ge=512)

    EMAIL_WEIGHT: float = Field(default=0.30)
    URL_WEIGHT: float = Field(default=0.30)
    DOMAIN_WEIGHT: float = Field(default=0.20)
    WEBPAGE_WEIGHT: float = Field(default=0.20)

    # Share of the composite score contributed by a *trained* CatBoost
    # prefilter. Deliberately modest: the prefilter only sees lexical URL
    # features while the layers corroborate each other with page, domain and
    # email evidence, so it should nudge the verdict rather than set it. Kept
    # well under 0.5 so a lone maximal prefilter score cannot drag a clean
    # multi-layer analysis above the SAFE ceiling on its own.
    PREFILTER_WEIGHT: float = Field(default=0.15, ge=0.0, le=0.5)

    SAFE_THRESHOLD: int = Field(default=30)
    SUSPICIOUS_THRESHOLD: int = Field(default=65)

    STORE_RAW_EMAIL: bool = Field(default=False)
    RETENTION_DAYS: int = Field(default=30)

    # Screenshot evidence is the most sensitive thing this backend stores — a
    # picture of the page a user visited — so it is purged on its own, much
    # shorter clock than the analysis record itself. The analysis (score,
    # indicators, evidence) survives under RETENTION_DAYS; only the image is
    # dropped. A value of 0 means "store none at all": every sweep strips the
    # screenshots immediately, which is the right setting for a shared box.
    VISUAL_RETENTION_DAYS: int = Field(default=7, ge=0)
    # How often the background sweep runs. The sweep is cheap (it only looks at
    # records older than the cutoff) and idempotent, so a coarse interval is
    # fine; it also runs once at startup so a restart enforces the policy.
    VISUAL_PURGE_INTERVAL_MINUTES: int = Field(default=360, ge=1)

    BRAND_LIST: str = Field(default=",".join(DEFAULT_BRANDS))
    ALLOWED_SCHEMES: str = Field(default=",".join(DEFAULT_SCHEMES))

    MAX_REQUEST_BYTES: int = Field(default=2_000_000)
    MAX_FETCH_BYTES: int = Field(default=3_000_000)

    # Origins the API answers cross-origin requests from. The dashboard is
    # normally opened on the same machine as the backend, but the point of a
    # self-hosted detector is that it can also be opened from a phone or a second
    # laptop on the same network — and the browser then refuses to let that page
    # call the API unless the private address it was served from is allowed.
    # Loopback, the browser-extension IDs and private (RFC 1918) hosts are
    # therefore permitted by default. A public origin is not: an arbitrary
    # internet page must not be able to use the operator's backend as a free
    # scanning service, and a phishing page must not be able to probe it.
    # Override this to restrict access to named origins.
    CORS_ORIGIN_REGEX: str = Field(
        default=(
            # Both extension schemes: Chromium reports
            # `chrome-extension://<id>` and Firefox reports
            # `moz-extension://<uuid>`. Allowing only the first meant a
            # deployed backend accepted the extension on Chrome and refused it
            # on Firefox, which looked like "the hosted backend is down".
            r"^((?:chrome|moz)-extension://.*"
            r"|https?://localhost(:\d+)?"
            r"|https?://127\.0\.0\.1(:\d+)?"
            r"|https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|[A-Za-z0-9-]+\.local)(?::\d+)?"
            r")$"
        )
    )

    # Sent when fetching a target page or taking its screenshot. The library
    # default ("python-httpx/x.y") is refused outright by a lot of the web —
    # Wikipedia answers 403 with a 126-byte notice, for example — and because
    # the fetch did not check the status code, that notice was parsed as the
    # page: the webpage layer reported "no forms, no credential fields, no
    # external resources" for a page it had never actually read. Keep this in
    # sync with scripts/data/generate_reference_hashes.py so reference captures
    # and probe captures render the same way.
    FETCH_USER_AGENT: str = Field(
        default=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        )
    )
    FETCH_ACCEPT_LANGUAGE: str = Field(default="en-US,en;q=0.9")

    # Whether the visual layer hands the captured screenshot back for display,
    # and in what form. "off" keeps the pixels on the server; "pixels" returns a
    # downscaled JPEG evidence image; "wireframe" returns an edge-only rendering
    # that preserves the layout while dropping colour and legible text, so the
    # dashboard can SHOW what it compared without storing the page itself.
    VISUAL_SCREENSHOT_MODE: str = Field(default="pixels")
    VISUAL_SCREENSHOT_MAX_WIDTH: int = Field(default=480)
    # Set to false to disable the automatic screenshot-evidence sweep entirely
    # (the retention policy then only runs when an operator calls it).
    VISUAL_AUTO_PURGE_ENABLED: bool = Field(default=True)
    # Budget for one rendered-screenshot comparison, including Chromium's cold
    # launch. It is not part of the network-layer deadline: rendering a real page
    # is slower than fetching it, and a 10 s slice (the old half-deadline) cut
    # the capture off on image-heavy sites and reported "visual: unavailable"
    # for a page that would have rendered fine.
    VISUAL_TIMEOUT_SECONDS: float = Field(default=30.0, ge=5.0)

    @field_validator("APP_ENV")
    @classmethod
    def _lower_env(cls, v: str) -> str:
        return v.lower()

    @field_validator("VISUAL_SCREENSHOT_MODE")
    @classmethod
    def _valid_screenshot_mode(cls, v: str) -> str:
        mode = (v or "off").lower()
        # An unrecognised value is a misconfiguration, and the safe reading is
        # "off" — never silently ship page pixels when the intent was wireframe.
        return mode if mode in {"off", "pixels", "wireframe"} else "off"

    @property
    def brands(self) -> List[str]:
        return [b.strip().lower() for b in self.BRAND_LIST.split(",") if b.strip()]

    @property
    def allowed_schemes(self) -> List[str]:
        return [s.strip().lower() for s in self.ALLOWED_SCHEMES.split(",") if s.strip()]

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    @property
    def layer_weights(self) -> dict:
        # The prefilter's share is carved out of the layer weights, so the
        # blend always sums to 1.0: (1 - PREFILTER_WEIGHT) * layers + W * ml.
        layer_total = self.EMAIL_WEIGHT + self.URL_WEIGHT + self.DOMAIN_WEIGHT + self.WEBPAGE_WEIGHT
        layer_total = layer_total or 1.0
        return {
            "email": self.EMAIL_WEIGHT / layer_total,
            "url": self.URL_WEIGHT / layer_total,
            "domain": self.DOMAIN_WEIGHT / layer_total,
            "webpage": self.WEBPAGE_WEIGHT / layer_total,
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()
