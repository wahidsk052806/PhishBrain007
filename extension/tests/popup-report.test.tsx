import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import PopupReport from "../src/popup/PopupReport";
import type { AnalysisResult } from "../src/types/analysis";

function sample(overrides: Partial<AnalysisResult> = {}): AnalysisResult {
  return {
    analysis_id: "abc-123",
    url: "https://paypa1-security.top/login",
    domain: "paypa1-security.top",
    threat_score: 82,
    risk_level: "HIGH_RISK",
    confidence: 0.9,
    indicators: ["Character-substituted brand domain", "Password field on a mismatched brand"],
    layers: {
      url: {
        risk: 64,
        indicators: ["Hostname contains 3 hyphens"],
        evidence: { hostname: "paypa1-security.top", hyphen_count: 3 },
      },
      domain: {
        risk: 71,
        indicators: ["Domain was registered 3 days ago"],
        evidence: { domain_age_days: 3 },
      },
      webpage: {
        risk: 58,
        indicators: ["Page presents the brand paypal but is not served from that domain"],
        evidence: { has_password_field: true },
      },
      email: {
        risk: 0,
        indicators: [],
        evidence: {},
        unavailable: true,
        notes: "No email context supplied",
      },
    },
    prefilter: {
      model_trained: true,
      score: 88,
      method: "catboost",
      weight: 0.15,
      blended: true,
      note: "Blended into the final score.",
      gate_tier: "triage",
      gate_passed: true,
      decision_threshold: 0.5,
      score_above_threshold: true,
    },
    llm_assessment: {
      status: "ok",
      model: "llama3.2",
      classification: "phishing",
      confidence: 0.86,
      reasoning_summary: "The page imitates PayPal and asks for credentials.",
      key_indicators: ["Brand impersonation"],
    },
    visual: {
      status: "ok",
      visual_similarity_score: 0.93,
      possible_brand: "paypal",
      screenshot_thumbnail: "data:image/jpeg;base64,ZmFrZS1zY3JlZW5zaG90",
      reference_thumbnail: "data:image/png;base64,cmVmZXJlbmNl",
    },
    explanation: "Risk assessment:\n\n1. Brand impersonation detected",
    recommended_action: "Do not enter credentials on this page.",
    latency_ms: 4200,
    degraded: ["Screenshot capture unavailable"],
    ...overrides,
  };
}

describe("PopupReport", () => {
  const html = renderToStaticMarkup(<PopupReport result={sample()} />);

  it("shows the verdict, score and provenance metrics", () => {
    expect(html).toContain("High Risk");
    expect(html).toContain("82");
    expect(html).toContain("90%");
    expect(html).toContain("4200 ms");
    expect(html).toContain("abc-123");
  });

  it("explains why: indicators and the full assessment text", () => {
    expect(html).toContain("Why this verdict");
    expect(html).toContain("Character-substituted brand domain");
    expect(html).toContain("Full assessment text");
  });

  it("breaks down every pipeline layer", () => {
    expect(html).toContain("What PhishBrain checked");
    expect(html).toContain("URL structure");
    expect(html).toContain("Domain &amp; DNS");
    expect(html).toContain("Page content");
    expect(html).toContain("Email context");
    expect(html).toContain("Not applicable to this target");
  });

  it("surfaces the ML pre-filter, LLM and visual signal cards", () => {
    expect(html).toContain("ML pre-filter (CatBoost)");
    expect(html).toContain("Trained CatBoost consulted");
    expect(html).toContain("15%");
    expect(html).toContain("triage");
    expect(html).toContain("Local LLM assessment");
    expect(html).toContain("llama3.2");
    expect(html).toContain("Visual / brand-clone analysis");
    expect(html).toContain("paypal");
  });

  it("shows the recommended action and degraded layers", () => {
    expect(html).toContain("Recommended action");
    expect(html).toContain("Do not enter credentials on this page.");
    expect(html).toContain("Degraded / unavailable layers");
  });

  it("shows the captured screenshot when a thumbnail is present", () => {
    expect(html).toContain("<img");
    expect(html).toContain("data:image/jpeg;base64,ZmFrZS1zY3JlZW5zaG90");
  });

  it("shows the captured page beside the matched brand reference", () => {
    expect(html).toContain("data:image/png;base64,cmVmZXJlbmNl");
    expect(html).toContain("This page");
    expect(html).toContain("Reference: paypal");
  });

  it("mounts the structural comparison when both images are present", () => {
    // Server-rendering does not run the effect, so this asserts the component
    // is wired in and reaches its initial state rather than a final score.
    expect(html).toContain("Comparing page structure");

    const noReference = renderToStaticMarkup(
      <PopupReport
        result={sample({
          visual: {
            status: "ok",
            possible_brand: null,
            screenshot_thumbnail: "data:image/jpeg;base64,ZmFrZQ==",
          },
        })}
      />,
    );
    expect(noReference).not.toContain("Comparing page structure");
  });

  it("omits the image when no thumbnail was captured", () => {
    const noShot = renderToStaticMarkup(
      <PopupReport result={sample({ visual: { status: "unavailable" } })} />,
    );
    expect(noShot).not.toContain("<img");
  });

  it("labels a provisional result so a quick verdict is not read as final", () => {
    const quick = renderToStaticMarkup(<PopupReport result={sample({ provisional: true })} />);
    expect(quick).toContain("Quick verdict");
    expect(quick).toContain("still running");

    // A finished result carries no such label.
    expect(html).not.toContain("Quick verdict");
  });

  it("does not report the model and screenshot layers as missing while they are pending", () => {
    // The quick pass deliberately runs no model and captures no page, so its
    // result carries neither field — which is exactly what the popup receives
    // in the seconds before the full pass lands.
    const quick = renderToStaticMarkup(
      <PopupReport result={sample({ provisional: true, llm_assessment: null, visual: null })} />,
    );
    expect(quick).not.toContain("No LLM reasoning layer was applied");
    expect(quick).not.toContain("Unavailable for this result");
    expect(quick).toContain("Still running");
  });

  it("flags demo results so a synthetic verdict is never mistaken for live", () => {
    const demo = renderToStaticMarkup(<PopupReport result={sample({ demo: true })} />);
    expect(demo).toContain("Demo data");
    expect(demo).toContain("No live request was made");
  });

  it("says the prefilter was not consulted when it is absent", () => {
    const noPrefilter = renderToStaticMarkup(<PopupReport result={sample({ prefilter: null })} />);
    expect(noPrefilter).toContain("Not consulted for this result");
  });
});
