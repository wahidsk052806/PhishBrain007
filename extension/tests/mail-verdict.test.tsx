import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import MailVerdictCard from "../src/content/MailVerdictCard";
import type { AnalysisResult } from "../src/types/analysis";

function emailResult(overrides: Partial<AnalysisResult> = {}): AnalysisResult {
  return {
    analysis_id: "9c1f4b2a-0000-4000-8000-000000000000",
    url: "billing@secure-paypa1.top",
    domain: "billing@secure-paypa1.top",
    threat_score: 88,
    risk_level: "HIGH_RISK",
    confidence: 0.91,
    indicators: [
      "Sender domain is a character-substituted lookalike of paypal",
      "Link text names paypal.com but the destination is secure-paypa1.top",
      "Message asks for a password or one-time code",
    ],
    layers: {
      url: { risk: 40, indicators: [], evidence: {} },
      domain: { risk: 62, indicators: [], evidence: {} },
      webpage: { risk: 0, indicators: [], evidence: {}, status: "not_applicable" },
      email: {
        risk: 88,
        indicators: [],
        evidence: { link_count: 3 },
      },
    },
    explanation: "Overall assessment: HIGH_RISK.",
    recommended_action: "Do not click links or enter credentials.",
    latency_ms: 812,
    degraded: [],
    ...overrides,
  } as AnalysisResult;
}

describe("MailVerdictCard", () => {
  it("states a clean verdict without shouting, and stays collapsed", () => {
    const html = renderToStaticMarkup(
      <MailVerdictCard result={emailResult({ risk_level: "SAFE", threat_score: 6, indicators: [] })} provider="gmail" />,
    );

    expect(html).toContain("Safe");
    expect(html).toContain("No phishing indicators found in this message");
    expect(html).toContain("Gmail message");
    expect(html).toContain(">6<");
    // A safe message must not dump an empty evidence block at the reader.
    expect(html).not.toContain("Why this message");
    expect(html).toContain("Details");
  });

  it("opens the evidence automatically for a high-risk message", () => {
    const html = renderToStaticMarkup(
      <MailVerdictCard
        result={emailResult()}
        provider="gmail"
        alert={{ delivered: true, status: 200, attempts: 1, error: null, at: 1 }}
        alertConfigured
      />,
    );

    expect(html).toContain("High risk");
    expect(html).toContain("billing@secure-paypa1.top");
    expect(html).toContain("character-substituted lookalike of paypal");
    expect(html).toContain("Links inspected");
    expect(html).toContain("SOC alert delivered");
    expect(html).toContain("HTTP 200");
  });

  it("reports a failed SOC delivery instead of claiming silence is success", () => {
    const html = renderToStaticMarkup(
      <MailVerdictCard
        result={emailResult({ risk_level: "SUSPICIOUS" })}
        provider="outlook"
        alert={{ delivered: false, status: 502, attempts: 2, error: "Bad gateway", at: 1 }}
        alertConfigured
      />,
    );

    expect(html).toContain("Outlook message");
    expect(html).toContain("SOC alert not delivered");
    expect(html).toContain("HTTP 502");
    expect(html).toContain("Bad gateway");
  });

  it("distinguishes 'no webhook configured' from a failed delivery", () => {
    const html = renderToStaticMarkup(
      <MailVerdictCard result={emailResult()} provider="gmail" alert={null} alertConfigured={false} />,
    );

    expect(html).toContain("no webhook configured");
  });
});
