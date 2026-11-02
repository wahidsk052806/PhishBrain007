import { useCallback, useEffect, useState } from "react";
import { api, BackendUnavailableError } from "./api";
import { loadDemoHistory, seedDemoHistoryIfEmpty } from "./demo";
import type { AnalysisResult } from "./types";
import { useBackendEndpoint } from "./useBackendEndpoint";
import { usePhishbrainSettings } from "./usePhishbrainSettings";

export interface AnalysesState {
  items: AnalysisResult[];
  loading: boolean;
  /** Populated when live backend data could not be loaded. */
  error: string | null;
  source: "backend" | "demo";
  reload: () => void;
}

/**
 * Loads analysis history. When demo mode is on (or the backend is
 * unreachable while demo mode is on) locally-computed DEMO DATA is used.
 * When demo mode is off, backend failures surface as an explicit error —
 * never as fabricated results.
 */
export function useAnalyses(): AnalysesState {
  const { settings } = usePhishbrainSettings();
  // History is read from whichever endpoint answered, so the reader must re-run
  // when that is decided — otherwise a LAN visitor keeps seeing the empty list
  // produced by asking their own `localhost` before the probe finished.
  const { resolution } = useBackendEndpoint();
  const [items, setItems] = useState<AnalysisResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [source, setSource] = useState<"backend" | "demo">("demo");
  const [nonce, setNonce] = useState(0);

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    (async () => {
      try {
        const res = await api.history(200);
        if (cancelled) return;
        setItems(res.items ?? []);
        setSource("backend");
      } catch (err) {
        if (cancelled) return;
        const detail =
          err instanceof BackendUnavailableError ? err.detail : "Unknown error loading history";
        // Local store holds both live-scan results and demo samples.
        const local = loadDemoHistory();
        if (local.length) {
          setItems(local);
          setSource("demo");
          setError(null);
        } else if (settings.demoMode) {
          setItems(seedDemoHistoryIfEmpty());
          setSource("demo");
          setError(null);
        } else {
          setItems([]);
          setSource("backend");
          setError(
            `Backend history unavailable (${detail}). Run a scan from the Analyze page to use the built-in live scanner, or start the FastAPI backend.`,
          );
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    const onLocal = () => setItems((prev) => (source === "demo" ? loadDemoHistory() : prev));
    window.addEventListener("phishbrain:history", onLocal);
    return () => {
      cancelled = true;
      window.removeEventListener("phishbrain:history", onLocal);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings.backendUrl, settings.demoMode, nonce, resolution?.url]);

  return { items, loading, error, source, reload };
}
