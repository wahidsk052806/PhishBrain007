/** Dashboard-side settings, persisted in localStorage (no backend secrets here). */

export interface DashboardSettings {
  backendUrl: string;
  demoMode: boolean;
  safeThreshold: number;
  suspiciousThreshold: number;
  theme: "dark" | "light";
}

export const DEFAULT_SETTINGS: DashboardSettings = {
  backendUrl: "http://localhost:8000",
  demoMode: true,
  safeThreshold: 30,
  suspiciousThreshold: 70,
  theme: "dark",
};

const KEY = "phishbrain.settings";

export function loadSettings(): DashboardSettings {
  if (typeof window === "undefined") return DEFAULT_SETTINGS;
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return DEFAULT_SETTINGS;
    return { ...DEFAULT_SETTINGS, ...(JSON.parse(raw) as Partial<DashboardSettings>) };
  } catch {
    return DEFAULT_SETTINGS;
  }
}

export function saveSettings(settings: DashboardSettings): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(KEY, JSON.stringify(settings));
  window.dispatchEvent(new CustomEvent("phishbrain:settings"));
}
