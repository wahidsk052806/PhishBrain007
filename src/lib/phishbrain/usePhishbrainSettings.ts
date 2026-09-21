import { useCallback, useEffect, useState } from "react";
import { DEFAULT_SETTINGS, loadSettings, saveSettings, type DashboardSettings } from "./settings";

export function usePhishbrainSettings() {
  const [settings, setSettings] = useState<DashboardSettings>(DEFAULT_SETTINGS);

  useEffect(() => {
    setSettings(loadSettings());
    const sync = () => setSettings(loadSettings());
    window.addEventListener("phishbrain:settings", sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener("phishbrain:settings", sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle("light", settings.theme === "light");
  }, [settings.theme]);

  const update = useCallback((patch: Partial<DashboardSettings>) => {
    const next = { ...loadSettings(), ...patch };
    saveSettings(next);
    setSettings(next);
  }, []);

  return { settings, update };
}
