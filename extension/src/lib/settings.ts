import { storage } from "./browser";
import {
  DEFAULT_BACKEND_URL,
  DEFAULT_DASHBOARD_URL,
  DEFAULT_CLOUD_SCAN_URL,
  DEFAULT_CLOUD_EMAIL_URL,
} from "../services/api";

export type BannerMode = "banner" | "silent";

export interface Settings {
  backendUrl: string;
  dashboardUrl: string;
  cloudScanUrl: string;
  cloudEmailScanUrl: string;
  useCloudFallback: boolean;
  autoScan: boolean;
  bannerMode: BannerMode;
  riskThreshold: number; // 0-100, warn at/above this threat score
  allowlist: string[]; // domains, persisted
  /** Opt-in: POST every high-risk detection to this webhook (SOC / email relay). */
  alertWebhookUrl: string;
  alertsEnabled: boolean;
  /** Opt-in: capture the visible tab and send it for visual brand-clone analysis. */
  captureScreenshots: boolean;
}

export const DEFAULT_SETTINGS: Settings = {
  backendUrl: DEFAULT_BACKEND_URL,
  dashboardUrl: DEFAULT_DASHBOARD_URL,
  cloudScanUrl: DEFAULT_CLOUD_SCAN_URL,
  cloudEmailScanUrl: DEFAULT_CLOUD_EMAIL_URL,
  useCloudFallback: true,
  autoScan: true,
  bannerMode: "banner",
  riskThreshold: 50,
  allowlist: [],
  alertWebhookUrl: "",
  alertsEnabled: false,
  captureScreenshots: false,
};

export async function getSettings(): Promise<Settings> {
  const stored = await storage.get<Partial<Settings>>([
    "backendUrl",
    "dashboardUrl",
    "cloudScanUrl",
    "cloudEmailScanUrl",
    "useCloudFallback",
    "autoScan",
    "bannerMode",
    "riskThreshold",
    "allowlist",
    "alertWebhookUrl",
    "alertsEnabled",
    "captureScreenshots",
  ]);
  return { ...DEFAULT_SETTINGS, ...stored };
}

export async function setSettings(partial: Partial<Settings>): Promise<void> {
  await storage.set(partial);
}

export function isDomainAllowlisted(hostname: string, allowlist: string[]): boolean {
  const host = hostname.toLowerCase();
  return allowlist.some((entry) => {
    const normalized = entry.trim().toLowerCase();
    if (!normalized) return false;
    return host === normalized || host.endsWith(`.${normalized}`);
  });
}
