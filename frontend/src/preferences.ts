import type { Shift } from "./api";

const PREFERENCES_KEY = "socforge.soc_preferences";

export type SOCPreferences = {
  defaultTemplate: Shift["template"];
  defaultDurationMinutes: number;
  defaultNoisePerMinute: number;
  autoRefresh: boolean;
  refreshSeconds: 15 | 30 | 60;
};

export const defaultPreferences: SOCPreferences = {
  defaultTemplate: "phishing_macro",
  defaultDurationMinutes: 30,
  defaultNoisePerMinute: 12,
  autoRefresh: false,
  refreshSeconds: 30,
};

export function hasStoredPreferences(): boolean {
  return window.localStorage.getItem(PREFERENCES_KEY) !== null;
}

export function loadPreferences(): SOCPreferences {
  try {
    const raw = window.localStorage.getItem(PREFERENCES_KEY);
    if (!raw) return defaultPreferences;
    const value = JSON.parse(raw) as Partial<SOCPreferences>;
    return {
      defaultTemplate:
        value.defaultTemplate && ["phishing_macro", "brute_force", "ransomware_precursor"].includes(value.defaultTemplate)
          ? value.defaultTemplate
          : defaultPreferences.defaultTemplate,
      defaultDurationMinutes:
        Number.isInteger(value.defaultDurationMinutes) &&
        Number(value.defaultDurationMinutes) >= 5 &&
        Number(value.defaultDurationMinutes) <= 240
          ? Number(value.defaultDurationMinutes)
          : defaultPreferences.defaultDurationMinutes,
      defaultNoisePerMinute:
        Number.isInteger(value.defaultNoisePerMinute) &&
        Number(value.defaultNoisePerMinute) >= 0 &&
        Number(value.defaultNoisePerMinute) <= 100
          ? Number(value.defaultNoisePerMinute)
          : defaultPreferences.defaultNoisePerMinute,
      autoRefresh: value.autoRefresh === true,
      refreshSeconds: [15, 30, 60].includes(Number(value.refreshSeconds))
        ? (Number(value.refreshSeconds) as SOCPreferences["refreshSeconds"])
        : defaultPreferences.refreshSeconds,
    };
  } catch (error) {
    if (!(error instanceof SyntaxError)) throw error;
    window.localStorage.removeItem(PREFERENCES_KEY);
    return defaultPreferences;
  }
}

export function savePreferences(preferences: SOCPreferences): void {
  window.localStorage.setItem(PREFERENCES_KEY, JSON.stringify(preferences));
}
