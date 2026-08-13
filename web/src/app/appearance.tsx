import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import type { UserPreferences } from "../api/types";

const defaultPreferences: UserPreferences = {
  themeMode: "system",
  accent: "violet",
  density: "comfortable",
  reducedMotion: false,
};

interface AppearanceContextValue {
  preferences: UserPreferences;
  setPreferences: (preferences: UserPreferences) => void;
}

const AppearanceContext = createContext<AppearanceContextValue | null>(null);

function readThemeCache(): UserPreferences {
  try {
    const value = localStorage.getItem("arca.appearance");
    if (!value) return defaultPreferences;
    const parsed = JSON.parse(value) as Partial<UserPreferences>;
    return {
      themeMode: parsed.themeMode === "light" || parsed.themeMode === "dark" ? parsed.themeMode : "system",
      accent: parsed.accent ?? "violet",
      density: parsed.density === "compact" ? "compact" : "comfortable",
      reducedMotion: Boolean(parsed.reducedMotion),
    };
  } catch {
    return defaultPreferences;
  }
}

export function AppearanceProvider({ children }: { children: ReactNode }) {
  const [preferences, setPreferences] = useState<UserPreferences>(readThemeCache);

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = preferences.themeMode;
    root.dataset.accent = preferences.accent;
    root.dataset.density = preferences.density;
    root.dataset.reduceMotion = String(preferences.reducedMotion);
    root.style.colorScheme = preferences.themeMode === "system" ? "light dark" : preferences.themeMode;
    localStorage.setItem("arca.appearance", JSON.stringify(preferences));
  }, [preferences]);

  const value = useMemo(() => ({ preferences, setPreferences }), [preferences]);
  return <AppearanceContext.Provider value={value}>{children}</AppearanceContext.Provider>;
}

export function useAppearance(): AppearanceContextValue {
  const context = useContext(AppearanceContext);
  if (!context) throw new Error("useAppearance must be used inside AppearanceProvider");
  return context;
}

export { defaultPreferences };
