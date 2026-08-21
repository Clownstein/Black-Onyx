import React, { createContext, useContext, useEffect, useMemo, useState } from "react";

export type ThemeVersion = "dark" | "light";
export type SidebarStyle = "full" | "mini";
export type AccentSwatch = "violet" | "teal" | "blue" | "indigo" | "emerald" | "amber" | "rose";

const STORAGE_KEY = "blackonyx_theme_v1";
const ACCENT_IDS: AccentSwatch[] = ["violet", "teal", "blue", "indigo", "emerald", "amber", "rose"];

type StoredTheme = {
  version: ThemeVersion;
  accent: AccentSwatch;
  sidebar: SidebarStyle;
};

type ThemeContextValue = {
  version: ThemeVersion;
  accent: AccentSwatch;
  sidebar: SidebarStyle;
  setVersion: (value: ThemeVersion) => void;
  setAccent: (value: AccentSwatch) => void;
  setSidebar: (value: SidebarStyle) => void;
  toggleSidebar: () => void;
};

const defaults: StoredTheme = { version: "dark", accent: "violet", sidebar: "full" };

function loadStored(): StoredTheme {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return defaults;
    const parsed = JSON.parse(raw) as Partial<StoredTheme>;
    return {
      version: parsed.version === "light" ? "light" : "dark",
      accent: ACCENT_IDS.includes(parsed.accent as AccentSwatch)
        ? (parsed.accent as AccentSwatch)
        : "violet",
      sidebar: parsed.sidebar === "mini" ? "mini" : "full",
    };
  } catch {
    return defaults;
  }
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<StoredTheme>(() => loadStored());

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    document.documentElement.dataset.theme = state.version;
    document.documentElement.dataset.accent = state.accent;
    document.documentElement.dataset.sidebar = state.sidebar;
    document.body.dataset.themeVersion = state.version;
    document.body.dataset.accent = state.accent;
    document.body.dataset.sidebarStyle = state.sidebar;
  }, [state]);

  const value = useMemo<ThemeContextValue>(() => ({
    version: state.version,
    accent: state.accent,
    sidebar: state.sidebar,
    setVersion: (version) => setState((prev) => ({ ...prev, version })),
    setAccent: (accent) => setState((prev) => ({ ...prev, accent })),
    setSidebar: (sidebar) => setState((prev) => ({ ...prev, sidebar })),
    toggleSidebar: () => setState((prev) => ({ ...prev, sidebar: prev.sidebar === "mini" ? "full" : "mini" })),
  }), [state]);

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme requires ThemeProvider");
  return ctx;
}

export const ACCENT_OPTIONS: { id: AccentSwatch; label: string; color: string }[] = [
  { id: "violet", label: "Onyx violet", color: "#6C3CF2" },
  { id: "teal", label: "Teal", color: "#4bd4bd" },
  { id: "blue", label: "Blue", color: "#0d99ff" },
  { id: "indigo", label: "Indigo", color: "#6366f1" },
  { id: "emerald", label: "Emerald", color: "#10b981" },
  { id: "amber", label: "Amber", color: "#f59e0b" },
  { id: "rose", label: "Rose", color: "#f43f5e" },
];
