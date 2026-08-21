import React from "react";
import { ACCENT_OPTIONS, useTheme } from "./ThemeContext";

export function ThemePanel({ open, onClose }: { open: boolean; onClose: () => void }) {
  const theme = useTheme();
  if (!open) return null;
  return (
    <aside className="theme-panel" aria-label="Theme customizer">
      <div className="section-head">
        <div>
          <span className="section-kicker">Appearance</span>
          <h2>Theme</h2>
        </div>
        <button type="button" className="ghost compact" onClick={onClose} aria-label="Close theme panel">×</button>
      </div>
      <label>
        Mode
        <select value={theme.version} onChange={(e) => theme.setVersion(e.target.value as "dark" | "light")}>
          <option value="dark">Dark</option>
          <option value="light">Light</option>
        </select>
      </label>
      <label>
        Sidebar
        <select value={theme.sidebar} onChange={(e) => theme.setSidebar(e.target.value as "full" | "mini")}>
          <option value="full">Full</option>
          <option value="mini">Mini</option>
        </select>
      </label>
      <div className="accent-swatches" role="list">
        <span className="section-kicker">Accent</span>
        <div className="accent-swatch-row">
          {ACCENT_OPTIONS.map((option) => (
            <button
              key={option.id}
              type="button"
              className={`accent-swatch ${theme.accent === option.id ? "active" : ""}`}
              style={{ background: option.color }}
              title={option.label}
              aria-label={option.label}
              onClick={() => theme.setAccent(option.id)}
            />
          ))}
        </div>
      </div>
    </aside>
  );
}
