import { describe, expect, it } from "vitest";
import detectionCss from "../detection/styles.css?raw";
import securityLabSource from "../workflows_security_lab.tsx?raw";
import adminSource from "../workflows_admin.tsx?raw";
import themeSource from "./ThemeContext.tsx?raw";

// The detection stylesheet only arrives as text because vite.config.ts sets
// `test.css: true`; under vitest's default CSS stub it read as "" and the
// negative assertions below were green whatever the file contained. The first
// test guards that, so the suite fails loudly instead of silently passing.

describe("non-gallery theme contract", () => {
  it("actually loaded the sources it asserts about", () => {
    for (const source of [detectionCss, securityLabSource, adminSource, themeSource]) {
      expect(source.length).toBeGreaterThan(200);
    }
  });

  it("keeps the dark violet defaults and the existing storage contract", () => {
    expect(themeSource).toContain('const STORAGE_KEY = "blackonyx_theme_v1"');
    expect(themeSource).toContain('const defaults: StoredTheme = { version: "dark", accent: "violet", sidebar: "full" }');
  });

  it("scopes detection styles to the detection console", () => {
    const forbiddenGlobals = [":root", "html", "body", ".app-shell", ".topbar", ".panel", ".badge", ".btn"];

    for (const selector of forbiddenGlobals) {
      expect(detectionCss).not.toMatch(new RegExp(`^\\s*${selector.replace(".", "\\.")}\\b`, "m"));
    }

    const selectorLines = detectionCss
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("/*") && !line.startsWith("*") && !line.startsWith("@") && line.endsWith("{"));

    expect(selectorLines.every((line) =>
      line.startsWith(".detection-console") ||
      line === "from {" ||
      line === "to {" ||
      /^\d+% \{$/.test(line)
    )).toBe(true);
  });

  it("keeps Security Lab on shared CSS instead of inline presentation colors", () => {
    expect(securityLabSource).not.toContain("style={{");
    expect(securityLabSource).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(securityLabSource).not.toMatch(/rgba?\(/i);
  });

  it("uses the scoped detection wrapper for the embedded admin module", () => {
    expect(adminSource).toMatch(/className="detection-console"[\s\S]*<DetectionAdmin\s*\/>/);
  });
});
