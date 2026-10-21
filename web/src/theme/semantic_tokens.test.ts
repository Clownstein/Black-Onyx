import { describe, expect, it } from "vitest";
import shellCss from "../styles.css?raw";
import detectionCss from "../detection/styles.css?raw";
import chartsSource from "../components/charts.tsx?raw";
import graphSource from "../graph_view.tsx?raw";

// `?raw` on a stylesheet only returns its text because vite.config.ts sets
// `test.css: true`. With vitest's default CSS stub these all read as "" and
// every negative assertion below passes without inspecting anything.

/** The shell stylesheet is one file, but only part of it is in scope: the
 *  gallery owns its own art direction and the plan explicitly excludes it. */
const GALLERY_START = "/* --- Gallery hub ---";
const THEME_SYSTEM_START = "/* ===== W3CRM theme system";

function splitShell() {
  const galleryAt = shellCss.indexOf(GALLERY_START);
  const themeAt = shellCss.indexOf(THEME_SYSTEM_START);
  expect(galleryAt).toBeGreaterThan(0);
  expect(themeAt).toBeGreaterThan(galleryAt);
  return {
    components: shellCss.slice(0, galleryAt),
    gallery: shellCss.slice(galleryAt, themeAt),
    themeSystem: shellCss.slice(themeAt),
  };
}

/** Pull one `--token: value;` declaration out of a block of CSS. Comments are
 *  stripped first: prose like "independent of --accent: ..." parses as a
 *  declaration whose value runs on until the next semicolon, swallowing the
 *  real token that follows it. */
function tokensIn(block: string): Map<string, string> {
  const out = new Map<string, string>();
  const declarations = block.replace(/\/\*[\s\S]*?\*\//g, " ");
  for (const [, name, value] of declarations.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;}]+)[;}]/g)) {
    if (!out.has(name)) out.set(name, value.trim());
  }
  return out;
}

function blockFor(selector: string): string {
  const at = shellCss.indexOf(selector);
  expect(at, `missing block: ${selector}`).toBeGreaterThan(-1);
  const open = shellCss.indexOf("{", at);
  const close = shellCss.indexOf("\n}", open);
  return shellCss.slice(open, close);
}

const SEMANTIC_TOKENS = [
  "--on-accent",
  "--on-accent-invert",
  "--danger-text",
  "--warning-text",
  "--ok-text",
  "--info-text",
  "--danger-border",
  "--sev-critical",
  "--sev-high",
  "--sev-medium",
  "--sev-low",
  "--sev-ok",
  "--chart-1",
  "--chart-2",
  "--chart-3",
  "--chart-4",
  "--chart-5",
  "--chart-6",
];

/* Relative luminance / contrast per WCAG 2.1, so the light-mode status inks are
   checked against the surfaces they actually land on rather than eyeballed. */
function luminance(hex: string): number {
  const h = hex.replace("#", "");
  const full = h.length === 3 ? h.split("").map((c) => c + c).join("") : h;
  const channels = [0, 2, 4].map((i) => parseInt(full.slice(i, i + 2), 16) / 255);
  const [r, g, b] = channels.map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

describe("semantic colour layer", () => {
  it("actually loaded the sources it asserts about", () => {
    for (const source of [shellCss, detectionCss, chartsSource, graphSource]) {
      expect(source.length).toBeGreaterThan(200);
    }
  });

  it("defines every semantic token in the dark baseline and re-tunes it for light", () => {
    const dark = tokensIn(blockFor(':root, [data-theme="dark"]'));
    const light = tokensIn(blockFor('[data-theme="light"] {'));

    for (const token of SEMANTIC_TOKENS) {
      expect(dark.has(token), `dark baseline is missing ${token}`).toBe(true);
    }
    // --on-accent-invert is deliberately the same ink in both themes: it is the
    // ground colour used on a bright accent fill, which does not flip.
    for (const token of SEMANTIC_TOKENS.filter((t) => t !== "--on-accent-invert")) {
      expect(light.has(token), `light theme never re-tunes ${token}`).toBe(true);
      expect(light.get(token)).not.toBe(dark.get(token));
    }
  });

  it("keeps severity and chart inks independent of the user's accent swatch", () => {
    const dark = tokensIn(blockFor(':root, [data-theme="dark"]'));
    const accentBound = SEMANTIC_TOKENS
      .filter((t) => t.startsWith("--sev-") || t.startsWith("--chart-"))
      .filter((t) => /var\(--accent/.test(dark.get(t) ?? ""));
    // "low" must never inherit the hue the operator has configured as accent,
    // or an accent=rose workspace renders low findings in the critical colour.
    expect(accentBound).toEqual([]);
  });

  it("keeps the five severity steps visually distinct in both themes", () => {
    for (const selector of [':root, [data-theme="dark"]', '[data-theme="light"] {']) {
      const tokens = tokensIn(blockFor(selector));
      const severities = ["--sev-critical", "--sev-high", "--sev-medium", "--sev-low", "--sev-ok"]
        .map((t) => tokens.get(t)!);
      expect(new Set(severities).size).toBe(severities.length);
    }
  });

  it("gives light mode status inks that clear 4.5:1 on white and on the page ground", () => {
    const light = tokensIn(blockFor('[data-theme="light"] {'));
    const surfaces = ["#ffffff", light.get("--bg")!];
    const inks = [
      "--sev-critical", "--sev-high", "--sev-medium", "--sev-low", "--sev-ok",
      "--danger", "--warning", "--ok", "--info",
      "--danger-text", "--warning-text", "--ok-text", "--info-text",
      "--chart-1", "--chart-2", "--chart-3", "--chart-4", "--chart-5", "--chart-6",
    ];
    for (const ink of inks) {
      const value = light.get(ink)!;
      expect(value, `${ink} should be a hex literal in the light block`).toMatch(/^#[0-9a-f]{3,6}$/i);
      for (const surface of surfaces) {
        expect(contrast(value, surface), `${ink} on ${surface}`).toBeGreaterThanOrEqual(4.5);
      }
    }
  });

  it("leaves no hard-coded colour in non-gallery component rules", () => {
    const { components, themeSystem } = splitShell();
    // Theme-definition blocks are where literals belong; component rules are not.
    const componentRules = (components + themeSystem)
      .split(/\r?\n/)
      .filter((line) => !/^\s*--[a-z0-9-]+\s*:/.test(line))
      .filter((line) => !/^\s*\[data-accent=/.test(line))
      .filter((line) => !/^\s*\[data-theme="light"\]/.test(line))
      .filter((line) => !/^\s*background(-color)?:\s*#|^\s*color:\s*var/.test(line) || true);

    const offenders = componentRules.filter(
      (line) => /#[0-9a-fA-F]{3,8}\b|rgba?\(/.test(line) && !/--auth|auth-shell|linear-gradient\(160deg/.test(line),
    );
    // The auth backdrop scrim is the one deliberate exception: a fixed veil over
    // a fixed photograph, with its own light-mode counterpart.
    expect(offenders).toEqual([]);
  });

  it("aliases the detection console onto the shared scale instead of its own hexes", () => {
    expect(detectionCss).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
    expect(detectionCss).not.toMatch(/rgba?\(/);
    for (const step of ["critical", "high", "medium", "low", "ok"]) {
      expect(detectionCss).toContain(`--detection-${step}: var(--sev-${step})`);
    }
  });

  it("draws charts and the graph from theme tokens only", () => {
    expect(chartsSource).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
    expect(chartsSource).toContain("var(--chart-1)");
    expect(graphSource).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
    // --surface-soft is the panel fill; a node painted with it is invisible.
    expect(graphSource).not.toContain('"var(--surface-soft)"');
  });
});
