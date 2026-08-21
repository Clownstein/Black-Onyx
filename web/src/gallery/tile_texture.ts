import * as THREE from "three";
import { GalleryPreview, GallerySection, GalleryTile } from "./types";

/**
 * Rasterizes a tile into a texture for the R3F scene. The alternative — a live
 * DOM overlay projected into the scene per tile — tanks FPS at dozens of
 * tiles, and the only maintained implementation of it ships in a dependency
 * this project deliberately no longer carries (see Scene.tsx). A canvas
 * texture per tile is far cheaper at this tile count (~20-60).
 *
 * Composition follows the reference gallery rather than a dashboard card: the
 * top two-thirds is an image-like *plate* (a section-tinted field carrying an
 * abstract render of the tile's data), and type is confined to a quiet caption
 * band underneath. The old layout put a bright accent strip, a glyph chip, a
 * badge pill, a border, a title, a subtitle and a metrics row all on one
 * surface — legible up close, but at gallery scale it read as a wall of
 * control-panel widgets instead of a wall of pictures.
 */

const WIDTH = 768;
const HEIGHT = 480;
/** Height of the caption band; the plate takes everything above it. */
const CAPTION_H = 150;
const PLATE_H = HEIGHT - CAPTION_H;
const PAD = 34;

/** Black Onyx identity sheet — deep / charcoal / slate / silver / violet. */
const INK = {
  base: "#1A1A1F",
  caption: "#0B0B0E",
  title: "#E8EAEF",
  muted: "#A9ADB6",
  hairline: "rgba(169, 173, 182, .18)",
};

/**
 * Per-section hue drawn only from the brand kit so the wall stays Black Onyx
 * rather than a rainbow of unrelated product colours. Variety still comes from
 * plate painters + seed, not from off-brand teal/amber fills.
 */
const SECTION_TINT: Record<GallerySection, string> = {
  investigate: "#A78BFA",
  intelligence: "#6C3CF2",
  operations: "#A9ADB6",
  control: "#7A7F8A",
  sites: "#A78BFA",
}

const BADGE_TINT: Record<string, string> = {
  LIVE: "#A78BFA",
  SAVED: "#6C3CF2",
  ALERTS: "#ef6875",
  LOCKED: "#A9ADB6",
  EMPTY: "#A9ADB6",
};

function tintOf(tile: GalleryTile): string {
  return SECTION_TINT[tile.section] || SECTION_TINT.control;
}

function withAlpha(hex: string, alpha: number): string {
  const value = hex.replace("#", "");
  const r = parseInt(value.slice(0, 2), 16);
  const g = parseInt(value.slice(2, 4), 16);
  const b = parseInt(value.slice(4, 6), 16);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

function roundRect(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
}

/**
 * Deterministic per-tile pseudo-randomness. The abstract plates must look
 * hand-varied but must not reshuffle on every metrics poll, so the seed is the
 * tile id rather than Math.random.
 */
function seedFrom(text: string): () => number {
  let state = 0;
  for (let i = 0; i < text.length; i++) state = (state * 31 + text.charCodeAt(i)) >>> 0;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

function truncate(ctx: CanvasRenderingContext2D, text: string, maxWidth: number): string {
  if (ctx.measureText(text).width <= maxWidth) return text;
  let out = text;
  while (out.length > 1 && ctx.measureText(`${out}…`).width > maxWidth) out = out.slice(0, -1);
  return `${out}…`;
}

function setFont(ctx: CanvasRenderingContext2D, font: string, letterSpacing?: string) {
  ctx.font = font;
  // Supported in current Chromium/Firefox; harmless where it is not.
  if (letterSpacing !== undefined) {
    (ctx as CanvasRenderingContext2D & { letterSpacing?: string }).letterSpacing = letterSpacing;
  }
}

/* ------------------------------------------------------------------ plates */

function drawSparkline(ctx: CanvasRenderingContext2D, series: number[], tint: string, x: number, y: number, w: number, h: number) {
  if (series.length < 2) return;
  const min = Math.min(...series);
  const max = Math.max(...series);
  const span = max - min || 1;
  ctx.beginPath();
  series.forEach((value, index) => {
    const px = x + (index / (series.length - 1)) * w;
    const py = y + h - ((value - min) / span) * h;
    if (index === 0) ctx.moveTo(px, py);
    else ctx.lineTo(px, py);
  });
  ctx.strokeStyle = withAlpha(tint, 0.9);
  ctx.lineWidth = 3;
  ctx.stroke();
}

function drawMetricPlate(ctx: CanvasRenderingContext2D, tile: GalleryTile, tint: string) {
  const entries = Object.entries(tile.metrics || {});
  const [label, value] = entries[0] || ["", "—"];
  ctx.textAlign = "left";
  ctx.textBaseline = "alphabetic";
  ctx.fillStyle = INK.title;
  setFont(ctx, "300 108px 'Segoe UI', system-ui, sans-serif", "-4px");
  ctx.fillText(truncate(ctx, String(value), WIDTH - PAD * 2), PAD, PLATE_H - 74);

  if (label) {
    ctx.fillStyle = withAlpha(tint, 0.85);
    setFont(ctx, "700 17px 'Segoe UI', system-ui, sans-serif", "1.6px");
    ctx.fillText(truncate(ctx, label.toUpperCase(), WIDTH - PAD * 2), PAD, PLATE_H - 40);
  }

  // Remaining metrics as a quiet second line, so a rich tile still reads rich
  // without competing with the headline number.
  if (entries.length > 1) {
    ctx.fillStyle = INK.muted;
    setFont(ctx, "400 17px 'Segoe UI', system-ui, sans-serif", "0.4px");
    const rest = entries.slice(1, 3).map(([k, v]) => `${k} ${v}`).join("   ·   ");
    ctx.fillText(truncate(ctx, rest, WIDTH - PAD * 2), PAD, PLATE_H - 14);
  }

  if (tile.sparkline && tile.sparkline.length > 1) {
    drawSparkline(ctx, tile.sparkline, tint, PAD, PAD + 24, WIDTH - PAD * 2, 96);
  }
}

function drawHeatmapPlate(ctx: CanvasRenderingContext2D, tile: GalleryTile, tint: string) {
  const random = seedFrom(tile.id);
  const cols = 14;
  const rows = 6;
  const gap = 6;
  const cellW = (WIDTH - PAD * 2 - gap * (cols - 1)) / cols;
  const cellH = 22;
  const top = PLATE_H - PAD - rows * (cellH + gap) + gap;
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      const heat = Math.pow(random(), 1.7);
      ctx.fillStyle = withAlpha(tint, 0.06 + heat * 0.72);
      roundRect(ctx, PAD + c * (cellW + gap), top + r * (cellH + gap), cellW, cellH, 3);
      ctx.fill();
    }
  }
}

function drawListPlate(ctx: CanvasRenderingContext2D, tile: GalleryTile, tint: string) {
  const random = seedFrom(tile.id);
  const rows = 5;
  const rowH = 30;
  const top = PLATE_H - PAD - rows * rowH;
  for (let r = 0; r < rows; r++) {
    const y = top + r * rowH;
    const width = (WIDTH - PAD * 2) * (0.32 + random() * 0.62);
    ctx.fillStyle = withAlpha(tint, 0.5 - r * 0.07);
    roundRect(ctx, PAD, y, 5, 14, 2.5);
    ctx.fill();
    ctx.fillStyle = `rgba(226, 238, 247, ${0.2 - r * 0.028})`;
    roundRect(ctx, PAD + 18, y + 3, width, 8, 4);
    ctx.fill();
  }
}

function drawFaviconPlate(ctx: CanvasRenderingContext2D, tile: GalleryTile, tint: string) {
  // Favicons are fetched asynchronously and cannot be rasterized here without
  // making texture creation async; the monogram is the synchronous stand-in
  // and the real icon still shows on the list-view card.
  const initials = (tile.title.match(/\b[a-z0-9]/gi) || []).slice(0, 2).join("").toUpperCase() || "··";
  const cx = WIDTH / 2;
  const cy = PLATE_H / 2 + 10;
  ctx.beginPath();
  ctx.arc(cx, cy, 74, 0, Math.PI * 2);
  ctx.fillStyle = withAlpha(tint, 0.12);
  ctx.fill();
  ctx.strokeStyle = withAlpha(tint, 0.4);
  ctx.lineWidth = 2;
  ctx.stroke();
  ctx.fillStyle = withAlpha(tint, 0.95);
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  setFont(ctx, "300 58px 'Segoe UI', system-ui, sans-serif", "1px");
  ctx.fillText(initials, cx, cy + 2);
  ctx.textAlign = "left";
  ctx.textBaseline = "alphabetic";
}

function drawColorPlate(ctx: CanvasRenderingContext2D, tile: GalleryTile, tint: string) {
  const random = seedFrom(tile.id);
  // Concentric arcs, offset per tile — an abstract "cover image" that fills the
  // plate the way project photography does in the reference.
  const cx = WIDTH * (0.2 + random() * 0.6);
  const cy = PLATE_H * (0.3 + random() * 0.5);
  ctx.save();
  ctx.beginPath();
  ctx.rect(0, 0, WIDTH, PLATE_H);
  ctx.clip();
  for (let i = 7; i >= 1; i--) {
    ctx.beginPath();
    ctx.arc(cx, cy, i * 42, 0, Math.PI * 2);
    ctx.strokeStyle = withAlpha(tint, 0.05 + (8 - i) * 0.035);
    ctx.lineWidth = 1.5;
    ctx.stroke();
  }
  ctx.restore();
}

const PLATE_PAINTERS: Record<GalleryPreview, (ctx: CanvasRenderingContext2D, tile: GalleryTile, tint: string) => void> = {
  metric: drawMetricPlate,
  heatmap: drawHeatmapPlate,
  list: drawListPlate,
  favicon: drawFaviconPlate,
  color: drawColorPlate,
};

/* ------------------------------------------------------------------ export */

export function createTileTexture(tile: GalleryTile): THREE.CanvasTexture {
  const canvas = document.createElement("canvas");
  canvas.width = WIDTH;
  canvas.height = HEIGHT;
  const ctx = canvas.getContext("2d");
  if (!ctx) return new THREE.CanvasTexture(canvas);

  const tint = tintOf(tile);

  // Plate: near-black ground with a single soft light source, so tiles catch
  // the eye by luminance rather than by outline.
  ctx.fillStyle = INK.base;
  ctx.fillRect(0, 0, WIDTH, PLATE_H);
  const glow = ctx.createRadialGradient(WIDTH * 0.28, PLATE_H * 0.12, 0, WIDTH * 0.28, PLATE_H * 0.12, WIDTH * 0.9);
  glow.addColorStop(0, withAlpha(tint, 0.17));
  glow.addColorStop(0.55, withAlpha(tint, 0.04));
  glow.addColorStop(1, "rgba(0,0,0,0)");
  ctx.fillStyle = glow;
  ctx.fillRect(0, 0, WIDTH, PLATE_H);

  PLATE_PAINTERS[tile.preview]?.(ctx, tile, tint);

  // Caption band.
  ctx.fillStyle = INK.caption;
  ctx.fillRect(0, PLATE_H, WIDTH, CAPTION_H);
  ctx.fillStyle = INK.hairline;
  ctx.fillRect(0, PLATE_H, WIDTH, 1);

  ctx.textAlign = "left";
  ctx.textBaseline = "alphabetic";

  // Eyebrow: section on the left, status word on the right. A word in the
  // section's own tint replaces the old badge pill — same information, none of
  // the chrome.
  ctx.fillStyle = INK.muted;
  setFont(ctx, "700 15px 'Segoe UI', system-ui, sans-serif", "2.4px");
  ctx.fillText(tile.section.toUpperCase(), PAD, PLATE_H + 42);

  if (tile.badge) {
    const badgeTint = BADGE_TINT[tile.badge] || INK.muted;
    ctx.textAlign = "right";
    ctx.fillStyle = badgeTint;
    ctx.fillText(tile.badge, WIDTH - PAD, PLATE_H + 42);
    ctx.textAlign = "left";
  }

  ctx.fillStyle = INK.title;
  setFont(ctx, "500 42px 'Segoe UI', system-ui, sans-serif", "-0.8px");
  ctx.fillText(truncate(ctx, tile.title, WIDTH - PAD * 2), PAD, PLATE_H + 92);

  ctx.fillStyle = INK.muted;
  setFont(ctx, "400 20px 'Segoe UI', system-ui, sans-serif", "0px");
  ctx.fillText(truncate(ctx, tile.subtitle, WIDTH - PAD * 2), PAD, PLATE_H + 124);

  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  // Tiles curl steeply away at the rim; without anisotropy those read as a
  // smeared mess. 4 is well within every WebGL2 implementation's limit.
  texture.anisotropy = 4;
  texture.needsUpdate = true;
  return texture;
}
