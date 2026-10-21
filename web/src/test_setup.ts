import { vi } from "vitest";

// Node 26 exposes native Web Storage globals even without a backing file.
// Browser tests must use the real storage belonging to their jsdom window.
// Vitest aliases `window` to globalThis, so access its underlying jsdom instance.
const browserWindow = (globalThis as typeof globalThis & {
  jsdom: { window: Window };
}).jsdom.window;
vi.stubGlobal("localStorage", browserWindow.localStorage);
vi.stubGlobal("sessionStorage", browserWindow.sessionStorage);
