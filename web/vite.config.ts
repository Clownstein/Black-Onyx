// defineConfig comes from vitest/config so the `test` block is typed; loadEnv
// is a plain Vite export and is not re-exported there.
import { defineConfig } from "vitest/config";
import { loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import { createReadStream, existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const projectBackground = resolve(projectRoot, "BlackOnyxBackground.png");
const projectLogo = resolve(projectRoot, "BlackOnyxTransparentLogo.png");

type RootAsset = { urlPath: string; fileName: string; sourcePath: string; contentType: string };

const rootAssets: RootAsset[] = [
  {
    urlPath: "/background.png",
    fileName: "background.png",
    sourcePath: projectBackground,
    contentType: "image/png",
  },
  {
    urlPath: "/logo.png",
    fileName: "logo.png",
    sourcePath: projectLogo,
    contentType: "image/png",
  },
];

function rootBrandAssets() {
  return {
    name: "black-onyx-root-assets",
    buildStart() {
      for (const asset of rootAssets) {
        if (!existsSync(asset.sourcePath)) {
          throw new Error(`Required web UI asset is missing: ${asset.sourcePath}`);
        }
      }
    },
    generateBundle() {
      for (const asset of rootAssets) {
        this.emitFile({
          type: "asset",
          fileName: asset.fileName,
          source: readFileSync(asset.sourcePath),
        });
      }
    },
    configureServer(server) {
      for (const asset of rootAssets) {
        server.middlewares.use(asset.urlPath, (_request, response, next) => {
          if (!existsSync(asset.sourcePath)) {
            next();
            return;
          }
          response.setHeader("Content-Type", asset.contentType);
          response.setHeader("Cache-Control", "no-cache");
          createReadStream(asset.sourcePath).pipe(response);
        });
      }
    },
  };
}

/** Fail builds when an entry or lazy chunk regresses past its delivery budget. */
function chunkBudgets(maxEntryBytes = 900 * 1024, maxChunkBytes = 1024 * 1024) {
  return {
    name: "black-onyx-chunk-budgets",
    generateBundle(_options: unknown, bundle: Record<string, any>) {
      const chunks = Object.values(bundle).filter((asset: any) => asset.type === "chunk");
      const oversizedEntries = chunks.filter(
        (asset: any) => asset.isEntry && Buffer.byteLength(asset.code, "utf8") > maxEntryBytes,
      );
      const oversizedChunks = chunks.filter(
        (asset: any) => Buffer.byteLength(asset.code, "utf8") > maxChunkBytes,
      );
      if (oversizedEntries.length || oversizedChunks.length) {
        const format = (asset: any) => `${asset.fileName} (${Buffer.byteLength(asset.code, "utf8")} bytes)`;
        const details = [
          oversizedEntries.length ? `entry budget ${maxEntryBytes}: ${oversizedEntries.map(format).join(", ")}` : "",
          oversizedChunks.length ? `chunk budget ${maxChunkBytes}: ${oversizedChunks.map(format).join(", ")}` : "",
        ].filter(Boolean).join("; ");
        this.error(`JavaScript bundle budget exceeded: ${details}`);
      }
    },
  };
}

/**
 * API port for the dev proxy, taken from the project-root .env rather than
 * hardcoded.
 *
 * `BLACK_ONYX_PORT` is what actually decides where the API listens (and
 * what docker-compose publishes). This proxy used to assume 8000, so any
 * deployment that set a different port left `npm run dev` posting to a closed
 * socket — which surfaces in the UI as a bare "Failed to fetch" on sign-in,
 * with nothing to suggest the port is the problem. Falls back to 8000, the
 * value of SecurityConfig.external_url's default.
 */
function apiTarget(mode: string): string {
  // Empty prefix: these are plain process env vars, not VITE_-exposed ones, and
  // they are read here at config time only — never bundled into the client.
  const env = loadEnv(mode, projectRoot, "");
  const port = env.BLACK_ONYX_PORT || "8000";
  return `http://127.0.0.1:${port}`;
}

export default defineConfig(({ mode }) => ({
  plugins: [react(), rootBrandAssets(), chunkBudgets()],
  test: {
    environment: "jsdom",
    // Unit tests only; e2e/ is driven by Playwright, which owns its own runner.
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    // jest-dom's ESM build imports lodash without file extensions, which Node
    // cannot resolve when the dependency is externalized.
    server: { deps: { inline: ["@testing-library/jest-dom"] } },
  },
  build: { outDir: "dist", emptyOutDir: true, chunkSizeWarningLimit: 1024 },
  server: {
    proxy: { "/api": apiTarget(mode), "/ws": { target: apiTarget(mode), ws: true } }
  }
}));
