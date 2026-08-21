import { defineConfig, devices } from "@playwright/test";
import { fileURLToPath } from "node:url";
import path from "node:path";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const python = process.platform === "win32" ? ".venv\\Scripts\\python.exe" : ".venv/bin/python";
const browserChannel = process.env.E2E_BROWSER_CHANNEL;

// Keep browser binaries beside the checkout rather than in the user profile.
// Workers inherit this, so it must match the path used by `playwright install`.
process.env.PLAYWRIGHT_BROWSERS_PATH ||= path.join(projectRoot, ".playwright-browsers");

export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  fullyParallel: false,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: process.env.E2E_BASE_URL || "http://127.0.0.1:8765",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },
  projects: [{
    name: "chromium",
    use: { ...devices["Desktop Chrome"], ...(browserChannel ? { channel: browserChannel } : {}) },
  }],
  webServer: process.env.E2E_BASE_URL ? undefined : {
    command: `${python} scripts/e2e_server.py`,
    cwd: projectRoot,
    url: "http://127.0.0.1:8765/api/v1/health",
    reuseExistingServer: false,
    timeout: 120_000,
  },
});
