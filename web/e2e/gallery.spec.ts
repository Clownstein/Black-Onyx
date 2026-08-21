import { expect, test } from "@playwright/test";

async function login(page: import("@playwright/test").Page) {
  await page.goto("/");
  await page.getByLabel("Email").fill("admin@example.com");
  await page.getByLabel("Password", { exact: true }).fill("correct horse battery staple");
  await page.getByRole("button", { name: "Sign in" }).click();
  // The immersive gallery hub is the default landing page post-login. Wait on
  // a rendered hub tile, NOT the URL: the login form is served at "/" too, so
  // a URL assertion passes instantly and lets the next step race the pending
  // login request (which then cancels it and drops the session).
  await waitForGallerySettled(page);
  await expect(page).toHaveURL(/\/$/);
}

/**
 * Waits for the tile queries to settle. `data-tile-id` is emitted by both the
 * visible list cards and the canvas mode's visually-hidden a11y anchor layer,
 * so this is view-independent. Asserts *attachment*, not visibility: in canvas
 * mode the anchor exists for assistive tech but is clipped off-screen.
 */
async function waitForGallerySettled(page: import("@playwright/test").Page) {
  await expect(page.locator('[data-tile-id="route:/dashboard"]')).toBeAttached();
}

/** Canvas is the default, so DOM-level tile tests must opt into list mode. */
async function openListView(page: import("@playwright/test").Page) {
  await login(page);
  await waitForGallerySettled(page);
  const listToggle = page.getByRole("button", { name: "List", exact: true });
  // The toggle is absent entirely when WebGL/reduced-motion force list mode,
  // in which case the list is already showing.
  if (await listToggle.count()) await listToggle.click();
  await expect(page.locator("a.gallery-tile", { hasText: "Dashboard" })).toBeVisible();
}

test("the hub owns the full viewport with no classic sidebar", async ({ page }) => {
  await login(page);
  await waitForGallerySettled(page);
  // The immersive route is deliberately rendered outside the sidebar shell —
  // a "Primary" nav here means the hub has been boxed back into a column.
  await expect(page.getByRole("navigation", { name: "Primary" })).toHaveCount(0);
  await expect(page.locator(".app-shell")).toHaveCount(0);
  const hub = page.locator(".gallery-hub");
  await expect(hub).toBeVisible();
  const [box, viewport] = [await hub.boundingBox(), page.viewportSize()!];
  expect(box!.width).toBeCloseTo(viewport.width, 0);
  expect(box!.height).toBeCloseTo(viewport.height, 0);
  // Account controls move into the floating chrome once the sidebar is gone.
  await expect(page.getByRole("button", { name: "Log out" })).toBeVisible();
});

test("gallery hub renders built-in tiles as real, navigable links", async ({ page }) => {
  await openListView(page);
  const dashboardTile = page.locator("a.gallery-tile", { hasText: "Dashboard" });
  await expect(dashboardTile).toHaveAttribute("href", "/dashboard");
  const iocTile = page.locator("a.gallery-tile", { hasText: "IOC workbench" });
  await expect(iocTile).toHaveAttribute("href", "/iocs");

  await iocTile.click();
  await expect(page).toHaveURL(/\/iocs$/);
  await expect(page.getByRole("heading", { name: /IOC/i }).first()).toBeVisible();
});

test("section pill narrows the visible tile set without a full reload", async ({ page }) => {
  await openListView(page);
  const casesTile = page.locator('a.gallery-tile[data-tile-id="route:/cases"]');
  await expect(casesTile).toBeVisible();

  await page.getByRole("button", { name: "Sites", exact: true }).click();
  await expect(casesTile).toHaveCount(0);
  await expect(page.getByText("Pin SIEM, EDR, and vendor consoles here.")).toBeVisible();

  // Toggling the same section again clears the filter.
  await page.getByRole("button", { name: "Sites", exact: true }).click();
  await expect(casesTile).toBeVisible();
});

test("filter panel narrows the visible tile set by text match", async ({ page }) => {
  await openListView(page);
  await page.getByRole("button", { name: /^Filter/ }).click();
  await page.getByPlaceholder("Title, subtitle, URL, or tag").fill("watchlist");
  await expect(page.locator("a.gallery-tile", { hasText: "Watchlists" })).toBeVisible();
  await expect(page.locator("a.gallery-tile", { hasText: "Dashboard" })).toHaveCount(0);
});

test("add, reach by filter, and delete a site round-trips through the gallery", async ({ page }) => {
  await openListView(page);
  await page.getByRole("button", { name: "Sites", exact: true }).click();
  // The empty-Sites state also offers its own "+ Add site" button — scope to
  // the persistent CTA in the chrome.
  await page.locator(".gallery-cta").getByRole("button", { name: "+ Add site" }).click();

  await expect(page.getByRole("heading", { name: "Add site" })).toBeVisible();
  await page.getByLabel("Display name").fill("E2E Test Console");
  await page.getByLabel(/^URL/).fill("https://e2e-console.example.com");
  await page.getByRole("button", { name: "Add site", exact: true }).click();

  const siteTile = page.locator("a.gallery-tile", { hasText: "E2E Test Console" });
  await expect(siteTile).toBeVisible();
  await expect(siteTile).toHaveAttribute("target", "_blank");

  // Manage login → Delete site removes it from the gallery.
  await page.locator(".gallery-tile-shell", { hasText: "E2E Test Console" })
    .getByRole("button", { name: "Manage login" }).click();
  await page.getByRole("button", { name: "Delete site" }).click();
  await expect(page.locator("a.gallery-tile", { hasText: "E2E Test Console" })).toHaveCount(0);
});

test("classic sidebar layout remains reachable from the gallery logo", async ({ page }) => {
  await login(page);
  await waitForGallerySettled(page);
  await page.getByRole("link", { name: "Exit immersive gallery to the classic dashboard" }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.getByRole("heading", { name: "Security operations overview" })).toBeVisible();
  // The sidebar exists on classic routes — it is only the hub that drops it.
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
});

test("gallery nav link returns to the immersive hub from the classic layout", async ({ page }) => {
  await login(page);
  await waitForGallerySettled(page);
  await page.getByRole("link", { name: "Exit immersive gallery to the classic dashboard" }).click();
  await expect(page).toHaveURL(/\/dashboard$/);

  await page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Gallery" }).click();
  await expect(page).toHaveURL(/\/$/);
  await waitForGallerySettled(page);
  await expect(page.getByRole("navigation", { name: "Primary" })).toHaveCount(0);
});

test("prefers-reduced-motion hides the canvas toggle and never mounts a <canvas>", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await login(page);
  await waitForGallerySettled(page);
  await expect(page.getByRole("button", { name: "Gallery", exact: true })).toHaveCount(0);
  await expect(page.locator("canvas")).toHaveCount(0);
  // List mode is forced, so tiles must be genuinely on-screen.
  await expect(page.locator("a.gallery-tile", { hasText: "Dashboard" })).toBeVisible();
});

async function openCanvasView(page: import("@playwright/test").Page) {
  await login(page);
  await waitForGallerySettled(page);
  // Canvas is the default view — no toggle click needed. Its absence means
  // WebGL/reduced-motion forced the list fallback, covered by other tests.
  test.skip(await page.getByRole("button", { name: "Gallery", exact: true }).count() === 0, "WebGL unavailable in this browser/host — list view is the mandatory fallback and is covered by other tests.");
  const canvasRoot = page.locator(".gallery-canvas-root");
  await expect(canvasRoot).toBeVisible();
  await expect(page.locator("canvas")).toBeVisible();
  // A mounted <canvas> is not an interactive one: until the renderer has drawn
  // a frame there is no geometry to raycast, and a press lands on empty space.
  await expect(canvasRoot).toHaveAttribute("data-scene-ready", "true");
  const box = await canvasRoot.boundingBox();
  if (!box) throw new Error("canvas root has no bounding box");
  return { canvasRoot, centerX: box.x + box.width / 2, centerY: box.y + box.height / 2 };
}

test("canvas view: a deliberate drag pans without navigating", async ({ page }) => {
  const { centerX, centerY } = await openCanvasView(page);

  // Well past the 10px drag threshold — must pan, not navigate.
  await page.mouse.move(centerX, centerY);
  await page.mouse.down();
  await page.mouse.move(centerX + 220, centerY + 40, { steps: 12 });
  await page.mouse.up();
  await expect(page).toHaveURL(/\/$/);
});

test("canvas view: a short click on the front-most tile navigates", async ({ page }) => {
  const { centerX, centerY } = await openCanvasView(page);
  // Which tile lands dead-centre depends on the drum's row/column layout, so
  // assert the click routed to *some* real built-in tile rather than pinning a
  // specific one — that keeps this a drag-vs-click test instead of a brittle
  // restatement of the layout maths.
  const routes = await page.locator('[data-tile-id^="route:"]')
    .evaluateAll(nodes => nodes.map(node => node.getAttribute("href")));
  expect(routes.length).toBeGreaterThan(0);

  await page.mouse.move(centerX, centerY);
  await page.mouse.down();
  await page.mouse.move(centerX + 2, centerY + 1);
  await page.mouse.up();

  await expect(page).not.toHaveURL(/\/$/, { timeout: 10_000 });
  expect(routes).toContain(new URL(page.url()).pathname);
});
