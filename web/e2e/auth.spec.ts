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
  await expect(page.locator('[data-tile-id="route:/dashboard"]')).toBeAttached();
  await expect(page).toHaveURL(/\/$/);
}

async function logoutFromClassic(page: import("@playwright/test").Page) {
  await page.getByRole("button", { name: /E2E Administrator admin/i }).click();
  const logoutResponse = page.waitForResponse(
    response => response.url().endsWith("/api/v1/auth/logout") && response.request().method() === "POST",
  );
  await page.getByRole("button", { name: "Log out" }).click();
  expect((await logoutResponse).status()).toBe(200);
}

test("administrator can sign in and log out", async ({ page }) => {
  await login(page);
  // Use the classic shell for this auth assertion so WebGL rendering cannot
  // delay the click. The gallery uses the same Root-level logout callback.
  await page.goto("/dashboard");
  await logoutFromClassic(page);
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
  await expect(page.getByLabel("Email")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Security operations overview" })).toHaveCount(0);
});

test("administrator can open the lazy detection console", async ({ page }) => {
  await login(page);
  await page.goto("/detection");
  await expect(page.getByRole("heading", { name: "Detection overview" })).toBeVisible();
});

test("invite registration creates a role-restricted viewer", async ({ page }) => {
  await login(page);
  // Navigate directly rather than clicking a tile: the hub defaults to canvas
  // mode, where tile anchors exist for a11y but are not click targets.
  await page.goto("/admin");
  // The user table renders its own per-account "Role for <email>" selects, so
  // the invitation controls are resolved within their own form.
  const invite = page.locator("form").filter({
    has: page.getByRole("heading", { name: "Create invitation" }),
  });
  await invite.getByLabel("Email address").fill("viewer@example.com");
  await invite.getByLabel("Access role").selectOption("viewer");
  await invite.getByRole("button", { name: "Create secure invitation" }).click();
  const invitation = await page.getByLabel("Single-use URL").inputValue();
  // Classic routes keep the sidebar, so "Log out" resolves there.
  await logoutFromClassic(page);

  await page.goto(invitation);
  await page.getByLabel("Display name").fill("E2E Viewer");
  await page.getByLabel("Password", { exact: true }).fill("viewer correct horse battery");
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByText("viewer", { exact: true })).toBeVisible();

  // Operational workflows are withheld from viewers in both the navigation and
  // the router, so a direct visit falls back to the gallery hub (home). The
  // hub's tile anchors are role-filtered by the same predicate, so neither the
  // sidebar nor a tile should offer these routes.
  for (const label of ["Administration", "Jobs", "Ingest", "Chat", "IOCs", "Rules"]) {
    await expect(page.getByRole("link", { name: label })).toHaveCount(0);
  }
  await page.goto("/ingest");
  await expect(page).toHaveURL(/\/$/);

  // Reports stay readable for viewers, without the generation form.
  await page.goto("/reports");
  await expect(page.getByText("Viewer accounts can read and download shared reports")).toBeVisible();
  await expect(page.getByRole("button", { name: "Generate report" })).toHaveCount(0);
});
