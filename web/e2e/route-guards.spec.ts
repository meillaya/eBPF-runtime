// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Route-guard QA for the dev-bypass path: on loopback the console skips
// OIDC entirely, assigns the admin role, and every RequireRole gate
// (including the policy-admin rollout surface) must open. The OIDC flow
// itself is out of scope by design (dev mode bypasses it).
import { expect, noConsoleErrors, test } from "./helpers/fixtures";

test.describe("dev-mode loopback bypass", () => {
  test("loopback session is dev-bypassed with the admin role", async ({ page }) => {
    await page.goto("/");
    // Topbar chip advertises the bypass.
    await expect(page.getByText("DEV BYPASS")).toBeVisible();
    await expect(page.locator(".chip--dev")).toHaveAttribute(
      "title",
      "Loopback dev bypass: auth skipped, admin role assigned",
    );
    // Rail footer shows the synthetic session + resolved role label.
    await expect(page.getByText("dev-loopback")).toBeVisible();
    await expect(page.locator(".session-id")).toContainText("Admin");
  });

  test("no sign-out control exists in dev mode", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("button", { name: "Sign out" })).toHaveCount(0);
  });

  test("admin session sees every nav section (Telemetry, Detection, Fleet)", async ({ page }) => {
    await page.goto("/");
    const rail = page.getByRole("navigation", { name: "Primary" });
    await expect(rail.getByText("Telemetry")).toBeVisible();
    await expect(rail.getByText("Detection")).toBeVisible();
    await expect(rail.getByText("Fleet")).toBeVisible();
  });
});

test.describe("role-gated routes under admin", () => {
  test("/rollout opens the policy-admin surface with mutation controls", async ({
    page,
    consoleErrors,
  }) => {
    await page.goto("/rollout");
    // Admin copy (viewers get "browse only — mutations need policy-admin").
    await expect(page.locator(".view-sub")).toContainText("stage · commit · rollback");
    // Version list renders the mocked lifecycle (STAGED/READY/COMMITTED).
    await expect(page.locator(".version-name", { hasText: "v16" })).toBeVisible();
    await expect(page.locator(".version-name", { hasText: "v15" })).toBeVisible();
    await expect(page.locator(".version-name", { hasText: "v14" })).toBeVisible();
    // Admin-only controls are present: stage form + commit/rollback gates.
    await expect(page.getByRole("button", { name: "Stage", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Commit", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Rollback", exact: true })).toBeVisible();
    noConsoleErrors(consoleErrors);
  });

  test("viewer-level gated routes render their data for the admin session", async ({
    page,
    consoleErrors,
  }) => {
    await page.goto("/policies");
    await expect(page.locator("main h1.view-title")).toBeVisible();

    await page.goto("/rules");
    await expect(page.getByText("Reverse shell egress")).toBeVisible();

    await page.goto("/agents");
    await expect(page.getByText("edge-node-01")).toBeVisible();
    noConsoleErrors(consoleErrors);
  });
});
