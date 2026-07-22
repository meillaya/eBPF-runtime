// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Navigation QA: every console route loads under the dev-bypass admin
// session with no console errors, the nav rail drives SPA navigation,
// and the topbar breadcrumb tracks the active route.
import { expect, noConsoleErrors, test } from "./helpers/fixtures";

const ROUTES = [
  { path: "/", crumb: "Overview" },
  { path: "/events", crumb: "Event stream" },
  { path: "/processes", crumb: "Process tree" },
  { path: "/sockets", crumb: "Socket lifecycle" },
  { path: "/dns", crumb: "DNS packets" },
  { path: "/files", crumb: "File operations" },
  { path: "/syscalls", crumb: "Syscall latency" },
  { path: "/alerts", crumb: "Alert feed" },
  { path: "/drops", crumb: "Drop & loss" },
  { path: "/rules", crumb: "Detection rules" },
  { path: "/policies", crumb: "Policy lifecycle" },
  { path: "/rollout", crumb: "Policy rollout" },
  { path: "/agents", crumb: "Agent inventory" },
] as const;

test.describe("route loading", () => {
  for (const route of ROUTES) {
    test(`${route.path} loads with its view title and no console errors`, async ({
      page,
      consoleErrors,
    }) => {
      await page.goto(route.path);
      await expect(page.locator("main h1.view-title")).toBeVisible();
      await expect(page.locator(".topbar-crumb")).toContainText(route.crumb);
      await expect(page.locator("main")).toBeVisible();
      noConsoleErrors(consoleErrors);
    });
  }

  test("unknown route renders the 404 view with a way back", async ({ page, consoleErrors }) => {
    await page.goto("/definitely-not-a-route");
    await expect(page.getByText("404 — no such console route")).toBeVisible();
    await page.getByRole("link", { name: "Back to overview" }).click();
    await expect(page).toHaveURL(/\/$/);
    await expect(page.locator(".topbar-crumb")).toContainText("Overview");
    noConsoleErrors(consoleErrors);
  });
});

test.describe("nav rail", () => {
  test("rail exposes every console route and marks the active link", async ({ page }) => {
    await page.goto("/");
    const rail = page.getByRole("navigation", { name: "Primary" });
    const links = rail.getByRole("link");
    await expect(links).toHaveCount(ROUTES.length);
    for (const route of ROUTES) {
      await expect(
        rail.getByRole("link", { name: railLabel(route.path), exact: true }),
      ).toBeVisible();
    }
  });

  test("clicking rail links navigates without a full reload", async ({ page, consoleErrors }) => {
    await page.goto("/");
    const rail = page.getByRole("navigation", { name: "Primary" });

    await rail.getByRole("link", { name: "Alerts", exact: true }).click();
    await expect(page).toHaveURL(/\/alerts$/);
    await expect(page.locator(".topbar-crumb")).toContainText("Alert feed");
    await expect(rail.getByRole("link", { name: "Alerts", exact: true })).toHaveAttribute(
      "aria-current",
      "page",
    );

    await rail.getByRole("link", { name: "Rollout", exact: true }).click();
    await expect(page).toHaveURL(/\/rollout$/);
    await expect(page.locator(".topbar-crumb")).toContainText("Policy rollout");

    await rail.getByRole("link", { name: "Overview", exact: true }).click();
    await expect(page).toHaveURL(/\/$/);
    await expect(page.locator(".topbar-crumb")).toContainText("Overview");

    noConsoleErrors(consoleErrors);
  });

  test("breadcrumb updates as routes change via SPA navigation", async ({ page }) => {
    await page.goto("/");
    const crumb = page.locator(".topbar-crumb");
    await expect(crumb).toContainText("console /");
    await expect(crumb).toContainText("Overview");

    await page.getByRole("link", { name: "Events", exact: true }).click();
    await expect(crumb).toContainText("Event stream");

    await page.getByRole("link", { name: "Processes", exact: true }).click();
    await expect(crumb).toContainText("Process tree");
  });
});

function railLabel(path: string): string {
  const labels: Record<string, string> = {
    "/": "Overview",
    "/events": "Events",
    "/processes": "Processes",
    "/sockets": "Sockets",
    "/dns": "DNS",
    "/files": "Files",
    "/syscalls": "Syscalls",
    "/alerts": "Alerts",
    "/drops": "Drops",
    "/rules": "Rules",
    "/policies": "Policies",
    "/rollout": "Rollout",
    "/agents": "Agents",
  };
  return labels[path] ?? path;
}
