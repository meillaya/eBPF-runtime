// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// First-class state QA (DESIGN.md §8): every view must render exactly
// one of loading / empty / error / degraded, and error states must
// recover through their Retry control. Mock-side latency (api.delay)
// holds the first response so the skeleton is observable; tests still
// synchronize only on selectors.
import { expect, noConsoleErrors, test } from "./helpers/fixtures";
import { HEALTH } from "./helpers/mock-api";

test.describe("loading state", () => {
  test("table skeleton shows while the first page is in flight, then data", async ({
    page,
    api,
    consoleErrors,
  }) => {
    api.delay("/alerts", 800);
    await page.goto("/alerts");
    const skeleton = page.locator('[role="status"][aria-label="Loading rows"]');
    await expect(skeleton).toBeVisible();
    await expect(skeleton).toHaveAttribute("aria-busy", "true");
    // Data replaces the skeleton once the mock responds.
    await expect(page.getByRole("table", { name: "Alerts" })).toBeVisible();
    await expect(skeleton).toHaveCount(0);
    noConsoleErrors(consoleErrors);
  });

  test("overview shows the agent skeleton before health lands", async ({ page, api }) => {
    api.delay("/health", 600);
    await page.goto("/");
    await expect(page.locator('[role="status"][aria-label="Loading rows"]').first()).toBeVisible();
    await expect(page.getByText("Agent identity")).toBeVisible();
  });
});

test.describe("empty state", () => {
  test("alerts renders the honest empty state when no alerts fired", async ({
    page,
    api,
    consoleErrors,
  }) => {
    api.set("/alerts", { alerts: [] });
    await page.goto("/alerts");
    await expect(
      page.getByText("No alerts fired — rules are quiet. This is the empty state, not a failure."),
    ).toBeVisible();
    noConsoleErrors(consoleErrors);
  });

  test("events shows 'live but silent' when the stream carries nothing", async ({
    page,
    consoleErrors,
  }) => {
    await page.goto("/events");
    await expect(page.getByText("Stream is live but silent")).toBeVisible();
    noConsoleErrors(consoleErrors);
  });
});

test.describe("error state", () => {
  test("API failure shows the error panel with a working retry", async ({
    page,
    api,
    consoleErrors,
  }) => {
    api.fail("/health", 503, "control plane gone");
    await page.goto("/");

    const panel = page.getByRole("alert");
    await expect(panel).toBeVisible();
    await expect(panel).toContainText("Unable to reach the control plane");
    await expect(panel).toContainText("HTTP 503: control plane gone");

    // Fix the backend, retry, and the board recovers.
    api.set("/health", HEALTH);
    await page.getByRole("button", { name: "Retry request" }).click();
    await expect(page.getByText("Agent identity")).toBeVisible();
    await expect(panel).toHaveCount(0);
    // The forced 503 is this test's own doing — Chromium logs it.
    noConsoleErrors(consoleErrors, [/server responded with a status of 503/]);
  });

  test("alert feed failure surfaces the scoped error panel", async ({ page, api }) => {
    api.fail("/alerts", 500, "rule engine exploded");
    await page.goto("/alerts");
    const panel = page.getByRole("alert");
    await expect(panel).toContainText("Unable to reach the alert feed");
    await expect(panel).toContainText("HTTP 500: rule engine exploded");
    await expect(page.getByRole("button", { name: "Retry request" })).toBeVisible();
  });
});

test.describe("degraded state", () => {
  test("refresh failure with cached rows shows the degraded banner, not an error", async ({
    page,
    api,
  }) => {
    await page.goto("/");
    await expect(page.getByText("Agent identity")).toBeVisible();

    // The overview polls /health every 5s; the next poll fails → degraded.
    api.fail("/health", 500, "blip");
    await expect(page.getByText("Showing cached data — live refresh failed")).toBeVisible({
      timeout: 8000,
    });
    // Stale data stays on screen.
    await expect(page.getByText("Agent identity")).toBeVisible();
    await expect(page.getByText(HEALTH.node_name)).toBeVisible();
  });
});
