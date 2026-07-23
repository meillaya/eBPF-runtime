// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Visual regression baselines for the key views. The ticking UTC clock
// is masked and CSS animations are frozen (playwright.config.ts), so
// baselines are deterministic across runs. Only baselines are committed.
import { expect, test } from "./helpers/fixtures";
import { fileOpenFrames, PROCESS_TREE_FRAMES } from "./helpers/mock-api";

test.describe("visual baselines", () => {
  test("overview", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByText("Agent identity")).toBeVisible();
    await expect(page.getByText("Kernel compatibility")).toBeVisible();
    await expect(page).toHaveScreenshot("overview.png", {
      mask: [page.getByRole("timer")],
    });
  });

  test("events live feed", async ({ page, stream }) => {
    stream.onConnect = (ws) => {
      for (const frame of fileOpenFrames()) ws.send(JSON.stringify(frame));
    };
    await page.goto("/events");
    await expect(
      page.getByRole("table", { name: "Live kernel events" }).locator("tbody tr"),
    ).toHaveCount(3);
    await expect(page).toHaveScreenshot("events-live.png", {
      mask: [page.getByRole("timer")],
    });
  });

  test("process tree", async ({ page, stream }) => {
    stream.onConnect = (ws) => {
      for (const frame of PROCESS_TREE_FRAMES) ws.send(JSON.stringify(frame));
    };
    await page.goto("/processes");
    await expect(page.getByRole("tree")).toBeVisible();
    await page.getByRole("button", { name: "Expand all" }).click();
    await expect(page.getByRole("treeitem")).toHaveCount(3);
    await expect(page).toHaveScreenshot("process-tree.png", {
      mask: [page.getByRole("timer")],
    });
  });

  test("alerts", async ({ page }) => {
    await page.goto("/alerts");
    await expect(page.getByRole("table", { name: "Alerts" })).toBeVisible();
    await expect(page).toHaveScreenshot("alerts.png", {
      mask: [page.getByRole("timer")],
    });
  });

  test("rollout", async ({ page }) => {
    await page.goto("/rollout");
    await expect(page.getByText("Commit gate")).toBeVisible();
    await expect(page).toHaveScreenshot("rollout.png", {
      mask: [page.getByRole("timer")],
    });
  });

  test("not found", async ({ page }) => {
    await page.goto("/no-such-route");
    await expect(page.getByText("404 — no such console route")).toBeVisible();
    await expect(page).toHaveScreenshot("not-found.png", {
      mask: [page.getByRole("timer")],
    });
  });

  test("overview at mobile width", async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto("/");
    await expect(page.getByText("Agent identity")).toBeVisible();
    await expect(page).toHaveScreenshot("overview-mobile.png", {
      mask: [page.getByRole("timer")],
    });
  });
});
