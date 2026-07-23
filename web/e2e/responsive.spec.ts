// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Responsive QA at 375 / 768 / 1440: no horizontal page overflow on any
// key view, the nav rail collapses below 860px, and dense tables scroll
// horizontally inside their wrappers instead of breaking the layout.
import type { Page } from "@playwright/test";
import { expect, noConsoleErrors, test } from "./helpers/fixtures";
import { fileOpenFrames, PROCESS_TREE_FRAMES } from "./helpers/mock-api";

const VIEWPORTS = [
  { name: "mobile 375", width: 375, height: 812 },
  { name: "tablet 768", width: 768, height: 1024 },
  { name: "desktop 1440", width: 1440, height: 900 },
] as const;

async function assertNoPageOverflow(page: Page, label: string): Promise<void> {
  const box = await page.evaluate(() => ({
    scroll: document.documentElement.scrollWidth,
    client: document.documentElement.clientWidth,
  }));
  expect(
    box.scroll,
    `${label}: horizontal overflow (scrollWidth ${box.scroll} > clientWidth ${box.client})`,
  ).toBeLessThanOrEqual(box.client);
}

for (const vp of VIEWPORTS) {
  test.describe(vp.name, () => {
    test.use({ viewport: { width: vp.width, height: vp.height } });

    test("key views never overflow horizontally", async ({ page, stream, consoleErrors }) => {
      stream.onConnect = (ws) => {
        for (const frame of [...fileOpenFrames(), ...PROCESS_TREE_FRAMES]) {
          ws.send(JSON.stringify(frame));
        }
      };

      await page.goto("/");
      await expect(page.getByText("Agent identity")).toBeVisible();
      await assertNoPageOverflow(page, "overview");

      await page.goto("/events");
      await expect(page.getByRole("table", { name: "Live kernel events" })).toBeVisible();
      await assertNoPageOverflow(page, "events");

      await page.goto("/processes");
      await expect(page.getByRole("tree")).toBeVisible();
      await assertNoPageOverflow(page, "processes");

      await page.goto("/alerts");
      await expect(page.getByRole("table", { name: "Alerts" })).toBeVisible();
      await assertNoPageOverflow(page, "alerts");

      await page.goto("/rollout");
      await expect(page.getByText("Commit gate")).toBeVisible();
      await assertNoPageOverflow(page, "rollout");

      noConsoleErrors(consoleErrors);
    });

    if (vp.width <= 860) {
      test("nav rail collapses below 860px", async ({ page }) => {
        await page.goto("/");
        await expect(page.getByRole("navigation", { name: "Primary" })).toBeHidden();
        // Content still owns the full width.
        await expect(page.getByRole("main")).toBeVisible();
      });
    } else {
      test("nav rail is docked at desktop width", async ({ page }) => {
        await page.goto("/");
        await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
      });
    }

    test("dense tables scroll horizontally inside their wrapper", async ({ page }) => {
      await page.goto("/alerts");
      const wrap = page.locator(".tbl-wrap").first();
      await expect(wrap).toBeVisible();
      await expect(wrap).toHaveCSS("overflow-x", "auto");
      const dims = await wrap.evaluate((el) => ({
        scroll: el.scrollWidth,
        client: el.clientWidth,
      }));
      if (vp.width <= 768) {
        // The 7-column alert table cannot fit a narrow viewport — it must
        // scroll inside the wrapper rather than push the page wider.
        expect(dims.scroll).toBeGreaterThan(dims.client);
      } else {
        expect(dims.scroll).toBeLessThanOrEqual(dims.client + 1);
      }
    });
  });
}
