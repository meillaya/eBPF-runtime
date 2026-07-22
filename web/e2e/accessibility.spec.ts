// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Accessibility QA: axe-core scans (zero critical/serious violations),
// keyboard operation (skip link, tab order, focus management), and ARIA
// semantics for the shell, tables, and the process tree.

import type { Result } from "axe-core";
import { getViolations, injectAxe } from "axe-playwright";
import { expect, test } from "./helpers/fixtures";
import { PROCESS_TREE_FRAMES } from "./helpers/mock-api";

function formatViolations(violations: Result[]): string {
  return violations
    .map(
      (v) =>
        `[${v.impact}] ${v.id}: ${v.help}\n` +
        v.nodes
          .slice(0, 3)
          .map((n) => `    ${n.target.join(" ")} — ${n.failureSummary ?? ""}`)
          .join("\n"),
    )
    .join("\n\n");
}

const SCAN_VIEWS = [
  { path: "/", waitFor: "Agent identity" },
  { path: "/events", waitFor: "Stream is live but silent" },
  { path: "/processes", waitFor: "PID 50", seedTree: true },
  { path: "/alerts", waitFor: "reverse-shell-egress" },
  { path: "/rules", waitFor: "Reverse shell egress" },
  { path: "/rollout", waitFor: "Commit gate" },
  { path: "/agents", waitFor: "edge-node-01" },
] as const;

test.describe("axe-core scans", () => {
  for (const view of SCAN_VIEWS) {
    test(`${view.path} has zero critical/serious axe violations`, async ({ page, stream }) => {
      if (view.seedTree) {
        stream.onConnect = (ws) => {
          for (const frame of PROCESS_TREE_FRAMES) ws.send(JSON.stringify(frame));
        };
      }
      await page.goto(view.path);
      await expect(page.getByText(view.waitFor).first()).toBeVisible();
      // Finish in-flight finite CSS animations (row-in) so axe reads
      // settled computed styles — mid-animation opacity reads as a false
      // color-contrast violation. Infinite pulses live on aria-hidden
      // decorative nodes and cannot be finished.
      await page.evaluate(() => {
        for (const anim of document.getAnimations()) {
          const timing = anim.effect?.getComputedTiming();
          if (timing !== undefined && timing.endTime !== Number.POSITIVE_INFINITY) anim.finish();
        }
      });

      await injectAxe(page);
      const violations = await getViolations(page);
      const blocking = violations.filter((v) => v.impact === "critical" || v.impact === "serious");
      // Non-blocking findings surface in the test output for triage.
      const other = violations.filter((v) => v.impact !== "critical" && v.impact !== "serious");
      if (other.length > 0) {
        // eslint-disable-next-line no-console -- triage output only
        console.info(`axe (non-blocking) on ${view.path}:\n${formatViolations(other)}`);
      }
      expect(
        blocking,
        `blocking axe violations on ${view.path}:\n${formatViolations(blocking)}`,
      ).toHaveLength(0);
    });
  }
});

test.describe("keyboard operation", () => {
  test("skip link is the first tab stop and jumps to main content", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
    const skip = page.getByRole("link", { name: "Skip to content" });
    await page.keyboard.press("Tab");
    await expect(skip).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/#main-content$/);
    await expect(page.locator("main#main-content")).toBeInViewport();
  });

  test("tab order moves from the skip link into the primary nav", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
    await page.keyboard.press("Tab"); // skip link
    await page.keyboard.press("Tab"); // first rail link
    await expect(
      page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Overview" }),
    ).toBeFocused();
  });

  test("alert row expansion keeps focus and exposes aria-expanded", async ({ page }) => {
    await page.goto("/alerts");
    // Label flips Expand ⇄ Collapse; the id keeps the locator on one element.
    const toggle = page.getByRole("button", { name: /alert al-0001/ });
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
    await expect(toggle).toBeFocused();
    // The match-explanation detail row is now in the tree.
    await expect(page.locator("tr.detail-row")).toHaveCount(1);
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await expect(page.locator("tr.detail-row")).toHaveCount(0);
  });
});

test.describe("ARIA semantics", () => {
  test("shell landmarks, labels, and live-region timer are wired", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
    await expect(page.getByRole("main")).toHaveId("main-content");
    // UTC clock is an announced timer, not decorative text.
    await expect(page.getByRole("timer")).toHaveAttribute(
      "aria-label",
      "Coordinated universal time",
    );
    // The kind filter select carries a programmatic label.
    await page.goto("/events");
    await expect(page.locator("label[for='kind-filter']")).toHaveCount(1);
    await expect(page.getByRole("table", { name: "Live kernel events" })).toBeVisible();
  });

  test("process tree follows the ARIA tree pattern", async ({ page, stream }) => {
    stream.onConnect = (ws) => {
      for (const frame of PROCESS_TREE_FRAMES) ws.send(JSON.stringify(frame));
    };
    await page.goto("/processes");
    const tree = page.getByRole("tree", { name: "Process tree (generation-identified)" });
    await expect(tree).toBeVisible();

    const items = tree.getByRole("treeitem");
    await expect(items.first()).toHaveAttribute("aria-level", "1");
    // Root is auto-expanded; every parent exposes its expanded state.
    await expect(items.first()).toHaveAttribute("aria-expanded", "true");
    // aria-setsize/posinset present on items.
    await expect(items.first()).toHaveAttribute("aria-setsize", /.+/);
    await expect(items.first()).toHaveAttribute("aria-posinset", /.+/);
    // Descriptive per-node labels (identity, generation, exec, state).
    await expect(items.first()).toHaveAttribute(
      "aria-label",
      /PID 50, generation 1, \/usr\/sbin\/sshd/,
    );
  });
});
