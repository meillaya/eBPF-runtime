// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Process-tree QA: the ARIA tree folds live fork/exec/exit frames into
// generation-identified rows; expand/collapse (buttons, clicks, and full
// keyboard operation), incomplete-ancestry honesty, and the historical
// REST mode (/events × fork+exec+exit) are all exercised.
import { expect, noConsoleErrors, test } from "./helpers/fixtures";
import { liveFrame, PROCESS_TREE_FRAMES, pidTgid } from "./helpers/mock-api";

const treeitem = (page: import("@playwright/test").Page, idx: number) =>
  page.locator(`[role="treeitem"][data-idx="${idx}"]`);

function seedTree(stream: { onConnect: ((ws: { send(data: string): void }) => void) | null }) {
  stream.onConnect = (ws) => {
    for (const frame of PROCESS_TREE_FRAMES) ws.send(JSON.stringify(frame));
  };
}

test.describe("live fold", () => {
  test("fork/exec/exit frames fold into sshd → bash → curl(exited)", async ({
    page,
    stream,
    consoleErrors,
  }) => {
    seedTree(stream);
    await page.goto("/processes");
    const tree = page.getByRole("tree");
    await expect(tree).toBeVisible();

    // Roots auto-expand: sshd + bash visible; curl still folded under bash.
    await expect(tree.getByRole("treeitem")).toHaveCount(2);
    await expect(treeitem(page, 0)).toContainText("PID 50");
    await expect(treeitem(page, 0)).toContainText("sshd");
    await expect(treeitem(page, 0)).toHaveAttribute("aria-level", "1");
    await expect(treeitem(page, 0)).toHaveAttribute("aria-expanded", "true");
    await expect(treeitem(page, 1)).toContainText("PID 100");
    await expect(treeitem(page, 1)).toContainText("bash");
    await expect(treeitem(page, 1)).toHaveAttribute("aria-level", "2");
    await expect(treeitem(page, 1)).toHaveAttribute("aria-expanded", "false");
    await expect(tree.getByText("PID 200")).toHaveCount(0);

    // Exit folded into the record: the exec timeline shows all 3 execs.
    await expect(page.getByText("3 execs")).toBeVisible();
    noConsoleErrors(consoleErrors);
  });

  test("expand all / collapse all toolbar buttons work", async ({ page, stream }) => {
    seedTree(stream);
    await page.goto("/processes");
    const tree = page.getByRole("tree");
    await expect(tree.getByRole("treeitem")).toHaveCount(2);

    await page.getByRole("button", { name: "Expand all" }).click();
    await expect(tree.getByRole("treeitem")).toHaveCount(3);
    const curl = treeitem(page, 2);
    await expect(curl).toContainText("PID 200");
    await expect(curl).toContainText("curl");
    await expect(curl).toContainText("EXIT 0");
    await expect(curl).toHaveAttribute("aria-level", "3");

    await page.getByRole("button", { name: "Collapse all" }).click();
    await expect(tree.getByRole("treeitem")).toHaveCount(1);
  });

  test("clicking a row toggles its children", async ({ page, stream }) => {
    seedTree(stream);
    await page.goto("/processes");
    const tree = page.getByRole("tree");
    const bash = treeitem(page, 1);

    await bash.click();
    await expect(tree.getByRole("treeitem")).toHaveCount(3);
    await expect(bash).toHaveAttribute("aria-expanded", "true");
    await bash.click();
    await expect(tree.getByRole("treeitem")).toHaveCount(2);
    await expect(bash).toHaveAttribute("aria-expanded", "false");
  });

  test("full keyboard operation: arrows, Enter, Home/End, Escape", async ({ page, stream }) => {
    seedTree(stream);
    await page.goto("/processes");
    const tree = page.getByRole("tree");
    await expect(tree.getByRole("treeitem")).toHaveCount(2);

    await treeitem(page, 0).focus();

    // ↓ traverse to bash
    await page.keyboard.press("ArrowDown");
    await expect(treeitem(page, 1)).toBeFocused();

    // → expands bash (children appear, focus held)
    await page.keyboard.press("ArrowRight");
    await expect(tree.getByRole("treeitem")).toHaveCount(3);
    await expect(treeitem(page, 1)).toBeFocused();

    // → again enters the first child (curl)
    await page.keyboard.press("ArrowRight");
    await expect(treeitem(page, 2)).toBeFocused();

    // ← on a leaf returns to the parent
    await page.keyboard.press("ArrowLeft");
    await expect(treeitem(page, 1)).toBeFocused();

    // Enter toggles (collapses bash → curl folds away)
    await page.keyboard.press("Enter");
    await expect(tree.getByRole("treeitem")).toHaveCount(2);
    await expect(treeitem(page, 1)).toBeFocused();

    // End / Home jump within the visible rows
    await page.keyboard.press("End");
    await expect(treeitem(page, 1)).toBeFocused();
    await page.keyboard.press("Home");
    await expect(treeitem(page, 0)).toBeFocused();

    // Escape collapses everything
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("ArrowRight"); // re-expand bash first
    await expect(tree.getByRole("treeitem")).toHaveCount(3);
    await page.keyboard.press("Escape");
    await expect(tree.getByRole("treeitem")).toHaveCount(1);
  });

  test("unobserved parents are marked, never invented", async ({ page, stream }) => {
    stream.onConnect = (ws) => {
      for (const frame of PROCESS_TREE_FRAMES) ws.send(JSON.stringify(frame));
      // PID 300 claims parent PID 999 — never observed in the window.
      ws.send(
        JSON.stringify(
          liveFrame(
            8,
            "EVENT_KIND_PROCESS_FORK",
            {
              process_fork: {
                child: {
                  pid_tgid: pidTgid(300, 300),
                  task_start_time_ns: 4_000_000,
                  parent_pid_tgid: pidTgid(999, 999),
                  uid: 0,
                  gid: 0,
                },
                is_thread: false,
              },
            },
            8_000_000,
          ),
        ),
      );
    };
    await page.goto("/processes");
    await expect(page.getByText("1 nodes with incomplete ancestry")).toBeVisible();
    await expect(page.getByText("ANCESTRY INCOMPLETE")).toBeVisible();
  });
});

test.describe("historical mode", () => {
  test("queries fork/exec/exit from REST and folds the same tree", async ({
    page,
    api,
    consoleErrors,
  }) => {
    await page.goto("/processes");
    await page.getByRole("button", { name: "Historical", exact: true }).click();

    // One /events request per process kind.
    await expect
      .poll(() =>
        api.requests
          .filter((r) => r.pathname === "/events")
          .map((r) => r.search)
          .sort(),
      )
      .toEqual([
        "?event_kind=EVENT_KIND_PROCESS_EXEC_RESULT&limit=400",
        "?event_kind=EVENT_KIND_PROCESS_EXIT&limit=400",
        "?event_kind=EVENT_KIND_PROCESS_FORK&limit=400",
      ]);

    const tree = page.getByRole("tree");
    await expect(tree.getByRole("treeitem")).toHaveCount(2);
    await expect(treeitem(page, 0)).toContainText("PID 50");
    await expect(treeitem(page, 1)).toContainText("PID 100");

    // Historical affordances: range select + refresh.
    await expect(page.locator("#ptree-range")).toBeVisible();
    await expect(page.getByRole("button", { name: "Refresh" })).toBeVisible();
    noConsoleErrors(consoleErrors);
  });
});
