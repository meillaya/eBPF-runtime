// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Table QA for the surfaces that implement it: client-side severity
// filtering + opaque cursor pagination (alerts), row activation into a
// detail drawer (rules), and the DataTable roving-tabindex keyboard
// contract (sockets feed). The console ships no column-sort controls —
// filtering, pagination, and keyboard row traversal are the contract.
import { expect, noConsoleErrors, test } from "./helpers/fixtures";

test.describe("alerts — filter and pagination", () => {
  test("severity filter narrows rows and reports what is hidden", async ({
    page,
    consoleErrors,
  }) => {
    await page.goto("/alerts");
    const table = page.getByRole("table", { name: "Alerts" });
    await expect(table.locator("tbody tr")).toHaveCount(4);

    await page.locator("#alert-severity-filter").selectOption("CRITICAL");
    await expect(table.locator("tbody tr")).toHaveCount(1);
    // The surviving row is the CRITICAL reverse-shell alert.
    await expect(table).toContainText("reverse-shell-egress");
    await expect(page.getByText("filtered to CRITICAL — 3 hidden")).toBeVisible();

    await page.locator("#alert-severity-filter").selectOption("MEDIUM");
    await expect(table.locator("tbody tr")).toHaveCount(1);
    await expect(page.getByText("filtered to MEDIUM — 3 hidden")).toBeVisible();

    await page.locator("#alert-severity-filter").selectOption("ALL");
    await expect(table.locator("tbody tr")).toHaveCount(4);
    await expect(page.getByText("every severity")).toBeVisible();
    noConsoleErrors(consoleErrors);
  });

  test("'Older' walks the opaque cursor and terminates on the last page", async ({
    page,
    api,
    consoleErrors,
  }) => {
    await page.goto("/alerts");
    const table = page.getByRole("table", { name: "Alerts" });
    await expect(table.locator("tbody tr")).toHaveCount(4);

    const older = page.getByRole("button", { name: "Older →" });
    await expect(older).toBeVisible();
    await older.click();

    // The second page is fetched with the server-issued cursor.
    await expect
      .poll(() => api.requests.filter((r) => r.pathname === "/alerts").map((r) => r.search))
      .toContain("?cursor=page-2&limit=50");
    await expect(table.locator("tbody tr")).toHaveCount(2);
    // Last page carries no cursor → the control disappears.
    await expect(older).toHaveCount(0);
    noConsoleErrors(consoleErrors);
  });
});

test.describe("rules — row activation", () => {
  test("clicking a rule row opens the detail drawer; Close dismisses it", async ({
    page,
    consoleErrors,
  }) => {
    await page.goto("/rules");
    const row = page
      .getByRole("table", { name: /Rules in pack/ })
      .filter({ hasText: "Reverse shell egress" })
      .locator("tbody tr")
      .first();
    await row.locator("td").first().click();

    await expect(page.getByRole("button", { name: "Close" })).toBeVisible();
    await expect(
      page.locator("section[aria-label='YAML preview of rule Reverse shell egress']"),
    ).toBeVisible();

    await page.getByRole("button", { name: "Close" }).click();
    await expect(page.getByRole("button", { name: "Close" })).toHaveCount(0);
    noConsoleErrors(consoleErrors);
  });

  test("Enter on a focused rule row activates it (keyboard parity)", async ({ page }) => {
    await page.goto("/rules");
    const row = page
      .getByRole("table", { name: /Rules in pack/ })
      .filter({ hasText: "Reverse shell egress" })
      .locator("tbody tr")
      .first();
    await row.focus();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("button", { name: "Close" })).toBeVisible();
  });
});

test.describe("data table keyboard contract", () => {
  test("roving tabindex with Arrow/Home/End across socket rows", async ({
    page,
    consoleErrors,
  }) => {
    await page.goto("/sockets");
    await page.getByRole("button", { name: "Historical", exact: true }).click();

    const table = page.getByRole("table", { name: "Socket lifecycle events" });
    const rowAt = (i: number) => table.locator(`tbody tr[data-idx="${i}"]`);
    await expect(table.locator("tbody tr")).toHaveCount(3);

    // Roving tabindex: exactly one row is tabbable.
    await expect(rowAt(0)).toHaveAttribute("tabindex", "0");
    await expect(rowAt(1)).toHaveAttribute("tabindex", "-1");
    await expect(rowAt(2)).toHaveAttribute("tabindex", "-1");

    await rowAt(0).focus();
    await page.keyboard.press("ArrowDown");
    await expect(rowAt(1)).toBeFocused();
    await page.keyboard.press("ArrowDown");
    await expect(rowAt(2)).toBeFocused();
    await page.keyboard.press("ArrowDown"); // clamped at the last row
    await expect(rowAt(2)).toBeFocused();
    await page.keyboard.press("Home");
    await expect(rowAt(0)).toBeFocused();
    await page.keyboard.press("End");
    await expect(rowAt(2)).toBeFocused();
    await page.keyboard.press("ArrowUp");
    await expect(rowAt(1)).toBeFocused();
    noConsoleErrors(consoleErrors);
  });
});
