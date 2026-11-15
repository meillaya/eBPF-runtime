import { expect, test } from "@playwright/test";

test("dev dashboard renders and opens the core surfaces", async ({ page }) => {
  test.skip(!process.env.EBPF_DEV_WEB_URL, "set EBPF_DEV_WEB_URL to run the dev dashboard smoke test");
  await page.goto(process.env.EBPF_DEV_WEB_URL!);
  await expect(page.locator(".wordmark")).toHaveText("eBPF fleet");
  await expect(page.getByRole("heading", { name: "Fleet overview" })).toBeAttached();

  const nav = (name: string) => page.locator(".nav button").filter({ hasText: name });
  for (const label of ["Overview", "Events", "Alerts", "Agents", "Policies", "Audit"]) {
    await expect(nav(label)).toBeVisible();
  }

  await nav("Events").click();
  await expect(page.locator("tbody tr").first()).toBeVisible();
  await page.locator("tbody tr").first().click();
  await expect(page.locator(".drawer")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.locator(".drawer")).toHaveCount(0);

  await nav("Policies").click();
  await expect(page.getByRole("button", { name: "Validate" })).toBeVisible();
  await expect(page.locator("tbody tr").first()).toBeVisible();

  await nav("Audit").click();
  await expect(page.getByRole("heading", { name: "Audit trail", level: 1 })).toBeAttached();
  await expect(page.locator("tbody tr").first()).toBeVisible();
});
