import { expect, test } from "@playwright/test";

test("dev dashboard renders the fleet shell and recent events", async ({ page }) => {
  test.skip(!process.env.EBPF_DEV_WEB_URL, "set EBPF_DEV_WEB_URL to run the dev dashboard smoke test");
  await page.goto(process.env.EBPF_DEV_WEB_URL!);
  await expect(page.getByRole("heading", { name: "eBPF fleet" })).toBeVisible();
  await expect(page.getByRole("button", { name: "events" })).toBeVisible();
  await expect(page.locator("tbody tr").first()).toBeVisible();
});
