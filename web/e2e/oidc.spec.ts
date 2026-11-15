import { expect, test } from "@playwright/test";
import { accessToken, apiBase, stageAndCommit } from "./helpers";

test("admin completes the Dex authorization-code flow and sees audit rows", async ({
  page,
  request,
}) => {
  const token = await accessToken(request, "alice", "alice-password");
  await stageAndCommit(request, token, 1);

  await page.goto("/");
  await expect(page.locator(".wordmark")).toHaveText("eBPF fleet");
  await page.getByRole("button", { name: "Sign in" }).click();

  await expect(page.locator('input[name="login"]')).toBeVisible();
  await page.locator('input[name="login"]').fill("alice");
  await page.locator('input[name="password"]').fill("alice-password");
  await page.locator('button[type="submit"]').click();

  await expect(page.locator(".wordmark")).toHaveText("eBPF fleet");
  await expect(page.getByRole("button", { name: "Sign out" })).toBeVisible();

  await page.getByRole("button", { name: "Policies" }).click();
  await expect(page.locator("tbody tr").first()).toBeVisible();

  await page.getByRole("button", { name: "Audit" }).click();
  await expect(page.locator("tbody tr").first()).toBeVisible();
  await expect(page.locator("tbody")).toContainText("policy.stage");

  const agents = await request.get(`${apiBase}/agents`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  expect(agents.ok()).toBeTruthy();
  const body = (await agents.json()) as { agents: Array<{ spiffe_id: string }> };
  expect(body.agents.some((agent) => agent.spiffe_id.endsWith("/node-1"))).toBeTruthy();

  // The live agent acknowledges only after it swaps its rule engine. A
  // one-agent rollout therefore proves the threshold path end to end.
  await stageAndCommit(request, token, 2);
  const created = await request.post(`${apiBase}/policies/2/rollout`, {
    headers: { Authorization: `Bearer ${token}` },
    data: { min_ratio: 1.0, timeout_secs: 30 },
  });
  expect(created.ok()).toBeTruthy();
  await expect
    .poll(
      async () => {
        const response = await request.get(`${apiBase}/policies/2/rollout`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!response.ok()) {
          return "missing";
        }
        const rollout = (await response.json()) as { rollout: { status: string } };
        return rollout.rollout.status;
      },
      { timeout: 30_000 },
    )
    .toBe("promoted");

  await page.reload();
  await page.getByRole("button", { name: "Policies" }).click();
  await expect(page.locator("tbody")).toContainText("promoted");
  await page.getByRole("button", { name: "Audit" }).click();
  await expect(page.locator("tbody")).toContainText("policy.rollout.promoted");
  await page.screenshot({
    path: "../target/verification/oidc-dashboard.png",
    fullPage: true,
  });
});

test("viewer sees read-only policy surfaces and no audit navigation", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.locator('input[name="login"]').fill("vera");
  await page.locator('input[name="password"]').fill("vera-password");
  await page.locator('button[type="submit"]').click();

  await expect(page.locator(".wordmark")).toHaveText("eBPF fleet");
  await expect(page.locator(".identity")).toContainText("Viewer");
  await expect(page.getByRole("button", { name: "Audit" })).toHaveCount(0);

  await page.getByRole("button", { name: "Policies" }).click();
  await expect(page.locator("tbody tr").first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Stage version" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Commit", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Roll out", exact: true })).toHaveCount(0);
});
