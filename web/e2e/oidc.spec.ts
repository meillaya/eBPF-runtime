import { expect, test } from "@playwright/test";
import { accessToken, apiBase, stageAndCommit } from "./helpers";

test("admin completes the Dex authorization-code flow and sees audit rows", async ({
  page,
  request,
}) => {
  const token = await accessToken(request, "alice", "alice-password");
  await stageAndCommit(request, token, 1);

  await page.goto("/");
  await expect(page.getByRole("heading", { name: "eBPF fleet" })).toBeVisible();
  await page.getByRole("button", { name: "Sign in" }).click();

  await expect(page.locator('input[name="login"]')).toBeVisible();
  await page.locator('input[name="login"]').fill("alice");
  await page.locator('input[name="password"]').fill("alice-password");
  await page.locator('button[type="submit"]').click();

  await expect(page.getByRole("heading", { name: "eBPF fleet" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign out" })).toBeVisible();

  await page.getByRole("button", { name: "policies" }).click();
  await expect(page.locator("tbody tr").first()).toBeVisible();

  await page.getByRole("button", { name: "audit" }).click();
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
  await page.getByRole("button", { name: "policies" }).click();
  await expect(page.locator("tbody")).toContainText("promoted 1/1");
  await page.getByRole("button", { name: "audit" }).click();
  await expect(page.locator("tbody")).toContainText("policy.rollout.promoted");
  await page.screenshot({
    path: "../target/verification/oidc-dashboard.png",
    fullPage: true,
  });
});
