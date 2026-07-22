// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Playwright config for the Sentinel Console browser QA suite.
//
// The Vite dev server starts automatically (webServer) with
// VITE_API_BASE="" so the dashboard talks same-origin REST/WS — every
// request is intercepted by page.route / page.routeWebSocket in the
// fixtures (no live backend needed). baseURL is loopback, which
// activates the dev-bypass auth path (admin role, no OIDC).
//
// Port 8090 (not the default 8080): on shared dev hosts 8080 is
// routinely occupied by rootless container port-forwarders; the
// loopback hostname — not the port — is what enables the dev bypass.
import { defineConfig, devices } from "@playwright/test";

// webServer.env replaces process.env for the server process — carry the
// current environment through and force same-origin API mode.
const serverEnv: Record<string, string> = {};
for (const [key, value] of Object.entries(process.env)) {
  if (typeof value === "string") serverEnv[key] = value;
}
serverEnv.VITE_API_BASE = "";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: "http://127.0.0.1:8090",
    trace: "on-first-retry",
  },
  expect: {
    toHaveScreenshot: {
      // Freeze CSS animations (live-dot pulse, skeleton shimmer, row-in)
      // and hide carets so baselines are deterministic.
      animations: "disabled",
      caret: "hide",
      maxDiffPixelRatio: 0.01,
    },
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command: "bun run dev -- --port 8090 --strictPort",
    port: 8090,
    env: serverEnv,
    reuseExistingServer: !process.env.CI,
    stdout: "ignore",
    stderr: "pipe",
  },
});
