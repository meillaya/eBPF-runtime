import { defineConfig } from "@playwright/test";

const baseURL = process.env.EBPF_WEB_URL ?? "http://127.0.0.1:8081";

export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  expect: { timeout: 20_000 },
  fullyParallel: false,
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL,
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
  },
});
