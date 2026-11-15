// Capture the live dashboard for verification evidence.
//
// Usage (from web/):
//   node scripts/shot-stack.mjs http://127.0.0.1:18080 [outDir]
//
// Foreground the stack's HTTP port first, e.g. over SSH from the repository
// VM lab:
//   ssh -i target/vm/keys/id_ed25519 -p 2222 \
//     -N -L 127.0.0.1:18080:127.0.0.1:8080 fleet@127.0.0.1
//
// Captures a 1500x1100 overview viewport (the README image), a full-page
// overview, and one screenshot per remaining surface. Default output is
// ../target/verification/dashboard-*.png; copy dashboard-rootful.png into
// docs/verification/ after a real compose-stack run.
import { chromium } from "playwright";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const url = process.argv[2] ?? "http://127.0.0.1:18080";
const outDir = resolve(process.argv[3] ?? "../target/verification");
await mkdir(outDir, { recursive: true });

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1500, height: 1100 }, deviceScaleFactor: 1 });
const errors = [];
page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
page.on("console", (message) => {
  if (message.type() === "error") errors.push(`console: ${message.text()}`);
});

await page.goto(url, { waitUntil: "networkidle" });
await page.locator(".masthead").waitFor({ timeout: 30000 });
await page.waitForTimeout(1500);

const summary = await page.evaluate(() => {
  const text = (selector) => document.querySelector(selector)?.textContent?.trim() ?? "";
  return {
    title: document.title,
    measures: [...document.querySelectorAll(".measure")].map((measure) => ({
      value: measure.querySelector(".measure-value")?.textContent?.trim(),
      label: measure.querySelector(".measure-label")?.textContent?.trim(),
      note: measure.querySelector(".measure-note")?.textContent?.trim(),
    })),
    updated: text(".updated"),
  };
});
console.log(JSON.stringify(summary, null, 2));

await page.screenshot({ path: resolve(outDir, "dashboard-rootful.png") });
await page.screenshot({ path: resolve(outDir, "dashboard-rootful-full.png"), fullPage: true });

// Evidence shots for the remaining surfaces, same session.
for (const [label, view] of [
  ["events", "Events"],
  ["alerts", "Alerts"],
  ["agents", "Agents"],
  ["policies", "Policies"],
  ["audit", "Audit"],
]) {
  await page.locator(".nav button").filter({ hasText: view }).first().click();
  await page.waitForTimeout(600);
  await page.screenshot({ path: resolve(outDir, `dashboard-${label}.png`) });
}

await browser.close();
if (errors.length) {
  console.log("PAGE ERRORS:", errors.join(" | "));
  process.exitCode = 1;
} else {
  console.log("no page errors");
}
