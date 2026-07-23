// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Shared test fixtures. Every test page gets:
//   * consoleErrors — browser console errors + page errors, collected
//     from the moment the page exists (assert empty with noConsoleErrors)
//   * api    — the REST mock controller (installApiMocks)
//   * stream — the event-stream WebSocket controller (installStreamMock;
//     default behavior: accept and stay open, silent — views render
//     their "live but silent" state with zero console noise)
import { test as base, expect } from "@playwright/test";
import {
  type ApiMock,
  installApiMocks,
  installStreamMock,
  type StreamController,
} from "./mock-api";

interface ConsoleFixtures {
  consoleErrors: string[];
  api: ApiMock;
  stream: StreamController;
}

export const test = base.extend<ConsoleFixtures>({
  consoleErrors: [
    async ({ page }, use) => {
      const errors: string[] = [];
      page.on("console", (msg) => {
        if (msg.type() === "error") errors.push(msg.text());
      });
      page.on("pageerror", (err) => {
        errors.push(`pageerror: ${err.message}`);
      });
      await use(errors);
    },
    { auto: true },
  ],
  // auto: every test page gets the mocked REST + WS surface, whether or
  // not the test body references the controllers.
  api: [
    async ({ page }, use) => {
      await use(await installApiMocks(page));
    },
    { auto: true },
  ],
  stream: [
    async ({ page }, use) => {
      await use(await installStreamMock(page));
    },
    { auto: true },
  ],
});

export { expect };

/**
 * Fail when the page logged console errors, except for patterns the test
 * explicitly expects (e.g. a deliberately forced network failure).
 */
export function noConsoleErrors(errors: string[], allowed: RegExp[] = []): void {
  const unexpected = errors.filter((e) => !allowed.some((re) => re.test(e)));
  expect(unexpected, `unexpected console errors:\n${unexpected.join("\n")}`).toEqual([]);
}
