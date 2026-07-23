// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Live event-stream QA over a mocked WebSocket (/events/stream,
// subprotocol kernel-v1.event-stream.v1): connect + render, server-side
// disconnect → reconnect resuming from the seq cursor (since_ts) with
// overlap dedupe, slow-consumer 1013 fast reconnect, pause/resume, and
// the client-side kind filter.
import { expect, noConsoleErrors, test } from "./helpers/fixtures";
import { fileOpenFrames, liveFrame, pidTgid } from "./helpers/mock-api";

const BASH = pidTgid(100, 100);

function fileOpenPayload(path: string) {
  return {
    file_open: {
      task: { pid_tgid: BASH, task_start_time_ns: 2_000_000 },
      path,
      flags: 0,
      succeeded: true,
      errno_value: 0,
      from_lsm: false,
    },
  };
}

const rows = (page: import("@playwright/test").Page) =>
  page.getByRole("table", { name: "Live kernel events" }).locator("tbody tr");

test.describe("connect and render", () => {
  test("frames land in the table newest-first with live stats", async ({
    page,
    stream,
    consoleErrors,
  }) => {
    stream.onConnect = (ws) => {
      for (const frame of fileOpenFrames()) ws.send(JSON.stringify(frame));
    };
    await page.goto("/events");

    await expect(page.locator(".conn--live")).toBeVisible();
    await expect(rows(page)).toHaveCount(3);
    // Newest first: seq 3 on top.
    await expect(rows(page).first()).toContainText("3");

    const panel = page.locator(".panel", { hasText: "Live stream" }).first();
    await expect(panel.locator(".chip", { hasText: "received" })).toContainText("3");
    await expect(panel.locator(".chip", { hasText: "last seq" })).toContainText("3");
    noConsoleErrors(consoleErrors);
  });
});

test.describe("reconnect", () => {
  test("server drop → reconnect resumes from the cursor and dedupes the overlap", async ({
    page,
    stream,
    consoleErrors,
  }) => {
    // StrictMode opens two sockets on mount; every connection gets the
    // initial batch (the client's seq cursor dedupes the repeats). The
    // drop is issued only once the rows prove ingestion.
    const initial = fileOpenFrames(); // seq 1..3, ts 1M..3M
    let dropIssued = false;
    stream.onConnect = (ws) => {
      for (const frame of initial) ws.send(JSON.stringify(frame));
      if (dropIssued) {
        // Overlapping resume window: seq 3 again (must be dropped by the
        // client's seq cursor), then new frames 4 and 5.
        ws.send(JSON.stringify(initial[2]));
        ws.send(
          JSON.stringify(
            liveFrame(4, "EVENT_KIND_FILE_OPEN", fileOpenPayload("/etc/hosts"), 4_000_000),
          ),
        );
        ws.send(
          JSON.stringify(
            liveFrame(5, "EVENT_KIND_FILE_OPEN", fileOpenPayload("/etc/motd"), 5_000_000),
          ),
        );
      }
    };

    await page.goto("/events");
    await expect(rows(page)).toHaveCount(3);

    dropIssued = true;
    stream.closeAll(1011, "test drop");

    // The reconnect is surfaced to the operator with the resume cursor
    // (alert title and body are sibling nodes).
    const reconnecting = page.getByText("Reconnecting to the event stream");
    await expect(reconnecting).toBeVisible({ timeout: 3000 });
    await expect(page.getByText(/resume from seq 3/)).toBeVisible();

    // The retry socket resumes from the last observed monotonic ts
    // (mount sockets carry no cursor; the reconnect is the last one).
    await stream.waitForConnections(3);
    expect(stream.urls[stream.urls.length - 1]).toContain("since_ts_monotonic_ns=3000000");

    // Final state: five unique events, overlap deduped, stream live again.
    await expect(rows(page)).toHaveCount(5);
    await expect(page.locator(".conn--live")).toBeVisible();
    await expect(reconnecting).toHaveCount(0);
    const panel = page.locator(".panel", { hasText: "Live stream" }).first();
    await expect(panel.locator(".chip", { hasText: "received" })).toContainText("5");
    await expect(panel.locator(".chip", { hasText: "last seq" })).toContainText("5");
    noConsoleErrors(consoleErrors);
  });

  test("slow-consumer shed (1013) reconnects immediately with the cursor", async ({
    page,
    stream,
    consoleErrors,
  }) => {
    stream.onConnect = (ws) => {
      ws.send(JSON.stringify(fileOpenFrames(1, 1_000_000)[0]));
    };
    await page.goto("/events");
    await expect(rows(page)).toHaveCount(1);

    stream.closeAll(1013, "slow consumer");

    // 1013 skips the backoff entirely — the retry socket arrives fast and
    // resumes from the last observed ts.
    await stream.waitForConnections(3);
    expect(stream.urls[stream.urls.length - 1]).toContain("since_ts_monotonic_ns=1000000");
    await expect(page.locator(".conn--live")).toBeVisible();
    noConsoleErrors(consoleErrors);
  });
});

test.describe("pause and resume", () => {
  test("pause closes the socket; resume reconnects from the cursor", async ({
    page,
    stream,
    consoleErrors,
  }) => {
    let resumed = false;
    stream.onConnect = (ws) => {
      for (const frame of fileOpenFrames()) ws.send(JSON.stringify(frame));
      if (resumed) {
        ws.send(
          JSON.stringify(
            liveFrame(4, "EVENT_KIND_FILE_OPEN", fileOpenPayload("/etc/hosts"), 4_000_000),
          ),
        );
      }
    };
    await page.goto("/events");
    await expect(rows(page)).toHaveCount(3);

    const pauseBtn = page.getByRole("button", { name: "Pause", exact: true });
    await pauseBtn.click();
    await expect(page.getByRole("button", { name: "Resume", exact: true })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    await expect(page.locator(".conn--idle")).toBeVisible();

    resumed = true;
    await page.getByRole("button", { name: "Resume", exact: true }).click();
    await stream.waitForConnections(3);
    expect(stream.urls[stream.urls.length - 1]).toContain("since_ts_monotonic_ns=3000000");
    await expect(rows(page)).toHaveCount(4);
    await expect(page.locator(".conn--live")).toBeVisible();
    noConsoleErrors(consoleErrors);
  });
});

test.describe("kind filter", () => {
  test("filters the visible buffer client-side without dropping frames", async ({
    page,
    stream,
    consoleErrors,
  }) => {
    stream.onConnect = (ws) => {
      ws.send(
        JSON.stringify(
          liveFrame(1, "EVENT_KIND_FILE_OPEN", fileOpenPayload("/etc/passwd"), 1_000_000),
        ),
      );
      ws.send(
        JSON.stringify(
          liveFrame(
            2,
            "EVENT_KIND_NETWORK_CONNECT",
            {
              network_connect: {
                task: { pid_tgid: BASH, task_start_time_ns: 2_000_000 },
                socket_cookie: 4242,
                family: 2,
                local_addr: "10.0.0.5",
                remote_addr: "93.184.216.34",
                local_port: 51000,
                remote_port: 443,
                is_result: true,
                established: true,
                errno_value: 0,
                from_cgroup: true,
              },
            },
            2_000_000,
          ),
        ),
      );
      ws.send(
        JSON.stringify(
          liveFrame(3, "EVENT_KIND_FILE_OPEN", fileOpenPayload("/etc/hostname"), 3_000_000),
        ),
      );
    };
    await page.goto("/events");
    await expect(rows(page)).toHaveCount(3);

    await page.locator("#kind-filter").selectOption("EVENT_KIND_FILE_OPEN");
    await expect(rows(page)).toHaveCount(2);

    await page.locator("#kind-filter").selectOption("EVENT_KIND_NETWORK_CONNECT");
    await expect(rows(page)).toHaveCount(1);
    await expect(rows(page).first()).toContainText("2");

    await page.locator("#kind-filter").selectOption("all");
    await expect(rows(page)).toHaveCount(3);
    noConsoleErrors(consoleErrors);
  });
});
