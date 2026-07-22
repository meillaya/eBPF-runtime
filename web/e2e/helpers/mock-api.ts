// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Deterministic API + WebSocket mocks for the browser QA suite.
//
// The Playwright config starts Vite with VITE_API_BASE="" so every
// request the dashboard makes is same-origin (REST paths /health,
// /events, … and WS /events/stream). installApiMocks intercepts the
// REST surface (fetch/xhr only — never document navigation or Vite
// assets); installStreamMock owns the event-stream WebSocket.
//
// Latency injected via ApiMock.delay() runs inside the route handler
// (mock-side), so tests still synchronize purely on selectors.
import type { Page, Route, WebSocketRoute } from "@playwright/test";
import type { Event, EventKind, LiveEvent } from "../../src/api/event-types";
import type {
  AgentInventory,
  Alert,
  Compatibility,
  Health,
  Policy,
  PolicyAck,
  Rule,
} from "../../src/api/types";

// ---------------------------------------------------------------------------
// Identity helpers (pid_tgid = tgid << 32 | pid; arithmetic, not bitwise)
// ---------------------------------------------------------------------------

const U32 = 4294967296;

export function pidTgid(tgid: number, pid: number): number {
  return tgid * U32 + pid;
}

// ---------------------------------------------------------------------------
// REST fixtures
// ---------------------------------------------------------------------------

export const HEALTH: Health = {
  agent_id: "agent-7f3d9c2e",
  node_name: "edge-node-01",
  cluster: "lab-west",
  epoch_unix_sec: 1750000000,
  loaded_sensors: ["exec", "file", "net", "lsm"],
  degraded_sensors: ["dns"],
  blocked_sensors: [],
  events_emitted_total: 1284211,
  events_dropped_total: 37,
  supported_load_rate: 250000,
};

export const COMPATIBILITY: Compatibility = {
  kernel_release: "6.12.8-200.fc41.x86_64",
  bpf_lsm_active: true,
  bpf_token_active: true,
  cgroup_mode: "UNIFIED",
  bpf_program_type_allowlist: ["kprobe", "tracepoint", "lsm", "cgroup_skb"],
};

export const ALERTS_PAGE_1: Alert[] = [
  {
    id: "al-0001",
    rule_id: "reverse-shell-egress",
    event_id: "evt-0009",
    fired_at: "2026-07-21T14:03:22Z",
    severity: "CRITICAL",
    status: "OPEN",
    rule_digest: "sha256:9f2c1ab4",
    explanation:
      "lsm_deny: EPERM on exec of /bin/sh by node-exporter; own_deny=true — DENY attributed to policy v14",
  },
  {
    id: "al-0002",
    rule_id: "suid-exec",
    event_id: "evt-0004",
    fired_at: "2026-07-21T13:58:10Z",
    severity: "HIGH",
    status: "ACKNOWLEDGED",
    rule_digest: "sha256:77aa01dd",
    explanation: "setuid binary executed from a world-writable directory",
  },
  {
    id: "al-0003",
    rule_id: "tmpfs-persist",
    event_id: "evt-0008",
    fired_at: "2026-07-21T13:45:51Z",
    severity: "MEDIUM",
    status: "OPEN",
    rule_digest: "sha256:5e1b9c02",
    explanation: "file created under /dev/shm with the executable bit set",
  },
  {
    id: "al-0004",
    rule_id: "suid-exec",
    event_id: "evt-0002",
    fired_at: "2026-07-21T13:30:05Z",
    severity: "LOW",
    status: "RESOLVED",
    rule_digest: "sha256:77aa01dd",
    explanation: "informational: passwd invoked by cron",
  },
];

export const ALERTS_PAGE_2: Alert[] = [
  {
    id: "al-0005",
    rule_id: "reverse-shell-egress",
    event_id: "evt-0007",
    fired_at: "2026-07-21T12:59:59Z",
    severity: "HIGH",
    status: "SUPPRESSED",
    rule_digest: "sha256:9f2c1ab4",
    explanation: "egress connection from a shell process to a non-allowlisted peer",
  },
  {
    id: "al-0006",
    rule_id: "tmpfs-persist",
    event_id: "evt-0005",
    fired_at: "2026-07-21T12:41:17Z",
    severity: "CRITICAL",
    status: "OPEN",
    rule_digest: "sha256:5e1b9c02",
    explanation: "lsm_deny: EPERM unlink of /dev/shm/.x — own_deny=true",
  },
];

export const RULES: Rule[] = [
  {
    id: "reverse-shell-egress",
    name: "Reverse shell egress",
    severity: "CRITICAL",
    status: "ACTIVE",
    body: { when: { event_kind: "EVENT_KIND_PROCESS_EXEC_RESULT" } },
    tags: ["shell", "egress"],
  },
  {
    id: "suid-exec",
    name: "setuid exec",
    severity: "HIGH",
    status: "ACTIVE",
    body: { when: { event_kind: "EVENT_KIND_PROCESS_EXEC_RESULT" } },
    tags: ["privilege"],
  },
  {
    id: "tmpfs-persist",
    name: "tmpfs persistence",
    severity: "MEDIUM",
    status: "DRAFT",
    body: { when: { event_kind: "EVENT_KIND_FILE_CREATE" } },
    tags: ["persistence"],
  },
];

export const POLICIES: Policy[] = [
  {
    version: "v16",
    status: "STAGED",
    digest: "sha256:c0ffee03",
    created_at: "2026-07-21T12:00:00Z",
    author: "dev-loopback",
    notes: "stage test",
  },
  {
    version: "v15",
    status: "READY",
    digest: "sha256:beef0002",
    created_at: "2026-07-21T09:30:00Z",
    author: "ci-bot",
  },
  {
    version: "v14",
    status: "COMMITTED",
    digest: "sha256:9f2c1ab4",
    created_at: "2026-07-20T18:12:00Z",
    author: "ops",
    notes: "current fleet baseline",
  },
];

export const POLICY_ACKS: PolicyAck[] = [
  {
    agent_id: "agent-7f3d9c2e",
    policy_version: "v14",
    digest: "sha256:9f2c1ab4",
    accepted: true,
    acked_at: "2026-07-20T18:20:00Z",
  },
  {
    agent_id: "agent-2b8e41fa",
    policy_version: "v14",
    digest: "sha256:9f2c1ab4",
    accepted: false,
    rejected_reasons: ["digest mismatch"],
    acked_at: "2026-07-20T18:21:30Z",
  },
];

export const AGENTS: AgentInventory[] = [
  {
    agent_id: "agent-7f3d9c2e",
    node_name: "edge-node-01",
    cluster: "lab-west",
    last_seen_epoch: 1750000100,
    policy_version: "v14",
  },
  {
    agent_id: "agent-2b8e41fa",
    node_name: "edge-node-02",
    cluster: "lab-west",
    last_seen_epoch: 1750000050,
    policy_version: "v14",
  },
];

export const DROPS = {
  drops: [
    { id: "drop-0001", sensor: "exec", count: 22, reason: "ring full" },
    { id: "drop-0002", sensor: "dns", count: 15, reason: "shim overflow" },
  ],
};

// ---------------------------------------------------------------------------
// Event fixtures (REST /events) — a mixed batch covering every view.
// Process events fold into the tree: init → bash → curl (exited 0).
// ---------------------------------------------------------------------------

const EVENT_BASE_TS = 5_000_000_000_000;

function wallFor(seq: number): string {
  return new Date(Date.UTC(2026, 6, 21, 14, 0, seq)).toISOString();
}

function forkPayload(pid: number, tgid: number, startNs: number, parentPidTgid?: number) {
  const child: Record<string, unknown> = {
    pid_tgid: pidTgid(tgid, pid),
    task_start_time_ns: startNs,
    uid: 0,
    gid: 0,
  };
  if (parentPidTgid !== undefined) child.parent_pid_tgid = parentPidTgid;
  return { process_fork: { child, is_thread: false } };
}

function execPayload(pid: number, tgid: number, startNs: number, path: string, succeeded = true) {
  return {
    process_exec_result: {
      task: { pid_tgid: pidTgid(tgid, pid), task_start_time_ns: startNs },
      binary_path: path,
      succeeded,
      errno_value: succeeded ? 0 : 2,
      argv_truncated: false,
    },
  };
}

function exitPayload(pid: number, tgid: number, startNs: number, exitCode: number) {
  return {
    process_exit: {
      task: { pid_tgid: pidTgid(tgid, pid), task_start_time_ns: startNs },
      exit_code: exitCode,
      exit_group: true,
      group_dead_observed: true,
    },
  };
}

// The forest fold treats parentPid <= 1 as the natural root boundary
// (lib/process-tree.ts), so the chain starts at sshd (pid 50), not init.
const SSHD = pidTgid(50, 50);
const BASH = pidTgid(100, 100);
const CURL = pidTgid(200, 200);

function makeEvent(seq: number, kind: EventKind, payload: Record<string, unknown>): Event {
  return {
    event_id: `evt-${String(seq).padStart(4, "0")}`,
    seq,
    ts_monotonic_ns: EVENT_BASE_TS + seq * 1_000_000,
    ts_wall: wallFor(seq),
    sensor: "edge-node-01",
    event_kind: kind,
    ...payload,
  } as Event;
}

export const EVENTS: Event[] = [
  makeEvent(1, "EVENT_KIND_PROCESS_FORK", forkPayload(50, 50, 1_000_000)),
  makeEvent(2, "EVENT_KIND_PROCESS_EXEC_RESULT", execPayload(50, 50, 1_000_000, "/usr/sbin/sshd")),
  makeEvent(3, "EVENT_KIND_PROCESS_FORK", forkPayload(100, 100, 2_000_000, SSHD)),
  makeEvent(4, "EVENT_KIND_PROCESS_EXEC_RESULT", execPayload(100, 100, 2_000_000, "/usr/bin/bash")),
  makeEvent(5, "EVENT_KIND_PROCESS_FORK", forkPayload(200, 200, 3_000_000, BASH)),
  makeEvent(6, "EVENT_KIND_PROCESS_EXEC_RESULT", execPayload(200, 200, 3_000_000, "/usr/bin/curl")),
  makeEvent(7, "EVENT_KIND_PROCESS_EXIT", exitPayload(200, 200, 3_000_000, 0)),
  makeEvent(8, "EVENT_KIND_FILE_OPEN", {
    file_open: {
      task: { pid_tgid: BASH, task_start_time_ns: 2_000_000 },
      path: "/etc/passwd",
      flags: 0,
      succeeded: true,
      errno_value: 0,
      from_lsm: false,
    },
  }),
  makeEvent(9, "EVENT_KIND_NETWORK_CONNECT", {
    network_connect: {
      task: { pid_tgid: CURL, task_start_time_ns: 3_000_000 },
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
  }),
  makeEvent(10, "EVENT_KIND_DNS_PACKET", {
    dns_packet: {
      task: { pid_tgid: CURL, task_start_time_ns: 3_000_000 },
      is_query: true,
      transport: 17,
      packet_bytes: "AAABAAABAAAAAAAAAAdleGFtcGxlA2NvbQAAAQAB",
      truncated: false,
      is_egress: true,
    },
  }),
  makeEvent(11, "EVENT_KIND_SYSCALL_EXIT", {
    syscall_exit: {
      task: { pid_tgid: BASH, task_start_time_ns: 2_000_000 },
      syscall_nr: 59,
      ts_monotonic_ns: EVENT_BASE_TS + 11 * 1_000_000,
      elapsed_ns: 120000,
      no_return: false,
      errno_value: 0,
    },
  }),
  makeEvent(12, "EVENT_KIND_NETWORK_CONNECT", {
    network_connect: {
      task: { pid_tgid: BASH, task_start_time_ns: 2_000_000 },
      socket_cookie: 4300,
      family: 2,
      local_addr: "10.0.0.5",
      remote_addr: "198.51.100.7",
      local_port: 51002,
      remote_port: 8443,
      is_result: true,
      established: false,
      errno_value: 115, // EINPROGRESS — nonblocking connect, outcome pending
      from_cgroup: false,
    },
  }),
  makeEvent(13, "EVENT_KIND_NETWORK_CONNECT", {
    network_connect: {
      task: { pid_tgid: SSHD, task_start_time_ns: 1_000_000 },
      socket_cookie: 4301,
      family: 2,
      local_addr: "10.0.0.5",
      remote_addr: "203.0.113.9",
      local_port: 51004,
      remote_port: 80,
      is_result: true,
      established: false,
      errno_value: 111, // ECONNREFUSED
      from_cgroup: true,
    },
  }),
];

// ---------------------------------------------------------------------------
// Live-stream frames (WebSocket /events/stream, live.rs LiveEvent shape)
// ---------------------------------------------------------------------------

export function liveFrame(
  seq: number,
  kind: EventKind,
  payload: unknown,
  tsMonoNs: number,
): LiveEvent {
  return {
    seq,
    event_id: `live-${String(seq).padStart(4, "0")}`,
    event_kind: kind,
    node_name: "edge-node-01",
    cluster: "lab-west",
    ts_monotonic_ns: tsMonoNs,
    payload: JSON.stringify(payload),
  };
}

/** sshd → bash → curl (exited 0), as live frames seq 1..7. */
export const PROCESS_TREE_FRAMES: LiveEvent[] = [
  liveFrame(1, "EVENT_KIND_PROCESS_FORK", forkPayload(50, 50, 1_000_000), 1_000_000),
  liveFrame(
    2,
    "EVENT_KIND_PROCESS_EXEC_RESULT",
    execPayload(50, 50, 1_000_000, "/usr/sbin/sshd"),
    2_000_000,
  ),
  liveFrame(3, "EVENT_KIND_PROCESS_FORK", forkPayload(100, 100, 2_000_000, SSHD), 3_000_000),
  liveFrame(
    4,
    "EVENT_KIND_PROCESS_EXEC_RESULT",
    execPayload(100, 100, 2_000_000, "/usr/bin/bash"),
    4_000_000,
  ),
  liveFrame(5, "EVENT_KIND_PROCESS_FORK", forkPayload(200, 200, 3_000_000, BASH), 5_000_000),
  liveFrame(
    6,
    "EVENT_KIND_PROCESS_EXEC_RESULT",
    execPayload(200, 200, 3_000_000, "/usr/bin/curl"),
    6_000_000,
  ),
  liveFrame(7, "EVENT_KIND_PROCESS_EXIT", exitPayload(200, 200, 3_000_000, 0), 7_000_000),
];

/** Three plain file_open frames for generic stream tests (seq 1..3). */
export function fileOpenFrames(startSeq = 1, startTs = 1_000_000): LiveEvent[] {
  const paths = ["/etc/passwd", "/etc/hostname", "/var/log/audit.log"];
  return paths.map((path, i) =>
    liveFrame(
      startSeq + i,
      "EVENT_KIND_FILE_OPEN",
      {
        file_open: {
          task: { pid_tgid: BASH, task_start_time_ns: 2_000_000 },
          path,
          flags: 0,
          succeeded: true,
          errno_value: 0,
          from_lsm: false,
        },
      },
      startTs + i * 1_000_000,
    ),
  );
}

// ---------------------------------------------------------------------------
// REST mock
// ---------------------------------------------------------------------------

export interface RecordedRequest {
  method: string;
  pathname: string;
  search: string;
}

type RouteFn = (route: Route, url: URL) => void | Promise<void>;

interface Entry {
  delayMs: number;
  handle: RouteFn;
}

export interface ApiMock {
  /** Serve a static JSON body (200) for an exact pathname. */
  set(pathname: string, body: unknown): void;
  /** Serve with a custom handler (route + parsed URL). */
  setHandler(key: string, fn: RouteFn): void;
  /** Respond with an error status + `{error}` body. */
  fail(pathname: string, status?: number, message?: string): void;
  /** Add mock-side latency before the current handler runs. */
  delay(pathname: string, ms: number): void;
  /** Every intercepted API request, in order. */
  readonly requests: RecordedRequest[];
}

const API_PATH_RE = /^\/(health|compatibility|events|alerts|rules|policies|agents|drops)(\/.*)?$/;

/** Synthetic keys for parameterized policy routes. */
const POLICY_PATTERNS: ReadonlyArray<{ re: RegExp; key: string }> = [
  { re: /^\/policies\/[^/]+\/acks$/, key: "policy:acks" },
  { re: /^\/policies\/[^/]+\/rollback$/, key: "policy:rollback" },
  { re: /^\/policies\/[^/]+$/, key: "policy:version" },
];

function resolveKey(pathname: string): string {
  for (const { re, key } of POLICY_PATTERNS) {
    if (re.test(pathname)) return key;
  }
  return pathname;
}

function fulfillJson(route: Route, status: number, body: unknown): Promise<void> {
  return route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    globalThis.setTimeout(resolve, ms);
  });
}

export async function installApiMocks(page: Page): Promise<ApiMock> {
  const handlers = new Map<string, Entry>();
  const requests: RecordedRequest[] = [];

  const mock: ApiMock = {
    set(pathname, body) {
      handlers.set(pathname, { delayMs: 0, handle: (route) => fulfillJson(route, 200, body) });
    },
    setHandler(key, fn) {
      const prev = handlers.get(key);
      handlers.set(key, { delayMs: prev?.delayMs ?? 0, handle: fn });
    },
    fail(pathname, status = 500, message = "e2e: forced failure") {
      handlers.set(pathname, {
        delayMs: 0,
        handle: (route) => fulfillJson(route, status, { error: message }),
      });
    },
    delay(pathname, ms) {
      const prev = handlers.get(pathname);
      if (prev === undefined) {
        handlers.set(pathname, { delayMs: ms, handle: (route) => fulfillJson(route, 200, {}) });
      } else {
        prev.delayMs = ms;
      }
    },
    requests,
  };

  // ---- defaults -----------------------------------------------------------
  mock.set("/health", HEALTH);
  mock.set("/compatibility", COMPATIBILITY);
  mock.setHandler("/events", (route, url) => {
    const kind = url.searchParams.get("event_kind");
    let events = EVENTS;
    if (kind !== null) events = events.filter((e) => e.event_kind === kind);
    const limitRaw = url.searchParams.get("limit");
    if (limitRaw !== null) {
      const limit = Number.parseInt(limitRaw, 10);
      if (!Number.isNaN(limit)) events = events.slice(0, limit);
    }
    return fulfillJson(route, 200, { events });
  });
  mock.setHandler("/alerts", (route, url) => {
    const cursor = url.searchParams.get("cursor");
    return cursor === "page-2"
      ? fulfillJson(route, 200, { alerts: ALERTS_PAGE_2 })
      : fulfillJson(route, 200, { alerts: ALERTS_PAGE_1, next_cursor: "page-2" });
  });
  mock.set("/rules", { rules: RULES });
  mock.set("/rules/validate", { valid: true, errors: [], warnings: [] });
  mock.set("/rules/test", { matched: true, score: 0.92, field_matches: { event_kind: true } });
  mock.set("/policies", { policies: POLICIES });
  mock.set("/policies/stage", { committed_count: 0, ack_count: 2, rejected_count: 0 });
  mock.set("/policies/commit", { committed_count: 2, ack_count: 2, rejected_count: 0 });
  mock.setHandler("policy:version", (route) => fulfillJson(route, 200, POLICIES[2]));
  mock.setHandler("policy:acks", (route) => fulfillJson(route, 200, { acks: POLICY_ACKS }));
  mock.setHandler("policy:rollback", (route) =>
    fulfillJson(route, 200, { committed_count: 2, ack_count: 2, rejected_count: 0 }),
  );
  mock.set("/agents", { agents: AGENTS });
  mock.set("/drops", DROPS);

  // ---- interceptor ----------------------------------------------------------
  await page.route(
    (u) => API_PATH_RE.test(new URL(u).pathname),
    async (route) => {
      const req = route.request();
      const resourceType = req.resourceType();
      // Never intercept document navigation (SPA routes share API pathnames)
      // or Vite assets/HMR — only the fetch() API surface.
      if (resourceType !== "xhr" && resourceType !== "fetch") {
        await route.fallback();
        return;
      }
      const url = new URL(req.url());
      requests.push({ method: req.method(), pathname: url.pathname, search: url.search });
      const entry = handlers.get(resolveKey(url.pathname));
      if (entry === undefined) {
        await fulfillJson(route, 500, { error: `e2e: unmocked API path ${url.pathname}` });
        return;
      }
      if (entry.delayMs > 0) await sleep(entry.delayMs);
      await entry.handle(route, url);
    },
  );

  return mock;
}

// ---------------------------------------------------------------------------
// WebSocket mock (/events/stream)
// ---------------------------------------------------------------------------

export interface StreamController {
  /** Connection URLs in order — inspect query params (since_ts cursor). */
  readonly urls: string[];
  readonly connections: WebSocketRoute[];
  /** Per-connection script hook; set before page.goto(). */
  onConnect: ((ws: WebSocketRoute, url: URL, index: number) => void) | null;
  /** Send a LiveEvent frame to every open connection. */
  send(frame: LiveEvent): void;
  sendRaw(data: string): void;
  /** Close every open connection from the server side. */
  closeAll(code?: number, reason?: string): void;
  waitForConnections(n: number): Promise<void>;
}

export async function installStreamMock(page: Page): Promise<StreamController> {
  const urls: string[] = [];
  const connections: WebSocketRoute[] = [];
  const open = new Set<WebSocketRoute>();
  let waiters: Array<{ n: number; resolve: () => void }> = [];

  const ctl: StreamController = {
    urls,
    connections,
    onConnect: null,
    send(frame) {
      ctl.sendRaw(JSON.stringify(frame));
    },
    sendRaw(data) {
      for (const ws of open) ws.send(data);
    },
    closeAll(code = 1011, reason = "e2e close") {
      for (const ws of open) ws.close({ code, reason });
    },
    waitForConnections(n) {
      if (connections.length >= n) return Promise.resolve();
      return new Promise((resolve) => {
        waiters.push({ n, resolve });
      });
    },
  };

  await page.routeWebSocket(
    (u) => new URL(u).pathname === "/events/stream",
    (ws) => {
      urls.push(ws.url());
      connections.push(ws);
      open.add(ws);
      ws.onClose(() => {
        open.delete(ws);
      });
      const index = connections.length - 1;
      const ready = waiters.filter((w) => connections.length >= w.n);
      waiters = waiters.filter((w) => connections.length < w.n);
      for (const w of ready) w.resolve();
      ctl.onConnect?.(ws, new URL(ws.url()), index);
    },
  );

  return ctl;
}
