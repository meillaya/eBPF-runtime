// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// WebSocket client for /events/stream (openapi subprotocol
// kernel-v1.event-stream.v1; frames are live.rs LiveEvent JSON).
//   * seq is the resume cursor — on reconnect we re-request from the
//     last seen monotonic ts and drop frames with seq <= lastSeq
//   * 1013 = slow-consumer shed → reconnect immediately
//   * bounded ring buffer (drop-oldest) mirrors the server's cap
//   * exponential backoff + jitter, capped attempts → `failed`

import { parseLiveFrame, streamUrl } from "../api/client";
import type { EventKind, LiveEvent } from "../api/event-types";

export type StreamStatus = "connecting" | "live" | "reconnecting" | "paused" | "failed" | "closed";

export interface StreamSnapshot {
  status: StreamStatus;
  events: LiveEvent[];
  receivedTotal: number;
  droppedTotal: number;
  lastSeq: number | null;
  attempts: number;
  lastError: string | null;
}

export interface StreamOptions {
  bufferCap?: number;
  maxAttempts?: number;
  sensor?: string;
  onStatus?: (status: StreamStatus) => void;
}

const DEFAULT_BUFFER_CAP = 500;
const DEFAULT_MAX_ATTEMPTS = 12;
const BASE_BACKOFF_MS = 500;
const MAX_BACKOFF_MS = 30_000;
const SLOW_CONSUMER_CODE = 1013;
export const STREAM_SUBPROTOCOL = "kernel-v1.event-stream.v1";

export class EventStream {
  private ws: WebSocket | null = null;
  private events: LiveEvent[] = [];
  private receivedTotal = 0;
  private droppedTotal = 0;
  private lastSeq: number | null = null;
  private sinceTs: number | null = null;
  private attempts = 0;
  private lastError: string | null = null;
  private status: StreamStatus = "closed";
  private stopped = true;
  private retryTimer: number | undefined;
  private readonly bufferCap: number;
  private readonly maxAttempts: number;
  private readonly sensor: string | undefined;
  private readonly onStatus: ((status: StreamStatus) => void) | undefined;
  private readonly listeners = new Set<() => void>();
  // useSyncExternalStore requires a stable snapshot between emissions
  private snap: StreamSnapshot = {
    status: "closed",
    events: [],
    receivedTotal: 0,
    droppedTotal: 0,
    lastSeq: null,
    attempts: 0,
    lastError: null,
  };

  constructor(opts: StreamOptions = {}) {
    this.bufferCap = opts.bufferCap ?? DEFAULT_BUFFER_CAP;
    this.maxAttempts = opts.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    if (opts.sensor !== undefined) this.sensor = opts.sensor;
    if (opts.onStatus !== undefined) this.onStatus = opts.onStatus;
  }

  subscribe(fn: () => void): () => void {
    this.listeners.add(fn);
    return () => {
      this.listeners.delete(fn);
    };
  }

  getSnapshot(): StreamSnapshot {
    return this.snap;
  }

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    this.attempts = 0;
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    if (this.retryTimer !== undefined) globalThis.clearTimeout(this.retryTimer);
    this.ws?.close(1000, "client stopped");
    this.ws = null;
    this.setStatus("closed");
  }

  pause(): void {
    if (this.status === "paused" || this.stopped) return;
    this.stopped = true;
    if (this.retryTimer !== undefined) globalThis.clearTimeout(this.retryTimer);
    this.ws?.close(1000, "client paused");
    this.ws = null;
    this.setStatus("paused");
  }

  resume(): void {
    if (this.status !== "paused") return;
    this.stopped = false;
    this.attempts = 0;
    this.connect();
  }

  clear(): void {
    this.events = [];
    this.droppedTotal = 0;
    this.emit();
  }

  private connect(): void {
    const params = new URLSearchParams();
    if (this.sinceTs !== null) params.set("since_ts_monotonic_ns", String(this.sinceTs));
    if (this.sensor !== undefined) params.set("sensor", this.sensor);

    let ws: WebSocket;
    try {
      ws = new WebSocket(streamUrl(params), STREAM_SUBPROTOCOL);
    } catch (cause) {
      this.scheduleRetry(`socket construction failed: ${String(cause)}`);
      return;
    }
    this.ws = ws;
    this.setStatus(this.attempts === 0 ? "connecting" : "reconnecting");

    ws.onopen = () => {
      this.attempts = 0;
      this.lastError = null;
      this.setStatus("live");
    };
    ws.onmessage = (ev: MessageEvent) => {
      if (typeof ev.data !== "string") return;
      const frame = parseLiveFrame(ev.data);
      if (frame === null) return;
      this.ingest(frame);
    };
    ws.onclose = (ev: CloseEvent) => {
      if (this.stopped) return;
      const reason = ev.reason !== "" ? ev.reason : `code ${ev.code}`;
      if (ev.code === SLOW_CONSUMER_CODE) {
        // server shed us for being slow — reconnect immediately
        this.lastError = `slow consumer shed (${reason})`;
        this.connect();
        return;
      }
      this.scheduleRetry(reason);
    };
    ws.onerror = () => {
      this.lastError = this.lastError ?? "socket error";
    };
  }

  private ingest(frame: LiveEvent): void {
    // seq-dedupe: the since_ts re-request window overlaps what we have
    if (this.lastSeq !== null && frame.seq <= this.lastSeq) return;
    this.lastSeq = frame.seq;
    this.sinceTs = frame.ts_monotonic_ns;
    this.receivedTotal += 1;
    const evicted = this.events.length + 1 - this.bufferCap;
    if (evicted > 0) this.droppedTotal += evicted;
    this.events =
      evicted > 0 ? [...this.events.slice(-(this.bufferCap - 1)), frame] : [...this.events, frame];
    this.emit();
  }

  private scheduleRetry(reason: string): void {
    this.lastError = reason;
    this.attempts += 1;
    if (this.attempts > this.maxAttempts) {
      // terminal until the operator calls start() again
      this.stopped = true;
      this.setStatus("failed");
      return;
    }
    this.setStatus("reconnecting");
    const exp = Math.min(MAX_BACKOFF_MS, BASE_BACKOFF_MS * 2 ** (this.attempts - 1));
    const jitter = Math.random() * exp * 0.3;
    this.retryTimer = globalThis.setTimeout(() => this.connect(), exp + jitter);
  }

  private setStatus(status: StreamStatus): void {
    if (this.status === status) return;
    this.status = status;
    this.onStatus?.(status);
    this.emit();
  }

  private emit(): void {
    this.snap = {
      status: this.status,
      events: this.events,
      receivedTotal: this.receivedTotal,
      droppedTotal: this.droppedTotal,
      lastSeq: this.lastSeq,
      attempts: this.attempts,
      lastError: this.lastError,
    };
    for (const fn of this.listeners) fn();
  }
}

export function eventKindFilter(
  events: ReadonlyArray<LiveEvent>,
  kind: EventKind | "all",
): LiveEvent[] {
  if (kind === "all") return [...events];
  return events.filter((e) => e.event_kind === kind);
}
