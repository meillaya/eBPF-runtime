// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Generic event feed for the telemetry views: one hook, two engines.
//   live       — WebSocket stream (live.rs LiveEvent frames), payloads
//                parsed defensively into the openapi Event shape
//   historical — REST /events with opaque cursor pagination
// Kind filtering is server-side when exactly one kind is requested and
// client-side otherwise (the contract takes a single event_kind param).
// The time range is a monotonic window anchored to the newest event
// observed when the range was chosen — the browser cannot read the
// node's boot clock, so "now" is always "newest observed".
import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { api, type EventQuery } from "../api/client";
import type { Event, EventKind, LiveEvent } from "../api/event-types";
import { liveToEvent } from "../live/liveToEvent";
import { EventStream } from "../live/stream";

export type FeedMode = "live" | "historical";

export type FeedStatus =
  | "connecting"
  | "live"
  | "reconnecting"
  | "paused"
  | "failed"
  | "loading"
  | "ready"
  | "degraded"
  | "error";

interface HistState {
  events: Event[];
  nextCursor: string | undefined;
  status: "loading" | "ready" | "degraded" | "error";
  error: Error | null;
}

export interface EventsFeedOptions {
  /** Stable (module-level) array — used in effect dependencies. */
  kinds: ReadonlyArray<EventKind>;
  mode: FeedMode;
  /** Window size chosen in the toolbar; 0 = full recall. */
  rangeSec: number;
  /** Historical cursor (ignored in live mode). */
  cursor?: string | undefined;
  /** "all" or a cluster name (live frames only; REST is proxy-scoped). */
  cluster?: string;
  limit?: number;
}

export interface EventsFeed {
  events: Event[];
  status: FeedStatus;
  error: Error | null;
  nextCursor: string | undefined;
  refetch: () => void;
  /** Live-engine telemetry (zeros in historical mode). */
  receivedTotal: number;
  droppedTotal: number;
  lastSeq: number | null;
  attempts: number;
  /** Cluster names observed on the live stream so far. */
  clusters: string[];
  togglePause: () => void;
  restart: () => void;
}

const IDLE_STREAM = {
  status: "connecting" as const,
  events: [] as LiveEvent[],
  receivedTotal: 0,
  droppedTotal: 0,
  lastSeq: null,
  attempts: 0,
  lastError: null,
};

export function useEvents(opts: EventsFeedOptions): EventsFeed {
  const { kinds, mode, rangeSec, cursor, cluster, limit } = opts;
  const clusterKey = cluster ?? "all";

  // ---- monotonic anchor: newest ts observed across either engine ----
  const anchorRef = useRef(0);
  const [sinceTs, setSinceTs] = useState<number | undefined>(undefined);
  useEffect(() => {
    setSinceTs(
      rangeSec > 0 && anchorRef.current > 0 ? anchorRef.current - rangeSec * 1e9 : undefined,
    );
  }, [rangeSec]);

  // ---- live engine (WebSocket) ----
  const live = mode === "live";
  const streamRef = useRef<EventStream | null>(null);
  if (streamRef.current === null) streamRef.current = new EventStream();
  const stream = streamRef.current;
  const subscribe = useCallback((onChange: () => void) => stream.subscribe(onChange), [stream]);
  const snap = useSyncExternalStore(subscribe, () => (live ? stream.getSnapshot() : IDLE_STREAM));
  useEffect(() => {
    if (!live) return;
    stream.start();
    return () => {
      stream.stop();
    };
  }, [live, stream]);

  const togglePause = useCallback(() => {
    const s = stream.getSnapshot().status;
    if (s === "paused") stream.resume();
    else if (s !== "closed" && s !== "failed") stream.pause();
  }, [stream]);
  const restart = useCallback(() => {
    stream.clear();
    stream.start();
  }, [stream]);

  const liveView = useMemo(() => {
    if (!live) return { events: [] as Event[], clusters: [] as string[] };
    const events: Event[] = [];
    const clusterSet = new Set<string>();
    for (let i = snap.events.length - 1; i >= 0; i--) {
      const frame = snap.events[i];
      if (frame === undefined) continue;
      clusterSet.add(frame.cluster);
      if (clusterKey !== "all" && frame.cluster !== clusterKey) continue;
      const event = liveToEvent(frame);
      if (event === null) continue;
      if (kinds.length > 0 && !kinds.includes(event.event_kind)) continue;
      events.push(event);
    }
    return { events, clusters: [...clusterSet].sort() };
  }, [live, snap.events, kinds, clusterKey]);

  // ---- historical engine (REST /events) ----
  const [hist, setHist] = useState<HistState>({
    events: [],
    nextCursor: undefined,
    status: "loading",
    error: null,
  });
  const [tick, setTick] = useState(0);
  // biome-ignore lint/correctness/useExhaustiveDependencies: tick is an intentional extra dep — bumping it forces a manual refetch
  useEffect(() => {
    if (live) return;
    let cancelled = false;
    const query: EventQuery = { limit: limit ?? 200 };
    if (cursor !== undefined) query.cursor = cursor;
    if (sinceTs !== undefined) query.since_ts_monotonic_ns = sinceTs;
    if (kinds.length === 1 && kinds[0] !== undefined) query.event_kind = kinds[0];
    void api.listEvents(query).then(
      (batch) => {
        if (cancelled) return;
        const kindSet = new Set(kinds);
        const events = batch.events.filter((e) => kindSet.size === 0 || kindSet.has(e.event_kind));
        for (const e of events) {
          if (e.ts_monotonic_ns > anchorRef.current) anchorRef.current = e.ts_monotonic_ns;
        }
        setHist({ events, nextCursor: batch.next_cursor, status: "ready", error: null });
      },
      (cause: unknown) => {
        if (cancelled) return;
        const error = cause instanceof Error ? cause : new Error(String(cause));
        setHist((h) => ({
          ...h,
          status: h.events.length > 0 ? "degraded" : "error",
          error,
        }));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [live, kinds, cursor, sinceTs, limit, tick]);

  // keep the anchor fresh from live frames too
  useEffect(() => {
    for (const frame of snap.events) {
      if (frame.ts_monotonic_ns > anchorRef.current) anchorRef.current = frame.ts_monotonic_ns;
    }
  }, [snap.events]);

  const refetch = useCallback(() => {
    if (live) restart();
    else setTick((t) => t + 1);
  }, [live, restart]);

  if (live) {
    const status: FeedStatus = snap.status === "closed" ? "connecting" : snap.status;
    return {
      events: liveView.events,
      status,
      error: snap.lastError === null ? null : new Error(snap.lastError),
      nextCursor: undefined,
      refetch,
      receivedTotal: snap.receivedTotal,
      droppedTotal: snap.droppedTotal,
      lastSeq: snap.lastSeq,
      attempts: snap.attempts,
      clusters: liveView.clusters,
      togglePause,
      restart,
    };
  }
  return {
    events: hist.events,
    status: hist.status,
    error: hist.error,
    nextCursor: hist.nextCursor,
    refetch,
    receivedTotal: 0,
    droppedTotal: 0,
    lastSeq: null,
    attempts: 0,
    clusters: [],
    togglePause,
    restart,
  };
}
