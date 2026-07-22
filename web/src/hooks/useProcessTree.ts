// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Data hooks for the process-tree view. Two sources, one state shape:
//   * live       — WebSocket stream, forest folded from buffered frames
//   * historical — REST /events (fork+exec+exit), one-shot fold per range
import { useMemo } from "react";
import { api } from "../api/client";
import type { Event } from "../api/event-types";
import type { ProcessForest, ProcessSourceEvent } from "../api/process-types";
import { type QueryStatus, useQuery } from "../api/query";
import { buildForest, normalizeEvent, parseLiveProcessFrame } from "../lib/process-tree";
import type { StreamStatus } from "../live/stream";
import { useEventStream } from "../live/useEventStream";

export interface ProcessTreeState {
  forest: ProcessForest | null;
  status: QueryStatus;
  error: Error | null;
}

export interface LiveProcessTreeState extends ProcessTreeState {
  streamStatus: StreamStatus;
  receivedTotal: number;
  droppedTotal: number;
  attempts: number;
  lastError: string | null;
  togglePause: () => void;
  restart: () => void;
}

function isProcessEvent(e: ProcessSourceEvent | null): e is ProcessSourceEvent {
  return e !== null;
}

/** Forest folded from the live stream buffer (bounded, seq-deduped). */
export function useLiveProcessTree(): LiveProcessTreeState {
  const stream = useEventStream("all");
  const { events, status, receivedTotal, droppedTotal, attempts, lastError } = stream;

  const forest = useMemo<ProcessForest | null>(() => {
    if (events.length === 0) return null;
    const normalized = events.map(parseLiveProcessFrame).filter(isProcessEvent);
    return buildForest(normalized);
  }, [events]);

  const stateStatus: QueryStatus = useMemo(() => {
    const hasData = forest !== null && forest.nodes.size > 0;
    if (hasData) {
      return status === "live" || status === "paused" ? "ready" : "degraded";
    }
    if (status === "failed") return "error";
    return status === "live" || status === "paused" ? "ready" : "loading";
  }, [forest, status]);

  return {
    forest,
    status: stateStatus,
    error: lastError === null ? null : new Error(lastError),
    streamStatus: status,
    receivedTotal,
    droppedTotal,
    attempts,
    lastError,
    togglePause: stream.togglePause,
    restart: stream.restart,
  };
}

const HIST_PAGE_LIMIT = 400;
const NS_PER_MIN = 60_000_000_000;

async function fetchHistoricalForest(rangeMin: number | null): Promise<ProcessForest> {
  const kinds = [
    "EVENT_KIND_PROCESS_FORK",
    "EVENT_KIND_PROCESS_EXEC_RESULT",
    "EVENT_KIND_PROCESS_EXIT",
  ] as const;
  const pages = await Promise.all(
    kinds.map((eventKind) => api.listEvents({ event_kind: eventKind, limit: HIST_PAGE_LIMIT })),
  );
  const merged: Event[] = pages.flatMap((page) => page.events);
  let normalized = merged.map(normalizeEvent).filter(isProcessEvent);
  if (rangeMin !== null && normalized.length > 0) {
    const refTs = normalized.reduce((max, e) => Math.max(max, e.tsMonoNs), 0);
    const cutoff = refTs - rangeMin * NS_PER_MIN;
    normalized = normalized.filter((e) => e.tsMonoNs >= cutoff);
  }
  return buildForest(normalized);
}

export interface HistoricalProcessTreeState extends ProcessTreeState {
  fetchedAt: number;
  refetch: () => void;
}

/** Forest from the historical /events API for a trailing time window. */
export function useHistoricalProcessTree(rangeMin: number | null): HistoricalProcessTreeState {
  const key = `process-tree:historical:${rangeMin === null ? "window" : rangeMin}`;
  const query = useQuery<ProcessForest>(key, () => fetchHistoricalForest(rangeMin));
  return {
    forest: query.data,
    status: query.status,
    error: query.error,
    fetchedAt: query.fetchedAt,
    refetch: query.refetch,
  };
}
