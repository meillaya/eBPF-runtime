// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Drop/loss telemetry hook. GET /drops returns free-form counter
// records (openapi additionalProperties: true), so every field is
// parsed defensively across the key conventions the agent emits
// (task-17 model: attempt / reserve_failure / commit / discard per
// source, plus sequence gaps and ring saturation). Counters are polled
// on their own key, independent of the event stream, and a rolling
// per-source loss-delta series feeds the sparklines.
import { useEffect, useMemo, useRef } from "react";
import { api } from "../api/client";
import { type QueryState, useQuery } from "../api/query";
import type { DropPage, DropRecord } from "../api/types";

export const SERIES_CAP = 48;

export interface DropCounters {
  source: string;
  attempt: number;
  reserveFailure: number;
  commit: number;
  discard: number;
  gaps: number;
  saturationPct: number;
  tsMono: number | null;
}

function num(rec: DropRecord, keys: readonly string[]): number {
  for (const key of keys) {
    const v = rec[key];
    if (typeof v === "number" && Number.isFinite(v)) return v;
    if (typeof v === "string" && v.trim() !== "" && Number.isFinite(Number(v))) return Number(v);
  }
  return 0;
}

function str(rec: DropRecord, keys: readonly string[]): string | null {
  for (const key of keys) {
    const v = rec[key];
    if (typeof v === "string" && v !== "") return v;
  }
  return null;
}

export function parseDropRecord(rec: DropRecord, index: number): DropCounters {
  const attempt = num(rec, ["attempt", "attempts", "attempt_total", "attempts_total"]);
  const reserveFailure = num(rec, [
    "reserve_failure",
    "reserve_failures",
    "ring_reserve_failure",
    "reserve_failure_total",
  ]);
  const commit = num(rec, ["commit", "commits", "commit_total", "commits_total"]);
  const discard = num(rec, ["discard", "discards", "discard_total", "discarded", "count"]);
  const gaps = num(rec, ["seq_gaps", "sequence_gaps", "gaps", "gap_count"]);
  const explicitSat = num(rec, ["saturation_pct", "ring_saturation_pct", "saturation_percent"]);
  const derived = attempt > 0 ? Math.min(100, Math.round((reserveFailure / attempt) * 100)) : 0;
  const tsRaw = num(rec, ["ts_monotonic_ns", "ts_mono_ns", "ts"]);
  return {
    source: str(rec, ["source", "sensor", "src"]) ?? `source-${index}`,
    attempt,
    reserveFailure,
    commit,
    discard,
    gaps,
    saturationPct: explicitSat > 0 ? explicitSat : derived,
    tsMono: tsRaw > 0 ? tsRaw : null,
  };
}

export interface DropSeriesState {
  query: QueryState<DropPage>;
  rows: DropCounters[];
  /** Per-source rolling loss deltas (reserve_failure + discard per poll). */
  series: ReadonlyMap<string, readonly number[]>;
  /** Per-source rolling sequence-gap deltas (one point per poll). */
  gapSeries: ReadonlyMap<string, readonly number[]>;
  /** Aggregate observed event rate (events/s) when timestamps allow it. */
  observedRate: number | null;
  totalDropped: number;
  totalGaps: number;
}

interface Sample {
  loss: number;
  gaps: number;
  attempt: number;
  ts: number | null;
}

export function useDropSeries(refreshMs = 5_000): DropSeriesState {
  const query = useQuery<DropPage>("drops:ops", () => api.listDrops({ limit: 200 }), refreshMs);
  const prevRef = useRef<Map<string, Sample>>(new Map());
  const seriesRef = useRef<Map<string, number[]>>(new Map());
  const gapSeriesRef = useRef<Map<string, number[]>>(new Map());
  const rateRef = useRef<number | null>(null);
  const seenRef = useRef(0);

  const rows = useMemo(
    () => (query.data === null ? [] : query.data.drops.map((rec, i) => parseDropRecord(rec, i))),
    [query.data],
  );

  useEffect(() => {
    if (query.data === null || query.fetchedAt === seenRef.current) return;
    seenRef.current = query.fetchedAt;
    let deltaAttempt = 0;
    let deltaSec = 0;
    for (const row of rows) {
      const loss = row.reserveFailure + row.discard;
      const prev = prevRef.current.get(row.source);
      let point = 0;
      if (prev !== undefined) {
        point = Math.max(0, loss - prev.loss);
        if (row.tsMono !== null && prev.ts !== null && row.tsMono > prev.ts) {
          deltaAttempt += Math.max(0, row.attempt - prev.attempt);
          deltaSec += (row.tsMono - prev.ts) / 1e9;
        }
      }
      prevRef.current.set(row.source, {
        loss,
        gaps: row.gaps,
        attempt: row.attempt,
        ts: row.tsMono,
      });
      const arr = seriesRef.current.get(row.source) ?? [];
      arr.push(point);
      if (arr.length > SERIES_CAP) arr.splice(0, arr.length - SERIES_CAP);
      seriesRef.current.set(row.source, arr);
      const gapArr = gapSeriesRef.current.get(row.source) ?? [];
      gapArr.push(prev === undefined ? 0 : Math.max(0, row.gaps - prev.gaps));
      if (gapArr.length > SERIES_CAP) gapArr.splice(0, gapArr.length - SERIES_CAP);
      gapSeriesRef.current.set(row.source, gapArr);
    }
    rateRef.current = deltaSec > 0 ? deltaAttempt / deltaSec : rateRef.current;
  }, [query.data, query.fetchedAt, rows]);

  const totalDropped = rows.reduce((acc, r) => acc + r.reserveFailure + r.discard, 0);
  const totalGaps = rows.reduce((acc, r) => acc + r.gaps, 0);

  return {
    query,
    rows,
    series: seriesRef.current,
    gapSeries: gapSeriesRef.current,
    observedRate: rateRef.current,
    totalDropped,
    totalGaps,
  };
}
