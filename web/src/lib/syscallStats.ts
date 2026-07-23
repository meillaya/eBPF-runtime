// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Aggregate SYSCALL_ENTER/EXIT events into histogram + percentile +
// orphan statistics for one fetched window. Orphans are multiset
// differences per (tgid, nr) — window-relative by construction.
import type { Event } from "../api/event-types";
import {
  buildHistogram,
  computePercentiles,
  type HistogramBucket,
  type LatencyPercentiles,
  matchOrphans,
  syscallName,
} from "./histogram";

export interface PerSyscall {
  nr: number;
  name: string;
  count: number;
  p50: number | null;
  p99: number | null;
  maxNs: number;
  noReturn: number;
}

export interface SyscallStats {
  buckets: HistogramBucket[];
  percentiles: LatencyPercentiles;
  sampleCount: number;
  sumNs: number;
  enterCount: number;
  noReturn: number;
  orphanEnter: number;
  orphanExit: number;
  perSyscall: PerSyscall[];
}

export function computeStats(
  events: ReadonlyArray<Event>,
  allowlist: ReadonlyArray<number>,
): SyscallStats {
  const allowed = allowlist.length > 0 ? new Set(allowlist) : null;
  const samples: number[] = [];
  const enterKeys: string[] = [];
  const exitKeys: string[] = [];
  let enterCount = 0;
  let noReturn = 0;
  const byNr = new Map<number, { latencies: number[]; noReturn: number }>();

  for (const e of events) {
    const enter = e.syscall_enter;
    if (enter !== undefined) {
      if (allowed !== null && !allowed.has(enter.syscall_nr)) continue;
      enterCount += 1;
      enterKeys.push(`${enter.task.pid_tgid}:${enter.syscall_nr}`);
      continue;
    }
    const exit = e.syscall_exit;
    if (exit === undefined) continue;
    if (allowed !== null && !allowed.has(exit.syscall_nr)) continue;
    exitKeys.push(`${exit.task.pid_tgid}:${exit.syscall_nr}`);
    samples.push(exit.elapsed_ns);
    if (exit.no_return) noReturn += 1;
    const entry = byNr.get(exit.syscall_nr) ?? { latencies: [], noReturn: 0 };
    entry.latencies.push(exit.elapsed_ns);
    if (exit.no_return) entry.noReturn += 1;
    byNr.set(exit.syscall_nr, entry);
  }

  samples.sort((a, b) => a - b);
  const orphans = matchOrphans(enterKeys, exitKeys);

  const perSyscall: PerSyscall[] = [...byNr.entries()]
    .map(([nr, entry]) => {
      const sorted = [...entry.latencies].sort((a, b) => a - b);
      const pcts = computePercentiles(sorted);
      return {
        nr,
        name: syscallName(nr),
        count: sorted.length,
        p50: pcts.p50,
        p99: pcts.p99,
        maxNs: sorted[sorted.length - 1] ?? 0,
        noReturn: entry.noReturn,
      };
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 12);

  return {
    buckets: buildHistogram(samples),
    percentiles: computePercentiles(samples),
    sampleCount: samples.length,
    sumNs: samples.reduce((acc, n) => acc + n, 0),
    enterCount,
    noReturn,
    orphanEnter: orphans.orphanEnter,
    orphanExit: orphans.orphanExit,
    perSyscall,
  };
}
