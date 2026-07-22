// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Syscall-latency histogram math. Buckets are log-decades of wall time
// (SYSCALL_EXIT.elapsed_ns is CLOCK_MONOTONIC/boot-clock wall time —
// never CPU time). Pure functions; the views own all interpretation.

/** Bucket upper edges in ns: 1µs, 10µs, 100µs, 1ms, 10ms, 100ms, 1s, 10s. */
export const LATENCY_EDGES_NS: readonly number[] = [
  1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000, 1_000_000_000, 10_000_000_000,
];

export interface HistogramBucket {
  index: number;
  label: string;
  count: number;
  sumNs: number;
}

function bucketLabel(index: number): string {
  if (index === 0) return "<1µs";
  if (index > LATENCY_EDGES_NS.length - 1) return "≥10s";
  const lo = LATENCY_EDGES_NS[index - 1] ?? 0;
  const hi = LATENCY_EDGES_NS[index] ?? 0;
  return `${formatNs(lo)}–${formatNs(hi)}`;
}

export function bucketIndexFor(ns: number): number {
  for (let i = 0; i < LATENCY_EDGES_NS.length; i++) {
    if (ns < (LATENCY_EDGES_NS[i] ?? Number.POSITIVE_INFINITY)) return i;
  }
  return LATENCY_EDGES_NS.length; // ≥10s
}

/** 9 buckets (below 1µs … 10s+), each with count and wall-time sum. */
export function buildHistogram(samples: ReadonlyArray<number>): HistogramBucket[] {
  const buckets: HistogramBucket[] = Array.from(
    { length: LATENCY_EDGES_NS.length + 1 },
    (_, i) => ({
      index: i,
      label: bucketLabel(i),
      count: 0,
      sumNs: 0,
    }),
  );
  for (const ns of samples) {
    const bucket = buckets[bucketIndexFor(ns)];
    if (bucket === undefined) continue;
    bucket.count += 1;
    bucket.sumNs += ns;
  }
  return buckets;
}

/** Linear-interpolated percentile over an ASC-sorted sample array. */
export function percentile(sortedAsc: ReadonlyArray<number>, p: number): number | null {
  if (sortedAsc.length === 0) return null;
  const rank = (p / 100) * (sortedAsc.length - 1);
  const lo = Math.floor(rank);
  const hi = Math.ceil(rank);
  const a = sortedAsc[lo];
  const b = sortedAsc[hi];
  if (a === undefined) return null;
  if (b === undefined || lo === hi) return a;
  return a + (b - a) * (rank - lo);
}

export interface LatencyPercentiles {
  p50: number | null;
  p95: number | null;
  p99: number | null;
  p999: number | null;
}

export function computePercentiles(sortedAsc: ReadonlyArray<number>): LatencyPercentiles {
  return {
    p50: percentile(sortedAsc, 50),
    p95: percentile(sortedAsc, 95),
    p99: percentile(sortedAsc, 99),
    p999: percentile(sortedAsc, 99.9),
  };
}

/** ns → "812ns" / "23.4µs" / "1.82ms" / "4.20s" (2 decimals max). */
export function formatNs(ns: number): string {
  if (ns < 1_000) return `${Math.round(ns)}ns`;
  if (ns < 1_000_000) return `${trimZero((ns / 1_000).toFixed(1))}µs`;
  if (ns < 1_000_000_000) return `${trimZero((ns / 1_000_000).toFixed(2))}ms`;
  return `${trimZero((ns / 1_000_000_000).toFixed(2))}s`;
}

function trimZero(s: string): string {
  return s.endsWith(".00") || s.endsWith(".0") ? s.replace(/\.?0+$/, "") : s;
}

/**
 * Orphan accounting within one fetched window: enters with no observed
 * exit (multiset difference per tgid+nr) and exits with no observed
 * enter. Window-relative by construction — the views must say so.
 */
export function matchOrphans(
  enterKeys: ReadonlyArray<string>,
  exitKeys: ReadonlyArray<string>,
): { orphanEnter: number; orphanExit: number } {
  const enters = new Map<string, number>();
  for (const key of enterKeys) enters.set(key, (enters.get(key) ?? 0) + 1);
  let orphanExit = 0;
  for (const key of exitKeys) {
    const left = enters.get(key) ?? 0;
    if (left > 0) enters.set(key, left - 1);
    else orphanExit += 1;
  }
  let orphanEnter = 0;
  for (const left of enters.values()) orphanEnter += left;
  return { orphanEnter, orphanExit };
}

/** Common x86_64 syscall numbers (abi/asm-generic names). */
const SYSCALL_NAMES: ReadonlyMap<number, string> = new Map([
  [0, "read"],
  [1, "write"],
  [2, "open"],
  [3, "close"],
  [4, "stat"],
  [5, "fstat"],
  [7, "poll"],
  [8, "lseek"],
  [9, "mmap"],
  [10, "mprotect"],
  [11, "munmap"],
  [12, "brk"],
  [13, "rt_sigaction"],
  [14, "rt_sigprocmask"],
  [16, "ioctl"],
  [17, "pread64"],
  [18, "pwrite64"],
  [19, "readv"],
  [20, "writev"],
  [21, "access"],
  [22, "pipe"],
  [23, "select"],
  [28, "madvise"],
  [32, "dup"],
  [33, "dup2"],
  [35, "nanosleep"],
  [39, "getpid"],
  [41, "socket"],
  [42, "connect"],
  [43, "accept"],
  [44, "sendto"],
  [45, "recvfrom"],
  [46, "sendmsg"],
  [47, "recvmsg"],
  [48, "shutdown"],
  [49, "bind"],
  [50, "listen"],
  [56, "clone"],
  [57, "fork"],
  [58, "vfork"],
  [59, "execve"],
  [60, "exit"],
  [61, "wait4"],
  [62, "kill"],
  [72, "fcntl"],
  [78, "getdents"],
  [79, "getcwd"],
  [80, "chdir"],
  [87, "unlink"],
  [89, "readlink"],
  [90, "chmod"],
  [96, "gettimeofday"],
  [102, "getuid"],
  [158, "arch_prctl"],
  [186, "gettid"],
  [202, "futex"],
  [217, "getdents64"],
  [228, "clock_gettime"],
  [230, "clock_nanosleep"],
  [231, "exit_group"],
  [232, "epoll_wait"],
  [233, "epoll_ctl"],
  [257, "openat"],
  [258, "mkdirat"],
  [263, "unlinkat"],
  [264, "renameat"],
  [268, "fchmodat"],
  [269, "faccessat"],
  [270, "pselect6"],
  [271, "ppoll"],
  [281, "epoll_pwait"],
  [284, "eventfd"],
  [288, "accept4"],
  [290, "eventfd2"],
  [291, "epoll_create1"],
  [292, "dup3"],
  [293, "pipe2"],
  [302, "renameat2"],
  [316, "execveat"],
  [318, "getrandom"],
  [319, "memfd_create"],
  [332, "statx"],
  [435, "clone3"],
  [439, "faccessat2"],
]);

export function syscallName(nr: number): string {
  return SYSCALL_NAMES.get(nr) ?? `#${nr}`;
}

/** Parse "1, 42 ,59" → sorted unique numbers; ignores garbage tokens. */
export function parseAllowlist(input: string): number[] {
  const out = new Set<number>();
  for (const token of input.split(/[,\s]+/)) {
    if (token === "") continue;
    const n = Number.parseInt(token, 10);
    if (Number.isInteger(n) && n >= 0) out.add(n);
  }
  return [...out].sort((a, b) => a - b);
}
