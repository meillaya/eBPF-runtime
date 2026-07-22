// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Pure process-forest builders. Fork/exec/exit events (REST Event payloads
// or live-stream frames) normalize into ProcessSourceEvents, fold into a
// ProcessForest with generation-based identity, and flatten into visible
// rows for the accessible tree. No React, no I/O — trivially testable.
import type { LiveEvent, ProcessExecResult, ProcessExit, ProcessFork } from "../api/event-types";
import type {
  ExecEntry,
  ProcessForest,
  ProcessRecord,
  ProcessSourceEvent,
  VisibleRow,
} from "../api/process-types";

const U32 = 4294967296;

/** pid_tgid (tgid << 32 | pid) → pid. Arithmetic, not bitwise (u64 > int32). */
export function pidOf(pidTgid: number): number {
  return pidTgid % U32;
}

/** pid_tgid → tgid (thread group leader pid). */
export function tgidOf(pidTgid: number): number {
  return Math.floor(pidTgid / U32);
}

/** Identity key: (pid, start_time). Never PID alone — PIDs are reused. */
export function procKey(pid: number, startNs: number): string {
  return `${pid}@${startNs}`;
}

/** Basename of an exec path for dense rows (full path goes to title/hover). */
export function execBasename(path: string): string {
  const i = path.lastIndexOf("/");
  return i === -1 ? path : path.slice(i + 1);
}

/** Back-project an event wall timestamp to the task start time. */
function deriveWallStart(
  wallIso: string | undefined,
  tsMonoNs: number,
  startNs: number,
): string | undefined {
  if (wallIso === undefined) return undefined;
  const wallMs = new Date(wallIso).getTime();
  if (Number.isNaN(wallMs) || startNs > tsMonoNs) return wallIso;
  return new Date(wallMs - (tsMonoNs - startNs) / 1e6).toISOString();
}

/** The subset of the openapi Event shape the forest fold consumes. */
interface EventLike {
  seq: number;
  ts_monotonic_ns: number;
  ts_wall?: string;
  process_fork?: ProcessFork;
  process_exec_result?: ProcessExecResult;
  process_exit?: ProcessExit;
}

/** Normalize one REST event; non-process events return null. */
export function normalizeEvent(ev: EventLike): ProcessSourceEvent | null {
  const base = {
    seq: ev.seq,
    tsMonoNs: ev.ts_monotonic_ns,
    wallIso: ev.ts_wall,
    parentPid: undefined as number | undefined,
    isThread: false,
    uid: undefined as number | undefined,
    gid: undefined as number | undefined,
    execPath: undefined as string | undefined,
    execSucceeded: undefined as boolean | undefined,
    errnoValue: undefined as number | undefined,
    exitCode: undefined as number | undefined,
    exitTs: undefined as number | undefined,
  };
  const fork = ev.process_fork;
  if (fork !== undefined && typeof fork.child?.pid_tgid === "number") {
    const child = fork.child;
    return {
      ...base,
      kind: "fork",
      pid: pidOf(child.pid_tgid),
      tgid: tgidOf(child.pid_tgid),
      startNs: child.task_start_time_ns ?? ev.ts_monotonic_ns,
      parentPid:
        typeof child.parent_pid_tgid === "number" ? pidOf(child.parent_pid_tgid) : undefined,
      isThread: fork.is_thread === true,
      uid: child.uid,
      gid: child.gid,
    };
  }
  const exec = ev.process_exec_result;
  if (exec !== undefined && typeof exec.task?.pid_tgid === "number") {
    const task = exec.task;
    return {
      ...base,
      kind: "exec",
      pid: pidOf(task.pid_tgid),
      tgid: tgidOf(task.pid_tgid),
      startNs: task.task_start_time_ns ?? ev.ts_monotonic_ns,
      parentPid: typeof task.parent_pid_tgid === "number" ? pidOf(task.parent_pid_tgid) : undefined,
      uid: task.uid,
      gid: task.gid,
      execPath: typeof exec.binary_path === "string" ? exec.binary_path : undefined,
      execSucceeded: exec.succeeded,
      errnoValue: exec.succeeded ? undefined : exec.errno_value,
    };
  }
  const exit = ev.process_exit;
  if (exit !== undefined && typeof exit.task?.pid_tgid === "number") {
    const task = exit.task;
    return {
      ...base,
      kind: "exit",
      pid: pidOf(task.pid_tgid),
      tgid: tgidOf(task.pid_tgid),
      startNs: task.task_start_time_ns ?? ev.ts_monotonic_ns,
      exitCode: exit.exit_code,
      exitTs: ev.ts_monotonic_ns,
    };
  }
  return null;
}

/**
 * Parse one live-stream frame (payload = redacted event JSON as string).
 * Defensive: unparseable or non-process payloads return null.
 */
export function parseLiveProcessFrame(frame: LiveEvent): ProcessSourceEvent | null {
  let value: unknown;
  try {
    value = JSON.parse(frame.payload);
  } catch {
    return null;
  }
  if (typeof value !== "object" || value === null) return null;
  const body = value as EventLike;
  if (
    body.process_fork === undefined &&
    body.process_exec_result === undefined &&
    body.process_exit === undefined
  ) {
    return null;
  }
  return normalizeEvent({ ...body, seq: frame.seq, ts_monotonic_ns: frame.ts_monotonic_ns });
}

function newRecord(key: string, ev: ProcessSourceEvent): ProcessRecord {
  return {
    key,
    pid: ev.pid,
    tgid: ev.tgid,
    startNs: ev.startNs,
    generation: 1,
    reusedPid: false,
    isThread: ev.isThread,
    forkTs: ev.tsMonoNs,
    wallStartIso: deriveWallStart(ev.wallIso, ev.tsMonoNs, ev.startNs),
    uid: ev.uid,
    gid: ev.gid,
    execPath: ev.execPath,
    execFailed: false,
    execErrno: undefined,
    execTs: undefined,
    exited: false,
    exitCode: undefined,
    exitTs: undefined,
    parentPid: ev.parentPid,
    parentKey: undefined,
    ancestryIncomplete: false,
    childKeys: [],
  };
}

/** Pick the candidate whose lifetime overlaps the child's fork time. */
function pickParent(
  candidates: readonly ProcessRecord[],
  child: ProcessRecord,
): ProcessRecord | undefined {
  let best: ProcessRecord | undefined;
  for (const c of candidates) {
    if (c.key === child.key || c.startNs > child.forkTs) continue;
    if (c.exitTs !== undefined && c.exitTs < child.forkTs) continue;
    if (best === undefined || c.startNs > best.startNs) best = c;
  }
  return best;
}

/** Fold normalized events (any order) into the forest. */
export function buildForest(events: readonly ProcessSourceEvent[]): ProcessForest {
  const sorted = events.slice().sort((a, b) => a.tsMonoNs - b.tsMonoNs || a.seq - b.seq);

  const nodes = new Map<string, ProcessRecord>();
  const order: string[] = [];
  const execs: ExecEntry[] = [];
  const recent: string[] = [];
  const touch = (key: string): void => {
    recent.push(key);
    if (recent.length > 8) recent.shift();
  };
  const upsert = (ev: ProcessSourceEvent): ProcessRecord => {
    const key = procKey(ev.pid, ev.startNs);
    const existing = nodes.get(key);
    if (existing !== undefined) return existing;
    const rec = newRecord(key, ev);
    nodes.set(key, rec);
    order.push(key);
    return rec;
  };

  for (const ev of sorted) {
    const rec = upsert(ev);
    touch(rec.key);
    if (ev.kind === "fork") {
      if (rec.parentPid === undefined) rec.parentPid = ev.parentPid;
      rec.wallStartIso = rec.wallStartIso ?? deriveWallStart(ev.wallIso, ev.tsMonoNs, ev.startNs);
    } else if (ev.kind === "exec") {
      if (rec.parentPid === undefined) rec.parentPid = ev.parentPid;
      if (ev.execPath !== undefined) rec.execPath = ev.execPath;
      rec.execTs = ev.tsMonoNs;
      rec.execFailed = ev.execSucceeded === false;
      rec.execErrno = rec.execFailed ? ev.errnoValue : undefined;
      rec.wallStartIso = rec.wallStartIso ?? deriveWallStart(ev.wallIso, ev.tsMonoNs, ev.startNs);
      execs.push({
        key: `${ev.seq}:${rec.key}`,
        procKey: rec.key,
        tsMonoNs: ev.tsMonoNs,
        wallIso: ev.wallIso,
        pid: ev.pid,
        path: ev.execPath ?? "(unknown)",
        succeeded: ev.execSucceeded !== false,
        errnoValue: ev.execSucceeded === false ? ev.errnoValue : undefined,
      });
    } else {
      rec.exited = true;
      rec.exitCode = ev.exitCode;
      rec.exitTs = ev.exitTs ?? ev.tsMonoNs;
    }
  }

  // Generation: ordinal of this (pid, startNs) identity among all distinct
  // start times observed for the PID. G>1 means PID reuse was observed.
  const startsByPid = new Map<number, number[]>();
  for (const rec of nodes.values()) {
    const starts = startsByPid.get(rec.pid);
    if (starts === undefined) startsByPid.set(rec.pid, [rec.startNs]);
    else if (!starts.includes(rec.startNs)) starts.push(rec.startNs);
  }
  for (const rec of nodes.values()) {
    const starts = startsByPid.get(rec.pid) ?? [rec.startNs];
    rec.generation = starts.indexOf(rec.startNs) + 1;
    rec.reusedPid = starts.length > 1;
  }

  // Ancestry: resolve parent edges only from observed identities. A missing
  // parent is marked, never invented. pid<=1 roots naturally (kernel/init).
  const procsByPid = new Map<number, ProcessRecord[]>();
  for (const rec of nodes.values()) {
    if (rec.isThread) continue;
    const list = procsByPid.get(rec.pid);
    if (list === undefined) procsByPid.set(rec.pid, [rec]);
    else list.push(rec);
  }
  for (const rec of nodes.values()) {
    let parent: ProcessRecord | undefined;
    if (rec.isThread) parent = pickParent(procsByPid.get(rec.tgid) ?? [], rec);
    if (parent === undefined && rec.parentPid !== undefined && rec.parentPid > 1) {
      parent = pickParent(procsByPid.get(rec.parentPid) ?? [], rec);
    }
    if (parent !== undefined) {
      rec.parentKey = parent.key;
      parent.childKeys.push(rec.key);
    } else if (rec.pid > 1 && (rec.parentPid !== undefined || rec.isThread)) {
      rec.ancestryIncomplete = true;
    }
  }
  const byFork = (a: string, b: string): number =>
    (nodes.get(a)?.forkTs ?? 0) - (nodes.get(b)?.forkTs ?? 0);
  for (const rec of nodes.values()) rec.childKeys.sort(byFork);

  const roots = order.filter((k) => nodes.get(k)?.parentKey === undefined);
  let processCount = 0;
  let threadCount = 0;
  let exitedCount = 0;
  let orphanCount = 0;
  let maxGeneration = 0;
  for (const rec of nodes.values()) {
    if (rec.isThread) threadCount += 1;
    else processCount += 1;
    if (rec.exited) exitedCount += 1;
    if (rec.ancestryIncomplete) orphanCount += 1;
    if (rec.generation > maxGeneration) maxGeneration = rec.generation;
  }
  return {
    nodes,
    roots,
    execs,
    recentKeys: recent,
    processCount,
    threadCount,
    exitedCount,
    orphanCount,
    maxGeneration,
    firstTs: sorted[0]?.tsMonoNs,
    lastTs: sorted[sorted.length - 1]?.tsMonoNs,
  };
}

/** DFS-flatten the forest into visible rows under the expansion state. */
export function flattenForest(forest: ProcessForest, expanded: ReadonlySet<string>): VisibleRow[] {
  const rows: VisibleRow[] = [];
  const walk = (keys: readonly string[], depth: number, parentKey: string | undefined): void => {
    keys.forEach((key, i) => {
      const node = forest.nodes.get(key);
      if (node === undefined) return;
      const hasChildren = node.childKeys.length > 0;
      const isExpanded = expanded.has(key);
      rows.push({
        key,
        depth,
        hasChildren,
        expanded: isExpanded,
        setSize: keys.length,
        posInSet: i + 1,
        parentKey,
        dashedGuide: node.ancestryIncomplete,
      });
      if (hasChildren && isExpanded) walk(node.childKeys, depth + 1, key);
    });
  };
  walk(forest.roots, 0, undefined);
  return rows;
}
