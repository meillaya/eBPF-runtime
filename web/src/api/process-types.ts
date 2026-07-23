// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Process-tree domain types. The wire surface delivers raw fork/exec/exit
// events (openapi Event payloads); the client folds them into a forest of
// ProcessRecords. Identity is generation-based: a process is identified by
// (pid, task_start_time) — NEVER by PID alone, because PIDs are reused.
// `generation` is the ordinal of this identity among all identities seen
// for the same PID inside the observation window (G1, G2, …; G>1 = reuse).

/** One normalized fork/exec/exit observation, source-agnostic. */
export interface ProcessSourceEvent {
  kind: "fork" | "exec" | "exit";
  seq: number;
  tsMonoNs: number;
  /** Wall time of the event itself (REST events only; live frames lack it). */
  wallIso: string | undefined;
  pid: number;
  tgid: number;
  /** task_start_time_ns — the second half of the identity tuple. */
  startNs: number;
  parentPid: number | undefined;
  isThread: boolean;
  uid: number | undefined;
  gid: number | undefined;
  execPath: string | undefined;
  execSucceeded: boolean | undefined;
  errnoValue: number | undefined;
  exitCode: number | undefined;
  exitTs: number | undefined;
}

/**
 * One folded process/thread identity. `key` is `${pid}@${startNs}` — the
 * generation-scoped identity; UI must always present it with generation.
 */
export interface ProcessRecord {
  key: string;
  pid: number;
  tgid: number;
  startNs: number;
  /** Ordinal identity for this PID in the window (1 = first seen). */
  generation: number;
  /** True when another identity shares this PID (PID reuse observed). */
  reusedPid: boolean;
  isThread: boolean;
  forkTs: number;
  /** Derived wall start time (event wall ts back-projected to startNs). */
  wallStartIso: string | undefined;
  uid: number | undefined;
  gid: number | undefined;
  execPath: string | undefined;
  execFailed: boolean;
  execErrno: number | undefined;
  execTs: number | undefined;
  exited: boolean;
  exitCode: number | undefined;
  exitTs: number | undefined;
  parentPid: number | undefined;
  /** Resolved parent identity key (never invented — see ancestryIncomplete). */
  parentKey: string | undefined;
  /**
   * A parent PID was reported but no matching identity exists in the
   * window (observation started mid-flight, or events were lost). The
   * client MUST NOT invent ancestry — the UI marks the edge explicitly.
   */
  ancestryIncomplete: boolean;
  childKeys: string[];
}

/** One exec result, kept for the chronological exec timeline. */
export interface ExecEntry {
  /** Unique per event: `${seq}:${pid}@${startNs}`. */
  key: string;
  procKey: string;
  tsMonoNs: number;
  wallIso: string | undefined;
  pid: number;
  path: string;
  succeeded: boolean;
  errnoValue: number | undefined;
}

/** The folded forest plus derived stats. */
export interface ProcessForest {
  nodes: ReadonlyMap<string, ProcessRecord>;
  /** Keys with no resolved parent, first-seen order. */
  roots: readonly string[];
  /** Chronological (ascending ts) exec results. */
  execs: readonly ExecEntry[];
  /** Recently touched keys — drives the row-in animation in live mode. */
  recentKeys: readonly string[];
  processCount: number;
  threadCount: number;
  exitedCount: number;
  /** Count of ancestry-incomplete (orphan-edge) nodes. */
  orphanCount: number;
  maxGeneration: number;
  firstTs: number | undefined;
  lastTs: number | undefined;
}

/** One visible row after flattening the forest with expansion state. */
export interface VisibleRow {
  key: string;
  depth: number;
  hasChildren: boolean;
  expanded: boolean;
  setSize: number;
  posInSet: number;
  parentKey: string | undefined;
  /** Dashed guide segment: this node's parent edge is missing. */
  dashedGuide: boolean;
}
