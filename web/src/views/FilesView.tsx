// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// File-operation view. Shows exactly what the sensor observed — never
// "complete file access". Result source is semantic: OWN_LSM (our own
// BPF LSM hook), PRIOR_LSM (an LSM deny that fired before ours, from
// LSM_DENY_OWN with own_deny=false), SYSCALL_FALLBACK (kprobe path used
// because the LSM hook was unavailable on this host).
import { useMemo, useState } from "react";
import type { Event, EventKind, Identity } from "../api/event-types";
import { EventToolbar } from "../components/EventToolbar";
import { FeedPanel } from "../components/FeedPanel";
import { ProcessCell } from "../components/ProcessCell";
import { type FeedMode, useEvents } from "../hooks/useEvents";
import { EACCES, EPERM, errnoLabel, fileOpenOp } from "../lib/decode";
import { cx, formatWall } from "../lib/format";
import type { Column } from "../ui/Table";

const KINDS: readonly EventKind[] = [
  "EVENT_KIND_FILE_OPEN",
  "EVENT_KIND_FILE_CREATE",
  "EVENT_KIND_FILE_UNLINK",
  "EVENT_KIND_FILE_RENAME",
  "EVENT_KIND_LSM_DENY_OWN",
];

type ResultSource = "OWN_LSM" | "PRIOR_LSM" | "SYSCALL_FALLBACK";
type OpResult = "success" | "failed" | "denied";

const SOURCE_TITLES: ReadonlyMap<ResultSource, string> = new Map([
  ["OWN_LSM", "Observed at this platform's own BPF LSM hook"],
  ["PRIOR_LSM", "Deny fired by another LSM before ours (LSM_DENY with own_deny=false)"],
  ["SYSCALL_FALLBACK", "LSM hook unavailable — observed via kprobe syscall fallback"],
]);

interface FileRow {
  key: string;
  wall: string;
  op: string;
  path: string;
  truncated: boolean;
  result: OpResult;
  errno: string;
  source: ResultSource;
  task: Identity;
  eventValids: Record<string, boolean> | undefined;
}

function classify(succeeded: boolean, errno: number): OpResult {
  if (succeeded) return "success";
  return errno === EACCES || errno === EPERM ? "denied" : "failed";
}

function isPathTruncated(valids: Record<string, boolean> | undefined): boolean {
  const { payload_trunc, payload_truncated } = valids ?? {};
  return payload_trunc === true || payload_truncated === true;
}

interface OpOutcome {
  succeeded: boolean;
  errno_value: number;
  from_lsm: boolean;
  task: Identity;
}

function toRow(e: Event): FileRow | null {
  const base = {
    key: e.event_id,
    wall: formatWall(e.ts_wall),
    truncated: isPathTruncated(e.valids),
    eventValids: e.valids,
  };
  const op = (name: string, path: string, p: OpOutcome): FileRow => ({
    ...base,
    op: name,
    path,
    result: classify(p.succeeded, p.errno_value),
    errno: errnoLabel(p.errno_value),
    source: p.from_lsm ? "OWN_LSM" : "SYSCALL_FALLBACK",
    task: p.task,
  });
  const fo = e.file_open;
  if (fo !== undefined) return op(fileOpenOp(fo.flags), fo.path, fo);
  const fc = e.file_create;
  if (fc !== undefined) return op("create", fc.path, fc);
  const fu = e.file_unlink;
  if (fu !== undefined) return op(fu.is_dir ? "rmdir" : "unlink", fu.path, fu);
  const fr = e.file_rename;
  if (fr !== undefined) return op("rename", `${fr.source_path} → ${fr.dest_path}`, fr);
  const deny = e.lsm_deny;
  if (deny !== undefined) {
    return {
      ...base,
      op: "deny",
      path: `${deny.hook} · ${deny.subject}`,
      result: "denied",
      errno: "—",
      source: deny.own_deny ? "OWN_LSM" : "PRIOR_LSM",
      task: deny.task,
    };
  }
  return null;
}

const RESULT_BADGE: ReadonlyMap<OpResult, { cls: string; label: string }> = new Map([
  ["success", { cls: "badge--live", label: "Success" }],
  ["failed", { cls: "badge--critical", label: "Failed" }],
  ["denied", { cls: "badge--high", label: "Denied" }],
]);

const COLUMNS: ReadonlyArray<Column<FileRow>> = [
  { key: "t", header: "t (UTC)", render: (r) => r.wall },
  { key: "op", header: "Operation", render: (r) => <span className="kind-cell">{r.op}</span> },
  {
    key: "path",
    header: "Path",
    render: (r) => (
      <span title={r.path}>
        {r.path}
        {r.truncated && (
          <span
            className="badge badge--medium trunc-flag"
            title="Sensor truncated this path payload"
          >
            trunc
          </span>
        )}
      </span>
    ),
  },
  {
    key: "result",
    header: "Result",
    render: (r) => {
      const meta = RESULT_BADGE.get(r.result) ?? RESULT_BADGE.get("failed");
      if (meta === undefined) return "—";
      return (
        <span className={cx("badge", meta.cls)}>
          <span className="dot" aria-hidden="true" />
          {meta.label}
        </span>
      );
    },
  },
  { key: "errno", header: "Errno", render: (r) => r.errno },
  {
    key: "source",
    header: "Result source",
    render: (r) => (
      <span
        className={cx("chip", `source--${r.source.toLowerCase()}`)}
        title={SOURCE_TITLES.get(r.source)}
      >
        {r.source}
      </span>
    ),
  },
  {
    key: "proc",
    header: "Process (tgid/pid)",
    render: (r) => <ProcessCell task={r.task} eventValids={r.eventValids} />,
  },
];

export function FilesView() {
  const [mode, setMode] = useState<FeedMode>("live");
  const [rangeSec, setRangeSec] = useState(900);
  const [cluster, setCluster] = useState("all");
  const [opFilter, setOpFilter] = useState("all");
  const [cursor, setCursor] = useState<string | undefined>(undefined);

  const scopeKey = `${mode}|${rangeSec}|${cluster}|${opFilter}`;
  const [seenScope, setSeenScope] = useState(scopeKey);
  if (seenScope !== scopeKey) {
    setSeenScope(scopeKey);
    setCursor(undefined);
  }

  const feed = useEvents({ kinds: KINDS, mode, rangeSec, cursor, cluster });
  const rows = useMemo(() => {
    const all: FileRow[] = [];
    for (const e of feed.events) {
      const row = toRow(e);
      if (row === null) continue;
      if (opFilter !== "all" && row.op !== opFilter) continue;
      all.push(row);
    }
    return all;
  }, [feed.events, opFilter]);

  return (
    <section aria-label="File operations">
      <div className="view-head">
        <h1 className="view-title">Files</h1>
        <p className="view-sub">
          observed file operations — exactly what the sensor saw, nothing inferred
        </p>
      </div>

      <EventToolbar
        idPrefix="files"
        mode={mode}
        onModeChange={setMode}
        rangeSec={rangeSec}
        onRangeChange={setRangeSec}
        cluster={cluster}
        onClusterChange={setCluster}
        clusters={feed.clusters}
      />

      <FeedPanel
        title="File operations"
        feed={feed}
        mode={mode}
        rows={rows}
        columns={COLUMNS}
        rowKey={(r) => r.key}
        ariaLabel="File operations"
        errorScope="file event feed"
        emptyTitle="No file operations observed in this window"
        emptyHint="Widen the window or switch to live mode. Absence here means nothing was captured — this view never claims complete file access."
        skeletonCols={7}
        onCursor={setCursor}
        filterControl={
          <>
            <label className="visually-hidden" htmlFor="files-op">
              Filter by operation
            </label>
            <select
              id="files-op"
              className="control"
              value={opFilter}
              onChange={(ev) => setOpFilter(ev.target.value)}
            >
              <option value="all">all operations</option>
              <option value="open-read">open-read</option>
              <option value="open-write">open-write</option>
              <option value="create">create</option>
              <option value="rename">rename</option>
              <option value="unlink">unlink</option>
              <option value="rmdir">rmdir</option>
              <option value="deny">LSM deny</option>
            </select>
          </>
        }
      />
    </section>
  );
}
