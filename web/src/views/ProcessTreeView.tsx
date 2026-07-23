// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Process tree view: fork/exec/exit folded into a generation-identified
// tree. Two sources behind one board — live WebSocket fold, or a
// historical /events query over a trailing window.
import { type ReactNode, useState } from "react";
import type { ProcessForest } from "../api/process-types";
import { useNow } from "../api/query";
import { ProcessTree } from "../components/ProcessTree";
import {
  type LiveProcessTreeState,
  type ProcessTreeState,
  useHistoricalProcessTree,
  useLiveProcessTree,
} from "../hooks/useProcessTree";
import { formatAgo, formatInt, formatMonoShort, formatWall } from "../lib/format";
import { execBasename } from "../lib/process-tree";
import { Alert } from "../ui/Alert";
import { ConnectionBadge, type ConnectionStatus } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Panel } from "../ui/Card";
import { EmptyState } from "../ui/EmptyState";
import { DegradedBanner, ErrorPanel, TableSkeleton } from "../ui/QueryStates";

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <span className="chip">
      <span className="conn-detail">{label}</span>
      {value}
    </span>
  );
}

function ExecTimeline({ forest }: { forest: ProcessForest }) {
  const execs = forest.execs.slice(-24).reverse();
  if (execs.length === 0) {
    return <p className="well-hint exec-none">No exec results in this window.</p>;
  }
  return (
    <ol className="exec-list">
      {execs.map((exec) => {
        const gen = forest.nodes.get(exec.procKey)?.generation ?? 1;
        return (
          <li key={exec.key} className="exec-row">
            <span className="exec-ts">
              {exec.wallIso !== undefined
                ? formatWall(exec.wallIso)
                : formatMonoShort(exec.tsMonoNs)}
            </span>
            <span className="exec-path" title={exec.path}>
              {execBasename(exec.path)}
            </span>
            <span className="exec-pid">
              {exec.pid}·G{gen}
            </span>
            <span className={exec.succeeded ? "badge badge--info" : "badge badge--medium"}>
              {exec.succeeded ? "OK" : `ERRNO ${exec.errnoValue ?? 0}`}
            </span>
          </li>
        );
      })}
    </ol>
  );
}

function LegendPanel() {
  return (
    <Panel title="Identity & legend">
      <dl className="kv">
        <dt>G badge</dt>
        <dd>Nth identity of a PID in this window — G&gt;1 means PID reuse was observed</dd>
        <dt>Green dot</dt>
        <dd>Running process (pulsing while the source is live)</dd>
        <dt>Muted dot</dt>
        <dd>Exited process; chip carries the exit code</dd>
        <dt>Blue dot</dt>
        <dd>Thread, nested under its TGID with a dotted guide</dd>
        <dt>Dashed guide</dt>
        <dd>Parent identity missing from the window — ancestry is marked, never invented</dd>
      </dl>
    </Panel>
  );
}

interface TreeBoardProps {
  state: ProcessTreeState;
  freshKeys: ReadonlySet<string> | undefined;
  meta: ReactNode;
  actions: ReactNode;
  emptyTitle: string;
  emptyHint: string;
  onFatalRetry: () => void;
}

function TreeBoard({
  state,
  freshKeys,
  meta,
  actions,
  emptyTitle,
  emptyHint,
  onFatalRetry,
}: TreeBoardProps) {
  const { forest, status, error } = state;
  return (
    <>
      {status === "degraded" && forest !== null && (
        <DegradedBanner error={error} staleRows={forest.nodes.size} />
      )}
      {forest !== null && forest.orphanCount > 0 && status !== "error" && (
        <Alert
          tone="warning"
          title={`${formatInt(forest.orphanCount)} nodes with incomplete ancestry`}
        >
          Their parents were never observed — the window started mid-flight or events were lost. No
          ancestry is invented; dashed guides mark the missing edges.
        </Alert>
      )}

      <div className="ptree-cols">
        <Panel
          title="Process tree"
          flush
          meta={
            forest !== null ? (
              <>
                {meta}
                <Stat label="proc" value={formatInt(forest.processCount)} />
                <Stat label="threads" value={formatInt(forest.threadCount)} />
                <Stat label="exited" value={formatInt(forest.exitedCount)} />
                <Stat label="orphans" value={formatInt(forest.orphanCount)} />
                <Stat label="max gen" value={`G${forest.maxGeneration}`} />
              </>
            ) : undefined
          }
          actions={actions}
        >
          {status === "error" ? (
            <div className="tbl-empty">
              <ErrorPanel error={error} onRetry={onFatalRetry} scope="process event source" />
            </div>
          ) : status === "loading" ? (
            <TableSkeleton rows={9} cols={5} />
          ) : forest === null || forest.nodes.size === 0 ? (
            <div className="tbl-empty">
              <EmptyState title={emptyTitle} hint={emptyHint} />
            </div>
          ) : (
            <ProcessTree
              forest={forest}
              ariaLabel="Process tree (generation-identified)"
              freshKeys={freshKeys}
            />
          )}
        </Panel>

        <div className="ptree-side">
          <Panel
            title="Exec timeline"
            flush
            meta={forest !== null ? `${formatInt(forest.execs.length)} execs` : undefined}
          >
            {forest === null ? (
              <div className="tbl-empty">
                <p className="well-hint">Waiting for exec results…</p>
              </div>
            ) : (
              <ExecTimeline forest={forest} />
            )}
          </Panel>
          <LegendPanel />
        </div>
      </div>
    </>
  );
}

const STREAM_BADGE: Record<string, ConnectionStatus> = {
  live: "live",
  connecting: "reconnecting",
  reconnecting: "reconnecting",
  paused: "idle",
  failed: "offline",
  closed: "offline",
};

function LiveBoard() {
  const live: LiveProcessTreeState = useLiveProcessTree();
  const { streamStatus, droppedTotal, attempts, lastError } = live;
  return (
    <>
      {streamStatus === "failed" && live.status !== "error" && (
        <Alert
          tone="critical"
          title={`Stream lost after ${attempts} attempts`}
          action={
            <Button variant="danger" size="sm" onClick={live.restart}>
              Reconnect
            </Button>
          }
        >
          {lastError ?? "unknown close reason"} — the buffered tree below is the last known state.
        </Alert>
      )}
      {streamStatus === "reconnecting" && (
        <Alert tone="warning" title="Reconnecting to the event stream">
          attempt {attempts}
          {lastError !== null && ` (${lastError})`} — the tree keeps the last buffered state.
        </Alert>
      )}
      {droppedTotal > 0 && streamStatus !== "failed" && (
        <Alert tone="warning" title={`${formatInt(droppedTotal)} frames evicted from the buffer`}>
          The live buffer is bounded; switch to historical mode for full recall.
        </Alert>
      )}
      <TreeBoard
        state={live}
        freshKeys={live.forest !== null ? new Set(live.forest.recentKeys) : undefined}
        meta={<ConnectionBadge status={STREAM_BADGE[streamStatus] ?? "offline"} />}
        actions={
          <>
            <Button size="sm" variant="ghost" onClick={live.togglePause}>
              {streamStatus === "paused" ? "Resume" : "Pause"}
            </Button>
            <Button size="sm" variant="ghost" onClick={live.restart}>
              Restart
            </Button>
          </>
        }
        emptyTitle={
          streamStatus === "live" ? "Stream is live but silent" : "Waiting for the stream"
        }
        emptyHint={
          streamStatus === "live"
            ? "No fork/exec/exit events in the buffer yet. Generate activity on the node."
            : "Connecting to the control plane event stream…"
        }
        onFatalRetry={live.restart}
      />
    </>
  );
}

const RANGES: ReadonlyArray<{ label: string; min: number | null }> = [
  { label: "last 5 min", min: 5 },
  { label: "last 15 min", min: 15 },
  { label: "last hour", min: 60 },
  { label: "full window", min: null },
];

function HistoricalBoard({ rangeMin }: { rangeMin: number | null }) {
  const hist = useHistoricalProcessTree(rangeMin);
  const nowTick = useNow(5_000);
  const fetchedAgo =
    hist.fetchedAt > 0 ? formatAgo(Math.floor(hist.fetchedAt / 1000), nowTick * 5) : "—";
  return (
    <TreeBoard
      state={hist}
      freshKeys={undefined}
      meta={<Stat label="fetched" value={fetchedAgo} />}
      actions={
        <Button size="sm" variant="ghost" onClick={hist.refetch}>
          Refresh
        </Button>
      }
      emptyTitle="No process events in this window"
      emptyHint="Widen the range, or switch to live mode to watch new fork/exec/exit activity."
      onFatalRetry={hist.refetch}
    />
  );
}

export function ProcessTreeView() {
  const [mode, setMode] = useState<"live" | "historical">("live");
  const [rangeMin, setRangeMin] = useState<number | null>(15);
  return (
    <section aria-label="Process tree">
      <div className="view-head">
        <h1 className="view-title">Processes</h1>
        <p className="view-sub">fork / exec / exit — generation identity</p>
        <fieldset className="seg">
          <legend className="visually-hidden">Source mode</legend>
          <button
            type="button"
            className="seg-btn"
            aria-pressed={mode === "live"}
            onClick={() => setMode("live")}
          >
            Live
          </button>
          <button
            type="button"
            className="seg-btn"
            aria-pressed={mode === "historical"}
            onClick={() => setMode("historical")}
          >
            Historical
          </button>
        </fieldset>
        {mode === "historical" && (
          <>
            <label className="visually-hidden" htmlFor="ptree-range">
              Historical time range
            </label>
            <select
              id="ptree-range"
              className="control"
              value={rangeMin === null ? "all" : String(rangeMin)}
              onChange={(ev) =>
                setRangeMin(ev.target.value === "all" ? null : Number(ev.target.value))
              }
            >
              {RANGES.map((r) => (
                <option key={r.label} value={r.min === null ? "all" : String(r.min)}>
                  {r.label}
                </option>
              ))}
            </select>
          </>
        )}
      </div>
      {mode === "live" ? <LiveBoard /> : <HistoricalBoard rangeMin={rangeMin} />}
    </section>
  );
}
