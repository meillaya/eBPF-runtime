// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Syscall latency view. Histograms SYSCALL_EXIT.elapsed_ns — wall time on
// CLOCK_MONOTONIC (boot clock), never CPU time. NO_RETURN exits and window-
// relative ORPHAN enter/exit counts are surfaced explicitly, not folded
// into the latency numbers. The allowlist narrows by syscall number.
import { useMemo, useState } from "react";
import type { EventKind } from "../api/event-types";
import { EventToolbar } from "../components/EventToolbar";
import { connectionStatus, FeedAlerts } from "../components/FeedPanel";
import { LatencyHistogram } from "../components/LatencyHistogram";
import { type FeedMode, useEvents } from "../hooks/useEvents";
import { formatInt } from "../lib/format";
import { formatNs, parseAllowlist } from "../lib/histogram";
import { computeStats, type PerSyscall } from "../lib/syscallStats";
import { ConnectionBadge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Panel } from "../ui/Card";
import { EmptyRows, ErrorPanel, TableSkeleton } from "../ui/QueryStates";
import { type Column, DataTable } from "../ui/Table";

const KINDS: readonly EventKind[] = ["EVENT_KIND_SYSCALL_ENTER", "EVENT_KIND_SYSCALL_EXIT"];

const SYSCALL_COLUMNS: ReadonlyArray<Column<PerSyscall>> = [
  { key: "name", header: "Syscall", render: (r) => <span className="kind-cell">{r.name}</span> },
  { key: "nr", header: "nr", align: "right", render: (r) => String(r.nr) },
  { key: "count", header: "Exits", align: "right", render: (r) => formatInt(r.count) },
  {
    key: "p50",
    header: "p50",
    align: "right",
    render: (r) => (r.p50 === null ? "—" : formatNs(r.p50)),
  },
  {
    key: "p99",
    header: "p99",
    align: "right",
    render: (r) => (r.p99 === null ? "—" : formatNs(r.p99)),
  },
  { key: "max", header: "max", align: "right", render: (r) => formatNs(r.maxNs) },
  {
    key: "nr2",
    header: "NO_RETURN",
    align: "right",
    render: (r) =>
      r.noReturn > 0 ? <span className="warn-num">{formatInt(r.noReturn)}</span> : "0",
  },
];

function Stat({ label, value, warn }: { label: string; value: string; warn?: boolean }) {
  return (
    <div className="counter">
      <span className={warn ? "stat-value stat-value--warn" : "stat-value"}>{value}</span>
      <span className="stat-label">{label}</span>
    </div>
  );
}

export function SyscallView() {
  const [mode, setMode] = useState<FeedMode>("live");
  const [rangeSec, setRangeSec] = useState(900);
  const [cluster, setCluster] = useState("all");
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [allowlistInput, setAllowlistInput] = useState("");

  const scopeKey = `${mode}|${rangeSec}|${cluster}`;
  const [seenScope, setSeenScope] = useState(scopeKey);
  if (seenScope !== scopeKey) {
    setSeenScope(scopeKey);
    setCursor(undefined);
  }

  const allowlist = useMemo(() => parseAllowlist(allowlistInput), [allowlistInput]);
  const feed = useEvents({ kinds: KINDS, mode, rangeSec, cursor, cluster });
  const stats = useMemo(() => computeStats(feed.events, allowlist), [feed.events, allowlist]);

  const failed = feed.status === "error" || feed.status === "failed";
  const hasData = feed.events.length > 0;

  return (
    <section aria-label="Syscall latency">
      <div className="view-head">
        <h1 className="view-title">Syscalls</h1>
        <p className="view-sub">enter→exit wall time (CLOCK_MONOTONIC) — not CPU time</p>
      </div>

      <EventToolbar
        idPrefix="syscalls"
        mode={mode}
        onModeChange={setMode}
        rangeSec={rangeSec}
        onRangeChange={setRangeSec}
        cluster={cluster}
        onClusterChange={setCluster}
        clusters={feed.clusters}
      />

      {failed && !hasData ? (
        <ErrorPanel error={feed.error} onRetry={feed.refetch} scope="syscall event feed" />
      ) : (
        <>
          <FeedAlerts feed={feed} mode={mode} />

          <Panel title="Window accounting" className="stack-top">
            <div className="counter-row">
              <Stat label="Exit samples" value={formatInt(stats.sampleCount)} />
              <Stat label="Enters seen" value={formatInt(stats.enterCount)} />
              <Stat
                label="Total wall time"
                value={stats.sampleCount > 0 ? formatNs(stats.sumNs) : "—"}
              />
              <Stat
                label="NO_RETURN exits"
                value={formatInt(stats.noReturn)}
                warn={stats.noReturn > 0}
              />
              <Stat
                label="Orphan enters"
                value={formatInt(stats.orphanEnter)}
                warn={stats.orphanEnter > 0}
              />
              <Stat
                label="Orphan exits"
                value={formatInt(stats.orphanExit)}
                warn={stats.orphanExit > 0}
              />
            </div>
            <p className="well-hint stack-top">
              Orphans are window-relative: enters whose exit fell outside this window, and exits
              whose enter preceded it. NO_RETURN exits (e.g. execve) never observe a return.
            </p>
          </Panel>

          <Panel
            title="Latency histogram"
            className="stack-top"
            meta={
              mode === "live" ? (
                <ConnectionBadge status={connectionStatus(feed)} />
              ) : (
                <span>{formatInt(feed.events.length)} events on page</span>
              )
            }
            actions={
              <>
                <label className="visually-hidden" htmlFor="syscalls-allowlist">
                  Allowlist filter (syscall numbers)
                </label>
                <input
                  id="syscalls-allowlist"
                  className="control allowlist-input"
                  type="text"
                  value={allowlistInput}
                  placeholder="allowlist: e.g. 0, 1, 59"
                  onChange={(ev) => setAllowlistInput(ev.target.value)}
                />
                {mode === "live" ? (
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={feed.togglePause}
                    aria-pressed={feed.status === "paused"}
                  >
                    {feed.status === "paused" ? "Resume" : "Pause"}
                  </Button>
                ) : (
                  feed.nextCursor !== undefined && (
                    <Button size="sm" variant="ghost" onClick={() => setCursor(feed.nextCursor)}>
                      Older →
                    </Button>
                  )
                )}
              </>
            }
          >
            {!hasData && (feed.status === "loading" || feed.status === "connecting") ? (
              <TableSkeleton rows={6} cols={4} />
            ) : (
              <LatencyHistogram
                buckets={stats.buckets}
                percentiles={stats.percentiles}
                sampleCount={stats.sampleCount}
              />
            )}
          </Panel>

          <Panel title="Per-syscall (top 12 by exits)" flush className="stack-top">
            {stats.perSyscall.length === 0 ? (
              <div className="tbl-empty">
                <EmptyRows
                  title="No syscall exits in this window"
                  hint={
                    allowlist.length > 0
                      ? "The allowlist filter matched nothing — check the syscall numbers."
                      : "The sensor only observes allowlisted syscalls; a silent window means none were captured."
                  }
                />
              </div>
            ) : (
              <DataTable
                columns={SYSCALL_COLUMNS}
                rows={stats.perSyscall}
                rowKey={(r) => String(r.nr)}
                ariaLabel="Per-syscall latency"
                focusable
              />
            )}
          </Panel>

          <p className="well-hint stack-top">
            Histogrammed values are SYSCALL_EXIT.elapsed_ns over the current window only — a sample
            of observed exits, not a whole-host profile.
          </p>
        </>
      )}
    </section>
  );
}
