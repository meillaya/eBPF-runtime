// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Socket lifecycle view. Semantic honesty contract: connect ATTEMPT rows
// are never merged with outcomes; EINPROGRESS is shown as "pending" (a
// nonblocking connect, not a success); failures carry their errno; state
// transitions render old → new verbatim from the kernel TCP state bytes.
import { useMemo, useState } from "react";
import type { Event, EventKind, Identity } from "../api/event-types";
import { EventToolbar } from "../components/EventToolbar";
import { FeedPanel } from "../components/FeedPanel";
import { ProcessCell } from "../components/ProcessCell";
import {
  phaseFromAccept,
  phaseFromConnect,
  phaseFromTcpState,
  type SocketPhase,
  SocketStateBadge,
  StateTransition,
} from "../components/SocketStateBadge";
import { type FeedMode, useEvents } from "../hooks/useEvents";
import { EINPROGRESS, errnoLabel, familyName, formatEndpoint } from "../lib/decode";
import { formatWall } from "../lib/format";
import type { Column } from "../ui/Table";

const KINDS: readonly EventKind[] = [
  "EVENT_KIND_NETWORK_CONNECT",
  "EVENT_KIND_NETWORK_ACCEPT",
  "EVENT_KIND_NETWORK_STATE",
];

type Scope = "all" | "connect" | "accept" | "state";

interface SocketRow {
  key: string;
  wall: string;
  source: "connect" | "accept" | "state";
  phase: SocketPhase | null;
  transition: { from: number; to: number } | null;
  tuple: string;
  family: number;
  cookie: string;
  task: Identity;
  eventValids: Record<string, boolean> | undefined;
  detail: string;
}

function toRow(e: Event): SocketRow | null {
  const base = {
    key: e.event_id,
    wall: formatWall(e.ts_wall),
    transition: null,
    eventValids: e.valids,
  };
  if (e.network_connect !== undefined) {
    const nc = e.network_connect;
    const pending = nc.is_result && nc.errno_value === EINPROGRESS;
    return {
      ...base,
      source: "connect",
      phase: phaseFromConnect(nc),
      tuple: `${formatEndpoint(nc.local_addr, nc.local_port)} → ${formatEndpoint(nc.remote_addr, nc.remote_port)}`,
      family: nc.family,
      cookie: String(nc.socket_cookie),
      task: nc.task,
      detail: pending
        ? "nonblocking — outcome pending"
        : nc.is_result
          ? `${errnoLabel(nc.errno_value)} · ${nc.from_cgroup ? "cgroup" : "syscall"}`
          : `connect() issued · ${nc.from_cgroup ? "cgroup" : "syscall"}`,
    };
  }
  if (e.network_accept !== undefined) {
    const na = e.network_accept;
    return {
      ...base,
      source: "accept",
      phase: phaseFromAccept(na),
      tuple: `${formatEndpoint(na.local_addr, na.local_port)} ← ${formatEndpoint(na.remote_addr, na.remote_port)}`,
      family: na.family,
      cookie: String(na.socket_cookie),
      task: na.task,
      detail: na.succeeded ? `fd ${na.returned_fd}` : errnoLabel(na.errno_value),
    };
  }
  if (e.network_state !== undefined) {
    const ns = e.network_state;
    return {
      ...base,
      source: "state",
      phase: phaseFromTcpState(ns.new_state),
      transition: { from: ns.old_state, to: ns.new_state },
      tuple: "—",
      family: 0,
      cookie: String(ns.socket_cookie),
      task: ns.task,
      detail: "—",
    };
  }
  return null;
}

const COLUMNS: ReadonlyArray<Column<SocketRow>> = [
  { key: "t", header: "t (UTC)", render: (r) => r.wall },
  {
    key: "phase",
    header: "Phase",
    render: (r) => (r.phase === null ? "—" : <SocketStateBadge phase={r.phase} />),
  },
  {
    key: "transition",
    header: "Transition",
    render: (r) =>
      r.transition === null ? (
        <span className="muted-cell">{r.source === "connect" ? "connect()" : r.source}</span>
      ) : (
        <StateTransition oldState={r.transition.from} newState={r.transition.to} />
      ),
  },
  {
    key: "tuple",
    header: "Tuple",
    render: (r) => (
      <span className="tuple-cell" title={r.tuple}>
        {r.family !== 0 && <span className="tuple-fam">{familyName(r.family)}</span>}
        {r.tuple}
      </span>
    ),
  },
  { key: "cookie", header: "Cookie", align: "right", render: (r) => r.cookie },
  {
    key: "proc",
    header: "Process (tgid/pid)",
    render: (r) => <ProcessCell task={r.task} eventValids={r.eventValids} />,
  },
  {
    key: "detail",
    header: "Result / errno",
    render: (r) => <span title={r.detail}>{r.detail}</span>,
  },
];

export function SocketsView() {
  const [mode, setMode] = useState<FeedMode>("live");
  const [rangeSec, setRangeSec] = useState(900);
  const [cluster, setCluster] = useState("all");
  const [scope, setScope] = useState<Scope>("all");
  const [cursor, setCursor] = useState<string | undefined>(undefined);

  const scopeKey = `${mode}|${rangeSec}|${cluster}|${scope}`;
  const [seenScope, setSeenScope] = useState(scopeKey);
  if (seenScope !== scopeKey) {
    setSeenScope(scopeKey);
    setCursor(undefined);
  }

  const feed = useEvents({ kinds: KINDS, mode, rangeSec, cursor, cluster });
  const rows = useMemo(() => {
    const all: SocketRow[] = [];
    for (const e of feed.events) {
      const row = toRow(e);
      if (row === null) continue;
      if (scope !== "all" && row.source !== scope) continue;
      all.push(row);
    }
    return all;
  }, [feed.events, scope]);

  return (
    <section aria-label="Socket lifecycle">
      <div className="view-head">
        <h1 className="view-title">Sockets</h1>
        <p className="view-sub">
          connect attempts ≠ results · transitions verbatim from kernel state
        </p>
      </div>

      <EventToolbar
        idPrefix="sockets"
        mode={mode}
        onModeChange={setMode}
        rangeSec={rangeSec}
        onRangeChange={setRangeSec}
        cluster={cluster}
        onClusterChange={setCluster}
        clusters={feed.clusters}
      />

      <FeedPanel
        title="Socket lifecycle"
        feed={feed}
        mode={mode}
        rows={rows}
        columns={COLUMNS}
        rowKey={(r) => r.key}
        ariaLabel="Socket lifecycle events"
        errorScope="socket event feed"
        emptyTitle="No socket events in this window"
        emptyHint="Widen the window or switch to live mode — attempts, accepts, and state transitions appear here as observed."
        skeletonCols={7}
        onCursor={setCursor}
        filterControl={
          <>
            <label className="visually-hidden" htmlFor="sockets-scope">
              Filter by event source
            </label>
            <select
              id="sockets-scope"
              className="control"
              value={scope}
              onChange={(ev) => setScope(ev.target.value as Scope)}
            >
              <option value="all">all sources</option>
              <option value="connect">connect</option>
              <option value="accept">accept</option>
              <option value="state">state transitions</option>
            </select>
          </>
        }
      />
    </section>
  );
}
