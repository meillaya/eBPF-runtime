// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Live event stream (WebSocket kernel-v1.event-stream.v1). Bounded
// buffer, seq cursor, pause/resume, kind filter. Payloads render as
// curated one-line summaries — raw JSON never hits the DOM.
import { useState } from "react";
import type { EventKind, LiveEvent } from "../api/event-types";
import { EVENT_KINDS } from "../api/event-types";
import { formatInt, formatMonoNs, shortId, shortKind, summarizePayload } from "../lib/format";
import { useEventStream } from "../live/useEventStream";
import { Alert } from "../ui/Alert";
import { ConnectionBadge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Panel } from "../ui/Card";
import { EmptyState } from "../ui/EmptyState";
import { type Column, DataTable } from "../ui/Table";

const COLUMNS: ReadonlyArray<Column<LiveEvent>> = [
  {
    key: "seq",
    header: "Seq",
    align: "right",
    render: (e) => <span className="strong num">{formatInt(e.seq)}</span>,
  },
  {
    key: "ts",
    header: "t (mono ns)",
    align: "right",
    render: (e) => formatMonoNs(e.ts_monotonic_ns),
  },
  {
    key: "kind",
    header: "Kind",
    render: (e) => <span className="kind-cell">{shortKind(e.event_kind)}</span>,
  },
  { key: "node", header: "Node", render: (e) => e.node_name },
  {
    key: "payload",
    header: "Payload",
    render: (e) => <span title={summarizePayload(e.payload)}>{summarizePayload(e.payload)}</span>,
  },
  {
    key: "id",
    header: "Event ID",
    render: (e) => <span title={e.event_id}>{shortId(e.event_id)}</span>,
  },
];

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <span className="chip">
      <span className="conn-detail">{label}</span>
      {value}
    </span>
  );
}

export function EventsView() {
  const [kind, setKind] = useState<EventKind | "all">("all");
  const stream = useEventStream(kind);
  const { status, visible, receivedTotal, droppedTotal, lastSeq, attempts, lastError } = stream;

  return (
    <section aria-label="Event stream">
      <div className="view-head">
        <h1 className="view-title">Events</h1>
        <p className="view-sub">kernel-v1.event-stream.v1</p>
      </div>

      {status === "failed" && (
        <Alert
          tone="critical"
          title={`Stream lost after ${attempts} attempts`}
          action={
            <Button variant="danger" size="sm" onClick={stream.restart}>
              Reconnect
            </Button>
          }
        >
          {lastError ?? "unknown close reason"} — the bounded buffer retains the last events below.
        </Alert>
      )}
      {status === "reconnecting" && (
        <Alert tone="warning" title="Reconnecting to the event stream">
          attempt {attempts} — resume from seq {lastSeq === null ? "0" : formatInt(lastSeq)}
          {lastError !== null && ` (${lastError})`}
        </Alert>
      )}
      {droppedTotal > 0 && status !== "failed" && (
        <Alert tone="warning" title={`${formatInt(droppedTotal)} events evicted from the buffer`}>
          The display buffer is bounded; older events were dropped. Use the historical /events API
          for full recall.
        </Alert>
      )}

      <Panel
        title="Live stream"
        flush
        meta={
          <>
            <ConnectionBadge
              status={
                status === "live"
                  ? "live"
                  : status === "reconnecting" || status === "connecting"
                    ? "reconnecting"
                    : status === "paused"
                      ? "idle"
                      : "offline"
              }
            />
            <Stat label="received" value={formatInt(receivedTotal)} />
            <Stat label="buffer" value={formatInt(visible.length)} />
            <Stat label="last seq" value={lastSeq === null ? "—" : formatInt(lastSeq)} />
          </>
        }
        actions={
          <>
            <label className="visually-hidden" htmlFor="kind-filter">
              Filter by event kind
            </label>
            <select
              id="kind-filter"
              className="control"
              value={kind}
              onChange={(ev) => setKind(ev.target.value as EventKind | "all")}
            >
              <option value="all">all kinds</option>
              {EVENT_KINDS.filter((k) => k !== "EVENT_KIND_UNSPECIFIED").map((k) => (
                <option key={k} value={k}>
                  {shortKind(k)}
                </option>
              ))}
            </select>
            <Button
              size="sm"
              variant="ghost"
              onClick={stream.togglePause}
              aria-pressed={status === "paused"}
            >
              {status === "paused" ? "Resume" : "Pause"}
            </Button>
            <Button size="sm" variant="ghost" onClick={stream.clearBuffer}>
              Clear
            </Button>
          </>
        }
      >
        <DataTable
          columns={COLUMNS}
          rows={visible.slice().reverse()}
          rowKey={(e) => `${e.seq}-${e.event_id}`}
          ariaLabel="Live kernel events"
          freshKeys={new Set(visible.slice(-3).map((e) => `${e.seq}-${e.event_id}`))}
          empty={
            status === "live" ? (
              <EmptyState
                title="Stream is live but silent"
                hint="No events match the current filter yet. Generate activity on the node, or clear the kind filter."
              />
            ) : (
              <EmptyState
                tone={status === "failed" ? "error" : "neutral"}
                title={status === "failed" ? "Stream disconnected" : "Waiting for the stream"}
                hint={
                  status === "failed"
                    ? "The WebSocket could not be established. Check the agent, then reconnect."
                    : "Connecting to the control plane over loopback…"
                }
              />
            )
          }
        />
      </Panel>
    </section>
  );
}
