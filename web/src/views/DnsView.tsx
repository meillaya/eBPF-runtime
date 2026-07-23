// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// DNS packet view. Semantic honesty contract: these are PACKETS OBSERVED
// on the wire, never "DNS lookups performed" — a query packet is not proof
// a resolver ran, and a truncated capture says so explicitly. Query/response
// correlation is by (transaction id, network namespace, transport) and is
// labeled paired/unpaired, never causally implied.
import { useMemo, useState } from "react";
import type { Event, EventKind, Identity } from "../api/event-types";
import { EventToolbar } from "../components/EventToolbar";
import { FeedPanel } from "../components/FeedPanel";
import { ProcessCell } from "../components/ProcessCell";
import { type FeedMode, useEvents } from "../hooks/useEvents";
import { DNS_QTYPES, decodeBase64, dnsTransportName, parseDnsPacket } from "../lib/decode";
import { cx, formatWall } from "../lib/format";
import type { Column } from "../ui/Table";

const KINDS: readonly EventKind[] = ["EVENT_KIND_DNS_PACKET"];

interface DnsRow {
  key: string;
  wall: string;
  egress: boolean;
  isQuery: boolean;
  qname: string;
  qtype: string;
  txid: string;
  corrKey: string;
  transport: number;
  truncated: boolean;
  netns: string;
  task: Identity;
  eventValids: Record<string, boolean> | undefined;
}

function toRow(e: Event): DnsRow | null {
  const dp = e.dns_packet;
  if (dp === undefined) return null;
  const parsed = parseDnsPacket(decodeBase64(dp.packet_bytes) ?? new Uint8Array(0));
  const txid = parsed === null ? "—" : `0x${parsed.txid.toString(16).padStart(4, "0")}`;
  const qtype =
    parsed?.qtype === undefined || parsed.qtype === null
      ? "—"
      : (DNS_QTYPES.get(parsed.qtype) ?? `type ${parsed.qtype}`);
  const netns = dp.task.net_ns_id !== undefined ? String(dp.task.net_ns_id) : "?";
  return {
    key: e.event_id,
    wall: formatWall(e.ts_wall),
    egress: dp.is_egress,
    isQuery: dp.is_query,
    qname: parsed?.qname ?? "— (undecoded)",
    qtype,
    txid,
    corrKey: `${txid}|ns:${netns}|${dp.transport}`,
    transport: dp.transport,
    truncated: dp.truncated,
    netns,
    task: dp.task,
    eventValids: e.valids,
  };
}

export function DnsView() {
  const [mode, setMode] = useState<FeedMode>("live");
  const [rangeSec, setRangeSec] = useState(900);
  const [cluster, setCluster] = useState("all");
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [roleFilter, setRoleFilter] = useState<"all" | "query" | "response">("all");

  const scopeKey = `${mode}|${rangeSec}|${cluster}|${roleFilter}`;
  const [seenScope, setSeenScope] = useState(scopeKey);
  if (seenScope !== scopeKey) {
    setSeenScope(scopeKey);
    setCursor(undefined);
  }

  const feed = useEvents({ kinds: KINDS, mode, rangeSec, cursor, cluster });
  const rows = useMemo(() => {
    const all: DnsRow[] = [];
    for (const e of feed.events) {
      const row = toRow(e);
      if (row === null) continue;
      if (roleFilter === "query" && !row.isQuery) continue;
      if (roleFilter === "response" && row.isQuery) continue;
      all.push(row);
    }
    return all;
  }, [feed.events, roleFilter]);

  const pairing = useMemo(() => {
    const seen = new Map<string, { query: boolean; response: boolean }>();
    for (const r of rows) {
      const entry = seen.get(r.corrKey) ?? { query: false, response: false };
      if (r.isQuery) entry.query = true;
      else entry.response = true;
      seen.set(r.corrKey, entry);
    }
    return seen;
  }, [rows]);

  const columns: ReadonlyArray<Column<DnsRow>> = [
    { key: "t", header: "t (UTC)", render: (r) => r.wall },
    {
      key: "dir",
      header: "Direction",
      render: (r) => (
        <span className={cx("chip", r.egress ? "dir--egress" : "dir--ingress")}>
          {r.egress ? "egress" : "ingress"}
        </span>
      ),
    },
    {
      key: "role",
      header: "Packet",
      render: (r) => <span className="kind-cell">{r.isQuery ? "QUERY" : "RESPONSE"}</span>,
    },
    {
      key: "name",
      header: "qname",
      render: (r) => (
        <span title={`${r.qname} (${r.qtype})`}>
          {r.qname} <span className="muted-cell">{r.qtype}</span>
        </span>
      ),
    },
    { key: "txid", header: "TXID", render: (r) => r.txid },
    { key: "transport", header: "Transport", render: (r) => dnsTransportName(r.transport) },
    {
      key: "trunc",
      header: "Trunc",
      render: (r) =>
        r.truncated ? (
          <span className="badge badge--medium" title="Sensor clipped this packet payload">
            <span className="dot" aria-hidden="true" />
            truncated
          </span>
        ) : (
          <span className="muted-cell">—</span>
        ),
    },
    {
      key: "corr",
      header: "Correlation",
      render: (r) => {
        const pair = pairing.get(r.corrKey);
        const paired = pair?.query === true && pair.response === true;
        return (
          <span
            className={cx("chip", paired ? "corr--paired" : "corr--solo")}
            title="Matched by (txid, net namespace, transport) within this window"
          >
            {paired ? "paired" : r.isQuery ? "query only" : "response only"}
          </span>
        );
      },
    },
    { key: "ns", header: "Net NS", align: "right", render: (r) => r.netns },
    {
      key: "proc",
      header: "Process (tgid/pid)",
      render: (r) => <ProcessCell task={r.task} eventValids={r.eventValids} />,
    },
  ];

  return (
    <section aria-label="DNS packets">
      <div className="view-head">
        <h1 className="view-title">DNS</h1>
        <p className="view-sub">packets observed on the wire — not resolver lookups</p>
      </div>

      <EventToolbar
        idPrefix="dns"
        mode={mode}
        onModeChange={setMode}
        rangeSec={rangeSec}
        onRangeChange={setRangeSec}
        cluster={cluster}
        onClusterChange={setCluster}
        clusters={feed.clusters}
      />

      <FeedPanel
        title="DNS packet observations"
        feed={feed}
        mode={mode}
        rows={rows}
        columns={columns}
        rowKey={(r) => r.key}
        ariaLabel="DNS packet observations"
        errorScope="DNS packet feed"
        emptyTitle="No DNS packets observed in this window"
        emptyHint="This view lists packets the sensor saw — a silent window means no DNS traffic was captured, not that no lookups happened."
        skeletonCols={10}
        onCursor={setCursor}
        filterControl={
          <>
            <label className="visually-hidden" htmlFor="dns-role">
              Filter by packet role
            </label>
            <select
              id="dns-role"
              className="control"
              value={roleFilter}
              onChange={(ev) => setRoleFilter(ev.target.value as "all" | "query" | "response")}
            >
              <option value="all">queries + responses</option>
              <option value="query">queries only</option>
              <option value="response">responses only</option>
            </select>
          </>
        }
      />
    </section>
  );
}
