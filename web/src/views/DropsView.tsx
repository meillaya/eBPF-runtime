// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Event drop/loss monitoring. Counters poll on their own key
// (independent of the event stream — a stream outage must not blind
// loss telemetry). Per-source cards show ring-buffer reserve
// failures, discards, sequence gaps and saturation; the envelope
// indicator compares the observed rate against the supported-load
// envelope (bench/schemas/supported-load.v1.json, surfaced via
// /health supported_load_rate). Read-only for every role.
import { useMemo, useState } from "react";
import { api } from "../api/client";
import { useQuery } from "../api/query";
import type { Health } from "../api/types";
import { DropCounter } from "../components/DropCounter";
import { useDropSeries } from "../hooks/useDropSeries";
import { cx, formatInt } from "../lib/format";
import { ConnectionBadge, type ConnectionStatus } from "../ui/Badge";
import { Panel } from "../ui/Card";
import { EmptyState } from "../ui/EmptyState";
import { DegradedBanner, ErrorPanel, TableSkeleton } from "../ui/QueryStates";

const POLL_STATUS: Record<string, ConnectionStatus> = {
  ready: "live",
  loading: "reconnecting",
  degraded: "degraded",
  error: "offline",
};

function EnvelopeMeter({ observed, supported }: { observed: number | null; supported: number }) {
  const pct = observed === null ? null : Math.min(100, Math.round((observed / supported) * 100));
  return (
    <div className="envelope">
      <div className="drop-metric">
        <span className="stat-value">
          {observed === null ? "—" : formatInt(Math.round(observed))}
        </span>
        <span className="stat-label">observed ev/s</span>
      </div>
      <div className="drop-metric">
        <span className="stat-value">{formatInt(supported)}</span>
        <span className="stat-label">supported ev/s</span>
      </div>
      <div className="envelope-bar">
        <div className="sat-row">
          <span className="stat-label">envelope</span>
          <div
            className="sat-track envelope-bar"
            role="img"
            aria-label={`Observed rate against the supported-load envelope: ${pct === null ? "measuring" : `${pct} percent`}`}
          >
            <div
              className={cx(
                "sat-fill",
                pct !== null && pct >= 85
                  ? "sat-fill--crit"
                  : pct !== null && pct >= 60
                    ? "sat-fill--hot"
                    : "",
              )}
              style={{ width: `${pct ?? 0}%` }}
            />
          </div>
          <span className="sat-pct">{pct === null ? "…" : `${pct}%`}</span>
        </div>
        <p className="conn-detail">
          sustained load above the envelope is expected to drop events, not silently pass
        </p>
      </div>
    </div>
  );
}

export function DropsView() {
  const drops = useDropSeries(5_000);
  const health = useQuery<Health>("health", api.getHealth, 15_000);
  const [sourceFilter, setSourceFilter] = useState<string>("all");

  const sources = useMemo(
    () => Array.from(new Set(drops.rows.map((r) => r.source))).sort(),
    [drops.rows],
  );
  const visible =
    sourceFilter === "all" ? drops.rows : drops.rows.filter((r) => r.source === sourceFilter);

  const supported = health.data?.supported_load_rate ?? 1000;
  const pollTone = POLL_STATUS[drops.query.status] ?? "offline";

  return (
    <section aria-label="Event drop and loss monitoring">
      <div className="view-head">
        <h1 className="view-title">Drops</h1>
        <p className="view-sub">ring-buffer loss · sequence gaps · polled apart from the stream</p>
      </div>

      {drops.query.status === "degraded" && (
        <DegradedBanner error={drops.query.error} staleRows={drops.rows.length} />
      )}

      <Panel
        title="Pipeline loss"
        className="stack-top"
        meta={
          <>
            <ConnectionBadge status={pollTone} detail="counter poll" />
            <span className="chip">
              <span className="conn-detail">total lost</span>
              {formatInt(drops.totalDropped)}
            </span>
            <span className="chip">
              <span className="conn-detail">seq gaps</span>
              {formatInt(drops.totalGaps)}
            </span>
          </>
        }
      >
        <EnvelopeMeter observed={drops.observedRate} supported={supported} />
      </Panel>

      <Panel
        title="Per-source counters"
        className="stack-top"
        meta={
          drops.query.data !== null ? (
            <>
              <label className="visually-hidden" htmlFor="drop-source-filter">
                Filter by source
              </label>
              <select
                id="drop-source-filter"
                className="control"
                value={sourceFilter}
                onChange={(ev) => setSourceFilter(ev.target.value)}
              >
                <option value="all">all sources</option>
                {sources.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
              <span>{visible.length} sources</span>
            </>
          ) : undefined
        }
      >
        {drops.query.status === "error" ? (
          <ErrorPanel error={drops.query.error} onRetry={drops.query.refetch} scope="drops feed" />
        ) : drops.query.data === null ? (
          <TableSkeleton rows={4} cols={4} />
        ) : visible.length === 0 ? (
          <EmptyState
            title="No drop records"
            hint="Every ring-buffer reserve is succeeding and no sequences gapped. This is the healthy state, not a missing feed — the poll is live."
          />
        ) : (
          <div className="drop-grid">
            {visible.map((row) => (
              <DropCounter
                key={row.source}
                counters={row}
                points={drops.series.get(row.source) ?? []}
                gapPoints={drops.gapSeries.get(row.source) ?? []}
              />
            ))}
          </div>
        )}
      </Panel>

      <p className="well-hint stack-top">
        Counters refresh every 5s on an independent poll — if the event stream dies, loss telemetry
        here still reports. Saturation derives from reserve failures over attempts unless the agent
        publishes an explicit ring percentage.
      </p>
    </section>
  );
}
