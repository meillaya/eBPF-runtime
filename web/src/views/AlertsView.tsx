// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Alert feed with cursor pagination. Read-only for every role (the
// openapi surface exposes no ack mutation yet).
import { useState } from "react";
import { ApiError, api } from "../api/client";
import { useQuery } from "../api/query";
import type { Alert, AlertPage } from "../api/types";
import { formatWall, shortId } from "../lib/format";
import { SeverityBadge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Panel } from "../ui/Card";
import { DegradedBanner, ErrorPanel, TableSkeleton } from "../ui/QueryStates";
import { type Column, DataTable } from "../ui/Table";

const COLUMNS: ReadonlyArray<Column<Alert>> = [
  { key: "fired", header: "Fired (UTC)", render: (a) => formatWall(a.fired_at) },
  { key: "sev", header: "Severity", render: (a) => <SeverityBadge severity={a.severity} /> },
  {
    key: "rule",
    header: "Rule",
    render: (a) => (
      <span className="strong" title={a.rule_id}>
        {shortId(a.rule_id, 24)}
      </span>
    ),
  },
  { key: "status", header: "Status", render: (a) => <span className="kind-cell">{a.status}</span> },
  {
    key: "why",
    header: "Explanation",
    render: (a) => <span title={a.explanation}>{a.explanation}</span>,
  },
  {
    key: "event",
    header: "Event",
    render: (a) => <span title={a.event_id}>{shortId(a.event_id)}</span>,
  },
];

export function AlertsView() {
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const query = useQuery<AlertPage>(`alerts:${cursor ?? "first"}`, () =>
    api.listAlerts(cursor === undefined ? { limit: 50 } : { cursor, limit: 50 }),
  );

  const rows = query.data?.alerts ?? [];

  return (
    <section aria-label="Alert feed">
      <div className="view-head">
        <h1 className="view-title">Alerts</h1>
        <p className="view-sub">rule engine feed</p>
      </div>

      {query.status === "degraded" && (
        <DegradedBanner error={query.error} staleRows={rows.length} />
      )}

      <Panel
        title="Alert feed"
        flush
        meta={query.data !== null ? `${rows.length} on page` : undefined}
        actions={
          query.data?.next_cursor !== undefined ? (
            <Button size="sm" variant="ghost" onClick={() => setCursor(query.data?.next_cursor)}>
              Older →
            </Button>
          ) : undefined
        }
      >
        {query.status === "error" ? (
          <div className="tbl-empty">
            <ErrorPanel error={query.error} onRetry={query.refetch} scope="alert feed" />
          </div>
        ) : query.data === null ? (
          <TableSkeleton rows={7} cols={6} />
        ) : (
          <DataTable
            columns={COLUMNS}
            rows={rows}
            rowKey={(a) => a.id}
            ariaLabel="Alerts"
            empty={
              <div className="tbl-empty">
                <p className="well-hint">
                  {cursor === undefined
                    ? "No alerts fired — rules are quiet. This is the empty state, not a failure."
                    : "No further pages."}
                </p>
              </div>
            }
          />
        )}
      </Panel>

      {query.error instanceof ApiError && query.error.status === 401 && (
        <p className="well-hint stack-top">
          HTTP 401 — the fleet proxy rejected the bearer token; re-sign in.
        </p>
      )}
    </section>
  );
}
