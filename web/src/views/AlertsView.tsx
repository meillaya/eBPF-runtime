// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Alert feed with cursor pagination, severity filtering, and
// expandable rows: each alert opens its match-explanation tree,
// evidence links, process context, and the action taken (alert vs
// deny with source attribution). Read-only for every role — the
// openapi surface exposes no ack mutation yet.
import { Fragment, useState } from "react";
import { ApiError, api } from "../api/client";
import { useQuery } from "../api/query";
import type { Alert, AlertPage, Severity } from "../api/types";
import { AlertDetail } from "../components/AlertDetail";
import { SeverityBadge } from "../components/SeverityBadge";
import { formatWall, shortId } from "../lib/format";
import { Button } from "../ui/Button";
import { Panel } from "../ui/Card";
import { DegradedBanner, ErrorPanel, TableSkeleton } from "../ui/QueryStates";

const SEVERITY_FILTERS: ReadonlyArray<Severity | "ALL"> = [
  "ALL",
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
];

function actionTaken(alert: Alert): "DENY" | "ALERT" {
  return /\bdeny|denied|EPERM|lsm[_-]deny|own[_-]deny\b/i.test(alert.explanation)
    ? "DENY"
    : "ALERT";
}

export function AlertsView() {
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [severityFilter, setSeverityFilter] = useState<Severity | "ALL">("ALL");
  const [expanded, setExpanded] = useState<string | null>(null);
  const query = useQuery<AlertPage>(`alerts:${cursor ?? "first"}`, () =>
    api.listAlerts(cursor === undefined ? { limit: 50 } : { cursor, limit: 50 }),
  );

  const page = query.data?.alerts ?? [];
  const rows = severityFilter === "ALL" ? page : page.filter((a) => a.severity === severityFilter);
  const colCount = 7;

  return (
    <section aria-label="Alert feed">
      <div className="view-head">
        <h1 className="view-title">Alerts</h1>
        <p className="view-sub">rule engine feed — expand a row for the match tree</p>
      </div>

      {query.status === "degraded" && (
        <DegradedBanner error={query.error} staleRows={page.length} />
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
        <div className="toolbar">
          <label className="stat-label" htmlFor="alert-severity-filter">
            Severity
          </label>
          <select
            id="alert-severity-filter"
            className="control"
            value={severityFilter}
            onChange={(ev) => setSeverityFilter(ev.target.value as Severity | "ALL")}
          >
            {SEVERITY_FILTERS.map((s) => (
              <option key={s} value={s}>
                {s === "ALL" ? "all severities" : s}
              </option>
            ))}
          </select>
          <span className="spacer" />
          <span className="conn-detail">
            {severityFilter === "ALL"
              ? "every severity"
              : `filtered to ${severityFilter} — ${page.length - rows.length} hidden`}
          </span>
        </div>

        {query.status === "error" ? (
          <div className="tbl-empty">
            <ErrorPanel error={query.error} onRetry={query.refetch} scope="alert feed" />
          </div>
        ) : query.data === null ? (
          <TableSkeleton rows={7} cols={colCount} />
        ) : (
          <div className="tbl-wrap">
            <table className="tbl" aria-label="Alerts">
              <thead>
                <tr>
                  <th scope="col" aria-label="Expand" />
                  <th scope="col">Fired (UTC)</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Rule / version digest</th>
                  <th scope="col">Status</th>
                  <th scope="col">Action</th>
                  <th scope="col">Event</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => {
                  const open = expanded === a.id;
                  const action = actionTaken(a);
                  return (
                    <Fragment key={a.id}>
                      <tr>
                        <td>
                          <button
                            type="button"
                            className="row-expand"
                            aria-expanded={open}
                            aria-label={`${open ? "Collapse" : "Expand"} alert ${shortId(a.id, 12)}`}
                            onClick={() => setExpanded(open ? null : a.id)}
                          >
                            {open ? "▾" : "▸"}
                          </button>
                        </td>
                        <td>{formatWall(a.fired_at)}</td>
                        <td>
                          <SeverityBadge severity={a.severity} />
                        </td>
                        <td>
                          <span className="strong" title={a.rule_id}>
                            {shortId(a.rule_id, 20)}
                          </span>{" "}
                          <span className="conn-detail" title={a.rule_digest}>
                            @{shortId(a.rule_digest, 8)}
                          </span>
                        </td>
                        <td>
                          <span className="kind-cell">{a.status}</span>
                        </td>
                        <td>
                          <SeverityBadge
                            severity={action === "DENY" ? "CRITICAL" : "INFO"}
                            label={action}
                          />
                        </td>
                        <td>
                          <span title={a.event_id}>{shortId(a.event_id)}</span>
                        </td>
                      </tr>
                      {open && (
                        <tr className="detail-row">
                          <td colSpan={colCount}>
                            <AlertDetail alert={a} />
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
            {rows.length === 0 && (
              <div className="tbl-empty">
                <p className="well-hint">
                  {query.data.alerts.length === 0
                    ? cursor === undefined
                      ? "No alerts fired — rules are quiet. This is the empty state, not a failure."
                      : "No further pages."
                    : `No ${severityFilter} alerts on this page — clear the severity filter to see all ${query.data.alerts.length}.`}
                </p>
              </div>
            )}
          </div>
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
