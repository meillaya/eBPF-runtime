import { useDeferredValue, useMemo, useState } from "react";
import type { Alert } from "../types";
import {
  formatIsoTimestamp,
  relativeToIso,
  severityTone,
  shortId,
  titleCase,
} from "../lib/format";
import { Badge, Button, Card, EmptyState, SearchInput, Segmented, TableShell } from "./ui";

type SeverityFilter = "all" | "critical" | "high" | "medium" | "low" | "info";

export function AlertsView({
  alerts,
  onAlert,
}: {
  alerts: Alert[];
  onAlert: (alert: Alert) => void;
}) {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<SeverityFilter>("all");
  const deferredSearch = useDeferredValue(search.trim().toLowerCase());
  const filtered = useMemo(
    () =>
      alerts.filter((alert) => {
        if (severity !== "all" && alert.severity !== severity) return false;
        if (!deferredSearch) return true;
        return [alert.rule_id, alert.explanation, alert.node_name, alert.event_id]
          .join(" ")
          .toLowerCase()
          .includes(deferredSearch);
      }),
    [alerts, deferredSearch, severity],
  );
  const critical = alerts.filter((alert) => alert.severity === "critical").length;
  const high = alerts.filter((alert) => alert.severity === "high").length;

  return (
    <div className="view">
      <div className="mini-stats">
        <div className="mini-stat">
          <span>Total alerts</span>
          <strong>{alerts.length}</strong>
        </div>
        <div className="mini-stat">
          <span>Critical</span>
          <strong className={critical ? "text-rose" : ""}>{critical}</strong>
        </div>
        <div className="mini-stat">
          <span>High</span>
          <strong className={high ? "text-orange" : ""}>{high}</strong>
        </div>
        <div className="mini-stat">
          <span>Latest</span>
          <strong className="mini-stat-small">{alerts[0] ? relativeToIso(alerts[0].fired_at) : "—"}</strong>
        </div>
      </div>

      <Card
        title="Alerts"
        subtitle={`${filtered.length} shown${filtered.length !== alerts.length ? ` of ${alerts.length}` : ""}`}
        bodyClassName="table-body"
      >
        <div className="table-toolbar">
          <SearchInput
            value={search}
            onChange={setSearch}
            placeholder="Search rule, explanation, node, event…"
          />
          <Segmented
            ariaLabel="Filter alerts by severity"
            size="sm"
            value={severity}
            onChange={setSeverity}
            options={[
              { value: "all", label: "All" },
              { value: "critical", label: "Critical" },
              { value: "high", label: "High" },
              { value: "medium", label: "Medium" },
              { value: "low", label: "Low" },
            ]}
          />
          {search || severity !== "all" ? (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setSearch("");
                setSeverity("all");
              }}
            >
              Clear
            </Button>
          ) : null}
        </div>
        {filtered.length ? (
          <TableShell>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th className="hide-sm">Rule</th>
                  <th>Explanation</th>
                  <th className="hide-sm">Node</th>
                  <th>Fired</th>
                  <th className="hide-sm">Event</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((alert) => (
                  <tr
                    key={alert.alert_id}
                    className="clickable-row"
                    tabIndex={0}
                    onClick={() => onAlert(alert)}
                    onKeyDown={(keyboard) => {
                      if (keyboard.key === "Enter" || keyboard.key === " ") {
                        keyboard.preventDefault();
                        onAlert(alert);
                      }
                    }}
                  >
                    <td>
                      <Badge tone={severityTone(alert.severity)} dot>
                        {titleCase(alert.severity)}
                      </Badge>
                    </td>
                    <td className="mono hide-sm">{alert.rule_id}</td>
                    <td className="explanation-cell" title={alert.explanation}>
                      {alert.explanation || "—"}
                    </td>
                    <td className="hide-sm">{alert.node_name || "—"}</td>
                    <td className="muted-cell" title={formatIsoTimestamp(alert.fired_at)}>
                      {relativeToIso(alert.fired_at)}
                    </td>
                    <td className="mono muted-cell hide-sm" title={alert.event_id}>
                      {shortId(alert.event_id, 10)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableShell>
        ) : (
          <EmptyState
            icon="bell"
            title={alerts.length ? "No alerts match" : "No alerts"}
            description={
              alerts.length
                ? "Change the severity filter or clear the search."
                : "Alert rows appear when a rule matches a forwarded event."
            }
          />
        )}
      </Card>
    </div>
  );
}
