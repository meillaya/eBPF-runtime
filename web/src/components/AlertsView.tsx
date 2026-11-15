import { useDeferredValue, useMemo, useState } from "react";
import type { Alert } from "../types";
import { formatClock, formatIsoTimestamp, formatNumber } from "../lib/format";
import {
  EmptyRow,
  FilterTabs,
  LinkButton,
  Measure,
  MeasureBand,
  SearchField,
  Section,
  Table,
  severityClass,
} from "./ui";

type SeverityFilter = "all" | "critical" | "high" | "medium" | "low" | "info";

const severityOptions: Array<{ value: SeverityFilter; label: string }> = [
  { value: "all", label: "All" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
  { value: "info", label: "Info" },
];

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

  const clearFilters = () => {
    setSearch("");
    setSeverity("all");
  };

  return (
    <div>
      <MeasureBand sub>
        <Measure value={formatNumber(alerts.length)} label="alerts" note="latest sample" />
        <Measure value={formatNumber(critical)} label="critical alerts" />
        <Measure value={formatNumber(high)} label="high alerts" />
      </MeasureBand>

      <div style={{ marginTop: 26 }}>
        <Section
          title="Alert register"
          meta={`${filtered.length} of ${alerts.length}, newest first`}
        >
          <div className="tools">
            <SearchField
              value={search}
              onChange={setSearch}
              label="Search"
              placeholder="rule, explanation, node, event"
            />
            <div className="field" style={{ gap: 4 }}>
              <span>Severity</span>
              <FilterTabs
                ariaLabel="Filter alerts by severity"
                value={severity}
                onChange={setSeverity}
                options={severityOptions}
              />
            </div>
          </div>

          <Table minWidth={720} label="Alert register">
            <colgroup>
              <col style={{ width: "9%" }} />
              <col style={{ width: "24%" }} />
              <col style={{ width: "44%" }} />
              <col style={{ width: "12%" }} />
              <col style={{ width: "11%" }} />
            </colgroup>
            <thead>
              <tr>
                <th scope="col">Severity</th>
                <th scope="col">Rule</th>
                <th scope="col">Explanation</th>
                <th scope="col">Node</th>
                <th scope="col" className="n">
                  Fired
                </th>
              </tr>
            </thead>
            <tbody>
              {filtered.length ? (
                filtered.map((alert) => (
                  <tr
                    key={alert.alert_id}
                    data-row="alert"
                    tabIndex={0}
                    onClick={() => onAlert(alert)}
                    onKeyDown={(keyboard) => {
                      if (keyboard.key === "Enter" || keyboard.key === " ") {
                        keyboard.preventDefault();
                        onAlert(alert);
                      }
                    }}
                  >
                    <td className="nowrap">
                      <span className={severityClass(alert.severity)}>{alert.severity}</span>
                    </td>
                    <td className="rule-cell">{alert.rule_id}</td>
                    <td>
                      <span className="clamp2" title={alert.explanation}>
                        {alert.explanation || "—"}
                      </span>
                    </td>
                    <td className="nowrap">{alert.node_name || "—"}</td>
                    <td className="n nowrap" title={formatIsoTimestamp(alert.fired_at)}>
                      {formatClock(alert.fired_at)}
                    </td>
                  </tr>
                ))
              ) : (
                <EmptyRow colSpan={5}>
                  {alerts.length
                    ? "No alerts match this filter."
                    : "No alerts have been raised yet."}
                  {alerts.length ? (
                    <>
                      {" "}
                      <LinkButton type="button" onClick={clearFilters}>
                        Clear filters
                      </LinkButton>
                    </>
                  ) : null}
                </EmptyRow>
              )}
            </tbody>
          </Table>
        </Section>
      </div>
    </div>
  );
}
