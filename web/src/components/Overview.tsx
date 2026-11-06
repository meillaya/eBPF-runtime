import { useMemo } from "react";
import type {
  Agent,
  Alert,
  AnalyticsSummary,
  Event,
  HealthSnapshot,
  Policy,
  Rollout,
} from "../types";
import {
  countOf,
  formatCompact,
  formatNumber,
  isOnline,
  kindTone,
  parseDate,
  percent,
  relativeTime,
  severityTone,
  statusTone,
  titleCase,
} from "../lib/format";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  Icon,
  ProgressBar,
  Segmented,
  TableShell,
} from "./ui";

export type Range = "1" | "6" | "24" | "168";

const rangeLabels: Record<Range, string> = {
  "1": "last hour",
  "6": "last 6 hours",
  "24": "last 24 hours",
  "168": "last 7 days",
};

const mixTones = ["teal", "sky", "violet", "amber", "rose", "emerald", "orange", "slate"];
const severityOrder = ["critical", "high", "medium", "low", "info"];

interface OverviewProps {
  agents: Agent[];
  events: Event[];
  alerts: Alert[];
  policies: Policy[];
  rollouts: Rollout[];
  analytics: AnalyticsSummary | null;
  analyticsError: string | null;
  health: HealthSnapshot | null;
  range: Range;
  onRange: (range: Range) => void;
  onNavigate: (tab: "events" | "alerts" | "agents" | "policies") => void;
  onEvent: (event: Event) => void;
  onAlert: (alert: Alert) => void;
  onAgent: (agent: Agent) => void;
}

function Stat({
  label,
  value,
  detail,
  icon,
  tone,
  tab,
  onClick,
}: {
  label: string;
  value: string;
  detail: string;
  icon: "server" | "activity" | "bell" | "shield";
  tone: string;
  tab: "events" | "alerts" | "agents" | "policies";
  onClick: () => void;
}) {
  const content = (
    <>
      <div className={`stat-icon stat-${tone}`}>
        <Icon name={icon} size={18} />
      </div>
      <span className="stat-label">{label}</span>
      <strong className="stat-value">{value}</strong>
      <span className="stat-detail">{detail}</span>
    </>
  );
  return (
    <a
      className="stat-card stat-button"
      href={`#${tab}`}
      onClick={(event) => {
        event.preventDefault();
        onClick();
      }}
    >
      {content}
    </a>
  );
}

export function Overview({
  agents,
  events,
  alerts,
  policies,
  rollouts,
  analytics,
  analyticsError,
  health,
  range,
  onRange,
  onNavigate,
  onEvent,
  onAlert,
  onAgent,
}: OverviewProps) {
  const online = agents.filter((agent) => isOnline(agent.last_seen_epoch)).length;
  const eventBuckets = analytics?.events ?? [];
  const alertBuckets = analytics?.alerts ?? [];
  const analyticsTotal = eventBuckets.reduce((sum, bucket) => sum + countOf(bucket.count), 0);
  const alertTotal = alertBuckets.reduce((sum, bucket) => sum + countOf(bucket.count), 0);
  const highPriority = alertBuckets.length
    ? alertBuckets
        .filter((bucket) => bucket.severity === "critical" || bucket.severity === "high")
        .reduce((sum, bucket) => sum + countOf(bucket.count), 0)
    : alerts.filter((alert) => alert.severity === "critical" || alert.severity === "high").length;
  const localEventKinds = useMemo(() => {
    const map = new Map<string, number>();
    for (const event of events) map.set(event.kind, (map.get(event.kind) ?? 0) + 1);
    return [...map.entries()].sort((a, b) => b[1] - a[1]);
  }, [events]);
  const localAlertSeverities = useMemo(() => {
    const map = new Map<string, number>();
    for (const alert of alerts) map.set(alert.severity, (map.get(alert.severity) ?? 0) + 1);
    return [...map.entries()].sort((a, b) => b[1] - a[1]);
  }, [alerts]);
  const mix = eventBuckets.length
    ? eventBuckets.map((bucket) => ({ kind: bucket.kind ?? "unknown", count: countOf(bucket.count) }))
    : localEventKinds.map(([kind, count]) => ({ kind, count }));
  const severities = alertBuckets.length
    ? severityOrder
        .map((severity) => ({
          severity,
          count: countOf(alertBuckets.find((bucket) => bucket.severity === severity)?.count),
        }))
        .filter((bucket) => bucket.count > 0)
    : localAlertSeverities.map(([severity, count]) => ({ severity, count }));
  const mixTotal = mix.reduce((sum, item) => sum + item.count, 0);
  const alertSeverityTotal = severities.reduce((sum, item) => sum + item.count, 0);
  const latestPolicy = policies[0];
  const latestRollout = rollouts[0];
  const latestRolloutStatus =
    latestRollout && latestPolicy && latestRollout.version === latestPolicy.version
      ? latestRollout
      : undefined;

  const activity = useMemo(() => {
    const bucketCount = 24;
    const times = events
      .map((event) => parseDate(event.time))
      .filter((time) => time > 0);
    if (!times.length) {
      const now = Date.now();
      return {
        values: Array.from({ length: bucketCount }, () => 0),
        start: now - 60_000,
        end: now,
        total: 0,
      };
    }
    const newest = Math.max(...times);
    const oldest = Math.min(...times);
    const span = Math.max(newest - oldest, 60_000);
    const start = newest - span;
    const bucketMs = span / bucketCount;
    const values = Array.from({ length: bucketCount }, () => 0);
    for (const time of times) {
      const index = Math.min(bucketCount - 1, Math.max(0, Math.floor((time - start) / bucketMs)));
      values[index] += 1;
    }
    return { values, start, end: newest, total: times.length };
  }, [events]);
  const activityMax = Math.max(1, ...activity.values);
  const activityWindow = Math.max(1, Math.round((activity.end - activity.start) / 60_000));

  const topAlerts = alerts.slice(0, 5);
  const topEvents = events.slice(0, 8);
  const agentRows = [...agents].sort((a, b) => {
    const aOnline = isOnline(a.last_seen_epoch) ? 1 : 0;
    const bOnline = isOnline(b.last_seen_epoch) ? 1 : 0;
    return bOnline - aOnline || b.last_seen_epoch - a.last_seen_epoch;
  });

  return (
    <div className="view overview">
      <div className="view-toolbar overview-toolbar">
        <div>
          <span className="eyebrow">Fleet pulse</span>
          <p className="toolbar-note">
            {analyticsError
              ? "Analytics is unavailable; cards fall back to the latest sample."
              : `Event and alert totals cover the ${rangeLabels[range]}.`}
          </p>
        </div>
        <Segmented
          ariaLabel="Analytics time range"
          value={range}
          onChange={onRange}
          options={[
            { value: "1", label: "1h" },
            { value: "6", label: "6h" },
            { value: "24", label: "24h" },
            { value: "168", label: "7d" },
          ]}
        />
      </div>

      <div className="kpi-grid">
        <Stat
          label="Online agents"
          value={`${online}/${agents.length}`}
          detail={agents.length ? `${agents.length - online} offline` : "no agents registered"}
          icon="server"
          tone={online === agents.length && agents.length > 0 ? "emerald" : "amber"}
          tab="agents"
          onClick={() => onNavigate("agents")}
        />
        <Stat
          label="Events"
          value={formatCompact(analyticsTotal || events.length)}
          detail={analyticsTotal ? rangeLabels[range] : "latest sample"}
          icon="activity"
          tone="sky"
          tab="events"
          onClick={() => onNavigate("events")}
        />
        <Stat
          label="Alerts"
          value={formatCompact(alertTotal || alerts.length)}
          detail={highPriority ? `${formatNumber(highPriority)} high priority` : "no high priority alerts"}
          icon="bell"
          tone={highPriority ? "rose" : "amber"}
          tab="alerts"
          onClick={() => onNavigate("alerts")}
        />
        <Stat
          label="Policies"
          value={formatNumber(policies.length)}
          detail={
            latestPolicy
              ? `latest v${latestPolicy.version} · ${titleCase(latestPolicy.status)}`
              : "nothing staged"
          }
          icon="shield"
          tone="violet"
          tab="policies"
          onClick={() => onNavigate("policies")}
        />
      </div>

      <div className="grid grid-2-1">
        <Card
          title="Event activity"
          subtitle={`${formatNumber(activity.total)} events across the latest ${activityWindow}-minute sample`}
          actions={<span className="card-meta">24 buckets</span>}
        >
          <div className="activity-chart" aria-label="Events per minute">
            {activity.values.map((value, index) => (
              <span
                className="activity-bar"
                key={index}
                style={{ height: `${Math.max(3, (value / activityMax) * 100)}%` }}
                title={`${value} events`}
              />
            ))}
          </div>
          <div className="activity-axis">
            <span>{new Date(activity.start).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
            <span>{new Date(activity.end).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
          </div>
        </Card>
        <Card
          title="Event mix"
          subtitle={analyticsError ? "from the latest event sample" : rangeLabels[range]}
          actions={
            analyticsError ? <Badge tone="amber">sample</Badge> : <Badge tone="emerald">clickhouse</Badge>
          }
        >
          {mix.length ? (
            <>
              <div className="mix-bar" aria-hidden="true">
                {mix.slice(0, 6).map((item, index) => (
                  <span
                    key={item.kind}
                    className={`mix-segment mix-${mixTones[index % mixTones.length]}`}
                    style={{ width: `${percent(item.count, mixTotal)}%` }}
                    title={`${item.kind}: ${item.count}`}
                  />
                ))}
              </div>
              <div className="mix-list">
                {mix.slice(0, 6).map((item, index) => (
                  <div className="mix-row" key={item.kind}>
                    <span className={`legend-dot dot-${mixTones[index % mixTones.length]}`} />
                    <span className="mix-name">{titleCase(item.kind)}</span>
                    <span className="mix-count">{formatNumber(item.count)}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <EmptyState icon="activity" title="No events yet" description="Once an agent is attached, events appear here." />
          )}
        </Card>
      </div>

      <div className="grid grid-2-1">
        <Card
          title="Recent alerts"
          subtitle={alerts.length ? `${alerts.length} in the latest sample` : "rule matches from recent events"}
          actions={
            <Button variant="ghost" size="sm" onClick={() => onNavigate("alerts")}>
              View all
            </Button>
          }
        >
          {severities.length ? (
            <div className="severity-breakdown">
              <div className="severity-mix" aria-hidden="true">
                {severities.map((entry) => (
                  <span
                    key={entry.severity}
                    className={`severity-seg mix-${severityTone(entry.severity)}`}
                    style={{ width: `${percent(entry.count, alertSeverityTotal)}%` }}
                    title={`${entry.severity}: ${entry.count}`}
                  />
                ))}
              </div>
              <div className="severity-legend">
                {severities.map((entry) => (
                  <span key={entry.severity}>
                    <span className={`legend-dot dot-${severityTone(entry.severity)}`} />
                    {titleCase(entry.severity)} <strong>{formatNumber(entry.count)}</strong>
                  </span>
                ))}
              </div>
            </div>
          ) : null}
          {topAlerts.length ? (
            <div className="alert-list">
              {topAlerts.map((alert) => (
                <button className="alert-item" key={alert.alert_id} onClick={() => onAlert(alert)}>
                  <span className={`severity-dot dot-${severityTone(alert.severity)}`} />
                  <span className="alert-main">
                    <span className="alert-explanation">{alert.explanation || alert.rule_id}</span>
                    <span className="alert-meta">
                      {alert.rule_id} · {alert.node_name} · {relativeTime(Date.parse(alert.fired_at) / 1000)}
                    </span>
                  </span>
                  <Badge tone={severityTone(alert.severity)}>{alert.severity}</Badge>
                </button>
              ))}
            </div>
          ) : (
            <EmptyState icon="shield" title="No alerts" description="The current rule packs have not matched." />
          )}
        </Card>
        <Card
          title="Agent health"
          subtitle={agents.length ? `${online} of ${agents.length} online` : "no registered nodes"}
          actions={
            <Button variant="ghost" size="sm" onClick={() => onNavigate("agents")}>
              View all
            </Button>
          }
        >
          {agentRows.length ? (
            <div className="agent-mini-list">
              {agentRows.slice(0, 6).map((agent) => {
                const agentOnline = isOnline(agent.last_seen_epoch);
                return (
                  <button className="agent-mini" key={agent.id} onClick={() => onAgent(agent)}>
                    <span className={`status-dot ${agentOnline ? "dot-emerald" : "dot-rose"}`} />
                    <span className="agent-mini-main">
                      <span>{agent.node_name || agent.spiffe_id}</span>
                      <span>{agent.sensors.join(", ") || "no sensors reported"}</span>
                    </span>
                    <span className="agent-mini-seen">{relativeTime(agent.last_seen_epoch)}</span>
                  </button>
                );
              })}
            </div>
          ) : (
            <EmptyState icon="server" title="No agents" description="Start an agent to populate the fleet." />
          )}
        </Card>
      </div>

      <Card
        title="Recent events"
        subtitle="Newest decoded events from PostgreSQL"
        actions={
          <Button variant="ghost" size="sm" onClick={() => onNavigate("events")}>
            Open event explorer
          </Button>
        }
        bodyClassName="table-body"
      >
        {topEvents.length ? (
          <TableShell>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Kind</th>
                  <th>Process</th>
                  <th>Path</th>
                  <th>PID</th>
                </tr>
              </thead>
              <tbody>
                {topEvents.map((event) => (
                  <tr key={event.event_id} onClick={() => onEvent(event)} className="clickable-row">
                    <td className="mono muted-cell">{relativeTime(Date.parse(event.time) / 1000)}</td>
                    <td>
                      <Badge tone={kindTone(event.kind)}>{event.kind}</Badge>
                    </td>
                    <td className="mono">{event.process_exec ?? "—"}</td>
                    <td className="path-cell" title={event.path}>
                      {event.path ?? "—"}
                    </td>
                    <td className="mono muted-cell">{event.pid}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableShell>
        ) : (
          <EmptyState icon="activity" title="No recent events" description="Events will appear as the agent forwards batches." />
        )}
      </Card>

      <div className="overview-footer">
        <div className="health-strip">
          <span className={`status-dot ${health?.api ? "dot-emerald" : "dot-rose"}`} />
          Control plane {health?.api ? "reachable" : "unreachable"}
          <span className="separator" />
          <span className={`status-dot ${health?.database ? "dot-emerald" : "dot-rose"}`} />
          Database {health?.database ? "ready" : "not ready"}
          {health?.detail ? <span className="health-detail">{health.detail}</span> : null}
        </div>
        <div className="policy-strip">
          {latestPolicy ? (
            <>
              <Badge tone={statusTone(latestPolicy.status)}>{titleCase(latestPolicy.status)}</Badge>
              <span>
                {latestPolicy.name} v{latestPolicy.version}
              </span>
              {latestRolloutStatus ? (
                <>
                  <span className="separator" />
                  <Badge tone={statusTone(latestRolloutStatus.status)}>
                    {titleCase(latestRolloutStatus.status)}
                  </Badge>
                  <span>
                    {latestRolloutStatus.applied_agents}/{latestRolloutStatus.expected_agents} applied
                  </span>
                  <div className="inline-progress">
                    <ProgressBar
                      value={latestRolloutStatus.applied_agents}
                      total={latestRolloutStatus.expected_agents}
                      tone={latestRolloutStatus.status === "rolled_back" ? "rose" : "teal"}
                    />
                  </div>
                </>
              ) : null}
            </>
          ) : (
            <span className="muted-cell">No policy staged</span>
          )}
        </div>
      </div>
    </div>
  );
}
