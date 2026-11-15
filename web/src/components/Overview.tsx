import type { KeyboardEvent } from "react";
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
  formatClock,
  formatCompact,
  formatDuration,
  formatNumber,
  isOnline,
  parseDate,
  shortId,
} from "../lib/format";
import {
  EmptyRow,
  FilterTabs,
  KeyValue,
  LinkButton,
  Measure,
  MeasureBand,
  Section,
  Table,
  severityClass,
  stateClass,
} from "./ui";

export type Range = "1" | "6" | "24" | "168";

const rangeLabels: Record<Range, string> = {
  "1": "last hour",
  "6": "last 6 hours",
  "24": "last 24 hours",
  "168": "last 7 days",
};

const rangeOptions: Array<{ value: Range; label: string }> = [
  { value: "1", label: "1h" },
  { value: "6", label: "6h" },
  { value: "24", label: "24h" },
  { value: "168", label: "7d" },
];

const severityOrder = ["critical", "high", "medium", "low", "info"];
const familyOrder = ["process", "file", "unknown"];

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

interface KindCount {
  kind: string;
  count: number;
}

interface SeverityCount {
  severity: string;
  count: number;
}

interface Family {
  sensor: string;
  count: number;
  kinds: KindCount[];
}

/* Local clock for epoch-second records (agents, rollouts); ISO records use formatClock. */
function clockFromEpoch(epochSeconds: number): string {
  return formatClock(new Date(epochSeconds * 1000).toISOString());
}

function localKindCounts(events: Event[]): KindCount[] {
  const counts = new Map<string, number>();
  for (const event of events) counts.set(event.kind, (counts.get(event.kind) ?? 0) + 1);
  return [...counts.entries()]
    .map(([kind, count]) => ({ kind, count }))
    .sort((a, b) => b.count - a.count);
}

function localSeverityCounts(alerts: Alert[]): SeverityCount[] {
  const counts = new Map<string, number>();
  for (const alert of alerts) counts.set(alert.severity, (counts.get(alert.severity) ?? 0) + 1);
  return [...counts.entries()]
    .map(([severity, count]) => ({ severity, count }))
    .sort((a, b) => b.count - a.count);
}

/* Two sensor families. Prefer the sensor reported in the event sample; fall back to the
   kind's namespace when a rarer kind is absent from the 250-row sample (e.g. FileRename). */
function inferSensor(kind: string): string {
  if (/^process/i.test(kind)) return "process";
  if (/^file/i.test(kind)) return "file";
  return "unknown";
}

function familiesFromKinds(kinds: KindCount[], sensorByKind: Map<string, string>): Family[] {
  const families = new Map<string, Family>();
  for (const item of kinds) {
    const sensor = sensorByKind.get(item.kind) ?? inferSensor(item.kind);
    const family = families.get(sensor) ?? { sensor, count: 0, kinds: [] };
    family.count += item.count;
    family.kinds.push(item);
    families.set(sensor, family);
  }
  const rank = (sensor: string) => {
    const index = familyOrder.indexOf(sensor);
    return index === -1 ? familyOrder.length : index;
  };
  return [...families.values()]
    .sort((a, b) => rank(a.sensor) - rank(b.sensor))
    .map((family) => ({
      ...family,
      kinds: [...family.kinds].sort((a, b) => b.count - a.count),
    }));
}

function activateRow<T>(item: T, onOpen: (item: T) => void) {
  return (event: KeyboardEvent<HTMLTableRowElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onOpen(item);
    }
  };
}

export function Overview({
  agents,
  events,
  alerts,
  policies,
  rollouts,
  analytics,
  analyticsError,
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

  /* Alert severity split: analytics buckets for the window, latest sample when absent. */
  const severities: SeverityCount[] = alertBuckets.length
    ? severityOrder
        .map((severity) => ({
          severity,
          count: countOf(alertBuckets.find((bucket) => bucket.severity === severity)?.count),
        }))
        .filter((entry) => entry.count > 0)
    : localSeverityCounts(alerts);
  const criticalCount = severities.find((entry) => entry.severity === "critical")?.count ?? 0;

  const topAlerts = alerts.slice(0, 5);
  const topEvents = events.slice(0, 8);

  const agentRows = [...agents].sort((a, b) => {
    const aOnline = isOnline(a.last_seen_epoch) ? 1 : 0;
    const bOnline = isOnline(b.last_seen_epoch) ? 1 : 0;
    return bOnline - aOnline || b.last_seen_epoch - a.last_seen_epoch;
  });

  /* The applied version is the one a rollout can report on; latest policy otherwise. */
  const appliedPolicies = policies.filter((policy) => policy.status === "applied");
  const latestPolicy: Policy | undefined = (appliedPolicies.length ? appliedPolicies : policies)
    .slice()
    .sort((a, b) => b.version - a.version)
    .at(0);
  const policyRollout = latestPolicy
    ? [...rollouts]
        .filter((rollout) => rollout.version === latestPolicy.version)
        .sort((a, b) => (b.started_at_epoch ?? 0) - (a.started_at_epoch ?? 0))[0]
    : undefined;

  const policyMeasureNote = latestPolicy
    ? policyRollout
      ? `${latestPolicy.status}, ${policyRollout.applied_agents} of ${policyRollout.expected_agents} agents`
      : latestPolicy.status
    : "nothing staged";

  const ackPending = policyRollout
    ? Math.max(
        0,
        policyRollout.expected_agents - policyRollout.applied_agents - policyRollout.rejected_agents,
      )
    : 0;
  const ackText = policyRollout
    ? [
        `${formatNumber(policyRollout.applied_agents)} applied`,
        ackPending ? `${formatNumber(ackPending)} pending` : "",
        policyRollout.rejected_agents ? `${formatNumber(policyRollout.rejected_agents)} rejected` : "",
      ]
        .filter(Boolean)
        .join(", ")
    : "";

  /* Event activity of the latest sample: mean rate over the sample span. */
  const sampleTimes = events.map((event) => parseDate(event.time)).filter((time) => time > 0);
  const hasSample = sampleTimes.length > 0;
  const newestSample = hasSample ? Math.max(...sampleTimes) : 0;
  const oldestSample = hasSample ? Math.min(...sampleTimes) : 0;
  const sampleSpanMs = Math.max(newestSample - oldestSample, 60_000);
  const ratePerMinute = hasSample ? events.length / (sampleSpanMs / 60_000) : 0;
  const sampleSpanSeconds = Math.round(sampleSpanMs / 1000);

  /* Event mix: analytics buckets for the window, latest sample when absent. */
  const sensorByKind = new Map<string, string>();
  for (const event of events) sensorByKind.set(event.kind, event.sensor);
  const mixFromAnalytics = eventBuckets.length > 0;
  const mixKinds: KindCount[] = mixFromAnalytics
    ? eventBuckets.map((bucket) => ({ kind: bucket.kind ?? "unknown", count: countOf(bucket.count) }))
    : localKindCounts(events);
  const families = familiesFromKinds(mixKinds, sensorByKind);
  const mixMeta = mixFromAnalytics
    ? `${rangeLabels[range]}, analytics`
    : analyticsError
      ? "latest sample, analytics unavailable"
      : "latest sample";

  const fleetMeta = agents.length ? `${agents.length} nodes, ${online} online` : undefined;
  const rolloutMeta = latestPolicy
    ? `${latestPolicy.name} v${latestPolicy.version}, ${latestPolicy.status}`
    : undefined;

  return (
    <>
      <MeasureBand>
        <Measure
          value={`${online}/${agents.length}`}
          label="agents online"
          note={agents.length ? `${agents.length - online} offline` : "no agents registered"}
        />
        <Measure
          value={formatCompact(analyticsTotal || events.length)}
          label="events"
          note={analyticsTotal ? rangeLabels[range] : "latest sample"}
        />
        <Measure
          value={formatCompact(alertTotal || alerts.length)}
          label="alerts"
          note={criticalCount ? `${formatNumber(criticalCount)} critical` : "none critical"}
          signal={criticalCount > 0}
        />
        <Measure
          value={latestPolicy ? `v${latestPolicy.version}` : "—"}
          label="policy"
          note={policyMeasureNote}
        />
      </MeasureBand>

      <div className="grid12 body-grid">
        <div className="col-8 stack">
          <Section
            title="Recent alerts"
            meta={alerts.length ? `${topAlerts.length} of ${alerts.length}, newest first` : undefined}
            tools={<LinkButton onClick={() => onNavigate("alerts")}>All alerts</LinkButton>}
          >
            <Table label="Most recent alerts" minWidth={700}>
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
                {topAlerts.length ? (
                  topAlerts.map((alert) => (
                    <tr
                      key={alert.alert_id}
                      data-row="alert"
                      tabIndex={0}
                      onClick={() => onAlert(alert)}
                      onKeyDown={activateRow(alert, onAlert)}
                    >
                      <td className="nowrap">
                        <span className={severityClass(alert.severity)}>{alert.severity}</span>
                      </td>
                      <td className="rule-cell">{alert.rule_id}</td>
                      <td>
                        <span className="clamp3" title={alert.explanation || alert.rule_id}>
                          {alert.explanation || alert.rule_id}
                        </span>
                      </td>
                      <td className="nowrap">{alert.node_name}</td>
                      <td className="n nowrap">{formatClock(alert.fired_at)}</td>
                    </tr>
                  ))
                ) : (
                  <EmptyRow colSpan={5}>No alerts in the current sample.</EmptyRow>
                )}
              </tbody>
            </Table>
          </Section>

          <Section
            title="Recent events"
            meta={events.length ? `${topEvents.length} of ${events.length}, newest first` : undefined}
            tools={<LinkButton onClick={() => onNavigate("events")}>All events</LinkButton>}
          >
            <Table label="Most recent events" minWidth={640}>
              <colgroup>
                <col style={{ width: "11%" }} />
                <col style={{ width: "14%" }} />
                <col style={{ width: "24%" }} />
                <col style={{ width: "42%" }} />
                <col style={{ width: "9%" }} />
              </colgroup>
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">Kind</th>
                  <th scope="col">Process</th>
                  <th scope="col">Path</th>
                  <th scope="col" className="n">
                    PID
                  </th>
                </tr>
              </thead>
              <tbody>
                {topEvents.length ? (
                  topEvents.map((event) => {
                    const path = event.path ?? event.old_path ?? "—";
                    return (
                      <tr
                        key={event.event_id}
                        data-row="event"
                        tabIndex={0}
                        onClick={() => onEvent(event)}
                        onKeyDown={activateRow(event, onEvent)}
                      >
                        <td className="nowrap">{formatClock(event.time)}</td>
                        <td>{event.kind}</td>
                        <td>{event.process_exec ?? "—"}</td>
                        <td className="rule-cell">
                          <span title={path === "—" ? undefined : path}>{path}</span>
                        </td>
                        <td className="n">{event.pid}</td>
                      </tr>
                    );
                  })
                ) : (
                  <EmptyRow colSpan={5}>No events in the current sample.</EmptyRow>
                )}
              </tbody>
            </Table>
          </Section>
        </div>

        <div className="col-4 stack">
          <Section
            title="Fleet"
            meta={fleetMeta}
            tools={<LinkButton onClick={() => onNavigate("agents")}>Agents</LinkButton>}
          >
            <Table label="Fleet register" minWidth={330}>
              <colgroup>
                <col style={{ width: "30%" }} />
                <col style={{ width: "20%" }} />
                <col style={{ width: "30%" }} />
                <col style={{ width: "20%" }} />
              </colgroup>
              <thead>
                <tr>
                  <th scope="col">Node</th>
                  <th scope="col">Generation</th>
                  <th scope="col" className="n">
                    Last seen
                  </th>
                  <th scope="col">State</th>
                </tr>
              </thead>
              <tbody>
                {agentRows.length ? (
                  agentRows.map((agent) => {
                    const agentOnline = isOnline(agent.last_seen_epoch);
                    return (
                      <tr
                        key={agent.id}
                        data-row="agent"
                        tabIndex={0}
                        onClick={() => onAgent(agent)}
                        onKeyDown={activateRow(agent, onAgent)}
                      >
                        <td>{agent.node_name || agent.spiffe_id}</td>
                        <td className="nowrap" title={agent.agent_generation}>
                          {shortId(agent.agent_generation, 8) || "—"}
                        </td>
                        <td className="n nowrap">{clockFromEpoch(agent.last_seen_epoch)}</td>
                        <td className="nowrap">
                          <span className={stateClass(agentOnline ? "online" : "offline")}>
                            {agentOnline ? "online" : "offline"}
                          </span>
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <EmptyRow colSpan={4}>No agents registered.</EmptyRow>
                )}
              </tbody>
            </Table>
          </Section>

          <Section
            title="Rollout"
            meta={rolloutMeta}
            tools={<LinkButton onClick={() => onNavigate("policies")}>Policies</LinkButton>}
          >
            {policyRollout ? (
              <KeyValue
                rows={[
                  [
                    "Applied",
                    `${formatNumber(policyRollout.applied_agents)} of ${formatNumber(
                      policyRollout.expected_agents,
                    )} agents`,
                  ],
                  ["Threshold", `${Math.round(policyRollout.min_ratio * 100)}% minimum`],
                  ["Timeout", `${formatNumber(policyRollout.timeout_secs)} seconds`],
                  [
                    "Finished",
                    policyRollout.finished_at_epoch
                      ? clockFromEpoch(policyRollout.finished_at_epoch)
                      : "pending",
                  ],
                  ["Acks", ackText],
                ]}
              />
            ) : (
              <p className="empty-cell">
                {latestPolicy ? "No rollout recorded." : "No policy staged."}
              </p>
            )}
          </Section>

          <Section
            title="Event rate"
            meta="event register sample"
            tools={
              <FilterTabs
                variant="range"
                ariaLabel="Analytics window"
                value={range}
                onChange={onRange}
                options={rangeOptions}
              />
            }
          >
            {hasSample ? (
              <>
                <div className="rate-line">
                  <strong>{ratePerMinute.toFixed(1)}</strong> events per minute
                </div>
                <div
                  className="rate-note"
                  title={`${formatClock(new Date(oldestSample).toISOString())} to ${formatClock(new Date(newestSample).toISOString())}`}
                >
                  {formatNumber(events.length)} events, {formatDuration(sampleSpanSeconds)} sample
                </div>
              </>
            ) : (
              <p className="empty-cell">No events in the latest sample.</p>
            )}
          </Section>

          <Section title="Event mix" meta={mixMeta}>
            {families.length ? (
              <div className="mix">
                {families.map((family) => (
                  <div key={family.sensor}>
                    <table className="reg mini" aria-label={`${family.sensor} sensor event mix`}>
                      <colgroup>
                        <col style={{ width: "62%" }} />
                        <col style={{ width: "38%" }} />
                      </colgroup>
                      <thead>
                        <tr>
                          <th scope="col">{family.sensor}</th>
                          <th scope="col" className="n">
                            {formatNumber(family.count)}
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {family.kinds.map((kind) => (
                          <tr key={kind.kind}>
                            <td>{kind.kind}</td>
                            <td className="n">{formatNumber(kind.count)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ))}
              </div>
            ) : (
              <p className="empty-cell">No event mix in the latest sample.</p>
            )}
          </Section>
        </div>
      </div>
    </>
  );
}
