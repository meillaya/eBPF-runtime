import type { ReactNode } from "react";
import type { Agent, Alert, Event } from "../types";
import { formatClock, isOnline, relativeToIso, titleCase } from "../lib/format";
import {
  Button,
  CopyButton,
  DetailBlock,
  Drawer,
  KeyValue,
  RawJSON,
  Table,
  severityClass,
  stateClass,
} from "./ui";

/* The register stamps times as YYYY-MM-DD HH:MM:SS, local time. */
function stamp(value: string | number | null | undefined): string {
  if (value == null || value === "") return "—";
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return String(value);
  const pad = (part: number) => String(part).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

export function EventDrawer({
  event,
  alerts,
  onClose,
}: {
  event: Event | null;
  alerts: Alert[];
  onClose: () => void;
}) {
  const related = event ? alerts.filter((alert) => alert.event_id === event.event_id) : [];
  const rows: Array<[string, ReactNode]> = [];
  if (event) {
    rows.push(["Time", stamp(event.time)]);
    rows.push(["Sensor", event.sensor]);
    rows.push(["Event id", event.event_id]);
    rows.push(["PID, TGID", `${event.pid} / ${event.tgid}`]);
    rows.push(["Process", event.process_exec ?? "—"]);
    if (event.path) rows.push(["Path", event.path]);
    if (event.old_path) rows.push(["Old path", event.old_path]);
    if (event.parent_pid != null || event.child_pid != null) {
      rows.push(["Parent, child", `${event.parent_pid ?? "—"} / ${event.child_pid ?? "—"}`]);
    }
    rows.push(["Cgroup id", String(event.cgroup_id)]);
    if (event.boot_id) rows.push(["Boot id", event.boot_id]);
    if (event.seq != null) rows.push(["Sequence", String(event.seq)]);
    rows.push(["Schema", `${event.schema_major ?? "?"}.${event.schema_minor ?? "?"}`]);
    if (event.open_flags != null) rows.push(["Open flags", `0x${event.open_flags.toString(16)}`]);
    if (event.mode != null) rows.push(["Mode", `0${event.mode.toString(8)}`]);
    if (event.exit_code != null) rows.push(["Exit code", String(event.exit_code)]);
  }

  return (
    <Drawer
      open={Boolean(event)}
      onClose={onClose}
      wide
      title={event ? event.kind : "Event"}
      subtitle={event ? `${event.sensor} sensor, ${stamp(event.time)}` : undefined}
      footer={event ? <CopyButton value={JSON.stringify(event, null, 2)} /> : undefined}
    >
      {event ? (
        <>
          <KeyValue className="detail" rows={rows} />

          {event.argv?.length ? (
            <DetailBlock title="Argument vector">
              <RawJSON value={event.argv} />
            </DetailBlock>
          ) : null}

          <DetailBlock title="Related alerts">
            {related.length ? (
              <Table className="mini" label="Alerts raised for this event">
                <thead>
                  <tr>
                    <th scope="col">Severity</th>
                    <th scope="col">Rule</th>
                    <th scope="col" className="n">
                      Fired
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {related.map((alert) => (
                    <tr key={alert.alert_id}>
                      <td>
                        <span className={severityClass(alert.severity)}>{alert.severity}</span>
                      </td>
                      <td className="rule-cell">{alert.rule_id}</td>
                      <td className="n nowrap">{formatClock(alert.fired_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            ) : (
              <p className="detail-note">No alert was raised for this event.</p>
            )}
          </DetailBlock>

          <DetailBlock title="Raw event">
            <RawJSON value={event} />
          </DetailBlock>
        </>
      ) : null}
    </Drawer>
  );
}

export function AlertDrawer({
  alert,
  onClose,
  onOpenEvent,
}: {
  alert: Alert | null;
  onClose: () => void;
  onOpenEvent: (eventId: string) => void;
}) {
  const rows: Array<[string, ReactNode]> = alert
    ? [
        ["Rule", alert.rule_id],
        ["Node", alert.node_name || "—"],
        ["Cluster", alert.cluster || "—"],
        ["Event", alert.event_id],
        ["Fired", stamp(alert.fired_at)],
        ["Severity", <span className={severityClass(alert.severity)}>{alert.severity}</span>],
      ]
    : [];

  return (
    <Drawer
      open={Boolean(alert)}
      onClose={onClose}
      title={alert ? alert.rule_id : "Alert"}
      subtitle={
        alert
          ? `${titleCase(alert.severity)} severity, ${alert.node_name || "unknown node"}, ${relativeToIso(
              alert.fired_at,
            )}`
          : undefined
      }
      footer={alert ? <CopyButton value={JSON.stringify(alert, null, 2)} /> : undefined}
    >
      {alert ? (
        <>
          <p className="detail-note">{alert.explanation || "No explanation was recorded."}</p>
          <KeyValue className="detail" rows={rows} />
          <div className="btn-row">
            <Button type="button" onClick={() => onOpenEvent(alert.event_id)}>
              Open event
            </Button>
          </div>
          <DetailBlock title="Raw alert">
            <RawJSON value={alert} />
          </DetailBlock>
        </>
      ) : null}
    </Drawer>
  );
}

export function AgentDrawer({
  agent,
  onClose,
}: {
  agent: Agent | null;
  onClose: () => void;
}) {
  const online = agent ? isOnline(agent.last_seen_epoch) : false;
  const rows: Array<[string, ReactNode]> = agent
    ? [
        ["Node", agent.node_name || "—"],
        ["SPIFFE id", agent.spiffe_id],
        ["Generation", agent.agent_generation],
        ["Cluster", agent.cluster_id],
        ["Last seen", stamp(agent.last_seen_epoch * 1000)],
        [
          "State",
          <span className={stateClass(online ? "online" : "offline")}>
            {online ? "online" : "offline"}
          </span>,
        ],
        ["Agent id", agent.id],
      ]
    : [];

  return (
    <Drawer
      open={Boolean(agent)}
      onClose={onClose}
      title={agent ? agent.node_name || "Agent" : "Agent"}
      subtitle={agent ? agent.spiffe_id : undefined}
      footer={agent ? <CopyButton value={JSON.stringify(agent, null, 2)} /> : undefined}
    >
      {agent ? (
        <>
          <KeyValue className="detail" rows={rows} />
          <DetailBlock title="Reported sensors">
            <p className="detail-note">
              {agent.sensors.length
                ? agent.sensors.join(", ")
                : "No sensors were reported at registration."}
            </p>
          </DetailBlock>
          <DetailBlock title="Raw agent record">
            <RawJSON value={agent} />
          </DetailBlock>
        </>
      ) : null}
    </Drawer>
  );
}
