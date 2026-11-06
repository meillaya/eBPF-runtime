import type { Agent, Alert, Event } from "../types";
import { isOnline, kindTone, relativeTime, relativeToIso, severityTone, statusTone, titleCase } from "../lib/format";
import {
  Badge,
  Button,
  CopyButton,
  Drawer,
  KeyValue,
} from "./ui";

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
  return (
    <Drawer
      open={Boolean(event)}
      onClose={onClose}
      title={event ? event.kind : "Event"}
      subtitle={event ? `${event.sensor} sensor · ${event.time}` : undefined}
      size="lg"
      footer={
        event ? (
          <div className="drawer-footer-actions">
            <CopyButton value={JSON.stringify(event, null, 2)} label="Copy JSON" />
          </div>
        ) : undefined
      }
    >
      {event ? (
        <div className="detail-stack">
          <div className="detail-hero">
            <Badge tone={kindTone(event.kind)}>{event.kind}</Badge>
            <span className="mono">{event.event_id}</span>
          </div>
          <KeyValue
            rows={[
              ["Time", event.time],
              ["Sensor", titleCase(event.sensor)],
              ["PID / TGID", `${event.pid} / ${event.tgid}`],
              ["Process", event.process_exec ?? "—"],
              ["Path", event.path ?? "—"],
              ["Old path", event.old_path ?? "—"],
              ["Parent / child", `${event.parent_pid ?? "—"} / ${event.child_pid ?? "—"}`],
              ["Cgroup id", String(event.cgroup_id)],
              ["Boot id", event.boot_id ?? "—"],
              ["Sequence", event.seq != null ? String(event.seq) : "—"],
              ["Schema", `${event.schema_major ?? "?"}.${event.schema_minor ?? "?"}`],
              ["Open flags", event.open_flags != null ? `0x${event.open_flags.toString(16)}` : "—"],
              ["Mode", event.mode != null ? `0${event.mode.toString(8)}` : "—"],
              ["Exit code", event.exit_code != null ? String(event.exit_code) : "—"],
            ]}
          />
          {event.argv?.length ? (
            <div>
              <span className="eyebrow">Argument vector</span>
              <pre className="json-block">{JSON.stringify(event.argv, null, 2)}</pre>
            </div>
          ) : null}
          {related.length ? (
            <div>
              <span className="eyebrow">Alerts for this event</span>
              <div className="alert-list compact-list">
                {related.map((alert) => (
                  <div className="alert-item static" key={alert.alert_id}>
                    <span className={`severity-dot dot-${severityTone(alert.severity)}`} />
                    <span className="alert-main">
                      <span className="alert-explanation">{alert.explanation || alert.rule_id}</span>
                      <span className="alert-meta">{alert.rule_id}</span>
                    </span>
                    <Badge tone={severityTone(alert.severity)}>{alert.severity}</Badge>
                  </div>
                ))}
              </div>
            </div>
          ) : null}
          <div>
            <span className="eyebrow">Raw event</span>
            <pre className="json-block">{JSON.stringify(event, null, 2)}</pre>
          </div>
        </div>
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
  return (
    <Drawer
      open={Boolean(alert)}
      onClose={onClose}
      title={alert ? alert.rule_id : "Alert"}
      subtitle={alert ? relativeToIso(alert.fired_at) : undefined}
      footer={
        alert ? (
          <div className="drawer-footer-actions">
            <CopyButton value={JSON.stringify(alert, null, 2)} label="Copy JSON" />
          </div>
        ) : undefined
      }
    >
      {alert ? (
        <div className="detail-stack">
          <div className="detail-hero">
            <Badge tone={severityTone(alert.severity)} dot>
              {titleCase(alert.severity)}
            </Badge>
            <span className="mono">{alert.alert_id}</span>
          </div>
          <p className="detail-explanation">{alert.explanation || "No explanation supplied."}</p>
          <KeyValue
            rows={[
              ["Rule", alert.rule_id],
              ["Node", alert.node_name || "—"],
              ["Cluster", alert.cluster || "—"],
              ["Event", alert.event_id],
              ["Fired", alert.fired_at],
            ]}
          />
          <Button variant="secondary" size="sm" icon="activity" onClick={() => onOpenEvent(alert.event_id)}>
            Open matching event
          </Button>
          <div>
            <span className="eyebrow">Raw alert</span>
            <pre className="json-block">{JSON.stringify(alert, null, 2)}</pre>
          </div>
        </div>
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
  return (
    <Drawer
      open={Boolean(agent)}
      onClose={onClose}
      title={agent ? agent.node_name || "Agent" : "Agent"}
      subtitle={agent ? agent.spiffe_id : undefined}
      footer={
        agent ? (
          <div className="drawer-footer-actions">
            <CopyButton value={JSON.stringify(agent, null, 2)} label="Copy JSON" />
          </div>
        ) : undefined
      }
    >
      {agent ? (
        <div className="detail-stack">
          <div className="detail-hero">
            <Badge tone={online ? "emerald" : "rose"} dot>
              {online ? "online" : "offline"}
            </Badge>
            <span className="muted-cell">seen {relativeTime(agent.last_seen_epoch)}</span>
          </div>
          <KeyValue
            rows={[
              ["Node", agent.node_name || "—"],
              ["SPIFFE id", agent.spiffe_id],
              ["Generation", agent.agent_generation],
              ["Cluster id", agent.cluster_id],
              ["Last seen", new Date(agent.last_seen_epoch * 1000).toLocaleString()],
              ["Agent id", agent.id],
            ]}
          />
          <div>
            <span className="eyebrow">Reported sensors</span>
            <div className="chip-row">
              {agent.sensors.length ? (
                agent.sensors.map((sensor) => (
                  <Badge tone={statusTone("capable")} key={sensor}>
                    {sensor}
                  </Badge>
                ))
              ) : (
                <span className="muted-cell">No sensors were reported at registration.</span>
              )}
            </div>
          </div>
          <div>
            <span className="eyebrow">Raw agent</span>
            <pre className="json-block">{JSON.stringify(agent, null, 2)}</pre>
          </div>
        </div>
      ) : null}
    </Drawer>
  );
}
