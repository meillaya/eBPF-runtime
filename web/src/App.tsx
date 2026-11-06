import { useEffect, useMemo, useState } from "react";
import { api, authEnabled, streamUrl } from "./api";
import { initAuth, login, logout } from "./auth";
import type { Agent, Alert, AuditRow, Event, Policy } from "./types";
import "./styles.css";

type Tab = "events" | "agents" | "policies" | "audit";

export default function App() {
  const [tab, setTab] = useState<Tab>("events");
  const [events, setEvents] = useState<Event[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [audit, setAudit] = useState<AuditRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [authenticated, setAuthenticated] = useState(false);
  const [live, setLive] = useState(false);

  useEffect(() => {
    initAuth().then(setAuthenticated).catch((reason) => setError(String(reason)));
  }, []);

  useEffect(() => {
    const load = async () => {
      try {
        setError(null);
        const [eventPage, alertPage, agentPage, policyPage] = await Promise.all([
          api.events(),
          api.alerts(),
          api.agents(),
          api.policies(),
        ]);
        setEvents(eventPage.events);
        setAlerts(alertPage.alerts);
        setAgents(agentPage.agents);
        setPolicies(policyPage.policies);
        if (tab === "audit") {
          setAudit((await api.audit()).audit);
        }
      } catch (reason) {
        setError(String(reason));
      }
    };
    void load();
  }, [tab]);

  useEffect(() => {
    if (tab !== "events") {
      return;
    }
    let socket: WebSocket | null = null;
    let retry: number | undefined;
    const connect = () => {
      socket = new WebSocket(streamUrl());
      socket.onopen = () => setLive(true);
      socket.onclose = () => {
        setLive(false);
        retry = window.setTimeout(connect, 2000);
      };
      socket.onmessage = (message) => {
        try {
          const event = JSON.parse(message.data) as Event;
          if (event.event_id) {
            setEvents((current) => [event, ...current].slice(0, 500));
          }
        } catch {
          // Ignore malformed frames.
        }
      };
    };
    connect();
    return () => {
      window.clearTimeout(retry);
      socket?.close();
    };
  }, [tab]);

  const counts = useMemo(() => {
    const byKind = new Map<string, number>();
    for (const event of events) {
      byKind.set(event.kind, (byKind.get(event.kind) ?? 0) + 1);
    }
    return byKind;
  }, [events]);

  return (
    <div className="shell">
      <header>
        <div>
          <h1>eBPF fleet</h1>
          <p className="muted">
            {live ? "live" : "snapshot"} · {events.length} recent events ·{" "}
            {alerts.length} alerts
          </p>
        </div>
        <div className="actions">
          {authEnabled ? (
            authenticated ? (
              <button onClick={() => void logout()}>Sign out</button>
            ) : (
              <button onClick={() => void login()}>Sign in</button>
            )
          ) : (
            <span className="badge">dev auth</span>
          )}
        </div>
      </header>

      <nav>
        {(["events", "agents", "policies", "audit"] as Tab[]).map((name) => (
          <button
            key={name}
            className={tab === name ? "active" : ""}
            onClick={() => setTab(name)}
          >
            {name}
          </button>
        ))}
      </nav>

      {error ? <div className="error">{error}</div> : null}

      {tab === "events" ? (
        <section>
          <div className="stats">
            {[...counts.entries()].map(([kind, count]) => (
              <span key={kind}>
                {kind} <strong>{count}</strong>
              </span>
            ))}
          </div>
          <table>
            <thead>
              <tr>
                <th>time</th>
                <th>kind</th>
                <th>pid</th>
                <th>path</th>
                <th>process</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <tr key={event.event_id}>
                  <td>{event.time}</td>
                  <td>{event.kind}</td>
                  <td>{event.pid}</td>
                  <td>{event.path ?? "-"}</td>
                  <td>{event.process_exec ?? "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ) : null}

      {tab === "agents" ? (
        <section>
          <table>
            <thead>
              <tr>
                <th>node</th>
                <th>spiffe id</th>
                <th>generation</th>
                <th>last seen</th>
              </tr>
            </thead>
            <tbody>
              {agents.map((agent) => (
                <tr key={agent.id}>
                  <td>{agent.node_name}</td>
                  <td>{agent.spiffe_id}</td>
                  <td>{agent.agent_generation}</td>
                  <td>{new Date(agent.last_seen_epoch * 1000).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ) : null}

      {tab === "policies" ? (
        <section>
          <table>
            <thead>
              <tr>
                <th>name</th>
                <th>version</th>
                <th>status</th>
                <th>digest</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {policies.map((policy) => (
                <tr key={policy.id}>
                  <td>{policy.name}</td>
                  <td>{policy.version}</td>
                  <td>{policy.status}</td>
                  <td className="mono">{policy.digest.slice(0, 16)}</td>
                  <td>
                    <button
                      onClick={() =>
                        api
                          .commit(policy.version)
                          .then(() => setTab("policies"))
                          .catch((reason) => setError(String(reason)))
                      }
                    >
                      commit
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ) : null}

      {tab === "audit" ? (
        <section>
          <table>
            <thead>
              <tr>
                <th>time</th>
                <th>actor</th>
                <th>action</th>
                <th>resource</th>
              </tr>
            </thead>
            <tbody>
              {audit.map((row, index) => (
                <tr key={`${row.action}-${index}`}>
                  <td>{new Date(row.created_at_epoch * 1000).toLocaleString()}</td>
                  <td>{row.actor}</td>
                  <td>{row.action}</td>
                  <td>{row.resource}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ) : null}
    </div>
  );
}
