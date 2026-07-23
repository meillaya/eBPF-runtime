// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Agent inventory: SPIFFE identity, heartbeat-derived health, sensor
// coverage, policy version, last-seen, event rate. Remote-agent health
// comes from heartbeat staleness; the local agent (matched by agent_id
// against /health) additionally reports sensor state and throughput.
import { useEffect, useRef, useState } from "react";
import { api } from "../api/client";
import { useNow, useQuery } from "../api/query";
import type { AgentInventory, AgentPage, Compatibility, Health } from "../api/types";
import { cx, formatAgo, formatInt, shortId } from "../lib/format";
import { Led } from "../ui/Badge";
import { Panel } from "../ui/Card";
import { DegradedBanner, ErrorPanel, TableSkeleton } from "../ui/QueryStates";
import { type Column, DataTable } from "../ui/Table";

const STALE_AFTER_SEC = 90;
const OFFLINE_AFTER_SEC = 300;

type AgentHealth = "healthy" | "degraded" | "blocked" | "offline";

const HEALTH_META: Record<AgentHealth, { tone: "ok" | "warn" | "bad"; word: string }> = {
  healthy: { tone: "ok", word: "healthy" },
  degraded: { tone: "warn", word: "degraded" },
  blocked: { tone: "bad", word: "blocked" },
  offline: { tone: "bad", word: "offline" },
};

function deriveHealth(agent: AgentInventory, local: Health | null, ageSec: number): AgentHealth {
  if (local !== null && local.agent_id === agent.agent_id) {
    if (local.blocked_sensors.length > 0) return "blocked";
    if (local.degraded_sensors.length > 0) return "degraded";
    return healthyOrStale(ageSec);
  }
  return healthyOrStale(ageSec);
}

function healthyOrStale(ageSec: number): AgentHealth {
  if (ageSec < STALE_AFTER_SEC) return "healthy";
  if (ageSec < OFFLINE_AFTER_SEC) return "degraded";
  return "offline";
}

/** SPIFFE URI → workload path (`agent/<cluster>/<node>`); full ID in title. */
function agentLabel(id: string): string {
  if (id.startsWith("spiffe://")) {
    const parts = id.slice("spiffe://".length).split("/");
    parts.shift();
    const tail = parts.join("/");
    if (tail !== "") return tail;
  }
  return shortId(id, 28);
}

function CapBadge({ active }: { active: boolean }) {
  return (
    <span className={cx("badge", active ? "badge--info" : "badge--medium")}>
      <span className="dot" aria-hidden="true" />
      {active ? "ACTIVE" : "INACTIVE"}
    </span>
  );
}

function CompatMatrix({ compat }: { compat: Compatibility }) {
  const cgroupOk = compat.cgroup_mode === "UNIFIED";
  return (
    <dl className="kv">
      <dt>Kernel</dt>
      <dd>{compat.kernel_release}</dd>
      <dt>BPF LSM</dt>
      <dd>
        <CapBadge active={compat.bpf_lsm_active} />
      </dd>
      <dt>BPF token</dt>
      <dd>
        <CapBadge active={compat.bpf_token_active} />
      </dd>
      <dt>Cgroup mode</dt>
      <dd>
        <span className={cx("badge", cgroupOk ? "badge--info" : "badge--medium")}>
          <span className="dot" aria-hidden="true" />
          {compat.cgroup_mode}
        </span>
      </dd>
      <dt>Prog types</dt>
      <dd>{formatInt(compat.bpf_program_type_allowlist.length)} allowlisted</dd>
    </dl>
  );
}

function SensorCoverage({ health }: { health: Health }) {
  const rows = [
    { label: "loaded", tone: "ok", names: health.loaded_sensors },
    { label: "degraded", tone: "warn", names: health.degraded_sensors },
    { label: "blocked", tone: "bad", names: health.blocked_sensors },
  ] as const;
  return (
    <ul className="sensor-list">
      {rows.map((r) => (
        <li key={r.label}>
          <Led tone={r.tone} label={`${r.label} · ${r.names.length}`} />
          <span className="sensor-state">{r.names.length > 0 ? r.names.join(", ") : "—"}</span>
        </li>
      ))}
    </ul>
  );
}

export function AgentsView() {
  const query = useQuery<AgentPage>("agents", () => api.listAgents({ limit: 100 }), 15_000);
  const health = useQuery<Health>("health", api.getHealth, 15_000);
  const compat = useQuery<Compatibility>("compatibility", api.getCompatibility, 60_000);
  const nowTick = useNow(5_000);
  const nowEpoch = nowTick * 5;

  const [eventRate, setEventRate] = useState<number | null>(null);
  const prevEmit = useRef<{ total: number; atMs: number } | null>(null);
  const emitted = health.data?.events_emitted_total;
  useEffect(() => {
    if (emitted === undefined) return;
    const atMs = Date.now();
    const prev = prevEmit.current;
    if (prev !== null && atMs > prev.atMs) {
      setEventRate(Math.max(0, Math.round(((emitted - prev.total) * 1000) / (atMs - prev.atMs))));
    }
    prevEmit.current = { total: emitted, atMs };
  }, [emitted]);

  const rows = query.data?.agents ?? [];
  const local = health.data ?? null;
  const counts = { healthy: 0, degraded: 0, attention: 0 };
  for (const a of rows) {
    const h = deriveHealth(a, local, nowEpoch - a.last_seen_epoch);
    if (h === "healthy") counts.healthy += 1;
    else if (h === "degraded") counts.degraded += 1;
    else counts.attention += 1;
  }
  const localSensorTotal =
    local === null
      ? 0
      : local.loaded_sensors.length + local.degraded_sensors.length + local.blocked_sensors.length;

  const columns: ReadonlyArray<Column<AgentInventory>> = [
    {
      key: "agent",
      header: "Agent (SPIFFE)",
      render: (a) => (
        <span className="strong" title={a.agent_id}>
          {agentLabel(a.agent_id)}
        </span>
      ),
    },
    { key: "node", header: "Node", render: (a) => a.node_name },
    { key: "cluster", header: "Cluster", render: (a) => a.cluster ?? "—" },
    {
      key: "health",
      header: "Health",
      render: (a) => {
        const h = deriveHealth(a, local, nowEpoch - a.last_seen_epoch);
        const meta = HEALTH_META[h];
        return <Led tone={meta.tone} label={meta.word} />;
      },
    },
    {
      key: "sensors",
      header: "Sensors",
      render: (a) => {
        if (local === null || local.agent_id !== a.agent_id) return "—";
        return (
          <span
            title={`degraded: ${local.degraded_sensors.join(", ") || "none"} · blocked: ${
              local.blocked_sensors.join(", ") || "none"
            }`}
          >
            {local.loaded_sensors.length}/{localSensorTotal}
          </span>
        );
      },
    },
    { key: "policy", header: "Policy", render: (a) => a.policy_version ?? "—" },
    {
      key: "seen",
      header: "Last seen",
      render: (a) => {
        const stale = nowEpoch - a.last_seen_epoch > STALE_AFTER_SEC;
        return <Led tone={stale ? "warn" : "ok"} label={formatAgo(a.last_seen_epoch, nowEpoch)} />;
      },
    },
    {
      key: "events",
      header: "Events",
      align: "right",
      render: (a) => {
        if (local === null || local.agent_id !== a.agent_id) return "—";
        const rate = eventRate === null ? "" : ` · ≈${formatInt(eventRate)}/s`;
        return `${formatInt(local.events_emitted_total)}${rate}`;
      },
    },
  ];

  return (
    <section aria-label="Agent inventory">
      <div className="view-head">
        <h1 className="view-title">Agents</h1>
        <p className="view-sub">fleet inventory · health · compatibility</p>
      </div>

      {query.status === "degraded" && (
        <DegradedBanner error={query.error} staleRows={rows.length} />
      )}

      <Panel title="Fleet summary">
        <div className="counter-row">
          <div className="counter">
            <span className="stat-value">{formatInt(rows.length)}</span>
            <span className="stat-label">Agents</span>
          </div>
          <div className="counter">
            <span className="stat-value">{formatInt(counts.healthy)}</span>
            <span className="stat-label">Healthy</span>
          </div>
          <div className="counter">
            <span className="stat-value stat-value--warn">{formatInt(counts.degraded)}</span>
            <span className="stat-label">Degraded</span>
          </div>
          <div className="counter">
            <span className="stat-value stat-value--warn">{formatInt(counts.attention)}</span>
            <span className="stat-label">Blocked / offline</span>
          </div>
        </div>
      </Panel>

      <div className="grid grid-2 stack-top">
        <Panel title="Node compatibility matrix">
          {compat.status === "error" && compat.data === null ? (
            <ErrorPanel
              error={compat.error}
              onRetry={compat.refetch}
              scope="compatibility endpoint"
            />
          ) : compat.data === null ? (
            <TableSkeleton rows={4} cols={2} />
          ) : (
            <CompatMatrix compat={compat.data} />
          )}
        </Panel>
        <Panel title="Local agent sensor coverage">
          {health.status === "error" && health.data === null ? (
            <ErrorPanel error={health.error} onRetry={health.refetch} scope="health endpoint" />
          ) : health.data === null ? (
            <TableSkeleton rows={3} cols={2} />
          ) : (
            <SensorCoverage health={health.data} />
          )}
        </Panel>
      </div>

      <Panel
        title="Inventory"
        flush
        meta={query.data !== null ? `${rows.length} agents` : undefined}
        className="stack-top"
      >
        {query.status === "error" ? (
          <div className="tbl-empty">
            <ErrorPanel error={query.error} onRetry={query.refetch} scope="agent inventory" />
          </div>
        ) : query.data === null ? (
          <TableSkeleton rows={6} cols={8} />
        ) : (
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(a) => a.agent_id}
            ariaLabel="Agents"
            empty={
              <div className="tbl-empty">
                <p className="well-hint">No agents registered with this control plane yet.</p>
              </div>
            }
          />
        )}
      </Panel>
    </section>
  );
}
