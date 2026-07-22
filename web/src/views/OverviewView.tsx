// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Status board: identity strip, sensor LEDs, headline counters,
// compatibility flags, recent drops. Meta endpoints are unauthenticated
// in dev mode (openapi security: []), so this view works pre-login too.
import { api } from "../api/client";
import { useQuery } from "../api/query";
import type { Compatibility, DropRecord, Health } from "../api/types";
import { formatEpochSec, formatInt } from "../lib/format";
import { Led } from "../ui/Badge";
import { Panel } from "../ui/Card";
import { DegradedBanner, ErrorPanel, TableSkeleton } from "../ui/QueryStates";

function Counter({ label, value, tone }: { label: string; value: number; tone?: "warn" }) {
  return (
    <div className="counter">
      <span className={tone === "warn" && value > 0 ? "stat-value stat-value--warn" : "stat-value"}>
        {formatInt(value)}
      </span>
      <span className="stat-label">{label}</span>
    </div>
  );
}

function SensorList({ health }: { health: Health }) {
  const rows: Array<{ name: string; tone: "ok" | "warn" | "bad"; state: string }> = [
    ...health.loaded_sensors.map((name) => ({ name, tone: "ok" as const, state: "loaded" })),
    ...health.degraded_sensors.map((name) => ({ name, tone: "warn" as const, state: "degraded" })),
    ...health.blocked_sensors.map((name) => ({ name, tone: "bad" as const, state: "blocked" })),
  ];
  if (rows.length === 0) return <p className="well-hint">No sensors reported.</p>;
  return (
    <ul className="sensor-list">
      {rows.map((row) => (
        <li key={row.name}>
          <Led tone={row.tone} label={row.name} />
          <span className="sensor-state">{row.state}</span>
        </li>
      ))}
    </ul>
  );
}

function CompatFlags({ compat }: { compat: Compatibility }) {
  return (
    <dl className="kv">
      <dt>Kernel</dt>
      <dd>{compat.kernel_release}</dd>
      <dt>BPF LSM</dt>
      <dd>{compat.bpf_lsm_active ? "active" : "inactive"}</dd>
      <dt>BPF token</dt>
      <dd>{compat.bpf_token_active ? "active" : "inactive"}</dd>
      <dt>Cgroup mode</dt>
      <dd>{compat.cgroup_mode}</dd>
      <dt>Program types</dt>
      <dd>{compat.bpf_program_type_allowlist.length} allowlisted</dd>
    </dl>
  );
}

interface DropSummaryFields {
  id?: unknown;
  sensor?: unknown;
  count?: unknown;
  reason?: unknown;
}

function dropKey(drop: DropRecord, index: number): string {
  const id = (drop as DropSummaryFields).id;
  return typeof id === "string" ? id : `drop-row-${index}`;
}

function dropSummary(drop: DropRecord): string {
  const fields = drop as DropSummaryFields;
  const sensor = typeof fields.sensor === "string" ? fields.sensor : "unknown";
  const count = typeof fields.count === "number" ? formatInt(fields.count) : "1";
  const reason = typeof fields.reason === "string" ? ` — ${fields.reason}` : "";
  return `${sensor}: ${count} dropped${reason}`;
}

export function OverviewView() {
  const health = useQuery("health", api.getHealth, 5_000);
  const compat = useQuery("compatibility", api.getCompatibility, 30_000);
  const drops = useQuery("drops", () => api.listDrops({ limit: 8 }), 10_000);

  if (health.status === "error") {
    return (
      <section aria-label="Overview">
        <div className="view-head">
          <h1 className="view-title">Overview</h1>
        </div>
        <ErrorPanel error={health.error} onRetry={health.refetch} scope="control plane" />
      </section>
    );
  }

  return (
    <section aria-label="Overview">
      <div className="view-head">
        <h1 className="view-title">Overview</h1>
        <p className="view-sub">node status board</p>
      </div>

      {health.status === "degraded" && <DegradedBanner error={health.error} />}

      {health.data === null ? (
        <Panel title="Agent" flush>
          <TableSkeleton rows={4} cols={3} />
        </Panel>
      ) : (
        <div className="grid grid-3">
          <Panel title="Agent identity">
            <dl className="kv">
              <dt>Agent</dt>
              <dd title={health.data.agent_id}>{health.data.agent_id}</dd>
              <dt>Node</dt>
              <dd>{health.data.node_name}</dd>
              <dt>Cluster</dt>
              <dd>{health.data.cluster}</dd>
              <dt>Epoch</dt>
              <dd>{formatEpochSec(health.data.epoch_unix_sec)}</dd>
            </dl>
          </Panel>

          <Panel title="Throughput">
            <div className="counter-row">
              <Counter label="Events emitted" value={health.data.events_emitted_total} />
              <Counter
                label="Events dropped"
                value={health.data.events_dropped_total}
                tone="warn"
              />
              <Counter label="Supported rate/s" value={health.data.supported_load_rate} />
            </div>
          </Panel>

          <Panel title="Sensors">
            <SensorList health={health.data} />
          </Panel>
        </div>
      )}

      <div className="grid grid-2 stack-top">
        <Panel title="Kernel compatibility">
          {compat.status === "error" && compat.data === null ? (
            <ErrorPanel
              error={compat.error}
              onRetry={compat.refetch}
              scope="compatibility endpoint"
            />
          ) : compat.data === null ? (
            <TableSkeleton rows={3} cols={2} />
          ) : (
            <CompatFlags compat={compat.data} />
          )}
        </Panel>

        <Panel
          title="Recent drops"
          meta={drops.data !== null ? `${drops.data.drops.length} shown` : undefined}
        >
          {drops.status === "error" && drops.data === null ? (
            <ErrorPanel error={drops.error} onRetry={drops.refetch} scope="drops feed" />
          ) : drops.data === null ? (
            <TableSkeleton rows={3} cols={2} />
          ) : drops.data.drops.length === 0 ? (
            <p className="well-hint">No drop records — the pipeline is keeping up.</p>
          ) : (
            <ul className="drop-list">
              {drops.data.drops.map((drop, i) => (
                <li key={dropKey(drop, i)}>{dropSummary(drop)}</li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </section>
  );
}
