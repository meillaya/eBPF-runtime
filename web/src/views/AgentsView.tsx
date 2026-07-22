// SPDX-License-Identifier: Apache-2.0 OR MIT
import { api } from "../api/client";
import { useNow, useQuery } from "../api/query";
import type { AgentInventory, AgentPage } from "../api/types";
import { formatAgo, shortId } from "../lib/format";
import { Led } from "../ui/Badge";
import { Panel } from "../ui/Card";
import { DegradedBanner, ErrorPanel, TableSkeleton } from "../ui/QueryStates";
import { type Column, DataTable } from "../ui/Table";

const STALE_AFTER_SEC = 90;

export function AgentsView() {
  const query = useQuery<AgentPage>("agents", () => api.listAgents({ limit: 100 }), 15_000);
  const nowTick = useNow(5_000);
  const nowEpoch = nowTick * 5;

  const columns: ReadonlyArray<Column<AgentInventory>> = [
    {
      key: "agent",
      header: "Agent",
      render: (a) => (
        <span className="strong" title={a.agent_id}>
          {shortId(a.agent_id, 30)}
        </span>
      ),
    },
    { key: "node", header: "Node", render: (a) => a.node_name },
    { key: "cluster", header: "Cluster", render: (a) => a.cluster ?? "—" },
    {
      key: "seen",
      header: "Last seen",
      render: (a) => {
        const stale = nowEpoch - a.last_seen_epoch > STALE_AFTER_SEC;
        return <Led tone={stale ? "warn" : "ok"} label={formatAgo(a.last_seen_epoch, nowEpoch)} />;
      },
    },
    { key: "policy", header: "Policy", render: (a) => a.policy_version ?? "—" },
  ];

  const rows = query.data?.agents ?? [];

  return (
    <section aria-label="Agent inventory">
      <div className="view-head">
        <h1 className="view-title">Agents</h1>
        <p className="view-sub">fleet inventory + last-seen</p>
      </div>

      {query.status === "degraded" && (
        <DegradedBanner error={query.error} staleRows={rows.length} />
      )}

      <Panel
        title="Inventory"
        flush
        meta={query.data !== null ? `${rows.length} agents` : undefined}
      >
        {query.status === "error" ? (
          <div className="tbl-empty">
            <ErrorPanel error={query.error} onRetry={query.refetch} scope="agent inventory" />
          </div>
        ) : query.data === null ? (
          <TableSkeleton rows={6} cols={5} />
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
