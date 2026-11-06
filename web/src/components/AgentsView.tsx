import { useDeferredValue, useMemo, useState } from "react";
import type { Agent } from "../types";
import { formatTimestamp, isOnline, relativeTime, shortId, truncateMiddle } from "../lib/format";
import { Badge, Button, Card, EmptyState, SearchInput, Segmented } from "./ui";

type AgentFilter = "all" | "online" | "offline";

export function AgentsView({
  agents,
  onAgent,
}: {
  agents: Agent[];
  onAgent: (agent: Agent) => void;
}) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<AgentFilter>("all");
  const deferredSearch = useDeferredValue(search.trim().toLowerCase());
  const online = agents.filter((agent) => isOnline(agent.last_seen_epoch)).length;
  const filtered = useMemo(
    () =>
      agents.filter((agent) => {
        const agentOnline = isOnline(agent.last_seen_epoch);
        if (filter === "online" && !agentOnline) return false;
        if (filter === "offline" && agentOnline) return false;
        if (!deferredSearch) return true;
        return [agent.node_name, agent.spiffe_id, agent.agent_generation]
          .join(" ")
          .toLowerCase()
          .includes(deferredSearch);
      }),
    [agents, deferredSearch, filter],
  );

  return (
    <div className="view">
      <div className="mini-stats">
        <div className="mini-stat">
          <span>Registered</span>
          <strong>{agents.length}</strong>
        </div>
        <div className="mini-stat">
          <span>Online</span>
          <strong className="text-emerald">{online}</strong>
        </div>
        <div className="mini-stat">
          <span>Offline</span>
          <strong className={agents.length - online ? "text-rose" : ""}>{agents.length - online}</strong>
        </div>
        <div className="mini-stat">
          <span>Coverage</span>
          <strong className="mini-stat-small">
            {agents.length
              ? `${new Set(agents.flatMap((agent) => agent.sensors)).size} sensor types`
              : "—"}
          </strong>
        </div>
      </div>

      <Card
        title="Agents"
        subtitle="One row per SPIFFE identity. Offline means no heartbeat in the last two minutes."
        bodyClassName="agents-body"
      >
        <div className="table-toolbar">
          <SearchInput
            value={search}
            onChange={setSearch}
            placeholder="Search node, SPIFFE id, generation…"
          />
          <Segmented
            ariaLabel="Filter agents"
            size="sm"
            value={filter}
            onChange={setFilter}
            options={[
              { value: "all", label: "All" },
              { value: "online", label: "Online" },
              { value: "offline", label: "Offline" },
            ]}
          />
        </div>
        {filtered.length ? (
          <div className="agent-grid">
            {filtered.map((agent) => {
              const agentOnline = isOnline(agent.last_seen_epoch);
              return (
                <button
                  type="button"
                  className={`agent-card ${agentOnline ? "agent-online" : "agent-offline"}`}
                  key={agent.id}
                  onClick={() => onAgent(agent)}
                >
                  <div className="agent-card-head">
                    <span className={`status-dot ${agentOnline ? "dot-emerald" : "dot-rose"}`} />
                    <span className="agent-node">{agent.node_name || "unnamed node"}</span>
                    <Badge tone={agentOnline ? "emerald" : "rose"}>
                      {agentOnline ? "online" : "offline"}
                    </Badge>
                  </div>
                  <span className="agent-spiffe mono" title={agent.spiffe_id}>
                    {truncateMiddle(agent.spiffe_id, 46)}
                  </span>
                  <div className="agent-meta-row">
                    <span title={formatTimestamp(agent.last_seen_epoch)}>
                      seen {relativeTime(agent.last_seen_epoch)}
                    </span>
                    <span className="mono" title={agent.agent_generation}>
                      gen {shortId(agent.agent_generation, 8)}
                    </span>
                  </div>
                  <div className="agent-sensors">
                    {agent.sensors.length ? (
                      agent.sensors.map((sensor) => (
                        <Badge tone="slate" key={sensor}>
                          {sensor}
                        </Badge>
                      ))
                    ) : (
                      <span className="muted-cell">No sensors reported</span>
                    )}
                  </div>
                </button>
              );
            })}
          </div>
        ) : (
          <EmptyState
            icon="server"
            title={agents.length ? "No agents match" : "No agents registered"}
            description={
              agents.length
                ? "Change the filter or clear the search."
                : "Start an agent with a valid transport config to register this node."
            }
            action={
              agents.length ? (
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    setSearch("");
                    setFilter("all");
                  }}
                >
                  Clear filters
                </Button>
              ) : undefined
            }
          />
        )}
      </Card>
    </div>
  );
}
