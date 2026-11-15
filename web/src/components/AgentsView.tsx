import { useDeferredValue, useMemo, useState } from "react";
import type { Agent } from "../types";
import { formatClock, formatNumber, formatTimestamp, isOnline, shortId } from "../lib/format";
import {
  EmptyRow,
  FilterTabs,
  LinkButton,
  Measure,
  MeasureBand,
  SearchField,
  Section,
  Table,
  stateClass,
} from "./ui";

type AgentFilter = "all" | "online" | "offline";

const clockOf = (epochSeconds: number) => formatClock(new Date(epochSeconds * 1000).toISOString());

function dayLabel(): string {
  return new Date().toLocaleDateString(undefined, {
    day: "2-digit",
    month: "short",
    year: "numeric",
  });
}

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
  const offline = agents.length - online;
  const sensorTypes = [...new Set(agents.flatMap((agent) => agent.sensors))];

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

  const clearFilters = () => {
    setSearch("");
    setFilter("all");
  };

  return (
    <div>
      <MeasureBand sub>
        <Measure value={formatNumber(agents.length)} label="registered" note="SPIFFE identities" />
        <Measure value={formatNumber(online)} label="online" note="heartbeat within 120s" />
        <Measure
          value={formatNumber(offline)}
          label="offline"
          note={offline ? "no heartbeat in 120s" : "all reporting"}
        />
        <Measure
          value={formatNumber(sensorTypes.length)}
          label="sensor types"
          note={sensorTypes.length ? sensorTypes.join(", ") : "none reported"}
        />
      </MeasureBand>

      <div style={{ marginTop: 26 }}>
        <Section
          title="Agents"
          meta={`${filtered.length} of ${agents.length}, ${dayLabel()}`}
        >
          <div className="tools">
            <SearchField
              value={search}
              onChange={setSearch}
              label="Search"
              placeholder="node, SPIFFE id, generation"
            />
            <div className="field" style={{ gap: 4 }}>
              <span>State</span>
              <FilterTabs<AgentFilter>
                ariaLabel="Filter agents by state"
                value={filter}
                onChange={setFilter}
                options={[
                  { value: "all", label: "All" },
                  { value: "online", label: "Online" },
                  { value: "offline", label: "Offline" },
                ]}
              />
            </div>
          </div>

          <Table minWidth={780} label="Agent register">
            <colgroup>
              <col style={{ width: "12%" }} />
              <col style={{ width: "36%" }} />
              <col style={{ width: "10%" }} />
              <col style={{ width: "12%" }} />
              <col style={{ width: "15%" }} />
              <col style={{ width: "15%" }} />
            </colgroup>
            <thead>
              <tr>
                <th scope="col">Node</th>
                <th scope="col">SPIFFE id</th>
                <th scope="col">Generation</th>
                <th scope="col">Sensors</th>
                <th scope="col" className="n">
                  Last seen
                </th>
                <th scope="col">State</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length ? (
                filtered.map((agent) => {
                  const agentOnline = isOnline(agent.last_seen_epoch);
                  const stateWord = agentOnline ? "online" : "offline";
                  return (
                    <tr
                      key={agent.id}
                      data-row="agent"
                      tabIndex={0}
                      onClick={() => onAgent(agent)}
                      onKeyDown={(keyboard) => {
                        if (keyboard.key === "Enter" || keyboard.key === " ") {
                          keyboard.preventDefault();
                          onAgent(agent);
                        }
                      }}
                    >
                      <td>{agent.node_name || "unnamed node"}</td>
                      <td className="rule-cell">{agent.spiffe_id}</td>
                      <td className="nowrap" title={agent.agent_generation}>
                        {shortId(agent.agent_generation, 8) || "—"}
                      </td>
                      <td className="nowrap">
                        {agent.sensors.length ? (
                          agent.sensors.join(", ")
                        ) : (
                          <span className="muted">none reported</span>
                        )}
                      </td>
                      <td className="n nowrap" title={formatTimestamp(agent.last_seen_epoch)}>
                        {clockOf(agent.last_seen_epoch)}
                      </td>
                      <td className="nowrap">
                        <span className={stateClass(stateWord)}>{stateWord}</span>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <EmptyRow colSpan={6}>
                  {agents.length ? "No agents match this filter." : "No agents registered."}{" "}
                  {agents.length ? (
                    <LinkButton type="button" onClick={clearFilters}>
                      Clear filters
                    </LinkButton>
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
