// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Pure rollout-state derivation shared by useRollout. Per-agent states
// mirror crates/policy-rollout AgentRolloutState; threshold math
// mirrors FleetRollout::threshold_met (integer percent, ready includes
// already-applied); digest comparison mirrors verify_digest
// (case-insensitive hex).
import type { AgentInventory, Policy, PolicyAck } from "../api/types";

export const AGENT_STATES = ["staged", "ready", "applied", "rejected", "disconnected"] as const;
export type AgentRolloutState = (typeof AGENT_STATES)[number];

export const STALE_AFTER_SEC = 90;

export interface AgentRolloutStatus {
  agentId: string;
  nodeName: string;
  state: AgentRolloutState;
  digestOk: boolean | null;
  reasons: string[];
  ackedAt: string | null;
  lastSeenEpoch: number | null;
}

export interface DigestReport {
  verified: number;
  mismatched: number;
  unreported: number;
}

export interface RolloutSummary {
  policy: Policy;
  agents: AgentRolloutStatus[];
  counts: Record<AgentRolloutState, number>;
  total: number;
  readyPct: number;
  appliedPct: number;
  thresholdMet: boolean;
  digest: DigestReport;
}

export interface AuditEvent {
  seq: number;
  at: string;
  actor: string;
  action: string;
  resource: string;
  success: boolean;
  error: string;
}

function digestMatches(reported: string | undefined, expected: string): boolean | null {
  if (reported === undefined || reported === "") return null;
  return reported.toLowerCase() === expected.toLowerCase();
}

function agentStatus(
  agentId: string,
  nodeName: string,
  lastSeenEpoch: number | null,
  ack: PolicyAck | undefined,
  policy: Policy,
  nowEpoch: number,
): AgentRolloutStatus {
  const stale = lastSeenEpoch !== null && nowEpoch - lastSeenEpoch > STALE_AFTER_SEC;
  if (ack === undefined) {
    return {
      agentId,
      nodeName,
      state: stale ? "disconnected" : "staged",
      digestOk: null,
      reasons: [],
      ackedAt: null,
      lastSeenEpoch,
    };
  }
  const digestOk = digestMatches(ack.digest ?? ack.hash_of_active, policy.digest);
  if (!ack.accepted) {
    return {
      agentId,
      nodeName,
      state: "rejected",
      digestOk,
      reasons: ack.rejected_reasons ?? [],
      ackedAt: ack.acked_at ?? null,
      lastSeenEpoch,
    };
  }
  const committed = policy.status === "COMMITTED" || policy.status === "APPLIED";
  return {
    agentId,
    nodeName,
    state: committed ? "applied" : "ready",
    digestOk,
    reasons: [],
    ackedAt: ack.acked_at ?? null,
    lastSeenEpoch,
  };
}

export function deriveSummary(
  policy: Policy,
  inventory: readonly AgentInventory[],
  acks: readonly PolicyAck[],
  nowEpoch: number,
  threshold: number,
): RolloutSummary {
  const ackByAgent = new Map(acks.map((a) => [a.agent_id, a]));
  const seen = new Set<string>();
  const agents: AgentRolloutStatus[] = inventory.map((inv) => {
    seen.add(inv.agent_id);
    return agentStatus(
      inv.agent_id,
      inv.node_name,
      inv.last_seen_epoch,
      ackByAgent.get(inv.agent_id),
      policy,
      nowEpoch,
    );
  });
  for (const ack of acks) {
    if (seen.has(ack.agent_id)) continue;
    agents.push(agentStatus(ack.agent_id, "—", null, ack, policy, nowEpoch));
  }
  const counts: Record<AgentRolloutState, number> = {
    staged: 0,
    ready: 0,
    applied: 0,
    rejected: 0,
    disconnected: 0,
  };
  const digest: DigestReport = { verified: 0, mismatched: 0, unreported: 0 };
  for (const a of agents) {
    counts[a.state] += 1;
    if (a.digestOk === null) digest.unreported += 1;
    else if (a.digestOk) digest.verified += 1;
    else digest.mismatched += 1;
  }
  const total = agents.length;
  const readyish = counts.ready + counts.applied;
  const readyPct = total === 0 ? 0 : Math.floor((readyish * 100) / total);
  const appliedPct = total === 0 ? 0 : Math.floor((counts.applied * 100) / total);
  return {
    policy,
    agents,
    counts,
    total,
    readyPct,
    appliedPct,
    thresholdMet: total > 0 && readyPct >= threshold,
    digest,
  };
}
