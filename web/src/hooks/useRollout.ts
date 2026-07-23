// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Rollout state management. Joins three independent polls — policy
// versions, agent inventory, per-version acks — into one per-agent
// picture of the STAGE→READY→COMMIT→APPLIED/REJECTED lifecycle via
// lib/rolloutStates (pure derivation mirroring crates/policy-rollout).
// Mutations append to a session-local audit trail shaped like the
// control-plane AuditRecord; the server-side log is not exposed over
// REST, so the console keeps its own honest record of what it issued.
import { useCallback, useMemo, useRef, useState } from "react";
import { api } from "../api/client";
import { type QueryState, useNow, useQuery } from "../api/query";
import type {
  AgentPage,
  Policy,
  PolicyAckPage,
  PolicyCommitResponse,
  PolicyPage,
  StagePolicyRequest,
} from "../api/types";
import { type AuditEvent, deriveSummary, type RolloutSummary } from "../lib/rolloutStates";

export type {
  AgentRolloutState,
  AgentRolloutStatus,
  AuditEvent,
  DigestReport,
  RolloutSummary,
} from "../lib/rolloutStates";
export { AGENT_STATES, STALE_AFTER_SEC } from "../lib/rolloutStates";

export interface UseRolloutResult {
  policiesQuery: QueryState<PolicyPage>;
  agentsQuery: QueryState<AgentPage>;
  policies: Policy[];
  selected: Policy | null;
  summary: RolloutSummary | null;
  thresholdMet: boolean;
  commit: () => Promise<void>;
  rollback: () => Promise<void>;
  stage: (req: StagePolicyRequest) => Promise<void>;
  busy: string | null;
  mutationError: string | null;
  lastResult: { action: string; version: string; res: PolicyCommitResponse } | null;
  audit: readonly AuditEvent[];
  clearMutationError: () => void;
  clearResult: () => void;
}

export function useRollout(
  selectedVersion: string | null,
  threshold: number,
  actor: string,
): UseRolloutResult {
  const policiesQuery = useQuery<PolicyPage>(
    "policies",
    () => api.listPolicies({ limit: 50 }),
    10_000,
  );
  const agentsQuery = useQuery<AgentPage>("agents", () => api.listAgents({ limit: 200 }), 15_000);
  const effectiveVersion = selectedVersion ?? policiesQuery.data?.policies[0]?.version ?? null;
  const acksQuery = useQuery<PolicyAckPage>(
    `acks:${effectiveVersion ?? "none"}`,
    () =>
      effectiveVersion === null
        ? Promise.resolve({ acks: [] })
        : api.listPolicyAcks(effectiveVersion, { limit: 200 }),
    5_000,
  );
  const nowEpoch = useNow(5_000) * 5;

  const [busy, setBusy] = useState<string | null>(null);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<{
    action: string;
    version: string;
    res: PolicyCommitResponse;
  } | null>(null);
  const [audit, setAudit] = useState<readonly AuditEvent[]>([]);
  const seqRef = useRef(0);

  const policies = policiesQuery.data?.policies ?? [];
  const selected =
    effectiveVersion === null
      ? null
      : (policies.find((p) => p.version === effectiveVersion) ?? null);

  const summary = useMemo<RolloutSummary | null>(() => {
    if (selected === null || agentsQuery.data === null) return null;
    return deriveSummary(
      selected,
      agentsQuery.data.agents,
      acksQuery.data?.acks ?? [],
      nowEpoch,
      threshold,
    );
  }, [selected, agentsQuery.data, acksQuery.data, nowEpoch, threshold]);

  const record = useCallback(
    (action: string, resource: string, success: boolean, error: string) => {
      seqRef.current += 1;
      const entry: AuditEvent = {
        seq: seqRef.current,
        at: new Date().toISOString(),
        actor,
        action,
        resource,
        success,
        error,
      };
      setAudit((prev) => [entry, ...prev].slice(0, 50));
    },
    [actor],
  );

  const run = useCallback(
    async (action: "commit" | "rollback") => {
      if (selected === null) return;
      const version = selected.version;
      setBusy(action);
      setMutationError(null);
      setLastResult(null);
      try {
        const res =
          action === "commit"
            ? await api.commitPolicy({
                version,
                digest: selected.digest,
                threshold_percent: threshold,
              })
            : await api.rollbackPolicy(version, selected.digest);
        record(`rollout.${action}`, `policy:${version}`, true, "");
        setLastResult({ action, version, res });
        policiesQuery.refetch();
        acksQuery.refetch();
      } catch (cause) {
        const message = cause instanceof Error ? cause.message : String(cause);
        record(`rollout.${action}`, `policy:${version}`, false, message);
        setMutationError(message);
      } finally {
        setBusy(null);
      }
    },
    [selected, threshold, record, policiesQuery, acksQuery],
  );

  const stage = useCallback(
    async (req: StagePolicyRequest) => {
      setBusy("stage");
      setMutationError(null);
      setLastResult(null);
      try {
        const res = await api.stagePolicy(req);
        record("policy.stage", `policy:${req.version}`, true, "");
        setLastResult({ action: "stage", version: req.version, res });
        policiesQuery.refetch();
      } catch (cause) {
        const message = cause instanceof Error ? cause.message : String(cause);
        record("policy.stage", `policy:${req.version}`, false, message);
        setMutationError(message);
      } finally {
        setBusy(null);
      }
    },
    [record, policiesQuery],
  );

  return {
    policiesQuery,
    agentsQuery,
    policies,
    selected,
    summary,
    thresholdMet: summary?.thresholdMet ?? false,
    commit: () => run("commit"),
    rollback: () => run("rollback"),
    stage,
    busy,
    mutationError,
    lastResult,
    audit,
    clearMutationError: () => setMutationError(null),
    clearResult: () => setLastResult(null),
  };
}
