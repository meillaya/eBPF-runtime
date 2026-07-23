// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Policy rollout administration: two-phase lifecycle (STAGE → READY →
// COMMIT → APPLIED / REJECTED), per-agent status, digest verification,
// threshold-gated commit, rollback. Browse = every role; stage /
// commit / rollback = policy-admin+ (Admin action in rbac.rs) and
// always behind a confirmation dialog that displays the audit intent.
import { useState } from "react";
import type { StagePolicyRequest } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { permits } from "../auth/roles";
import { RolloutDetail } from "../components/RolloutDetail";
import { type RolloutConfirm, RolloutDialogs } from "../components/RolloutDialogs";
import { RolloutVersionList, type StageForm } from "../components/RolloutVersionList";
import { useRollout } from "../hooks/useRollout";
import { formatInt } from "../lib/format";
import { Alert } from "../ui/Alert";
import { Panel } from "../ui/Card";
import { DegradedBanner, ErrorPanel, TableSkeleton } from "../ui/QueryStates";

export function RolloutView() {
  const { session } = useAuth();
  const canAdmin = session !== null && permits(session.role, "admin");
  const actor = session?.email ?? session?.subject ?? "unknown-operator";
  const [selectedVersion, setSelectedVersion] = useState<string | null>(null);
  const [threshold, setThreshold] = useState(100);
  const [confirm, setConfirm] = useState<RolloutConfirm | null>(null);
  const [stageForm, setStageForm] = useState<StageForm>({ version: "", digest: "", pbf: "" });
  const rollout = useRollout(selectedVersion, threshold, actor);
  const { summary, selected } = rollout;

  const runStage = (): void => {
    const req: StagePolicyRequest = {
      version: stageForm.version,
      digest: stageForm.digest,
      inactive_pbf_bytes: stageForm.pbf,
    };
    void rollout.stage(req).then(() => setConfirm(null));
  };

  return (
    <section aria-label="Policy rollout administration">
      <div className="view-head">
        <h1 className="view-title">Rollout</h1>
        <p className="view-sub">
          {canAdmin
            ? "stage · commit · rollback (policy-admin)"
            : "browse only — mutations need policy-admin"}
        </p>
      </div>

      {rollout.policiesQuery.status === "degraded" && (
        <DegradedBanner error={rollout.policiesQuery.error} staleRows={rollout.policies.length} />
      )}
      {rollout.mutationError !== null && (
        <Alert
          tone="critical"
          title="Rollout mutation rejected"
          onDismiss={rollout.clearMutationError}
        >
          {rollout.mutationError}
        </Alert>
      )}
      {rollout.lastResult !== null && (
        <Alert
          tone="info"
          title={`${rollout.lastResult.action} issued for ${rollout.lastResult.version} (202)`}
          onDismiss={rollout.clearResult}
        >
          committed {formatInt(rollout.lastResult.res.committed_count)} · acked{" "}
          {formatInt(rollout.lastResult.res.ack_count)} · rejected{" "}
          {formatInt(rollout.lastResult.res.rejected_count)} — per-agent results arrive over the
          control stream and appear in the detail column.
        </Alert>
      )}

      <div className="rollout-split stack-top">
        <RolloutVersionList
          policies={rollout.policies}
          selectedVersion={selected?.version ?? null}
          onSelect={setSelectedVersion}
          canStage={canAdmin}
          stageForm={stageForm}
          onStageFormChange={setStageForm}
          onStageRequest={() => setConfirm("stage")}
          queryStatus={rollout.policiesQuery.status}
          error={rollout.policiesQuery.error}
          onRetry={rollout.policiesQuery.refetch}
        />

        {summary === null ? (
          <Panel title="Rollout detail">
            {rollout.policiesQuery.status === "error" ? (
              <ErrorPanel
                error={rollout.policiesQuery.error}
                onRetry={rollout.policiesQuery.refetch}
                scope="policy store"
              />
            ) : (
              <TableSkeleton rows={5} cols={4} />
            )}
          </Panel>
        ) : (
          <RolloutDetail
            summary={summary}
            canAdmin={canAdmin}
            threshold={threshold}
            onThresholdChange={(v) => setThreshold(Math.max(1, Math.min(100, v)))}
            busy={rollout.busy}
            onCommitClick={() => setConfirm("commit")}
            onRollbackClick={() => setConfirm("rollback")}
            audit={rollout.audit}
          />
        )}
      </div>

      <RolloutDialogs
        confirm={confirm}
        version={confirm === "stage" ? stageForm.version : (selected?.version ?? "")}
        threshold={threshold}
        summary={summary}
        busy={rollout.busy}
        actor={actor}
        stageDigest={stageForm.digest}
        stagePbf={stageForm.pbf}
        onCommit={() => void rollout.commit().then(() => setConfirm(null))}
        onRollback={() => void rollout.rollback().then(() => setConfirm(null))}
        onStage={runStage}
        onClose={() => setConfirm(null)}
      />
    </section>
  );
}
