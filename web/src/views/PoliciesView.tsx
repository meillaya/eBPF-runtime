// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Policy lifecycle. Browse = viewer+; commit/rollback = policy-admin+
// (Admin action in rbac.rs). Mutations report the 202 commit-response
// counters; per-agent acks surface over the gRPC stream, not here.
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useQuery } from "../api/query";
import type { Policy, PolicyCommitResponse, PolicyPage } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { permits } from "../auth/roles";
import { formatWall, shortId } from "../lib/format";
import { Alert } from "../ui/Alert";
import { Button } from "../ui/Button";
import { Panel } from "../ui/Card";
import { DegradedBanner, ErrorPanel, TableSkeleton } from "../ui/QueryStates";
import { type Column, DataTable } from "../ui/Table";

const STATUS_TONE: Record<Policy["status"], string> = {
  STAGED: "badge--medium",
  READY: "badge--low",
  COMMITTED: "badge--info",
  APPLIED: "badge--critical",
  REJECTED: "badge--critical",
  STALE: "badge--info",
};

export function PoliciesView() {
  const { session } = useAuth();
  const canStage = session !== null && permits(session.role, "admin");
  const query = useQuery<PolicyPage>("policies", () => api.listPolicies({ limit: 50 }));
  const [busy, setBusy] = useState<string | null>(null);
  const [result, setResult] = useState<{ version: string; res: PolicyCommitResponse } | null>(null);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [threshold, setThreshold] = useState(100);

  const run = async (
    version: string,
    digest: string,
    action: "commit" | "rollback",
  ): Promise<void> => {
    setBusy(`${action}:${version}`);
    setMutationError(null);
    setResult(null);
    try {
      const res =
        action === "commit"
          ? await api.commitPolicy({ version, digest, threshold_percent: threshold })
          : await api.rollbackPolicy(version, digest);
      setResult({ version, res });
      query.refetch();
    } catch (cause) {
      setMutationError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(null);
    }
  };

  const columns: ReadonlyArray<Column<Policy>> = [
    {
      key: "version",
      header: "Version",
      render: (p) => <span className="strong">{p.version}</span>,
    },
    {
      key: "status",
      header: "Status",
      render: (p) => (
        <span className={`badge ${STATUS_TONE[p.status]}`}>
          <span className="dot" aria-hidden="true" />
          {p.status}
        </span>
      ),
    },
    {
      key: "digest",
      header: "Digest",
      render: (p) => <span title={p.digest}>{shortId(p.digest, 16)}</span>,
    },
    { key: "created", header: "Created (UTC)", render: (p) => formatWall(p.created_at) },
    { key: "author", header: "Author", render: (p) => p.author ?? "—" },
    {
      key: "actions",
      header: canStage ? "Actions" : "",
      render: (p) =>
        canStage ? (
          <span className="action-row">
            <Button
              size="sm"
              variant="ghost"
              loading={busy === `commit:${p.version}`}
              onClick={() => void run(p.version, p.digest, "commit")}
            >
              Commit
            </Button>
            <Button
              size="sm"
              variant="danger"
              loading={busy === `rollback:${p.version}`}
              onClick={() => void run(p.version, p.digest, "rollback")}
            >
              Rollback
            </Button>
          </span>
        ) : (
          <span className="conn-detail">read-only</span>
        ),
    },
  ];

  const rows = query.data?.policies ?? [];

  return (
    <section aria-label="Policy lifecycle">
      <div className="view-head">
        <h1 className="view-title">Policies</h1>
        <p className="view-sub">{canStage ? "stage · commit · rollback" : "browse only"}</p>
      </div>

      <p className="well-hint">
        Two-phase rollout administration — per-agent acks, digest verification, threshold gating,
        rollback — lives in the <Link to="/rollout">rollout console</Link>.
      </p>

      {query.status === "degraded" && (
        <DegradedBanner error={query.error} staleRows={rows.length} />
      )}

      {mutationError !== null && (
        <Alert
          tone="critical"
          title="Policy mutation rejected"
          onDismiss={() => setMutationError(null)}
        >
          {mutationError}
        </Alert>
      )}
      {result !== null && (
        <Alert
          tone="info"
          title={`Issued for ${result.version} (202)`}
          onDismiss={() => setResult(null)}
        >
          committed {result.res.committed_count} · acked {result.res.ack_count} · rejected{" "}
          {result.res.rejected_count} — per-agent results arrive over the control stream.
        </Alert>
      )}

      {canStage && (
        <Panel title="Commit threshold" className="stack-top">
          <div className="action-row">
            <label className="stat-label" htmlFor="threshold">
              Ack threshold %
            </label>
            <input
              id="threshold"
              className="control"
              type="number"
              min={1}
              max={100}
              value={threshold}
              onChange={(ev) =>
                setThreshold(Math.max(1, Math.min(100, Number.parseInt(ev.target.value, 10) || 1)))
              }
            />
            <span className="conn-detail">commit is refused below this agent-ack percentage</span>
          </div>
        </Panel>
      )}

      <Panel
        title="Policy versions"
        flush
        className="stack-top"
        meta={query.data !== null ? `${rows.length} versions` : undefined}
      >
        {query.status === "error" ? (
          <div className="tbl-empty">
            <ErrorPanel error={query.error} onRetry={query.refetch} scope="policy store" />
          </div>
        ) : query.data === null ? (
          <TableSkeleton rows={5} cols={5} />
        ) : (
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(p) => p.version}
            ariaLabel="Policy versions"
            empty={
              <div className="tbl-empty">
                <p className="well-hint">No policies staged or committed yet.</p>
              </div>
            }
          />
        )}
      </Panel>
    </section>
  );
}
