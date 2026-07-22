// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Right column of the rollout console for the selected version:
// lifecycle stepper + per-agent progress, the commit gate (threshold
// input, digest verification report, commit/rollback triggers), the
// full per-agent table (rejected and disconnected rows are ALWAYS
// shown), and the session audit trail.
import type { AgentRolloutStatus, AuditEvent, RolloutSummary } from "../hooks/useRollout";
import { cx, formatInt, formatWall, shortId } from "../lib/format";
import { Button } from "../ui/Button";
import { Panel } from "../ui/Card";
import { type Column, DataTable } from "../ui/Table";
import { LifecycleStepper } from "./LifecycleStepper";
import { RolloutProgress } from "./RolloutProgress";
import { POLICY_STATUS_TONE } from "./RolloutVersionList";

const AGENT_COLUMNS: ReadonlyArray<Column<AgentRolloutStatus>> = [
  {
    key: "agent",
    header: "Agent",
    render: (a) => <span title={a.agentId}>{shortId(a.agentId, 26)}</span>,
  },
  { key: "node", header: "Node", render: (a) => a.nodeName },
  {
    key: "state",
    header: "State",
    render: (a) => (
      <span
        className={cx(
          "badge",
          `badge--${a.state === "applied" ? "low" : a.state === "ready" ? "info" : a.state === "staged" ? "medium" : "critical"}`,
        )}
      >
        <span className="dot" aria-hidden="true" />
        {a.state}
      </span>
    ),
  },
  {
    key: "digest",
    header: "Digest",
    render: (a) =>
      a.digestOk === null ? (
        <span className="conn-detail">unreported</span>
      ) : a.digestOk ? (
        <span className="digest-ok">verified</span>
      ) : (
        <span className="digest-bad">MISMATCH</span>
      ),
  },
  { key: "acked", header: "Acked (UTC)", render: (a) => formatWall(a.ackedAt ?? undefined) },
  { key: "reasons", header: "Reasons", render: (a) => a.reasons.join("; ") || "—" },
];

export interface RolloutDetailProps {
  summary: RolloutSummary;
  canAdmin: boolean;
  threshold: number;
  onThresholdChange: (value: number) => void;
  busy: string | null;
  onCommitClick: () => void;
  onRollbackClick: () => void;
  audit: readonly AuditEvent[];
}

export function RolloutDetail({
  summary,
  canAdmin,
  threshold,
  onThresholdChange,
  busy,
  onCommitClick,
  onRollbackClick,
  audit,
}: RolloutDetailProps) {
  const readyish = summary.counts.ready + summary.counts.applied;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-4)", minWidth: 0 }}>
      <Panel
        title={`Lifecycle — ${summary.policy.version}`}
        meta={
          <span className={cx("badge", POLICY_STATUS_TONE[summary.policy.status])}>
            <span className="dot" aria-hidden="true" />
            {summary.policy.status}
          </span>
        }
      >
        <LifecycleStepper status={summary.policy.status} />
        <div className="stack-top">
          <RolloutProgress agents={summary.agents} counts={summary.counts} total={summary.total} />
        </div>
      </Panel>

      <Panel
        title="Commit gate"
        meta={
          <>
            <span className="chip">
              <span className="conn-detail">ready</span>
              {summary.readyPct}% ({formatInt(readyish)}/{formatInt(summary.total)})
            </span>
            <span className="chip">
              <span className="conn-detail">digest</span>
              <span className="digest-ok">{formatInt(summary.digest.verified)} ok</span>
              {summary.digest.mismatched > 0 && (
                <span className="digest-bad"> {formatInt(summary.digest.mismatched)} bad</span>
              )}
              {summary.digest.unreported > 0 && (
                <span className="conn-detail"> {formatInt(summary.digest.unreported)} unrep</span>
              )}
            </span>
          </>
        }
      >
        <div className="action-row">
          <label className="stat-label" htmlFor="rollout-threshold">
            Ack threshold %
          </label>
          <input
            id="rollout-threshold"
            className="control"
            type="number"
            min={1}
            max={100}
            value={threshold}
            disabled={!canAdmin}
            onChange={(ev) => onThresholdChange(Number.parseInt(ev.target.value, 10) || 1)}
          />
          <Button
            variant="primary"
            size="sm"
            disabled={!canAdmin || !summary.thresholdMet || busy !== null}
            onClick={onCommitClick}
          >
            Commit
          </Button>
          <Button
            variant="danger"
            size="sm"
            disabled={!canAdmin || busy !== null}
            onClick={onRollbackClick}
          >
            Rollback
          </Button>
          {!summary.thresholdMet && (
            <span className="conn-detail">
              ready {summary.readyPct}% &lt; threshold {threshold}% — commit is gated
            </span>
          )}
        </div>
      </Panel>

      <Panel
        title="Per-agent status"
        flush
        meta={`${formatInt(summary.total)} agents — none hidden`}
      >
        <DataTable
          columns={AGENT_COLUMNS}
          rows={summary.agents}
          rowKey={(a) => a.agentId}
          ariaLabel="Per-agent rollout status"
          empty={
            <div className="tbl-empty">
              <p className="well-hint">No agents tracked for this version.</p>
            </div>
          }
        />
      </Panel>

      <Panel title="Console audit trail (this session)" meta={`${formatInt(audit.length)} entries`}>
        {audit.length === 0 ? (
          <p className="well-hint">
            No mutations issued from this console session. The control plane keeps the authoritative
            server-side audit log; this trail records what this browser issued.
          </p>
        ) : (
          <ul className="audit-list">
            {audit.map((e) => (
              <li key={e.seq}>
                <span className="audit-ts">{formatWall(e.at)}</span>
                <span className="audit-actor">{e.actor}</span>
                <span>
                  {e.action} → {e.resource} ·{" "}
                  {e.success ? (
                    <span className="digest-ok">202 accepted</span>
                  ) : (
                    <span className="digest-bad">failed — {e.error}</span>
                  )}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}
