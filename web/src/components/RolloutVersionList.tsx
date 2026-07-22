// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Left rail of the rollout console: policy versions with lifecycle
// badges, plus the stage form (policy-admin+ only — staging
// distributes an INACTIVE policy, never an activation).

import type { QueryStatus } from "../api/query";
import type { Policy, PolicyStatus } from "../api/types";
import { cx, formatWall, shortId } from "../lib/format";
import { Button } from "../ui/Button";
import { Panel } from "../ui/Card";
import { ErrorPanel } from "../ui/QueryStates";

export const POLICY_STATUS_TONE: Record<PolicyStatus, string> = {
  STAGED: "badge--medium",
  READY: "badge--low",
  COMMITTED: "badge--info",
  APPLIED: "badge--critical",
  REJECTED: "badge--critical",
  STALE: "badge--info",
};

export interface StageForm {
  version: string;
  digest: string;
  pbf: string;
}

export interface RolloutVersionListProps {
  policies: readonly Policy[];
  selectedVersion: string | null;
  onSelect: (version: string) => void;
  canStage: boolean;
  stageForm: StageForm;
  onStageFormChange: (form: StageForm) => void;
  onStageRequest: () => void;
  queryStatus: QueryStatus;
  error: Error | null;
  onRetry: () => void;
}

export function RolloutVersionList({
  policies,
  selectedVersion,
  onSelect,
  canStage,
  stageForm,
  onStageFormChange,
  onStageRequest,
  queryStatus,
  error,
  onRetry,
}: RolloutVersionListProps) {
  const stageReady = stageForm.version !== "" && stageForm.digest !== "" && stageForm.pbf !== "";
  return (
    <Panel title="Policy versions" flush meta={`${policies.length} versions`}>
      {queryStatus === "error" ? (
        <div className="tbl-empty">
          <ErrorPanel error={error} onRetry={onRetry} scope="policy store" />
        </div>
      ) : policies.length === 0 ? (
        <div className="tbl-empty">
          <p className="well-hint">No policy versions staged or committed yet.</p>
        </div>
      ) : (
        policies.map((p) => (
          <button
            key={p.version}
            type="button"
            className="version-row"
            aria-current={selectedVersion === p.version}
            onClick={() => onSelect(p.version)}
          >
            <span className="version-row-head">
              <span className="version-name">{p.version}</span>
              <span className={cx("badge", POLICY_STATUS_TONE[p.status])}>
                <span className="dot" aria-hidden="true" />
                {p.status}
              </span>
            </span>
            <span className="conn-detail">
              {formatWall(p.created_at)} · digest {shortId(p.digest, 14)} · {p.author ?? "—"}
            </span>
          </button>
        ))
      )}
      {canStage && (
        <div className="toolbar">
          <label className="visually-hidden" htmlFor="stage-version">
            Version
          </label>
          <input
            id="stage-version"
            className="control"
            placeholder="version"
            value={stageForm.version}
            onChange={(ev) => onStageFormChange({ ...stageForm, version: ev.target.value })}
          />
          <label className="visually-hidden" htmlFor="stage-digest">
            Digest
          </label>
          <input
            id="stage-digest"
            className="control"
            placeholder="sha256 digest"
            value={stageForm.digest}
            onChange={(ev) => onStageFormChange({ ...stageForm, digest: ev.target.value })}
          />
          <label className="visually-hidden" htmlFor="stage-pbf">
            Inactive pbf (base64)
          </label>
          <input
            id="stage-pbf"
            className="control"
            placeholder="inactive pbf (base64)"
            value={stageForm.pbf}
            onChange={(ev) => onStageFormChange({ ...stageForm, pbf: ev.target.value })}
          />
          <Button size="sm" disabled={!stageReady} onClick={onStageRequest}>
            Stage
          </Button>
        </div>
      )}
    </Panel>
  );
}
