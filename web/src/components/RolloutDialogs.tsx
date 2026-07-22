// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Confirmation dialogs for the three rollout mutations. Each one
// displays the audit intent (actor, action, resource, timestamp) and
// the commit dialog additionally forces explicit threshold
// confirmation — the commit button label itself carries the threshold.

import type { RolloutSummary } from "../hooks/useRollout";
import { formatInt } from "../lib/format";
import { ConfirmDialog, type IntentEntry } from "./ConfirmDialog";

export type RolloutConfirm = "commit" | "rollback" | "stage";

export interface RolloutDialogsProps {
  confirm: RolloutConfirm | null;
  version: string;
  threshold: number;
  summary: RolloutSummary | null;
  busy: string | null;
  actor: string;
  stageDigest: string;
  stagePbf: string;
  onCommit: () => void;
  onRollback: () => void;
  onStage: () => void;
  onClose: () => void;
}

export function RolloutDialogs({
  confirm,
  version,
  threshold,
  summary,
  busy,
  actor,
  stageDigest,
  stagePbf,
  onCommit,
  onRollback,
  onStage,
  onClose,
}: RolloutDialogsProps) {
  const intent = (action: string, resource: string, extra: IntentEntry[]): IntentEntry[] => [
    { label: "Actor", value: actor },
    { label: "Action", value: action },
    { label: "Resource", value: resource },
    ...extra,
    { label: "Recorded", value: new Date().toISOString() },
  ];
  const readyish = summary === null ? 0 : summary.counts.ready + summary.counts.applied;

  return (
    <>
      <ConfirmDialog
        open={confirm === "commit"}
        title={`Commit ${version}`}
        intent={intent("rollout.commit", `policy:${version}`, [
          { label: "Threshold", value: `${threshold}% agent ack required` },
          {
            label: "Ready",
            value:
              summary === null
                ? "—"
                : `${summary.readyPct}% (${formatInt(readyish)}/${formatInt(summary.total)} agents)`,
          },
        ])}
        confirmLabel={`Commit at ${threshold}% threshold`}
        busy={busy === "commit"}
        onConfirm={onCommit}
        onCancel={onClose}
      >
        <p>
          Committing activates the staged policy on every agent that acked ready. Confirm the ack
          threshold above — the control plane refuses commits below it.
        </p>
      </ConfirmDialog>

      <ConfirmDialog
        open={confirm === "rollback"}
        title={`Rollback ${version}`}
        tone="danger"
        intent={intent("policy.rollback", `policy:${version}`, [
          { label: "Effect", value: "agents revert to the last-known-good active policy" },
        ])}
        confirmLabel="Rollback to last-known-good"
        busy={busy === "rollback"}
        onConfirm={onRollback}
        onCancel={onClose}
      >
        <p>
          Rollback reverts the fleet to the previous active policy. Disconnected agents keep their
          last-known-good until they reconnect — they are never force-updated while offline.
        </p>
      </ConfirmDialog>

      <ConfirmDialog
        open={confirm === "stage"}
        title="Stage new policy"
        intent={intent("policy.stage", `policy:${version}`, [
          { label: "Digest", value: stageDigest },
          { label: "Payload", value: `${stagePbf.length} base64 chars (inactive)` },
        ])}
        confirmLabel="Stage (inactive)"
        busy={busy === "stage"}
        onConfirm={onStage}
        onCancel={onClose}
      >
        <p>
          Staging distributes the policy to agents but never activates it — activation requires a
          separate commit once the ready threshold is met.
        </p>
      </ConfirmDialog>
    </>
  );
}
