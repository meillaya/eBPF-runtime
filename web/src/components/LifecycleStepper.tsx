// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Two-phase rollout lifecycle rail: STAGE → READY → COMMIT → APPLIED,
// with a REJECTED marker on the final step when agents refused the
// policy (mirrors crates/policy-rollout state-machine invariants:
// STAGE never activates, COMMIT needs threshold, APPLIED needs agent
// confirmation).
import type { PolicyStatus } from "../api/types";
import { cx } from "../lib/format";

const STEPS = ["STAGE", "READY", "COMMIT", "APPLIED"] as const;

function stepDone(status: PolicyStatus): number {
  switch (status) {
    case "STAGED":
      return 1;
    case "READY":
      return 2;
    case "COMMITTED":
      return 3;
    case "APPLIED":
      return 4;
    default:
      return status === "REJECTED" ? 1 : 0;
  }
}

export function LifecycleStepper({ status }: { status: PolicyStatus }) {
  const done = stepDone(status);
  const rejected = status === "REJECTED";
  return (
    <ol className="stepper" aria-label={`Rollout lifecycle: currently ${status}`}>
      {STEPS.map((label, i) => (
        <li
          key={label}
          className={cx(
            "step",
            i < done && "step--done",
            i === done && done < STEPS.length && !rejected && "step--current",
            rejected && i === STEPS.length - 1 && "step--rejected",
          )}
        >
          <span className="step-dot" aria-hidden="true" />
          <span className="step-label">
            {label}
            {rejected && i === STEPS.length - 1 ? " · REJECTED" : ""}
          </span>
        </li>
      ))}
    </ol>
  );
}
