// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Process attribution cell: tgid/pid + uid and an ALWAYS-visible validity
// marker. Green "valids ok" only when the record carries a valids map with
// every flag true; amber lists the fields the sensor marked invalid;
// muted "valids n/a" when the wire carried no validity data at all.
import type { Identity } from "../api/event-types";
import { invalidFields, processLabel } from "../lib/decode";
import { cx } from "../lib/format";

export function ValidityChip({ valids }: { valids: Record<string, boolean> | undefined }) {
  if (valids === undefined) {
    return (
      <span className={cx("chip", "validity", "validity--na")} title="No validity data on the wire">
        valids n/a
      </span>
    );
  }
  const bad = invalidFields(valids);
  if (bad.length === 0) {
    return (
      <span className={cx("chip", "validity", "validity--ok")} title="All reported fields valid">
        valids ok
      </span>
    );
  }
  return (
    <span
      className={cx("chip", "validity", "validity--bad")}
      title={`Sensor marked invalid: ${bad.join(", ")}`}
    >
      invalid: {bad.join(", ")}
    </span>
  );
}

export interface ProcessCellProps {
  task: Identity;
  /** Merge event-level valids with task-level ones for the marker. */
  eventValids?: Record<string, boolean> | undefined;
}

export function ProcessCell({ task, eventValids }: ProcessCellProps) {
  const merged =
    task.valids === undefined && eventValids === undefined
      ? undefined
      : { ...task.valids, ...eventValids };
  return (
    <span className="proc-cell">
      <span
        className="strong"
        title={`tgid/pid — task started ${task.task_start_time_ns ?? "?"} ns`}
      >
        {processLabel(task)}
      </span>
      {task.uid !== undefined && <span className="proc-uid">uid {task.uid}</span>}
      <ValidityChip valids={merged} />
    </span>
  );
}
