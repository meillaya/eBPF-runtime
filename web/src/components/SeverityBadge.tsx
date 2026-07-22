// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Severity indicator for the ops views. Extends the API Severity enum
// (LOW/MEDIUM/HIGH/CRITICAL) with an INFO level for neutral telemetry.
// Never color-alone (DESIGN.md §9): the word always renders beside the
// tinted dot, and the badge doubles as accessible text.
import type { Severity } from "../api/types";
import { cx } from "../lib/format";

export const SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
export type SeverityLevel = Severity | "INFO";

export function isSeverityLevel(value: string): value is SeverityLevel {
  return (SEVERITY_LEVELS as readonly string[]).includes(value);
}

export function SeverityBadge({
  severity,
  label,
}: {
  severity: SeverityLevel;
  /** Override the rendered word (e.g. a deny action) while keeping tone. */
  label?: string;
}) {
  return (
    <span className={cx("badge", `badge--${severity.toLowerCase()}`)}>
      <span className="dot" aria-hidden="true" />
      {label ?? severity}
    </span>
  );
}
