// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Severity is NEVER color-alone (DESIGN.md §9): every badge renders the
// word next to its tinted dot.
import type { Severity } from "../api/types";
import { cx } from "../lib/format";

export function SeverityBadge({ severity }: { severity: Severity }) {
  const cls = severity.toLowerCase();
  return (
    <span className={cx("badge", `badge--${cls}`)}>
      <span className="dot" aria-hidden="true" />
      {severity}
    </span>
  );
}

export type ConnectionStatus = "live" | "reconnecting" | "degraded" | "offline" | "idle";

const CONNECTION_META: Record<ConnectionStatus, { label: string; cls: string; pulse: boolean }> = {
  live: { label: "Live", cls: "conn--live", pulse: true },
  reconnecting: { label: "Reconnecting", cls: "conn--reconnecting", pulse: true },
  degraded: { label: "Degraded", cls: "conn--degraded", pulse: false },
  offline: { label: "Offline", cls: "conn--offline", pulse: false },
  idle: { label: "Paused", cls: "conn--idle", pulse: false },
};

/** Connection indicator: LED + word, announced via role=status. */
export function ConnectionBadge({ status, detail }: { status: ConnectionStatus; detail?: string }) {
  const meta = CONNECTION_META[status];
  return (
    <span role="status" className={cx("chip", "conn", meta.cls)}>
      <span className={cx("led", meta.pulse && "led--pulse")} aria-hidden="true" />
      {meta.label}
      {detail !== undefined && <span className="conn-detail">{detail}</span>}
    </span>
  );
}

/** Small status LED with accessible text sibling (pass label). */
export function Led({ tone, label }: { tone: "ok" | "warn" | "bad" | "idle"; label: string }) {
  return (
    <span className={cx("led-wrap", `led-wrap--${tone}`)}>
      <span className={cx("led", tone === "ok" && "led--pulse")} aria-hidden="true" />
      <span>{label}</span>
    </span>
  );
}
