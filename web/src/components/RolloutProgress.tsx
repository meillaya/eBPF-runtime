// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Rollout progress: a segmented bar (applied / ready / rejected /
// disconnected, remainder = staged) plus the per-agent dot grid.
// Rejected and disconnected agents are ALWAYS rendered — never
// collapsed into the healthy mass. Dots carry tooltips and the legend
// gives every tone a word (never color-alone, DESIGN.md §9).
import type { AgentRolloutState, AgentRolloutStatus } from "../hooks/useRollout";
import { cx, formatInt } from "../lib/format";

export const STATE_LABELS: Record<AgentRolloutState, string> = {
  staged: "Staged",
  ready: "Ready",
  applied: "Applied",
  rejected: "Rejected",
  disconnected: "Disconnected",
};

const LEGEND_ORDER: readonly AgentRolloutState[] = [
  "applied",
  "ready",
  "staged",
  "rejected",
  "disconnected",
];

function dotTitle(a: AgentRolloutStatus): string {
  const digest =
    a.digestOk === null ? "digest unreported" : a.digestOk ? "digest verified" : "DIGEST MISMATCH";
  const reasons = a.reasons.length > 0 ? ` — ${a.reasons.join("; ")}` : "";
  return `${a.nodeName} (${a.agentId}) — ${STATE_LABELS[a.state]}, ${digest}${reasons}`;
}

export interface RolloutProgressProps {
  agents: readonly AgentRolloutStatus[];
  counts: Record<AgentRolloutState, number>;
  total: number;
  /** Hide the dot grid for compact list rows. */
  compact?: boolean;
}

export function RolloutProgress({ agents, counts, total, compact = false }: RolloutProgressProps) {
  const pct = (n: number): number => (total === 0 ? 0 : (n / total) * 100);
  const segments: ReadonlyArray<{ state: AgentRolloutState; width: number }> = [
    { state: "applied", width: pct(counts.applied) },
    { state: "ready", width: pct(counts.ready) },
    { state: "rejected", width: pct(counts.rejected) },
    { state: "disconnected", width: pct(counts.disconnected) },
  ];

  return (
    <div>
      <div
        className="sat-track"
        style={{ height: 10 }}
        role="img"
        aria-label={`Rollout progress: ${formatInt(counts.applied)} applied, ${formatInt(counts.ready)} ready, ${formatInt(counts.staged)} staged, ${formatInt(counts.rejected)} rejected, ${formatInt(counts.disconnected)} disconnected of ${formatInt(total)} agents`}
      >
        <div style={{ display: "flex", height: "100%", gap: 1 }}>
          {segments.map(
            (seg) =>
              seg.width > 0 && (
                <div
                  key={seg.state}
                  className={cx(
                    "sat-fill",
                    seg.state === "ready" && "sat-fill--warn",
                    seg.state === "rejected" && "sat-fill--crit",
                    seg.state === "disconnected" && "sat-fill--hot",
                  )}
                  style={{ width: `${seg.width}%` }}
                />
              ),
          )}
        </div>
      </div>

      {!compact && (
        <div className="dot-grid" style={{ marginTop: "var(--space-2)" }}>
          {agents.map((a) => (
            <span
              key={a.agentId}
              className={cx("agent-dot", `agent-dot--${a.state}`)}
              title={dotTitle(a)}
              role="img"
              aria-label={dotTitle(a)}
            />
          ))}
          {total === 0 && <span className="conn-detail">no agents tracked</span>}
        </div>
      )}

      <div className="legend" style={{ marginTop: "var(--space-2)" }}>
        {LEGEND_ORDER.map((state) => (
          <span key={state} className="legend-item">
            <span className={cx("agent-dot", `agent-dot--${state}`)} aria-hidden="true" />
            {STATE_LABELS[state]} {formatInt(counts[state])}
          </span>
        ))}
      </div>
    </div>
  );
}
