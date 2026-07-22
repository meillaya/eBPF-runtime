// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Per-source drop/loss card: headline counters (ring-buffer reserve
// failures, discards, commits), a loss-per-poll sparkline, the ring
// saturation meter, and a sequence-gap strip (one cell per poll, red
// where gaps arrived). Pure SVG/CSS — no chart dependency.
import type { DropCounters } from "../hooks/useDropSeries";
import { cx, formatInt } from "../lib/format";

const SPARK_W = 100;
const SPARK_H = 30;

function sparkPaths(points: readonly number[]): { line: string; area: string } {
  if (points.length === 0) return { line: "", area: "" };
  const max = Math.max(1, ...points);
  const step = points.length === 1 ? SPARK_W : SPARK_W / (points.length - 1);
  const coords = points.map((v, i) => {
    const x = i * step;
    const y = SPARK_H - 2 - (v / max) * (SPARK_H - 6);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  const line = `M${coords.join(" L")}`;
  const first = coords[0] ?? "0,0";
  const lastX = ((points.length - 1) * step).toFixed(1);
  return { line, area: `${line} L${lastX},${SPARK_H} L${first.split(",")[0]},${SPARK_H} Z` };
}

function satTone(pct: number): string {
  if (pct >= 85) return "sat-fill--crit";
  if (pct >= 60) return "sat-fill--hot";
  if (pct >= 35) return "sat-fill--warn";
  return "";
}

function Metric({ label, value, bad }: { label: string; value: number; bad?: boolean }) {
  return (
    <div className="drop-metric">
      <span className={cx("stat-value", bad === true && value > 0 && "stat-value--bad")}>
        {formatInt(value)}
      </span>
      <span className="stat-label">{label}</span>
    </div>
  );
}

export interface DropCounterProps {
  counters: DropCounters;
  /** Rolling loss deltas (reserve_failure + discard) per poll. */
  points: readonly number[];
  /** Rolling sequence-gap deltas per poll. */
  gapPoints: readonly number[];
}

export function DropCounter({ counters, points, gapPoints }: DropCounterProps) {
  const { source, reserveFailure, discard, commit, attempt, gaps, saturationPct } = counters;
  const dropped = reserveFailure + discard;
  const lastDelta = points[points.length - 1] ?? 0;
  const hot = dropped > 0;
  const crit = saturationPct >= 85 || reserveFailure > 0;
  const { line, area } = sparkPaths(points);
  const sparkTone = crit ? "spark--crit" : hot ? "spark--hot" : "";
  const recentGaps = gapPoints.slice(-32);

  return (
    <article
      className={cx("drop-card", crit && "drop-card--crit", !crit && hot && "drop-card--hot")}
      aria-label={`Drop counters for ${source}`}
    >
      <header className="drop-card-head">
        <span className="drop-source">{source}</span>
        <span className="drop-rate">
          {points.length > 1 ? `+${formatInt(lastDelta)} last poll` : "sampling…"}
        </span>
      </header>

      <div className="drop-metrics">
        <Metric label="reserve fail" value={reserveFailure} bad />
        <Metric label="discard" value={discard} bad />
        <Metric label="commit" value={commit} />
        <Metric label="attempt" value={attempt} />
      </div>

      <svg
        className={cx("spark", sparkTone)}
        viewBox={`0 0 ${SPARK_W} ${SPARK_H}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={`Loss trend for ${source}: ${formatInt(dropped)} total lost across ${points.length} polls`}
      >
        {area !== "" && <path className="spark-area" d={area} />}
        {line !== "" && <path className="spark-line" d={line} />}
        <line className="spark-baseline" x1="0" y1={SPARK_H - 2} x2={SPARK_W} y2={SPARK_H - 2} />
      </svg>

      <div className="sat-row">
        <span className="stat-label">ring saturation</span>
        <div
          className="sat-track envelope-bar"
          role="img"
          aria-label={`Ring buffer saturation for ${source}: ${saturationPct} percent`}
        >
          <div
            className={cx("sat-fill", satTone(saturationPct))}
            style={{ width: `${Math.min(100, saturationPct)}%` }}
          />
        </div>
        <span className="sat-pct">{saturationPct}%</span>
      </div>

      <div className="sat-row">
        <span className="stat-label">seq gaps</span>
        <div
          className="gap-strip"
          role="img"
          aria-label={`${formatInt(gaps)} sequence gaps total; ${recentGaps.filter((g) => g > 0).length} of the last ${recentGaps.length} polls saw gaps`}
        >
          {recentGaps.length === 0 ? (
            <span className="conn-detail">no samples yet</span>
          ) : (
            recentGaps
              .map((g, i) => [`${source}-gap-${i}`, g] as const)
              .map(([cellKey, g]) => (
                <span
                  key={cellKey}
                  className={cx("gap-cell", g > 0 && "gap-cell--gap")}
                  title={g > 0 ? `${formatInt(g)} gaps` : "clean"}
                />
              ))
          )}
        </div>
        <span className="sat-pct">{formatInt(gaps)}</span>
      </div>
    </article>
  );
}
