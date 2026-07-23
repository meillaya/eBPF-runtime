// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Log-decade latency histogram: one bar per bucket (count-proportional,
// count + wall-time sum as text), plus a log axis carrying p50/p95/p99/
// p99.9 markers. Bars are aria-hidden decoration; every number is real
// text, so the figure is readable without sight.

import { cx } from "../lib/format";
import type { HistogramBucket, LatencyPercentiles } from "../lib/histogram";
import { bucketIndexFor, formatNs, LATENCY_EDGES_NS } from "../lib/histogram";

interface Marker {
  key: "p50" | "p95" | "p99" | "p999";
  label: string;
  value: number | null;
  cls: string;
}

function markersOf(p: LatencyPercentiles): Marker[] {
  return [
    { key: "p50", label: "p50", value: p.p50, cls: "mark--p50" },
    { key: "p95", label: "p95", value: p.p95, cls: "mark--p95" },
    { key: "p99", label: "p99", value: p.p99, cls: "mark--p99" },
    { key: "p999", label: "p99.9", value: p.p999, cls: "mark--p999" },
  ];
}

/** Position (0..100%) of a latency value along the equal-decade axis. */
function axisPosition(ns: number): number {
  const segments = LATENCY_EDGES_NS.length + 1;
  const idx = bucketIndexFor(ns);
  const lo = idx === 0 ? 0 : (LATENCY_EDGES_NS[idx - 1] ?? 1);
  const hi = LATENCY_EDGES_NS[idx] ?? lo * 10;
  const frac = hi > lo ? Math.min(1, Math.max(0, Math.log10(ns / lo) / Math.log10(hi / lo))) : 0;
  return ((idx + frac) / segments) * 100;
}

export interface LatencyHistogramProps {
  buckets: ReadonlyArray<HistogramBucket>;
  percentiles: LatencyPercentiles;
  sampleCount: number;
}

export function LatencyHistogram({ buckets, percentiles, sampleCount }: LatencyHistogramProps) {
  const maxCount = buckets.reduce((m, b) => Math.max(m, b.count), 0);
  const markers = markersOf(percentiles).filter((m) => m.value !== null);

  if (sampleCount === 0) {
    return <p className="well-hint">No exit samples in this window — nothing to histogram.</p>;
  }

  return (
    <figure className="hist" aria-label={`Latency histogram, ${sampleCount} samples`}>
      <div className="hist-rows">
        {buckets.map((b) => {
          const width = maxCount > 0 ? (b.count / maxCount) * 100 : 0;
          const hot = b.count > 0 && b.index >= bucketIndexFor(percentiles.p99 ?? 0);
          return (
            <div key={b.label} className="hist-row">
              <span className="hist-label">{b.label}</span>
              <span className="hist-track">
                <span
                  className={cx("hist-bar", hot && "hist-bar--hot")}
                  style={{ width: `${width}%` }}
                  aria-hidden="true"
                />
              </span>
              <span className="hist-count num">{b.count.toLocaleString("en-US")}</span>
              <span className="hist-sum num">{b.count > 0 ? formatNs(b.sumNs) : "—"}</span>
            </div>
          );
        })}
      </div>

      <div className="hist-axis" aria-hidden="true">
        <div className="hist-axis-line">
          {markers.map((m) => (
            <span
              key={m.key}
              className={cx("hist-mark", m.cls)}
              style={{ left: `${m.value === null ? 0 : axisPosition(m.value)}%` }}
            />
          ))}
        </div>
        <div className="hist-ticks">
          <span>&lt;1µs</span>
          {LATENCY_EDGES_NS.map((edge) => (
            <span key={edge}>{formatNs(edge)}</span>
          ))}
        </div>
      </div>

      <figcaption className="hist-legend">
        {markers.map((m) => (
          <span key={m.key} className={cx("chip", "hist-chip", m.cls)}>
            <span className="hist-chip-dot" aria-hidden="true" />
            {m.label}
            <strong>{m.value === null ? "—" : formatNs(m.value)}</strong>
          </span>
        ))}
        <span className="hist-note">wall time (CLOCK_MONOTONIC) — not CPU time</span>
      </figcaption>
    </figure>
  );
}
