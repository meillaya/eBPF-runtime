// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Shared telemetry toolbar: live/historical toggle, time-range selector,
// cluster scope. The range select is historical-only (the live window is
// the bounded stream buffer); the cluster select is live-only (historical
// recall is scoped by the connected control plane, not by this client).
import type { FeedMode } from "../hooks/useEvents";
import { cx } from "../lib/format";

export interface TimeRange {
  label: string;
  sec: number; // 0 = full recall (no since bound)
}

export const TIME_RANGES: readonly TimeRange[] = [
  { label: "5m", sec: 300 },
  { label: "15m", sec: 900 },
  { label: "1h", sec: 3600 },
  { label: "6h", sec: 21600 },
  { label: "24h", sec: 86400 },
  { label: "full", sec: 0 },
];

export interface EventToolbarProps {
  idPrefix: string;
  mode: FeedMode;
  onModeChange: (mode: FeedMode) => void;
  rangeSec: number;
  onRangeChange: (sec: number) => void;
  cluster: string;
  onClusterChange: (cluster: string) => void;
  clusters: ReadonlyArray<string>;
}

export function EventToolbar({
  idPrefix,
  mode,
  onModeChange,
  rangeSec,
  onRangeChange,
  cluster,
  onClusterChange,
  clusters,
}: EventToolbarProps) {
  return (
    <fieldset className="toolbar" aria-label="Feed controls">
      <fieldset className="toolbar-seg" aria-label="Feed mode">
        <button
          type="button"
          className={cx("seg-btn", mode === "live" && "seg-btn--on")}
          aria-pressed={mode === "live"}
          onClick={() => onModeChange("live")}
        >
          Live
        </button>
        <button
          type="button"
          className={cx("seg-btn", mode === "historical" && "seg-btn--on")}
          aria-pressed={mode === "historical"}
          onClick={() => onModeChange("historical")}
        >
          Historical
        </button>
      </fieldset>

      <label className="toolbar-field" htmlFor={`${idPrefix}-range`}>
        Window
        <select
          id={`${idPrefix}-range`}
          className="control"
          value={rangeSec}
          disabled={mode === "live"}
          title={mode === "live" ? "Live window = bounded stream buffer" : undefined}
          onChange={(ev) => onRangeChange(Number.parseInt(ev.target.value, 10))}
        >
          {TIME_RANGES.map((r) => (
            <option key={r.label} value={r.sec}>
              {r.label}
            </option>
          ))}
        </select>
      </label>

      <label className="toolbar-field" htmlFor={`${idPrefix}-cluster`}>
        Cluster
        <select
          id={`${idPrefix}-cluster`}
          className="control"
          value={cluster}
          disabled={mode === "historical"}
          title={
            mode === "historical"
              ? "Historical recall is scoped by the connected control plane"
              : undefined
          }
          onChange={(ev) => onClusterChange(ev.target.value)}
        >
          <option value="all">all clusters</option>
          {clusters.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
      </label>
    </fieldset>
  );
}
