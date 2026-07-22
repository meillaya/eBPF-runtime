// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Formatting + tiny shared helpers. Pure functions only; every view
// renders telemetry through these so units stay consistent.

/** Join class names, skipping falsy entries. */
export function cx(...parts: ReadonlyArray<string | false | undefined>): string {
  return parts.filter((p): p is string => Boolean(p)).join(" ");
}

const INT = new Intl.NumberFormat("en-US");

export function formatInt(n: number): string {
  return INT.format(n);
}

/** Epoch seconds → "2026-07-22 14:03:07Z" (UTC, mono-friendly). */
export function formatEpochSec(epochSec: number): string {
  const d = new Date(epochSec * 1000);
  return Number.isNaN(d.getTime()) ? "—" : d.toISOString().replace("T", " ").slice(0, 19);
}

/** RFC3339 wall string → "14:03:07.123" (UTC). */
export function formatWall(wall: string | undefined): string {
  if (wall === undefined) return "—";
  const d = new Date(wall);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toISOString().slice(11, 23);
}

/** Monotonic ns → compact "1 234 567 890" (tabular in CSS). */
export function formatMonoNs(ns: number | bigint): string {
  return typeof ns === "bigint" ? ns.toLocaleString("en-US") : formatInt(ns);
}

/** Last-seen epoch → "12s ago" style relative label. */
export function formatAgo(epochSec: number, nowEpochSec: number): string {
  const delta = Math.max(0, nowEpochSec - epochSec);
  if (delta < 60) return `${delta}s ago`;
  if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
  if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
  return `${Math.floor(delta / 86400)}d ago`;
}

/** Truncate long identifiers for dense cells. */
export function shortId(id: string, max = 18): string {
  return id.length <= max ? id : `${id.slice(0, max - 1)}…`;
}

/** EVENT_KIND_* → short human label ("EXEC", "FILE_OPEN", "LSM_DENY"). */
export function shortKind(kind: string): string {
  return kind.replace(/^EVENT_KIND_/, "");
}

/**
 * Safely parse a live-stream payload (JSON-as-string) and extract a
 * curated one-line summary. Raw payloads are NEVER dumped into the DOM
 * (task constraint); only known keys surface, HTML-escaped by React.
 */
export function summarizePayload(payload: string | undefined): string {
  if (payload === undefined || payload === "") return "—";
  let value: unknown;
  try {
    value = JSON.parse(payload);
  } catch {
    return "(unparseable payload)";
  }
  if (typeof value !== "object" || value === null) return "—";
  const rec = value as Record<string, unknown>;
  const firstString = (...keys: string[]): string | undefined => {
    for (const k of keys) {
      const v = rec[k];
      if (typeof v === "string" && v.length > 0) return v;
    }
    return undefined;
  };
  const summary = firstString(
    "binary_path",
    "path",
    "source_path",
    "subject",
    "hook",
    "remote_addr",
    "local_addr",
    "name",
  );
  if (summary !== undefined) return summary;
  const keys = Object.keys(rec);
  return keys.length === 0 ? "—" : `{${keys.slice(0, 3).join(", ")}}`;
}
