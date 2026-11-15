const numberFormat = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 });
const compactFormat = new Intl.NumberFormat(undefined, {
  notation: "compact",
  maximumFractionDigits: 1,
});
const relativeFormat = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

export function formatNumber(value: number | string | null | undefined): string {
  const parsed = typeof value === "string" ? Number(value) : value;
  return typeof parsed === "number" && Number.isFinite(parsed)
    ? numberFormat.format(parsed)
    : "0";
}

export function formatCompact(value: number | string | null | undefined): string {
  const parsed = typeof value === "string" ? Number(value) : value;
  if (typeof parsed !== "number" || !Number.isFinite(parsed)) {
    return "0";
  }
  return parsed < 1000 ? numberFormat.format(parsed) : compactFormat.format(parsed);
}

export function countOf(value: string | number | undefined): number {
  if (typeof value === "number") return Number.isFinite(value) ? value : 0;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

export function relativeTime(epochSeconds: number | null | undefined): string {
  if (!epochSeconds) return "never";
  return relativeToMs(epochSeconds * 1000);
}

export function relativeToIso(iso: string | null | undefined): string {
  if (!iso) return "never";
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? relativeToMs(ms) : iso;
}

export function relativeToMs(ms: number): string {
  const diffSeconds = Math.round((ms - Date.now()) / 1000);
  const absolute = Math.abs(diffSeconds);
  if (absolute < 60) return relativeFormat.format(diffSeconds, "second");
  if (absolute < 3600) return relativeFormat.format(Math.round(diffSeconds / 60), "minute");
  if (absolute < 86_400) return relativeFormat.format(Math.round(diffSeconds / 3600), "hour");
  return relativeFormat.format(Math.round(diffSeconds / 86_400), "day");
}

export function formatTimestamp(epochSeconds: number | null | undefined): string {
  if (!epochSeconds) return "never";
  return new Date(epochSeconds * 1000).toLocaleString();
}

export function formatIsoTimestamp(iso: string | null | undefined): string {
  if (!iso) return "never";
  const date = new Date(iso);
  return Number.isFinite(date.getTime()) ? date.toLocaleString() : iso;
}

export function formatClock(iso: string): string {
  const date = new Date(iso);
  return Number.isFinite(date.getTime())
    ? date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : iso;
}

export function formatDuration(totalSeconds: number): string {
  const seconds = Math.max(0, Math.round(totalSeconds));
  if (seconds >= 86400) return `${Math.floor(seconds / 86400)}d ${Math.floor((seconds % 86400) / 3600)}h`;
  if (seconds >= 3600) return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  if (seconds >= 60) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${seconds}s`;
}

export function shortId(value: string, length = 12): string {
  return value.length > length ? value.slice(0, length) : value;
}

export function titleCase(value: string): string {
  return value
    .replace(/[-_]/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}







export function parseDate(value: string | null | undefined): number {
  if (!value) return 0;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

export function download(name: string, content: string, type = "application/json"): void {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function eventSearchText(event: {
  event_id: string;
  kind: string;
  path?: string;
  process_exec?: string;
  pid: number;
  sensor: string;
}): string {
  return [event.kind, event.path, event.process_exec, event.pid, event.event_id, event.sensor]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

export function isOnline(lastSeenEpoch: number, windowSeconds = 120): boolean {
  return Date.now() / 1000 - lastSeenEpoch <= windowSeconds;
}
