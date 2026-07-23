// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Minimal JSON → YAML rendering for the read-only rule preview.
// Deliberately dependency-free (no new production deps allowed); rule
// bodies are plain JSON values, so a small recursive emitter covers
// them. Output is display-only — never parsed back.

function scalar(value: string | number | boolean | null): string {
  if (value === null) return "null";
  if (typeof value !== "string") return String(value);
  if (value === "") return '""';
  if (
    /[:#\-?&*!|>'"%@`{}[\],\n]/.test(value) ||
    /^\s|\s$/.test(value) ||
    /^[\d.~]|^(true|false|null)$/i.test(value)
  ) {
    return JSON.stringify(value);
  }
  return value;
}

function appendInline(lines: string[], token: string): void {
  const last = lines[lines.length - 1];
  if (last === undefined) lines.push(token);
  else lines[lines.length - 1] = `${last} ${token}`;
}

function emit(value: unknown, indent: number, lines: string[]): void {
  const pad = "  ".repeat(indent);
  if (Array.isArray(value)) {
    if (value.length === 0) {
      appendInline(lines, "[]");
      return;
    }
    for (const item of value) {
      if (item !== null && typeof item === "object") {
        lines.push(`${pad}-`);
        emit(item, indent + 1, lines);
      } else {
        lines.push(`${pad}- ${scalar(item as string | number | boolean | null)}`);
      }
    }
    return;
  }
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) {
      appendInline(lines, "{}");
      return;
    }
    for (const [key, child] of entries) {
      const keyText = /^[A-Za-z0-9_.-]+$/.test(key) ? key : JSON.stringify(key);
      if (child !== null && typeof child === "object") {
        lines.push(`${pad}${keyText}:`);
        emit(child, indent + 1, lines);
      } else {
        lines.push(`${pad}${keyText}: ${scalar(child as string | number | boolean | null)}`);
      }
    }
    return;
  }
  lines.push(`${pad}${scalar(value as string | number | boolean | null)}`);
}

export function toYaml(value: unknown): string {
  const lines: string[] = [];
  emit(value, 0, lines);
  return lines.length === 0 ? "null" : lines.join("\n");
}
