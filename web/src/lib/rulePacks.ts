// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Detection-pack grouping for the rule catalog. The pack convention
// lives in rule-id prefixes (tests/fixtures/{sensitive-files,reverse-
// shell,container-escape}/), not in enforced tags — so derive the pack
// from the id first, fall back to tags, then "unpackaged". Trigger
// stats are read defensively: openapi rule bodies are free-form and
// the engine does not publish counters yet.
import type { Rule } from "../api/types";

const PACKS = ["sensitive-files", "reverse-shell", "container-escape"] as const;
const PACK_PREFIX: Record<(typeof PACKS)[number], string> = {
  "sensitive-files": "sensitive-file",
  "reverse-shell": "reverse-shell",
  "container-escape": "container-escape",
};

export function packOf(rule: Rule): string {
  const id = rule.id.toLowerCase();
  for (const pack of PACKS) {
    if (id.startsWith(PACK_PREFIX[pack])) return pack;
  }
  for (const tag of rule.tags ?? []) {
    if ((PACKS as readonly string[]).includes(tag)) return tag;
  }
  return "unpackaged";
}

export function triggerCount(rule: Rule): number | null {
  const { trigger_count: v } = rule.body;
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v !== "" && Number.isFinite(Number(v))) return Number(v);
  return null;
}

export function lastTriggered(rule: Rule): string | null {
  const { last_triggered_at: v } = rule.body;
  return typeof v === "string" && v !== "" ? v : null;
}
