// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Expanded alert row: the rule engine's match explanation rendered as
// a predicate tree (crates/rules emits Explanation{field, operator,
// value, matched, children} — the wire field is a string, so parse
// defensively and fall back to plain text), evidence links to the
// triggering event, process context pulled from the matched fields,
// and the action taken with deny-source attribution.
import { useState } from "react";
import { Link } from "react-router-dom";
import type { Alert } from "../api/types";
import { cx, shortId } from "../lib/format";
import { SeverityBadge } from "./SeverityBadge";

interface ExplainNode {
  field: string;
  operator: string;
  value: string;
  matched: boolean;
  children: ExplainNode[];
}

function stringifyValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 1) {
      const only = entries[0];
      return only === undefined ? JSON.stringify(value) : stringifyValue(only[1]);
    }
    return JSON.stringify(value);
  }
  return String(value);
}

function parseNode(raw: unknown): ExplainNode | null {
  if (typeof raw !== "object" || raw === null) return null;
  const rec = raw as Record<string, unknown> & {
    field?: unknown;
    matched?: unknown;
    children?: unknown;
    operator?: unknown;
    value?: unknown;
  };
  if (typeof rec.field !== "string" || typeof rec.matched !== "boolean") return null;
  const children: ExplainNode[] = [];
  if (Array.isArray(rec.children)) {
    for (const child of rec.children) {
      const parsed = parseNode(child);
      if (parsed !== null) children.push(parsed);
    }
  }
  return {
    field: rec.field,
    operator: typeof rec.operator === "string" ? rec.operator : "",
    value: stringifyValue(rec.value),
    matched: rec.matched,
    children,
  };
}

export function parseExplanation(explanation: string): ExplainNode | null {
  try {
    return parseNode(JSON.parse(explanation));
  } catch {
    return null;
  }
}

const PROCESS_FIELD = /^(task|pid|comm|binary|path|argv|uid|gid|cgroup|mount_ns|parent)/i;

function collectProcessContext(node: ExplainNode, out: Array<[string, string]>): void {
  if (node.children.length === 0 && PROCESS_FIELD.test(node.field)) {
    out.push([node.field, node.value]);
  }
  for (const child of node.children) collectProcessContext(child, out);
}

function collectDenySource(node: ExplainNode, out: Array<[string, string]>): void {
  if (node.children.length === 0 && /^(hook|policy_version|own_deny|subject)$/i.test(node.field)) {
    out.push([node.field, node.value]);
  }
  for (const child of node.children) collectDenySource(child, out);
}

function Tree({ node }: { node: ExplainNode }) {
  const composite = node.children.length > 0;
  const mark = composite ? node.field.toUpperCase() : node.matched ? "HIT" : "MISS";
  return (
    <li>
      <span
        className={cx(
          "pred-mark",
          composite ? "pred-mark--hit" : node.matched ? "pred-mark--hit" : "pred-mark--miss",
        )}
      >
        {mark}
      </span>
      {composite ? (
        <span className="strong">{node.field}</span>
      ) : (
        <span>
          {node.field} <span className="kind-cell">{node.operator}</span> {node.value}
        </span>
      )}
      {composite && (
        <ul>
          {node.children.map((child, i) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: explanation tree is rebuilt per alert, children carry no stable id and never reorder
            <Tree key={`${child.field}-${i}`} node={child} />
          ))}
        </ul>
      )}
    </li>
  );
}

export function AlertDetail({ alert }: { alert: Alert }) {
  const [copied, setCopied] = useState(false);
  const tree = parseExplanation(alert.explanation);
  const process: Array<[string, string]> = [];
  const denyFields: Array<[string, string]> = [];
  if (tree !== null) {
    collectProcessContext(tree, process);
    collectDenySource(tree, denyFields);
  }
  const denied = /\bdeny|denied|EPERM|lsm[_-]deny|own[_-]deny\b/i.test(alert.explanation);

  const copyEventId = (): void => {
    navigator.clipboard
      .writeText(alert.event_id)
      .then(() => {
        setCopied(true);
        globalThis.setTimeout(() => setCopied(false), 1500);
      })
      .catch(() => setCopied(false));
  };

  return (
    <div className="detail-well">
      <div className="detail-block">
        <span className="stat-label">Match explanation</span>
        {tree !== null ? (
          <ul className="explain-tree">
            <Tree node={tree} />
          </ul>
        ) : (
          <p className="explain-fallback">{alert.explanation}</p>
        )}
      </div>

      <div className="detail-block">
        <span className="stat-label">Evidence</span>
        <span className="evidence-link">
          <span title={alert.event_id}>{shortId(alert.event_id, 26)}</span>
          <button type="button" className="btn btn--ghost btn--sm" onClick={copyEventId}>
            {copied ? "Copied" : "Copy ID"}
          </button>
          <Link to="/events">Open event stream →</Link>
        </span>
        <span className="stat-label" style={{ marginTop: "var(--space-2)" }}>
          Rule version
        </span>
        <span className="evidence-link">
          <span title={alert.rule_id}>{shortId(alert.rule_id, 26)}</span>
          <span className="conn-detail" title={alert.rule_digest}>
            digest {shortId(alert.rule_digest, 12)}
          </span>
        </span>
      </div>

      <div className="detail-block">
        <span className="stat-label">Process context</span>
        {process.length === 0 ? (
          <p className="conn-detail">no process fields in the explanation</p>
        ) : (
          <dl className="kv">
            {process.slice(0, 6).map(([field, value]) => (
              <div key={field} style={{ display: "contents" }}>
                <dt>{field}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>
        )}
      </div>

      <div className="detail-block">
        <span className="stat-label">Action taken</span>
        <SeverityBadge severity={denied ? "CRITICAL" : "INFO"} label={denied ? "DENY" : "ALERT"} />
        {denied && (
          <dl className="kv" style={{ marginTop: "var(--space-2)" }}>
            <dt>deny source</dt>
            <dd>
              {denyFields.length === 0
                ? "LSM hook (see explanation)"
                : denyFields.map(([f, v]) => `${f}=${v}`).join(" · ")}
            </dd>
          </dl>
        )}
      </div>
    </div>
  );
}
