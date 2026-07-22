// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Dry-run a rule against a recorded event (POST /rules/test). The
// operator picks a recent event from the historical API (or pastes
// event JSON), the evaluator answers matched/score/field_matches.
// Analyst+ surface — the view gates it, the server re-checks.
import { useState } from "react";
import { api } from "../api/client";
import type { Event, EventBatch } from "../api/event-types";
import { useQuery } from "../api/query";
import type { Rule, RuleTestResult } from "../api/types";
import { cx, formatInt, shortId, shortKind } from "../lib/format";
import { Alert } from "../ui/Alert";
import { Button } from "../ui/Button";
import { SeverityBadge } from "./SeverityBadge";

function fieldMatchValue(value: unknown): { text: string; matched: boolean | null } {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const rec = value as Record<string, unknown> & { matched?: unknown };
    if (typeof rec.matched === "boolean") {
      const rest = { ...rec };
      delete rest.matched;
      return { text: JSON.stringify(rest), matched: rec.matched };
    }
  }
  return { text: JSON.stringify(value), matched: null };
}

export function RuleTester({ rule }: { rule: Rule }) {
  const events = useQuery<EventBatch>("events:recent", () => api.listEvents({ limit: 25 }));
  const [pickedId, setPickedId] = useState<string>("");
  const [pasted, setPasted] = useState<string>("");
  const [result, setResult] = useState<RuleTestResult | null>(null);
  const [testing, setTesting] = useState(false);
  const [testError, setTestError] = useState<string | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);

  const picked = events.data?.events.find((e) => e.event_id === pickedId);

  const run = async (event: Event): Promise<void> => {
    setTesting(true);
    setTestError(null);
    setResult(null);
    try {
      setResult(await api.testRule(rule, event));
    } catch (cause) {
      setTestError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setTesting(false);
    }
  };

  const runPasted = (): void => {
    setParseError(null);
    try {
      const event = JSON.parse(pasted) as Event;
      if (typeof event.event_id !== "string" || typeof event.event_kind !== "string") {
        throw new Error("not an Event object (needs event_id + event_kind)");
      }
      void run(event);
    } catch (cause) {
      setParseError(cause instanceof Error ? cause.message : String(cause));
    }
  };

  return (
    <div>
      <div className="action-row">
        <label className="stat-label" htmlFor="tester-event">
          Test event
        </label>
        <select
          id="tester-event"
          className="control"
          value={pickedId}
          onChange={(ev) => setPickedId(ev.target.value)}
          disabled={events.data === null}
        >
          <option value="">
            {events.data === null ? "loading recent events…" : "pick a recent event"}
          </option>
          {(events.data?.events ?? []).map((e) => (
            <option key={e.event_id} value={e.event_id}>
              {shortKind(e.event_kind)} · seq {formatInt(e.seq)} · {shortId(e.event_id, 14)} ·{" "}
              {e.process_exec_result?.binary_path ??
                e.file_open?.path ??
                e.file_create?.path ??
                "—"}
            </option>
          ))}
        </select>
        <Button
          variant="primary"
          size="sm"
          loading={testing}
          disabled={picked === undefined}
          onClick={() => picked !== undefined && void run(picked)}
        >
          {testing ? "Evaluating…" : "Run against rule"}
        </Button>
      </div>

      <details className="stack-top">
        <summary className="conn-detail">…or paste event JSON</summary>
        <label className="visually-hidden" htmlFor="tester-paste">
          Event JSON
        </label>
        <textarea
          id="tester-paste"
          className="control yaml-block"
          rows={5}
          style={{ width: "100%", resize: "vertical" }}
          value={pasted}
          onChange={(ev) => setPasted(ev.target.value)}
          placeholder='{"event_id": "…", "event_kind": "EVENT_KIND_FILE_OPEN", …}'
        />
        {parseError !== null && <p className="digest-bad">{parseError}</p>}
        <Button size="sm" disabled={pasted.trim() === "" || testing} onClick={runPasted}>
          Evaluate pasted event
        </Button>
      </details>

      {testError !== null && (
        <div className="stack-top">
          <Alert tone="critical" title="Rule evaluation failed">
            {testError}
          </Alert>
        </div>
      )}

      {result !== null && (
        <div className="stack-top">
          <div className="action-row">
            <SeverityBadge
              severity={result.matched ? "CRITICAL" : "INFO"}
              label={result.matched ? "MATCHED" : "NO MATCH"}
            />
            <span className="score-meter">
              <span className="stat-label">score</span>
              <span className="strong">{result.score.toFixed(2)}</span>
              <span
                className="sat-track"
                style={{ width: 90, height: 6 }}
                role="img"
                aria-label={`Match score ${result.score.toFixed(2)} of 1`}
              >
                <span
                  className="sat-fill"
                  style={{ width: `${Math.max(0, Math.min(100, result.score * 100))}%` }}
                />
              </span>
            </span>
          </div>
          {result.field_matches !== undefined && Object.keys(result.field_matches).length > 0 && (
            <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-1)" }}>
              {Object.entries(result.field_matches).map(([field, value]) => {
                const rendered = fieldMatchValue(value);
                return (
                  <div
                    key={field}
                    className={cx("field-match", rendered.matched === false && "field-match--miss")}
                  >
                    <span
                      className={cx(
                        "pred-mark",
                        rendered.matched === false
                          ? "pred-mark--miss"
                          : rendered.matched === true
                            ? "pred-mark--hit"
                            : "",
                      )}
                    >
                      {rendered.matched === null ? "field" : rendered.matched ? "HIT" : "MISS"}
                    </span>
                    <span>
                      <span className="strong">{field}</span> {rendered.text}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
