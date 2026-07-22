// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Rule browse (viewer+) plus validate/test surface (analyst+ — the
// Write action in rbac.rs). The gate is UI-only; the server re-checks.
import { useState } from "react";
import { api } from "../api/client";
import { useQuery } from "../api/query";
import type { Rule, RulePage, RuleValidationResult } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { permits } from "../auth/roles";
import { shortId } from "../lib/format";
import { Alert } from "../ui/Alert";
import { SeverityBadge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Panel } from "../ui/Card";
import { DegradedBanner, ErrorPanel, TableSkeleton } from "../ui/QueryStates";
import { Spinner } from "../ui/Spinner";
import { type Column, DataTable } from "../ui/Table";

const COLUMNS: ReadonlyArray<Column<Rule>> = [
  { key: "name", header: "Name", render: (r) => <span className="strong">{r.name}</span> },
  { key: "sev", header: "Severity", render: (r) => <SeverityBadge severity={r.severity} /> },
  { key: "status", header: "Status", render: (r) => <span className="kind-cell">{r.status}</span> },
  { key: "tags", header: "Tags", render: (r) => (r.tags ?? []).join(", ") || "—" },
  { key: "id", header: "ID", render: (r) => <span title={r.id}>{shortId(r.id, 22)}</span> },
];

export function RulesView() {
  const { session } = useAuth();
  const canQuery = session !== null && permits(session.role, "write");
  const query = useQuery<RulePage>("rules", () => api.listRules({ limit: 100 }));
  const [selected, setSelected] = useState<Rule | null>(null);
  const [validation, setValidation] = useState<RuleValidationResult | null>(null);
  const [validating, setValidating] = useState(false);
  const [validateError, setValidateError] = useState<string | null>(null);

  const runValidate = async (rule: Rule): Promise<void> => {
    setValidating(true);
    setValidateError(null);
    setValidation(null);
    try {
      setValidation(await api.validateRule(rule));
    } catch (cause) {
      setValidateError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setValidating(false);
    }
  };

  const rows = query.data?.rules ?? [];

  return (
    <section aria-label="Detection rules">
      <div className="view-head">
        <h1 className="view-title">Rules</h1>
        <p className="view-sub">
          {canQuery ? "browse + validate (analyst)" : "browse only (viewer)"}
        </p>
      </div>

      {query.status === "degraded" && (
        <DegradedBanner error={query.error} staleRows={rows.length} />
      )}

      <Panel
        title="Rule catalog"
        flush
        meta={query.data !== null ? `${rows.length} rules` : undefined}
      >
        {query.status === "error" ? (
          <div className="tbl-empty">
            <ErrorPanel error={query.error} onRetry={query.refetch} scope="rule catalog" />
          </div>
        ) : query.data === null ? (
          <TableSkeleton rows={6} cols={5} />
        ) : (
          <DataTable
            columns={COLUMNS}
            rows={rows}
            rowKey={(r) => r.id}
            ariaLabel="Detection rules"
            onRowActivate={
              canQuery
                ? (rule) => {
                    setSelected(rule);
                    setValidation(null);
                    setValidateError(null);
                  }
                : undefined
            }
            empty={
              <div className="tbl-empty">
                <p className="well-hint">No rules defined yet.</p>
              </div>
            }
          />
        )}
      </Panel>

      {canQuery && selected !== null && (
        <Panel
          title="Validate rule"
          className="stack-top"
          meta={<span className="strong">{selected.name}</span>}
        >
          <div className="action-row">
            <Button
              variant="primary"
              size="sm"
              loading={validating}
              onClick={() => void runValidate(selected)}
            >
              {validating ? "Validating…" : "Validate against engine"}
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setSelected(null)}>
              Close
            </Button>
          </div>
          {validateError !== null && (
            <div className="stack-top">
              <Alert tone="critical" title="Validation request failed">
                {validateError}
              </Alert>
            </div>
          )}
          {validation !== null && (
            <div className="stack-top">
              <Alert
                tone={validation.valid ? "info" : "critical"}
                title={validation.valid ? "Rule is valid" : "Rule rejected"}
              >
                {validation.errors.length > 0 && validation.errors.join(" · ")}
                {validation.warnings !== undefined && validation.warnings.length > 0 && (
                  <> warnings: {validation.warnings.join(" · ")}</>
                )}
              </Alert>
            </div>
          )}
          {validating && <Spinner label="Validating rule" />}
        </Panel>
      )}

      {!canQuery && (
        <p className="well-hint stack-top">
          Selecting a rule for validation requires the analyst role. Your role can browse the
          catalog only.
        </p>
      )}
    </section>
  );
}
