// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Rule catalog grouped by detection pack, with validation, read-only
// YAML preview, trigger stats, enable/disable, and a dry-run tester.
// Browse = viewer+; validate/test/toggle = analyst+ (Write action in
// rbac.rs — UI gate only, the server re-checks). The openapi v1
// surface exposes no rule-write endpoint, so enable/disable is a
// confirmed, session-local override — the dialog says exactly that.
import { useMemo, useState } from "react";
import { api } from "../api/client";
import { useQuery } from "../api/query";
import type { Rule, RulePage, RuleValidationResult } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { permits } from "../auth/roles";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { RuleDetail } from "../components/RuleDetail";
import { SeverityBadge } from "../components/SeverityBadge";
import { cx, formatInt, formatWall, shortId } from "../lib/format";
import { lastTriggered, packOf, triggerCount } from "../lib/rulePacks";
import { Button } from "../ui/Button";
import { Panel } from "../ui/Card";
import { DegradedBanner, ErrorPanel, TableSkeleton } from "../ui/QueryStates";
import { type Column, DataTable } from "../ui/Table";

export function RulesView() {
  const { session } = useAuth();
  const actor = session?.email ?? session?.subject ?? "unknown-operator";
  const canWrite = session !== null && permits(session.role, "write");
  const query = useQuery<RulePage>("rules", () => api.listRules({ limit: 100 }));
  const [enabledOverride, setEnabledOverride] = useState<Record<string, boolean>>({});
  const [confirmToggle, setConfirmToggle] = useState<Rule | null>(null);
  const [validations, setValidations] = useState<Record<string, RuleValidationResult | "checking">>(
    {},
  );
  const [selected, setSelected] = useState<Rule | null>(null);

  const isEnabled = (rule: Rule): boolean => enabledOverride[rule.id] ?? rule.status === "ACTIVE";

  const runValidate = async (rule: Rule): Promise<void> => {
    setValidations((prev) => ({ ...prev, [rule.id]: "checking" }));
    try {
      const result = await api.validateRule(rule);
      setValidations((prev) => ({ ...prev, [rule.id]: result }));
    } catch (cause) {
      setValidations((prev) => ({
        ...prev,
        [rule.id]: {
          valid: false,
          errors: [cause instanceof Error ? cause.message : String(cause)],
        },
      }));
    }
  };

  const packs = useMemo(() => {
    const grouped = new Map<string, Rule[]>();
    for (const rule of query.data?.rules ?? []) {
      const pack = packOf(rule);
      grouped.set(pack, [...(grouped.get(pack) ?? []), rule]);
    }
    return Array.from(grouped.entries()).sort(([a], [b]) => a.localeCompare(b));
  }, [query.data]);

  const columns: ReadonlyArray<Column<Rule>> = [
    { key: "name", header: "Name", render: (r) => <span className="strong">{r.name}</span> },
    { key: "sev", header: "Severity", render: (r) => <SeverityBadge severity={r.severity} /> },
    {
      key: "enabled",
      header: canWrite ? "Enabled" : "Status",
      render: (r) =>
        canWrite ? (
          <span className="switch-cell">
            <button
              type="button"
              role="switch"
              className="switch"
              aria-checked={isEnabled(r)}
              aria-label={`${isEnabled(r) ? "Disable" : "Enable"} rule ${r.name}`}
              onClick={() => setConfirmToggle(r)}
            />
            <span className={cx("switch-state", isEnabled(r) && "switch-state--on")}>
              {isEnabled(r) ? "active" : "draft"}
            </span>
          </span>
        ) : (
          <span className="kind-cell">{r.status}</span>
        ),
    },
    {
      key: "triggers",
      header: "Triggers",
      align: "right",
      render: (r) => {
        const count = triggerCount(r);
        const last = lastTriggered(r);
        return (
          <span
            title={last === null ? "no trigger telemetry reported" : `last ${formatWall(last)} UTC`}
          >
            {count === null ? "—" : formatInt(count)}
            {last !== null && <span className="conn-detail"> · {formatWall(last)}</span>}
          </span>
        );
      },
    },
    {
      key: "validation",
      header: "Validation",
      render: (r) => {
        const v = validations[r.id];
        if (v === "checking") return <span className="conn-detail">checking…</span>;
        if (v === undefined)
          return canWrite ? (
            <Button size="sm" variant="ghost" onClick={() => void runValidate(r)}>
              Validate
            </Button>
          ) : (
            <span className="conn-detail">—</span>
          );
        return v.valid ? (
          <span className="digest-ok">
            valid
            {v.warnings !== undefined && v.warnings.length > 0
              ? ` · ${v.warnings.length} warn`
              : ""}
          </span>
        ) : (
          <span className="digest-bad" title={v.errors.join("; ")}>
            invalid · {v.errors.length}
          </span>
        );
      },
    },
    { key: "tags", header: "Tags", render: (r) => (r.tags ?? []).join(", ") || "—" },
    {
      key: "id",
      header: "ID",
      render: (r) => <span title={r.id}>{shortId(r.id, 18)}</span>,
    },
  ];

  const rows = query.data?.rules ?? [];
  const toggleTarget = confirmToggle;
  const toggleEnabled = toggleTarget === null ? false : isEnabled(toggleTarget);

  return (
    <section aria-label="Detection rules">
      <div className="view-head">
        <h1 className="view-title">Rules</h1>
        <p className="view-sub">
          {canWrite ? "browse · validate · test · toggle (analyst)" : "browse only (viewer)"}
        </p>
      </div>

      {query.status === "degraded" && (
        <DegradedBanner error={query.error} staleRows={rows.length} />
      )}

      <Panel
        title="Rule catalog"
        flush
        meta={query.data !== null ? `${rows.length} rules · ${packs.length} packs` : undefined}
      >
        {query.status === "error" ? (
          <div className="tbl-empty">
            <ErrorPanel error={query.error} onRetry={query.refetch} scope="rule catalog" />
          </div>
        ) : query.data === null ? (
          <TableSkeleton rows={6} cols={6} />
        ) : rows.length === 0 ? (
          <div className="tbl-empty">
            <p className="well-hint">No rules defined yet.</p>
          </div>
        ) : (
          packs.map(([pack, packRules]) => (
            <div key={pack}>
              <div className="pack-head">
                <span className="pack-name">{pack}</span>
                <span className="pack-count">
                  {packRules.length} rules · {packRules.filter((r) => isEnabled(r)).length} active
                </span>
              </div>
              <DataTable
                columns={columns}
                rows={packRules}
                rowKey={(r) => r.id}
                ariaLabel={`Rules in pack ${pack}`}
                onRowActivate={(rule) => setSelected(rule)}
              />
            </div>
          ))
        )}
      </Panel>

      {selected !== null && (
        <RuleDetail
          rule={selected}
          validation={validations[selected.id]}
          canWrite={canWrite}
          onClose={() => setSelected(null)}
        />
      )}

      {!canWrite && (
        <p className="well-hint stack-top">
          Validation, testing, and enable/disable require the analyst role. Your role can browse the
          catalog only.
        </p>
      )}

      <ConfirmDialog
        open={toggleTarget !== null}
        title={`${toggleEnabled ? "Disable" : "Enable"} ${toggleTarget?.name ?? ""}`}
        tone={toggleEnabled ? "danger" : "info"}
        intent={[
          { label: "Actor", value: actor },
          {
            label: "Action",
            value: toggleEnabled ? "rule.disable → DRAFT" : "rule.enable → ACTIVE",
          },
          { label: "Resource", value: `rule:${toggleTarget?.id ?? ""}` },
          { label: "Recorded", value: new Date().toISOString() },
        ]}
        confirmLabel={toggleEnabled ? "Disable rule" : "Enable rule"}
        onConfirm={() => {
          if (toggleTarget !== null) {
            setEnabledOverride((prev) => ({ ...prev, [toggleTarget.id]: !toggleEnabled }));
          }
          setConfirmToggle(null);
        }}
        onCancel={() => setConfirmToggle(null)}
      >
        <p>
          The openapi v1 surface has no rule-write endpoint yet, so this toggle is a session-local
          override in this console — the rule catalog on the server is unchanged until a rule-write
          API lands.
        </p>
      </ConfirmDialog>
    </section>
  );
}
