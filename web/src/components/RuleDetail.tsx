// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Selected-rule drawer: severity/status strip, read-only YAML preview
// (the body is NEVER editable — openapi v1 has no rule-write
// endpoint), last validation verdict, and the dry-run tester for
// analysts.
import type { Rule, RuleValidationResult } from "../api/types";
import { toYaml } from "../lib/yaml";
import { Alert } from "../ui/Alert";
import { Button } from "../ui/Button";
import { Panel } from "../ui/Card";
import { RuleTester } from "./RuleTester";
import { SeverityBadge } from "./SeverityBadge";

export interface RuleDetailProps {
  rule: Rule;
  validation: RuleValidationResult | "checking" | undefined;
  canWrite: boolean;
  onClose: () => void;
}

export function RuleDetail({ rule, validation, canWrite, onClose }: RuleDetailProps) {
  return (
    <Panel
      title="Rule detail"
      className="stack-top"
      meta={<span className="strong">{rule.name}</span>}
      actions={
        <Button size="sm" variant="ghost" onClick={onClose}>
          Close
        </Button>
      }
    >
      <div className="action-row">
        <SeverityBadge severity={rule.severity} />
        <span className="kind-cell">{rule.status}</span>
        <span className="conn-detail" title={rule.id}>
          {rule.id}
        </span>
      </div>

      <section className="stack-top" aria-label={`YAML preview of rule ${rule.name}`}>
        <span className="yaml-note">YAML preview — read-only</span>
        <pre className="yaml-block">{toYaml(rule.body)}</pre>
      </section>

      {validation !== undefined && validation !== "checking" && (
        <div className="stack-top">
          <Alert
            tone={validation.valid ? "info" : "critical"}
            title={validation.valid ? "Rule is valid" : "Rule rejected"}
          >
            {validation.errors.join(" · ")}
            {validation.warnings !== undefined && validation.warnings.length > 0 && (
              <> warnings: {validation.warnings.join(" · ")}</>
            )}
          </Alert>
        </div>
      )}

      {canWrite && (
        <div className="stack-top">
          <span className="yaml-note">Test against event</span>
          <RuleTester rule={rule} />
        </div>
      )}
    </Panel>
  );
}
