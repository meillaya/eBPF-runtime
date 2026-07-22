// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Domain types hand-mirrored from api/openapi.yaml
// (components.schemas — meta/alerts/rules/policies/agents/ops).
// Field names match the wire contract exactly (snake_case).

export interface Health {
  agent_id: string;
  node_name: string;
  cluster: string;
  epoch_unix_sec: number;
  loaded_sensors: string[];
  degraded_sensors: string[];
  blocked_sensors: string[];
  events_emitted_total: number;
  events_dropped_total: number;
  supported_load_rate: number;
}

export const CGROUP_MODES = ["UNIFIED", "HYBRID", "LEGACY", "UNKNOWN"] as const;
export type CgroupMode = (typeof CGROUP_MODES)[number];

export interface Compatibility {
  kernel_release: string;
  bpf_lsm_active: boolean;
  bpf_token_active: boolean;
  cgroup_mode: CgroupMode;
  bpf_program_type_allowlist: string[];
}

export const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const ALERT_STATUSES = ["OPEN", "ACKNOWLEDGED", "RESOLVED", "SUPPRESSED"] as const;
export type AlertStatus = (typeof ALERT_STATUSES)[number];

export interface Alert {
  id: string;
  rule_id: string;
  event_id: string;
  fired_at: string;
  severity: Severity;
  status: AlertStatus;
  rule_digest: string;
  explanation: string;
}

export interface AlertPage {
  alerts: Alert[];
  next_cursor?: string;
}

export const RULE_STATUSES = ["DRAFT", "ACTIVE", "RETIRED"] as const;
export type RuleStatus = (typeof RULE_STATUSES)[number];

export interface Rule {
  id: string;
  name: string;
  severity: Severity;
  status: RuleStatus;
  /** Opaque rule body — the API declares additionalProperties: true. */
  body: Record<string, unknown>;
  tags?: string[];
}

export interface RulePage {
  rules: Rule[];
  next_cursor?: string;
}

export interface RuleValidationResult {
  valid: boolean;
  errors: string[];
  warnings?: string[];
}

export interface RuleTestResult {
  matched: boolean;
  score: number;
  field_matches?: Record<string, unknown>;
}

export const POLICY_STATUSES = [
  "STAGED",
  "READY",
  "COMMITTED",
  "APPLIED",
  "REJECTED",
  "STALE",
] as const;
export type PolicyStatus = (typeof POLICY_STATUSES)[number];

export interface Policy {
  version: string;
  status: PolicyStatus;
  digest: string;
  created_at: string;
  author?: string;
  notes?: string;
}

export interface PolicyPage {
  policies: Policy[];
  next_cursor?: string;
}

export interface PolicyAck {
  agent_id: string;
  policy_version: string;
  digest?: string;
  hash_of_active?: string;
  accepted: boolean;
  rejected_reasons?: string[];
  acked_at?: string;
}

export interface PolicyAckPage {
  acks: PolicyAck[];
  next_cursor?: string;
}

export interface PolicyCommitResponse {
  committed_count: number;
  ack_count: number;
  rejected_count: number;
}

export interface StagePolicyRequest {
  version: string;
  digest: string;
  inactive_pbf_bytes: string;
  target_agent_ids?: string[];
}

export interface CommitPolicyRequest {
  version: string;
  digest: string;
  threshold_percent: number;
}

export interface AgentInventory {
  agent_id: string;
  node_name: string;
  cluster?: string;
  last_seen_epoch: number;
  policy_version?: string;
}

export interface AgentPage {
  agents: AgentInventory[];
  next_cursor?: string;
}

/** GET /drops rows are free-form counter records (additionalProperties). */
export type DropRecord = Record<string, unknown>;

export interface DropPage {
  drops: DropRecord[];
  next_cursor?: string;
}

/** Standard error body for every non-2xx response (openapi responses). */
export interface ApiErrorBody {
  error: string;
}
