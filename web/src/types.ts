export type Severity = "critical" | "high" | "medium" | "low" | "info" | string;
export type Role = "viewer" | "analyst" | "policy-admin" | "admin";

export interface RedactionFlags {
  argv_redacted?: boolean;
  message_redacted?: boolean;
  path_redacted?: boolean;
}

export interface Event {
  time: string;
  sensor: string;
  kind: string;
  schema_major?: number;
  schema_minor?: number;
  event_id: string;
  boot_id?: string;
  seq?: number;
  redaction?: RedactionFlags;
  pid: number;
  tgid: number;
  cgroup_id: number;
  task_start_ns?: number;
  path?: string;
  old_path?: string;
  process_exec?: string;
  argv?: string[];
  parent_pid?: number;
  child_pid?: number;
  exit_code?: number;
  thread?: boolean;
  flags?: number;
  open_flags?: number;
  mode?: number;
  length?: number;
  network?: unknown;
  syscall?: unknown;
  identity?: unknown;
  dns?: unknown;
  [key: string]: unknown;
}

export interface Alert {
  alert_id: string;
  rule_id: string;
  severity: Severity;
  event_id: string;
  fired_at: string;
  explanation: string;
  cluster: string;
  node_name: string;
}

export interface Agent {
  id: string;
  cluster_id: string;
  spiffe_id: string;
  node_name: string;
  agent_generation: string;
  last_seen_epoch: number;
  sensors: string[];
}

export interface Policy {
  id: string;
  name: string;
  version: number;
  content: string;
  digest: string;
  status: string;
  created_at_epoch: number;
}

export interface Rollout {
  id: string;
  cluster_id: string;
  policy_id: string;
  name: string;
  version: number;
  previous_version: number | null;
  requested_by: string;
  min_ratio: number;
  timeout_secs: number;
  force: boolean;
  status: string;
  expected_agents: number;
  applied_agents: number;
  rejected_agents: number;
  reason: string;
  detail: unknown;
  digest: string;
  started_at_epoch: number;
  deadline_epoch: number;
  finished_at_epoch: number | null;
}

export interface Ack {
  policy_version: number;
  agent_id: string;
  status: string;
  digest: string;
  message: string;
  updated_at_epoch: number;
}

export interface AuditRow {
  actor: string;
  action: string;
  resource: string;
  success: boolean;
  detail: unknown;
  created_at_epoch: number;
}

export interface AnalyticsBucket {
  kind?: string;
  severity?: string;
  count: string | number;
}

export interface AnalyticsSummary {
  events: AnalyticsBucket[];
  alerts: AnalyticsBucket[];
}

export interface ValidationResult {
  valid: boolean;
  digest?: string;
  rules?: number;
  error?: string;
}

export interface EventPage {
  events: Event[];
  next_cursor: string | null;
}

export interface AlertPage {
  alerts: Alert[];
  next_cursor: string | null;
}

export interface AgentPage {
  agents: Agent[];
  next_cursor: string | null;
}

export interface PolicyPage {
  policies: Policy[];
  next_cursor: string | null;
}

export interface AuditPage {
  audit: AuditRow[];
}

export interface RolloutPage {
  rollouts: Rollout[];
}

export interface AckPage {
  acks: Ack[];
  next_cursor: string | null;
}

export interface RolloutResponse {
  rollout: Rollout;
}

export interface HealthSnapshot {
  api: boolean;
  database: boolean;
  checkedAt: number;
  detail?: string;
}

export interface Meta {
  cluster_name: string;
  version: string;
  analytics: boolean;
}
