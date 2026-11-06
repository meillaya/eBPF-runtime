export interface Event {
  time: string;
  sensor: string;
  kind: string;
  pid: number;
  tgid: number;
  cgroup_id: number;
  event_id: string;
  path?: string;
  process_exec?: string;
  parent_pid?: number;
  child_pid?: number;
  exit_code?: number;
}

export interface Alert {
  alert_id: string;
  rule_id: string;
  severity: string;
  event_id: string;
  fired_at: string;
  explanation: string;
}

export interface Agent {
  id: string;
  spiffe_id: string;
  node_name: string;
  agent_generation: string;
  last_seen_epoch: number;
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

export interface AuditRow {
  actor: string;
  action: string;
  resource: string;
  success: boolean;
  created_at_epoch: number;
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
