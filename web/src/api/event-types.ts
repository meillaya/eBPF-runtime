// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Event-surface types hand-mirrored from api/openapi.yaml
// (components.schemas Event/Identity/payloads + EventBatch) and the
// control-plane live hub (crates/control-plane/src/live.rs LiveEvent).
// Keep field names EXACTLY as the wire contract — snake_case included.

export const EVENT_KINDS = [
  "EVENT_KIND_UNSPECIFIED",
  "EVENT_KIND_PROCESS_FORK",
  "EVENT_KIND_PROCESS_EXEC_RESULT",
  "EVENT_KIND_PROCESS_EXIT",
  "EVENT_KIND_FILE_OPEN",
  "EVENT_KIND_FILE_CREATE",
  "EVENT_KIND_FILE_UNLINK",
  "EVENT_KIND_FILE_RENAME",
  "EVENT_KIND_NETWORK_CONNECT",
  "EVENT_KIND_NETWORK_ACCEPT",
  "EVENT_KIND_NETWORK_STATE",
  "EVENT_KIND_DNS_PACKET",
  "EVENT_KIND_SYSCALL_ENTER",
  "EVENT_KIND_SYSCALL_EXIT",
  "EVENT_KIND_LSM_DENY_OWN",
  "EVENT_KIND_IDENTITY",
] as const;

export type EventKind = (typeof EVENT_KINDS)[number];

/** Task/process identity block (openapi Identity schema). */
export interface Identity {
  pid_tgid: number;
  task_start_time_ns?: number;
  cgroup_id?: number;
  mount_ns_id?: number;
  pid_ns_id?: number;
  net_ns_id?: number;
  user_ns_id?: number;
  uts_ns_id?: number;
  ipc_ns_id?: number;
  time_ns_id?: number;
  uid?: number;
  gid?: number;
  loginuid?: number;
  parent_pid_tgid?: number;
  valids?: Record<string, boolean>;
}

export interface ProcessExecResult {
  task: Identity;
  binary_path: string;
  argv_bytes?: string;
  succeeded: boolean;
  errno_value: number;
  argv_truncated: boolean;
}

export interface ProcessFork {
  child: Identity;
  is_thread: boolean;
}

export interface ProcessExit {
  task: Identity;
  exit_code: number;
  exit_group: boolean;
  group_dead_observed: boolean;
}

export interface FileOpen {
  task: Identity;
  path: string;
  flags: number;
  succeeded: boolean;
  errno_value: number;
  from_lsm: boolean;
}

export interface FileCreate {
  task: Identity;
  path: string;
  flags: number;
  mode: number;
  succeeded: boolean;
  errno_value: number;
  from_lsm: boolean;
}

export interface FileUnlink {
  task: Identity;
  path: string;
  is_dir: boolean;
  succeeded: boolean;
  errno_value: number;
  from_lsm: boolean;
}

export interface FileRename {
  task: Identity;
  source_path: string;
  dest_path: string;
  succeeded: boolean;
  errno_value: number;
  from_lsm: boolean;
}

export interface NetworkConnect {
  task: Identity;
  socket_cookie: number;
  family: number;
  local_addr?: string;
  remote_addr?: string;
  local_port?: number;
  remote_port?: number;
  is_result: boolean;
  established: boolean;
  errno_value: number;
  from_cgroup: boolean;
}

export interface NetworkAccept {
  task: Identity;
  socket_cookie: number;
  family: number;
  local_addr?: string;
  remote_addr?: string;
  local_port?: number;
  remote_port?: number;
  returned_fd: number;
  succeeded: boolean;
  errno_value: number;
}

export interface NetworkState {
  task: Identity;
  socket_cookie: number;
  old_state: number;
  new_state: number;
}

export interface DnsPacket {
  task: Identity;
  is_query: boolean;
  transport: number;
  packet_bytes: string;
  truncated: boolean;
  is_egress: boolean;
}

export interface SyscallEnter {
  task: Identity;
  syscall_nr: number;
  ts_monotonic_ns: number;
  compat_syscall_nr?: number;
}

export interface SyscallExit {
  task: Identity;
  syscall_nr: number;
  ts_monotonic_ns: number;
  elapsed_ns: number;
  compat_syscall_nr?: number;
  no_return: boolean;
  errno_value: number;
}

export interface LsmDeny {
  task: Identity;
  hook: string;
  subject: string;
  own_deny: boolean;
  policy_version: string;
  policy_digest?: string;
}

/** One REST event (openapi Event schema): exactly one payload is set. */
export interface Event {
  event_id: string;
  seq: number;
  ts_monotonic_ns: number;
  ts_wall?: string;
  sensor: string;
  event_kind: EventKind;
  valids?: Record<string, boolean>;
  kfuncs_used?: string[];
  process_exec_result?: ProcessExecResult;
  process_fork?: ProcessFork;
  process_exit?: ProcessExit;
  file_open?: FileOpen;
  file_create?: FileCreate;
  file_unlink?: FileUnlink;
  file_rename?: FileRename;
  network_connect?: NetworkConnect;
  network_accept?: NetworkAccept;
  network_state?: NetworkState;
  dns_packet?: DnsPacket;
  syscall_enter?: SyscallEnter;
  syscall_exit?: SyscallExit;
  lsm_deny?: LsmDeny;
  identity?: Identity;
}

/** GET /events response (openapi EventBatch). */
export interface EventBatch {
  events: Event[];
  /**
   * Extension: server-issued opaque pagination cursor
   * (control-plane pagination.rs PageResponse.next_cursor — the
   * OpenAPI EventBatch schema predates it; treat as optional).
   */
  next_cursor?: string;
}

/**
 * One WebSocket frame from /events/stream
 * (crates/control-plane/src/live.rs LiveEvent — serde wire shape).
 * `payload` is redacted event JSON **as a string**; parse defensively.
 */
export interface LiveEvent {
  seq: number;
  event_id: string;
  event_kind: EventKind;
  node_name: string;
  cluster: string;
  ts_monotonic_ns: number;
  payload: string;
}
