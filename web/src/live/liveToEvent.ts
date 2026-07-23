// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Decode one redacted live-stream frame (live.rs LiveEvent: payload is
// event JSON as a string) into the REST Event shape. Defensive by
// contract: unparseable payloads return null, unknown blocks are
// dropped, envelope fields always come from the frame itself.
import type { Event, LiveEvent } from "../api/event-types";

const PAYLOAD_BLOCKS = [
  "process_exec_result",
  "process_fork",
  "process_exit",
  "file_open",
  "file_create",
  "file_unlink",
  "file_rename",
  "network_connect",
  "network_accept",
  "network_state",
  "dns_packet",
  "syscall_enter",
  "syscall_exit",
  "lsm_deny",
  "identity",
] as const;

export function liveToEvent(frame: LiveEvent): Event | null {
  let value: unknown;
  try {
    value = JSON.parse(frame.payload);
  } catch {
    return null;
  }
  if (typeof value !== "object" || value === null) return null;
  const rec = value as Record<string, unknown>;
  const blocks: Record<string, unknown> = {};
  for (const key of PAYLOAD_BLOCKS) {
    const block = rec[key];
    if (typeof block === "object" && block !== null) blocks[key] = block;
  }
  const { valids } = rec;
  const event = {
    event_id: frame.event_id,
    seq: frame.seq,
    ts_monotonic_ns: frame.ts_monotonic_ns,
    sensor: frame.node_name,
    event_kind: frame.event_kind,
    ...blocks,
  } as Event;
  if (typeof valids === "object" && valids !== null) {
    event.valids = valids as Record<string, boolean>;
  }
  return event;
}
