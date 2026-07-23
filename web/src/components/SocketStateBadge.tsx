// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Connection-state indicator with semantic honesty baked in: a connect
// ATTEMPT is never rendered as ESTABLISHED, EINPROGRESS means "nonblocking
// connect issued, outcome pending" (not success), and a result is classified
// from its errno — REFUSED (ECONNREFUSED) vs FAILED (anything else).
import type { NetworkAccept, NetworkConnect } from "../api/event-types";
import { ECONNREFUSED, EINPROGRESS, tcpStateName } from "../lib/decode";
import { cx } from "../lib/format";

export type SocketPhase =
  | "ATTEMPT"
  | "EINPROGRESS"
  | "ESTABLISHED"
  | "REFUSED"
  | "FAILED"
  | "ACCEPTED"
  | "SYN_SENT"
  | "SYN_RECV"
  | "FIN_WAIT_1"
  | "FIN_WAIT_2"
  | "TIME_WAIT"
  | "CLOSE_WAIT"
  | "LAST_ACK"
  | "CLOSING"
  | "CLOSED"
  | "LISTEN";

type PhaseTone = "live" | "info" | "low" | "medium" | "critical" | "muted";

const PHASE_META: ReadonlyMap<SocketPhase, { label: string; tone: PhaseTone }> = new Map([
  ["ATTEMPT", { label: "Attempt", tone: "info" }],
  ["EINPROGRESS", { label: "Einprogress", tone: "low" }],
  ["ESTABLISHED", { label: "Established", tone: "live" }],
  ["REFUSED", { label: "Refused", tone: "critical" }],
  ["FAILED", { label: "Failed", tone: "critical" }],
  ["ACCEPTED", { label: "Accepted", tone: "live" }],
  ["SYN_SENT", { label: "Syn-Sent", tone: "info" }],
  ["SYN_RECV", { label: "Syn-Recv", tone: "live" }],
  ["FIN_WAIT_1", { label: "Fin-Wait-1", tone: "medium" }],
  ["FIN_WAIT_2", { label: "Fin-Wait-2", tone: "medium" }],
  ["TIME_WAIT", { label: "Time-Wait", tone: "medium" }],
  ["CLOSE_WAIT", { label: "Close-Wait", tone: "medium" }],
  ["LAST_ACK", { label: "Last-Ack", tone: "medium" }],
  ["CLOSING", { label: "Closing", tone: "medium" }],
  ["CLOSED", { label: "Closed", tone: "muted" }],
  ["LISTEN", { label: "Listen", tone: "low" }],
]);

const STATE_TO_PHASE: ReadonlyMap<number, SocketPhase> = new Map([
  [1, "ESTABLISHED"],
  [2, "SYN_SENT"],
  [3, "SYN_RECV"],
  [4, "FIN_WAIT_1"],
  [5, "FIN_WAIT_2"],
  [6, "TIME_WAIT"],
  [7, "CLOSED"],
  [8, "CLOSE_WAIT"],
  [9, "LAST_ACK"],
  [10, "LISTEN"],
  [11, "CLOSING"],
  [12, "SYN_RECV"],
]);

/** NETWORK_CONNECT: is_result splits attempts from outcomes. */
export function phaseFromConnect(nc: NetworkConnect): SocketPhase {
  if (!nc.is_result) return "ATTEMPT";
  if (nc.errno_value === EINPROGRESS) return "EINPROGRESS";
  if (nc.errno_value === ECONNREFUSED) return "REFUSED";
  if (nc.established && nc.errno_value === 0) return "ESTABLISHED";
  return "FAILED";
}

/** NETWORK_STATE: kernel TCP state byte → lifecycle phase. */
export function phaseFromTcpState(newState: number): SocketPhase | null {
  return STATE_TO_PHASE.get(newState) ?? null;
}

export function phaseFromAccept(na: NetworkAccept): SocketPhase {
  if (na.succeeded) return "ACCEPTED";
  if (na.errno_value === ECONNREFUSED) return "REFUSED";
  return "FAILED";
}

export function SocketStateBadge({ phase }: { phase: SocketPhase }) {
  const meta = PHASE_META.get(phase) ?? { label: phase, tone: "muted" as const };
  return (
    <span className={cx("badge", `badge--${meta.tone}`)}>
      <span className="dot" aria-hidden="true" />
      {meta.label}
    </span>
  );
}

/** "SYN_SENT → ESTABLISHED" transition cell for NETWORK_STATE rows. */
export function StateTransition({ oldState, newState }: { oldState: number; newState: number }) {
  return (
    <span className="transition-cell">
      <span className="transition-from">{tcpStateName(oldState)}</span>
      <span className="transition-arrow" aria-hidden="true">
        →
      </span>
      <span className="transition-to">{tcpStateName(newState)}</span>
    </span>
  );
}
