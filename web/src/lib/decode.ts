// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Wire-decode helpers for the telemetry views. Pure functions that turn
// raw openapi Event payload fields (base64 addresses, numeric enums,
// errno values, DNS packet bytes) into honest, display-ready strings.
// Nothing here ever invents data: undecodable fields render as "—".
import type { Identity } from "../api/event-types";

/** openapi `format: byte` fields are base64; decode defensively. */
export function decodeBase64(b64: string | undefined): Uint8Array | null {
  if (b64 === undefined || b64 === "") return null;
  try {
    const raw = globalThis.atob(b64);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

export const AF_INET = 2;
export const AF_INET6 = 10;

export function familyName(family: number): string {
  if (family === AF_INET) return "IPv4";
  if (family === AF_INET6) return "IPv6";
  return `af:${family}`;
}

function formatIpBytes(bytes: Uint8Array): string | null {
  if (bytes.length === 4) return Array.from(bytes).join(".");
  if (bytes.length === 16) {
    const groups: string[] = [];
    for (let i = 0; i < 16; i += 2) {
      const hi = bytes[i] ?? 0;
      const lo = bytes[i + 1] ?? 0;
      groups.push(((hi << 8) | lo).toString(16));
    }
    return groups.join(":");
  }
  return null;
}

/** Base64 addr + port → "10.0.0.4:5353" / "[2606:…]:443" / "—". */
export function formatEndpoint(addrB64: string | undefined, port: number | undefined): string {
  const ip = formatIpBytes(decodeBase64(addrB64) ?? new Uint8Array(0));
  if (ip === null) return "—";
  const host = ip.includes(":") ? `[${ip}]` : ip;
  return port === undefined ? host : `${host}:${port}`;
}

/** TCP state numbers from event-abi `enum kernel_v1_tcp_state`. */
const TCP_STATES: ReadonlyMap<number, string> = new Map([
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
  [12, "NEW_SYN_RECV"],
  [0xff, "NONE"],
]);

export function tcpStateName(state: number): string {
  return TCP_STATES.get(state) ?? `STATE_${state}`;
}

/** Common Linux errnos (generic table, arch-independent subset). */
const ERRNOS: ReadonlyMap<number, string> = new Map([
  [1, "EPERM"],
  [2, "ENOENT"],
  [9, "EBADF"],
  [11, "EAGAIN"],
  [13, "EACCES"],
  [14, "EFAULT"],
  [17, "EEXIST"],
  [20, "ENOTDIR"],
  [21, "EISDIR"],
  [22, "EINVAL"],
  [23, "ENFILE"],
  [24, "EMFILE"],
  [28, "ENOSPC"],
  [30, "EROFS"],
  [32, "EPIPE"],
  [95, "EOPNOTSUPP"],
  [98, "EADDRINUSE"],
  [99, "EADDRNOTAVAIL"],
  [101, "ENETUNREACH"],
  [103, "ECONNABORTED"],
  [104, "ECONNRESET"],
  [110, "ETIMEDOUT"],
  [111, "ECONNREFUSED"],
  [113, "EHOSTUNREACH"],
  [114, "EALREADY"],
  [115, "EINPROGRESS"],
]);

export const ECONNREFUSED = 111;
export const EINPROGRESS = 115;
export const EACCES = 13;
export const EPERM = 1;

/** 0 → "—" (success), known → "ECONNREFUSED (111)", else "errno 42". */
export function errnoLabel(value: number): string {
  if (value === 0) return "—";
  const name = ERRNOS.get(value);
  return name === undefined ? `errno ${value}` : `${name} (${value})`;
}

export function dnsTransportName(transport: number): string {
  if (transport === 0) return "UDP";
  if (transport === 1) return "TCP";
  return `transport:${transport}`;
}

export const DNS_QTYPES: ReadonlyMap<number, string> = new Map([
  [1, "A"],
  [2, "NS"],
  [5, "CNAME"],
  [6, "SOA"],
  [15, "MX"],
  [16, "TXT"],
  [28, "AAAA"],
  [33, "SRV"],
  [65, "HTTPS"],
  [255, "ANY"],
]);

export interface DnsHeaderInfo {
  txid: number;
  qname: string | null;
  qtype: number | null;
}

/**
 * Defensive DNS header + first-question parse from raw packet bytes.
 * Stops at compression pointers (0xC0) rather than following them —
 * the cleartext qname prefix is all we surface. Never throws.
 */
export function parseDnsPacket(bytes: Uint8Array): DnsHeaderInfo | null {
  if (bytes.length < 12) return null;
  const txid = ((bytes[0] ?? 0) << 8) | (bytes[1] ?? 0);
  const info: DnsHeaderInfo = { txid, qname: null, qtype: null };
  const labels: string[] = [];
  let cursor = 12;
  let consumed = 0; // bytes of the on-wire name we walked (for qtype offset)
  let total = 0;
  while (cursor < bytes.length && total < 253) {
    const len = bytes[cursor] ?? 0;
    if (len === 0) {
      consumed += 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      consumed += 2; // compression pointer: stop, do not follow
      break;
    }
    const end = cursor + 1 + len;
    if (end > bytes.length) return info; // header claims more than we have
    const decoder = new TextDecoder("ascii", { fatal: false });
    labels.push(decoder.decode(bytes.subarray(cursor + 1, end)));
    total += len + 1;
    consumed = end - 12 + 1;
    cursor = end;
  }
  if (labels.length > 0) info.qname = labels.join(".");
  const qtypeAt = 12 + consumed;
  if (qtypeAt + 2 <= bytes.length) {
    info.qtype = ((bytes[qtypeAt] ?? 0) << 8) | (bytes[qtypeAt + 1] ?? 0);
  }
  return info;
}

const O_WRONLY = 0o1;
const O_RDWR = 0o2;

/** FILE_OPEN flags → "open-read" / "open-write" (access-mode bits). */
export function fileOpenOp(flags: number): string {
  return (flags & (O_WRONLY | O_RDWR)) !== 0 ? "open-write" : "open-read";
}

/** pid_tgid packs tgid << 32 | pid (kernel convention). */
export function processLabel(task: Identity): string {
  const tgid = Math.floor(task.pid_tgid / 0x1_0000_0000);
  const pid = task.pid_tgid >>> 0;
  return `${tgid}/${pid}`;
}

/** Keys of a valids map that are explicitly false (= field invalid). */
export function invalidFields(valids: Record<string, boolean> | undefined): string[] {
  if (valids === undefined) return [];
  return Object.entries(valids)
    .filter(([, ok]) => !ok)
    .map(([key]) => key);
}
