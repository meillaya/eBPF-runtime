// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Typed REST client for the dashboard API (api/openapi.yaml is the
// authoritative contract — one method per operationId). Bearer tokens
// come from the in-memory session (auth/session.ts); nothing sensitive
// ever touches localStorage. The browser NEVER reaches the privileged
// agent gRPC surface — only this REST/WS contract.
import { getSession } from "../auth/session";
import type { Event, EventBatch, EventKind, LiveEvent } from "./event-types";
import type {
  AgentPage,
  AlertPage,
  ApiErrorBody,
  CommitPolicyRequest,
  Compatibility,
  DropPage,
  Health,
  Policy,
  PolicyAckPage,
  PolicyCommitResponse,
  PolicyPage,
  Rule,
  RulePage,
  RuleTestResult,
  RuleValidationResult,
  StagePolicyRequest,
} from "./types";

/** Non-2xx from the API, with the contract's `{error}` body decoded. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly retryAfterSec: number | undefined,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** REST base. Empty string = same-origin (fleet mode behind the proxy). */
export const API_BASE: string = import.meta.env.VITE_API_BASE ?? "http://127.0.0.1:9464";

/** WebSocket URL for /events/stream, derived from API_BASE or location. */
export function streamUrl(params: URLSearchParams): string {
  let base: string;
  if (API_BASE === "") {
    const scheme = globalThis.location.protocol === "https:" ? "wss:" : "ws:";
    base = `${scheme}//${globalThis.location.host}`;
  } else {
    base = API_BASE.replace(/^http/, "ws");
  }
  const qs = params.toString();
  return `${base}/events/stream${qs === "" ? "" : `?${qs}`}`;
}

interface RequestHeaders {
  Accept: string;
  Authorization?: string;
}

function authHeaders(): RequestHeaders {
  const session = getSession();
  if (session !== null && session.accessToken !== null) {
    return { Accept: "application/json", Authorization: `Bearer ${session.accessToken}` };
  }
  return { Accept: "application/json" };
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const url = `${API_BASE}${path}`;
  let res: Response;
  try {
    res = await fetch(url, { ...init, headers: { ...authHeaders(), ...init.headers } });
  } catch (cause) {
    throw new ApiError(0, `network unreachable: ${String(cause)}`, undefined);
  }
  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    try {
      const body = (await res.json()) as ApiErrorBody;
      if (typeof body.error === "string") message = body.error;
    } catch {
      // non-JSON error body; keep the status line
    }
    const retry = res.headers.get("Retry-After");
    const retryAfterSec = retry === null ? undefined : Number.parseInt(retry, 10);
    throw new ApiError(
      res.status,
      message,
      Number.isNaN(retryAfterSec ?? 0) ? undefined : retryAfterSec,
    );
  }
  return (await res.json()) as T;
}

/** Build a query string, omitting unset params. */
function qs(params: Record<string, string | number | undefined>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined) sp.set(k, String(v));
  }
  const s = sp.toString();
  return s === "" ? "" : `?${s}`;
}

export interface EventQuery {
  cursor?: string | undefined;
  since_ts_monotonic_ns?: number | undefined;
  sensor?: string | undefined;
  event_kind?: EventKind | undefined;
  limit?: number | undefined;
}

export const api = {
  // -- meta (unauthenticated in dev mode) --------------------------------
  getHealth: (): Promise<Health> => request("/health"),
  getCompatibility: (): Promise<Compatibility> => request("/compatibility"),

  // -- events -------------------------------------------------------------
  listEvents: (q: EventQuery = {}): Promise<EventBatch> => request(`/events${qs({ ...q })}`),

  // -- alerts -------------------------------------------------------------
  listAlerts: (q: { cursor?: string; limit?: number } = {}): Promise<AlertPage> =>
    request(`/alerts${qs({ ...q })}`),

  // -- rules ---------------------------------------------------------------
  listRules: (q: { cursor?: string; limit?: number } = {}): Promise<RulePage> =>
    request(`/rules${qs({ ...q })}`),
  getRule: (ruleId: string): Promise<Rule> => request(`/rules/${encodeURIComponent(ruleId)}`),
  validateRule: (rule: Rule): Promise<RuleValidationResult> =>
    request("/rules/validate", {
      method: "POST",
      body: JSON.stringify(rule),
      headers: { "Content-Type": "application/json" },
    }),
  testRule: (rule: Rule, event: Event): Promise<RuleTestResult> =>
    request("/rules/test", {
      method: "POST",
      body: JSON.stringify({ rule, event }),
      headers: { "Content-Type": "application/json" },
    }),

  // -- policies ------------------------------------------------------------
  listPolicies: (q: { cursor?: string; limit?: number } = {}): Promise<PolicyPage> =>
    request(`/policies${qs({ ...q })}`),
  getPolicy: (version: string): Promise<Policy> =>
    request(`/policies/${encodeURIComponent(version)}`),
  stagePolicy: (body: StagePolicyRequest): Promise<PolicyCommitResponse> =>
    request("/policies/stage", {
      method: "POST",
      body: JSON.stringify(body),
      headers: { "Content-Type": "application/json" },
    }),
  commitPolicy: (body: CommitPolicyRequest): Promise<PolicyCommitResponse> =>
    request("/policies/commit", {
      method: "POST",
      body: JSON.stringify(body),
      headers: { "Content-Type": "application/json" },
    }),
  rollbackPolicy: (version: string, digest?: string): Promise<PolicyCommitResponse> =>
    request(`/policies/${encodeURIComponent(version)}/rollback`, {
      method: "POST",
      body: JSON.stringify(digest === undefined ? {} : { digest }),
      headers: { "Content-Type": "application/json" },
    }),
  listPolicyAcks: (
    version: string,
    q: { cursor?: string; limit?: number } = {},
  ): Promise<PolicyAckPage> =>
    request(`/policies/${encodeURIComponent(version)}/acks${qs({ ...q })}`),

  // -- agents / ops ----------------------------------------------------------
  listAgents: (q: { cursor?: string; limit?: number } = {}): Promise<AgentPage> =>
    request(`/agents${qs({ ...q })}`),
  listDrops: (
    q: { cursor?: string; since_ts_monotonic_ns?: number; sensor?: string; limit?: number } = {},
  ): Promise<DropPage> => request(`/drops${qs({ ...q })}`),
};

/** Decode one WebSocket text frame into a LiveEvent (defensive). */
export function parseLiveFrame(data: string): LiveEvent | null {
  let value: unknown;
  try {
    value = JSON.parse(data);
  } catch {
    return null;
  }
  if (typeof value !== "object" || value === null) return null;
  interface RawFrame {
    seq?: unknown;
    event_id?: unknown;
    event_kind?: unknown;
    ts_monotonic_ns?: unknown;
  }
  const frame = value as RawFrame;
  if (typeof frame.seq !== "number" || typeof frame.event_id !== "string") return null;
  if (typeof frame.event_kind !== "string" || typeof frame.ts_monotonic_ns !== "number")
    return null;
  return value as LiveEvent;
}
