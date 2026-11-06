import { User } from "oidc-client-ts";
import type {
  AckPage,
  AgentPage,
  AlertPage,
  AnalyticsSummary,
  AuditPage,
  EventPage,
  HealthSnapshot,
  Meta,
  PolicyPage,
  RolloutPage,
  RolloutResponse,
  ValidationResult,
} from "./types";

const base = (import.meta.env.VITE_API_BASE ?? "/api/v1").replace(/\/$/, "");
const issuer = import.meta.env.VITE_OIDC_ISSUER as string | undefined;
const clientId = import.meta.env.VITE_OIDC_CLIENT_ID as string | undefined;

export const authEnabled = Boolean(issuer && clientId);

const rootUrl = (() => {
  const url = new URL(base, window.location.origin);
  url.pathname = url.pathname.replace(/\/api\/v1\/?$/, "");
  return url.toString().replace(/\/$/, "");
})();

let currentUser: User | null = null;

export function setUser(user: User | null) {
  currentUser = user;
}

export function getUser(): User | null {
  return currentUser;
}

export class ApiError extends Error {
  readonly status: number;
  readonly body: string;

  constructor(status: number, body: string) {
    super(status === 401 ? "Your session is no longer valid." : body || `HTTP ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

function authHeaders(extra?: Record<string, string>): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...extra,
  };
  if (currentUser) {
    headers.Authorization = `Bearer ${currentUser.access_token}`;
  }
  return headers;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), 20_000);
  try {
    const response = await fetch(`${base}${path}`, {
      ...init,
      headers: authHeaders(init?.headers as Record<string, string> | undefined),
      signal: controller.signal,
    });
    const body = await response.text();
    if (!response.ok) {
      throw new ApiError(response.status, body);
    }
    return body ? (JSON.parse(body) as T) : (undefined as T);
  } finally {
    window.clearTimeout(timer);
  }
}

async function post<T>(path: string, payload: unknown): Promise<T> {
  return request<T>(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function systemHealth(): Promise<HealthSnapshot> {
  const checkedAt = Date.now();
  const [api, ready] = await Promise.allSettled([
    fetch(`${rootUrl}/healthz`),
    fetch(`${rootUrl}/readyz`),
  ]);
  const apiOk = api.status === "fulfilled" && api.value.ok;
  const readyOk = ready.status === "fulfilled" && ready.value.ok;
  let detail: string | undefined;
  if (!readyOk && ready.status === "fulfilled") {
    try {
      const body = (await ready.value.json()) as { error?: string };
      detail = body.error;
    } catch {
      detail = `readyz returned ${ready.value.status}`;
    }
  }
  return { api: apiOk, database: readyOk, checkedAt, detail };
}

export const api = {
  health: systemHealth,
  meta: () => request<Meta>("/meta"),
  events: (limit = 250) => request<EventPage>(`/events?limit=${limit}`),
  alerts: () => request<AlertPage>("/alerts"),
  agents: () => request<AgentPage>("/agents"),
  policies: () => request<PolicyPage>("/policies"),
  rollouts: (limit = 50) => request<RolloutPage>(`/rollouts?limit=${limit}`),
  audit: () => request<AuditPage>("/audit"),
  analytics: (hours: number) =>
    request<AnalyticsSummary>(`/analytics/summary?hours=${Math.max(1, Math.round(hours))}`),
  acks: (version: number) => request<AckPage>(`/policies/${version}/acks`),
  validate: (content: string) => post<ValidationResult>("/rules/validate", { content }),
  stage: (version: number, content: string, name: string) =>
    post<{ policy: unknown }>("/policies/stage", { version, content, name }),
  commit: (version: number) => post<unknown>("/policies/commit", { version }),
  rollout: (version: number, minRatio: number, timeoutSecs: number, force: boolean) =>
    post<RolloutResponse>(`/policies/${version}/rollout`, {
      min_ratio: minRatio,
      timeout_secs: timeoutSecs,
      force,
    }),
};
