import { User } from "oidc-client-ts";
import type {
  AgentPage,
  AlertPage,
  AuditPage,
  EventPage,
  PolicyPage,
} from "./types";

const base = (import.meta.env.VITE_API_BASE ?? "/api/v1").replace(/\/$/, "");
const issuer = import.meta.env.VITE_OIDC_ISSUER as string | undefined;
const clientId = import.meta.env.VITE_OIDC_CLIENT_ID as string | undefined;

export const authEnabled = Boolean(issuer && clientId);
let currentUser: User | null = null;

export function setUser(user: User | null) {
  currentUser = user;
}

async function request<T>(path: string): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (currentUser) {
    headers.Authorization = `Bearer ${currentUser.access_token}`;
  }
  const response = await fetch(`${base}${path}`, { headers });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`${response.status}: ${body}`);
  }
  return (await response.json()) as T;
}

export const api = {
  events: (limit = 100) => request<EventPage>(`/events?limit=${limit}`),
  alerts: () => request<AlertPage>("/alerts"),
  agents: () => request<AgentPage>("/agents"),
  policies: () => request<PolicyPage>("/policies"),
  audit: () => request<AuditPage>("/audit"),
  stage: (version: number, content: string, name = "default") =>
    fetch(`${base}/policies/stage`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(currentUser ? { authorization: `Bearer ${currentUser.access_token}` } : {}),
      },
      body: JSON.stringify({ version, content, name }),
    }).then(async (response) => {
      if (!response.ok) {
        throw new Error(await response.text());
      }
      return response.json();
    }),
  commit: (version: number) =>
    fetch(`${base}/policies/commit`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(currentUser ? { authorization: `Bearer ${currentUser.access_token}` } : {}),
      },
      body: JSON.stringify({ version }),
    }).then(async (response) => {
      if (!response.ok) {
        throw new Error(await response.text());
      }
      return response.json();
    }),
};

export function streamUrl(): string {
  const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${window.location.host}${base}/events/stream`;
}
