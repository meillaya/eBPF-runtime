// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// In-memory session store. The access token (short-lived JWT) lives
// ONLY here — never in localStorage/sessionStorage (task constraint).
// The backend contract is `Authorization: Bearer <jwt>`; there is no
// cookie convention in crates/auth, so nothing is persisted here.
// PKCE transit state (verifier/state/nonce — non-secret, single-use)
// uses sessionStorage because it must survive the redirect hop.
import type { Role } from "./roles";

export interface Session {
  subject: string;
  email: string | null;
  role: Role;
  groups: string[];
  accessToken: string | null;
  expiresAtEpochSec: number | null;
  /** Loopback dev bypass is active (no OIDC; admin per task spec). */
  devMode: boolean;
}

let current: Session | null = null;
const subscribers = new Set<() => void>();

export function getSession(): Session | null {
  return current;
}

export function setSession(session: Session | null): void {
  current = session;
  for (const fn of subscribers) fn();
}

export function subscribeSession(fn: () => void): () => void {
  subscribers.add(fn);
  return () => {
    subscribers.delete(fn);
  };
}

/** Dev-mode loopback bypass: no auth, admin role (task 44 spec). */
export function devLoopbackSession(): Session {
  return {
    subject: "dev-loopback",
    email: null,
    role: "admin",
    groups: ["admins"],
    accessToken: null,
    expiresAtEpochSec: null,
    devMode: true,
  };
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1"]);

export function isLoopbackHost(): boolean {
  return LOOPBACK_HOSTS.has(globalThis.location.hostname);
}

/** Loopback bypass unless the operator explicitly forces OIDC. */
export function devBypassActive(): boolean {
  return isLoopbackHost() && import.meta.env.VITE_FORCE_OIDC !== "1";
}
