import { User, UserManager, WebStorageStateStore } from "oidc-client-ts";
import { authEnabled, getUser, setUser } from "./api";
import type { Role } from "./types";

const issuer = import.meta.env.VITE_OIDC_ISSUER as string | undefined;
const clientId = import.meta.env.VITE_OIDC_CLIENT_ID as string | undefined;

export interface AuthIdentity {
  name: string;
  email?: string;
  groups: string[];
  role: Role | null;
}

export const manager =
  authEnabled && issuer && clientId
    ? new UserManager({
        authority: issuer,
        client_id: clientId,
        redirect_uri: window.location.origin + "/callback",
        response_type: "code",
        scope: "openid profile email groups",
        userStore: new WebStorageStateStore({ store: window.sessionStorage }),
      })
    : null;

const roleOrder: Role[] = ["viewer", "analyst", "policy-admin", "admin"];

export function roleRank(role: Role | null): number {
  return role ? roleOrder.indexOf(role) : -1;
}

export function roleAtLeast(role: Role | null, minimum: Role): boolean {
  return roleRank(role) >= roleRank(minimum);
}

export function roleLabel(role: Role | null): string {
  switch (role) {
    case "admin":
      return "Admin";
    case "policy-admin":
      return "Policy admin";
    case "analyst":
      return "Analyst";
    case "viewer":
      return "Viewer";
    default:
      return "No fleet role";
  }
}

export function roleFromGroups(groups: string[]): Role | null {
  let role: Role | null = null;
  for (const group of groups) {
    const candidate: Role | null =
      group === "ebpf-admins" || group === "fleet-admins"
        ? "admin"
        : group === "ebpf-policy-admins" || group === "fleet-policy-admins"
          ? "policy-admin"
          : group === "ebpf-analysts" || group === "fleet-analysts"
            ? "analyst"
            : group === "ebpf-viewers" || group === "fleet-viewers"
              ? "viewer"
              : null;
    if (candidate && (!role || roleRank(candidate) > roleRank(role))) {
      role = candidate;
    }
  }
  return role;
}

function decodeJwt(token: string): Record<string, unknown> | null {
  try {
    const payload = token.split(".")[1];
    if (!payload) return null;
    const padded = payload.replace(/-/g, "+").replace(/_/g, "/").padEnd(
      payload.length + ((4 - (payload.length % 4)) % 4),
      "=",
    );
    return JSON.parse(atob(padded)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function identityFor(user: User): AuthIdentity {
  const claims = decodeJwt(user.access_token) ?? {};
  const groups = Array.isArray(claims.groups)
    ? (claims.groups as string[])
    : Array.isArray(user.profile?.groups)
      ? (user.profile.groups as string[])
      : [];
  const name =
    (typeof claims.name === "string" && claims.name) ||
    (typeof user.profile?.name === "string" && user.profile.name) ||
    (typeof claims.email === "string" && claims.email) ||
    (typeof claims.sub === "string" && claims.sub) ||
    "Signed in";
  const email =
    (typeof claims.email === "string" && claims.email) ||
    (typeof user.profile?.email === "string" && user.profile.email) ||
    undefined;
  return { name, email, groups, role: roleFromGroups(groups) };
}

export async function initAuth(): Promise<AuthIdentity | null> {
  if (!manager) {
    return null;
  }
  if (window.location.pathname === "/callback") {
    await manager.signinRedirectCallback();
    window.history.replaceState({}, "", "/");
  }
  let user = await manager.getUser();
  if (!user) {
    setUser(null);
    return null;
  }
  if (user.expired) {
    await manager.removeUser();
    setUser(null);
    return null;
  }
  setUser(user);
  return identityFor(user);
}

export async function login() {
  await manager?.signinRedirect();
}

export async function logout() {
  setUser(null);
  await manager?.signoutRedirect();
}

export function currentIdentity(): AuthIdentity | null {
  const user = getUser();
  return user ? identityFor(user) : null;
}
