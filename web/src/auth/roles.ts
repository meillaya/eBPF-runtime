// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Role hierarchy mirroring crates/auth/src/rbac.rs. Wire strings are
// kebab-case; privilege is strictly ascending (Ord on the Rust enum).
// The server remains authoritative — client-side resolution only shapes
// the UI (nav items, enabled actions); every request is re-checked by
// the control plane.

export const ROLES = ["viewer", "analyst", "policy-admin", "admin"] as const;
export type Role = (typeof ROLES)[number];

export const ROLE_RANK: Record<Role, number> = {
  viewer: 0,
  analyst: 1,
  "policy-admin": 2,
  admin: 3,
};

export const ROLE_LABELS: Record<Role, string> = {
  viewer: "Viewer",
  analyst: "Analyst",
  "policy-admin": "Policy Admin",
  admin: "Admin",
};

export function roleAtLeast(role: Role, required: Role): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[required];
}

/** Actions from rbac.rs (Read < Write < Admin < SuperAdmin). */
export const ACTIONS = ["read", "write", "admin", "super_admin"] as const;
export type Action = (typeof ACTIONS)[number];

const ACTION_FLOOR: Record<Action, Role> = {
  read: "viewer",
  write: "analyst",
  admin: "policy-admin",
  super_admin: "admin",
};

export function permits(role: Role, action: Action): boolean {
  return roleAtLeast(role, ACTION_FLOOR[action]);
}

/**
 * OIDC `groups` claim → role, mirroring default_control_plane_policy
 * (plural bindings) PLUS the singular names the dev Dex static config
 * issues (deploy/compose/config/dex-config.yaml). Highest match wins,
 * exactly like RbacPolicy::resolve_role.
 */
const GROUP_BINDINGS: Record<string, Role> = {
  viewers: "viewer",
  viewer: "viewer",
  analysts: "analyst",
  analyst: "analyst",
  "policy-admins": "policy-admin",
  "policy-admin": "policy-admin",
  admins: "admin",
  admin: "admin",
};

/** Resolve the highest role bound to any group; null = no binding. */
export function resolveRole(groups: readonly string[]): Role | null {
  let best: Role | null = null;
  for (const group of groups) {
    const role = GROUP_BINDINGS[group];
    if (role !== undefined && (best === null || ROLE_RANK[role] > ROLE_RANK[best])) {
      best = role;
    }
  }
  return best;
}
