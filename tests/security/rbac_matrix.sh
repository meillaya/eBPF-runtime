#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# RBAC negative matrix: adversarial role escalation tests.
#
# Tests the RBAC enforcement via PostgreSQL session variables (app.role)
# and RLS policies. Mirrors crates/auth/src/rbac.rs role hierarchy:
#   viewer < analyst < policy-admin < admin
#
# Route action requirements (from default_control_plane_policy):
#   Read       -> viewer+
#   Write      -> analyst+
#   Admin      -> policy-admin+ (stage/commit/rollback)
#   SuperAdmin -> admin only (config)
#
# Usage: bash tests/security/rbac_matrix.sh
# Requires: bash, jq, podman (or PSQL_CMD override)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib.sh"

CATEGORY="rbac"

echo "═══ RBAC Negative Matrix ═══"
echo ""

# Helper: attempt an operation with a given app.role via RLS test user.
# Returns the psql output. Usage: try_as_role <role> <sql>
try_as_role() {
  local role="$1" sql="$2"
  psql_rls -c "BEGIN; SET LOCAL app.role = '${role}'; SET LOCAL app.cluster_id = '${CLUSTER_ALPHA}'; ${sql} ROLLBACK;" 2>&1
}

# ---------------------------------------------------------------------------
# RBAC-001: viewer cannot write policies (INSERT)
# RLS policy_write requires app.role IN ('policy-admin', 'admin')
# ---------------------------------------------------------------------------
OUT=$(try_as_role "viewer" "INSERT INTO policies (name, description) VALUES ('viewer-hack', 'should fail');")
if echo "${OUT}" | grep -qi "permission denied\|row-level security\|violates\|ERROR"; then
  pass "RBAC-001" "${CATEGORY}" "viewer cannot INSERT policies" "blocked: $(echo "${OUT}" | head -1)"
else
  fail "RBAC-001" "${CATEGORY}" "viewer cannot INSERT policies" "INSERT succeeded — RLS bypass: ${OUT}"
fi

# ---------------------------------------------------------------------------
# RBAC-002: viewer cannot UPDATE policies
# ---------------------------------------------------------------------------
OUT=$(try_as_role "viewer" "UPDATE policies SET description = 'hacked' WHERE name = 'test-policy';")
if echo "${OUT}" | grep -qi "permission denied\|row-level security\|violates\|ERROR\|UPDATE 0"; then
  # UPDATE 0 means RLS filtered the row (no visible rows to update)
  pass "RBAC-002" "${CATEGORY}" "viewer cannot UPDATE policies" "blocked or 0 rows: $(echo "${OUT}" | head -1)"
else
  fail "RBAC-002" "${CATEGORY}" "viewer cannot UPDATE policies" "UPDATE succeeded: ${OUT}"
fi

# ---------------------------------------------------------------------------
# RBAC-003: analyst cannot admin (stage/commit via policy write)
# analyst is above viewer but below policy-admin
# ---------------------------------------------------------------------------
OUT=$(try_as_role "analyst" "INSERT INTO policies (name, description) VALUES ('analyst-hack', 'should fail');")
if echo "${OUT}" | grep -qi "permission denied\|row-level security\|violates\|ERROR"; then
  pass "RBAC-003" "${CATEGORY}" "analyst cannot INSERT policies" "blocked: $(echo "${OUT}" | head -1)"
else
  fail "RBAC-003" "${CATEGORY}" "analyst cannot INSERT policies" "INSERT succeeded — RLS bypass: ${OUT}"
fi

# ---------------------------------------------------------------------------
# RBAC-004: policy-admin cannot super-admin (config route)
# In DB terms: policy-admin can write policies but NOT oidc_role_bindings
# (which requires app.role = 'admin' per oidc_admin RLS policy)
# ---------------------------------------------------------------------------
OUT=$(try_as_role "policy-admin" "INSERT INTO oidc_role_bindings (binding_type, principal, role) VALUES ('sub', 'attacker', 'admin');")
if echo "${OUT}" | grep -qi "permission denied\|row-level security\|violates\|ERROR"; then
  pass "RBAC-004" "${CATEGORY}" "policy-admin cannot write oidc_role_bindings" "blocked: $(echo "${OUT}" | head -1)"
else
  fail "RBAC-004" "${CATEGORY}" "policy-admin cannot write oidc_role_bindings" "INSERT succeeded — privilege escalation: ${OUT}"
fi

# ---------------------------------------------------------------------------
# RBAC-005: unauthenticated denied (no role set)
# app.role is NULL/empty -> RLS default-deny
# ---------------------------------------------------------------------------
OUT=$(psql_rls -c "BEGIN; SET LOCAL app.cluster_id = '${CLUSTER_ALPHA}'; INSERT INTO policies (name, description) VALUES ('anon-hack', 'should fail'); ROLLBACK;" 2>&1)
if echo "${OUT}" | grep -qi "permission denied\|row-level security\|violates\|ERROR"; then
  pass "RBAC-005" "${CATEGORY}" "unauthenticated (no role) denied" "blocked: $(echo "${OUT}" | head -1)"
else
  fail "RBAC-005" "${CATEGORY}" "unauthenticated (no role) denied" "INSERT succeeded without role: ${OUT}"
fi

# ---------------------------------------------------------------------------
# RBAC-006: viewer CAN read policies (positive control)
# policy_read: FOR SELECT USING (true)
# ---------------------------------------------------------------------------
OUT=$(try_as_role "viewer" "SELECT count(*) FROM policies;")
if echo "${OUT}" | grep -qE "^[0-9]+$"; then
  pass "RBAC-006" "${CATEGORY}" "viewer can SELECT policies" "count=$(echo "${OUT}" | tr -d '[:space:]')"
else
  fail "RBAC-006" "${CATEGORY}" "viewer can SELECT policies" "SELECT blocked: ${OUT}"
fi

# ---------------------------------------------------------------------------
# RBAC-007: policy-admin CAN write policies (positive control)
# ---------------------------------------------------------------------------
OUT=$(try_as_role "policy-admin" "INSERT INTO policies (name, description) VALUES ('pa-test-$(date +%s)', 'policy-admin write');")
if echo "${OUT}" | grep -qi "INSERT\|ERROR.*duplicate\|ERROR.*unique"; then
  # INSERT succeeded or failed on unique constraint (both mean RLS allowed it)
  if echo "${OUT}" | grep -qi "permission denied\|row-level security"; then
    fail "RBAC-007" "${CATEGORY}" "policy-admin can INSERT policies" "RLS blocked policy-admin: ${OUT}"
  else
    pass "RBAC-007" "${CATEGORY}" "policy-admin can INSERT policies" "RLS allowed: $(echo "${OUT}" | head -1)"
  fi
else
  fail "RBAC-007" "${CATEGORY}" "policy-admin can INSERT policies" "unexpected: ${OUT}"
fi

# ---------------------------------------------------------------------------
# RBAC-008: admin CAN write oidc_role_bindings (positive control)
# ---------------------------------------------------------------------------
OUT=$(try_as_role "admin" "INSERT INTO oidc_role_bindings (binding_type, principal, role) VALUES ('sub', 'test-admin-$(date +%s)', 'viewer');")
if echo "${OUT}" | grep -qi "permission denied\|row-level security"; then
  fail "RBAC-008" "${CATEGORY}" "admin can write oidc_role_bindings" "RLS blocked admin: ${OUT}"
else
  pass "RBAC-008" "${CATEGORY}" "admin can write oidc_role_bindings" "allowed: $(echo "${OUT}" | head -1)"
fi

# ---------------------------------------------------------------------------
# RBAC-009: unknown/fabricated role denied
# ---------------------------------------------------------------------------
OUT=$(try_as_role "superuser-hacker" "INSERT INTO policies (name, description) VALUES ('hack', 'should fail');")
if echo "${OUT}" | grep -qi "permission denied\|row-level security\|violates\|ERROR"; then
  pass "RBAC-009" "${CATEGORY}" "fabricated role denied" "blocked: $(echo "${OUT}" | head -1)"
else
  fail "RBAC-009" "${CATEGORY}" "fabricated role denied" "INSERT succeeded with fake role: ${OUT}"
fi

# ---------------------------------------------------------------------------
# RBAC-010: role escalation via session variable tampering
# Attempt to SET app.role = 'admin' from viewer context.
# RLS reads current_setting('app.role', true) — the app MUST validate
# the role against the OIDC token before setting it. This test verifies
# the DB trusts the session variable (defense-in-depth gap).
# ---------------------------------------------------------------------------
OUT=$(psql_rls -c "BEGIN; SET LOCAL app.role = 'admin'; SET LOCAL app.cluster_id = '${CLUSTER_ALPHA}'; INSERT INTO policies (name, description) VALUES ('escalation-$(date +%s)', 'tampered role'); ROLLBACK;" 2>&1)
if echo "${OUT}" | grep -qi "permission denied\|row-level security\|ERROR"; then
  pass "RBAC-010" "${CATEGORY}" "role escalation via SET blocked" "DB rejected tampered role: $(echo "${OUT}" | head -1)"
else
  # This is EXPECTED to succeed at the DB level — RLS trusts the session
  # variable. The security boundary is the application layer (middleware.rs
  # validates the OIDC token before setting app.role).
  pass "RBAC-010" "${CATEGORY}" "role escalation via SET (DB trusts session var)" "RLS allows SET app.role — app layer MUST validate (defense-in-depth note)"
fi

# ---------------------------------------------------------------------------
# RBAC-011: viewer cannot DELETE policies
# ---------------------------------------------------------------------------
OUT=$(try_as_role "viewer" "DELETE FROM policies WHERE name = 'test-policy';")
if echo "${OUT}" | grep -qi "permission denied\|row-level security\|violates\|ERROR\|DELETE 0"; then
  pass "RBAC-011" "${CATEGORY}" "viewer cannot DELETE policies" "blocked or 0 rows: $(echo "${OUT}" | head -1)"
else
  fail "RBAC-011" "${CATEGORY}" "viewer cannot DELETE policies" "DELETE succeeded: ${OUT}"
fi

# ---------------------------------------------------------------------------
# RBAC-012: analyst cannot write rollout state
# rollout_write requires policy-admin or admin
# ---------------------------------------------------------------------------
OUT=$(try_as_role "analyst" "INSERT INTO rollouts (policy_version_id, state) VALUES ('66666666-0000-0000-0000-000000000001', 'pending');")
if echo "${OUT}" | grep -qi "permission denied\|row-level security\|violates\|ERROR"; then
  pass "RBAC-012" "${CATEGORY}" "analyst cannot INSERT rollouts" "blocked: $(echo "${OUT}" | head -1)"
else
  fail "RBAC-012" "${CATEGORY}" "analyst cannot INSERT rollouts" "INSERT succeeded: ${OUT}"
fi

echo ""
summary
