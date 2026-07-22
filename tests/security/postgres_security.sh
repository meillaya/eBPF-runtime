#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# PostgreSQL security adversarial tests.
#
# Tests RLS enforcement, audit immutability, role separation, and SQL
# injection resistance against the live PostgreSQL instance.
#
# CRITICAL FINDING: The compose stack creates control_app as SUPERUSER,
# which bypasses ALL RLS regardless of migration 0007's NOBYPASSRLS.
# RLS tests use control_app_rls_test (non-superuser, NOBYPASSRLS).
#
# Usage: bash tests/security/postgres_security.sh
# Requires: bash, jq, podman (or PSQL_CMD override)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib.sh"

CATEGORY="postgres"

echo "═══ PostgreSQL Security Adversarial Tests ═══"
echo ""

# ---------------------------------------------------------------------------
# PG-001: CRITICAL — control_app superuser finding
# Migration 0007 intends control_app as NON-superuser with NOBYPASSRLS.
# The compose stack creates it as SUPERUSER, which bypasses ALL RLS.
# ---------------------------------------------------------------------------
OUT=$(psql_app -c "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'control_app';")
APP_IS_SUPER=$(echo "${OUT}" | awk -F'|' '{print $1}' | tr -d '[:space:]')
APP_IS_BYPASS=$(echo "${OUT}" | awk -F'|' '{print $2}' | tr -d '[:space:]')
if [ "${APP_IS_SUPER}" = "t" ]; then
  fail "PG-001" "${CATEGORY}" "control_app is SUPERUSER (CRITICAL)" "rolsuper=t — RLS completely bypassed; migration 0007 intends non-superuser"
else
  pass "PG-001" "${CATEGORY}" "control_app is not superuser" "rolsuper=${APP_IS_SUPER}, rolbypassrls=${APP_IS_BYPASS}"
fi

# ---------------------------------------------------------------------------
# PG-002: control_app_rls_test has NOBYPASSRLS
# ---------------------------------------------------------------------------
OUT=$(psql_app -c "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'control_app_rls_test';")
IS_SUPER=$(echo "${OUT}" | awk -F'|' '{print $1}' | tr -d '[:space:]')
IS_BYPASS=$(echo "${OUT}" | awk -F'|' '{print $2}' | tr -d '[:space:]')
if [ "${IS_SUPER}" = "f" ] && [ "${IS_BYPASS}" = "f" ]; then
  pass "PG-002" "${CATEGORY}" "RLS test role: NOBYPASSRLS confirmed" "rolsuper=f, rolbypassrls=f"
else
  fail "PG-002" "${CATEGORY}" "RLS test role: NOBYPASSRLS confirmed" "rolsuper=${IS_SUPER}, rolbypassrls=${IS_BYPASS}"
fi

# ---------------------------------------------------------------------------
# PG-003: RLS cluster isolation — cannot see other cluster's nodes
# Set app.cluster_id = alpha; should NOT see beta's nodes.
# ---------------------------------------------------------------------------
OUT=$(psql_rls -c "BEGIN; SET LOCAL app.cluster_id = '${CLUSTER_ALPHA}'; SET LOCAL app.role = 'admin'; SELECT hostname FROM nodes; ROLLBACK;" 2>&1)
if echo "${OUT}" | grep -q "node-alpha-1" && ! echo "${OUT}" | grep -q "node-beta-1"; then
  pass "PG-003" "${CATEGORY}" "RLS cluster isolation: alpha sees only alpha nodes" "visible: $(echo "${OUT}" | grep node | tr '\n' ' ')"
else
  fail "PG-003" "${CATEGORY}" "RLS cluster isolation: alpha sees only alpha nodes" "leak detected: ${OUT}"
fi

# ---------------------------------------------------------------------------
# PG-004: RLS cross-cluster INSERT blocked
# Try to INSERT a node into cluster-beta while scoped to cluster-alpha.
# ---------------------------------------------------------------------------
OUT=$(psql_rls -c "BEGIN; SET LOCAL app.cluster_id = '${CLUSTER_ALPHA}'; SET LOCAL app.role = 'admin'; INSERT INTO nodes (id, cluster_id, hostname) VALUES ('99999999-0000-0000-0000-000000000099', '${CLUSTER_BETA}', 'cross-cluster-hack'); ROLLBACK;" 2>&1)
if echo "${OUT}" | grep -qi "row-level security\|violates\|ERROR\|permission denied"; then
  pass "PG-004" "${CATEGORY}" "RLS cross-cluster INSERT blocked" "WITH CHECK enforced: $(echo "${OUT}" | head -1)"
else
  fail "PG-004" "${CATEGORY}" "RLS cross-cluster INSERT blocked" "cross-cluster INSERT succeeded: ${OUT}"
fi

# ---------------------------------------------------------------------------
# PG-005: RLS cross-cluster UPDATE blocked
# Try to UPDATE beta's node while scoped to alpha.
# ---------------------------------------------------------------------------
OUT=$(psql_rls -c "BEGIN; SET LOCAL app.cluster_id = '${CLUSTER_ALPHA}'; SET LOCAL app.role = 'admin'; UPDATE nodes SET hostname = 'hacked' WHERE cluster_id = '${CLUSTER_BETA}'; ROLLBACK;" 2>&1)
# UPDATE 0 means RLS filtered the row (no visible rows)
if echo "${OUT}" | grep -qE "UPDATE 0|ERROR|permission denied|row-level security"; then
  pass "PG-005" "${CATEGORY}" "RLS cross-cluster UPDATE blocked" "0 rows affected or error: $(echo "${OUT}" | head -1)"
else
  fail "PG-005" "${CATEGORY}" "RLS cross-cluster UPDATE blocked" "UPDATE succeeded on other cluster: ${OUT}"
fi

# ---------------------------------------------------------------------------
# PG-006: Audit log INSERT allowed (append-only positive)
# ---------------------------------------------------------------------------
OUT=$(psql_rls -c "BEGIN; SET LOCAL app.role = 'admin'; INSERT INTO audit_log (seq, actor, action, resource) VALUES (nextval('audit_log_seq'), 'sec-test', 'test.insert', '/security/test'); ROLLBACK;" 2>&1)
if echo "${OUT}" | grep -qi "INSERT\|ERROR.*duplicate\|ERROR.*unique"; then
  if echo "${OUT}" | grep -qi "permission denied\|row-level security"; then
    fail "PG-006" "${CATEGORY}" "audit_log INSERT allowed" "RLS blocked INSERT: ${OUT}"
  else
    pass "PG-006" "${CATEGORY}" "audit_log INSERT allowed" "append works: $(echo "${OUT}" | head -1)"
  fi
else
  fail "PG-006" "${CATEGORY}" "audit_log INSERT allowed" "unexpected: ${OUT}"
fi

# ---------------------------------------------------------------------------
# PG-007: Audit log UPDATE denied (immutability)
# No UPDATE policy exists + control_app_rls_test has no UPDATE privilege.
# ---------------------------------------------------------------------------
OUT=$(psql_rls -c "BEGIN; SET LOCAL app.role = 'admin'; UPDATE audit_log SET actor = 'tampered' WHERE actor = 'admin@example.com'; ROLLBACK;" 2>&1)
if echo "${OUT}" | grep -qi "permission denied\|row-level security\|ERROR\|UPDATE 0"; then
  pass "PG-007" "${CATEGORY}" "audit_log UPDATE denied (immutable)" "blocked: $(echo "${OUT}" | head -1)"
else
  fail "PG-007" "${CATEGORY}" "audit_log UPDATE denied (immutable)" "UPDATE succeeded — audit tampered: ${OUT}"
fi

# ---------------------------------------------------------------------------
# PG-008: Audit log DELETE denied (immutability)
# No DELETE policy exists + no DELETE privilege granted.
# ---------------------------------------------------------------------------
OUT=$(psql_rls -c "BEGIN; SET LOCAL app.role = 'admin'; DELETE FROM audit_log WHERE actor = 'admin@example.com'; ROLLBACK;" 2>&1)
if echo "${OUT}" | grep -qi "permission denied\|row-level security\|ERROR\|DELETE 0"; then
  pass "PG-008" "${CATEGORY}" "audit_log DELETE denied (immutable)" "blocked: $(echo "${OUT}" | head -1)"
else
  fail "PG-008" "${CATEGORY}" "audit_log DELETE denied (immutable)" "DELETE succeeded — audit destroyed: ${OUT}"
fi

# ---------------------------------------------------------------------------
# PG-009: SQL injection in app.cluster_id setting
# Attempt to inject SQL via the cluster_id session variable.
# ---------------------------------------------------------------------------
OUT=$(psql_rls -c "BEGIN; SET LOCAL app.cluster_id = '${CLUSTER_ALPHA}''; DROP TABLE policies; --'; SET LOCAL app.role = 'admin'; SELECT count(*) FROM policies; ROLLBACK;" 2>&1)
# The table should still exist
CHECK=$(psql_app -c "SELECT count(*) FROM policies;" 2>&1)
if echo "${CHECK}" | grep -qE "^[0-9]+$"; then
  pass "PG-009" "${CATEGORY}" "SQL injection in cluster_id neutralized" "policies table intact, count=$(echo "${CHECK}" | tr -d '[:space:]')"
else
  fail "PG-009" "${CATEGORY}" "SQL injection in cluster_id neutralized" "table may be damaged: ${CHECK}"
fi

# ---------------------------------------------------------------------------
# PG-010: SQL injection in app.role setting
# ---------------------------------------------------------------------------
OUT=$(psql_rls -c "BEGIN; SET LOCAL app.role = 'admin''; DROP TABLE audit_log; --'; SELECT count(*) FROM policies; ROLLBACK;" 2>&1)
CHECK=$(psql_app -c "SELECT count(*) FROM audit_log;" 2>&1)
if echo "${CHECK}" | grep -qE "^[0-9]+$"; then
  pass "PG-010" "${CATEGORY}" "SQL injection in app.role neutralized" "audit_log table intact, count=$(echo "${CHECK}" | tr -d '[:space:]')"
else
  fail "PG-010" "${CATEGORY}" "SQL injection in app.role neutralized" "table may be damaged: ${CHECK}"
fi

# ---------------------------------------------------------------------------
# PG-011: control_audit role cannot UPDATE state tables
# control_audit has SELECT-only + INSERT on audit_log.
# ---------------------------------------------------------------------------
OUT=$(psql_audit -c "UPDATE policies SET description = 'hacked' WHERE name = 'test-policy';" 2>&1)
if echo "${OUT}" | grep -qi "permission denied\|ERROR"; then
  pass "PG-011" "${CATEGORY}" "control_audit cannot UPDATE policies" "blocked: $(echo "${OUT}" | head -1)"
else
  fail "PG-011" "${CATEGORY}" "control_audit cannot UPDATE policies" "UPDATE succeeded: ${OUT}"
fi

# ---------------------------------------------------------------------------
# PG-012: control_audit role cannot DELETE
# ---------------------------------------------------------------------------
OUT=$(psql_audit -c "DELETE FROM policies WHERE name = 'test-policy';" 2>&1)
if echo "${OUT}" | grep -qi "permission denied\|ERROR"; then
  pass "PG-012" "${CATEGORY}" "control_audit cannot DELETE policies" "blocked: $(echo "${OUT}" | head -1)"
else
  fail "PG-012" "${CATEGORY}" "control_audit cannot DELETE policies" "DELETE succeeded: ${OUT}"
fi

# ---------------------------------------------------------------------------
# PG-013: OIDC tables admin-only (viewer cannot read oidc_role_bindings)
# oidc_admin policy: USING (app.role = 'admin')
# ---------------------------------------------------------------------------
OUT=$(psql_rls -c "BEGIN; SET LOCAL app.role = 'viewer'; SET LOCAL app.cluster_id = '${CLUSTER_ALPHA}'; SELECT count(*) FROM oidc_role_bindings; ROLLBACK;" 2>&1)
# Should return 0 (RLS filters all rows) or error
COUNT=$(echo "${OUT}" | grep -oE "^[0-9]+" | head -1)
if [ "${COUNT}" = "0" ] || echo "${OUT}" | grep -qi "ERROR\|permission denied"; then
  pass "PG-013" "${CATEGORY}" "viewer cannot read oidc_role_bindings" "RLS filtered: count=${COUNT:-0}"
else
  fail "PG-013" "${CATEGORY}" "viewer cannot read oidc_role_bindings" "viewer saw ${COUNT} rows: ${OUT}"
fi

# ---------------------------------------------------------------------------
# PG-014: RLS policy count matches schema anchor
# ---------------------------------------------------------------------------
POLICY_COUNT=$(psql_app -c "SELECT count(*) FROM pg_policies;" 2>&1 | tr -d '[:space:]')
EXPECTED_COUNT=$(jq -r '.properties.rls_policy_count.default' "${SCHEMA}")
if [ "${POLICY_COUNT}" = "${EXPECTED_COUNT}" ]; then
  pass "PG-014" "${CATEGORY}" "RLS policy count matches schema" "count=${POLICY_COUNT} (expected ${EXPECTED_COUNT})"
else
  fail "PG-014" "${CATEGORY}" "RLS policy count matches schema" "count=${POLICY_COUNT}, expected ${EXPECTED_COUNT}"
fi

# ---------------------------------------------------------------------------
# PG-015: No cluster scope = no data visible (RLS default-deny)
# Without SET app.cluster_id, current_setting returns NULL -> no rows match.
# ---------------------------------------------------------------------------
OUT=$(psql_rls -c "BEGIN; SET LOCAL app.role = 'admin'; SELECT count(*) FROM nodes; ROLLBACK;" 2>&1)
COUNT=$(echo "${OUT}" | grep -oE "^[0-9]+" | head -1)
if [ "${COUNT}" = "0" ] || echo "${OUT}" | grep -qi "ERROR"; then
  pass "PG-015" "${CATEGORY}" "no cluster scope = no data (default-deny)" "count=${COUNT:-0}"
else
  fail "PG-015" "${CATEGORY}" "no cluster scope = no data (default-deny)" "saw ${COUNT} rows without cluster scope: ${OUT}"
fi

# ---------------------------------------------------------------------------
# PG-016: control_app (superuser) bypasses RLS — demonstrates the finding
# ---------------------------------------------------------------------------
OUT=$(psql_app -c "SELECT count(*) FROM nodes;" 2>&1)
COUNT=$(echo "${OUT}" | grep -oE "^[0-9]+" | head -1)
if [ "${APP_IS_SUPER:-}" = "t" ] && [ "${COUNT:-0}" -gt 0 ] 2>/dev/null; then
  fail "PG-016" "${CATEGORY}" "control_app superuser bypasses RLS (CRITICAL)" "sees ALL ${COUNT} nodes without SET app.cluster_id — RLS ineffective for this role"
else
  pass "PG-016" "${CATEGORY}" "control_app RLS behavior" "count=${COUNT:-0} (superuser=${APP_IS_SUPER:-unknown})"
fi

echo ""
summary
