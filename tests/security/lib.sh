#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Shared test harness for adversarial security integration tests.
# Source this file; do not execute directly.
#
# Provides: evidence recording, JWT crafting, psql wrapper, assertions.
# All constants are read from bench/schemas/security.v1.json (the single
# source of truth).

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths & config
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCHEMA="${REPO_ROOT}/bench/schemas/security.v1.json"
EVIDENCE_DIR="${REPO_ROOT}/.omo/evidence"
EVIDENCE_FILE="${EVIDENCE_FILE:-${EVIDENCE_DIR}/security-$(date -u +%Y%m%dT%H%M%SZ).jsonl}"
mkdir -p "${EVIDENCE_DIR}"

# psql access: override PSQL_CMD for environments with native psql.
# Default: podman exec into the k1-postgres container.
PSQL_CMD="${PSQL_CMD:-podman exec -i k1-postgres psql}"
PG_USER="${PG_USER:-control_app}"
PG_DB="${PG_DB:-kernel_v1}"
RLS_TEST_USER="${RLS_TEST_USER:-control_app_rls_test}"
RLS_TEST_PASS="${RLS_TEST_PASS:-rls-test-dev-only}"

# OIDC constants from schema
OIDC_ISSUER="$(jq -r '.properties.oidc_issuer.default' "${SCHEMA}")"
OIDC_CLIENT_ID="$(jq -r '.properties.oidc_client_id.default' "${SCHEMA}")"
OIDC_EXPIRY_S="$(jq -r '.properties.oidc_token_expiry_s.default' "${SCHEMA}")"
OIDC_IAT_SKEW_S="$(jq -r '.properties.oidc_iat_skew_s.default' "${SCHEMA}")"

# Test cluster IDs from schema
CLUSTER_ALPHA="$(jq -r '.properties.test_cluster_ids.properties.alpha.default' "${SCHEMA}")"
CLUSTER_BETA="$(jq -r '.properties.test_cluster_ids.properties.beta.default' "${SCHEMA}")"

# Counters
_PASS=0; _FAIL=0; _SKIP=0; _DEFERRED=0; _TOTAL=0

# ---------------------------------------------------------------------------
# Evidence recording
# ---------------------------------------------------------------------------
_now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

_record() {
  local test_id="$1" category="$2" name="$3" result="$4" detail="$5"
  _TOTAL=$((_TOTAL + 1))
  case "${result}" in
    PASS)     _PASS=$((_PASS + 1)) ;;
    FAIL)     _FAIL=$((_FAIL + 1)) ;;
    SKIP)     _SKIP=$((_SKIP + 1)) ;;
    DEFERRED) _DEFERRED=$((_DEFERRED + 1)) ;;
  esac
  local line
  line=$(jq -cn \
    --arg tid "${test_id}" \
    --arg cat "${category}" \
    --arg name "${name}" \
    --arg result "${result}" \
    --arg detail "${detail}" \
    --arg ts "$(_now_iso)" \
    '{test_id:$tid, category:$cat, name:$name, result:$result, detail:$detail, timestamp:$ts}')
  echo "${line}" >> "${EVIDENCE_FILE}"
  # Human-readable output
  local color="\033[0m"
  case "${result}" in
    PASS)     color="\033[32m" ;;
    FAIL)     color="\033[31m" ;;
    SKIP)     color="\033[33m" ;;
    DEFERRED) color="\033[36m" ;;
  esac
  printf "${color}[%-8s]${color} %s  %s — %s\n" "${result}" "${test_id}" "${name}" "${detail}"
}

pass()     { _record "$1" "$2" "$3" "PASS"     "${4:-}"; }
fail()     { _record "$1" "$2" "$3" "FAIL"     "${4:-}"; }
skip()     { _record "$1" "$2" "$3" "SKIP"     "${4:-}"; }
deferred() { _record "$1" "$2" "$3" "DEFERRED" "${4:-}"; }

summary() {
  echo ""
  echo "═══════════════════════════════════════════════════════"
  echo "  SECURITY TEST SUMMARY"
  echo "  Total: ${_TOTAL}  Pass: ${_PASS}  Fail: ${_FAIL}  Skip: ${_SKIP}  Deferred: ${_DEFERRED}"
  echo "  Evidence: ${EVIDENCE_FILE}"
  echo "═══════════════════════════════════════════════════════"
  [ "${_FAIL}" -eq 0 ]
}

# ---------------------------------------------------------------------------
# PostgreSQL helpers
# ---------------------------------------------------------------------------

# Run SQL as control_app (superuser in compose — see PG-009 finding).
# NOTE: || true prevents set -e from killing the script on expected SQL errors.
psql_app() {
  ${PSQL_CMD} -U "${PG_USER}" -d "${PG_DB}" -t -A "$@" 2>&1 || true
}

# Run SQL as the non-superuser RLS test role.
psql_rls() {
  PGPASSWORD="${RLS_TEST_PASS}" ${PSQL_CMD} -U "${RLS_TEST_USER}" -d "${PG_DB}" -t -A "$@" 2>&1 || true
}

# Run SQL as control_audit (read-only role).
psql_audit() {
  PGPASSWORD="control_audit_dev_only" ${PSQL_CMD} -U control_audit -d "${PG_DB}" -t -A "$@" 2>&1 || true
}

# ---------------------------------------------------------------------------
# JWT crafting (bash + openssl, no external JWT library)
# ---------------------------------------------------------------------------

# Base64url encode (no padding).
b64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

# Base64url decode.
b64url_dec() {
  local input="$1"
  # Restore padding
  local mod=$(( ${#input} % 4 ))
  if [ "${mod}" -eq 2 ]; then input="${input}=="
  elif [ "${mod}" -eq 3 ]; then input="${input}="
  fi
  echo -n "${input}" | tr '_-' '/+' | openssl base64 -d -A 2>/dev/null || echo ""
}

# HMAC-SHA256 sign.
hmac_sha256() {
  local data="$1" secret="$2"
  echo -n "${data}" | openssl dgst -sha256 -hmac "${secret}" -binary | b64url
}

# Craft a JWT with explicit header, payload, and signing secret.
# Usage: craft_jwt '{"alg":"HS256","typ":"JWT"}' '{"sub":"x"}' "secret"
# Returns: header.payload.signature
craft_jwt() {
  local header_json="$1" payload_json="$2" secret="${3:-test-secret}"
  local h p sig
  h=$(echo -n "${header_json}" | b64url)
  p=$(echo -n "${payload_json}" | b64url)
  sig=$(hmac_sha256 "${h}.${p}" "${secret}")
  echo "${h}.${p}.${sig}"
}

# Craft a JWT with alg:none (no signature).
craft_jwt_none() {
  local payload_json="$1"
  local h p
  h=$(echo -n '{"alg":"none","typ":"JWT"}' | b64url)
  p=$(echo -n "${payload_json}" | b64url)
  echo "${h}.${p}."
}

# Craft a JWT with a tampered payload (signature from original).
craft_jwt_tampered() {
  local original_jwt="$1" new_payload_json="$2"
  local h p_old sig
  h=$(echo "${original_jwt}" | cut -d. -f1)
  sig=$(echo "${original_jwt}" | cut -d. -f3)
  p_old=$(echo -n "${new_payload_json}" | b64url)
  echo "${h}.${p_old}.${sig}"
}

# Decode JWT payload (segment 2) as JSON.
jwt_payload() {
  local jwt="$1"
  local payload
  payload=$(echo "${jwt}" | cut -d. -f2)
  b64url_dec "${payload}"
}

# Decode JWT header (segment 1) as JSON.
jwt_header() {
  local jwt="$1"
  local header
  header=$(echo "${jwt}" | cut -d. -f1)
  b64url_dec "${header}"
}

# ---------------------------------------------------------------------------
# Claim validation (mirrors web/src/auth/oidc.ts validateClaims)
# Returns error string or empty on success.
# ---------------------------------------------------------------------------
validate_claims() {
  local claims_json="$1" expected_nonce="${2:-}" now_epoch="${3:-$(date +%s)}"
  local iss aud exp iat nonce

  iss=$(echo "${claims_json}" | jq -r '.iss // empty')
  aud=$(echo "${claims_json}" | jq -r 'if .aud | type == "array" then .aud | join(",") else .aud // empty end')
  exp=$(echo "${claims_json}" | jq -r '.exp // 0')
  iat=$(echo "${claims_json}" | jq -r '.iat // 0')
  nonce=$(echo "${claims_json}" | jq -r '.nonce // empty')

  # Check required claims
  for claim in iss sub aud exp iat; do
    local val
    val=$(echo "${claims_json}" | jq -r ".${claim} // empty")
    if [ -z "${val}" ]; then
      echo "missing required claim: ${claim}"
      return 0
    fi
  done

  if [ "${iss}" != "${OIDC_ISSUER}" ]; then
    echo "issuer mismatch (${iss})"
    return 0
  fi

  if ! echo ",${aud}," | grep -q ",${OIDC_CLIENT_ID},"; then
    echo "audience mismatch (${aud})"
    return 0
  fi

  if [ "${now_epoch}" -ge "${exp}" ]; then
    echo "token expired"
    return 0
  fi

  local max_iat=$((now_epoch + OIDC_IAT_SKEW_S))
  if [ "${iat}" -gt "${max_iat}" ]; then
    echo "token issued in the future"
    return 0
  fi

  if [ -n "${expected_nonce}" ] && [ "${nonce}" != "${expected_nonce}" ]; then
    echo "nonce mismatch"
    return 0
  fi

  echo ""
}

# ---------------------------------------------------------------------------
# Infrastructure checks
# ---------------------------------------------------------------------------
check_pg() {
  local result
  result=$(psql_app -c "SELECT 1;" 2>&1)
  if echo "${result}" | grep -q "1"; then
    return 0
  fi
  return 1
}

check_dex() {
  local code
  code=$(curl -sf -o /dev/null -w '%{http_code}' "http://127.0.0.1:5556/dex/.well-known/openid-configuration" 2>/dev/null || echo "000")
  [ "${code}" = "200" ]
}
