#!/usr/bin/env bash
# Live Dex + LDAP + mTLS API assertions.
#
# Run this on the host through SSH forwards to the VM:
#   ssh -L 5556:127.0.0.1:5556 -L 8081:127.0.0.1:8081 ...
#   scripts/oidc/api-tests.sh
#
# It needs curl, jq, and the test CA at target/oidc/certs/ca.crt. Tokens are
# never written to disk.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CA="${CA:-$root/target/oidc/certs/ca.crt}"
DEX_ISSUER="${DEX_ISSUER:-http://127.0.0.1:8081/dex}"
API="${API_BASE:-http://127.0.0.1:8081/api/v1}"
CLIENT_ID="${CLIENT_ID:-ebpf-dashboard}"
WRONG_CLIENT_ID="${WRONG_CLIENT_ID:-wrong-audience}"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok: $*"; }

wait_for() {
  local url="$1" extra="${2:-}"
  for _ in $(seq 1 60); do
    # shellcheck disable=SC2086
    if curl -fsS --cacert "$CA" $extra "$url" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  fail "timed out waiting for $url"
}

http_status() {
  curl -sS -o /dev/null -w '%{http_code}' --cacert "$CA" "$@"
}

token() {
  local user="$1" password="$2" client="$3"
  local body
  body=$(curl -fsS --cacert "$CA" -X POST "$DEX_ISSUER/token" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=password' \
    --data-urlencode "username=$user" \
    --data-urlencode "password=$password" \
    --data-urlencode "client_id=$client" \
    --data-urlencode 'scope=openid groups email profile')
  local access
  access=$(printf '%s' "$body" | jq -er '.access_token')
  [[ -n "$access" ]] || fail "no access token for $user"
  printf '%s' "$access"
}

groups_for() {
  local tok="$1" payload
  payload=$(printf '%s' "$tok" | cut -d. -f2 | tr '_-' '/+')
  case $(( ${#payload} % 4 )) in
    2) payload="$payload==" ;;
    3) payload="$payload=" ;;
  esac
  printf '%s' "$payload" | base64 -d 2>/dev/null
}

wait_for "$DEX_ISSUER/.well-known/openid-configuration"
for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:8081/healthz >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS http://127.0.0.1:8081/readyz >/dev/null || fail "control plane not ready"
pass "control plane ready"

admin=$(token alice alice-password "$CLIENT_ID")
viewer=$(token vera vera-password "$CLIENT_ID")
nobody=$(token mallory mallory-password "$CLIENT_ID")
wrong_aud=$(token alice alice-password "$WRONG_CLIENT_ID")

groups_for "$admin" | jq -e '.groups | index("ebpf-admins")' >/dev/null \
  || fail "admin token has no ebpf-admins group"
pass "admin access token carries the LDAP group"

[[ "$(http_status -H "Authorization: Bearer $admin" "$API/events")" == 200 ]] \
  || fail "admin GET /events"
[[ "$(http_status -H "Authorization: Bearer $viewer" "$API/events")" == 200 ]] \
  || fail "viewer GET /events"
pass "viewer can read events"

CONTENT=$'schema_version: 1\nengine_version: "1.0.0"\nrules: []\n'
STAGE=$(jq -n --arg content "$CONTENT" '{version: 1, content: $content, name: "default"}')
[[ "$(http_status -X POST -H "Authorization: Bearer $admin" -H 'Content-Type: application/json' -d "$STAGE" "$API/policies/stage")" == 200 ]] \
  || fail "admin stage"
[[ "$(http_status -X POST -H "Authorization: Bearer $admin" -H 'Content-Type: application/json' -d '{"version":1}' "$API/policies/commit")" == 200 ]] \
  || fail "admin commit"
pass "admin staged and committed a policy"

[[ "$(http_status -X POST -H "Authorization: Bearer $viewer" -H 'Content-Type: application/json' -d "$STAGE" "$API/policies/stage")" == 403 ]] \
  || fail "viewer stage should be 403"
pass "viewer gets 403 on policy staging"

[[ "$(http_status -H "Authorization: Bearer $wrong_aud" "$API/events")" == 401 ]] \
  || fail "wrong audience should be 401"
pass "wrong audience is rejected"

[[ "$(http_status -H "Authorization: Bearer $nobody" "$API/events")" == 401 ]] \
  || fail "token without a fleet group should be 401"
pass "token without a fleet group is rejected"

agents=$(curl -fsS --cacert "$CA" -H "Authorization: Bearer $admin" "$API/agents")
printf '%s' "$agents" | jq -e '.agents[] | select(.spiffe_id == "spiffe://example.org/ebpf-agent/node-1")' >/dev/null \
  || fail "agent did not register with the expected SPIFFE SAN"
pass "agent registered with its per-node SPIFFE identity"

audit=$(curl -fsS --cacert "$CA" -H "Authorization: Bearer $admin" "$API/audit")
printf '%s' "$audit" | jq -e '.audit[] | select(.action == "policy.stage")' >/dev/null \
  || fail "audit row for policy.stage missing"
pass "audit rows are visible to the admin"

echo "all live OIDC/RBAC/mTLS assertions passed"
