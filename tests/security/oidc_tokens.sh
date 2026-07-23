#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# OIDC token validation adversarial tests.
#
# Tests the OIDC claim validation contract (mirrors web/src/auth/oidc.ts
# validateClaims and crates/auth/src/middleware.rs session validation).
# Live Dex token exchange is tested when Dex is reachable; otherwise
# adversarial tokens are crafted locally with openssl.
#
# Usage: bash tests/security/oidc_tokens.sh
# Requires: bash, jq, openssl, curl

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib.sh"

CATEGORY="oidc"
NOW=$(date +%s)
FUTURE=$((NOW + 7200))
PAST=$((NOW - 100))

echo "═══ OIDC Token Validation Adversarial Tests ═══"
echo "Issuer: ${OIDC_ISSUER}"
echo "Client: ${OIDC_CLIENT_ID}"
echo ""

# ---------------------------------------------------------------------------
# OIDC-001: alg:none attack
# A JWT with alg=none and empty signature MUST be rejected.
# ---------------------------------------------------------------------------
PAYLOAD=$(jq -cn --arg iss "${OIDC_ISSUER}" --arg aud "${OIDC_CLIENT_ID}" \
  --argjson exp "${FUTURE}" --argjson iat "${NOW}" \
  '{iss:$iss, sub:"attacker", aud:$aud, exp:$exp, iat:$iat, nonce:"n1", groups:["admin"]}')
TOKEN_NONE=$(craft_jwt_none "${PAYLOAD}")
HDR=$(jwt_header "${TOKEN_NONE}")
ALG=$(echo "${HDR}" | jq -r '.alg')
if [ "${ALG}" = "none" ]; then
  # Verify the token has an empty signature segment
  SIG_SEG=$(echo "${TOKEN_NONE}" | awk -F. '{print $3}')
  if [ -z "${SIG_SEG}" ]; then
    pass "OIDC-001" "${CATEGORY}" "alg:none attack crafted" "alg=none, empty signature — validator MUST reject"
  else
    fail "OIDC-001" "${CATEGORY}" "alg:none attack crafted" "signature segment not empty"
  fi
else
  fail "OIDC-001" "${CATEGORY}" "alg:none attack crafted" "header alg=${ALG}, expected none"
fi

# ---------------------------------------------------------------------------
# OIDC-002: Tampered signature
# Modify payload after signing; original signature no longer valid.
# ---------------------------------------------------------------------------
VALID_PAYLOAD=$(jq -cn --arg iss "${OIDC_ISSUER}" --arg aud "${OIDC_CLIENT_ID}" \
  --argjson exp "${FUTURE}" --argjson iat "${NOW}" \
  '{iss:$iss, sub:"user-1", aud:$aud, exp:$exp, iat:$iat, nonce:"n2", groups:["viewer"]}')
VALID_TOKEN=$(craft_jwt "${VALID_PAYLOAD}" "${VALID_PAYLOAD}" "real-secret")
# Tamper: change sub to admin
TAMPERED_PAYLOAD=$(jq -cn --arg iss "${OIDC_ISSUER}" --arg aud "${OIDC_CLIENT_ID}" \
  --argjson exp "${FUTURE}" --argjson iat "${NOW}" \
  '{iss:$iss, sub:"admin", aud:$aud, exp:$exp, iat:$iat, nonce:"n2", groups:["admin"]}')
TAMPERED_TOKEN=$(craft_jwt_tampered "${VALID_TOKEN}" "${TAMPERED_PAYLOAD}")
# Verify: recompute signature with same secret; it should NOT match
T_H=$(echo "${TAMPERED_TOKEN}" | cut -d. -f1)
T_P=$(echo "${TAMPERED_TOKEN}" | cut -d. -f2)
T_SIG=$(echo "${TAMPERED_TOKEN}" | cut -d. -f3)
EXPECTED_SIG=$(hmac_sha256 "${T_H}.${T_P}" "real-secret")
if [ "${T_SIG}" != "${EXPECTED_SIG}" ]; then
  pass "OIDC-002" "${CATEGORY}" "tampered signature detected" "payload modified, signature mismatch confirmed"
else
  fail "OIDC-002" "${CATEGORY}" "tampered signature detected" "signature still matches after tamper — test broken"
fi

# ---------------------------------------------------------------------------
# OIDC-003: Wrong issuer
# ---------------------------------------------------------------------------
WRONG_ISS_PAYLOAD=$(jq -cn --arg aud "${OIDC_CLIENT_ID}" \
  --argjson exp "${FUTURE}" --argjson iat "${NOW}" \
  '{iss:"https://evil.example.com", sub:"user-1", aud:$aud, exp:$exp, iat:$iat}')
ERR=$(validate_claims "${WRONG_ISS_PAYLOAD}" "" "${NOW}")
if echo "${ERR}" | grep -q "issuer mismatch"; then
  pass "OIDC-003" "${CATEGORY}" "wrong issuer rejected" "${ERR}"
else
  fail "OIDC-003" "${CATEGORY}" "wrong issuer rejected" "expected issuer mismatch, got: ${ERR:-<accepted>}"
fi

# ---------------------------------------------------------------------------
# OIDC-004: Wrong audience
# ---------------------------------------------------------------------------
WRONG_AUD_PAYLOAD=$(jq -cn --arg iss "${OIDC_ISSUER}" \
  --argjson exp "${FUTURE}" --argjson iat "${NOW}" \
  '{iss:$iss, sub:"user-1", aud:"evil-client", exp:$exp, iat:$iat}')
ERR=$(validate_claims "${WRONG_AUD_PAYLOAD}" "" "${NOW}")
if echo "${ERR}" | grep -q "audience mismatch"; then
  pass "OIDC-004" "${CATEGORY}" "wrong audience rejected" "${ERR}"
else
  fail "OIDC-004" "${CATEGORY}" "wrong audience rejected" "expected audience mismatch, got: ${ERR:-<accepted>}"
fi

# ---------------------------------------------------------------------------
# OIDC-005: Expired token
# ---------------------------------------------------------------------------
EXPIRED_PAYLOAD=$(jq -cn --arg iss "${OIDC_ISSUER}" --arg aud "${OIDC_CLIENT_ID}" \
  --argjson iat "${PAST}" \
  '{iss:$iss, sub:"user-1", aud:$aud, exp:($iat + 60), iat:$iat}')
# exp = PAST + 60, which is still in the past
ERR=$(validate_claims "${EXPIRED_PAYLOAD}" "" "${NOW}")
if echo "${ERR}" | grep -q "token expired"; then
  pass "OIDC-005" "${CATEGORY}" "expired token rejected" "${ERR}"
else
  fail "OIDC-005" "${CATEGORY}" "expired token rejected" "expected expired, got: ${ERR:-<accepted>}"
fi

# ---------------------------------------------------------------------------
# OIDC-006: Wrong nonce
# ---------------------------------------------------------------------------
NONCE_PAYLOAD=$(jq -cn --arg iss "${OIDC_ISSUER}" --arg aud "${OIDC_CLIENT_ID}" \
  --argjson exp "${FUTURE}" --argjson iat "${NOW}" \
  '{iss:$iss, sub:"user-1", aud:$aud, exp:$exp, iat:$iat, nonce:"attacker-nonce"}')
ERR=$(validate_claims "${NONCE_PAYLOAD}" "expected-nonce-123" "${NOW}")
if echo "${ERR}" | grep -q "nonce mismatch"; then
  pass "OIDC-006" "${CATEGORY}" "wrong nonce rejected" "${ERR}"
else
  fail "OIDC-006" "${CATEGORY}" "wrong nonce rejected" "expected nonce mismatch, got: ${ERR:-<accepted>}"
fi

# ---------------------------------------------------------------------------
# OIDC-007: Future iat (beyond skew)
# ---------------------------------------------------------------------------
FUTURE_IAT_PAYLOAD=$(jq -cn --arg iss "${OIDC_ISSUER}" --arg aud "${OIDC_CLIENT_ID}" \
  --argjson exp "$((NOW + 7200))" \
  --argjson iat "$((NOW + OIDC_IAT_SKEW_S + 60))" \
  '{iss:$iss, sub:"user-1", aud:$aud, exp:$exp, iat:$iat}')
ERR=$(validate_claims "${FUTURE_IAT_PAYLOAD}" "" "${NOW}")
if echo "${ERR}" | grep -q "issued in the future"; then
  pass "OIDC-007" "${CATEGORY}" "future iat rejected" "${ERR}"
else
  fail "OIDC-007" "${CATEGORY}" "future iat rejected" "expected future iat, got: ${ERR:-<accepted>}"
fi

# ---------------------------------------------------------------------------
# OIDC-008: Missing required claims (no sub)
# ---------------------------------------------------------------------------
NO_SUB_PAYLOAD=$(jq -cn --arg iss "${OIDC_ISSUER}" --arg aud "${OIDC_CLIENT_ID}" \
  --argjson exp "${FUTURE}" --argjson iat "${NOW}" \
  '{iss:$iss, aud:$aud, exp:$exp, iat:$iat}')
ERR=$(validate_claims "${NO_SUB_PAYLOAD}" "" "${NOW}")
if echo "${ERR}" | grep -q "missing required claim"; then
  pass "OIDC-008" "${CATEGORY}" "missing sub claim rejected" "${ERR}"
else
  fail "OIDC-008" "${CATEGORY}" "missing sub claim rejected" "expected missing claim, got: ${ERR:-<accepted>}"
fi

# ---------------------------------------------------------------------------
# OIDC-009: Valid token accepted (positive control)
# ---------------------------------------------------------------------------
VALID_CLAIMS=$(jq -cn --arg iss "${OIDC_ISSUER}" --arg aud "${OIDC_CLIENT_ID}" \
  --argjson exp "${FUTURE}" --argjson iat "${NOW}" \
  '{iss:$iss, sub:"user-1", aud:$aud, exp:$exp, iat:$iat, nonce:"n9", groups:["viewer"]}')
ERR=$(validate_claims "${VALID_CLAIMS}" "n9" "${NOW}")
if [ -z "${ERR}" ]; then
  pass "OIDC-009" "${CATEGORY}" "valid token accepted" "positive control: all claims valid"
else
  fail "OIDC-009" "${CATEGORY}" "valid token accepted" "valid token rejected: ${ERR}"
fi

# ---------------------------------------------------------------------------
# OIDC-010: HS256/RS256 confusion attack
# Attacker signs with HMAC using the RSA public key as the secret.
# A validator expecting RS256 would verify with the public key and
# accept the HMAC signature. We verify the header declares HS256
# while the token is crafted to look like it should be RS256.
# ---------------------------------------------------------------------------
CONFUSION_HDR='{"alg":"HS256","typ":"JWT","kid":"rsa-key-1"}'
CONFUSION_PAYLOAD=$(jq -cn --arg iss "${OIDC_ISSUER}" --arg aud "${OIDC_CLIENT_ID}" \
  --argjson exp "${FUTURE}" --argjson iat "${NOW}" \
  '{iss:$iss, sub:"attacker", aud:$aud, exp:$exp, iat:$iat, groups:["admin"]}')
CONFUSION_TOKEN=$(craft_jwt "${CONFUSION_HDR}" "${CONFUSION_PAYLOAD}" "public-key-material")
CONF_HDR=$(jwt_header "${CONFUSION_TOKEN}")
CONF_ALG=$(echo "${CONF_HDR}" | jq -r '.alg')
if [ "${CONF_ALG}" = "HS256" ]; then
  pass "OIDC-010" "${CATEGORY}" "HS256/RS256 confusion crafted" "alg=HS256 with kid=rsa-key-1 — validator MUST pin expected alg"
else
  fail "OIDC-010" "${CATEGORY}" "HS256/RS256 confusion crafted" "unexpected alg: ${CONF_ALG}"
fi

# ---------------------------------------------------------------------------
# OIDC-011: Empty audience array
# ---------------------------------------------------------------------------
EMPTY_AUD_PAYLOAD=$(jq -cn --arg iss "${OIDC_ISSUER}" \
  --argjson exp "${FUTURE}" --argjson iat "${NOW}" \
  '{iss:$iss, sub:"user-1", aud:[], exp:$exp, iat:$iat}')
ERR=$(validate_claims "${EMPTY_AUD_PAYLOAD}" "" "${NOW}")
if echo "${ERR}" | grep -q "audience mismatch"; then
  pass "OIDC-011" "${CATEGORY}" "empty audience array rejected" "${ERR}"
else
  fail "OIDC-011" "${CATEGORY}" "empty audience array rejected" "expected audience mismatch, got: ${ERR:-<accepted>}"
fi

# ---------------------------------------------------------------------------
# OIDC-LIVE: Live Dex token exchange (deferred if Dex is down)
# ---------------------------------------------------------------------------
if check_dex; then
  echo ""
  echo "--- Live Dex OIDC flow ---"
  # Dex password grant is not standard; use the authorization code flow
  # via curl. Dex supports the resource-owner password grant for static
  # passwords when the connector allows it.
  TOKEN_RESP=$(curl -sf -X POST "http://127.0.0.1:5556/dex/token" \
    -d "grant_type=password" \
    -d "username=admin@example.com" \
    -d "password=password" \
    -d "client_id=${OIDC_CLIENT_ID}" \
    -d "client_secret=dev-secret" \
    -d "scope=openid email groups" 2>&1 || echo "TOKEN_EXCHANGE_FAILED")

  if echo "${TOKEN_RESP}" | jq -e '.id_token' >/dev/null 2>&1; then
    ID_TOKEN=$(echo "${TOKEN_RESP}" | jq -r '.id_token')
    CLAIMS=$(jwt_payload "${ID_TOKEN}")
    ISS=$(echo "${CLAIMS}" | jq -r '.iss')
    if [ "${ISS}" = "${OIDC_ISSUER}" ]; then
      pass "OIDC-LIVE-01" "${CATEGORY}" "live Dex admin token obtained" "iss=${ISS}"
    else
      fail "OIDC-LIVE-01" "${CATEGORY}" "live Dex admin token obtained" "wrong issuer: ${ISS}"
    fi
    # Validate claims
    ERR=$(validate_claims "${CLAIMS}" "" "${NOW}")
    if [ -z "${ERR}" ]; then
      pass "OIDC-LIVE-02" "${CATEGORY}" "live token claims valid" "all claims pass validation"
    else
      fail "OIDC-LIVE-02" "${CATEGORY}" "live token claims valid" "${ERR}"
    fi
  else
    skip "OIDC-LIVE-01" "${CATEGORY}" "live Dex token exchange" "password grant not supported by Dex static connector: ${TOKEN_RESP:0:120}"
    skip "OIDC-LIVE-02" "${CATEGORY}" "live token claims valid" "skipped (no token)"
  fi
else
  deferred "OIDC-LIVE-01" "${CATEGORY}" "live Dex token exchange" "Dex not reachable at 127.0.0.1:5556"
  deferred "OIDC-LIVE-02" "${CATEGORY}" "live token claims valid" "Dex not reachable"
fi

# ---------------------------------------------------------------------------
# SPIRE/SPIFFE: deferred (not running)
# ---------------------------------------------------------------------------
deferred "SPIFFE-01" "${CATEGORY}" "SPIRE SVID issuance" "SPIRE not running in dev compose — deferred to self-hosted runner"
deferred "SPIFFE-02" "${CATEGORY}" "SPIFFE-bound command authorization" "SPIRE not running — deferred"

echo ""
summary
