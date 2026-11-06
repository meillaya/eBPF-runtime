#!/usr/bin/env bash
# Run the live OIDC harness from the host after the VM ports are forwarded.
#
# Required forwards (from the VM):
#   8081 -> 127.0.0.1:8081   (Caddy: dashboard, API, Dex)
# The control plane and Dex run in the rootful VM. This script only drives
# the host-side checks; it does not start or stop the compose stack.

set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

[[ -f target/oidc/certs/ca.crt ]] || scripts/gen-test-certs.sh

echo "waiting for the OIDC proxy on 127.0.0.1:8081"
for _ in $(seq 1 120); do
  if curl -fsS http://127.0.0.1:8081/healthz >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS http://127.0.0.1:8081/healthz >/dev/null || {
  echo "start the OIDC profile in the VM first; see docs/runbooks/oidc-dex-ldap.md" >&2
  exit 1
}

scripts/oidc/api-tests.sh

cd web
EBPF_WEB_URL="${EBPF_WEB_URL:-http://127.0.0.1:8081}" \
EBPF_DEX_ISSUER="${EBPF_DEX_ISSUER:-http://127.0.0.1:8081/dex}" \
EBPF_API_BASE="${EBPF_API_BASE:-http://127.0.0.1:8081/api/v1}" \
bunx playwright test
