#!/usr/bin/env bash
# scripts/proto-check.sh — kernel-v1 (eBPF Runtime Security & Observability)
#
# proto:check task body. Task 6 of the approved Prometheus plan.
#
# Runs, in order:
#   1. buf lint proto              — must exit 0
#   2. scripts/proto-freshness.sh  — must exit 0 (deterministic source)
#   3. scripts/proto-roundtrip.py  — must exit 0 (every EventKind
#      oneof variant encodes/decodes through the Python protobuf
#      runtime; byte-for-byte equivalence is asserted)
#   4. openapi-spec-validator api/openapi.yaml
#                                  — must exit 0. When the validator
#      is not on PATH, fall back to a stdlib-only structural check
#      that asserts the top-level keys (openapi, info, paths,
#      components, security) are all present.
#
# Exit codes:
#   0  every check passed
#   1  one or more checks failed
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

set -euo pipefail
LC_ALL=C
export LC_ALL

PROG="${0##*/}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

PYTHONPATH="${PYTHONPATH:-}"
PROTOBUF_PYTHONPATH="/nix/store/sgrxc7nrkgd01afizzzcpp2yz561rr2f-python3.13-protobuf-7.34.1/lib/python3.13/site-packages"
if [[ -d "${PROTOBUF_PYTHONPATH}" ]]; then
    PYTHONPATH="${PROTOBUF_PYTHONPATH}:${PYTHONPATH}"
    export PYTHONPATH
fi

log() { printf '[%s] %s\n' "${PROG}" "$*"; }
fail() { printf '[%s] FAIL: %s\n' "${PROG}" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. buf lint
# ---------------------------------------------------------------------------
log "buf lint proto"
if ! command -v buf >/dev/null 2>&1; then
    fail "buf is not on PATH; enter the devenv shell or run via 'devenv tasks run proto:check'"
fi
if ! buf lint proto; then
    fail "buf lint proto failed"
fi
log "buf lint proto OK"

# ---------------------------------------------------------------------------
# 2. freshness
# ---------------------------------------------------------------------------
log "scripts/proto-freshness.sh"
if ! bash "${SCRIPT_DIR}/proto-freshness.sh"; then
    fail "proto-freshness.sh failed"
fi

# ---------------------------------------------------------------------------
# 3. Python round-trip
# ---------------------------------------------------------------------------
log "scripts/proto-roundtrip.py"
if ! python3 "${SCRIPT_DIR}/proto-roundtrip.py"; then
    fail "proto-roundtrip.py failed"
fi

# ---------------------------------------------------------------------------
# 4. OpenAPI validation
# ---------------------------------------------------------------------------
log "api/openapi.yaml"
if ! command -v uvx >/dev/null 2>&1; then
    fail "uvx is not on PATH; install uv and rerun, or run via 'devenv tasks run proto:check'"
fi
if ! uvx --quiet openapi-spec-validator api/openapi.yaml; then
    fail "openapi-spec-validator rejected api/openapi.yaml"
fi
log "openapi-spec-validator OK"

log "proto:check PASS"
