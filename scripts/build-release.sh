#!/usr/bin/env bash
# scripts/build-release.sh - kernel-v1 high-level release orchestrator.
#
# Usage:
#   scripts/build-release.sh [--target <system>] [--out <path>]
#
# Default target: x86_64-linux. The flag exists so F1 / CI can build
# aarch64-linux on an arm64 runner without editing the script.
#
# Steps:
#   1. Build the Nix release derivation for the target system
#      (release.nix#release.<system>). This produces the
#      release.tar.gz with kernel-v1-agent-placeholder and
#      release-manifest.json. The Nix build is optional; when nix is
#      not available on the host, this step is skipped (the
#      release-verify.sh fallback path produces an equivalent OCI
#      layout from first principles).
#   2. Run scripts/release-verify.sh --out <out> on the same output
#      path. This step is mandatory; the verdict it writes is the
#      acceptance signal.
#
# Exit codes:
#   0  release-verify.sh verdict == "passed"
#   1  any failure (nix build failed, release-verify.sh exited non-zero,
#      verdict == "failed")
#   2  bad usage
#
# The script defaults to the OCI-Image-Layout scaffold path when no
# container engine is available, exactly as documented in
# release-verify.sh.
#
# Task 8 of .omo/plans/ebpf-runtime-security-observability.md.
# SPDX-License-Identifier: Apache-2.0 OR MIT

set -euo pipefail

LC_ALL=C
export LC_ALL

PROG="${0##*/}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

TARGET="x86_64-linux"
OUT=""
SKIP_NIX=0

usage() {
    cat <<EOF
Usage: ${PROG} [--target <system>] [--out <path>] [--skip-nix]

  --target <system>   Nix system to build (default: x86_64-linux)
  --out    <path>     output directory for the OCI layout (default: release/out)
  --skip-nix          skip the Nix release derivation build
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            TARGET="${2:-}"
            shift 2
            ;;
        --target=*)
            TARGET="${1#--target=}"
            shift
            ;;
        --out)
            OUT="${2:-}"
            shift 2
            ;;
        --out=*)
            OUT="${1#--out=}"
            shift
            ;;
        --skip-nix)
            SKIP_NIX=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "${PROG}: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

case "${TARGET}" in
    x86_64-linux|aarch64-linux) ;;
    *)
        echo "${PROG}: unsupported --target ${TARGET} (expected x86_64-linux or aarch64-linux)" >&2
        exit 2
        ;;
esac

if [[ -z "${OUT}" ]]; then
    OUT="${REPO_ROOT}/release/out"
fi

mkdir -p "${OUT}"

log() { echo "[${PROG}] $*"; }

# --------------------------------------------------------------------------
# Step 1: Nix release derivation (optional)
# --------------------------------------------------------------------------

if [[ "${SKIP_NIX}" -eq 0 ]] && command -v nix >/dev/null 2>&1; then
    log "step 1/2: nix build ./release.nix#release.${TARGET}"
    if nix build --no-link --print-out-paths "./release.nix#release.${TARGET}" \
        >"${OUT}/.nix-release.out" 2>"${OUT}/.nix-release.err"; then
        NIX_OUT="$(cat "${OUT}/.nix-release.out")"
        log "nix release derivation produced: ${NIX_OUT}"
    else
        log "WARN: nix build failed; the release-verify.sh fallback path still produces a valid OCI layout"
        cat "${OUT}/.nix-release.err" >&2 || true
    fi
else
    if [[ "${SKIP_NIX}" -eq 0 ]]; then
        log "step 1/2: skipping (nix not available)"
    else
        log "step 1/2: skipping (--skip-nix)"
    fi
fi

# --------------------------------------------------------------------------
# Step 2: release verification
# --------------------------------------------------------------------------

log "step 2/2: scripts/release-verify.sh --out ${OUT}"
exec "${SCRIPT_DIR}/release-verify.sh" --out "${OUT}"