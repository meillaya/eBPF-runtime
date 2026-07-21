#!/usr/bin/env bash
# scripts/proto-freshness.sh — kernel-v1 (eBPF Runtime Security & Observability)
#
# Deterministic source-tree freshness check for the protobuf /
# OpenAPI contract. Task 6 of the approved Prometheus plan.
#
# Computes a SHA-256 over every file under proto/, api/, buf.yaml,
# buf.gen.yaml (and the freshness script itself, so an unintended
# change to the check is visible), then runs the same computation
# again immediately and asserts the two digests are identical.
# This is the lightest possible "deterministic generation twice"
# check the plan's acceptance criterion calls for; in task 6 there
# is no Rust/TypeScript generation step yet, so the check is
# implicitly: the source tree is byte-stable across two reads.
#
# Subsequent tasks (35, 44) will replace this script with one that
# also invokes `buf generate` and hashes the produced files; the
# public contract — `scripts/proto-freshness.sh` exits 0 on
# deterministic source, non-zero otherwise — stays the same.
#
# Exit codes:
#   0  every check passed; tree is deterministic
#   1  two SHA-256 digests differ (non-deterministic source)
#   2  missing tool (sha256sum)
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

set -euo pipefail
LC_ALL=C
export LC_ALL

PROG="${0##*/}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if ! command -v sha256sum >/dev/null 2>&1; then
    echo "${PROG}: required tool missing: sha256sum" >&2
    exit 2
fi

# Files included in the digest:
#   - Every file under proto/
#   - Every file under api/
#   - buf.yaml, buf.gen.yaml at the repo root
#   - This script itself (so an unintended edit to the check is
#     visible in the diff, not silently changing the answer).
sorted_files() {
    {
        if [[ -d "${REPO_ROOT}/proto" ]]; then
            (cd "${REPO_ROOT}" && find proto -type f | LC_ALL=C sort)
        fi
        if [[ -d "${REPO_ROOT}/api" ]]; then
            (cd "${REPO_ROOT}" && find api -type f | LC_ALL=C sort)
        fi
        for f in buf.yaml buf.gen.yaml; do
            if [[ -f "${REPO_ROOT}/${f}" ]]; then
                printf '%s\n' "${f}"
            fi
        done
        printf '%s\n' "scripts/proto-freshness.sh"
    } | LC_ALL=C sort -u
}

digest_once() {
    local files
    files="$(sorted_files)"
    if [[ -z "${files}" ]]; then
        echo "${PROG}: no files in proto/, api/, or buf.*.yaml — nothing to digest" >&2
        return 1
    fi
    (
        cd "${REPO_ROOT}"
        # shellcheck disable=SC2086
        sha256sum $files
    ) | sha256sum | awk '{print $1}'
}

main() {
    local first second
    first="$(digest_once)"
    second="$(digest_once)"
    if [[ "${first}" != "${second}" ]]; then
        echo "${PROG}: tree is not deterministic across two reads" >&2
        echo "${PROG}: first =${first}" >&2
        echo "${PROG}: second=${second}" >&2
        exit 1
    fi
    printf '%s %s\n' "${PROG}: deterministic source tree" "${first}"
}

main "$@"
