#!/usr/bin/env bash
# scripts/proto-breaking.sh — kernel-v1 (eBPF Runtime Security & Observability)
#
# proto:breaking task body. Task 6 of the approved Prometheus plan.
#
# Compares the current `proto/` against the checked-in
# tests/fixtures/proto/baseline.v1.binpb snapshot. Exit 0 means
# the v1 contract has not changed; exit non-zero means a later
# change attempted a breaking field deletion / reuse / type change.
#
# Exit codes:
#   0  no breaking change against the v1 baseline
#   1  buf breaking reported a change
#   2  baseline file missing
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

set -euo pipefail
LC_ALL=C
export LC_ALL

PROG="${0##*/}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

BASELINE="${REPO_ROOT}/tests/fixtures/proto/baseline.v1.binpb"
if [[ ! -f "${BASELINE}" ]]; then
    echo "${PROG}: baseline missing: ${BASELINE}" >&2
    exit 2
fi

if ! command -v buf >/dev/null 2>&1; then
    echo "${PROG}: buf not on PATH" >&2
    exit 2
fi

# `buf breaking` exits non-zero on a breaking change. We want the
# script to exit non-zero in that case too, so the CI aggregator
# surfaces the regression. The "current vs baseline" semantics is:
# baseline = the v1.0.0 snapshot; current = whatever is on disk.
buf breaking --against "${BASELINE}"
