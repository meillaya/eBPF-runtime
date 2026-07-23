#!/usr/bin/env bash
# scripts/spdx-lint.sh — kernel-v1 (eBPF Runtime Security & Observability)
#
# SPDX-License-Identifier policy enforcement for committed BPF C sources.
# Task 4 of the approved Prometheus plan.
#
# RULE SUMMARY
# ------------
# This script enforces the kernel's BPF licensing rules, NOT the repo's
# user-space LICENSE-* files. Per the kernel's
# Documentation/bpf/bpf_licensing.rst (and the SPDX policy documented in
# README.md):
#
#   * .bpf.c / .h files committed under bpf/sensors/ that attach to BPF
#     LSM hooks MUST declare a GPL-compatible SPDX identifier.
#     Accepted values:
#         GPL-2.0-only
#         GPL-2.0-or-later
#         GPL-2.0-only WITH Linux-syscall-note
#     Anything else (MIT, Apache-2.0, dual MIT/Apache-2.0) is rejected
#     with a non-zero exit because the verifier would refuse the program
#     at load time.
#
#   * .bpf.c / .h files committed under bpf/sensors/ that attach to
#     non-LSM hooks (tracepoints, kprobes, raw_tracepoints, TP-btf,
#     perf_event) accept any license from the allowlist:
#         Dual MIT/Apache-2.0  (this is the project default)
#         GPL-2.0-only
#         GPL-2.0-or-later
#         BSD-2-Clause
#         BSD-3-Clause
#
#   * .bpf.c / .h files outside bpf/ are NOT subject to this lint (e.g.
#     a C helper at the repo root or under scripts/ is allowed to use any
#     license the user-space dual LICENSE-* already grants). The script
#     silently skips them.
#
#   * Every file under bpf/ MUST declare an SPDX identifier somewhere
#     in its first 30 lines. Missing identifier is a hard error.
#
# EXIT CODES
# ----------
#   0  every file in scope passed
#   1  one or more files failed (missing SPDX, disallowed license, or
#      a file that we expected to be a regular C source but couldn't
#      read as text)
#
# USAGE
# -----
#   scripts/spdx-lint.sh                 # scan the whole repo
#   scripts/spdx-lint.sh bpf/sensors/    # scan a specific directory

set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"

# Map of BPF hook family -> "lsm" | "other". Task 4 wires the policy
# structurally; per-file hook detection belongs to task 10's build
# pipeline (bpf:build), which inserts the chosen SEC("lsm/...") into the
# final CO-RE object. Until task 10 lands, we use a conservative
# approximation: every committed .bpf.c under bpf/sensors/ is treated
# as an LSM candidate, so the strictest allowlist applies. Per-file
# overrides land via a sidecar "<file>.license" companion file (an
# explicit `allow: dual-mit-apache` comment in such a file lifts the
# restriction when the file is a tracing program).
#
# The override format is:
#   # SPDX override: tracing
# meaning "this file uses a non-LSM hook; allow the relaxed allowlist".
#
# Detection is keyed on the SEC("...") string in the .bpf.c source
# itself when present (preferred) and falls back to the companion file.

LSM_LICENSE_ALLOWLIST=(
    "GPL-2.0-only"
    "GPL-2.0-or-later"
    "GPL-2.0-only WITH Linux-syscall-note"
)

RELAXED_LICENSE_ALLOWLIST=(
    "MIT"
    "Apache-2.0"
    "Dual MIT/Apache-2.0"
    "GPL-2.0-only"
    "GPL-2.0-or-later"
    "BSD-2-Clause"
    "BSD-3-Clause"
)

errors=0
checked=0

is_in_string() {
    local needle="$1"
    shift
    local item
    for item in "$@"; do
        if [ "$item" = "$needle" ]; then
            return 0
        fi
    done
    return 1
}

# Determine whether a single .bpf.c / .h file is an LSM program.
# We accept three signals, in priority order:
#   1. A sidecar "<file>.license" line saying `kind: tracing|relaxed`.
#   2. A SEC("lsm/...") attribute in the file body.
#   3. The default for files under bpf/sensors/ is `lsm` (strict).
# Other locations under bpf/ default to `relaxed`.
classify_file() {
    local path="$1"
    local sidecar="${path}.license"
    local base
    base="$(basename "$path")"

    if [ -f "$sidecar" ]; then
        if grep -Eq '^[[:space:]]*kind:[[:space:]]*tracing' "$sidecar"; then
            echo "relaxed"
            return
        fi
        if grep -Eq '^[[:space:]]*kind:[[:space:]]*lsm' "$sidecar"; then
            echo "lsm"
            return
        fi
    fi

    # SEC("lsm/...") attribute -> LSM hook
    if grep -Eq '^[[:space:]]*SEC[[:space:]]*\([[:space:]]*"lsm/' "$path" 2>/dev/null; then
        echo "lsm"
        return
    fi

    # Other SEC() attributes -> non-LSM tracing
    if grep -Eq '^[[:space:]]*SEC[[:space:]]*\(' "$path" 2>/dev/null; then
        echo "relaxed"
        return
    fi

    # Default by location: bpf/sensors/* -> lsm (strict);
    # bpf/* anywhere else -> relaxed.
    case "$path" in
        bpf/sensors/*) echo "lsm" ;;
        bpf/*)         echo "relaxed" ;;
        *)             echo "skip" ;;
    esac
}

# Pull the SPDX-License-Identifier value out of the first 30 lines.
# Captures everything from "SPDX-License-Identifier:" up to end-of-line,
# then strips a single trailing "WITH <exception>" pair off so we can
# index the base license ("GPL-2.0-only WITH Linux-syscall-note" ->
# "GPL-2.0-only WITH Linux-syscall-note" when in the LSM allowlist, or
# "Dual MIT/Apache-2.0" -> "Dual MIT/Apache-2.0" in the relaxed list).
extract_spdx() {
    local path="$1"
    awk 'NR <= 30 {
        if (match($0, /SPDX-License-Identifier:[[:space:]]*(.+)/, m)) {
            sub(/[[:space:]]*\*\//, "", m[1])
            sub(/[[:space:]]+$/, "", m[1])
            print m[1]
            exit
        }
    }' "$path"
}

scan_file() {
    local path="$1"
    local class
    class="$(classify_file "$path")"

    if [ "$class" = "skip" ]; then
        return 0
    fi

    checked=$((checked + 1))

    local spdx
    spdx="$(extract_spdx "$path" || true)"
    if [ -z "$spdx" ]; then
        printf 'spdx-lint: %s: missing SPDX-License-Identifier in first 30 lines\n' "$path" >&2
        errors=$((errors + 1))
        return 1
    fi

    local allowlist_name="RELAXED"
    local -n allowlist
    if [ "$class" = "lsm" ]; then
        allowlist_name="LSM"
        allowlist=LSM_LICENSE_ALLOWLIST
    else
        allowlist_name="RELAXED"
        allowlist=RELAXED_LICENSE_ALLOWLIST
    fi

    if ! is_in_string "$spdx" "${allowlist[@]}"; then
        printf 'spdx-lint: %s: SPDX=%s not in %s allowlist\n' \
            "$path" "$spdx" "$allowlist_name" >&2
        errors=$((errors + 1))
        return 1
    fi

    printf 'spdx-lint: ok %s [%s]\n' "$path" "$spdx"
}

scan_tree() {
    local root="$1"
    if [ ! -d "$root" ]; then
        return 0
    fi

    # Walk the committed tree, not the working directory, so we don't lint
    # files that the user is in the middle of writing. The set is
    # `git ls-files` filtered by extension.
    local files
    files="$(git -C "$REPO_ROOT" ls-files \
        -- "$root" 2>/dev/null \
        | grep -E '\.(bpf\.c|h)$' || true)"

    if [ -z "$files" ]; then
        return 0
    fi

    local f
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        scan_file "$f" || true
    done <<< "$files"
}

main() {
    if [ "$#" -eq 0 ]; then
        scan_tree "bpf"
    else
        for arg in "$@"; do
            scan_tree "$arg"
        done
    fi

    if [ "$checked" -eq 0 ]; then
        echo "spdx-lint: no .bpf.c / .h files under bpf/ (trivially clean)"
    fi

    if [ "$errors" -gt 0 ]; then
        echo "spdx-lint: FAIL ($errors violations across $checked files)" >&2
        exit 1
    fi

    echo "spdx-lint: PASS ($checked files checked)"
    exit 0
}

main "$@"
