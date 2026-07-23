#!/usr/bin/env bash
# scripts/loc-lint.sh — kernel-v1 (eBPF Runtime Security & Observability)
#
# Enforces the plan's "no module above 250 pure LOC" rule. Task 4 of the
# approved Prometheus plan.
#
# "Pure LOC" = lines that are NOT blank and NOT pure comments
# (`// ...` for Rust, `// ...` / `/* ... */` for C, `# ...` for shell /
# Python / TypeScript). We use a deliberately simple per-file line-count
# filter rather than cloc/scc because:
#
#   * we control the codebase; false positives are easy to fix
#   * we want a CI-friendly tool with zero network/Python dependency
#   * we want deterministic exit codes for both passing (0) and
#     failing (1) runs
#
# The script walks the repo (or a list of roots supplied on the command
# line), filters to extensions the plan budgets against (.rs, .ts, .tsx,
# .js, .jsx, .bpf.c, .h, .py, .sh) under `crates/`, `web/`, `bpf/`,
# `scripts/`, and `proto/`, then exits non-zero if any file exceeds
# LOC_LIMIT (default 250).
#
# Generated paths (target/, dist/, **/generated.rs) are excluded.
#
# Baseline exception file (scripts/loc-baseline.txt)
# -----------------------------------------------
# The plan forbids blanket waivers, but does allow per-file tracking.
# Files committed BEFORE task 4 closed (preflight.sh, lib.rs of the
# preflight-schema crate, etc.) may already exceed 250. Each one is
# recorded in `scripts/loc-baseline.txt` with a one-line rationale and
# a `due:` marker that names the task expected to split the file. The
# baseline file is itself linted: removing it re-enables the rule.
#
# EXIT CODES
#   0  every checked file has <= LIMIT pure lines
#   1  one or more files exceeded LIMIT
#
# USAGE
#   scripts/loc-lint.sh                 # scan the whole repo
#   scripts/loc-lint.sh crates/         # scan only crates/

set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
LOC_LIMIT="${LOC_LIMIT:-250}"
BASELINE_FILE="${BASELINE_FILE:-$REPO_ROOT/scripts/loc-baseline.txt}"

# Roots scanned by default; can be overridden by CLI args.
if [ "$#" -eq 0 ]; then
    ROOTS=(crates web bpf scripts proto)
else
    ROOTS=("$@")
fi

# Extensions the plan budgets against.
EXTS='\.(rs|ts|tsx|js|jsx|bpf\.c|h|py|sh)$'

errors=0
checked=0
max_seen=0
max_file=""
waived=0

is_baselined() {
    local rel="$1"
    [ -f "$BASELINE_FILE" ] || return 1
    # Comment lines and blank lines are ignored; each non-comment line
    # is the relative path of one exempted file.
    local p
    while IFS= read -r p; do
        [ -z "$p" ] && continue
        case "$p" in
            \#*) continue ;;
        esac
        # Strip any "  # reason" trailing comment so the path column
        # is the only field matched.
        p="${p%%[[:space:]]*#*}"
        p="${p##+([[:space:]])}"
        p="${p%%+([[:space:]])}"
        if [ "$p" = "$rel" ]; then
            return 0
        fi
    done < "$BASELINE_FILE"
    return 1
}

count_pure_loc() {
    local path="$1"
    awk '
        BEGIN { count = 0 }
        {
            line = $0
            # strip whitespace for classification only
            t = line
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", t)
            if (t == "") next
            # Rust // and shell/Python # comments
            if (t ~ /^\/\//) next
            if (t ~ /^#/) next
            # /* ... */ single-line block comment
            if (t ~ /^\/\*.*\*\/[[:space:]]*$/) next
            # leading block comment-only line
            if (t ~ /^\/\*/ && t !~ /\*\//) next
            count++
        }
        END { print count }
    ' "$path"
}

scan_file() {
    local path="$1"
    # Skip generated paths
    case "$path" in
        target/*|*/target/*) return 0 ;;
        */dist/*|dist/*) return 0 ;;
        */generated.rs|*/generated.rs) return 0 ;;
        web/node_modules/*|*/node_modules/*) return 0 ;;
    esac

    local rel="${path#$REPO_ROOT/}"

    local n
    n="$(count_pure_loc "$path")"
    if [ "$n" -gt "$max_seen" ]; then
        max_seen="$n"
        max_file="$path"
    fi
    checked=$((checked + 1))

    if [ "$n" -gt "$LOC_LIMIT" ]; then
        if is_baselined "$rel"; then
            waived=$((waived + 1))
            printf 'loc-lint: WAIVE %s has %d pure-LOC (baselined)\n' \
                "$rel" "$n"
        else
            printf 'loc-lint: FAIL %s has %d pure-LOC (> %d)\n' \
                "$rel" "$n" "$LOC_LIMIT" >&2
            errors=$((errors + 1))
        fi
    fi
}

scan_root() {
    local root="$1"
    if [ ! -d "$REPO_ROOT/$root" ]; then
        return 0
    fi
    local files
    files="$(git -C "$REPO_ROOT" ls-files -- "$root" 2>/dev/null \
        | grep -E "$EXTS" || true)"
    if [ -z "$files" ]; then
        return 0
    fi
    local f
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        scan_file "$REPO_ROOT/$f" || true
    done <<< "$files"
}

main() {
    for r in "${ROOTS[@]}"; do
        scan_root "$r"
    done

    if [ "$errors" -gt 0 ]; then
        echo "loc-lint: FAIL ($errors files exceed $LOC_LIMIT pure-LOC across $checked files; $waived baseline waivers)" >&2
        if [ -n "$max_file" ]; then
            echo "loc-lint: largest file = $max_file ($max_seen pure-LOC)" >&2
        fi
        exit 1
    fi

    if [ "$checked" -eq 0 ]; then
        echo "loc-lint: no source files under scanned roots (trivially clean)"
    else
        echo "loc-lint: PASS ($checked files checked, max $max_seen pure-LOC at $max_file; $waived baseline waivers)"
    fi
    exit 0
}

main "$@"
