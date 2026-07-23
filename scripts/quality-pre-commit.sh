#!/usr/bin/env bash
# scripts/quality-pre-commit.sh — kernel-v1 (eBPF Runtime Security & Observability)
#
# Pre-commit hook driver. Mirrors `.pre-commit-config.yaml` and is also
# wired through `devenv.git-hooks.hooks.pre-commit` (task 4).
#
# The hook runs the same gates as `devenv tasks run quality:rust` plus
# SPDX, but is intentionally narrower than the full `quality:all`
# aggregate: pre-commit only checks slices that can complete inside the
# commit-time budget (a few seconds). The CI lane is the source of
# truth for the full gate; pre-commit is the developer-loop guardrail.
#
# Pass criteria: every command exits 0. The hook fails the commit on
# any non-zero exit; `git commit --no-verify` skips it (not recommended
# except for emergency hotfixes that must be reverted immediately).

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

echo "[pre-commit] cargo fmt --all -- --check"
cargo fmt --all -- --check

echo "[pre-commit] cargo clippy --workspace --all-targets --all-features -- -D warnings"
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "[pre-commit] scripts/spdx-lint.sh"
bash scripts/spdx-lint.sh

echo "[pre-commit] scripts/loc-lint.sh"
bash scripts/loc-lint.sh

echo "[pre-commit] PASS"
