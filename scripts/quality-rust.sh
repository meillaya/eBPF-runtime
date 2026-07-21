#!/usr/bin/env bash
# scripts/quality-rust.sh — kernel-v1 (eBPF Runtime Security & Observability)
#
# Driver for `devenv tasks run quality:rust`. The task body in
# `devenv.nix` shells out to this script so the same checks can run
# standalone (`bash scripts/quality-rust.sh`) without a devenv shell.
#
# Order matters: fmt must run first so clippy doesn't flag formatting
# drift as a lint warning. deny runs before nextest so the supply-chain
# gate can short-circuit on a vulnerable advisory before the test
# suite spends cycles. The LOC lint runs last because clippy can
# rewrite code (it doesn't here, but the ordering is defensive).
#
# EXIT CODES
#   0  every step passed
#   1  one or more steps failed
#
# USAGE
#   bash scripts/quality-rust.sh

set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
cd "$REPO_ROOT"

echo "[quality:rust] cargo fmt --all -- --check"
cargo fmt --all -- --check

echo "[quality:rust] cargo clippy --workspace --all-targets --all-features -- -D warnings"
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "[quality:rust] cargo deny check"
cargo deny check

echo "[quality:rust] cargo nextest run --workspace"
cargo nextest run --workspace || {
    rc=$?
    echo "[quality:rust] cargo nextest failed (rc=$rc); falling back to cargo test"
    cargo test --workspace
}

echo "[quality:rust] scripts/loc-lint.sh"
bash "$REPO_ROOT/scripts/loc-lint.sh"

echo "[quality:rust] PASS"
