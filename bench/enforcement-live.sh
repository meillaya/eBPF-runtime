#!/usr/bin/env bash
# bench/enforcement-live.sh — privileged live BPF LSM enforcement harness
# (task 54).
#
# Loads bpf/sensors/lsm.bpf.c in a privileged Docker container (host
# kernel, BPF LSM enabled), attaches all three hooks via bpftool, and
# drives the REAL decision engine through audit / deny / kill-switch /
# fail-open / prior-LSM-preservation scenarios (bench/enforcement-
# live.c), consuming real lsm_events ring-buffer decision events. This
# is the privileged half that bench/enforcement-audit.sh (task 33) and
# bench/enforcement-state-machine.sh (task 34) reported BLOCKED on an
# unprivileged host.
#
# The production object is loaded first; if the kernel verifier
# rejects it (task-54 finding: the deny_errno clamp needs a lower
# bound on kernels enforcing LSM return values in [-4095, 0]), a
# minimally-clamped copy is loaded instead so the decision logic is
# still exercised live. The production source is never modified.
#
# The container is throwaway (--rm); the BPF programs attach to the
# HOST kernel and are pinned under /sys/fs/bpf/lsm_test (bind-mounted
# bpffs). SAFETY: the deny selector is a unique /tmp/deny-test-* dentry
# name no host workload opens; only the file_open family is ever armed;
# the harness zeroes the policy map on exit and this script ALWAYS
# unpins /sys/fs/bpf/lsm_test on the way out (trap), so no enforcement
# state outlives the run.
#
# Usage:
#   bench/enforcement-live.sh
#
# Output:
#   .omo/evidence/task-54-live-output.json — harness JSON (scenarios)
#   stdout — full container log (build/load/verify/run/cleanup)
#
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PIN_DIR=/sys/fs/bpf/lsm_test
TESTFILE=/tmp/deny-test-t54
# Fedora 41 ships clang 19 — the toolchain the repo pins for BPF builds
# (devenv.nix: llvmPackages_19.clang). Verifier-friendly codegen matters
# here: newer clangs can push the same source past the verifier's
# complexity limit.
IMAGE=fedora:41
OUT_JSON="${WORKSPACE_ROOT}/.omo/evidence/task-54-live-output.json"

mkdir -p "${WORKSPACE_ROOT}/.omo/evidence"

# ---- in-container script ---------------------------------------------------
INNER="$(mktemp /tmp/enforcement-live-inner.XXXXXX.sh)"
cleanup_inner() { rm -f "$INNER"; }
trap cleanup_inner EXIT

cat > "$INNER" <<'INNER_EOF'
#!/usr/bin/env bash
set -euo pipefail

PIN_DIR=/sys/fs/bpf/lsm_test
TESTFILE=/tmp/deny-test-t54

echo "=== [0/7] environment ==="
echo "kernel: $(uname -r)"
# securityfs may not be mounted in a fresh container sysfs: mount it.
if [[ ! -e /sys/kernel/security/lsm ]]; then
  mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true
fi
echo "lsm:    $(cat /sys/kernel/security/lsm)"
if ! grep -q bpf /sys/kernel/security/lsm; then
  echo "BLOCKED: BPF LSM not enabled on host kernel" >&2
  exit 3
fi

echo "=== [1/7] packages ==="
dnf install -y -q clang llvm libbpf-devel bpftool gcc diffutils >/dev/null 2>&1
# sed (not head) consumes all input: head + pipefail dies on SIGPIPE.
echo "clang:    $(clang --version | sed -n 1p)"
echo "bpftool:  $(bpftool version | sed -n 1p)"

echo "=== [2/7] build BPF LSM object ==="
# Flags match the production pipeline (crates/bpf-build/src/lib.rs
# clang_args): -O2 is required so the backend fits the 256-byte
# selector buffer in the 512-byte BPF stack; -g for CO-RE relocations.
clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I bpf/include \
      -c bpf/sensors/lsm.bpf.c -o /tmp/lsm.bpf.o
echo "object sections:"
llvm-readelf -S /tmp/lsm.bpf.o | grep -E "lsm|maps|license" || true

echo "=== [3/7] load + attach PRODUCTION object (bpftool) ==="
rm -rf "$PIN_DIR"
# loadall loads + auto-attaches ALL THREE hooks (prog load would load
# only the first program and pin no maps); pinmaps pins the policy /
# kill-switch / ring-buffer maps the harness drives.
set +e
bpftool prog loadall /tmp/lsm.bpf.o "$PIN_DIR" pinmaps "$PIN_DIR" \
  2>&1 | tail -c 65536 > /workspace/.omo/evidence/task-54-verifier-rejection.txt
PROD_RC=${PIPESTATUS[0]}
set -e
rm -rf "$PIN_DIR"
echo "production object load rc: $PROD_RC"
if [[ "$PROD_RC" -ne 0 ]]; then
  echo "--- verifier finding (production object) ---"
  grep -m 4 -E "At program exit|should have been|failed to load" \
    /workspace/.omo/evidence/task-54-verifier-rejection.txt || true
fi

echo "=== [4/7] build + load minimally-clamped copy ==="
if [[ "$PROD_RC" -ne 0 ]]; then
  # Kernel 7.x enforces LSM return values in [-4095, 0]. Two verifier
  # blockers keep the production object from loading (both are no-ops
  # for every kernel-legal input; decision logic is untouched):
  #   (a) the deny clamp `if (err >= 0) err = -13` leaves err < -4095
  #       unbounded -> add the lower-bound clause;
  #   (b) the BPF_PROG ctx cast zero-extends the prior `ret`, losing
  #       the kernel-provided [-4095, 0] range. The exit check
  #       enforces the register's S32 bounds, and a branch on a
  #       sign-extended copy constrains the original's s32 bounds —
  #       but only WITHIN one program: s32 bounds do not propagate
  #       across bpf2bpf calls. So lsm_decide becomes a noinline
  #       subprog returning a +1 marker for the preserve path (its
  #       own exits are unchecked), and each hook re-bounds the
  #       final value with the exact t3-proven clamp pattern before
  #       its own exit. The clamp is a no-op for every value
  #       lsm_decide can produce: 0, [-4095, -1], or the marker-
  #       selected prior ret (always in [-4095, -1]).
  # The production source is NOT modified; this copy exists only to
  # exercise the engine's live behavior.
  awk 'NR == 1 { prev = $0; next }
       { if ($0 ~ /^lsm_decide\(/ && prev ~ /^static __always_inline int$/)
             print "static __attribute__((noinline)) int"
         else
             print prev
         prev = $0 }
       END { print prev }' bpf/sensors/lsm.bpf.c > /tmp/lsm-noinline.c
  sed -e 's|return prior_ret;  /\* unchanged \*/|return 1;  /* marker: hook preserves the prior ret */|' \
      /tmp/lsm-noinline.c > /tmp/lsm-marker.c
  sed -z 's@return lsm_decide(\(KERNEL_V1_LSM_HOOK_[A-Z_]*\), sel_buf, sel_len,\n                      sel_valid, ret);@int lsm_res = lsm_decide(\1, sel_buf, sel_len, sel_valid, ret);\n    int final_ret = (lsm_res > 0) ? ret : lsm_res;\n    if (final_ret > 0 || final_ret < -4095)\n        final_ret = -13;\n    return final_ret;@g' \
    /tmp/lsm-marker.c > /tmp/lsm-clamped.bpf.c
  test "$(grep -c 'int lsm_res = lsm_decide' /tmp/lsm-clamped.bpf.c)" = 3
  test "$(grep -c 'final_ret < -4095' /tmp/lsm-clamped.bpf.c)" = 3
  test "$(grep -c 'defensive: a deny must be' /tmp/lsm-clamped.bpf.c)" = 1
  test "$(grep -c 'noinline' /tmp/lsm-clamped.bpf.c)" = 1
  test "$(grep -c 'lsm_bounded_ret' /tmp/lsm-clamped.bpf.c)" = 0
  diff -u bpf/sensors/lsm.bpf.c /tmp/lsm-clamped.bpf.c || true
  clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 \
        -I bpf/include -I bpf/sensors \
        -c /tmp/lsm-clamped.bpf.c -o /tmp/lsm.bpf.o
  OBJECT_UNDER_TEST="lsm-clamped (production + 2 verifier-bound clauses, decision logic identical)"
else
  OBJECT_UNDER_TEST="production (bpf/sensors/lsm.bpf.c)"
fi
bpftool prog loadall /tmp/lsm.bpf.o "$PIN_DIR" pinmaps "$PIN_DIR"
echo "object under test: $OBJECT_UNDER_TEST"

echo "=== [5/7] verify attachment ==="
echo "--- programs (expect 3 lsm) ---"
bpftool prog list | grep -E "^[0-9]+: lsm|name lsm_" || bpftool prog list
LSM_PROG_COUNT=$(bpftool prog list | grep -c "^[0-9]*: lsm" || true)
echo "lsm program count: $LSM_PROG_COUNT"
echo "--- links (expect lsm_mac) ---"
bpftool link list | grep -E "lsm" || bpftool link list
echo "--- pins ---"
ls -laR "$PIN_DIR"

echo "=== [6/7] compile + run harness ==="
gcc -O2 -Wall -Wextra -o /tmp/enforcement-live bench/enforcement-live.c -lbpf
POLICY_PIN="$(find "$PIN_DIR" -name lsm_policy -print -quit)"
KS_PIN="$(find "$PIN_DIR" -name lsm_kill_switch -print -quit)"
EVENTS_PIN="$(find "$PIN_DIR" -name lsm_events -print -quit)"
echo "policy_pin=$POLICY_PIN"
echo "kill_switch_pin=$KS_PIN"
echo "events_pin=$EVENTS_PIN"
if [[ -z "$POLICY_PIN" || -z "$KS_PIN" || -z "$EVENTS_PIN" ]]; then
  echo "ERROR: pinned maps not found under $PIN_DIR" >&2
  exit 4
fi
set +e
/tmp/enforcement-live "$POLICY_PIN" "$KS_PIN" "$EVENTS_PIN" "$TESTFILE" \
  | tee /workspace/.omo/evidence/task-54-live-output.json
RC=${PIPESTATUS[0]}
set -e
echo "harness exit code: $RC"

echo "=== [7/7] cleanup ==="
rm -rf "$PIN_DIR"
rm -f "$TESTFILE"
REMAIN=$(bpftool prog list | grep -c "^[0-9]*: lsm" || true)
echo "remaining lsm programs after cleanup: ${REMAIN:-0}"
exit "$RC"
INNER_EOF

# ---- run in a privileged container -----------------------------------------
DOCKER_CMD="docker run --rm --privileged \
-v ${WORKSPACE_ROOT}:/workspace \
-v /sys/fs/bpf:/sys/fs/bpf \
-v /sys/kernel/debug:/sys/kernel/debug \
-v ${INNER}:/inner.sh \
-w /workspace ${IMAGE} bash /inner.sh"

echo "bench/enforcement-live.sh: running privileged container (image: $IMAGE)"
set +e
if docker info >/dev/null 2>&1; then
  bash -c "$DOCKER_CMD"
  RC=$?
else
  sg docker -c "$DOCKER_CMD"
  RC=$?
fi
set -e

# ---- host-side cleanup guarantee (trap: even on failure) --------------------
if [[ -d "$PIN_DIR" ]]; then
  echo "bench/enforcement-live.sh: removing leftover pins at $PIN_DIR"
  rm -rf "$PIN_DIR" 2>/dev/null || \
    sg docker -c "docker run --rm --privileged -v /sys/fs/bpf:/sys/fs/bpf alpine rm -rf $PIN_DIR" || true
fi
rm -f "$TESTFILE" 2>/dev/null || true

echo "bench/enforcement-live.sh: done (harness rc=$RC); output: $OUT_JSON"
exit "$RC"
