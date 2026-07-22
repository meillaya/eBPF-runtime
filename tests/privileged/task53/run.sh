#!/usr/bin/env bash
# tests/privileged/task53/run.sh — kernel-v1 task 53 privileged suite driver.
#
# Runs INSIDE a privileged Docker container (archlinux base) with the repo
# bind-mounted at /workspace, bpffs at /sys/fs/bpf, and tracefs at
# /sys/kernel/debug. Usage (from the host):
#
#   sg docker -c "docker run --rm --privileged --pid=host \
#     -v \$PWD:/workspace -v /sys/fs/bpf:/sys/fs/bpf \
#     -v /sys/kernel/debug:/sys/kernel/debug -w /workspace \
#     kernel-v1-task53 bash tests/privileged/task53/run.sh"
#
# Steps: compile every sensor object, prove verifier acceptance via
# bpftool prog loadall + prog list, then drive the live harness through
# ordering / supported-load / saturation modes against the process sensor.
# Every step's exit code and output is captured in $OUT/steps.jsonl; the
# consolidated verdict lands in $OUT/task-53-live.json (printed to stdout).
#
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -uo pipefail
LC_ALL=C
export LC_ALL

cd /workspace || exit 1
OUT=/tmp/task53
mkdir -p "$OUT"
STEPS="$OUT/steps.jsonl"
: >"$STEPS"
FAILED=0

# Record one step: name + command + rc + truncated output.
step() {
    local name="$1"
    shift
    local safe
    safe="$(printf '%s' "$name" | tr -c 'A-Za-z0-9._-' '_')"
    local outf="$OUT/$safe.out"
    local errf="$OUT/$safe.err"
    local rc=0
    "$@" >"$outf" 2>"$errf" || rc=$?
    jq -n --arg name "$name" --arg cmd "$*" --argjson rc "$rc" \
        --arg out "$(head -c 3500 "$outf" 2>/dev/null)" \
        --arg err "$(head -c 1500 "$errf" 2>/dev/null)" \
        '{name:$name,cmd:$cmd,rc:$rc,out:$out,err:$err}' >>"$STEPS"
    echo "[step] $name rc=$rc"
    return "$rc"
}

# Always leave /sys/fs/bpf clean, even on early failure.
cleanup_pins() {
    rm -rf /sys/fs/bpf/task53_* 2>/dev/null || true
}
trap cleanup_pins EXIT

echo "== task-53 privileged BPF sensor suite =="

# ---- 0. toolchain ------------------------------------------------------
step "toolchain_clang" bash -c 'clang --version | head -1'
step "toolchain_bpftool" bash -c 'bpftool version | head -1'
step "toolchain_libbpf" bash -c 'pacman -Q libbpf; ls -l /usr/lib/libbpf.so*'
step "toolchain_rustc" bash -c 'rustc --version 2>/dev/null || echo unavailable'
step "host_kernel" bash -c 'uname -rm'
step "host_btf" bash -c 'sha256sum /sys/kernel/btf/vmlinux'

# ---- 1. compile every sensor object (amd64) -----------------------------
SENSORS="process file network dns syscall identity lsm"
for s in $SENSORS; do
    step "build_${s}" clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 \
        -I bpf/include -c "bpf/sensors/${s}.bpf.c" -o "$OUT/${s}.bpf.o"
done
step "objdump_process_sections" bash -c \
    "llvm-objdump -h $OUT/process.bpf.o | grep -E 'raw_tracepoint|kprobe|\\.BTF'"

# ---- 2. prove verifier acceptance: bpftool prog loadall + list ----------
step "load_process_pin" bpftool prog loadall "$OUT/process.bpf.o" \
    /sys/fs/bpf/task53_process
step "load_file_pin" bpftool prog loadall "$OUT/file.bpf.o" \
    /sys/fs/bpf/task53_file
step "load_network_pin" bpftool prog loadall "$OUT/network.bpf.o" \
    /sys/fs/bpf/task53_network
step "load_dns_pin" bpftool prog loadall "$OUT/dns.bpf.o" \
    /sys/fs/bpf/task53_dns
step "load_syscall_pin" bpftool prog loadall "$OUT/syscall.bpf.o" \
    /sys/fs/bpf/task53_syscall
step "load_identity_pin" bpftool prog loadall "$OUT/identity.bpf.o" \
    /sys/fs/bpf/task53_identity
step "load_lsm_pin" bpftool prog loadall "$OUT/lsm.bpf.o" \
    /sys/fs/bpf/task53_lsm
step "prog_list_loaded" bpftool prog list
step "prog_show_fork" bash -c \
    'bpftool prog show pinned /sys/fs/bpf/task53_process/tp_sched_process_fork'

# Unpin: the harness loads its own instance; pins must not survive the run.
step "unpin_all" bash -c 'rm -rf /sys/fs/bpf/task53_* && ls -A /sys/fs/bpf'

# ---- 3. build the live harness ------------------------------------------
step "build_harness" gcc -O2 -Wall -o "$OUT/harness" \
    tests/privileged/task53/harness.c -lbpf -lelf -lz -lpthread

# Minimal static executable the supported-load generator execs: a dynamic
# /bin/true costs ~4 ms/exec (ld.so), capping the generator below the
# declared envelope; a static 3-instruction exit(0) costs ~0.3 ms so the
# generator can hold exactly 1000 events/s/cpu.
cat >"$OUT/true_fast.S" <<'EOF'
.text
.globl _start
_start:
    mov $60, %rax
    xor %edi, %edi
    syscall
EOF
step "build_true_fast" gcc -static -nostdlib -o "$OUT/true_fast" "$OUT/true_fast.S"

# ---- 4. ordering: fork/exec/exit captured with causal order -------------
step "harness_ordering" "$OUT/harness" "$OUT/process.bpf.o" \
    --mode=ordering --workers=4 --children=25 --rate=100 --drain=2 \
    --out="$OUT/ordering.json"
[ -s "$OUT/ordering.json" ] || FAILED=1

# ---- 5. supported-load envelope: zero critical loss at declared rate ----
# 1000 events/s/cpu (schema default) = 250 children/s/cpu: each child
# produces 4 events (fork + exec-kprobe + exec-tp + exit). One deadline-
# pinned worker per CPU exec'ing the static true_fast holds the declared
# envelope; CPU 0 is kept for the consumer, which runs SCHED_FIFO(10) there
# so host load can never stall the drain and fake a ring-buffer drop.
NPROC="$(nproc)"
WORKERS=$((NPROC > 1 ? NPROC - 1 : 1))
step "harness_supported" bash -c \
    "$OUT/harness $OUT/process.bpf.o --mode=supported --workers=$WORKERS \
     --children=2500 --rate=250 --bin=$OUT/true_fast --consumer-rt=10 \
     --max-gen=90 --drain=3 --out=$OUT/supported.json &
     hp=\$!
     sleep 5
     bpftool prog list >$OUT/prog_list_attached.out 2>&1
     bpftool link list >$OUT/link_list_attached.out 2>&1
     jq -n --arg prog \"\$(cat $OUT/prog_list_attached.out)\" \
           --arg link \"\$(cat $OUT/link_list_attached.out)\" \
           '{prog_list:\$prog,link_list:\$link}' >$OUT/attached.json
     wait \$hp"
[ -s "$OUT/supported.json" ] || FAILED=1

# ---- 6. saturation: tiny ring + paused consumer -> visible, reconciled loss
step "harness_saturation" "$OUT/harness" "$OUT/process.bpf.o" \
    --mode=saturation --ring-size=4096 --workers=4 --children=150 \
    --rate=0 --drain=3 --out="$OUT/saturation.json"
[ -s "$OUT/saturation.json" ] || FAILED=1

# ---- 7. cleanup verification --------------------------------------------
step "post_prog_list" bpftool prog list
step "post_bpf_fs_clean" bash -c \
    'ls /sys/fs/bpf/ 2>/dev/null; ! ls -d /sys/fs/bpf/task53_* 2>/dev/null && echo NO_TASK53_PINS'

# ---- 8. consolidate ------------------------------------------------------
# securityfs is not auto-mounted in the container; mount it read-only so the
# active-LSM list (bpf_lsm_active) is the host's real value.
mount -t securityfs none /sys/kernel/security 2>/dev/null || true
step "env_json" bash -c "jq -n \
  --arg kernel \"\$(uname -r)\" --arg arch \"\$(uname -m)\" \
  --arg btf \"\$(sha256sum /sys/kernel/btf/vmlinux | cut -d' ' -f1)\" \
  --arg clang \"\$(clang --version | head -1)\" \
  --arg bpftool \"\$(bpftool version | head -1)\" \
  --arg libbpf \"\$(pacman -Q libbpf | awk '{print \$2}')\" \
  --arg rustc \"\$(rustc --version 2>/dev/null || echo unavailable)\" \
  --arg lsm \"\$(cat /sys/kernel/security/lsm 2>/dev/null || echo unknown)\" \
  --argjson ubd \"\$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo 2)\" \
  '{kernel:\$kernel,arch:\$arch,btf_sha256:\$btf,clang:\$clang,bpftool:\$bpftool,libbpf:\$libbpf,rustc:\$rustc,lsm:\$lsm,unprivileged_bpf_disabled:\$ubd}'"

ORD_V=$(jq -r '.verdict' "$OUT/ordering.json" 2>/dev/null || echo missing)
SUP_V=$(jq -r '.verdict' "$OUT/supported.json" 2>/dev/null || echo missing)
SAT_V=$(jq -r '.verdict' "$OUT/saturation.json" 2>/dev/null || echo missing)

jq -n \
    --slurpfile ord "$OUT/ordering.json" \
    --slurpfile sup "$OUT/supported.json" \
    --slurpfile sat "$OUT/saturation.json" \
    --slurpfile att "$OUT/attached.json" \
    --slurpfile env "$OUT/env_json.out" \
    --slurpfile steps "$STEPS" \
    --arg ord_v "$ORD_V" --arg sup_v "$SUP_V" --arg sat_v "$SAT_V" \
    '{
        task: 53,
        verdicts: {ordering: $ord_v, supported: $sup_v, saturation: $sat_v},
        overall: (if ($ord_v == "passed" and $sup_v == "passed" and $sat_v == "passed")
                  then "passed" else "failed" end),
        environment: $env[0],
        attached: $att[0],
        ordering: $ord[0],
        supported: $sup[0],
        saturation: $sat[0],
        steps: $steps
    }' >"$OUT/task-53-live.json"

echo "== task-53-live.json =="
cat "$OUT/task-53-live.json"

# Persist results past the --rm container when the host bind-mounts an out dir.
if [ -n "${TASK53_COPY_OUT:-}" ]; then
    mkdir -p "$TASK53_COPY_OUT"
    cp "$OUT/task-53-live.json" "$OUT/ordering.json" "$OUT/supported.json" \
        "$OUT/saturation.json" "$OUT/attached.json" "$STEPS" \
        "$TASK53_COPY_OUT/" 2>/dev/null || true
    echo "copied results to $TASK53_COPY_OUT"
fi

if [ "$FAILED" -ne 0 ]; then
    echo "TASK53_RUN_FAILED" >&2
    exit 1
fi
jq -e '.overall == "passed"' "$OUT/task-53-live.json" >/dev/null
