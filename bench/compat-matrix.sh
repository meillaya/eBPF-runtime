#!/usr/bin/env bash
# bench/compat-matrix.sh — Probe BPF/kernel compatibility on the current host.
# Part of task 55: multi-kernel, multi-arch, cgroup, and runtime compatibility matrix.
#
# Checks: BTF, BPF LSM, cgroup v2, TCX, ring buffer, program types, helpers.
# Outputs JSON to stdout; unprivileged checks run on host, privileged checks
# optionally via Docker (--privileged flag).
#
# Usage:
#   bench/compat-matrix.sh              # host-only (unprivileged) checks
#   bench/compat-matrix.sh --privileged # also run bpftool feature probe in Docker
#
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail

SCHEMA="bench/schemas/compat-matrix.v1.json"
PRIVILEGED="${1:-}"
KERNEL="$(uname -r)"
ARCH="$(uname -m)"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- Helpers ---
json_bool() { [[ "$1" == "true" ]] && echo "true" || echo "false"; }
json_val() {
  # Output valid JSON: true/false bare, anything else quoted string
  case "$1" in
    true|false) echo "$1" ;;
    *) echo "\"$1\"" ;;
  esac
}

# --- Feature probes (unprivileged, host) ---

# BTF readable
BTF_FILE="/sys/kernel/btf/vmlinux"
if [[ -f "$BTF_FILE" ]]; then
  BTF_FIRST="$(bpftool btf dump file "$BTF_FILE" format c 2>/dev/null | head -1 || true)"
  [[ -z "$BTF_FIRST" ]] && BTF_FIRST="dump_failed"
  BTF_OK=true
else
  BTF_FIRST="not_found"
  BTF_OK=false
fi

# BPF LSM active
LSM_LIST="$(cat /sys/kernel/security/lsm 2>/dev/null || echo "")"
if echo "$LSM_LIST" | grep -q "bpf"; then
  LSM_OK=true
else
  LSM_OK=false
fi

# Cgroup v2
CGROUP_TYPE="$(stat -fc %T /sys/fs/cgroup/ 2>/dev/null || echo "unknown")"
if [[ "$CGROUP_TYPE" == "cgroup2fs" ]]; then
  CGROUP_V2=true
else
  CGROUP_V2=false
fi

# unprivileged_bpf_disabled
UNPRIV_BPF="$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo "unknown")"

# --- Privileged probes (bpftool feature probe) ---
FEATURE_PROBE=""
TCX_OK="not_tested"
RINGBUF_OK="not_tested"
LSM_HOOKS_OK="not_tested"
RAW_TP_OK="not_tested"
KPROBE_OK="not_tested"
CGROUP_SKB_OK="not_tested"
RINGBUF_OUTPUT_OK="not_tested"
PROBE_READ_KERNEL_OK="not_tested"

run_feature_probe() {
  # Try host first (needs CAP_BPF/CAP_SYS_ADMIN)
  if FEATURE_PROBE="$(bpftool feature probe 2>/dev/null)"; then
    echo "host"
    return 0
  fi

  # Try unprivileged mode
  if FEATURE_PROBE="$(bpftool feature probe unprivileged 2>/dev/null)"; then
    echo "host_unprivileged"
    return 0
  fi

  # Try privileged Docker container
  if [[ "$PRIVILEGED" == "--privileged" ]] && command -v docker &>/dev/null; then
    if FEATURE_PROBE="$(sg docker -c "docker run --rm --privileged \
      -v /sys/kernel/debug:/sys/kernel/debug \
      archlinux:latest \
      bash -c 'pacman -Sy --noconfirm linux-tools >/dev/null 2>&1 && bpftool feature probe'" 2>/dev/null)"; then
      echo "privileged_container"
      return 0
    fi
  fi

  echo "unavailable"
  return 1
}

PROBE_METHOD="$(run_feature_probe || echo "unavailable")"

if [[ "$PROBE_METHOD" != "unavailable" && -n "$FEATURE_PROBE" ]]; then
  # Parse feature probe output
  TCX_OK=$(json_bool "$(echo "$FEATURE_PROBE" | grep -qi "tcx" && echo true || echo false)")
  RINGBUF_OK=$(json_bool "$(echo "$FEATURE_PROBE" | grep -qi "ringbuf" && echo true || echo false)")
  LSM_HOOKS_OK=$(json_bool "$(echo "$FEATURE_PROBE" | grep -qi "lsm" && echo true || echo false)")
  RAW_TP_OK=$(json_bool "$(echo "$FEATURE_PROBE" | grep -qi "raw_tracepoint" && echo true || echo false)")
  KPROBE_OK=$(json_bool "$(echo "$FEATURE_PROBE" | grep -qi "kprobe" && echo true || echo false)")
  CGROUP_SKB_OK=$(json_bool "$(echo "$FEATURE_PROBE" | grep -qi "cgroup_skb" && echo true || echo false)")
  RINGBUF_OUTPUT_OK=$(json_bool "$(echo "$FEATURE_PROBE" | grep -qi "ringbuf_output" && echo true || echo false)")
  PROBE_READ_KERNEL_OK=$(json_bool "$(echo "$FEATURE_PROBE" | grep -qi "probe_read_kernel" && echo true || echo false)")
fi

# --- Determine overall status ---
# All core features expected on 7.1.3: BTF, LSM, cgroup v2, TCX, ringbuf, all prog types
ALL_PASS=true
DEGRADED_FEATURES="[]"

if [[ "$BTF_OK" != "true" ]]; then ALL_PASS=false; fi
if [[ "$LSM_OK" != "true" ]]; then ALL_PASS=false; fi
if [[ "$CGROUP_V2" != "true" ]]; then ALL_PASS=false; fi

# TCX degraded coverage
if [[ "$TCX_OK" == "false" ]]; then
  DEGRADED_FEATURES='[{"feature":"tcx","reason":"TCX not available","fallback":"classic TC clsact qdisc (BPF_PROG_TYPE_SCHED_CLS)"}]'
fi

if [[ "$ALL_PASS" == "true" ]]; then
  STATUS="supported"
else
  STATUS="degraded"
fi

# --- Output JSON ---
cat <<EOF
{
  "schema_version": 1,
  "schema_ref": "$SCHEMA",
  "timestamp": "$TS",
  "kernel": "$KERNEL",
  "arch": "$ARCH",
  "probe_method": "$PROBE_METHOD",
  "status": "$STATUS",
  "unprivileged_bpf_disabled": "$UNPRIV_BPF",
  "lsm_list": "$LSM_LIST",
  "cgroup_fs_type": "$CGROUP_TYPE",
  "features": {
    "btf_readable": $BTF_OK,
    "btf_first_line": "$(echo "$BTF_FIRST" | sed 's/"/\\"/g')",
    "bpf_lsm_active": $LSM_OK,
    "cgroup_v2": $CGROUP_V2,
    "tcx": $(json_val "$TCX_OK"),
    "ring_buffer": $(json_val "$RINGBUF_OK"),
    "bpf_lsm_hooks": $(json_val "$LSM_HOOKS_OK"),
    "prog_raw_tracepoint": $(json_val "$RAW_TP_OK"),
    "prog_kprobe": $(json_val "$KPROBE_OK"),
    "prog_cgroup_skb": $(json_val "$CGROUP_SKB_OK"),
    "helper_ringbuf_output": $(json_val "$RINGBUF_OUTPUT_OK"),
    "helper_probe_read_kernel": $(json_val "$PROBE_READ_KERNEL_OK")
  },
  "degraded_coverage": $DEGRADED_FEATURES,
  "requires_vm": [
    {"kernel": "5.15.0", "arch": "x86_64", "reason": "kernel not available on host"},
    {"kernel": "5.15.0", "arch": "arm64", "reason": "kernel+arch not available on host"},
    {"kernel": "6.1.0", "arch": "x86_64", "reason": "kernel not available on host"},
    {"kernel": "6.1.0", "arch": "arm64", "reason": "kernel+arch not available on host"},
    {"kernel": "6.6.0", "arch": "x86_64", "reason": "kernel not available on host"},
    {"kernel": "6.6.0", "arch": "arm64", "reason": "kernel+arch not available on host"},
    {"kernel": "7.1.3", "arch": "arm64", "reason": "arch not available on host"}
  ]
}
EOF
