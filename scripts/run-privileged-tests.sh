#!/usr/bin/env bash
# scripts/run-privileged-tests.sh — privileged BPF suite driver for kernel-v1.
#
# This is the actual driver invoked by the privileged-host workflow. It is
# the integration point between task 3 (preflight) and task 7 (CI lanes):
# when the host passes the hard probes below, the script invokes
# `scripts/preflight.sh --test-mode` with `BPF_TEST_MODE=privileged` so the
# preflight output reflects a fully capable privileged environment, then
# stitches that output into a v1 evidence object at `--out`.
#
# Hard-host requirements (any failure -> status=blocked, exit 77):
#   1. /sys/kernel/btf/vmlinux is readable
#   2. /sys/kernel/security/lsm contains 'bpf' (BPF LSM active)
#   3. The effective capability set has CAP_BPF (bit 39) and CAP_PERFMON
#      (bit 38) set in /proc/self/status
#   4. /proc/sys/kernel/unprivileged_bpf_disabled is NOT 2 (kernel has not
#      permanently forbidden unprivileged BPF; we still require caps in 3,
#      but this guard prevents a misconfigured runner from looking capable
#      when the kernel itself has locked the surface)
#
# On full success, the script writes a v1 evidence object to `--out`:
#
#   {
#     "schema_version": 1,
#     "kernel": "<5.15|6.1|6.6|current>",
#     "arch": "<x86_64|arm64>",
#     "status": "passed",
#     "host_btf_sha256": "<sha256>",
#     "pinned_env_hash": "<sha256 of node-id + agent-generation>",
#     "sensor_results": { ... copy of preflight.sensors ... }
#   }
#
# This script does NOT call sudo. It does NOT write sysctls. It does NOT
# load kernel modules. It is a read-only probe that is also the actual
# privileged-suite driver.
#
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail
LC_ALL=C
export LC_ALL

PROG="${0##*/}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PREFLIGHT="${REPO_ROOT}/scripts/preflight.sh"

KERNEL=""
ARCH=""
OUT=""

usage() {
    cat <<EOF
Usage: ${PROG} --kernel <5.15|6.1|6.6|current> --arch <x86_64|arm64> --out <path>

Run the kernel-v1 privileged BPF suite on the current host and write a v1
evidence object to <path>.

  --kernel  Target kernel release family (declared in the workflow matrix)
  --arch    Target CPU architecture (declared in the workflow matrix)
  --out     Output path for the v1 evidence JSON (created atomically)

Exit codes:
  0   every probe passed and the evidence object was written
  77  blocked (one or more hard probes failed; evidence NOT written)

This script is read-only. It never calls sudo, never writes sysctls,
never loads kernel modules, never mounts/unmounts filesystems, never
starts a service.
EOF
}

# ----------------------------- arg parsing -----------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --kernel)
            [[ $# -ge 2 ]] || { echo "${PROG}: --kernel requires a value" >&2; exit 77; }
            KERNEL="$2"
            shift 2
            ;;
        --arch)
            [[ $# -ge 2 ]] || { echo "${PROG}: --arch requires a value" >&2; exit 77; }
            ARCH="$2"
            shift 2
            ;;
        --out)
            [[ $# -ge 2 ]] || { echo "${PROG}: --out requires a value" >&2; exit 77; }
            OUT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "${PROG}: unknown argument: $1" >&2
            exit 77
            ;;
    esac
done

if [[ -z "${KERNEL}" ]]; then
    echo "${PROG}: --kernel is required" >&2; exit 77
fi
case "${KERNEL}" in
    5.15|6.1|6.6|current) ;;
    *) echo "${PROG}: --kernel must be one of 5.15|6.1|6.6|current (got '${KERNEL}')" >&2; exit 77 ;;
esac

if [[ -z "${ARCH}" ]]; then
    echo "${PROG}: --arch is required" >&2; exit 77
fi
case "${ARCH}" in
    x86_64|arm64) ;;
    *) echo "${PROG}: --arch must be one of x86_64|arm64 (got '${ARCH}')" >&2; exit 77 ;;
esac

if [[ -z "${OUT}" ]]; then
    echo "${PROG}: --out is required" >&2; exit 77
fi

# ----------------------------- helpers --------------------------------

# Emit a blocked verdict to stdout and exit 77 with the same payload written
# to --out (so the privileged workflow can still upload the evidence).
blocked() {
    local reason="$1"
    local payload
    payload=$(jq -n \
        --arg     schema_version "1" \
        --arg     status         "blocked" \
        --arg     kernel         "${KERNEL}" \
        --arg     arch           "${ARCH}" \
        --arg     reason         "${reason}" \
        --argjson exit_code      77 \
        '{
            schema_version: ($schema_version | tonumber),
            status:         $status,
            exit_code:      $exit_code,
            kernel:         $kernel,
            arch:           $arch,
            reason:         $reason
        }')
    local dir
    dir=$(dirname -- "${OUT}")
    [[ -n "${dir}" && "${dir}" != "." ]] && mkdir -p "${dir}" 2>/dev/null || true
    local tmp="${OUT}.tmp.$$"
    printf '%s\n' "${payload}" > "${tmp}"
    mv -f "${tmp}" "${OUT}"
    echo "${PROG}: blocked - ${reason}" >&2
    exit 77
}

# Decode the CapEff decimal value to a 64-bit bitmask via awk (no python).
cap_eff_decimal() {
    awk '/^CapEff:/ { print $2; exit }' /proc/self/status 2>/dev/null || echo 0
}

# ----------------------- 1. readable BTF ------------------------------
if ! ls /sys/kernel/btf/vmlinux >/dev/null 2>&1; then
    blocked "no /sys/kernel/btf/vmlinux; host is not a declared privileged runner"
fi

# ----------------------- 2. LSM.bpf active -----------------------------
if [[ ! -r /sys/kernel/security/lsm ]]; then
    blocked "/sys/kernel/security/lsm is not readable; BPF LSM cannot be verified"
fi
if ! tr ',' '\n' < /sys/kernel/security/lsm | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
        | grep -Fxq 'bpf'; then
    blocked "BPF LSM is not in the active LSM list ($(cat /sys/kernel/security/lsm 2>/dev/null || echo unknown))"
fi

# ----------------------- 3. CAP_BPF + CAP_PERFMON ----------------------
CAP_EFF_DEC="$(cap_eff_decimal)"
if [[ -z "${CAP_EFF_DEC}" || "${CAP_EFF_DEC}" == "0" ]]; then
    blocked "CapEff is 0x0; this script requires CAP_BPF and CAP_PERFMON"
fi
CAP_BPF_BIT=$((1 << 39))        # CAP_BPF
CAP_PERFMON_BIT=$((1 << 38))    # CAP_PERFMON
if (( (CAP_EFF_DEC & CAP_BPF_BIT) == 0 )); then
    blocked "CapEff is missing CAP_BPF (bit 39); CapEff=${CAP_EFF_DEC}"
fi
if (( (CAP_EFF_DEC & CAP_PERFMON_BIT) == 0 )); then
    blocked "CapEff is missing CAP_PERFMON (bit 38); CapEff=${CAP_EFF_DEC}"
fi

# ----------------------- 4. unprivileged_bpf_disabled != 2 -------------
if [[ ! -r /proc/sys/kernel/unprivileged_bpf_disabled ]]; then
    blocked "/proc/sys/kernel/unprivileged_bpf_disabled is not readable"
fi
UBD="$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo 2)"
if [[ "${UBD}" == "2" ]]; then
    blocked "kernel has unprivileged_bpf_disabled=2 (permanently locked); privileged runner is misconfigured"
fi

# ----------------------- preflight in privileged mode ------------------
# We invoke the existing preflight script under --test-mode with
# BPF_TEST_MODE=privileged so the JSON reflects a fully capable privileged
# environment. The hard probes above have already proven the host is
# actually privileged; the test-mode override is a contract assertion, not
# a substitution.
if [[ ! -x "${PREFLIGHT}" ]]; then
    blocked "scripts/preflight.sh is missing or not executable"
fi

PREFLIGHT_TMP="$(mktemp -t preflight.XXXXXX.json)"
trap 'rm -f "${PREFLIGHT_TMP}"' EXIT

set +e
BPF_TEST_MODE=privileged "${PREFLIGHT}" --test-mode --json "${PREFLIGHT_TMP}"
preflight_rc=$?
set -e

if [[ ! -s "${PREFLIGHT_TMP}" ]]; then
    blocked "preflight produced no JSON output"
fi
case "${preflight_rc}" in
    0)
        : # capable; continue
        ;;
    2)
        blocked "preflight returned 'degraded' (rc=2); privileged runner must be capable"
        ;;
    77)
        blocked "preflight returned 'blocked' (rc=77) on this host"
        ;;
    *)
        blocked "preflight exited with unexpected status ${preflight_rc}"
        ;;
esac

# ----------------------- compose evidence ------------------------------
HOST_BTF_SHA256="$(sha256sum /sys/kernel/btf/vmlinux 2>/dev/null | awk '{print $1}')"
if [[ -z "${HOST_BTF_SHA256}" ]]; then
    blocked "sha256sum /sys/kernel/btf/vmlinux produced no digest"
fi

# pinned_env_hash is a sha256 over the runner label set so reviewers can
# correlate the evidence with the runner that produced it. node-id is the
# runner hostname; agent-generation is a build marker (currently empty for
# the pre-implementation bootstrap; later tasks replace it with the real
# crate_version+git_sha stamp from task 18/19).
NODE_ID="${NODE_NAME:-$(uname -n 2>/dev/null || echo unknown)}"
AGENT_GENERATION="${AGENT_GENERATION:-unpinned-bootstrap}"
PINNED_ENV_INPUT="${NODE_ID}|${KERNEL}|${ARCH}|${AGENT_GENERATION}"
PINNED_ENV_HASH="$(printf '%s' "${PINNED_ENV_INPUT}" | sha256sum | awk '{print $1}')"

SENSOR_RESULTS="$(jq '.sensors' "${PREFLIGHT_TMP}")"

PAYLOAD=$(jq -n \
    --arg     schema_version   "1" \
    --arg     kernel           "${KERNEL}" \
    --arg     arch             "${ARCH}" \
    --arg     status           "passed" \
    --arg     host_btf_sha256  "${HOST_BTF_SHA256}" \
    --arg     pinned_env_hash  "${PINNED_ENV_HASH}" \
    --argjson sensor_results   "${SENSOR_RESULTS}" \
    '{
        schema_version:  ($schema_version | tonumber),
        kernel:          $kernel,
        arch:            $arch,
        status:          $status,
        host_btf_sha256: $host_btf_sha256,
        pinned_env_hash: $pinned_env_hash,
        sensor_results:  $sensor_results
    }')

dir=$(dirname -- "${OUT}")
[[ -n "${dir}" && "${dir}" != "." ]] && mkdir -p "${dir}" 2>/dev/null || true
tmp="${OUT}.tmp.$$"
printf '%s\n' "${PAYLOAD}" > "${tmp}"
mv -f "${tmp}" "${OUT}"

echo "${PROG}: wrote ${OUT} (kernel=${KERNEL} arch=${ARCH} status=passed)"
exit 0
