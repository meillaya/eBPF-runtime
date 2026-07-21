#!/usr/bin/env bash
# scripts/preflight.sh — non-mutating host compatibility preflight for the
# kernel-v1 eBPF runtime-security-and-observability platform.
#
# This script is a read-only probe of the Linux host substrate. It does NOT
# mutate the host: it never invokes sudo, never writes to sysctls, never loads
# or unloads kernel modules, never mounts or unmounts filesystems, never starts
# a container runtime or service, and never attaches a lasting BPF probe.
#
# Facts captured (all read-only):
#   * kernel:    release, version, arch, boot_id, hostname
#   * BTF:       /sys/kernel/btf/vmlinux readability, size, sha256
#   * LSM:       active list from /sys/kernel/security/lsm and whether 'bpf'
#                is in the list (required for BPF LSM hooks)
#   * cgroup:    v1/v2/unified mode, mount path, exposed controllers
#   * mounts:    bpffs (/sys/fs/bpf), tracefs, debugfs
#   * privilege: CapEff / CapBnd as 0x... hex; derived can_load
#                (true iff CapEff has CAP_BPF + CAP_PERFMON AND the kernel
#                has not permanently disabled unprivileged BPF)
#   * BPF:       presence of key kfuncs/helper symbols in /proc/kallsyms
#   * runtime:   host vs. docker/containerd/cri-o (best-effort, read-only)
#   * sensors:   per-sensor capable|degraded|blocked with named reason
#
# Exit codes:
#   0   fully capable (every required sensor reports 'capable' and BPF can
#       be loaded by this process)
#   2   degraded (some sensors are degraded — coverage is partial; agent may
#       still run with the named limitations)
#   77  blocked (a required feature is unavailable — agent cannot run)
#
# Flags:
#   --json <path>    Emit JSON to <path> atomically (temp + mv). If omitted,
#                    JSON is written to stdout.
#   --test-mode      Acknowledge that the script is allowed to honour the
#                    BPF_TEST_MODE env var for synthetic fact injection. This
#                    flag is required to enable test mocking; the env var
#                    alone is ignored. When mocking is active, the script
#                    prints a loud banner to stderr so it is never silent.
#   --help           Print usage and exit 0.
#
# Toolchain policy:
#   The script depends only on POSIX utilities (cat, stat, mount, sha256sum)
#   plus jq. It does NOT depend on sudo, sysctl, modprobe, systemctl, mount(8)
#   write paths, ip, nft, bpftool, or any other mutating tool.
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

set -euo pipefail
LC_ALL=C
export LC_ALL

PROG="${0##*/}"

JSON_PATH=""
TEST_MODE_FLAG=0

usage() {
    cat <<'EOF'
Usage: preflight.sh [--json <path>] [--test-mode] [--help]

Read-only host compatibility preflight for the kernel-v1 eBPF runtime
security and observability platform.

  --json <path>   Emit JSON to <path> atomically (temp + mv). If omitted,
                  the JSON document is written to stdout.
  --test-mode     Allow the script to honour the BPF_TEST_MODE env var for
                  synthetic fact injection. The flag MUST be passed AND the
                  env var MUST be set; mocking is never reachable from the
                  env var alone. When mocking is active, a banner is emitted
                  to stderr so the substitution is never silent.
  --help          Print this message and exit 0.

Exit codes:
  0   fully capable
  2   degraded (warnings present; coverage partial)
  77  blocked (one or more required features unavailable)

This script does NOT mutate the host. It never uses sudo, never writes
sysctls, never loads kernel modules, never mounts/unmounts filesystems,
and never starts a service.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --json)
            [[ $# -ge 2 ]] || { echo "$PROG: --json requires a path" >&2; exit 2; }
            JSON_PATH="$2"
            shift 2
            ;;
        --test-mode)
            TEST_MODE_FLAG=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "$PROG: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Toolchain gate
# ---------------------------------------------------------------------------
require_tool() {
    local t="$1"
    if ! command -v "$t" >/dev/null 2>&1; then
        echo "$PROG: required tool missing: $t" >&2
        return 1
    fi
}

if ! require_tool jq; then
    cat <<'EOF' >&2
{"schema_version":1,"status":"blocked","blocked_reason":"jq is required to construct preflight JSON; install jq and rerun."}
EOF
    exit 77
fi

# ---------------------------------------------------------------------------
# Test-mode banner
# ---------------------------------------------------------------------------
test_mode_active() {
    # Mocking requires BOTH --test-mode AND the BPF_TEST_MODE env var. The
    # env var alone is intentionally ignored to keep mock injection out of
    # reach of an unattended production invocation.
    [[ "${TEST_MODE_FLAG}" == "1" ]] && [[ -n "${BPF_TEST_MODE:-}" ]]
}

if test_mode_active; then
    {
        echo "================================================================"
        echo "$PROG: TEST MODE ACTIVE (BPF_TEST_MODE=${BPF_TEST_MODE})"
        echo "$PROG: Fact values are synthetic; they are NOT host observations."
        echo "$PROG: This mode is for unit tests / CI ONLY and prints to stderr"
        echo "$PROG: so that a production invocation cannot silently mutate."
        echo "================================================================"
    } >&2
fi

# ---------------------------------------------------------------------------
# Capability / cgroup / BTF constant helpers
# ---------------------------------------------------------------------------
# CAP_BPF = 39, CAP_PERFMON = 38
CAP_BPF_BIT=$((1 << 39))
CAP_PERFMON_BIT=$((1 << 38))

hex_caps() {
    # Render a decimal capability mask as 0x... lower-case hex. We always
    # emit 16 digits to keep output widths stable across values.
    local dec="${1:-0}"
    printf '0x%016x' "$dec"
}

# ---------------------------------------------------------------------------
# Probes (each returns a single jq -n expression or plain string)
# ---------------------------------------------------------------------------
probe_kernel_release() {
    uname -r 2>/dev/null || echo "unknown"
}

probe_kernel_version() {
    # /proc/sys/kernel/osrelease gives the same string as uname -r but is
    # directly readable in JSON; we keep both for cross-checking.
    cat /proc/sys/kernel/osrelease 2>/dev/null || echo "unknown"
}

probe_arch() {
    uname -m 2>/dev/null || echo "unknown"
}

probe_boot_id() {
    cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo "unknown"
}

probe_hostname() {
    hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || echo "unknown"
}

probe_btf() {
    # Always reports the canonical BTF path. If readable, computes size and
    # sha256. If not, returns readable=false and null/zero for size/sha256.
    local path="/sys/kernel/btf/vmlinux" readable="false" size=0 sha="null"
    if [[ -r "$path" ]]; then
        readable="true"
        size=$(stat -c '%s' -- "$path" 2>/dev/null || echo 0)
        if command -v sha256sum >/dev/null 2>&1; then
            sha=$(sha256sum -- "$path" 2>/dev/null | awk '{print $1}' | head -n1 || true)
            [[ -z "$sha" ]] && sha="null"
        fi
    fi
    jq -n --arg p "$path" --argjson r "$readable" --argjson s "$size" --arg sha "$sha" \
        '{path: $p, readable: $r, size: $s, sha256: (if $sha == "null" then null else $sha end)}'
}

probe_lsm() {
    local raw="" list="" bpf_in_list="false"
    if [[ -r /sys/kernel/security/lsm ]]; then
        raw=$(cat /sys/kernel/security/lsm 2>/dev/null | tr -d '\n' || true)
    fi
    list=$(printf '%s' "$raw" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | awk 'length>0' | paste -sd ',' -)
    case ",${list}," in
        *,bpf,*) bpf_in_list="true" ;;
        *) bpf_in_list="false" ;;
    esac
    [[ -z "$list" ]] && list="unknown"
    jq -n --arg l "$list" --argjson b "$bpf_in_list" \
        '{active: $l, bpf_in_list: $b}'
}

probe_cgroup() {
    local mode="unknown" mount_path="" controllers=""

    # Detect cgroup v2 by fs type at /sys/fs/cgroup.
    if [[ -d /sys/fs/cgroup ]]; then
        mount_path="/sys/fs/cgroup"
        local fstype
        fstype=$(stat -fc '%T' /sys/fs/cgroup 2>/dev/null || echo "")
        case "$fstype" in
            cgroup2fs|cgroup2)
                mode="unified"
                if [[ -r /sys/fs/cgroup/cgroup.controllers ]]; then
                    controllers=$(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null \
                        | tr ' ' '\n' | awk 'length>0' | paste -sd ',' -)
                fi
                ;;
            tmpfs|*)
                # tmpfs at /sys/fs/cgroup typically indicates hybrid (v1+v2).
                mode="hybrid"
                # Probe for cgroup v1 controllers under /sys/fs/cgroup/<ctrl>.
                controllers=$(ls -1 /sys/fs/cgroup 2>/dev/null \
                    | grep -Ev '^(cgroup\.|cgroup$|unified|cgroup\.max\.|cgroup\.threads|cgroup\.stat|cgroup\.pressure|cgroup\.procs|cgroup\.subtree_control|cpuset\.|cpu\.|cpuacct|memory\.|devices\.|freezer\.|net_cls\.|net_prio\.|pids\.|rdma\.|hugetlb\.|misc\.|unified)$' \
                    | paste -sd ',' -)
                [[ -z "$controllers" ]] && controllers="unknown"
                ;;
        esac
    fi

    # Some hosts mount cgroup v2 under /sys/fs/cgroup/unified even in legacy mode.
    if [[ "$mode" == "unknown" ]]; then
        if [[ -r /sys/fs/cgroup/unified/cgroup.controllers ]]; then
            mode="hybrid"
            mount_path="/sys/fs/cgroup/unified"
            controllers=$(cat /sys/fs/cgroup/unified/cgroup.controllers 2>/dev/null \
                | tr ' ' '\n' | awk 'length>0' | paste -sd ',' -)
        elif [[ -r /proc/self/cgroup ]]; then
            local cg
            cg=$(cat /proc/self/cgroup 2>/dev/null | head -n1 || true)
            case "$cg" in
                0::*) mode="unified"; mount_path="/sys/fs/cgroup" ;;
                *)    mode="legacy" ;;
            esac
        fi
    fi

    jq -n --arg m "$mode" --arg p "$mount_path" --arg c "$controllers" \
        '{mode: $m, unified_mount: $p, controllers: $c}'
}

probe_mounts() {
    local bpffs="" tracefs="" debugfs=""
    local m
    while IFS= read -r m; do
        case "$m" in
            *" type bpf "*)       bpffs=$(printf '%s' "$m" | awk '{print $3}') ;;
            *" type tracefs "*)   tracefs=$(printf '%s' "$m" | awk '{print $3}') ;;
            *" type debugfs "*)   debugfs=$(printf '%s' "$m" | awk '{print $3}') ;;
        esac
    done < <(mount 2>/dev/null)
    # Default to canonical paths if not present, to keep JSON shape stable.
    [[ -z "$bpffs"   ]] && bpffs="/sys/fs/bpf"
    [[ -z "$tracefs" ]] && tracefs="/sys/kernel/tracing"
    [[ -z "$debugfs" ]] && debugfs="/sys/kernel/debug"
    jq -n --arg b "$bpffs" --arg t "$tracefs" --arg d "$debugfs" \
        '{bpffs: {path: $b}, tracefs: {path: $t}, debugfs: {path: $d}}'
}

probe_privilege() {
    local eff_hex="0x0000000000000000" bnd_hex="0x0000000000000000"
    local eff_dec=0 bnd_dec=0 can_load="false"
    local status status 2>/dev/null || true
    if [[ -r /proc/self/status ]]; then
        eff_hex=$(awk '/^CapEff:/ {printf "0x%016x\n", strtonum("0x"$2); exit}' /proc/self/status 2>/dev/null || echo "0x0000000000000000")
        bnd_hex=$(awk '/^CapBnd:/ {printf "0x%016x\n", strtonum("0x"$2); exit}' /proc/self/status 2>/dev/null || echo "0x0000000000000000")
        eff_dec=$(awk '/^CapEff:/ {print strtonum("0x"$2); exit}' /proc/self/status 2>/dev/null || echo 0)
        bnd_dec=$(awk '/^CapBnd:/ {print strtonum("0x"$2); exit}' /proc/self/status 2>/dev/null || echo 0)
    fi

    # unprivileged_bpf_disabled: 0 = allow, 1 = temporarily disabled,
    # 2 = permanently disabled. Treat values 1 and 2 as "cannot load".
    local ubd=0
    if [[ -r /proc/sys/kernel/unprivileged_bpf_disabled ]]; then
        ubd=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo 0)
    fi

    if (( (eff_dec & CAP_BPF_BIT) == CAP_BPF_BIT )) \
        && (( (eff_dec & CAP_PERFMON_BIT) == CAP_PERFMON_BIT )) \
        && [[ "$ubd" != "1" && "$ubd" != "2" ]]; then
        can_load="true"
    else
        can_load="false"
    fi

    jq -n --arg e "$eff_hex" --arg b "$bnd_hex" --argjson c "$can_load" --argjson u "$ubd" \
        '{effective: $e, bounding: $b, can_load: $c, unprivileged_bpf_disabled: $u}'
}

probe_bpf_helpers() {
    # Look up well-known helpers in /proc/kallsyms. The address column is
    # 0x0000000000000000 when kptr_restrict is set; we only care about
    # symbol presence, not the address.
    local helpers=(
        "bpf_probe_read_user"
        "bpf_probe_read_kernel"
        "bpf_ringbuf_output"
        "bpf_map_lookup_elem"
        "bpf_get_current_pid_tgid"
        "bpf_get_current_cgroup_id"
        "bpf_get_ns_current_pid_tgid"
    )
    local json="{"
    local first=1
    local h
    for h in "${helpers[@]}"; do
        local present="false"
        if [[ -r /proc/kallsyms ]] \
            && grep -E "[[:space:]]${h}(\$|[[:space:]])" /proc/kallsyms >/dev/null 2>&1; then
            present="true"
        fi
        if [[ $first -eq 1 ]]; then first=0; else json+=","; fi
        json+="\"$h\":$present"
    done
    json+="}"
    printf '%s' "$json"
}

probe_container() {
    # Best-effort container detection. We only inspect marker files and
    # /proc/1/cgroup; we never query the daemon, never start anything.
    local runtime="host"
    local in_container="false"
    if [[ -r /run/.containerenv ]]; then
        in_container="true"
        # /run/.containerenv may contain a 'engine=' line. Treat anything
        # other than a known runtime as 'unknown'.
        local engine
        engine=$(grep -E '^engine=' /run/.containerenv 2>/dev/null \
            | head -n1 | cut -d= -f2- | tr -d '"' || true)
        case "$engine" in
            docker|containerd|cri-o|podman) runtime="$engine" ;;
            "")                              runtime="unknown" ;;
            *)                               runtime="unknown" ;;
        esac
    elif [[ -r /.dockerenv ]]; then
        in_container="true"
        runtime="docker"
    else
        # /proc/1/cgroup patterns. A leading '0::/...' line indicates pure
        # cgroup v2 and the absence of a /docker|/containerd|/crio-/ prefix.
        local first_cg
        first_cg=$(awk 'NR==1' /proc/1/cgroup 2>/dev/null || true)
        case "$first_cg" in
            *"/docker-"*)    in_container="true"; runtime="docker" ;;
            *"/containerd-"*) in_container="true"; runtime="containerd" ;;
            *"/crio-"*|*"crio-conmon-"*) in_container="true"; runtime="cri-o" ;;
            *"/kubepods/"*) in_container="true"; runtime="unknown" ;;
            *) in_container="false"; runtime="host" ;;
        esac
    fi
    jq -n --arg r "$runtime" --argjson c "$in_container" \
        '{runtime: $r, in_container: $c}'
}

# ---------------------------------------------------------------------------
# Sensor derivation
# ---------------------------------------------------------------------------
# Hard requirements => status == "blocked" (the sensor literally cannot run).
# Soft requirements => status == "degraded" (the sensor can run with privilege
# or with an admin intervention; we record the named reason).
#
# Per the plan's acceptance criteria, an unprivileged host with readable BTF,
# LSM.bpf in the active list, and cgroup v2 unified reports .status ==
# "degraded" (exit 2) — i.e. soft failures (missing capabilities) do not
# promote to a global "blocked" verdict, only hard failures do.
#
# The loader is treated specially: it can still install / scaffold the agent
# without BPF capabilities, so can_load=false is a soft (degraded) failure for
# the loader, while missing BTF is a hard (blocked) failure.

derive_sensor() {
    # $1=name $2=hard_btf $3=hard_lsm_bpf $4=soft_load $5=soft_cgroup
    # $6=lsm_bpf_present
    # Prints one JSON object: {"status":"...", "reason": "..."|null}.
    local name="$1" hard_btf="$2" hard_lsm="$3" soft_load="$4" soft_cg="$5" have_lsm="$6"
    local status="capable" reason="null"

    if [[ "$hard_btf" == "true" ]]; then
        if [[ "${BTF_READABLE:-false}" != "true" ]]; then
            status="blocked"
            reason="btf-unreadable"
        fi
    fi
    if [[ "$status" == "capable" && "$hard_lsm" == "true" ]]; then
        if [[ "$have_lsm" != "true" ]]; then
            status="blocked"
            reason="lsm-bpf-not-in-list"
        fi
    fi

    if [[ "$status" == "capable" && "$soft_load" == "true" ]]; then
        if [[ "${CAN_LOAD:-false}" != "true" ]]; then
            status="degraded"
            reason="no-cap-bpf-or-perfmon"
        fi
    fi
    if [[ "$status" == "capable" && "$soft_cg" == "true" ]]; then
        if [[ "${CGROUP_MODE:-unknown}" != "unified" ]]; then
            status="degraded"
            reason="cgroup-not-unified"
        fi
    fi
    if [[ "$status" == "capable" ]]; then
        case "$name" in
            identity.bpf)
                if [[ "${HELP_NS_PID_TGID:-false}" != "true" ]]; then
                    status="degraded"
                    reason="helper-missing:bpf_get_ns_current_pid_tgid"
                fi
                ;;
            ringbuf.bpf)
                if [[ "${HELP_RINGBUF_OUTPUT:-false}" != "true" ]]; then
                    status="degraded"
                    reason="helper-missing:bpf_ringbuf_output"
                fi
                ;;
        esac
    fi
    jq -n --arg s "$status" --arg r "$reason" \
        '{status: $s, reason: (if $r == "null" then null else $r end)}'
}

derive_overall_status() {
    local can_load="$1"; shift
    local blocked=0 degraded=0
    local s
    for s in "$@"; do
        case "$s" in
            blocked)  blocked=1 ;;
            degraded) degraded=1 ;;
        esac
    done
    if [[ $blocked -eq 1 ]]; then
        printf '%s' "blocked"; return
    fi
    if [[ $degraded -eq 0 && "$can_load" == "true" ]]; then
        printf '%s' "capable"; return
    fi
    printf '%s' "degraded"
}

# ---------------------------------------------------------------------------
# Synthetic fact injection (test mode only)
# ---------------------------------------------------------------------------
# Mocking is gated on BOTH --test-mode AND BPF_TEST_MODE. When BPF_TEST_MODE
# is "privileged", every probe above has already produced real values; here
# we replace the four critical values that the plan's acceptance criteria
# depend on:
#   * privilege.can_load       -> true
#   * privilege.effective      -> 0x0000000080000000 (CAP_BPF + CAP_PERFMON set)
#   * privilege.bounding       -> 0x000001ffffffffff
#   * privilege.unprivileged_bpf_disabled -> 0
# For BPF_TEST_MODE=blocked we degrade further: BTF unreadable, lsm.bpf
# missing, no-cap.
apply_synthetic_facts() {
    case "${BPF_TEST_MODE:-}" in
        privileged)
            PRIV_EFFECTIVE='0x0000000080000000'
            PRIV_BOUNDING='0x000001ffffffffff'
            PRIV_CAN_LOAD='true'
            PRIV_UBD=0
            ;;
        blocked)
            PRIV_EFFECTIVE='0x0000000000000000'
            PRIV_BOUNDING='0x0000000000000000'
            PRIV_CAN_LOAD='false'
            PRIV_UBD=2
            BTF_PATH_SYN='/sys/kernel/btf/vmlinux'
            BTF_READABLE_SYN='false'
            BTF_SIZE_SYN=0
            BTF_SHA_SYN='null'
            LSM_ACTIVE_SYN='capability,landlock,yama'
            LSM_BPF_IN_LIST_SYN='false'
            ;;
        *)
            echo "$PROG: BPF_TEST_MODE must be 'privileged' or 'blocked' (got '${BPF_TEST_MODE}')" >&2
            exit 2
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Main assembly
# ---------------------------------------------------------------------------
main() {
    local kernel_release kernel_version arch boot_id hostname_val
    kernel_release=$(probe_kernel_release)
    kernel_version=$(probe_kernel_version)
    arch=$(probe_arch)
    boot_id=$(probe_boot_id)
    hostname_val=$(probe_hostname)

    # Collect raw probe JSON.
    local btf_json lsm_json cgroup_json mounts_json priv_json helpers_json container_json
    btf_json=$(probe_btf)
    lsm_json=$(probe_lsm)
    cgroup_json=$(probe_cgroup)
    mounts_json=$(probe_mounts)
    priv_json=$(probe_privilege)
    helpers_json=$(probe_bpf_helpers)
    container_json=$(probe_container)

    # Apply synthetic facts if test mode is active.
    if test_mode_active; then
        apply_synthetic_facts
        if [[ -n "${PRIV_EFFECTIVE:-}" ]]; then
            priv_json=$(jq -n --arg e "$PRIV_EFFECTIVE" --arg b "${PRIV_BOUNDING}" \
                --argjson c "${PRIV_CAN_LOAD}" --argjson u "${PRIV_UBD:-0}" \
                '{effective: $e, bounding: $b, can_load: $c, unprivileged_bpf_disabled: $u}')
        fi
        if [[ -n "${BTF_READABLE_SYN:-}" ]]; then
            btf_json=$(jq -n --arg p "${BTF_PATH_SYN:-/sys/kernel/btf/vmlinux}" \
                --argjson r "$BTF_READABLE_SYN" --argjson s "${BTF_SIZE_SYN:-0}" \
                --arg sha "${BTF_SHA_SYN:-null}" \
                '{path: $p, readable: $r, size: $s, sha256: (if $sha == "null" then null else $sha end)}')
        fi
        if [[ -n "${LSM_ACTIVE_SYN:-}" ]]; then
            lsm_json=$(jq -n --arg l "$LSM_ACTIVE_SYN" --argjson b "${LSM_BPF_IN_LIST_SYN:-false}" \
                '{active: $l, bpf_in_list: $b}')
        fi
    fi

    # Lift individual facts to shell variables so the sensor derivation can
    # branch on them.
    BTF_READABLE=$(jq -r '.readable' <<<"$btf_json")
    BTF_SIZE=$(jq -r '.size' <<<"$btf_json")
    BTF_SHA=$(jq -r '.sha256' <<<"$btf_json")
    BTF_PATH=$(jq -r '.path' <<<"$btf_json")
    LSM_ACTIVE=$(jq -r '.active' <<<"$lsm_json")
    LSM_BPF_IN_LIST=$(jq -r '.bpf_in_list' <<<"$lsm_json")
    CGROUP_MODE=$(jq -r '.mode' <<<"$cgroup_json")
    CAN_LOAD=$(jq -r '.can_load' <<<"$priv_json")
    HELP_NS_PID_TGID=$(jq -r '.["bpf_get_ns_current_pid_tgid"]' <<<"$helpers_json")
    HELP_RINGBUF_OUTPUT=$(jq -r '.["bpf_ringbuf_output"]' <<<"$helpers_json")

    local s_process s_file s_network s_dns s_syscall s_lsm s_identity s_ringbuf s_loader
    s_process=$(derive_sensor   process.bpf   true false true true  "$LSM_BPF_IN_LIST")
    s_file=$(derive_sensor     file.bpf      true false true true  "$LSM_BPF_IN_LIST")
    s_network=$(derive_sensor  network.bpf   true false true true  "$LSM_BPF_IN_LIST")
    s_dns=$(derive_sensor      dns.bpf       true false true true  "$LSM_BPF_IN_LIST")
    s_syscall=$(derive_sensor  syscall.bpf   true false true true  "$LSM_BPF_IN_LIST")
    s_lsm=$(derive_sensor      lsm.bpf       true true  true true  "$LSM_BPF_IN_LIST")
    s_identity=$(derive_sensor identity.bpf  true false true true  "$LSM_BPF_IN_LIST")
    s_ringbuf=$(derive_sensor  ringbuf.bpf   true false true true  "$LSM_BPF_IN_LIST")
    s_loader=$(derive_sensor   loader        true false true false "$LSM_BPF_IN_LIST")

    local overall
    overall=$(derive_overall_status "$CAN_LOAD" \
        "$(jq -r .status <<<"$s_process")" \
        "$(jq -r .status <<<"$s_file")" \
        "$(jq -r .status <<<"$s_network")" \
        "$(jq -r .status <<<"$s_dns")" \
        "$(jq -r .status <<<"$s_syscall")" \
        "$(jq -r .status <<<"$s_lsm")" \
        "$(jq -r .status <<<"$s_identity")" \
        "$(jq -r .status <<<"$s_ringbuf")" \
        "$(jq -r .status <<<"$s_loader")")

    # Build the top-level JSON payload.
    local blocked_reason="null"
    case "$overall" in
        blocked)
            blocked_reason="one or more sensors are blocked; see .sensors"
            ;;
        degraded)
            blocked_reason="null"
            ;;
        capable)
            blocked_reason="null"
            ;;
    esac

    local payload
    payload=$(jq -n \
        --arg     schema_version "1" \
        --arg     status "$overall" \
        --arg     blocked_reason "$blocked_reason" \
        --argjson kernel "$(jq -n \
            --arg r "$kernel_release" \
            --arg v "$kernel_version" \
            --arg a "$arch" \
            --arg b "$boot_id" \
            --arg h "$hostname_val" \
            '{release: $r, version: $v, arch: $a, boot_id: $b, hostname: $h}')" \
        --argjson btf "$btf_json" \
        --argjson lsm "$lsm_json" \
        --argjson cgroup "$cgroup_json" \
        --argjson mounts "$mounts_json" \
        --argjson privilege "$priv_json" \
        --argjson helpers "$helpers_json" \
        --argjson container "$container_json" \
        --argjson sensors "$(jq -n \
            --argjson process   "$s_process" \
            --argjson file      "$s_file" \
            --argjson network   "$s_network" \
            --argjson dns       "$s_dns" \
            --argjson syscall   "$s_syscall" \
            --argjson lsm       "$s_lsm" \
            --argjson identity  "$s_identity" \
            --argjson ringbuf   "$s_ringbuf" \
            --argjson loader    "$s_loader" \
            '{
                "process.bpf":   $process,
                "file.bpf":      $file,
                "network.bpf":   $network,
                "dns.bpf":       $dns,
                "syscall.bpf":   $syscall,
                "lsm.bpf":       $lsm,
                "identity.bpf":  $identity,
                "ringbuf.bpf":   $ringbuf,
                "loader":        $loader
            }')" \
        '{
            schema_version: ($schema_version | tonumber),
            status: $status,
            blocked_reason: $blocked_reason,
            kernel: $kernel,
            features: {
                btf: $btf,
                lsm: $lsm,
                cgroup: $cgroup,
                mounts: $mounts,
                bpf: {
                    helpers: $helpers
                }
            },
            privilege: $privilege,
            container: $container,
            sensors: $sensors
        }')

    # Emit.
    if [[ -n "$JSON_PATH" ]]; then
        local dir
        dir=$(dirname -- "$JSON_PATH")
        [[ -n "$dir" && "$dir" != "." ]] && mkdir -p "$dir" 2>/dev/null || true
        local tmp="${JSON_PATH}.tmp.$$"
        printf '%s\n' "$payload" > "$tmp"
        mv -f "$tmp" "$JSON_PATH"
    else
        printf '%s\n' "$payload"
    fi

    case "$overall" in
        blocked) exit 77 ;;
        degraded) exit 2 ;;
        capable) exit 0 ;;
    esac
}

main "$@"
