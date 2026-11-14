#!/usr/bin/env bash
# Boot the pinned arm64 Ubuntu cloud image and run the 0.3 arm64
# functional row: --version, doctor, record, query, and replay.
#
# This runner exists because the lab host is x86_64 and there is no native
# aarch64 KVM host available. The arm64 guest is therefore booted with QEMU
# TCG system emulation. That is a FUNCTIONAL smoke only: it proves the
# aarch64 static binary loads and its BPF sensors attach on a real aarch64
# kernel, and it is NOT a performance measurement. Every evidence file
# records emulated=true and the TCG caveat.
#
# The row is fail-closed: a missing/unpinned image, a non-aarch64 or
# non-static binary, a failed boot, a failed cloud-init, a failed doctor,
# a record that produces no events, a missing FileOpen path, or a replay
# that does not reproduce the recorded event count fails the run (exit 1).
# The VM is torn down on exit unless --keep is given.
#
# Usage: scripts/vm/run-arm64.sh [options]
#
# Options:
#   --image <name>        image key from scripts/vm/images.json
#                         (default: ubuntu-24.04-arm64)
#   --name <instance>     lab instance name (default: arm64-tcg)
#   --binary <path>       static aarch64 binary
#                         (default: target/release/ebpf-fleet-aarch64)
#   --stamp <stamp>       output directory name under target/vm/arm64
#                         (default: UTC timestamp)
#   --record-seconds <n>  record window (default: 8; guest time, so wall
#                         time is longer under TCG)
#   --boot-timeout <n>    SSH boot budget in seconds (default: 900)
#   --cpus <n>            guest vCPUs (default: 4)
#   --memory <mib>        guest memory in MiB (default: 4096)
#   --keep                leave the VM running after the row
#   --help                show this help
#
# Run inside the development shell so qemu, cloud-localds, ssh and jq are
# on PATH:
#
#   nix develop --impure --command scripts/vm/run-arm64.sh
#
# Output (gitignored, under target/vm):
#   target/vm/arm64/<stamp>/row.json           structured evidence
#   target/vm/arm64/<stamp>/row.txt            human-readable summary
#   target/vm/arm64/<stamp>/                    raw artifacts
#
# Environment:
#   VM_LAB_ROOT       state root shared with scripts/vm/lab.sh
#   VM_ARM64_UEFI     AArch64 UEFI firmware (auto-detected otherwise)

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/../.." && pwd -P)"
lab="$script_dir/lab.sh"
images_json="$script_dir/images.json"
vm_root="${VM_LAB_ROOT:-$repo_root/target/vm}"
arm64_root="$vm_root/arm64"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
image="ubuntu-24.04-arm64"
instance="arm64-tcg"
binary="$repo_root/target/release/ebpf-fleet-aarch64"
record_seconds=8
boot_timeout=900
cpus=4
memory_mb=4096
keep=0
probe_dir="/tmp/arm64-probe"
probe_path="$probe_dir/created-by-arm64"

out_root=""
binary_sha=""
binary_size=0
binary_version=""
version_rc=1
host_name=""
host_arch=""
host_kernel=""
image_sha=""
image_arch=""
accel=""
boot_ok=0
boot_seconds=0
cloud_init_ok=0
cloud_init_seconds=0
guest_kernel=""
guest_uname=""
guest_arch=""
os_pretty=""
btf_present=0
btf_size=0
btf_sha=""
lsm=""
unprivileged=""
guest_sha=""
doctor_rc=1
doctor_kernel_ok=false
doctor_btf_ok=false
record_rc=1
record_events=0
decode_errors=0
distinct_stacks=""
kinds_rc=1
paths_rc=1
counts='{}'
file_open_count=0
process_count=0
probe_seen=0
replay_rc=1
replay_lines=0
replay_valid=0
first_kind=""
checks='[]'
notes='[]'
row_status="fail"
row_start=$SECONDS
teardown_done=0

info() { printf 'arm64: %s\n' "$*" >&2; }
warn() { printf 'arm64: warning: %s\n' "$*" >&2; }
die() {
  printf 'arm64: error: %s\n' "$*" >&2
  exit 1
}

usage() {
  awk 'NR > 1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"
}

# ---------------------------------------------------------------------------
# arguments
# ---------------------------------------------------------------------------

while (($# > 0)); do
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    --image | --name | --binary | --stamp | --record-seconds | --boot-timeout | --cpus | --memory)
      [[ $# -ge 2 && -n "$2" ]] || die "option $1 needs a value"
      case "$1" in
        --image) image="$2" ;;
        --name) instance="$2" ;;
        --binary) binary="$2" ;;
        --stamp) stamp="$2" ;;
        --record-seconds) record_seconds="$2" ;;
        --boot-timeout) boot_timeout="$2" ;;
        --cpus) cpus="$2" ;;
        --memory) memory_mb="$2" ;;
      esac
      shift 2
      ;;
    --image=*) image="${1#*=}"; shift ;;
    --name=*) instance="${1#*=}"; shift ;;
    --binary=*) binary="${1#*=}"; shift ;;
    --stamp=*) stamp="${1#*=}"; shift ;;
    --record-seconds=*) record_seconds="${1#*=}"; shift ;;
    --boot-timeout=*) boot_timeout="${1#*=}"; shift ;;
    --cpus=*) cpus="${1#*=}"; shift ;;
    --memory=*) memory_mb="${1#*=}"; shift ;;
    --keep) keep=1; shift ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

[[ "$record_seconds" =~ ^[0-9]+$ ]] || die "--record-seconds must be an integer"
((record_seconds >= 4)) || die "--record-seconds must be at least 4"
[[ "$boot_timeout" =~ ^[0-9]+$ ]] || die "--boot-timeout must be an integer"
[[ "$cpus" =~ ^[0-9]+$ ]] || die "--cpus must be an integer"
[[ "$memory_mb" =~ ^[0-9]+$ ]] || die "--memory must be an integer"
[[ "$stamp" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "--stamp must be letters, digits, dot, underscore or hyphen"
[[ "$instance" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || die "--name must be lowercase letters, digits and hyphens"

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# evidence helpers
# ---------------------------------------------------------------------------

add_check() {
  # add_check <name> <true|false> <required> <detail>
  checks="$(jq -c --arg n "$1" --argjson ok "$2" --argjson req "$3" --arg d "$4" \
    '. + [{name: $n, ok: $ok, required: $req, detail: $d}]' <<<"$checks")"
}

add_note() {
  notes="$(jq -c --arg n "$1" '. + [$n]' <<<"$notes")"
}

failed_required() {
  jq -r '[.[] | select(.required and (.ok | not)) | .name] | join(", ")' <<<"$checks"
}

write_row() {
  local duration failed
  duration=$((SECONDS - row_start))
  failed="$(failed_required)"
  if [[ -z "$failed" ]]; then
    row_status="pass"
  else
    row_status="fail"
  fi
  jq -n \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg runner "scripts/vm/run-arm64.sh" \
    --arg status "$row_status" \
    --arg host_name "$host_name" \
    --arg host_arch "$host_arch" \
    --arg host_kernel "$host_kernel" \
    --arg image "$image" \
    --arg image_sha "$image_sha" \
    --arg image_arch "$image_arch" \
    --arg accel "$accel" \
    --argjson emulated "$([[ "$accel" == "tcg" ]] && printf true || printf false)" \
    --arg instance "$instance" \
    --argjson boot_ok "$boot_ok" \
    --argjson boot_seconds "$boot_seconds" \
    --argjson cloud_init_ok "$cloud_init_ok" \
    --argjson cloud_init_seconds "$cloud_init_seconds" \
    --arg guest_arch "$guest_arch" \
    --arg guest_kernel "$guest_kernel" \
    --arg guest_uname "$guest_uname" \
    --arg os_pretty "$os_pretty" \
    --argjson btf_present "$btf_present" \
    --argjson btf_size "$btf_size" \
    --arg btf_sha "$btf_sha" \
    --arg lsm "$lsm" \
    --arg unprivileged "$unprivileged" \
    --arg binary "$binary" \
    --arg binary_sha "$binary_sha" \
    --argjson binary_size "$binary_size" \
    --arg binary_version "$binary_version" \
    --arg guest_sha "$guest_sha" \
    --argjson doctor_rc "$doctor_rc" \
    --argjson doctor_kernel_ok "$doctor_kernel_ok" \
    --argjson doctor_btf_ok "$doctor_btf_ok" \
    --argjson record_rc "$record_rc" \
    --argjson record_events "$record_events" \
    --argjson record_seconds "$record_seconds" \
    --argjson version_rc "$version_rc" \
    --argjson decode_errors "$decode_errors" \
    --argjson kinds_rc "$kinds_rc" \
    --argjson paths_rc "$paths_rc" \
    --argjson counts "$counts" \
    --arg probe_path "$probe_path" \
    --argjson file_open_count "$file_open_count" \
    --argjson process_count "$process_count" \
    --argjson probe_seen "$probe_seen" \
    --argjson replay_rc "$replay_rc" \
    --argjson replay_lines "$replay_lines" \
    --argjson replay_valid "$replay_valid" \
    --arg first_kind "$first_kind" \
    --argjson duration "$duration" \
    --argjson checks "$checks" \
    --argjson notes "$notes" \
    '{
      schema_version: 1,
      runner: $runner,
      generated_at: $generated_at,
      status: $status,
      host: {name: $host_name, arch: $host_arch, kernel: $host_kernel},
      emulation: {
        accelerator: $accel,
        emulated: $emulated,
        caveat: "QEMU TCG system emulation: functional smoke only, not a performance measurement"
      },
      image: {key: $image, arch: $image_arch, sha256: $image_sha},
      instance: $instance,
      boot: {ok: ($boot_ok == 1), seconds: $boot_seconds},
      cloud_init: {ok: ($cloud_init_ok == 1), seconds: $cloud_init_seconds},
      guest: {
        arch: $guest_arch,
        kernel: $guest_kernel,
        uname: $guest_uname,
        os_pretty_name: $os_pretty,
        btf: {present: ($btf_present == 1), size_bytes: $btf_size, sha256: $btf_sha},
        lsm: $lsm,
        unprivileged_bpf_disabled: $unprivileged
      },
      binary: {
        host_path: $binary,
        host_sha256: $binary_sha,
        host_size_bytes: $binary_size,
        guest_path: "/tmp/ebpf-fleet",
        guest_sha256: $guest_sha,
        sha256_match: ($guest_sha == $binary_sha),
        version: $binary_version
      },
      checks: {
        version: {exit_code: $version_rc},
        doctor: {exit_code: $doctor_rc, kernel_ok: $doctor_kernel_ok, btf_ok: $doctor_btf_ok},
        record: {exit_code: $record_rc, seconds: $record_seconds, events: $record_events, decode_errors: $decode_errors},
        query: {kinds_exit_code: $kinds_rc, file_paths_exit_code: $paths_rc, kinds: $counts, file_open_count: $file_open_count, process_count: $process_count, probe_path: $probe_path},
        replay: {exit_code: $replay_rc, lines: $replay_lines, valid_jsonl: ($replay_valid == 1), first_kind: $first_kind}
      },
      result: {
        required_failures: ([$checks[] | select(.required and (.ok | not)) | .name]),
        all_checks: $checks
      },
      notes: $notes,
      duration_s: $duration
    }' >"$out_root/row.json"
}

# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------

preflight() {
  have jq || die "jq is required"
  have file || die "file is required"
  have readelf || die "readelf is required"
  [[ -x "$lab" ]] || die "missing executable lab script: $lab"
  [[ -f "$images_json" ]] || die "missing image catalogue: $images_json"
  [[ -f "$binary" ]] || die "aarch64 binary not found: $binary (build it with scripts/build-static.sh --arch aarch64 --btf <btf>)"
  [[ -x "$binary" ]] || die "binary is not executable: $binary"

  local machine desc
  machine="$(readelf -h "$binary" | sed -n 's/.*Machine:[[:space:]]*//p' | head -n 1)"
  case "$machine" in
    *AArch64*) ;;
    *) die "$binary is not an AArch64 binary (ELF machine: '$machine')" ;;
  esac
  desc="$(file -b "$binary")"
  case "$desc" in
    *"static-pie linked"* | *"statically linked"*) ;;
    *) die "refusing a non-static binary ($binary): $desc" ;;
  esac
  if readelf -d "$binary" 2>/dev/null | grep -q NEEDED; then
    die "$binary has dynamic NEEDED entries; the guest has no matching ARM64 libc"
  fi
  binary_sha="$(sha256sum "$binary" | awk '{print $1}')"
  binary_size="$(stat -c %s "$binary")"

  jq -e --arg k "$image" '.images[$k] != null' "$images_json" >/dev/null 2>&1 ||
    die "unknown image '$image' (see $images_json)"
  [[ "$(jq -r --arg k "$image" '.images[$k].status // ""' "$images_json")" == "pinned" ]] ||
    die "image '$image' is not pinned in $images_json"
  image_sha="$(jq -r --arg k "$image" '.images[$k].sha256 // ""' "$images_json")"
  image_arch="$(jq -r --arg k "$image" '.images[$k].arch // ""' "$images_json")"
  [[ "$image_arch" == "aarch64" ]] || die "image '$image' is $image_arch, not aarch64"

  host_name="$(hostname -s 2>/dev/null || hostname)"
  host_arch="$(uname -m)"
  host_kernel="$(uname -r)"
  accel="$(jq -r --arg k "$image" --arg host "$host_arch" \
    'if (.images[$k].arch == $host) then "kvm" else "tcg" end' "$images_json")"
  info "host: $host_name $host_arch kernel $host_kernel"
  info "image: $image ($image_arch, sha256 ${image_sha:0:12}...) -> accel $accel"
  info "binary: $binary ($(du -h "$binary" | cut -f1), sha256 ${binary_sha:0:12}...)"
  if [[ "$accel" == "tcg" ]]; then
    warn "TCG system emulation: functional smoke only, NOT a performance row"
  fi
}

preflight_output() {
  mkdir -p "$arm64_root"
  out_root="$arm64_root/$stamp"
  [[ ! -e "$out_root" ]] || die "output already exists: $out_root (pass a different --stamp)"
  mkdir -p "$out_root"
  out_root="$(cd -- "$out_root" && pwd -P)"
}

# ---------------------------------------------------------------------------
# guest helpers
# ---------------------------------------------------------------------------

guest() {
  "$lab" run --name "$instance" -- "$@"
}

write_activity_script() {
  cat >"$out_root/activity.sh" <<ACTIVITY
#!/usr/bin/env bash
# Generated by scripts/vm/run-arm64.sh. Deterministic process and file
# activity for the record window; the fixed marker path is what the row
# looks for in the decoded FileOpen paths.
set -u
duration="\${1:-6}"
case "\$duration" in
  '' | *[!0-9]*) duration=6 ;;
esac
probe_dir="$probe_dir"
marker="$probe_path"
rm -rf "\$probe_dir"
mkdir -p "\$probe_dir"
printf 'arm64 activity marker\n' >"\$marker"
deadline=\$((SECONDS + duration))
i=0
while ((SECONDS < deadline)); do
  i=\$((i + 1))
  cat "\$marker" >/dev/null 2>&1 || true
  head -c 16 /etc/hostname >/dev/null 2>&1 || true
  /bin/true || true
  /bin/false || true
  /bin/sh -c 'exit 3' || true
  printf 'arm64 scratch %s\n' "\$i" >"\$probe_dir/scratch.txt"
  cat "\$probe_dir/scratch.txt" >/dev/null 2>&1 || true
  rm -f "\$probe_dir/scratch.txt"
  ls "\$probe_dir" >/dev/null 2>&1 || true
  sleep 0.2
done
/bin/sh -c 'exit 7' || true
echo arm64-activity-ok
ACTIVITY
  chmod 0755 "$out_root/activity.sh"
}

# ---------------------------------------------------------------------------
# row body
# ---------------------------------------------------------------------------

cleanup() {
  local rc=$?
  trap - EXIT
  if ((teardown_done == 0)) && ((keep == 0)); then
    "$lab" down --name "$instance" >/dev/null 2>&1 ||
      warn "could not tear down $instance; run: scripts/vm/lab.sh down --name $instance"
  elif ((keep)); then
    info "instance $instance left running; stop it with: scripts/vm/lab.sh down --name $instance"
  fi
  exit "$rc"
}
trap cleanup EXIT

run_row() {
  local start

  # A leftover instance with the same name would boot stale overlay state.
  if [[ -d "$vm_root/instances/$instance" ]]; then
    "$lab" down --name "$instance" --purge >/dev/null 2>&1 || true
  fi

  # ---- boot -------------------------------------------------------------
  info "bootstrap: verify/download the pinned arm64 image"
  "$lab" bootstrap --image "$image" >"$out_root/bootstrap.log" 2>&1 ||
    die "bootstrap failed (see $out_root/bootstrap.log)"
  add_check "bootstrap" true true "pinned image verified by scripts/vm/lab.sh"

  info "boot: QEMU $accel $image as instance $instance"
  start=$SECONDS
  if "$lab" up --image "$image" --name "$instance" --accel "$accel" \
    --cloud-init lean --timeout "$boot_timeout" --cpus "$cpus" --memory "$memory_mb" \
    >"$out_root/up.log" 2>&1; then
    boot_ok=1
    boot_seconds=$((SECONDS - start))
    add_check "boot" true true "SSH ready after ${boot_seconds}s (${boot_timeout}s budget)"
  else
    add_check "boot" false true "lab.sh up failed; see $out_root/up.log and target/vm/instances/$instance/logs"
    return 1
  fi
  cp -f "$vm_root/instances/$instance/logs/console.log" "$out_root/console.log" 2>/dev/null || true
  cp -f "$vm_root/instances/$instance/instance.json" "$out_root/instance.json" 2>/dev/null || true

  # ---- guest facts + cloud-init ----------------------------------------
  info "wait: cloud-init status (lean seed has no apt step)"
  start=$SECONDS
  local deadline=$((SECONDS + 300)) ready=""
  while ((SECONDS < deadline)); do
    if ready="$(guest 'cloud-init status 2>/dev/null | head -n 1; id -un')" &&
      [[ "$ready" == *"status: done"* ]] && [[ "$ready" == *fleet* ]]; then
      cloud_init_ok=1
      cloud_init_seconds=$((SECONDS - start))
      break
    fi
    sleep 5
  done
  if ((cloud_init_ok)); then
    add_check "cloud_init" true true "cloud-init done after ${cloud_init_seconds}s"
  else
    add_check "cloud_init" false true "cloud-init did not report done within 300s: ${ready:-no output}"
  fi

  guest 'uname -a' >"$out_root/guest-uname.txt" 2>&1 || true
  guest 'cat /etc/os-release' >"$out_root/guest-os-release.txt" 2>&1 || true
  guest 'uname -m; uname -r' >"$out_root/guest-arch-kernel.txt" 2>&1 || true
  guest 'ls -l /sys/kernel/btf/vmlinux; wc -c < /sys/kernel/btf/vmlinux; sha256sum /sys/kernel/btf/vmlinux' \
    >"$out_root/guest-btf.txt" 2>&1 || true
  guest 'cat /sys/kernel/security/lsm 2>/dev/null || echo unavailable; cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo unknown' \
    >"$out_root/guest-security.txt" 2>&1 || true
  guest 'cloud-init status --long' >"$out_root/guest-cloud-init.txt" 2>&1 || true

  guest_arch="$(sed -n 1p "$out_root/guest-arch-kernel.txt" 2>/dev/null | tr -d '[:space:]')"
  guest_kernel="$(sed -n 2p "$out_root/guest-arch-kernel.txt" 2>/dev/null | tr -d '[:space:]')"
  guest_uname="$(sed -n 1p "$out_root/guest-uname.txt" 2>/dev/null || true)"
  os_pretty="$(sed -n 's/^PRETTY_NAME=//p' "$out_root/guest-os-release.txt" 2>/dev/null | tr -d '"' | head -n 1)"
  btf_size="$(sed -n 's/^\([0-9][0-9]*\)$/\1/p' "$out_root/guest-btf.txt" 2>/dev/null | head -n 1)"
  btf_size="${btf_size:-0}"
  btf_sha="$(sed -n 's/^\([0-9a-f]\{64\}\) .*/\1/p' "$out_root/guest-btf.txt" 2>/dev/null | head -n 1)"
  [[ "$(sed -n 1p "$out_root/guest-btf.txt" 2>/dev/null)" == *"/sys/kernel/btf/vmlinux"* ]] && btf_present=1
  lsm="$(sed -n 1p "$out_root/guest-security.txt" 2>/dev/null || true)"
  unprivileged="$(sed -n 2p "$out_root/guest-security.txt" 2>/dev/null || true)"

  if [[ "$guest_arch" == "aarch64" ]]; then
    add_check "guest_arch" true true "guest uname -m is aarch64"
  else
    add_check "guest_arch" false true "guest uname -m is '${guest_arch:-unknown}', expected aarch64"
  fi
  if ((btf_present)) && ((btf_size > 0)); then
    add_check "guest_btf" true true "/sys/kernel/btf/vmlinux present, ${btf_size} bytes, sha256 ${btf_sha:0:12}..."
  else
    add_check "guest_btf" false true "guest /sys/kernel/btf/vmlinux missing or empty"
  fi

  # ---- copy the static aarch64 binary ----------------------------------
  if "$lab" copy --name "$instance" "$binary" /tmp/ebpf-fleet >"$out_root/copy.log" 2>&1; then
    guest chmod 0755 /tmp/ebpf-fleet >>"$out_root/copy.log" 2>&1 || true
    guest_sha="$(guest 'sha256sum /tmp/ebpf-fleet' 2>/dev/null | awk '{print $1}')" || guest_sha=""
    if [[ "$guest_sha" == "$binary_sha" ]]; then
      add_check "binary_upload" true true "guest sha256 matches host ($binary_sha)"
    else
      add_check "binary_upload" false true "guest sha256 '${guest_sha:-missing}' != host '$binary_sha'"
    fi
  else
    add_check "binary_upload" false true "lab.sh copy failed; see $out_root/copy.log"
  fi

  # ---- --version -------------------------------------------------------
  binary_version="$(guest /tmp/ebpf-fleet --version 2>"$out_root/version.err" || true)"
  if [[ "$binary_version" == ebpf-fleet* ]]; then
    version_rc=0
    add_check "version" true true "$binary_version"
  else
    add_check "version" false true "guest could not run --version: '${binary_version:-<empty>}' (see $out_root/version.err)"
    return 1
  fi

  # ---- doctor --json ---------------------------------------------------
  doctor_rc=0
  guest sudo -n /tmp/ebpf-fleet doctor --json >"$out_root/doctor.json" 2>"$out_root/doctor.err" || doctor_rc=$?
  if jq -e 'type == "array"' "$out_root/doctor.json" >/dev/null 2>&1; then
    doctor_kernel_ok="$(jq -r '[.[] | select(.name == "kernel") | .ok] | first // false' "$out_root/doctor.json")"
    doctor_btf_ok="$(jq -r '[.[] | select(.name == "btf") | .ok] | first // false' "$out_root/doctor.json")"
  fi
  if ((doctor_rc == 0)) && [[ "$doctor_kernel_ok" == "true" && "$doctor_btf_ok" == "true" ]]; then
    add_check "doctor" true true "doctor --json exit 0; kernel+btf ok"
  else
    add_check "doctor" false true "doctor --json exit $doctor_rc kernel_ok=$doctor_kernel_ok btf_ok=$doctor_btf_ok"
  fi

  # ---- record + query + replay ----------------------------------------
  write_activity_script
  "$lab" copy --name "$instance" "$out_root/activity.sh" /tmp/arm64-activity.sh >"$out_root/copy-activity.log" 2>&1 ||
    add_check "activity_upload" false true "could not upload the activity script"
  guest chmod 0755 /tmp/arm64-activity.sh >>"$out_root/copy-activity.log" 2>&1 || true
  guest sudo -n rm -rf "$probe_dir" /tmp/arm64.fleet /tmp/arm64-activity.log >/dev/null 2>&1 || true

  local record_pid activity_rc=0
  local activity_window=$((record_seconds - 2))
  ((activity_window >= 1)) || activity_window=1
  guest sudo -n /tmp/ebpf-fleet record --for "$record_seconds" --out /tmp/arm64.fleet \
    >"$out_root/record.out" 2>"$out_root/record.err" &
  record_pid=$!
  sleep 2
  guest env PROBE_DIR="$probe_dir" bash /tmp/arm64-activity.sh "$activity_window" \
    >"$out_root/activity.out" 2>"$out_root/activity.err" || activity_rc=$?
  record_rc=0
  wait "$record_pid" || record_rc=$?

  if ((record_rc == 0)); then
    add_check "record" true true "record --for $record_seconds exited 0 while activity was generated"
  else
    add_check "record" false true "record exited $record_rc; see $out_root/record.err"
  fi
  if [[ "$activity_rc" == "0" ]]; then
    add_check "activity" true true "deterministic activity for ${activity_window}s completed"
  else
    add_check "activity" false true "activity generator exited $activity_rc; see $out_root/activity.err"
  fi
  # record's summary line has grown over releases ("recorded N events (D
  # decode errors)" and "recorded N events and M distinct stacks (D decode
  # errors)"); parse both instead of failing the row on a wording change.
  if grep -Eq 'recorded [0-9]+ events' "$out_root/record.err" 2>/dev/null; then
    record_events="$(sed -n 's/.*recorded \([0-9][0-9]*\) events.*/\1/p' "$out_root/record.err" | head -n 1)"
    decode_errors="$(sed -n 's/.*(\([0-9][0-9]*\) decode errors).*/\1/p' "$out_root/record.err" | head -n 1)"
    distinct_stacks="$(sed -n 's/.*and \([0-9][0-9]*\) distinct stacks.*/\1/p' "$out_root/record.err" | head -n 1)"
  fi
  record_events="${record_events:-0}"
  decode_errors="${decode_errors:-0}"
  if ((record_events > 0)); then
    add_check "record_events" true true "recorded $record_events events ($decode_errors decode errors)"
  else
    add_check "record_events" false true "recording reported no events; see $out_root/record.err"
  fi

  if ((record_rc == 0 && record_events > 0)); then
    # lab.sh run hands the command to `ssh ... --`, which joins argv with
    # spaces; quote the SQL ourselves or the guest shell splits "count(*)".
    kinds_rc=0
    local sql_kinds remote_kinds
    sql_kinds="select kind, count(*) as n from events group by kind order by kind"
    remote_kinds="sudo -n /tmp/ebpf-fleet query /tmp/arm64.fleet $(printf '%q' "$sql_kinds")"
    guest "$remote_kinds" \
      >"$out_root/query-kinds.txt" 2>"$out_root/query-kinds.err" || kinds_rc=$?
    if ((kinds_rc == 0)); then
      counts="$(awk -F'|' 'NF >= 4 {
          k = $2; n = $3
          gsub(/^[[:space:]]+|[[:space:]]+$/, "", k)
          gsub(/^[[:space:]]+|[[:space:]]+$/, "", n)
          if (k != "" && k != "kind" && n ~ /^[0-9]+$/) print k "\t" n
        }' "$out_root/query-kinds.txt" | jq -R -s '
          split("\n") | map(select(length > 0) | split("\t") | {(.[0]): (.[1] | tonumber)}) | add // {}')"
      file_open_count="$(jq -r '.["FileOpen"] // 0' <<<"$counts")"
      local fork_n exec_n exit_n
      fork_n="$(jq -r '.["ProcessFork"] // 0' <<<"$counts")"
      exec_n="$(jq -r '.["ProcessExec"] // 0' <<<"$counts")"
      exit_n="$(jq -r '.["ProcessExit"] // 0' <<<"$counts")"
      process_count=$((fork_n + exec_n + exit_n))
    fi
    if ((kinds_rc == 0 && file_open_count > 0)); then
      add_check "query_kinds" true true "kinds: $(jq -c . <<<"$counts")"
    else
      add_check "query_kinds" false true "FileOpen=$file_open_count types; kinds: $(jq -c . <<<"$counts")"
    fi

    paths_rc=0
    local sql_paths remote_paths
    sql_paths="select path, count(*) as n from events where kind = 'FileOpen' group by path order by n desc limit 25"
    remote_paths="sudo -n /tmp/ebpf-fleet query /tmp/arm64.fleet $(printf '%q' "$sql_paths")"
    guest "$remote_paths" \
      >"$out_root/query-file-paths.txt" 2>"$out_root/query-file-paths.err" || paths_rc=$?
    if ((paths_rc == 0)) && grep -qF -- "$probe_path" "$out_root/query-file-paths.txt"; then
      probe_seen=1
    fi

    replay_rc=0
    guest sudo -n /tmp/ebpf-fleet replay /tmp/arm64.fleet \
      >"$out_root/replay.jsonl" 2>"$out_root/replay.err" || replay_rc=$?
    replay_lines="$(wc -l <"$out_root/replay.jsonl" 2>/dev/null || echo 0)"
    replay_lines="${replay_lines//[[:space:]]/}"
    local first_line
    first_line="$(head -n 1 "$out_root/replay.jsonl" 2>/dev/null || true)"
    if [[ -n "$first_line" ]] && jq -e 'type == "object" and (.kind | type == "string")' >/dev/null 2>&1 <<<"$first_line"; then
      replay_valid=1
      first_kind="$(jq -r '.kind' <<<"$first_line")"
    fi
    if ((replay_rc == 0 && replay_valid && replay_lines == record_events)); then
      add_check "replay" true true "replay exit 0, $replay_lines lines == recorded events, first kind=$first_kind"
    else
      add_check "replay" false true "replay exit $replay_rc lines=$replay_lines recorded=$record_events valid=$replay_valid"
    fi
    # The probe path may not fit in the SQL top-25 table when the guest has
    # a large variety of opened paths; the replay stream has every event, so
    # use it to confirm the file sensor really decoded a /tmp path.
    if ((probe_seen == 0 && replay_valid)) && grep -qF -- "$probe_path" "$out_root/replay.jsonl" 2>/dev/null; then
      probe_seen=1
      add_note "FileOpen '$probe_path' verified from the replay JSONL stream (not only the SQL top-25 table)"
    fi
    if ((paths_rc != 0)); then
      add_check "file_open_paths" false true "FileOpen path query exited $paths_rc; see $out_root/query-file-paths.err"
    elif ((file_open_count > 0 && probe_seen)); then
      add_check "file_open_paths" true true "FileOpen=$file_open_count; deterministic probe path '$probe_path' decoded"
    else
      add_check "file_open_paths" false true "FileOpen=$file_open_count; probe path '$probe_path' not decoded"
    fi
  else
    add_check "query_kinds" false true "skipped: record produced no events"
    add_check "file_open_paths" false true "skipped: record produced no events"
    add_check "replay" false true "skipped: record produced no events"
  fi

  add_note "arm64 row booted via QEMU $accel on $host_arch host $host_name: functional smoke only, not performance"
  add_note "guest kernel $guest_kernel, BTF ${btf_size} bytes (sha256 ${btf_sha:0:12}...), LSM '$lsm'"
  if [[ -n "$distinct_stacks" ]]; then
    add_note "record reported $distinct_stacks distinct stacks (stack-capture path present in this build)"
  fi
  if [[ "$lsm" != *bpf* ]]; then
    add_note "guest LSM list has no bpf: the file sensor uses the kprobe/pt_regs fallback (expected on this kernel)"
  fi
  write_row
  row_status="$(jq -r '.status' "$out_root/row.json")"
  if [[ "$row_status" != "pass" ]]; then
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

preflight
preflight_output

if run_row; then
  status=0
else
  status=1
fi
if [[ ! -f "$out_root/row.json" ]]; then
  # A very early failure (boot/version) must still leave structured evidence.
  write_row
fi

jq -r '
  "arm64 functional row: \(.status | ascii_upcase) (emulated=\(.emulation.emulated), accel=\(.emulation.accelerator))",
  "  host:   \(.host.name) \(.host.arch) \(.host.kernel)",
  "  image:  \(.image.key) sha256 \(.image.sha256[0:12])...",
  "  guest:  \(.guest.arch) \(.guest.kernel) BTF \(.guest.btf.size_bytes) bytes",
  "  binary: \(.binary.version) sha256 \(.binary.host_sha256[0:12])... guest_match=\(.binary.sha256_match)",
  "  record: \(.checks.record.events) events, \(.checks.record.decode_errors) decode errors",
  "  query:  kinds=\(.checks.query.kinds | tojson)",
  "  replay: \(.checks.replay.lines) lines first_kind=\(.checks.replay.first_kind)",
  (if (.result.required_failures | length) > 0 then "  FAILED: " + (.result.required_failures | join(", ")) else "  all required checks passed" end),
  "",
  "  TCG caveat: \(.emulation.caveat)"
' "$out_root/row.json" | tee "$out_root/row.txt"
info "evidence: $out_root/row.json"

if ((status == 0)); then
  info "ARM64 FUNCTIONAL ROW PASS (TCG emulation, non-performance): $out_root"
else
  info "ARM64 FUNCTIONAL ROW FAIL: $out_root"
fi
exit "$status"
