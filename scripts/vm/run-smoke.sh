#!/usr/bin/env bash
# Boot a local KVM VM and run the basic lab smoke test over SSH.
#
# The smoke proves the VM is a real KVM guest with a usable BPF-capable
# kernel interface and a working SSH path:
#
#   1. `uname -r` reports the guest kernel release
#   2. /sys/kernel/btf/vmlinux exists (BTF for CO-RE capable kernels)
#   3. `echo smoke-ok` round-trips over SSH
#
# It also checks the cloud-init contract from scripts/vm/cloud-init:
# user `fleet` exists with passwordless sudo. If SSH works, cloud-init has
# already created that user, so this check is immediate.
#
# Usage: scripts/vm/run-smoke.sh [options]
#
# Options:
#   --image <name>   image key from scripts/vm/images.json
#                    (default: $SMOKE_IMAGE, otherwise ubuntu-24.04)
#   --name <name>    lab instance name (default: smoke-<image>)
#   --keep           leave the VM running after the smoke test
#   --help           show this help
#
# The VM, its overlay and its logs are created under target/vm/ by
# scripts/vm/lab.sh and the VM is torn down on exit unless --keep is used.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
lab="$script_dir/lab.sh"
repo_root="$(cd -- "$script_dir/../.." && pwd -P)"
vm_root="${VM_LAB_ROOT:-$repo_root/target/vm}"

image="${SMOKE_IMAGE:-ubuntu-24.04}"
name=""
keep=0
boot_timeout="${SMOKE_BOOT_TIMEOUT:-240}"

usage() {
  awk 'NR > 1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"
}

die() {
  printf 'smoke: error: %s\n' "$*" >&2
  exit 1
}

while (($# > 0)); do
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    --image)
      [[ $# -ge 2 && -n "$2" ]] || die "option --image needs a value"
      image="$2"
      shift 2
      ;;
    --image=*)
      image="${1#*=}"
      shift
      ;;
    --name)
      [[ $# -ge 2 && -n "$2" ]] || die "option --name needs a value"
      name="$2"
      shift 2
      ;;
    --name=*)
      name="${1#*=}"
      shift
      ;;
    --keep) keep=1; shift ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

[[ -x "$lab" ]] || die "missing executable lab script: $lab"
instance="${name:-smoke-$(printf '%s' "$image" | tr '.' '-')}"

# shellcheck disable=SC2329 # invoked indirectly by the EXIT trap
cleanup() {
  local status=$?
  trap - EXIT
  if ((keep == 0)) && [[ -d "$vm_root/instances/$instance" ]]; then
    "$lab" down --name "$instance" >/dev/null 2>&1 ||
      printf 'smoke: warning: could not tear down instance %s; run: scripts/vm/lab.sh down --name %s\n' \
        "$instance" "$instance" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

[[ -x "$lab" ]] || die "$lab is not executable; run: chmod +x scripts/vm/lab.sh"
"$lab" bootstrap --image "$image"
"$lab" up --image "$image" --name "$instance" --timeout "$boot_timeout"

guest() {
  "$lab" run --name "$instance" -- "$@"
}

pass=0
fail=0
report_pass() { printf 'PASS %-38s %s\n' "$1" "$2"; pass=$((pass + 1)); }
report_fail() { printf 'FAIL %-38s %s\n' "$1" "$2"; fail=$((fail + 1)); }

printf '\n== smoke: image=%s instance=%s host=%s\n' "$image" "$instance" "$(hostname -s 2>/dev/null || hostname)"

kernel="$(guest uname -r)" || kernel=""
if [[ -n "$kernel" ]]; then
  report_pass "uname -r" "$kernel"
else
  report_fail "uname -r" "no output over SSH"
fi

btf="$(guest 'test -r /sys/kernel/btf/vmlinux && echo present || echo missing')" || btf="missing"
if [[ "$btf" == "present" ]]; then
  btf_size="$(guest 'wc -c < /sys/kernel/btf/vmlinux' 2>/dev/null || echo unknown)"
  report_pass "/sys/kernel/btf/vmlinux" "present (${btf_size//[[:space:]]/} bytes)"
else
  report_fail "/sys/kernel/btf/vmlinux" "missing or unreadable in guest"
fi

smoke_out="$(guest echo smoke-ok)" || smoke_out=""
if [[ "$smoke_out" == "smoke-ok" ]]; then
  report_pass "echo smoke-ok" "smoke-ok"
else
  report_fail "echo smoke-ok" "unexpected output: '${smoke_out:-<empty>}'"
fi

sudo_ok=0
sudo_out=""
for _ in $(seq 1 30); do
  if sudo_out="$(guest 'id -un; sudo -n true && echo sudo-ok' 2>&1)"; then
    [[ "$sudo_out" == *"sudo-ok"* ]] && { sudo_ok=1; break; }
  fi
  sleep 2
done
if ((sudo_ok)); then
  report_pass "fleet user + passwordless sudo" "$(guest 'id -un')"
else
  report_fail "fleet user + passwordless sudo" "sudo -n true failed: ${sudo_out:-no output}"
fi

printf '\n'
if ((fail == 0)); then
  printf 'SMOKE PASS: %d/%d checks (image %s, kernel %s)\n' "$pass" "$((pass + fail))" "$image" "${kernel:-unknown}"
  if ((keep)); then
    printf 'instance %s left running; connect with: scripts/vm/lab.sh ssh --name %s\n' "$instance" "$instance"
    printf 'stop it with: scripts/vm/lab.sh down --name %s\n' "$instance"
  fi
  exit 0
fi
printf 'SMOKE FAIL: %d/%d checks failed (image %s)\n' "$fail" "$((pass + fail))" "$image"
exit 1
