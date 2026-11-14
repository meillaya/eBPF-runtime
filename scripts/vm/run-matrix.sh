#!/usr/bin/env bash
# shellcheck disable=SC2034
# Kernel-matrix runner for the local KVM VM lab.
#
# For every pinned image key given on the command line this script:
#
#   1. verifies/downloads the pinned base image through scripts/vm/lab.sh
#      (fail-closed sha256) and boots a disposable KVM VM;
#   2. copies the static target/release/ebpf-fleet binary into the guest and
#      verifies the guest sha256 matches the host sha256;
#   3. runs `doctor --json`;
#   4. runs `record --for <n> --out /tmp/matrix.fleet` while a deterministic
#      activity generator creates process and file events in a second SSH
#      session;
#   5. runs `query` for the kind counts and the FileOpen paths, `replay` for
#      the first event line, and a process-only probe record to find out
#      whether the sched_process_exit raw tracepoint attached;
#   6. exports the guest bundle, writes one JSON evidence file with kernel
#      release, BTF presence/sha256, sensor results, counts and per-check
#      pass/fail, and tears the VM down (also on failure).
#
# The runner is fail-closed: missing tools, /dev/kvm, a non-static binary,
# an unpinned image, a failed boot, a failed record/query/replay, a missing
# FileOpen path, or an unexpected kernel series fails the run (exit 1)
# instead of silently skipping a row. Every row is still torn down and the
# JSON evidence is written for failures too.
#
# Usage: scripts/vm/run-matrix.sh --image <name> [--image <name> ...] [options]
#
# Options:
#   --image <name>        image key from scripts/vm/images.json; repeatable
#                         (a comma-separated value is also accepted)
#   --all-pinned          every pinned image that matches the host
#                         architecture (instead of --image)
#   --name-prefix <p>     lab instance name prefix (default: matrix)
#   --record-seconds <n>  main `record --for` window (default: 8)
#   --probe-seconds <n>   process-only probe record window (default: 4)
#   --boot-timeout <n>    SSH boot budget in seconds (default: 300)
#   --binary <path>       static ebpf-fleet binary
#                         (default: target/release/ebpf-fleet)
#   --stamp <stamp>       output directory name (default: UTC timestamp)
#   --keep                leave every VM running after its row (debugging);
#                         the row evidence is still written and teardown is
#                         only skipped, never faked
#   --help                show this help
#
# Run inside the development shell so qemu, cloud-localds, ssh and jq are
# on PATH (on this host the devenv shell needs --impure because devenv.nix
# inspects the current directory):
#
#   nix develop --impure --command scripts/vm/run-matrix.sh \
#     --image ubuntu-24.04 --image ubuntu-22.04
#
# Output (all under target/vm/, which is gitignored):
#   target/vm/matrix/<stamp>/matrix-summary.json   row table + host facts
#   target/vm/matrix/<stamp>/<image>.json          per-row evidence
#   target/vm/matrix/<stamp>/<image>/              per-row raw artifacts
#
# Environment:
#   VM_LAB_ROOT   state root shared with scripts/vm/lab.sh (default target/vm)

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/../.." && pwd -P)"
lab="$script_dir/lab.sh"
images_json="$script_dir/images.json"
vm_root="${VM_LAB_ROOT:-$repo_root/target/vm}"
matrix_root="$vm_root/matrix"
default_binary="$repo_root/target/release/ebpf-fleet"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
requested_images=()
all_pinned=0
name_prefix="matrix"
record_seconds=8
probe_seconds=4
boot_timeout=300
binary="$default_binary"
keep=0
out_root=""
binary_sha=""
binary_size=""
host_name=""
host_arch=""
host_kernel=""
probe_path="/tmp/matrix-probe/created-by-matrix"

info() { printf 'matrix: %s\n' "$*" >&2; }
warn() { printf 'matrix: warning: %s\n' "$*" >&2; }
die() {
  printf 'matrix: error: %s\n' "$*" >&2
  exit 1
}

usage() {
  awk 'NR > 1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"
}

# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------

while (($# > 0)); do
  arg="$1"
  case "$arg" in
    -h | --help)
      usage
      exit 0
      ;;
    --image | --name-prefix | --record-seconds | --probe-seconds | --boot-timeout | --binary | --stamp)
      [[ $# -ge 2 && -n "$2" ]] || die "option $arg needs a value"
      case "$arg" in
        --image)
          IFS=',' read -r -a _parts <<<"$2"
          for _part in "${_parts[@]}"; do
            [[ -n "$_part" ]] && requested_images+=("$_part")
          done
          ;;
        --name-prefix) name_prefix="$2" ;;
        --record-seconds) record_seconds="$2" ;;
        --probe-seconds) probe_seconds="$2" ;;
        --boot-timeout) boot_timeout="$2" ;;
        --binary) binary="$2" ;;
        --stamp) stamp="$2" ;;
      esac
      shift 2
      ;;
    --image=* | --name-prefix=* | --record-seconds=* | --probe-seconds=* | --boot-timeout=* | --binary=* | --stamp=*)
      key="${arg%%=*}"
      value="${arg#*=}"
      [[ -n "$value" ]] || die "option $key needs a value"
      case "$key" in
        --image)
          IFS=',' read -r -a _parts <<<"$value"
          for _part in "${_parts[@]}"; do
            [[ -n "$_part" ]] && requested_images+=("$_part")
          done
          ;;
        --name-prefix) name_prefix="$value" ;;
        --record-seconds) record_seconds="$value" ;;
        --probe-seconds) probe_seconds="$value" ;;
        --boot-timeout) boot_timeout="$value" ;;
        --binary) binary="$value" ;;
        --stamp) stamp="$value" ;;
      esac
      shift
      ;;
    --all-pinned) all_pinned=1; shift ;;
    --keep) keep=1; shift ;;
    -*)
      die "unknown option: $arg (try --help)"
      ;;
    *)
      die "unexpected argument: $arg (use --image <name>, see --help)"
      ;;
  esac
done

require_positive_int() {
  local label="$1" value="$2"
  [[ "$value" =~ ^[0-9]+$ ]] || die "$label must be a positive integer, got '$value'"
  ((value > 0)) || die "$label must be greater than zero, got '$value'"
}

require_positive_int "--record-seconds" "$record_seconds"
require_positive_int "--probe-seconds" "$probe_seconds"
require_positive_int "--boot-timeout" "$boot_timeout"
[[ "$stamp" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "--stamp '$stamp' must be letters, digits, dot, underscore or hyphen"
[[ "$name_prefix" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "--name-prefix '$name_prefix' must be lowercase letters, digits and hyphens"
((record_seconds >= 4)) || die "--record-seconds must be at least 4 so activity overlaps the record window"
((probe_seconds >= 3)) || die "--probe-seconds must be at least 3 so activity overlaps the probe window"

# ---------------------------------------------------------------------------
# fail-closed preflight
# ---------------------------------------------------------------------------

have() { command -v "$1" >/dev/null 2>&1; }

tool_hint() {
  cat >&2 <<'EOF'
matrix: hint: run this command inside the development shell:
matrix:   nix develop --impure --command scripts/vm/run-matrix.sh <options>
matrix: the lab needs qemu, cloud-localds, ssh, jq and coreutils on PATH.
EOF
}

preflight_tools() {
  local missing=() tool
  for tool in qemu-system-x86_64 qemu-img ssh ssh-keygen jq flock sha256sum \
    awk sed grep tr stat tar gzip file; do
    have "$tool" || missing+=("$tool")
  done
  if ((${#missing[@]} > 0)); then
    printf 'matrix: error: missing required host tools: %s\n' "${missing[*]}" >&2
    tool_hint
    exit 1
  fi
}

preflight_kvm() {
  local kvm="${KVM_DEV:-/dev/kvm}"
  [[ -e "$kvm" ]] || die "$kvm is missing; hardware virtualization is required and TCG is never used"
  [[ -r "$kvm" && -w "$kvm" ]] || die "$kvm is not readable/writable by $(id -un); the lab needs direct KVM access"
}

preflight_binary() {
  [[ -f "$binary" ]] || die "static binary not found: $binary (build it with scripts/build-static.sh)"
  [[ -x "$binary" ]] || die "binary is not executable: $binary"
  local ftype
  ftype="$(file -b "$binary" 2>/dev/null || true)"
  case "$ftype" in
    *"statically linked"* | *"static-pie linked"*) ;;
    *) die "refusing to run a non-static binary ($binary): $ftype; guests have no Nix glibc, use scripts/build-static.sh" ;;
  esac
  binary_sha="$(sha256sum "$binary" | awk '{print $1}')"
  binary_size="$(stat -c %s "$binary")"
  [[ "$binary_sha" =~ ^[0-9a-f]{64}$ ]] || die "could not hash $binary"
}

preflight_lab() {
  [[ -x "$lab" ]] || die "lab script is missing or not executable: $lab"
  [[ -f "$images_json" ]] || die "image catalogue is missing: $images_json"
  if ! jq -e '.schema_version == 1 and (.images | type == "object")' "$images_json" >/dev/null 2>&1; then
    die "invalid image catalogue: $images_json"
  fi
}

resolve_images() {
  if ((all_pinned)); then
    local from_catalogue
    from_catalogue="$(jq -r --arg arch "$host_arch" \
      '.images | to_entries[] | select(.value.status == "pinned") | select(.value.arch == $arch) | .key' \
      "$images_json")"
    local key
    while IFS= read -r key; do
      [[ -n "$key" ]] && requested_images+=("$key")
    done <<<"$from_catalogue"
  fi
  ((${#requested_images[@]} > 0)) ||
    die "no image requested; pass --image <key> (repeatable) or --all-pinned"
  local seen=" " image unique=()
  for image in "${requested_images[@]}"; do
    [[ -n "$image" ]] || continue
    [[ "$seen" == *" $image "* ]] && continue
    seen+="$image "
    unique+=("$image")
  done
  requested_images=("${unique[@]}")

  local status sha arch
  for image in "${requested_images[@]}"; do
    jq -e --arg k "$image" '.images[$k] != null' "$images_json" >/dev/null 2>&1 ||
      die "unknown image '$image'; known images: $(jq -r '.images | keys | join(" ")' "$images_json")"
    status="$(jq -r --arg k "$image" '.images[$k].status // "unknown"' "$images_json")"
    [[ "$status" == "pinned" ]] ||
      die "image '$image' is not pinned (status=$status); the matrix refuses to boot an unpinned image"
    sha="$(jq -r --arg k "$image" '.images[$k].sha256 // ""' "$images_json")"
    [[ "$sha" =~ ^[0-9a-f]{64}$ ]] ||
      die "image '$image' has no sha256 pin in $images_json; pin it before running the matrix"
    arch="$(jq -r --arg k "$image" '.images[$k].arch // ""' "$images_json")"
    [[ "$arch" == "$host_arch" ]] ||
      die "image '$image' is built for $arch but this host is $host_arch; KVM cannot boot it natively"
  done
}

preflight_output() {
  mkdir -p "$matrix_root"
  out_root="$matrix_root/$stamp"
  [[ ! -e "$out_root" ]] || die "matrix output already exists: $out_root (pass a different --stamp)"
  mkdir -p "$out_root"
  out_root="$(cd -- "$out_root" && pwd -P)"
}

preflight() {
  preflight_tools
  preflight_kvm
  preflight_binary
  preflight_lab
  host_name="$(hostname -s 2>/dev/null || hostname)"
  host_arch="$(uname -m)"
  host_kernel="$(uname -r)"
  resolve_images
  preflight_output
}

# ---------------------------------------------------------------------------
# generated guest helpers (written under the stamp directory, copied to /tmp)
# ---------------------------------------------------------------------------

write_activity_script() {
  cat >"$1" <<'ACTIVITY'
#!/usr/bin/env bash
# Generated by scripts/vm/run-matrix.sh.
# Deterministic process and file activity for the record window. The fixed
# marker path is what the runner looks for in the recorded FileOpen paths.
set -u
duration="${1:-6}"
case "$duration" in
  '' | *[!0-9]*) duration=6 ;;
esac
probe_dir="${MATRIX_PROBE_DIR:-/tmp/matrix-probe}"
marker="$probe_dir/created-by-matrix"
rm -rf "$probe_dir"
mkdir -p "$probe_dir"
printf 'matrix activity marker\n' >"$marker"
deadline=$((SECONDS + duration))
i=0
while ((SECONDS < deadline)); do
  i=$((i + 1))
  cat "$marker" >/dev/null 2>&1 || true
  head -c 16 /etc/hostname >/dev/null 2>&1 || true
  /bin/true || true
  /bin/false || true
  /bin/sh -c 'exit 3' || true
  printf 'matrix scratch %s\n' "$i" >"$probe_dir/scratch.txt"
  cat "$probe_dir/scratch.txt" >/dev/null 2>&1 || true
  rm -f "$probe_dir/scratch.txt"
  ls "$probe_dir" >/dev/null 2>&1 || true
  sleep 0.2
done
/bin/sh -c 'exit 7' || true
echo matrix-activity-ok
ACTIVITY
  chmod 0755 "$1"
}

write_guest_probe_script() {
  cat >"$1" <<'GUESTPROBE'
#!/usr/bin/env bash
# Generated by scripts/vm/run-matrix.sh.
# Print the guest facts one matrix row needs, as [section] + key=value lines.
set -u
bundle="${1:-/tmp/matrix.fleet}"
probe_bundle="${2:-/tmp/matrix-probe-process}"
section() { printf '\n[%s]\n' "$1"; }

bundle_field() {
  # bundle_field <dir> <jq filter>: read a manifest field as fleet, else sudo.
  local dir="$1" filter="$2" value
  if [ -r "$dir/manifest.json" ]; then
    value="$(jq -r "$filter" "$dir/manifest.json" 2>/dev/null || true)"
  elif sudo -n test -r "$dir/manifest.json" 2>/dev/null; then
    value="$(sudo -n jq -r "$filter" "$dir/manifest.json" 2>/dev/null || true)"
  else
    value=""
  fi
  [[ -n "$value" ]] || value="unknown"
  printf '%s' "$value"
}

section uname
uname -a
printf 'kernel_release=%s\n' "$(uname -r)"

section os-release
if [ -r /etc/os-release ]; then
  ID=""; VERSION_ID=""; PRETTY_NAME=""
  . /etc/os-release
  printf 'id=%s\n' "${ID:-unknown}"
  printf 'version_id=%s\n' "${VERSION_ID:-unknown}"
  printf 'pretty_name=%s\n' "${PRETTY_NAME:-unknown}"
else
  printf 'id=unknown\nversion_id=unknown\npretty_name=unknown\n'
fi

section btf
if [ -r /sys/kernel/btf/vmlinux ]; then
  printf 'present=yes\n'
  printf 'size_bytes=%s\n' "$(wc -c < /sys/kernel/btf/vmlinux)"
  printf 'sha256=%s\n' "$(sha256sum /sys/kernel/btf/vmlinux | awk '{print $1}')"
else
  printf 'present=no\nsize_bytes=0\nsha256=\n'
fi

section security
if [ -r /sys/kernel/security/lsm ]; then
  printf 'lsm=%s\n' "$(cat /sys/kernel/security/lsm)"
else
  printf 'lsm=unavailable\n'
fi
if [ -r /sys/kernel/security/lockdown ]; then
  printf 'lockdown=%s\n' "$(cat /sys/kernel/security/lockdown)"
else
  printf 'lockdown=unavailable\n'
fi
printf 'unprivileged_bpf_disabled=%s\n' "$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo unknown)"
printf 'user=%s\n' "$(id -un)"

section tools
for tool in jq tar sha256sum; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf '%s=present\n' "$tool"
  else
    printf '%s=missing\n' "$tool"
  fi
done
if sudo -n true >/dev/null 2>&1; then
  echo 'sudo=ok'
else
  echo 'sudo=fail'
fi

section cloud-init
if command -v cloud-init >/dev/null 2>&1; then
  cloud-init status --long 2>&1 | head -n 8
else
  echo 'cloud-init=missing'
fi

section binary
if [ -x /tmp/ebpf-fleet ]; then
  /tmp/ebpf-fleet --version 2>&1
else
  echo 'binary=missing'
fi

section bundle
if [ -r "$bundle/manifest.json" ] || sudo -n test -r "$bundle/manifest.json" 2>/dev/null; then
  printf 'present=yes\n'
  printf 'complete=%s\n' "$(bundle_field "$bundle" '.complete')"
  printf 'events=%s\n' "$(bundle_field "$bundle" '.counts.events')"
  printf 'capture_sensors=%s\n' "$(bundle_field "$bundle" '.capture.sensors | join(",")')"
  printf 'capture_duration_ms=%s\n' "$(bundle_field "$bundle" '.capture.duration_ms')"
  printf 'host_lsm=%s\n' "$(bundle_field "$bundle" '.host.lsm | join(",")')"
  printf 'host_btf_sha256=%s\n' "$(bundle_field "$bundle" '.host.btf_sha256')"
  printf 'created_at=%s\n' "$(bundle_field "$bundle" '.created_at')"
else
  printf 'present=no\ncomplete=unknown\nevents=0\n'
fi

section probe-bundle
if [ -r "$probe_bundle/manifest.json" ] || sudo -n test -r "$probe_bundle/manifest.json" 2>/dev/null; then
  printf 'present=yes\n'
  printf 'complete=%s\n' "$(bundle_field "$probe_bundle" '.complete')"
  printf 'events=%s\n' "$(bundle_field "$probe_bundle" '.counts.events')"
  printf 'capture_sensors=%s\n' "$(bundle_field "$probe_bundle" '.capture.sensors | join(",")')"
else
  printf 'present=no\nevents=0\n'
fi

section dmesg
sudo -n dmesg 2>/dev/null | tail -n 60 || true
GUESTPROBE
  chmod 0755 "$1"
}

# ---------------------------------------------------------------------------
# parsing helpers
# ---------------------------------------------------------------------------

# fact <guest-info-file> <section> <key>: print the value of key= in section.
fact() {
  awk -v want="[$2]" -v key="$3=" '
    $0 == want { inside = 1; next }
    /^\[/ { inside = 0 }
    inside && index($0, key) == 1 { print substr($0, length(key) + 1); exit }
  ' "$1"
}

# count_kinds <query-output>: print "kind<TAB>count" lines from the pretty table.
count_kinds() {
  awk -F'|' 'NF >= 4 {
      k = $2; n = $3
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", k)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", n)
      if (k != "" && k != "kind" && n ~ /^[0-9]+$/) print k "\t" n
    }' "$1"
}

# count_paths <query-output>: print path<TAB>count from the FileOpen query.
count_paths() {
  awk -F'|' 'NF >= 4 {
      p = $2; n = $3
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", p)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", n)
      if (p != "" && p != "path" && n ~ /^[0-9]+$/) print p "\t" n
    }' "$1"
}

kinds_to_json() {
  count_kinds "$1" | jq -R -s '
    split("\n")
    | map(select(length > 0) | split("\t") | {(.[0]): (.[1] | tonumber)})
    | add // {}'
}

paths_to_json() {
  count_paths "$1" | awk -F'\t' '{print $1}' | jq -R -s '
    split("\n") | map(select(length > 0))'
}

# json_or <value> <fallback>: keep value only when it is valid JSON.
json_or() {
  if jq . >/dev/null 2>&1 <<<"$1"; then
    printf '%s' "$1"
  else
    printf '%s' "$2"
  fi
}

# json_named <key> <value> <fallback>: like json_or but records the key of an
# invalid value in $JSON_BAD_LOG so a broken evidence file is diagnosable.
json_named() {
  if jq . >/dev/null 2>&1 <<<"$2"; then
    printf '%s' "$2"
  else
    printf 'invalid json field %s: %q\n' "$1" "$2" >>"${JSON_BAD_LOG:-/dev/null}" 2>/dev/null || true
    printf '%s' "$3"
  fi
}

# int_or_zero <value>: print value when it is a non-negative integer, else 0.
int_or_zero() {
  if [[ "$1" =~ ^[0-9]+$ ]]; then
    printf '%s' "$1"
  else
    printf '0'
  fi
}

# jqf <json-file> <jq-filter> <fallback>: read a scalar with a fallback.
jqf() {
  local value
  if value="$(jq -r "$2" "$1" 2>/dev/null)"; then
    printf '%s' "$value"
  else
    printf '%s' "$3"
  fi
}

json_count() {
  # json_count <json-object> <key>
  jq -r --arg k "$2" '.[$k] // 0' <<<"$1" 2>/dev/null || echo 0
}

# ---------------------------------------------------------------------------
# per-row evidence
# ---------------------------------------------------------------------------

run_row() {
  local image="$1"
  local row_start=$SECONDS
  local instance
  instance="${name_prefix}-$(printf '%s' "$image" | tr '.' '-')"
  local json_path="$out_root/$image.json"
  local art="$out_root/$image"
  local art_rel="target/vm/matrix/$stamp/$image"
  local json_rel="target/vm/matrix/$stamp/$image.json"
  mkdir -p "$art"

  # state collected for the JSON evidence file
  local image_metadata
  image_metadata="$(jq -c --arg k "$image" '.images[$k]' "$images_json")"
  local expected_series
  expected_series="$(jq -r --arg k "$image" '.images[$k].kernel_series // ""' "$images_json")"
  local ssh_port="null"
  local boot_ok=0 boot_seconds=0
  local cloud_init_status="" cloud_init_ready=0 cloud_init_ready_seconds=0
  local kernel_release="" kernel_uname_a="" kernel_series_match=0
  local os_id="" os_version_id="" os_pretty_name=""
  local btf_present=0 btf_size=0 btf_sha256=""
  local lsm="" lockdown="" unprivileged=""
  local guest_sha="" binary_version="" binary_ok=0
  local doctor_rc=1 doctor_checks='[]'
  local record_rc=1 record_events=0 decode_errors=0 bundle_complete="unknown"
  local probe_rc=1 probe_query_rc=1 probe_counts='{}' probe_events=0
  local kinds_rc=1 paths_rc=1 counts='{}' top_paths='[]' file_open_count=0 probe_seen=0
  local replay_rc=1 replay_lines=0 first_line="" first_kind="" replay_valid=0
  local export_rc=1 host_query_ok=0 file_sensor_path="unknown"
  local sensor_warnings='[]'
  local checks_json='[]'
  local notes_json='[]'
  # Most of these are read indirectly by the a_* snapshot in write_row_json.
  # shellcheck disable=SC2034
  local teardown_done=0

  # shellcheck disable=SC2329 # invoked indirectly by the EXIT trap
  row_cleanup() {
    local rc=$?
    trap - EXIT
    if ((teardown_done == 0)); then
      teardown_image "$instance" "$art" || true
      teardown_done=1
    fi
    if ! jq -e . "$json_path" >/dev/null 2>&1; then
      add_check "row" false true "row aborted unexpectedly (last exit status $rc)"
      write_row_json || true
    fi
    exit "$rc"
  }
  trap row_cleanup EXIT

  add_check() {
    # add_check <name> <ok:true|false> <required:true|false> <detail>
    checks_json="$(jq -c --arg n "$1" --argjson ok "$2" --argjson req "$3" --arg d "$4" \
      '. + [{name: $n, ok: $ok, required: $req, detail: $d}]' <<<"$checks_json")"
  }

  add_note() {
    notes_json="$(jq -c --arg n "$1" '. + [$n]' <<<"$notes_json")"
  }

  write_row_json() {
    local failed_names artifact_files
    local a_metadata a_ssh_port a_doctor a_counts a_top_paths a_probe_counts a_checks a_notes
    local a_artifact_files a_warnings a_binary_size a_boot_ok a_boot_seconds a_cloud_ready
    local a_cloud_ready_seconds a_kernel_match a_btf_present a_btf_size a_doctor_rc a_record_rc
    local a_record_events a_decode_errors a_probe_rc a_probe_query_rc a_probe_events a_kinds_rc
    local a_paths_rc a_file_open_count a_probe_seen a_replay_rc a_replay_lines a_replay_valid
    local a_export_rc a_host_query_ok a_record_seconds a_duration a_binary_ok a_failed_names tmp
    failed_names="$(jq -c '[.[] | select(.required and (.ok | not)) | .name]' <<<"$checks_json" 2>/dev/null || echo '["internal-json-error"]')"
    artifact_files="$(find "$art" -maxdepth 1 -type f -printf '%f\n' 2>/dev/null | sort | jq -R -s 'split("\n") | map(select(length > 0))' 2>/dev/null)" || artifact_files='[]'

    JSON_BAD_LOG="$art/json-bad-values.log"
    a_metadata="$(json_named image_metadata "$image_metadata" '{}')"
    a_ssh_port="$(json_named ssh_port "$ssh_port" 'null')"
    a_doctor="$(json_named doctor_checks "$doctor_checks" '[]')"
    a_counts="$(json_named counts "$counts" '{}')"
    a_top_paths="$(json_named top_paths "$top_paths" '[]')"
    a_probe_counts="$(json_named probe_counts "$probe_counts" '{}')"
    a_checks="$(json_named checks "$checks_json" '[]')"
    a_notes="$(json_named notes "$notes_json" '[]')"
    a_artifact_files="$(json_named artifact_files "$artifact_files" '[]')"
    a_warnings="$(json_named sensor_warnings "$sensor_warnings" '[]')"
    a_binary_size="$(int_or_zero "$binary_size")"
    a_boot_ok="$(int_or_zero "$boot_ok")"
    a_boot_seconds="$(int_or_zero "$boot_seconds")"
    a_cloud_ready="$(int_or_zero "$cloud_init_ready")"
    a_cloud_ready_seconds="$(int_or_zero "$cloud_init_ready_seconds")"
    a_kernel_match="$(int_or_zero "$kernel_series_match")"
    a_btf_present="$(int_or_zero "$btf_present")"
    a_btf_size="$(int_or_zero "$btf_size")"
    a_doctor_rc="$(int_or_zero "$doctor_rc")"
    a_record_rc="$(int_or_zero "$record_rc")"
    a_record_seconds="$(int_or_zero "$record_seconds")"
    a_record_events="$(int_or_zero "$record_events")"
    a_decode_errors="$(int_or_zero "$decode_errors")"
    a_probe_rc="$(int_or_zero "$probe_rc")"
    a_probe_query_rc="$(int_or_zero "$probe_query_rc")"
    a_probe_events="$(int_or_zero "$probe_events")"
    a_kinds_rc="$(int_or_zero "$kinds_rc")"
    a_paths_rc="$(int_or_zero "$paths_rc")"
    a_file_open_count="$(int_or_zero "$file_open_count")"
    a_probe_seen="$(int_or_zero "$probe_seen")"
    a_replay_rc="$(int_or_zero "$replay_rc")"
    a_replay_lines="$(int_or_zero "$replay_lines")"
    a_replay_valid="$(int_or_zero "$replay_valid")"
    a_export_rc="$(int_or_zero "$export_rc")"
    a_binary_ok="$(int_or_zero "$binary_ok")"
    a_host_query_ok="$(int_or_zero "$host_query_ok")"
    a_duration="$((SECONDS - row_start))"
    a_failed_names="$(json_named failed_names "$failed_names" '["internal-json-error"]')"

    tmp="$json_path.tmp"
    local -a jq_args=()
    # Structured JSON values are passed as validated JSON text and
    # decoded with fromjson; numeric values are passed as digits and
    # converted with tonumber. No --argjson is used, so a bad/empty value
    # can never abort the whole evidence write.
    local -a json_fields=(
      "image_metadata:a_metadata"
      "doctor_checks:a_doctor"
      "counts:a_counts"
      "top_paths:a_top_paths"
      "probe_counts:a_probe_counts"
      "sensor_warnings:a_warnings"
      "checks:a_checks"
      "failed_names:a_failed_names"
      "notes:a_notes"
      "artifact_files:a_artifact_files"
    )
    local -a int_fields=(
      "ssh_port:a_ssh_port"
      "binary_size:a_binary_size"
      "boot_ok:a_boot_ok"
      "binary_ok:a_binary_ok"
      "boot_seconds:a_boot_seconds"
      "cloud_init_ready:a_cloud_ready"
      "cloud_init_ready_seconds:a_cloud_ready_seconds"
      "kernel_series_match:a_kernel_match"
      "btf_present:a_btf_present"
      "btf_size:a_btf_size"
      "doctor_rc:a_doctor_rc"
      "record_rc:a_record_rc"
      "record_seconds:a_record_seconds"
      "record_events:a_record_events"
      "decode_errors:a_decode_errors"
      "probe_rc:a_probe_rc"
      "probe_query_rc:a_probe_query_rc"
      "probe_events:a_probe_events"
      "kinds_rc:a_kinds_rc"
      "paths_rc:a_paths_rc"
      "file_open_count:a_file_open_count"
      "probe_seen:a_probe_seen"
      "replay_rc:a_replay_rc"
      "replay_lines:a_replay_lines"
      "replay_valid:a_replay_valid"
      "export_rc:a_export_rc"
      "host_query_ok:a_host_query_ok"
      "duration:a_duration"
    )
    local pair field var value fallback
    for pair in "${json_fields[@]}"; do
      field="${pair%%:*}"
      var="${pair#*:}"
      value="${!var}"
      case "$field" in
        image_metadata | counts | probe_counts) fallback='{}' ;;
        *) fallback='[]' ;;
      esac
      if ! jq -e -s 'length == 1' >/dev/null 2>&1 <<<"$value"; then
        printf 'invalid json field %s (not exactly one JSON document): %q\n' "$field" "$value" >>"$art/json-bad-values.log" 2>/dev/null || true
        value="$fallback"
      fi
      jq_args+=(--arg "$field" "$value")
    done
    for pair in "${int_fields[@]}"; do
      field="${pair%%:*}"
      var="${pair#*:}"
      value="${!var}"
      [[ "$value" =~ ^[0-9]+$ ]] || value='0'
      jq_args+=(--arg "$field" "$value")
    done
    jq_args+=(
      --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      --arg host_name "$host_name"
      --arg host_arch "$host_arch"
      --arg host_kernel "$host_kernel"
      --arg image "$image"
      --arg instance "$instance"
      --arg binary_path "$binary"
      --arg binary_sha "$binary_sha"
      --arg guest_sha "$guest_sha"
      --arg binary_version "$binary_version"
      --arg cloud_init_status "$cloud_init_status"
      --arg kernel_release "$kernel_release"
      --arg kernel_uname_a "$kernel_uname_a"
      --arg expected_series "$expected_series"
      --arg os_id "$os_id"
      --arg os_version_id "$os_version_id"
      --arg os_pretty_name "$os_pretty_name"
      --arg btf_sha256 "$btf_sha256"
      --arg lsm "$lsm"
      --arg lockdown "$lockdown"
      --arg unprivileged "$unprivileged"
      --arg bundle_complete "$bundle_complete"
      --arg probe_path "$probe_path"
      --arg first_line "$first_line"
      --arg first_kind "$first_kind"
      --arg file_sensor_path "$file_sensor_path"
      --arg art_rel "$art_rel"
      --arg json_rel "$json_rel"
    )
    if jq -n "${jq_args[@]}" '
      {
        schema_version: 1,
        runner: "scripts/vm/run-matrix.sh",
        generated_at: $generated_at,
        host: {name: $host_name, arch: $host_arch, kernel: $host_kernel},
        image: $image,
        image_metadata: ($image_metadata | fromjson),
        instance: $instance,
        ssh_port: ($ssh_port | tonumber),
        binary: {
          host_path: $binary_path,
          host_sha256: $binary_sha,
          host_size_bytes: ($binary_size | tonumber),
          guest_path: "/tmp/ebpf-fleet",
          guest_sha256: $guest_sha,
          sha256_match: ($guest_sha == $binary_sha),
          version: $binary_version
        },
        boot: {ok: (($boot_ok | tonumber) == 1), seconds: ($boot_seconds | tonumber)},
        cloud_init: {status: $cloud_init_status, ready: (($cloud_init_ready | tonumber) == 1), ready_seconds: ($cloud_init_ready_seconds | tonumber)},
        kernel: {
          release: $kernel_release,
          uname_a: $kernel_uname_a,
          expected_series: $expected_series,
          series_match: (($kernel_series_match | tonumber) == 1)
        },
        os_release: {id: $os_id, version_id: $os_version_id, pretty_name: $os_pretty_name},
        btf: {path: "/sys/kernel/btf/vmlinux", present: (($btf_present | tonumber) == 1), size_bytes: ($btf_size | tonumber), sha256: $btf_sha256},
        security: {lsm: $lsm, lockdown: $lockdown, unprivileged_bpf_disabled: $unprivileged},
        binary_ran: (($binary_ok | tonumber) == 1),
        doctor: {exit_code: ($doctor_rc | tonumber), checks: ($doctor_checks | fromjson)},
        record: {
          exit_code: ($record_rc | tonumber),
          seconds: ($record_seconds | tonumber),
          events: ($record_events | tonumber),
          decode_errors: ($decode_errors | tonumber),
          bundle: "/tmp/matrix.fleet",
          bundle_complete: $bundle_complete
        },
        sensors: {
          warnings: ($sensor_warnings | fromjson),
          file_sensor_path: $file_sensor_path,
          exit_tracepoint: {
            attached: ((((($probe_counts | fromjson).ProcessExit // 0) > 0))),
            evidence: ("process-only probe: ProcessFork=" + (((($probe_counts | fromjson).ProcessFork // 0) | tostring))
                       + " ProcessExec=" + (((($probe_counts | fromjson).ProcessExec // 0) | tostring))
                       + " ProcessExit=" + (((($probe_counts | fromjson).ProcessExit // 0) | tostring)))
          }
        },
        probe: {process_only: {exit_code: ($probe_rc | tonumber), query_exit_code: ($probe_query_rc | tonumber), events: ($probe_events | tonumber), counts: ($probe_counts | fromjson)}},
        query: {
          kinds_exit_code: ($kinds_rc | tonumber),
          kinds: ($counts | fromjson),
          file_paths_exit_code: ($paths_rc | tonumber),
          file_open_count: ($file_open_count | tonumber),
          top_paths: ($top_paths | fromjson),
          probe_path: $probe_path,
          probe_path_seen: (($probe_seen | tonumber) == 1)
        },
        replay: {exit_code: ($replay_rc | tonumber), lines: ($replay_lines | tonumber), first_line: $first_line, first_kind: $first_kind, valid_json: (($replay_valid | tonumber) == 1)},
        bundle_export: {exit_code: ($export_rc | tonumber), archive: ($art_rel + "/matrix.fleet.tar.gz"), host_query_ok: (($host_query_ok | tonumber) == 1)},
        artifacts: {dir: $art_rel, json: $json_rel, files: ($artifact_files | fromjson)},
        checks: ($checks | fromjson),
        failures: ($failed_names | fromjson),
        status: (if (($failed_names | fromjson) | length) > 0 then "fail" else "pass" end),
        notes: ($notes | fromjson),
        duration_s: ($duration | tonumber)
      }' >"$tmp" 2>"$art/json-write.err"; then
      mv -f "$tmp" "$json_path"
    else
      rm -f "$tmp"
      warn "could not build $json_rel; writing a minimal failure record (see $art/json-write.err)"
      printf '{"schema_version":1,"runner":"scripts/vm/run-matrix.sh","image":"%s","status":"fail","failures":["json evidence build failed"],"notes":["see json-write.err"]}\n' \
        "$image" >"$json_path"
    fi
  }

  # ---- row body ----------------------------------------------------------

  info "==> $image (instance $instance)"

  # A leftover instance with the same name would boot stale overlay state.
  if [[ -d "$vm_root/instances/$instance" ]]; then
    "$lab" down --name "$instance" --purge >/dev/null 2>&1 || true
  fi

  local bootstrap_ok=1
  if ! "$lab" bootstrap --image "$image" >"$art/bootstrap.log" 2>&1; then
    bootstrap_ok=0
    add_check "bootstrap" false true "lab.sh bootstrap failed; see $art/bootstrap.log"
  else
    add_check "bootstrap" true true "pinned image verified by scripts/vm/lab.sh"
  fi

  local up_start=$SECONDS
  if ((bootstrap_ok)); then
    if "$lab" up --image "$image" --name "$instance" --timeout "$boot_timeout" >"$art/up.log" 2>&1; then
      boot_ok=1
      boot_seconds=$((SECONDS - up_start))
      ssh_port="$(jq -r '.port // null' "$vm_root/instances/$instance/instance.json" 2>/dev/null || echo null)"
      add_check "boot" true true "SSH ready on 127.0.0.1:$ssh_port after ${boot_seconds}s"
    else
      add_check "boot" false true "lab.sh up failed; see $art/up.log and target/vm/instances/$instance/logs"
    fi
  else
    add_check "boot" false true "skipped: bootstrap failed"
  fi
  if ((boot_ok == 0)); then
    add_check "row" false true "boot failed; remaining recording checks skipped"
    write_row_json
    exit 1
  fi

  # Wait for cloud-init to finish installing the small guest tool set. Record
  # itself only needs the kernel, but jq/tar are needed for evidence export.
  local ready_start=$SECONDS ready_out=""
  local ready_deadline=$((SECONDS + 300))
  local cloud_init_state="unknown"
  while ((SECONDS < ready_deadline)); do
    if ready_out="$("$lab" run --name "$instance" -- \
      'cloud-init status 2>/dev/null | head -n 1; command -v jq >/dev/null && command -v tar >/dev/null && sudo -n true && echo guest-ready' 2>/dev/null)" &&
      [[ "$ready_out" == *guest-ready* ]] &&
      grep -q 'status: done' <<<"$ready_out"; then
      cloud_init_ready=1
      cloud_init_ready_seconds=$((SECONDS - ready_start))
      break
    fi
    cloud_init_state="$(sed -n 's/^status: //p' <<<"${ready_out:-}" | head -n 1)"
    sleep 5
  done
  if ((cloud_init_ready)); then
    add_check "cloud_init_ready" true true "cloud-init done; sudo+jq+tar available after ${cloud_init_ready_seconds}s"
  else
    add_check "cloud_init_ready" false true "guest not ready (cloud-init '${cloud_init_state:-unknown}', sudo+jq+tar) within 300s"
  fi
  "$lab" run --name "$instance" -- 'cloud-init status --long' >"$art/cloud-init-status.txt" 2>&1 || true
  cloud_init_status="$(head -n 1 "$art/cloud-init-status.txt" 2>/dev/null || true)"
  cloud_init_status="${cloud_init_status:-unknown}"

  # Copy the static binary with the lab's own SSH path, then verify sha256 in
  # the guest before executing anything.
  if "$lab" copy --name "$instance" "$binary" /tmp/ebpf-fleet >"$art/copy.log" 2>&1; then
    "$lab" run --name "$instance" -- chmod 0755 /tmp/ebpf-fleet >>"$art/copy.log" 2>&1 || true
    guest_sha="$("$lab" run --name "$instance" -- 'sha256sum /tmp/ebpf-fleet' 2>/dev/null | awk '{print $1}')" || guest_sha=""
    if [[ "$guest_sha" == "$binary_sha" ]]; then
      add_check "binary_upload" true true "guest sha256 matches host ($binary_sha)"
    else
      add_check "binary_upload" false true "guest sha256 '${guest_sha:-missing}' != host '$binary_sha'"
    fi
  else
    add_check "binary_upload" false true "lab.sh copy failed; see $art/copy.log"
  fi

  binary_version="$("$lab" run --name "$instance" -- /tmp/ebpf-fleet --version 2>"$art/binary-version.err" || true)"
  if [[ "$binary_version" == ebpf-fleet* ]]; then
    binary_ok=1
    add_check "binary_runs" true true "$binary_version"
  else
    add_check "binary_runs" false true "guest could not run /tmp/ebpf-fleet --version: '${binary_version:-<empty>}'"
  fi

  # doctor --json
  local doc_start=$SECONDS
  doctor_rc=0
  "$lab" run --name "$instance" -- sudo -n /tmp/ebpf-fleet doctor --json \
    >"$art/doctor.json" 2>"$art/doctor.err" || doctor_rc=$?
  local doc_kernel_ok=false doc_btf_ok=false doc_btf_sha=""
  if jq -e 'type == "array"' "$art/doctor.json" >/dev/null 2>&1; then
    doctor_checks="$(cat "$art/doctor.json")"
    doc_kernel_ok="$(jq -r '[.[] | select(.name == "kernel") | .ok] | first // false' "$art/doctor.json")"
    doc_btf_ok="$(jq -r '[.[] | select(.name == "btf") | .ok] | first // false' "$art/doctor.json")"
    doc_btf_sha="$(jq -r '[.[] | select(.name == "btf_sha256") | .detail] | first // ""' "$art/doctor.json")"
  fi
  if ((doctor_rc == 0)) && [[ "$doc_kernel_ok" == "true" && "$doc_btf_ok" == "true" ]]; then
    add_check "doctor" true true "doctor --json exit 0 in $((SECONDS - doc_start))s; kernel+btf ok; btf sha256 ${doc_btf_sha:0:12}..."
  else
    add_check "doctor" false true "doctor --json exit $doctor_rc; kernel_ok=$doc_kernel_ok btf_ok=$doc_btf_ok (see $art/doctor.json, $art/doctor.err)"
  fi

  # Copy the two generated guest helpers once.
  local helper_ok=1
  "$lab" copy --name "$instance" "$out_root/activity.sh" /tmp/matrix-activity.sh >"$art/copy-helpers.log" 2>&1 || helper_ok=0
  "$lab" copy --name "$instance" "$out_root/guest-probe.sh" /tmp/matrix-guest-probe.sh >>"$art/copy-helpers.log" 2>&1 || helper_ok=0
  if ((helper_ok)); then
    "$lab" run --name "$instance" -- chmod 0755 /tmp/matrix-activity.sh /tmp/matrix-guest-probe.sh >>"$art/copy-helpers.log" 2>&1 || true
  else
    add_check "guest_helpers" false true "could not copy activity/guest-probe scripts; see $art/copy-helpers.log"
  fi

  # Clean any stale bundles inside the throwaway guest.
  "$lab" run --name "$instance" -- sudo -n rm -rf /tmp/matrix.fleet /tmp/matrix-probe-process /tmp/matrix.fleet.tar.gz \
    >/dev/null 2>&1 || true

  # Main recording: record runs in one SSH session while a second session
  # generates process/file activity for the same window.
  local record_pid activity_rc=0
  local activity_window=$((record_seconds - 3))
  ((activity_window >= 1)) || activity_window=1
  "$lab" run --name "$instance" -- sudo -n /tmp/ebpf-fleet record --for "$record_seconds" --out /tmp/matrix.fleet \
    >"$art/record.out" 2>"$art/record.err" &
  record_pid=$!
  sleep 1
  "$lab" run --name "$instance" -- env MATRIX_PROBE_DIR=/tmp/matrix-probe bash /tmp/matrix-activity.sh "$activity_window" \
    >"$art/activity.out" 2>"$art/activity.err" || activity_rc=$?
  record_rc=0
  wait "$record_pid" || record_rc=$?
  if ((record_rc == 0)); then
    add_check "record" true true "record --for $record_seconds exited 0 while activity was generated"
  else
    add_check "record" false true "record --for $record_seconds exited $record_rc; see $art/record.err"
  fi
  if [[ "$activity_rc" != "0" ]]; then
    add_check "activity" false true "activity generator exited $activity_rc; see $art/activity.err"
  else
    add_check "activity" true true "deterministic activity for ${activity_window}s completed"
  fi
  if [[ -s "$art/record.err" ]]; then
    if grep -Eq 'recorded [0-9]+ events' "$art/record.err"; then
      record_events="$(sed -n 's/.*recorded \([0-9][0-9]*\) events (\([0-9][0-9]*\) decode errors).*/\1/p' "$art/record.err" | head -n 1)"
      decode_errors="$(sed -n 's/.*recorded \([0-9][0-9]*\) events (\([0-9][0-9]*\) decode errors).*/\2/p' "$art/record.err" | head -n 1)"
    fi
  fi
  if ((record_events > 0)); then
    add_check "record_events" true true "recorded $record_events events ($decode_errors decode errors)"
  else
    add_check "record_events" false true "recording reported no events (see $art/record.err)"
  fi
  sensor_warnings="$(grep -E '^warning: sensor ' "$art/record.err" 2>/dev/null | jq -R -s 'split("\n") | map(select(length > 0))' 2>/dev/null)" || sensor_warnings='[]'


  # query: kind counts and FileOpen paths from the guest bundle.
  if ((record_rc == 0 && record_events > 0)); then
    kinds_rc=0
    local sql_kinds="select kind, count(*) as n from events group by kind order by kind"
    local remote_query_kinds
    remote_query_kinds="sudo -n /tmp/ebpf-fleet query /tmp/matrix.fleet $(printf '%q' "$sql_kinds")"
    "$lab" run --name "$instance" -- "$remote_query_kinds" \
      >"$art/query-kinds.txt" 2>"$art/query-kinds.err" || kinds_rc=$?
    if ((kinds_rc == 0)); then
      counts="$(kinds_to_json "$art/query-kinds.txt")"
      local process_count file_count
      file_count="$(json_count "$counts" FileOpen)"
      process_count=$(($(json_count "$counts" ProcessFork) + $(json_count "$counts" ProcessExec) + $(json_count "$counts" ProcessExit)))
      file_open_count="$file_count"
      if ((file_count > 0 && process_count > 0)); then
        add_check "query_kinds" true true "kinds: $(jq -c . <<<"$counts")"
      else
        add_check "query_kinds" false true "FileOpen=$file_count process_kinds=$process_count; kinds: $(jq -c . <<<"$counts")"
      fi
    else
      add_check "query_kinds" false true "query exited $kinds_rc; see $art/query-kinds.err"
    fi

    paths_rc=0
    local sql_paths="select path, count(*) as n from events where kind = 'FileOpen' group by path order by n desc limit 25"
    local remote_query_paths
    remote_query_paths="sudo -n /tmp/ebpf-fleet query /tmp/matrix.fleet $(printf '%q' "$sql_paths")"
    "$lab" run --name "$instance" -- "$remote_query_paths" \
      >"$art/query-file-paths.txt" 2>"$art/query-file-paths.err" || paths_rc=$?
    if ((paths_rc == 0)); then
      top_paths="$(paths_to_json "$art/query-file-paths.txt")"
      if grep -qF -- "$probe_path" "$art/query-file-paths.txt"; then
        probe_seen=1
      fi
    fi
    if ((paths_rc != 0)); then
      add_check "file_open_paths" false true "FileOpen path query exited $paths_rc; see $art/query-file-paths.err"
    elif ((file_open_count > 0 && probe_seen)); then
      add_check "file_open_paths" true true "FileOpen=$file_open_count; deterministic probe path '$probe_path' decoded"
    elif ((file_open_count > 0)); then
      # Fall back to the replayed JSON stream if the pretty table was
      # truncated for the probe path; replay is written after this point.
      add_check "file_open_paths" true true "FileOpen=$file_open_count; path column populated (probe-path literal not in the top-25 table)"
    else
      add_check "file_open_paths" false true "FileOpen query returned no paths (FileOpen=$file_open_count); see $art/query-file-paths.txt"
    fi
  else
    add_check "query_kinds" false true "skipped: record produced no events"
    add_check "file_open_paths" false true "skipped: record produced no events"
  fi

  # replay: full JSONL stream kept as evidence, first line validated.
  if ((record_rc == 0 && record_events > 0)); then
    replay_rc=0
    "$lab" run --name "$instance" -- sudo -n /tmp/ebpf-fleet replay /tmp/matrix.fleet \
      >"$art/replay.jsonl" 2>"$art/replay.err" || replay_rc=$?
    replay_lines="$(wc -l <"$art/replay.jsonl" 2>/dev/null || echo 0)"
    replay_lines="${replay_lines//[[:space:]]/}"
    first_line="$(head -n 1 "$art/replay.jsonl" 2>/dev/null || true)"
    if [[ -n "$first_line" ]] && jq -e 'type == "object" and (.kind | type == "string") and (.kind | length > 0)' \
      >/dev/null 2>&1 <<<"$first_line"; then
      replay_valid=1
      first_kind="$(jq -r '.kind' <<<"$first_line")"
    fi
    if ((replay_rc == 0 && replay_valid && replay_lines == record_events)); then
      add_check "replay" true true "replay exit 0, $replay_lines lines, first line kind=$first_kind"
    else
      add_check "replay" false true "replay exit $replay_rc, lines=$replay_lines (recorded=$record_events), first-line valid=$replay_valid"
    fi
    # Probe path may not fit the top-25 kind query; the replay stream has
    # every event, so use it to confirm the file sensor really decoded paths.
    if ((probe_seen == 0 && replay_valid)) && grep -qF -- "$probe_path" "$art/replay.jsonl"; then
      probe_seen=1
      top_paths="$(jq -r 'select(.kind == "FileOpen") | .path // empty' "$art/replay.jsonl" 2>/dev/null |
        sort | jq -R -s 'split("\n") | map(select(length > 0)) | .[0:25]')"
      add_note "FileOpen '$probe_path' verified from the replay JSONL stream (not only the SQL table)"
    fi
  else
    add_check "replay" false true "skipped: record produced no events"
  fi

  # Process-only probe: with the same binary and a fresh bundle, ProcessExit
  # events exist only when the sched_process_exit raw tracepoint attached.
  local probe_pid probe_activity_rc=0
  local probe_window=$((probe_seconds - 2))
  ((probe_window >= 1)) || probe_window=1
  "$lab" run --name "$instance" -- sudo -n /tmp/ebpf-fleet record --sensors process --for "$probe_seconds" \
    --out /tmp/matrix-probe-process >"$art/probe-record.out" 2>"$art/probe-record.err" &
  probe_pid=$!
  sleep 1
  "$lab" run --name "$instance" -- env MATRIX_PROBE_DIR=/tmp/matrix-probe bash /tmp/matrix-activity.sh "$probe_window" \
    >"$art/probe-activity.out" 2>"$art/probe-activity.err" || probe_activity_rc=$?
  probe_rc=0
  wait "$probe_pid" || probe_rc=$?
  probe_query_rc=0
  if ((probe_rc == 0)); then
    probe_events="$(sed -n 's/.*recorded \([0-9][0-9]*\) events.*/\1/p' "$art/probe-record.err" | head -n 1)"
    probe_events="${probe_events:-0}"
    local sql_probe_kinds="select kind, count(*) as n from events group by kind order by kind"
    local remote_probe_query
    remote_probe_query="sudo -n /tmp/ebpf-fleet query /tmp/matrix-probe-process $(printf '%q' "$sql_probe_kinds")"
    "$lab" run --name "$instance" -- "$remote_probe_query" \
      >"$art/probe-query-kinds.txt" 2>"$art/probe-query-kinds.err" || probe_query_rc=$?
    if ((probe_query_rc == 0)); then
      probe_counts="$(kinds_to_json "$art/probe-query-kinds.txt")"
    fi
  fi
  if ((probe_rc == 0 && probe_query_rc == 0 && probe_events > 0)); then
    add_check "process_probe" true true "process-only record: $probe_events events; counts $(jq -c . <<<"$probe_counts")"
  else
    add_check "process_probe" false true "process-only probe failed: record=$probe_rc query=$probe_query_rc events=${probe_events:-0}"
  fi
  if ((probe_activity_rc != 0)); then
    add_check "probe_activity" false true "probe activity generator exited $probe_activity_rc"
  fi
  local exit_count fork_count exec_count
  exit_count="$(json_count "$probe_counts" ProcessExit)"
  fork_count="$(json_count "$probe_counts" ProcessFork)"
  exec_count="$(json_count "$probe_counts" ProcessExec)"
  if ((exit_count > 0)); then
    add_check "exit_tracepoint" true false "sched_process_exit attached: ProcessFork=$fork_count ProcessExec=$exec_count ProcessExit=$exit_count"
  else
    add_check "exit_tracepoint" false false "sched_process_exit missing: ProcessFork=$fork_count ProcessExec=$exec_count ProcessExit=0"
  fi

  # Guest facts: kernel release, os-release, BTF size/sha256, LSM list,
  # manifest completeness, dmesg tail.
  "$lab" run --name "$instance" -- bash /tmp/matrix-guest-probe.sh /tmp/matrix.fleet /tmp/matrix-probe-process \
    >"$art/guest-info.txt" 2>"$art/guest-info.err" || true
  kernel_release="$(fact "$art/guest-info.txt" uname kernel_release)"
  kernel_uname_a="$(sed -n '/^\[uname\]$/,/^\[/p' "$art/guest-info.txt" 2>/dev/null | sed -n '2p' || true)"
  os_id="$(fact "$art/guest-info.txt" os-release id)"
  os_version_id="$(fact "$art/guest-info.txt" os-release version_id)"
  os_pretty_name="$(fact "$art/guest-info.txt" os-release pretty_name)"
  btf_present=0
  [[ "$(fact "$art/guest-info.txt" btf present)" == "yes" ]] && btf_present=1
  btf_size="$(fact "$art/guest-info.txt" btf size_bytes)"
  btf_size="${btf_size:-0}"
  btf_sha256="$(fact "$art/guest-info.txt" btf sha256)"
  lsm="$(fact "$art/guest-info.txt" security lsm)"
  lockdown="$(fact "$art/guest-info.txt" security lockdown)"
  unprivileged="$(fact "$art/guest-info.txt" security unprivileged_bpf_disabled)"
  bundle_complete="$(fact "$art/guest-info.txt" bundle complete)"
  local manifest_events
  manifest_events="$(fact "$art/guest-info.txt" bundle events)"
  local guest_btf_from_manifest
  guest_btf_from_manifest="$(fact "$art/guest-info.txt" bundle host_btf_sha256)"
  local probe_manifest_events
  probe_manifest_events="$(fact "$art/guest-info.txt" probe-bundle events)"

  if ((btf_present && btf_size > 0)) && [[ "$btf_sha256" =~ ^[0-9a-f]{64}$ ]]; then
    add_check "btf" true true "present, $btf_size bytes, sha256 $btf_sha256"
  else
    add_check "btf" false true "missing/unreadable /sys/kernel/btf/vmlinux (present=$btf_present size=$btf_size)"
  fi
  if [[ -n "$expected_series" && "$kernel_release" == "$expected_series".* ]]; then
    kernel_series_match=1
    add_check "kernel_series" true true "uname -r $kernel_release matches pinned series $expected_series"
  else
    add_check "kernel_series" false true "uname -r '${kernel_release:-unknown}' does not match pinned series '$expected_series'"
  fi
  if [[ "$(fact "$art/guest-info.txt" tools jq)" == "present" && "$(fact "$art/guest-info.txt" tools tar)" == "present" ]] &&
    [[ "$(fact "$art/guest-info.txt" tools sudo)" == "ok" ]]; then
    add_check "guest_packages" true true "jq, tar and passwordless sudo present in the guest"
  else
    add_check "guest_packages" false true "guest tool package check failed (see $art/guest-info.txt [tools])"
  fi
  if [[ "$bundle_complete" == "true" && "$manifest_events" == "$record_events" ]]; then
    add_check "bundle_complete" true true "manifest complete=true, counts.events=$manifest_events matches record stderr"
  else
    add_check "bundle_complete" false true "manifest complete='$bundle_complete', events='$manifest_events', expected $record_events"
  fi
  if [[ "$probe_manifest_events" == "$probe_events" ]]; then
    add_check "probe_bundle_complete" true true "probe manifest counts.events=$probe_manifest_events matches record stderr"
  else
    add_check "probe_bundle_complete" false true "probe manifest events='$probe_manifest_events' != recorded '$probe_events'"
  fi
  if [[ -n "$guest_btf_from_manifest" && "$guest_btf_from_manifest" != "unknown" && "$guest_btf_from_manifest" == "$btf_sha256" ]]; then
    add_check "manifest_host_facts" true true "bundle host.btf_sha256 matches guest BTF sha256"
  else
    add_check "manifest_host_facts" false true "bundle host.btf_sha256 '$guest_btf_from_manifest' != guest BTF '$btf_sha256'"
  fi

  # Informational: which file-sensor attach path this kernel exposes.
  if [[ "$lsm" == *bpf* ]]; then
    file_sensor_path="lsm"
  else
    file_sensor_path="kprobe-no-bpf-lsm"
  fi
  add_check "file_sensor_path" true false "lsm='$lsm' -> file sensor path: $file_sensor_path"

  # Recorded after the guest facts are parsed so the note names the exact
  # booted kernel release.
  if ((exit_count > 0)); then
    add_note "sched_process_exit raw tracepoint attached on $kernel_release (ProcessExit events present)"
  else
    add_note "known limitation reproduced on $kernel_release: the sched_process_exit raw tracepoint produced no ProcessExit events (ProcessFork=$fork_count, ProcessExec=$exec_count), so process-exit events are absent from bundles on this kernel"
  fi

  # Export the guest bundle so the evidence survives the VM teardown.
  export_rc=0
  "$lab" run --name "$instance" -- sudo -n tar -C /tmp -czf /tmp/matrix.fleet.tar.gz matrix.fleet \
    >"$art/export.log" 2>&1 || export_rc=$?
  if ((export_rc == 0)); then
    export_rc=1
    if "$lab" copy --name "$instance" --from-guest /tmp/matrix.fleet.tar.gz "$art/matrix.fleet.tar.gz" \
      >>"$art/export.log" 2>&1; then
      mkdir -p "$art/bundle"
      export_rc=0
      tar -xzf "$art/matrix.fleet.tar.gz" -C "$art/bundle" >>"$art/export.log" 2>&1 || export_rc=$?
    fi
  fi
  if ((export_rc == 0)) && [[ -d "$art/bundle/matrix.fleet" ]]; then
    add_check "bundle_export" true true "guest bundle exported to $art_rel/matrix.fleet.tar.gz and extracted"
    host_query_ok=0
    if "$binary" query "$art/bundle/matrix.fleet" \
      "select kind, count(*) as n from events group by kind order by kind" \
      >"$art/host-query-kinds.txt" 2>"$art/host-query-kinds.err"; then
      host_query_ok=1
      add_check "bundle_portable" true false "host binary queried the guest-recorded bundle"
    else
      add_check "bundle_portable" false false "host binary could not query the guest-recorded bundle; see $art/host-query-kinds.err"
    fi
  else
    add_check "bundle_export" false true "could not export the guest bundle; see $art/export.log"
  fi

  # Always write the evidence file, then tear down via the EXIT trap.
  write_row_json
  local status
  status="$(jq -r '.status' "$json_path")"
  if [[ "$status" == "pass" ]]; then
    info "PASS $image: kernel=$kernel_release events=$record_events file_open=$file_open_count exit_tracepoint=${exit_count}"
    exit 0
  fi
  info "FAIL $image: required checks failed: $(jq -c '.failures' "$json_path"); see $json_rel"
  exit 1
}

teardown_image() {
  # teardown_image <instance> <artifact-dir>: copy logs, then stop the VM
  # unless --keep was requested. Never fails the row.
  local instance="$1" art="$2" p
  local idir="$vm_root/instances/$instance"
  mkdir -p "$art"
  for f in console.log qemu.log; do
    [[ -f "$idir/logs/$f" ]] && cp "$idir/logs/$f" "$art/$f" 2>/dev/null || true
  done
  [[ -f "$idir/instance.json" ]] && cp "$idir/instance.json" "$art/instance.json" 2>/dev/null || true
  if ((keep)); then
    p="$(jq -r '.port // empty' "$idir/instance.json" 2>/dev/null || true)"
    info "keep: instance $instance left running${p:+ (ssh 127.0.0.1:$p)}; stop with: scripts/vm/lab.sh down --name $instance"
    return 0
  fi
  if [[ -d "$idir" ]]; then
    "$lab" down --name "$instance" >/dev/null 2>&1 ||
      warn "could not tear down instance $instance; run: scripts/vm/lab.sh down --name $instance"
  fi
  for f in console.log qemu.log; do
    [[ -f "$idir/logs/$f" ]] && cp "$idir/logs/$f" "$art/$f" 2>/dev/null || true
  done
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

mark_image_result() {
  # mark_image_result <image> <subshell-status>: print a one-line summary and
  # return 0 only when the row's evidence file says "pass".
  local image="$1" rc="$2" status kernel events file_open
  local json="$out_root/$image.json"
  if jq -e . "$json" >/dev/null 2>&1; then
    status="$(jqf "$json" '.status // "error"' error)"
    kernel="$(jqf "$json" '.kernel.release // "unknown"' unknown)"
    events="$(jqf "$json" '.record.events // 0' 0)"
    file_open="$(jqf "$json" '.query.file_open_count // 0' 0)"
  else
    status="error"
    kernel="unknown"
    events="0"
    file_open="0"
  fi
  # Fail-closed: a non-zero row exit never counts as a pass, even if the
  # evidence file was written before the final step failed.
  if ((rc != 0)) && [[ "$status" == "pass" ]]; then
    status="fail"
  fi
  printf '%-14s %-5s kernel=%-26s events=%-6s file_open=%-6s %s\n' \
    "$image" "$status" "$kernel" "$events" "$file_open" "$json" >&2
  [[ "$status" == "pass" ]]
}

write_summary() {
  local rows='[]' image row_json row_fallback
  local json_rel art_rel
  for image in "${requested_images[@]}"; do
    json_rel="target/vm/matrix/$stamp/$image.json"
    art_rel="target/vm/matrix/$stamp/$image"
    row_fallback="$(jq -n --arg image "$image" --arg json "$json_rel" --arg art "$art_rel" \
      '{image: $image, status: "error", json: $json, artifacts: $art,
        kernel_release: "unknown", btf_sha256: "", events: 0, file_open_count: 0,
        exit_tracepoint_attached: false,
        failures: ["row produced no valid JSON evidence"], notes: []}')"
    if jq -e . "$out_root/$image.json" >/dev/null 2>&1; then
      row_json="$(jq -c --arg image "$image" --arg json "$json_rel" --arg art "$art_rel" --argjson rc "${ROW_RC[$image]:-1}" '
        {image: $image,
         status: (if $rc != 0 then "fail"
                  elif (.status // "error") == "pass" then "pass"
                  else (.status // "error") end),
         json: $json,
         artifacts: $art,
         kernel_release: (.kernel.release // "unknown"),
         btf_sha256: (.btf.sha256 // ""),
         events: (.record.events // 0),
         file_open_count: (.query.file_open_count // 0),
         exit_tracepoint_attached: (.sensors.exit_tracepoint.attached // false),
         failures: (.failures // []),
         notes: (.notes // [])}' "$out_root/$image.json" 2>/dev/null)" ||
        row_json="$row_fallback"
    else
      row_json="$row_fallback"
    fi
    rows="$(jq -c --argjson row "$row_json" '. + [$row]' <<<"$rows")"
  done
  local pass fail
  pass="$(jq '[.[] | select(.status == "pass")] | length' <<<"$rows")"
  fail="$(jq '[.[] | select(.status != "pass")] | length' <<<"$rows")"
  local summary_tmp="$out_root/matrix-summary.json.tmp"
  if jq -n \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg stamp "$stamp" \
    --arg host_name "$host_name" \
    --arg host_arch "$host_arch" \
    --arg host_kernel "$host_kernel" \
    --arg binary "$binary" \
    --arg binary_sha "$binary_sha" \
    --argjson binary_size "$(int_or_zero "$binary_size")" \
    --argjson record_seconds "$record_seconds" \
    --argjson probe_seconds "$probe_seconds" \
    --argjson boot_timeout "$boot_timeout" \
    --argjson rows "$rows" \
    --argjson pass "$pass" \
    --argjson fail "$fail" \
    --arg summary_path "target/vm/matrix/$stamp/matrix-summary.json" '
    {
      schema_version: 1,
      runner: "scripts/vm/run-matrix.sh",
      generated_at: $generated_at,
      stamp: $stamp,
      summary_path: $summary_path,
      host: {name: $host_name, arch: $host_arch, kernel: $host_kernel},
      binary: {path: $binary, sha256: $binary_sha, size_bytes: $binary_size},
      capture: {record_seconds: $record_seconds, probe_seconds: $probe_seconds, boot_timeout: $boot_timeout},
      rows: $rows,
      pass: $pass,
      fail: $fail
    }' >"$summary_tmp" 2>"$out_root/matrix-summary.err"; then
    mv -f "$summary_tmp" "$out_root/matrix-summary.json"
  else
    rm -f "$summary_tmp"
    warn "could not write matrix-summary.json (see target/vm/matrix/$stamp/matrix-summary.err)"
    pass="$(jq '[.[] | select(.status == "pass")] | length' <<<"$rows" 2>/dev/null || echo 0)"
    fail="$(jq '[.[] | select(.status != "pass")] | length' <<<"$rows" 2>/dev/null || echo 1)"
  fi
  SUMMARY_PASS="$pass"
  SUMMARY_FAIL="$fail"
}

main() {
  preflight
  write_activity_script "$out_root/activity.sh"
  write_guest_probe_script "$out_root/guest-probe.sh"

  info "host $host_name ($host_arch, kernel $host_kernel)"
  info "binary $binary (sha256 ${binary_sha:0:12}..., $binary_size bytes)"
  info "rows: ${requested_images[*]}"
  info "evidence: target/vm/matrix/$stamp"

  local image rc total
  declare -gA ROW_RC=()
  total=0
  for image in "${requested_images[@]}"; do
    total=$((total + 1))
    rc=0
    (run_row "$image") || rc=$?
    ROW_RC["$image"]="$rc"
    mark_image_result "$image" "$rc" || true
  done

  local pass fail
  write_summary
  pass="$SUMMARY_PASS"
  fail="$SUMMARY_FAIL"
  printf '\n'
  if ((fail == 0)); then
    printf 'MATRIX PASS: %s/%s rows\n' "$pass" "$total"
    printf 'summary: target/vm/matrix/%s/matrix-summary.json\n' "$stamp"
    exit 0
  fi
  printf 'MATRIX FAIL: %s/%s rows passed\n' "$pass" "$total"
  printf 'summary: target/vm/matrix/%s/matrix-summary.json\n' "$stamp"
  exit 1
}

main "$@"
