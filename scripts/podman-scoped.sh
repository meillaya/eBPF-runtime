#!/usr/bin/env bash
# Run rootless Podman with all state constrained to this workspace.
#
# The repository's 0.2 plan uses rootless Podman for unprivileged work such
# as image builds, image save/load, and test fixtures. Rootful Podman for
# the BPF data path runs inside the KVM lab VM, not on the host.
#
# Usage:
#   scripts/podman-scoped.sh info
#   scripts/podman-scoped.sh build -t localhost/ebpf-fleet:test .
#   scripts/podman-scoped.sh save -o target/podman/images/ebpf-fleet.tar localhost/ebpf-fleet:test
#
# The wrapper sets graphroot, runroot, TMPDIR, and XDG_RUNTIME_DIR under
# target/podman. It refuses to run if any resolved path escapes the
# repository. It never invokes sudo.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
base="$root/target/podman"

# All persistent and runtime state lives here. target/ is gitignored.
storage="$base/storage"
runroot="$base/runroot"
tmp="$base/tmp"
runtime="$base/runtime"
images="$base/images"

mkdir -p "$storage" "$runroot" "$tmp" "$runtime" "$images"
chmod 700 "$runtime"

# Fail closed rather than silently falling back to the user's default
# ~/.local/share/containers graphroot.
for path in "$base" "$storage" "$runroot" "$tmp" "$runtime" "$images"; do
  resolved="$(realpath -m -- "$path")"
  case "$resolved" in
    "$root"/*) ;;
    *)
      echo "podman-scoped: refusing path outside workspace: $resolved" >&2
      exit 1
      ;;
  esac
done

storage_conf="$base/storage.conf"
if [[ ! -f "$storage_conf" ]] || ! grep -Fq "graphroot = \"$storage\"" "$storage_conf" 2>/dev/null; then
  cat >"$storage_conf" <<EOF
[storage]
driver = "overlay"
graphroot = "$storage"
runroot = "$runroot"
EOF
fi

if ! command -v podman >/dev/null 2>&1; then
  echo "podman-scoped: podman is not on PATH" >&2
  exit 1
fi

export CONTAINERS_STORAGE_CONF="$storage_conf"
export TMPDIR="$tmp"
export XDG_RUNTIME_DIR="$runtime"

# --root/--runroot make the containment explicit even if a caller has a
# conflicting CONTAINERS_STORAGE_CONF. --events-backend=file keeps event
# state with the container store rather than a user runtime directory.
exec podman \
  --root "$storage" \
  --runroot "$runroot" \
  --events-backend=file \
  "$@"
