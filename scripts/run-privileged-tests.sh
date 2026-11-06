#!/usr/bin/env bash
# Run the privileged sensor test against the running kernel.
#
# The test loads the process sensor, runs /bin/true, and reads the ring
# buffer until it sees the exec event. It needs root, CAP_BPF, and
# CAP_PERFMON. A container needs --privileged and --pid=host.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root: sudo -E $0" >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is not on root's PATH; run with sudo -E or install the toolchain" >&2
  exit 1
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
cargo test -p runtime --test privileged -- --ignored --nocapture
