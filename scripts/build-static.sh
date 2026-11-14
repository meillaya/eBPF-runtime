#!/usr/bin/env bash
# Build the release `ebpf-fleet` as a static-pie binary.
#
# The project dev shell uses a Nix glibc, which is newer than the glibc in
# common cloud images. A static link keeps the local binary installable on
# older distributions without shipping a glibc or a container runtime.
#
# The build requires Nix (for glibc.static), the project dev shell, and the
# embedded BPF sensors. It writes only under target/ and leaves the binary at
# target/release/ebpf-fleet.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

glibc_static="$(nix build --no-link --print-out-paths nixpkgs#glibc.static)"
[[ -d "$glibc_static/lib" ]] || {
  echo "build-static: glibc.static has no lib directory: $glibc_static" >&2
  exit 1
}

nix develop --no-pure-eval --accept-flake-config -c \
  cargo rustc -p fleet --release --locked -- \
  -C target-feature=+crt-static \
  -L "native=$glibc_static/lib"

bin="target/release/ebpf-fleet"
[[ -x "$bin" ]] || { echo "build-static: missing $bin" >&2; exit 1; }
if ldd "$bin" 2>&1 | grep -qE 'not a dynamic executable|statically linked'; then
  :
else
  echo "build-static: $bin is not statically linked" >&2
  ldd "$bin" >&2 || true
  exit 1
fi

# Symbols are not needed in the distributed local binary.
if command -v strip >/dev/null 2>&1; then
  strip --strip-all "$bin"
fi
sha256sum "$bin" >"$bin.sha256"
printf 'built %s (%s)\n' "$bin" "$(du -h "$bin" | cut -f1)"
cat "$bin.sha256"
