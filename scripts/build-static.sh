#!/usr/bin/env bash
# Build the release `ebpf-fleet` as a static-pie binary.
#
# The project dev shell uses a Nix glibc, which is newer than the glibc in
# common cloud images. A static link keeps the local binary installable on
# older distributions without shipping a glibc or a container runtime.
#
# The build requires Nix (for glibc.static), the project dev shell, and the
# embedded BPF sensors. It writes only under target/.
#
# Native build (unchanged command):
#
#   scripts/build-static.sh
#
# writes the host-architecture binary at target/release/ebpf-fleet and
# target/release/ebpf-fleet-<arch> (both with .sha256), where <arch> is
# x86_64 or aarch64.
#
# Cross build for aarch64 on an x86_64 host (0.3 release path):
#
#   scripts/build-static.sh --arch aarch64 --btf <arm64-kernel-BTF>
#
# writes target/release/ebpf-fleet-aarch64 (+ .sha256). The BPF sensors are
# CO-RE objects compiled for arm64, so bpf-build must see an arm64 kernel
# BTF at /sys/kernel/btf/vmlinux. That file is bind-mounted read-only from
# the --btf path inside an unprivileged user+mount namespace, which is the
# same view a native aarch64 host has; no sudo is used and the host /sys is
# not modified. The BTF must be a raw BTF blob (the exact bytes of
# /sys/kernel/btf/vmlinux, magic 0xeb9f). The TCG lab can produce it from
# the pinned arm64 Ubuntu image:
#
#   scripts/vm/lab.sh up --image ubuntu-24.04-arm64 --cloud-init lean \
#     --accel tcg --name arm64-tcg
#   mkdir -p target/cross
#   scripts/vm/lab.sh copy --name arm64-tcg --from-guest \
#     /sys/kernel/btf/vmlinux target/cross/arm64-vmlinux.btf
#   scripts/build-static.sh --arch aarch64 --btf target/cross/arm64-vmlinux.btf
#
# The cross toolchain is evaluated from the flake inputs pinned in
# flake.lock: the rust-overlay toolchain named in rust-toolchain.toml with
# the aarch64 standard library added, the nixpkgs aarch64 cross gcc, and
# the nixpkgs aarch64 glibc static library. A native aarch64 host does not
# need any of that: `--arch aarch64` there takes the native path above.
#
# Options:
#   --arch <x86_64|aarch64>  target architecture (default: host arch)
#   --btf <path>             arm64 kernel BTF blob for a cross build
#                            (env EBPF_FLEET_ARM64_BTF is also accepted;
#                            required when --arch differs from the host)
#   --help                   show this help

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

usage() {
  awk 'NR > 1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"
}

die() {
  printf 'build-static: error: %s\n' "$*" >&2
  exit 1
}

info() {
  printf 'build-static: %s\n' "$*" >&2
}

have() { command -v "$1" >/dev/null 2>&1; }

host_arch() {
  case "$(uname -m)" in
    x86_64 | amd64) printf 'x86_64\n' ;;
    aarch64 | arm64) printf 'aarch64\n' ;;
    *) die "unsupported host architecture: $(uname -m) (supported: x86_64, aarch64)" ;;
  esac
}

normalize_arch() {
  case "$1" in
    x86_64 | amd64) printf 'x86_64\n' ;;
    aarch64 | arm64) printf 'aarch64\n' ;;
    *) die "unsupported target architecture: '$1' (supported: x86_64, aarch64)" ;;
  esac
}

# ---------------------------------------------------------------------------
# arguments
# ---------------------------------------------------------------------------

target_arch_arg=""
btf="${EBPF_FLEET_ARM64_BTF:-}"

while (($# > 0)); do
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    --arch | --btf)
      [[ $# -ge 2 && -n "$2" ]] || die "option $1 needs a value"
      case "$1" in
        --arch) target_arch_arg="$2" ;;
        --btf) btf="$2" ;;
      esac
      shift 2
      ;;
    --arch=*)
      target_arch_arg="${1#*=}"
      shift
      ;;
    --btf=*)
      btf="${1#*=}"
      shift
      ;;
    *)
      die "unknown argument: $1 (try --help)"
      ;;
  esac
done

host="$(host_arch)"
target="$host"
[[ -n "$target_arch_arg" ]] && target="$(normalize_arch "$target_arch_arg")"

case "$host:$target" in
  x86_64:x86_64 | aarch64:aarch64)
    native=1
    ;;
  x86_64:aarch64)
    native=0
    ;;
  *)
    die "cross-build from $host to $target is not implemented; build on a native $target runner (the release workflow uses an $target GitHub-hosted runner)"
    ;;
esac

# ---------------------------------------------------------------------------
# verification helpers
# ---------------------------------------------------------------------------

require_elf_tools() {
  local tool missing=()
  for tool in file readelf sha256sum; do
    have "$tool" || missing+=("$tool")
  done
  ((${#missing[@]} == 0)) || die "missing required verification tools: ${missing[*]}"
}

# verify_static_elf <binary> <x86_64|aarch64>
verify_static_elf() {
  local bin="$1" want="$2" desc machine kind
  [[ -f "$bin" ]] || die "missing built binary: $bin"
  [[ -x "$bin" ]] || die "built binary is not executable: $bin"

  desc="$(file -b "$bin" 2>/dev/null || true)"
  case "$desc" in
    *"static-pie linked"*) kind="static-pie" ;;
    *"statically linked"*) kind="static" ;;
    *) die "$bin is not statically linked (file: '${desc:-unknown}')" ;;
  esac

  machine="$(readelf -h "$bin" 2>/dev/null | sed -n 's/.*Machine:[[:space:]]*//p' | head -n 1)"
  case "$want:$machine" in
    x86_64:*X86-64* | aarch64:*AArch64*) ;;
    *) die "$bin has the wrong ELF machine for $want: '${machine:-unknown}'" ;;
  esac

  if readelf -d "$bin" 2>/dev/null | grep -q 'NEEDED'; then
    die "$bin has dynamic NEEDED entries (not fully static)"
  fi
  if readelf -l "$bin" 2>/dev/null | grep -q 'INTERP'; then
    die "$bin has a PT_INTERP program header (not a static executable)"
  fi

  info "verified $bin: $want $kind, $desc, $(du -h "$bin" | cut -f1)"
}

# write_asset <built-binary> <arch>: publish the arch-named release asset.
write_asset() {
  local built="$1" arch="$2" asset="target/release/ebpf-fleet-$2"
  cp -f "$built" "$asset"
  (cd target/release && sha256sum "ebpf-fleet-$arch" >"ebpf-fleet-$arch.sha256")
  info "asset $asset ($(du -h "$asset" | cut -f1))"
  cat "$asset.sha256"
}

# ---------------------------------------------------------------------------
# native build (host arch == target arch)
# ---------------------------------------------------------------------------

native_build() {
  local glibc_static bin
  info "native build for $target"
  # libbpf-sys vendors elfutils for its static build. On a native aarch64
  # Nix runner libbpf-sys picked clang as `cc`, but elfutils' configure passes
  # GCC-only warnings such as -Werror=stringop-overflow, which clang rejects.
  # Use gcc for the vendored C build; BPF compilation still uses the pinned
  # clang explicitly and the Rust link still uses the static glibc.
  if [[ "$target" == "aarch64" ]]; then
    export CC="${CC:-gcc}"
    export CXX="${CXX:-g++}"
  fi
  glibc_static="$(nix build --no-link --print-out-paths nixpkgs#glibc.static)"
  [[ -d "$glibc_static/lib" ]] || {
    die "glibc.static has no lib directory: $glibc_static"
  }

  if [[ "$target" == "aarch64" ]]; then
    # Nix's devshell sets CC=clang; libbpf-sys vendors elfutils and its
    # configure passes GCC-only warning flags that clang rejects. Passing
    # CC/CXX through `env` overrides the devshell default for the Rust
    # build; BPF compilation still uses the pinned clang explicitly.
    nix develop --no-pure-eval --accept-flake-config -c \
      env CC=gcc CXX=g++ \
      cargo rustc -p fleet --release --locked -- \
      -C target-feature=+crt-static \
      -L "native=$glibc_static/lib"
  else
    nix develop --no-pure-eval --accept-flake-config -c \
      cargo rustc -p fleet --release --locked -- \
      -C target-feature=+crt-static \
      -L "native=$glibc_static/lib"
  fi

  bin="target/release/ebpf-fleet"
  [[ -x "$bin" ]] || die "missing $bin"

  # Symbols are not needed in the distributed local binary.
  if have strip; then
    strip --strip-all "$bin"
  fi

  verify_static_elf "$bin" "$target"
  sha256sum "$bin" >"$bin.sha256"
  write_asset "$bin" "$target"
  printf 'built %s (%s)\n' "$bin" "$(du -h "$bin" | cut -f1)"
  cat "$bin.sha256"
}

# ---------------------------------------------------------------------------
# aarch64 cross build from x86_64
# ---------------------------------------------------------------------------

resolve_cross_toolchain() {
  # Build one store path that bundles the pinned cross toolchain:
  # rust (with the aarch64 std), aarch64 gcc/binutils, aarch64 glibc.static.
  local channel expr toolchain_dir
  channel="$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' rust-toolchain.toml | head -n 1)"
  [[ -n "$channel" ]] || die "cannot read the toolchain channel from rust-toolchain.toml"
  info "cross toolchain channel: rust $channel"

  expr="$(
    cat <<EOF
let
  repo = builtins.getFlake "$root";
  rustOverlay = repo.inputs.rust-overlay;
  pkgs = import repo.inputs.nixpkgs {
    system = "$host-linux";
    overlays = [ rustOverlay.overlays.default ];
  };
  cross = pkgs.pkgsCross.aarch64-multiplatform;
  rust = pkgs.rust-bin.stable."$channel".default.override {
    targets = [ "aarch64-unknown-linux-gnu" ];
  };
in
pkgs.runCommand "ebpf-fleet-aarch64-cross-toolchain" { } ''
  mkdir -p \$out
  ln -s \${rust} \$out/rust
  ln -s \${cross.stdenv.cc} \$out/gcc
  ln -s \${cross.glibc.static} \$out/glibc-static
''
EOF
  )"
  toolchain_dir="$(nix build --impure --no-link --print-out-paths --expr "$expr")"
  [[ -x "$toolchain_dir/rust/bin/rustc" ]] ||
    die "cross toolchain has no rustc: $toolchain_dir/rust/bin/rustc"
  [[ -x "$toolchain_dir/gcc/bin/aarch64-unknown-linux-gnu-gcc" ]] ||
    die "cross toolchain has no aarch64 gcc: $toolchain_dir/gcc"
  [[ -d "$toolchain_dir/glibc-static/lib" ]] ||
    die "cross toolchain has no aarch64 static glibc: $toolchain_dir/glibc-static"
  printf '%s\n' "$toolchain_dir"
}

resolve_arm64_btf() {
  local path
  path="$btf"
  if [[ -z "$path" ]]; then
    path="target/cross/arm64-vmlinux.btf"
  fi
  [[ -f "$path" ]] || {
    cat >&2 <<EOF
build-static: error: the aarch64 cross build needs an arm64 kernel BTF blob.
build-static: error: provide --btf <path> or set EBPF_FLEET_ARM64_BTF.
build-static: how: boot the pinned arm64 image under the TCG lab and copy
build-static: how: /sys/kernel/btf/vmlinux out of it:
build-static: how:   scripts/vm/lab.sh up --image ubuntu-24.04-arm64 \\
build-static: how:     --cloud-init lean --accel tcg --name arm64-tcg
build-static: how:   scripts/vm/lab.sh copy --name arm64-tcg --from-guest \\
build-static: how:     /sys/kernel/btf/vmlinux target/cross/arm64-vmlinux.btf
build-static: note: the BTF is the exact blob the guest kernel exposes; the
build-static: note: sensors are CO-RE and compile against the arm64 types.
EOF
    exit 1
  }
  [[ -s "$path" ]] || die "arm64 BTF file is empty: $path"
  local magic sha
  magic="$(od -An -tx1 -N4 "$path" | tr -d ' \n')"
  [[ "$magic" == "9feb0100" ]] ||
    die "arm64 BTF file is not a raw BTF blob (magic '$magic', expected 9feb0100): $path"
  sha="$(sha256sum "$path" | cut -d' ' -f1)"
  info "arm64 BTF: $(cd "$(dirname "$path")" && pwd -P)/$(basename "$path") sha256 $sha"
  printf '%s/%s\n' "$(cd "$(dirname "$path")" && pwd -P)" "$(basename "$path")"
}

cross_build() {
  local btf_path toolchain_dir runner bin
  info "cross build for aarch64 on $host"
  require_elf_tools
  have nix || die "cross build needs Nix"
  have unshare || die "cross build needs unshare(1) from util-linux"

  btf_path="$(resolve_arm64_btf)"
  [[ -e /sys/kernel/btf/vmlinux ]] ||
    die "/sys/kernel/btf/vmlinux is missing on this host; the cross build bind-mounts the arm64 BTF over it"
  if ! unshare -rm true >/dev/null 2>&1; then
    die "the cross build needs unprivileged user+mount namespaces (unshare -rm); this host forbids them. Build on a native aarch64 host instead."
  fi

  toolchain_dir="$(resolve_cross_toolchain)"
  info "cross toolchain: $toolchain_dir"
  info "arm64 BTF: $btf_path (sha256 $(sha256sum "$btf_path" | cut -d' ' -f1))"

  mkdir -p target/cross
  runner="target/cross/cross-build.sh"
  cat >"$runner" <<EOF
#!/usr/bin/env bash
# Generated by scripts/build-static.sh for the aarch64 cross build.
set -euo pipefail
cd "$root"
export PATH="$toolchain_dir/rust/bin:\$PATH"
export CC_aarch64_unknown_linux_gnu="$toolchain_dir/gcc/bin/aarch64-unknown-linux-gnu-gcc"
export CXX_aarch64_unknown_linux_gnu="$toolchain_dir/gcc/bin/aarch64-unknown-linux-gnu-g++"
export AR_aarch64_unknown_linux_gnu="$toolchain_dir/gcc/bin/aarch64-unknown-linux-gnu-ar"
export RANLIB_aarch64_unknown_linux_gnu="$toolchain_dir/gcc/bin/aarch64-unknown-linux-gnu-ranlib"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$toolchain_dir/gcc/bin/aarch64-unknown-linux-gnu-gcc"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-feature=+crt-static -L native=$toolchain_dir/glibc-static/lib"
export CARGO_INCREMENTAL=0
exec cargo build -p fleet --release --locked --target aarch64-unknown-linux-gnu
EOF
  chmod 0755 "$runner"

  # bpf-build reads the kernel BTF from the fixed path
  # /sys/kernel/btf/vmlinux; inside this private mount namespace the host
  # file is replaced by the arm64 blob. The host /sys is untouched.
  unshare -rm bash -c '
    set -euo pipefail
    mount --bind "$1" /sys/kernel/btf/vmlinux
    shift
    exec "$@"
  ' build-static "$btf_path" \
    nix develop --no-pure-eval --accept-flake-config -c bash "$runner"

  # Prove the objects embedded in this binary are arm64. The generated
  # bpf-loader table is per-cargo-target, so unlike the shared
  # target/bpf-out/ build directory it cannot be replaced by a concurrent
  # native x86_64 build in the same workspace.
  local embedded
  embedded="$(ls -t target/aarch64-unknown-linux-gnu/release/build/bpf-loader-*/out/embedded_artifacts.rs 2>/dev/null | head -n 1)"
  [[ -n "$embedded" && -f "$embedded" ]] ||
    die "missing the bpf-loader embedded sensor table under target/aarch64-unknown-linux-gnu/release/build"
  [[ "$(grep -c 'arch: "arm64"' "$embedded")" -ge 2 ]] ||
    die "the sensors embedded in the aarch64 binary are not arm64: $embedded"
  info "embedded BPF sensors: $(grep -o 'name: "[a-z]*", arch: "arm64"' "$embedded" | tr '\n' ' ')"
  if [[ -f target/bpf-out/file.arm64.bpf.o ]]; then
    info "arm64 BPF sensor object: $(file -b target/bpf-out/file.arm64.bpf.o)"
  fi

  bin="target/aarch64-unknown-linux-gnu/release/ebpf-fleet"
  [[ -f "$bin" ]] || die "missing cross-built binary: $bin"
  if [[ -x "$toolchain_dir/gcc/bin/aarch64-unknown-linux-gnu-strip" ]]; then
    "$toolchain_dir/gcc/bin/aarch64-unknown-linux-gnu-strip" --strip-all "$bin"
  fi

  verify_static_elf "$bin" aarch64
  write_asset "$bin" aarch64

  # Optional: run the foreign-architecture binary with qemu user emulation.
  # The static binary needs no interpreter, so this proves it is executable
  # even though the host kernel cannot run it natively.
  if have qemu-aarch64; then
    info "qemu-user smoke: $(qemu-aarch64 "target/release/ebpf-fleet-aarch64" --version 2>&1)"
  else
    info "qemu-aarch64 not on PATH; skipping the qemu-user smoke"
  fi
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

require_elf_tools
if ((native)); then
  native_build
else
  cross_build
fi
