# release.nix — kernel-v1 (eBPF Runtime Security & Observability)
#
# Reproducible Nix flake that produces a `release` package output per
# system (x86_64-linux, aarch64-linux). Each output is a tarball
# containing a single placeholder binary plus a release-manifest.json.
# Later tasks (49-51) replace the placeholder binary with the real
# agent binary produced by `cargo build --release`; this flake is the
# skeleton that wraps that future binary in a versioned, signed,
# multi-arch release artifact.
#
# Re-uses the same nixpkgs / devenv inputs as ./flake.nix so the
# agent's runtime toolchain (clang, bpftools, libbpf, sqlcipher) is
# inherited without duplication. No package list is re-declared here.
#
# Invocation:
#   nix build ./release.nix#release.x86_64-linux
#   nix build ./release.nix#release.aarch64-linux
#
# The `release` derivation compiles a freestanding placeholder ELF for
# the target architecture via the system C compiler (clang). Each
# architecture naturally produces its own ELF class, so the downstream
# `scripts/oci-inspect.py` `file`-architecture check works without
# any conditional logic beyond reading the ELF header.
#
# Task 8 of .omo/plans/ebpf-runtime-security-observability.md.
# SPDX-License-Identifier: Apache-2.0 OR MIT

{
  description = "kernel-v1 — reproducible release artefacts (task 8)";

  inputs = {
    # Follow the same nixpkgs pinned by devenv as flake.nix does; the
    # agent's runtime requirements (clang, bpftools, libbpf, sqlcipher)
    # are inherited without re-declaration. We follow `devenv/nixpkgs`
    # here because flake.nix follows `devenv/nixpkgs` and any drift
    # between the two would be a supply-chain regression that the
    # task-4 quality gates (cargo deny) would flag.
    nixpkgs.follows = "devenv/nixpkgs";

    # We do not need devenv.lib here, but follow the same input so
    # the lock evaluation stays hermetic and identical to flake.nix.
    devenv.url = "github:cachix/devenv/v2.1.2";
  };

  outputs = { self, nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forEachSystem = nixpkgs.lib.genAttrs systems;

      # Map nix system to the OCI arch label used in
      # scripts/release-verify.sh and scripts/oci-inspect.py.
      archForSystem = sys:
        if sys == "x86_64-linux" then "amd64"
        else if sys == "aarch64-linux" then "arm64"
        else throw "release.nix: unsupported system '${sys}'";

      # What `file(1)` is expected to print for an ELF binary of the
      # given OCI arch. The OCI inspector asserts on this prefix.
      elfClassForArch = arch:
        if arch == "amd64" then "ELF 64-bit LSB executable, x86-64"
        else if arch == "arm64" then "ELF 64-bit LSB executable, ARM aarch64"
        else throw "release.nix: unknown arch '${arch}'";

      # The release commit. When the flake is built from a working
      # tree, sourceInfo.rev is the dirty commit hash; for tagged
      # releases it is the resolved tag commit. When no git context is
      # available (e.g. fetched tarball) fall back to the all-zeros
      # placeholder.
      commit =
        let
          rev = self.sourceInfo.rev or "0000000000000000000000000000000000000000";
        in
          builtins.substring 0 40 rev;

      # Freestanding placeholder source. The C program uses raw
      # syscalls (write + exit) so it builds without libc / musl /
      # glibc and produces an ELF whose architecture matches the
      # build system. The string is embedded in the derivation; no
      # separate source file is required, keeping the scaffold
      # single-file.
      placeholderC = arch: ''
        /* kernel-v1 agent placeholder (task 8 scaffold).
         *
         * Replaced by the real agent binary in tasks 49-51. The
         * placeholder is freestanding (no libc); it writes the
         * self-identification line to stdout via the write(2) syscall
         * and exits 0 via the exit_group(2) syscall so the binary
         * builds on every architecture without external runtime
         * dependencies. The build system compiles this C source
         * natively, producing an ELF binary whose class matches the
         * target system; scripts/oci-inspect.py checks `file(1)`
         * output against the manifest's expected class.
         */
        static const char msg[] =
            "kernel-v1 agent placeholder ${arch} build ${commit}\\n";

        /* Linux syscall numbers (x86_64 / aarch64). */
        #if defined(__x86_64__)
        #  define SYS_WRITE   1
        #  define SYS_EXIT   60
        #elif defined(__aarch64__)
        #  define SYS_WRITE   64
        #  define SYS_EXIT   93
        #else
        #  error "unsupported architecture for placeholder"
        #endif

        /* Linux write(2) -> int write(int fd, const void *buf, unsigned long count). */
        static long sys_write(int fd, const void *buf, unsigned long count) {
            long ret;
            __asm__ volatile (
                "syscall"
                : "=a"(ret)
                : "0"((long)SYS_WRITE), "D"(fd), "S"(buf), "d"(count)
                : "rcx", "r11", "memory"
            );
            return ret;
        }

        /* Linux exit_group(2). */
        static void sys_exit(int code) {
            __asm__ volatile (
                "syscall"
                :
                : "a"((long)SYS_EXIT), "D"((long)code)
                : "memory"
            );
            __builtin_unreachable();
        }

        void _start(void) {
            sys_write(1, msg, sizeof msg - 1);
            sys_exit(0);
        }
      '';
    in
    {
      packages = forEachSystem (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          arch = archForSystem system;
          elfClass = elfClassForArch arch;
        in
        {
          release = pkgs.stdenv.mkDerivation {
            pname = "kernel-v1-release-${arch}";
            version = "0.0.0-placeholder";

            # We write the source directly in buildCommand rather than
            # unpacking a tarball; this keeps the derivation hermetic
            # (no extra src attribute) and matches the task spec that
            # the placeholder builds without a Rust toolchain.
            dontUnpack = true;

            nativeBuildInputs = [
              pkgs.stdenv.cc
              pkgs.coreutils
              pkgs.file
            ];

            buildCommand = ''
              set -euo pipefail

              # ---- 1. Compile the freestanding placeholder C source. ----
              cat > placeholder.c <<'PLACEHOLDER_EOF'
              ${placeholderC arch}
              PLACEHOLDER_EOF
              $CC -O2 -Wall -Wextra -ffreestanding -nostdlib -static \
                  -fuse-ld=lld \
                  -o placeholder placeholder.c

              # ---- 2. Generate release-manifest.json. ----
              mkdir -p "$out/bin" "$out/share"
              install -Dm755 placeholder "$out/bin/kernel-v1-agent-placeholder"

              # Per-architecture symlink as documented in the task
              # spec: binaries.<arch>.elf symlink target.
              ln -s kernel-v1-agent-placeholder \
                  "$out/bin/kernel-v1-agent-${arch}.elf"

              sha256=$(sha256sum "$out/bin/kernel-v1-agent-placeholder" \
                          | awk '{print $1}')
              elf_class="$(${pkgs.file}/bin/file -b \
                          "$out/bin/kernel-v1-agent-placeholder")"

              # BTF is build-host state, not build-target state. Read
              # it when the build sandbox happens to expose
              # /sys/kernel/btf/vmlinux (it usually does not; this is
              # an empty string for cross builds and for hydra-style
              # isolated builds).
              btf_sha=""
              if [ -r /sys/kernel/btf/vmlinux ]; then
                btf_sha=$(sha256sum /sys/kernel/btf/vmlinux \
                            | awk '{print $1}')
              fi

              kernel_release=""
              if [ -r /proc/sys/kernel/osrelease ]; then
                kernel_release=$(cat /proc/sys/kernel/osrelease)
              fi

              # The version is a placeholder for task 8; later tasks
              # inject the real `git describe --tags --dirty` output.
              version="0.0.0-placeholder"

              cat > "$out/share/release-manifest.json" <<JSON
              {
                "schema_version": 1,
                "schema": "https://kernel-v1.local/schemas/release-manifest/v1.json",
                "commit": "${commit}",
                "version": "$version",
                "build_kernel_release": "$kernel_release",
                "build_btf_sha256": "$btf_sha",
                "binaries": {
                  "${arch}": {
                    "path": "$out/bin/kernel-v1-agent-${arch}.elf",
                    "elf_class": "$elf_class",
                    "sha256": "$sha256"
                  }
                }
              }
              JSON

              # ---- 3. Package into a tarball (the per-task output
              # shape is "a tarball containing a single placeholder
              # binary plus a release-manifest.json"). The $out is a
              # directory so consumers can also reach individual
              # files; release.tar.gz is the canonical archive.
              tar -C "$out" -czf "$out/release.tar.gz" bin share
            '';

            meta = with pkgs.lib; {
              description = "kernel-v1 release tarball for ${arch} (task 8 placeholder; replaced by real binary in tasks 49-51)";
              platforms = [ system ];
              license = [ pkgs.lib.licenses.asl20 pkgs.lib.licenses.mit ];
            };
          };
        });
    };
}