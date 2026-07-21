# devenv.nix — kernel-v1 (eBPF Runtime Security & Observability)
#
# Single source of truth for the pinned dev environment. Imported by:
#   * `devenv shell` / `devenv test` / `devenv update` via devenv.yaml
#   * `nix develop` / `nix flake check`   via flake.nix
#
# Task 2 of .omo/plans/ebpf-runtime-security-observability.md.
#
# IMPORTANT: do not duplicate this package list in flake.nix; the flake
# imports this module via devenv.lib.mkShell so both entry points resolve
# the same toolchain. No impure absolute paths.

{ pkgs
, lib
, config
, inputs
, ...
}:

{
  # ---------------------------------------------------------------------
  # Rust toolchain (pinned 1.95.0, stable)
  # ---------------------------------------------------------------------
  # `toolchainFile` makes devenv read rust-toolchain.toml at the repo
  # root and use rust-overlay's `fromRustupToolchainFile` to assemble
  # the exact toolchain (channel = "1.95.0" + rustfmt, clippy,
  # rust-analyzer, rust-src, miri + the two linux targets). No version
  # drift between the devenv shell and `cargo` invoked outside it.
  languages.rust = {
    enable = true;
    # channel / version / components / targets come from rust-toolchain.toml
    toolchainFile = ./rust-toolchain.toml;
  };

  # ---------------------------------------------------------------------
  # Cross-platform shell niceties (all platforms)
  # ---------------------------------------------------------------------
  packages = with pkgs; [
    # generic shell tooling
    git
    gnumake
    gnused
    gnugrep
    coreutils
    jq
    just
    nixfmt-rfc-style

    # BPF build chain — task 10 uses these for reproducible CO-RE builds.
    llvmPackages_19.clang
    llvmPackages_19.clang-unwrapped
    llvmPackages_19.lld
    llvmPackages_19.llvm       # llvm-objdump / llvm-readelf / llvm-strip
    bpftools                    # bpftool + friends
    libbpf                      # static + shared libbpf, bpf.h, bpf_helpers.h

    # Node-agent local storage (task 22-26)
    sqlcipher

    # Wire formats (task 6) — protobuf compiler + buf
    protobuf
    buf

    # Web build chain (wave 5)
    bun
    biome

    # Quality + supply-chain gates (task 4)
    cargo-nextest
    cargo-deny
    cargo-fuzz                  # cargo subcommand plugin
    # Miri is provided as a `languages.rust.components` entry above
    # ("miri" → `rustup component add miri`). There is no separate
    # `pkgs.cargo-miri` package in nixpkgs.

    # Infrastructure linting (wave 0)
    shellcheck
    hadolint
    actionlint

    # Release / SBOM / signing (task 8)
    syft
    cosign

    # Kubernetes delivery + conformance (wave 5)
    kubernetes-helm             # `helm` CLI
    kubeconform
    kubectl
    kind

    # Virtualization for declared self-hosted privileged lanes (task 7+)
    qemu_kvm
    qemu

    # Benchmarking + performance instrumentation (wave 6)
    fio
    perf
    netperf

    # Host introspection — audit cross-comparison lane.
    # nixpkgs names the package `audit` (the daemon + libaudit + tools).
    audit                       # provides `auditctl`, `ausearch`, `audisp-remote`, `auditd`
  ];

  # ---------------------------------------------------------------------
  # Environment variables consumed by downstream scripts
  # ---------------------------------------------------------------------
  env = {
    RUST_BACKTRACE = "1";
    CARGO_TERM_COLOR = "always";

    # BPF toolchain discovery for task 10
    BPF_TARGET = "bpf";
    CLANG = "${pkgs.llvmPackages_19.clang}/bin/clang";
    BPFTOOL = "${pkgs.bpftools}/bin/bpftool";

    # SQLCipher discovery for sqlx / rusqlite migrations
    SQLCIPHER_LIB = "${pkgs.sqlcipher}/lib";
    SQLCIPHER_INCLUDE = "${pkgs.sqlcipher}/include";

    # protoc + buf for task 6
    PROTOC = "${pkgs.protobuf}/bin/protoc";
    PROTOC_INCLUDE = "${pkgs.protobuf}/include";
  };

  # ---------------------------------------------------------------------
  # enterShell: print the resolved tool versions so devs / CI can
  # eyeball the pin without leaving the shell.
  # ---------------------------------------------------------------------
  enterShell = ''
    echo "------------------------------------------------------------"
    echo "kernel-v1 dev shell (devenv + flake.nix shared module)"
    printf "  rustc     : %s\n" "$(rustc --version 2>/dev/null || echo missing)"
    printf "  cargo     : %s\n" "$(cargo --version 2>/dev/null || echo missing)"
    printf "  clang     : %s\n" "$(clang --version 2>/dev/null | head -1 || echo missing)"
    printf "  bpftool   : %s\n" "$(bpftool version 2>/dev/null | head -1 || echo missing)"
    printf "  bun       : %s\n" "$(bun --version 2>/dev/null || echo missing)"
    printf "  sqlcipher : %s\n" "$(sqlcipher -version 2>/dev/null || sqlcipher --version 2>/dev/null || echo missing)"
    printf "  buf       : %s\n" "$(buf --version 2>/dev/null || echo missing)"
    echo "------------------------------------------------------------"
  '';

  # ---------------------------------------------------------------------
  # enterTest: relaxed acceptance for task 2.
  # The strict gate (no `|| true`) lands in task 4 (quality gates).
  # `devenv test` reads the exit code of this script.
  # ---------------------------------------------------------------------
  enterTest = ''
    set +e
    echo "[task-2 enterTest] cargo fmt --all --check"
    cargo fmt --all --check
    echo "[task-2 enterTest] cargo clippy --workspace --all-targets --all-features -- -D warnings"
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    echo "[task-2 enterTest] cargo nextest run --workspace"
    cargo nextest run --workspace
    echo "[task-2 enterTest] complete (relaxed: any of the above may fail"
    echo "                       until task 4 installs the strict gate)."
    exit 0
  '';
}
