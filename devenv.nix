# Development shell for the eBPF runtime.
#
# clang 19 is not optional. clang 20 and newer lower large memcpy calls
# to an unresolved extern that libbpf cannot resolve against the kernel
# BTF on the kernels tested here. The loader build fails early when the
# compiler version is wrong.

{ pkgs, ... }:

{
  languages.rust = {
    enable = true;
    toolchainFile = ./rust-toolchain.toml;
  };

  packages = with pkgs; [
    bpftools
    bun
    nodejs
    git
    jq
    libbpf
    openssl
    rdkafka
    llvmPackages_19.clang
    llvmPackages_19.clang-unwrapped
    llvmPackages_19.llvm
    pkg-config
  ];

  env = {
    RUST_BACKTRACE = "1";
    # Nix's hardening flags add _FORTIFY_SOURCE without optimisation.
    # libbpf-sys builds its vendored C dependencies with -Werror, so give
    # the C compiler an optimisation level.
    CFLAGS = "-O2";
    CXXFLAGS = "-O2";
    CLANG = "${pkgs.llvmPackages_19.clang-unwrapped}/bin/clang";
    BPFTOOL = "${pkgs.bpftools}/bin/bpftool";
  };

  enterShell = ''
    printf 'rustc   %s\n' "$(rustc --version)"
    printf 'clang   %s\n' "$(clang --version | head -1)"
    printf 'bpftool %s\n' "$(bpftool version | head -1)"
    echo
    echo "Build the sensors: cargo run -p bpf-build -- build"
    echo "Run the tests:     cargo test --workspace"
  '';
}
