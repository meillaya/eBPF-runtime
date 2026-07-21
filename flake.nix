# flake.nix — kernel-v1 (eBPF Runtime Security & Observability)
#
# Nix flake wrapper that re-uses the same `devenv.nix` consumed by the
# `devenv` CLI. No package list is duplicated here; the flake only:
#   * pins devenv and follows its nixpkgs,
#   * configures the devenv.cachix.org binary cache,
#   * exposes `devShells.<system>.default` for x86_64-linux + aarch64-linux.
#
# Task 2 of .omo/plans/ebpf-runtime-security-observability.md.
{
  description = "kernel-v1 — eBPF Runtime Security & Observability (dev shell)";

  inputs = {
    devenv.url = "github:cachix/devenv/v2.1.2";
    # Re-use the nixpkgs pinned by devenv so `devenv shell` and
    # `nix develop` resolve identical packages.
    nixpkgs.follows = "devenv/nixpkgs";
  };

  # Pin the devenv binary cache so the lock evaluation stays fast and
  # deterministic. The key matches the official devenv documentation.
  nixConfig = {
    extra-trusted-public-keys = [
      "devenv.cachix.org-1:9wHtecUiNYE0yHXZCai9oU9S0GFTwUIKFSND63vCSHo="
    ];
    extra-substituters = [
      "https://devenv.cachix.org"
    ];
  };

  outputs = { self, devenv, nixpkgs, ... }@inputs:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forEachSystem = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forEachSystem (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          # Same module the `devenv` CLI imports. No duplication.
          default = devenv.lib.mkShell {
            inherit inputs pkgs;
            modules = [ ./devenv.nix ];
          };
        });
    };
}
