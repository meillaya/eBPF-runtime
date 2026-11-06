# Development shell for the eBPF runtime.
#
# `nix develop` and `devenv shell` both read devenv.nix, so the tool
# versions stay in one place.

{
  description = "eBPF runtime for process and file tracing";

  inputs = {
    devenv.url = "github:cachix/devenv/v2.1.2";
    nixpkgs.follows = "devenv/nixpkgs";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

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
          default = devenv.lib.mkShell {
            inherit inputs pkgs;
            modules = [ ./devenv.nix ];
          };
        });
    };
}
