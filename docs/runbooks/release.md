# Release a static ebpf-fleet binary

The local binary is the product front door. Releases are static-pie
artifacts so they run on a clean cloud image without the project's Nix
glibc or a container runtime.

## Build locally

```bash
nix develop
scripts/build-static.sh
```

The script builds `target/release/ebpf-fleet` with
`glibc.static`, verifies that `ldd` reports a static executable, strips
symbols, and writes `target/release/ebpf-fleet.sha256`.

## Cut a release

1. Update the version in the workspace crates and `CHANGELOG.md`.
2. Run `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
   and `scripts/build-static.sh`.
3. Test the static artifact on a clean Ubuntu 24.04 VM:
   `--version`, `doctor`, `record`, `query`, `replay`, `pack`, `unpack`.
4. Tag and push: `git tag -s v0.2.0 && git push origin v0.2.0`.
5. `.github/workflows/release.yml` builds, signs with keyless cosign,
   attests provenance, generates an SBOM, and publishes the GitHub release.
6. Verify the published artifact with `scripts/install.sh`; it checks the
   SHA-256 and uses cosign when available.

## Current limits

- x86_64 and aarch64 static artifacts; the aarch64 cross-build and a
  functional TCG row are documented in `docs/verification/arm64.md`, with a
  native aarch64 KVM row still pending.
- The binary is static glibc, not musl; it has no runtime glibc dependency
  but still relies on the kernel ABI and Linux UAPI.
- The release workflow requires GitHub Actions billing and OIDC; until that
  is fixed, run `scripts/build-static.sh` locally and attach the artifact
  manually.
