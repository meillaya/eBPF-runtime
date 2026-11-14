# Local release signing fallback

The preferred release path is `.github/workflows/release.yml`: GitHub
Actions builds the static binary, uses keyless cosign, emits an SBOM, attests
provenance, and publishes the GitHub release.

When GitHub Actions is unavailable, `scripts/release-local.sh` performs the
same artifact assembly with an explicit local cosign key:

```bash
nix shell nixpkgs#cosign nixpkgs#syft -c \
  env EBPF_FLEET_COSIGN_PASSWORD='<ephemeral-password>' \
  scripts/release-local.sh 0.2.0
```

Outputs under `target/release/ebpf-fleet-0.2.0/`:

- `ebpf-fleet-x86_64` — static x86_64 binary
- `ebpf-fleet-x86_64.sha256`
- `ebpf-fleet.spdx.json` and checksum
- `ebpf-fleet-x86_64.cosign.bundle` and checksum
- `cosign.pub` — public key
- `ebpf-fleet-0.2.0-x86_64.tar.gz` plus checksum

The script verifies the signature immediately. The private key stays under
`target/release/` and must never be committed. A local key is an explicit
fallback, not the production keyless identity; publish the public key and
record the key fingerprint in the release notes.

Verification:

```bash
cosign verify-blob --key cosign.pub \
  --bundle ebpf-fleet-x86_64.cosign.bundle ebpf-fleet-x86_64
sha256sum -c ebpf-fleet-x86_64.sha256
```
