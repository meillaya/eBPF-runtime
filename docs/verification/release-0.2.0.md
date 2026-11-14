# Release evidence: ebpf-fleet 0.2.0

Status: **locally built, signed, and VM-tested** on 2026-11-14.
The public GitHub release is pending merge/push and the keyless CI workflow;
this page records the offline artifact and its verifiable metadata.

## Artifact

| Field | Value |
| --- | --- |
| Version | `ebpf-fleet 0.2.0` |
| Architecture | x86_64, static-pie |
| Binary | `ebpf-fleet-x86_64` |
| Binary SHA-256 | `bc48014367de000b0557177e03f4a6bdd057202ce2c00527009c631536f4b345` |
| Binary size | 134194760 bytes |
| Tarball | `ebpf-fleet-0.2.0-x86_64.tar.gz` |
| Tarball SHA-256 | `42d8e9392080a3637520d2f9ee97c9eea9076d5cc915660eac26e033d10fb382` |
| Tarball size | 44456686 bytes |
| SBOM | [SBOM](release-0.2.0/ebpf-fleet.spdx.json) |
| Signature bundle | [signature bundle](release-0.2.0/ebpf-fleet-x86_64.cosign.bundle) |
| Public key | [cosign.pub](release-0.2.0/cosign.pub) |
| Public key DER SHA-256 | `09f3501d84edb6b8a60ab168b1f89d230f2a7d93745e74394bf7ee86341009f7` |

The binary and tarball are intentionally not committed (128 MiB/43 MiB);
their checksums, SBOM, signature bundle, and public key are checked in.
The tarball contains the binary, its checksum, the SBOM, the cosign public
key, and both license files.

## Signature

This local artifact uses an **explicit release key** because GitHub Actions
billing currently blocks the keyless workflow. The public key is checked in;
the private key stays under `target/release/` and is not committed.

```bash
# In the directory that holds the downloaded/extracted 0.2.0 artifacts:
cosign verify-blob --key cosign.pub \
  --bundle ebpf-fleet-x86_64.cosign.bundle ebpf-fleet-x86_64
sha256sum -c ebpf-fleet-x86_64.sha256
```

The preferred keyless workflow is [.github/workflows/release.yml](../../.github/workflows/release.yml);
it uses GitHub OIDC, keyless cosign, provenance attestation, and publishes
the same artifact. This local key is a fallback, not the production identity.

## Verification performed

- `scripts/build-static.sh` produced a statically linked x86_64 binary.
- Cosign signed and immediately verified the binary.
- The tarball was assembled from the binary, checksums, SBOM, public key,
  and licenses.
- The kernel matrix PASS 4/4 was run with this exact binary
  (`bc48014367de000b0557177e03f4a6bdd057202ce2c00527009c631536f4b345`): Ubuntu 24.04/22.04 and Debian 12/13, including
  `ProcessExit` and decoded `FileOpen` paths. See
  [kernel-matrix.md](kernel-matrix.md).
- A clean Ubuntu 24.04 KVM guest extracted the tarball and ran
  `--version`, `doctor`, `probe verify`, record/query/replay. See
  [release-0.2.0-vm.md](release-0.2.0-vm.md).
- `scripts/install.sh` downloaded the artifact from a local HTTP server,
  matched the SHA-256, verified the cosign signature with
  `EBPF_FLEET_COSIGN_PUB`, installed it into a temporary prefix, and ran
  `--version` (0.2.0). This exercises the same installer path the public
  release will use.

## Honest gaps before publishing

- The keyless GitHub release workflow has not run; GitHub Actions billing is
  still blocking it.
- The binary is x86_64 only. arm64 needs a native aarch64 build/host.
- Stack capture/symbolization is not in 0.2.
- Fedora 42 is pinned but not boot-validated.
