# Release evidence: ebpf-fleet 0.3.0 (keyless, x86_64 + aarch64)

Status: **published with keyless GitHub OIDC cosign, provenance
attestation, and per-architecture SBOMs** on 2026-11-14.

Public release: <https://github.com/meillaya/eBPF-runtime/releases/tag/v0.3.0>

## Assets

| Asset | SHA-256 | Size |
| --- | --- | ---: |
| `ebpf-fleet-x86_64` | `97a29a234e5279735b47eface8ef58b484cf0d5d4e68a012da56af1969a37385` | 138083848 B |
| `ebpf-fleet-aarch64` | `f5ee2f0378c0ab5313d23d809dec4045b6e8db44a136c5686527c697b4819eb1` | 121182848 B |
| `ebpf-fleet.spdx.json` | release asset | — |
| `ebpf-fleet-aarch64.spdx.json` | release asset | — |

Each architecture has its own `.sha256`, `.cosign.bundle`, and SBOM
checksum asset. The release job verifies all checksums before publishing.

## Signature and provenance

The release workflow
([run 43579886104](https://github.com/meillaya/eBPF-runtime/actions/runs/43579886104))
completed the x86_64 and aarch64 builds, keyless signing, provenance
attestation, and publication.

Independent verification of the downloaded assets:

```bash
cosign verify-blob --bundle ebpf-fleet-x86_64.cosign.bundle \
  --certificate-identity-regexp \
    'https://github.com/meillaya/eBPF-runtime/.github/workflows/release.yml@refs/tags/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ebpf-fleet-x86_64
cosign verify-blob --bundle ebpf-fleet-aarch64.cosign.bundle \
  --certificate-identity-regexp \
    'https://github.com/meillaya/eBPF-runtime/.github/workflows/release.yml@refs/tags/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ebpf-fleet-aarch64
gh attestation verify ebpf-fleet-x86_64 --repo meillaya/eBPF-runtime
gh attestation verify ebpf-fleet-aarch64 --repo meillaya/eBPF-runtime
```

Both cosign checks and both attestations passed.

## Installer

The public installer was tested against the published release:

```bash
EBPF_FLEET_VERSION=v0.3.0 EBPF_FLEET_PREFIX=/tmp/install-0.3.0 \
  scripts/install.sh
# ebpf-fleet-x86_64: OK
# verifying keyless cosign signature
# Verified OK
# ebpf-fleet 0.3.0
```

The aarch64 asset selection is covered by the installer test suite; the
real aarch64 binary was executed in the arm64 VM row below. Keyless
verification against a published aarch64 asset is covered by the same
release workflow signature check above.

## Verification tied to this release

- **Kernel matrix 5/5 with the published x86_64 asset:** Ubuntu
  24.04/22.04, Debian 12/13, Fedora 42. Evidence:
  [kernel-matrix.md](kernel-matrix.md) and
  `docs/verification/kernel-matrix/2026-11-14j/`.
- **arm64 functional row with the published aarch64 asset:** Ubuntu 24.04
  kernel 6.8, QEMU TCG, record/query/replay; explicitly non-performance.
  Evidence: [arm64.md](arm64.md), row
  `target/vm/arm64/2026-11-14-0.3.0-release/`.
- **Stack capture/symbolization and v1 compatibility:** [stacks.md](stacks.md).
- **Custom probe run/decode/unload:** [probe-runtime.md](probe-runtime.md).
- **Stack-mode benchmark:** [benchmarks/0.3.md](../benchmarks/0.3.md).

## Notes

- The arm64 row is TCG-functional only; no native aarch64 KVM host is
  available on the lab machine.
- The release workflow builds aarch64 natively on `ubuntu-24.04-arm`.
- v0.2.0 used a local release key; v0.2.2 and v0.3.0 use keyless identity.
