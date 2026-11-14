# Release evidence: ebpf-fleet 0.2.2 (keyless)

Status: **published with keyless GitHub OIDC cosign**, provenance attestation,
and a keyless installer test on 2026-11-14.

Public release: <https://github.com/meillaya/eBPF-runtime/releases/tag/v0.2.2>

This release exists to prove the trusted release path from green `main`
before 0.3 feature work. The CLI and bundle format are unchanged from 0.2.0.

## Artifact

| Field | Value |
| --- | --- |
| Version | `ebpf-fleet 0.2.2` |
| Architecture | x86_64, static-pie |
| Binary SHA-256 | `a4e158d4e0ab9c0162ab7f0ca5e24d581052a5edb2736c4d273f326efe5f1243` |
| Release | <https://github.com/meillaya/eBPF-runtime/releases/tag/v0.2.2> |
| SBOM | `ebpf-fleet.spdx.json` release asset |
| Signature | keyless cosign bundle asset |
| Provenance | GitHub artifact attestation |

## Verification

The release workflow
([run 43560482263](https://github.com/meillaya/eBPF-runtime/actions/runs/43560482263))
completed all steps:

- static binary build from green `main`
- keyless cosign signing
- GitHub provenance attestation
- SBOM generation
- release publication

Independent checks on the downloaded assets:

```bash
cosign verify-blob \
  --bundle ebpf-fleet-x86_64.cosign.bundle \
  --certificate-identity-regexp \
    'https://github.com/meillaya/eBPF-runtime/.github/workflows/release.yml@refs/tags/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ebpf-fleet-x86_64
gh attestation verify ebpf-fleet-x86_64 --repo meillaya/eBPF-runtime
```

Both passed. The installer was tested from the public release:

```bash
EBPF_FLEET_PREFIX="$PWD/target/install-public-022" \
EBPF_FLEET_VERSION=v0.2.2 scripts/install.sh
# -> ebpf-fleet-x86_64: OK
# -> install: verifying keyless cosign signature
# -> Verified OK
# -> ebpf-fleet 0.2.2
```

## Notes

- v0.2.1 was withdrawn before publication because its release job failed at
  SBOM generation; v0.2.2 contains the fixed release workflow.
- The earlier v0.2.0 release used an explicit local cosign key and is retained
  as historical evidence. New releases use keyless identity.
- The release is x86_64 only; arm64 is a 0.3 target.
