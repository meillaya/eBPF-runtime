#!/usr/bin/env bash
# Build, package, SBOM, and sign a local ebpf-fleet release artifact.
#
# This is the no-GitHub-Actions fallback. The preferred path is the keyless
# `release.yml` workflow. This script uses an explicit local cosign key so the
# release can still be verified offline; never commit the private key.
#
# Usage:
#   EBPF_FLEET_COSIGN_PASSWORD=... scripts/release-local.sh 0.2.0
#
# Requirements: nix, cosign, syft, tar, sha256sum. Install the Go tools with:
#   nix shell nixpkgs#cosign nixpkgs#syft -c scripts/release-local.sh 0.2.0

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:-}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "usage: $0 <semver, e.g. 0.2.0>" >&2
  exit 2
}
for tool in nix cosign syft tar sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "release-local: missing $tool; use nix shell nixpkgs#cosign nixpkgs#syft" >&2
    exit 1
  }
done

cd "$root"
scripts/build-static.sh

artifact_dir="target/release/ebpf-fleet-${version}"
key_prefix="target/release/cosign-release"
rm -rf "$artifact_dir"
mkdir -p "$artifact_dir"

# The local binary name matches the release workflow and installer contract.
cp target/release/ebpf-fleet "$artifact_dir/ebpf-fleet-x86_64"
cp target/release/ebpf-fleet.sha256 "$artifact_dir/ebpf-fleet-x86_64.sha256" 2>/dev/null || true
# Rewrite the checksum for the renamed asset.
(cd "$artifact_dir" && sha256sum ebpf-fleet-x86_64 > ebpf-fleet-x86_64.sha256)
cp LICENSE-APACHE LICENSE-MIT "$artifact_dir/"

syft "file:$artifact_dir/ebpf-fleet-x86_64" \
  -o spdx-json="$artifact_dir/ebpf-fleet.spdx.json" >/dev/null
(cd "$artifact_dir" && sha256sum ebpf-fleet.spdx.json > ebpf-fleet.spdx.json.sha256)

if [[ ! -f "$key_prefix.key" ]]; then
  : "${EBPF_FLEET_COSIGN_PASSWORD:?set EBPF_FLEET_COSIGN_PASSWORD to generate the local release key}"
  COSIGN_PASSWORD="$EBPF_FLEET_COSIGN_PASSWORD" cosign generate-key-pair \
    --output-key-prefix "$key_prefix" >/dev/null
fi
cp "$key_prefix.pub" "$artifact_dir/cosign.pub"
COSIGN_PASSWORD="${EBPF_FLEET_COSIGN_PASSWORD:-}" cosign sign-blob --yes \
  --key "$key_prefix.key" \
  --bundle "$artifact_dir/ebpf-fleet-x86_64.cosign.bundle" \
  "$artifact_dir/ebpf-fleet-x86_64"
(cd "$artifact_dir" && sha256sum ebpf-fleet-x86_64.cosign.bundle > ebpf-fleet-x86_64.cosign.bundle.sha256)

# Verify the signature immediately; a release build must not claim a signature
# it cannot check.
cosign verify-blob --key "$key_prefix.pub" \
  --bundle "$artifact_dir/ebpf-fleet-x86_64.cosign.bundle" \
  "$artifact_dir/ebpf-fleet-x86_64" >/dev/null

tar --sort=name --mtime='UTC 2026-01-01' --owner=0 --group=0 --numeric-owner \
  -C "$artifact_dir" -czf "target/release/ebpf-fleet-${version}-x86_64.tar.gz" \
  ebpf-fleet-x86_64 ebpf-fleet-x86_64.sha256 ebpf-fleet-x86_64.cosign.bundle \
  ebpf-fleet.spdx.json cosign.pub LICENSE-APACHE LICENSE-MIT
(cd target/release && sha256sum "ebpf-fleet-${version}-x86_64.tar.gz" > "ebpf-fleet-${version}-x86_64.tar.gz.sha256")

printf '\nrelease-local: artifacts\n'
ls -lh "$artifact_dir" "target/release/ebpf-fleet-${version}-x86_64.tar.gz"*
printf '\npublic key fingerprint:\n'
cosign public-key --key "$key_prefix.pub" 2>/dev/null || true
