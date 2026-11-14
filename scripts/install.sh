#!/usr/bin/env bash
# Install a released static `ebpf-fleet` binary.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/meillaya/eBPF-runtime/main/scripts/install.sh | sh
#   EBPF_FLEET_VERSION=v0.2.0 sh scripts/install.sh
#   EBPF_FLEET_PREFIX="$HOME/.local/bin" sh scripts/install.sh
#
# The release artifacts are static binaries for Linux x86_64 and
# aarch64. The script maps `uname -m` to the architecture token the release
# workflow publishes (`ebpf-fleet-<arch>`), verifies the SHA-256, and
# verifies the keyless cosign bundle when cosign is available. It refuses to
# install an unsupported architecture rather than installing a wrong binary.

set -euo pipefail

repo="${EBPF_FLEET_REPO:-meillaya/eBPF-runtime}"
version="${EBPF_FLEET_VERSION:-latest}"
prefix="${EBPF_FLEET_PREFIX:-/usr/local/bin}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

case "$(uname -s)" in
  Linux) ;;
  *) echo "install: only Linux is supported" >&2; exit 1 ;;
esac
# Both kernel naming variants map to the release asset token. The release
# workflow publishes ebpf-fleet-x86_64 and ebpf-fleet-aarch64; release-local.sh
# uses the same x86_64 asset name.
case "$(uname -m)" in
  x86_64|amd64) arch="x86_64" ;;
  aarch64|arm64) arch="aarch64" ;;
  *) echo "install: no published artifact for $(uname -m); supported: x86_64, aarch64" >&2; exit 1 ;;
esac
asset="${EBPF_FLEET_ASSET:-ebpf-fleet-$arch}"

if [[ -n "${EBPF_FLEET_BASE_URL:-}" ]]; then
  base="${EBPF_FLEET_BASE_URL%/}"
elif [[ "$version" == "latest" ]]; then
  base="https://github.com/$repo/releases/latest/download"
else
  base="https://github.com/$repo/releases/download/$version"
fi
url="$base/$asset"
checksum_url="$base/$asset.sha256"

echo "install: downloading $url"
curl -fsSL --retry 3 -o "$tmp/$asset" "$url"
curl -fsSL --retry 3 -o "$tmp/$asset.sha256" "$checksum_url"
(cd "$tmp" && sha256sum -c "$asset.sha256")

if command -v cosign >/dev/null 2>&1 &&
   curl -fsSL --retry 3 -o "$tmp/$asset.cosign.bundle" "$base/$asset.cosign.bundle"; then
  # Prefer a checked-in/public release key when the release publishes one.
  # Keyless releases do not ship cosign.pub and fall back to the OIDC identity.
  key="${EBPF_FLEET_COSIGN_PUB:-}"
  if [[ -n "$key" && ! -f "$key" ]]; then
    curl -fsSL --retry 3 -o "$tmp/cosign.pub" "$key"
    key="$tmp/cosign.pub"
  fi
  if [[ -z "$key" ]] && curl -fsSL --retry 3 -o "$tmp/cosign.pub" "$base/cosign.pub" 2>/dev/null; then
    key="$tmp/cosign.pub"
  fi
  if [[ -n "$key" ]]; then
    echo "install: verifying cosign signature with release key"
    cosign verify-blob --key "$key" --bundle "$tmp/$asset.cosign.bundle" "$tmp/$asset"
  else
    echo "install: verifying keyless cosign signature"
    cosign verify-blob     --bundle "$tmp/$asset.cosign.bundle"     --certificate-identity-regexp "https://github.com/$repo/.github/workflows/release.yml@refs/tags/.*"     --certificate-oidc-issuer "https://token.actions.githubusercontent.com"     "$tmp/$asset"
  fi
else
  echo "install: cosign signature not checked (cosign or bundle unavailable)" >&2
fi

mkdir -p "$prefix"
install -m 0755 "$tmp/$asset" "$prefix/ebpf-fleet"
echo "install: installed $prefix/ebpf-fleet"
"$prefix/ebpf-fleet" --version
