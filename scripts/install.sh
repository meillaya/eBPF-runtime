#!/usr/bin/env bash
# Install a released static `ebpf-fleet` binary.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/meillaya/eBPF-runtime/main/scripts/install.sh | sh
#   EBPF_FLEET_VERSION=v0.2.0 sh scripts/install.sh
#   EBPF_FLEET_PREFIX="$HOME/.local/bin" sh scripts/install.sh
#
# The release artifact is a static x86_64 binary today. arm64 release support
# is tracked separately; the script fails rather than installing a wrong arch.

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
case "$(uname -m)" in
  x86_64|amd64) asset="ebpf-fleet-x86_64" ;;
  *) echo "install: no published artifact for $(uname -m) yet" >&2; exit 1 ;;
esac

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
  if [[ -n "${EBPF_FLEET_COSIGN_PUB:-}" ]]; then
    key="${EBPF_FLEET_COSIGN_PUB}"
    if [[ ! -f "$key" ]]; then
      curl -fsSL --retry 3 -o "$tmp/cosign.pub" "$base/cosign.pub"
      key="$tmp/cosign.pub"
    fi
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
