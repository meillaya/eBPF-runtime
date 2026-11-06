#!/usr/bin/env bash
# Generate throwaway certificates for the OIDC/mTLS compose profile.
#
# Outputs (all under target/oidc/certs, gitignored):
#   ca.crt/ca.key                 test CA
#   control.crt/control.key       control-plane gRPC server cert
#   agent.crt/agent.key           per-node client cert with a SPIFFE URI SAN
#   dex.crt/dex.key               Dex HTTPS cert for 127.0.0.1:5556
#
# Never reuse these outside the test profile. The private keys are 0600 and
# must not be committed.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-$root/target/oidc/certs}"
node="${2:-node-1}"
days="${3:-3}"

mkdir -p "$out"
cd "$out"

umask 077
if [[ ! -f ca.crt || ! -f ca.key ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days "$days" \
    -keyout ca.key -out ca.crt \
    -subj "/CN=eBPF fleet test CA" >/dev/null 2>&1
fi

issue() {
  local name="$1" cn="$2" san="$3" eku="$4"
  openssl req -newkey rsa:2048 -nodes -sha256 \
    -keyout "$name.key" -out "$name.csr" \
    -subj "/CN=$cn" >/dev/null 2>&1
  cat > "$name.ext" <<EXT
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=$eku
subjectAltName=$san
EXT
  openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key \
    -CAcreateserial -days "$days" -sha256 \
    -extfile "$name.ext" -out "$name.crt" >/dev/null 2>&1
  rm -f "$name.csr" "$name.ext"
  chmod 600 "$name.key"
}

issue control control-plane "DNS:control-plane,IP:127.0.0.1" serverAuth
issue agent "$node" "URI:spiffe://example.org/ebpf-agent/$node" clientAuth
issue dex dex "IP:127.0.0.1,DNS:localhost" serverAuth

chmod 600 ca.key
echo "wrote test certificates to $out"
