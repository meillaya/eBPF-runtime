#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 OR MIT
# SPIRE agent dev entrypoint: waits for the server, generates a join
# token, then starts the agent.
#
# SECURITY: DEV-ONLY. The join token is generated at runtime from the
# dev SPIRE server. No static tokens are stored.
#
# Consumed by: deploy/compose/Dockerfile.spire-agent-dev

set -e

SERVER_SOCKET="/tmp/spire-server/private/api.sock"
AGENT_CONFIG="/etc/spire/agent.conf"
MAX_WAIT=60

echo "[spire-agent-dev] waiting for SPIRE server at ${SERVER_SOCKET}..."
elapsed=0
while [ ! -S "${SERVER_SOCKET}" ]; do
    elapsed=$((elapsed + 1))
    if [ "${elapsed}" -ge "${MAX_WAIT}" ]; then
        echo "[spire-agent-dev] ERROR: server socket not available after ${MAX_WAIT}s" >&2
        exit 1
    fi
    sleep 1
done

# Wait for the server to be ready (healthcheck passes).
echo "[spire-agent-dev] waiting for SPIRE server to be ready..."
elapsed=0
while ! /opt/spire/bin/spire-server healthcheck \
    -socketPath "${SERVER_SOCKET}" >/dev/null 2>&1; do
    elapsed=$((elapsed + 1))
    if [ "${elapsed}" -ge "${MAX_WAIT}" ]; then
        echo "[spire-agent-dev] ERROR: server not ready after ${MAX_WAIT}s" >&2
        exit 1
    fi
    sleep 1
done

echo "[spire-agent-dev] generating join token..."
TOKEN_OUTPUT=$(/opt/spire/bin/spire-server token generate \
    -socketPath "${SERVER_SOCKET}" 2>&1)

# Parse the token from the output. Format: "Token: <hex>"
TOKEN=$(echo "${TOKEN_OUTPUT}" | sed -n 's/^Token:[[:space:]]*//p')
if [ -z "${TOKEN}" ]; then
    # Fallback: try to extract any hex-looking token.
    TOKEN=$(echo "${TOKEN_OUTPUT}" | grep -oE '[0-9a-f]{8,}' | head -1 || true)
fi

if [ -z "${TOKEN}" ]; then
    echo "[spire-agent-dev] ERROR: failed to parse join token" >&2
    echo "${TOKEN_OUTPUT}" >&2
    exit 1
fi

echo "[spire-agent-dev] starting agent with join token..."
exec /opt/spire/bin/spire-agent run \
    -config "${AGENT_CONFIG}" \
    -joinToken "${TOKEN}"
