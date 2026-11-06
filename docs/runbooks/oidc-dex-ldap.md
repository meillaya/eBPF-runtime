# Live Dex + OpenLDAP + mTLS profile

This profile exercises the identity path that the development compose file
does not: Dex discovery and JWKS fetch, LDAP group claims, RBAC, gRPC
mTLS, a per-node SPIFFE URI SAN, and the dashboard authorization-code
flow. It is a test harness, not a production identity deployment.

## Ports and topology

| Component | Address |
|---|---|
| Dashboard, API, Dex discovery/token (Caddy) | `http://127.0.0.1:8081` |
| Control-plane HTTP (behind Caddy) | `127.0.0.1:8082` |
| Control-plane gRPC | `127.0.0.1:9444` |
| Dex HTTPS (internal) | `127.0.0.1:5556` |
| OpenLDAP | bridge, published `127.0.0.1:1389` |
| PostgreSQL | bridge, published `127.0.0.1:5433` |
| ClickHouse | bridge, published `127.0.0.1:8124` |

Caddy is the same-origin facade. The browser talks only to `:8081`, so
OIDC discovery and token requests are not cross-origin. Dex keeps an
internal HTTPS listener; Caddy forwards `/dex/*` to it and everything else
to the control plane. The control plane fetches JWKS directly from Dex's
HTTPS endpoint with the test CA.

## Certificates

```bash
scripts/gen-test-certs.sh
```

This writes test-only material under `target/oidc/certs` (gitignored):

- `ca.crt` / `ca.key`
- `control.crt` / `control.key` for `DNS:control-plane,IP:127.0.0.1`
- `agent.crt` / `agent.key` with
  `URI:spiffe://example.org/ebpf-agent/node-1`
- `dex.crt` / `dex.key` for `IP:127.0.0.1,DNS:localhost`

The control plane trusts the CA through `oidc_ca`; the agent trusts it for
mTLS. The test CA is not installed system-wide. Do not reuse these keys.

## Start the stack

Build the dashboard with the proxy issuer so the built bundle points at
`:8081/dex`:

```bash
podman machine ssh ebpf-sandbox -- '
  cd /home/core/src
  sudo podman build --network=host \
    --build-arg VITE_OIDC_ISSUER=http://127.0.0.1:8081/dex \
    --build-arg VITE_OIDC_CLIENT_ID=ebpf-dashboard \
    -t localhost/ebpf-fleet-oidc:test .
  sudo env PATH="/home/core/bin:$PATH" \
    podman compose -f deploy/compose/oidc/compose.yaml up -d --no-build
'
```

The compose file sets `dev = false` for the control plane and agent. The
control plane requires TLS, OIDC issuer, JWKS, and audience. The agent uses
the per-node client certificate. Dex uses OpenLDAP
(`ou=people,dc=example,dc=org` and `ou=groups,dc=example,dc=org`) with
group search enabled.

Test users and groups:

| User | Password | Group | Expected role |
|---|---|---|---|
| `alice` | `alice-password` | `ebpf-admins` | Admin |
| `vera` | `vera-password` | `ebpf-viewers` | Viewer |
| `mallory` | `mallory-password` | none | 401/no role |

Dex has two public clients: `ebpf-dashboard` (the dashboard audience) and
`wrong-audience` (the wrong-audience negative case). Password grant is
enabled because `passwordConnector` is set to the LDAP connector, and the
harness requests the `groups` scope.

## Wait for the stack

```bash
curl -fsS http://127.0.0.1:8081/healthz
curl -fsS http://127.0.0.1:8081/dex/.well-known/openid-configuration
```

The discovery `issuer` must be `http://127.0.0.1:8081/dex`; the
`jwks_uri` in the discovery document points at the proxy, while the control
plane config fetches the direct HTTPS endpoint with the test CA.

## API and RBAC assertions

```bash
scripts/oidc/api-tests.sh
```

The script obtains password-grant access tokens and checks:

- the admin token carries the `ebpf-admins` LDAP group;
- admin and viewer can read events;
- admin can stage and commit; viewer gets 403 on stage;
- a token for the `wrong-audience` client gets 401;
- a token with no fleet group gets 401;
- `/agents` contains the agent with
  `spiffe://example.org/ebpf-agent/node-1`;
- `/audit` contains the `policy.stage` row.

Expiry and a token signed by the wrong key are covered by the auth crate's
unit tests with a locally signed fixture. A live Dex run does not mint an
expired token without slowing the suite; the verifier and the API's 401
mapping are the same code path.

## Dashboard flow

Run Playwright on the host. The `ignoreHTTPSErrors` setting is harmless
because the browser now sees the HTTP proxy.

```bash
cd web
EBPF_WEB_URL=http://127.0.0.1:8081 \
EBPF_DEX_ISSUER=http://127.0.0.1:8081/dex \
EBPF_API_BASE=http://127.0.0.1:8081/api/v1 \
bunx playwright test
```

The OIDC spec:

1. obtains an admin token and stages/commits a policy through the API;
2. clicks Sign in and completes the Dex LDAP login as `alice`;
3. checks the dashboard, policies table, and audit tab;
4. stages and commits version 2, starts a one-agent rollout with
   `min_ratio = 1.0`, and waits for `promoted`;
5. reloads the dashboard and checks the rollout status column and the
   `policy.rollout.promoted` audit row.

That last step is also the live proof that the agent acknowledges after the
rule engine swap rather than after persistence.

## Certificate rotation

The agent polls its certificate, key, and CA metadata. Replace the agent
certificate while the stack is running:

```bash
scripts/gen-test-certs.sh
```

Within the poll interval the agent logs
`TLS material changed; restarting agent`, exits, and the compose
`restart: unless-stopped` policy starts it again. Confirm:

```bash
podman machine ssh ebpf-sandbox -- '
  cd /home/core/src
  sudo env PATH="/home/core/bin:$PATH" \
    podman compose -f deploy/compose/oidc/compose.yaml logs --tail=40 agent
  sudo env PATH="/home/core/bin:$PATH" \
    podman compose -f deploy/compose/oidc/compose.yaml exec -T postgres \
    psql -U ebpf -d control -c "SELECT spiffe_id, agent_generation, last_seen FROM agents;"
'
```

The generation and `last_seen` change. The agent re-registers under the same
SPIFFE SAN with the new certificate.

## Common failures

- **Dex exits with `exec: "serve": executable file not found`.** The image
  entrypoint is `docker-entrypoint`; the command must be
  `["dex", "serve", "/etc/dex/config.yaml"]`, not just `serve`.
- **Sign in does nothing and the console shows a CORS error.** Dex does not
  add CORS headers for a SPA on another origin. Use the Caddy same-origin
  proxy and build the dashboard with the `:8081/dex` issuer.
- **Dex cannot read its cert.** The test keys are mode 0600. The Dex
  container in this profile runs as root for that reason; do not weaken the
  key permissions.
- **Agent reports `transport error` once.** The control plane may still be
  starting; delivery retries. Confirm the agent row appears before treating
  it as a failure.
- **JWKS fetch fails with a certificate error.** Set `oidc_ca` to the test
  CA and confirm the direct Dex URL is `https://127.0.0.1:5556/dex/keys`.
- **LDAP login fails.** Check that the custom bootstrap LDIF loaded:
  `podman compose ... exec ldap ldapsearch -x -H ldap://127.0.0.1:389 -b dc=example,dc=org`.
  The `osixia` image logs `Add custom bootstrap ldif` during first start.

## Cleanup

```bash
podman machine ssh ebpf-sandbox -- '
  cd /home/core/src
  sudo env PATH="/home/core/bin:$PATH" \
    podman compose -f deploy/compose/oidc/compose.yaml down -v
'
```

The profile creates its own PostgreSQL, ClickHouse, and agent volumes.
