# Live Dex + OpenLDAP + mTLS verification

Date: 2026-11-06
Profile: `deploy/compose/oidc/compose.yaml`
Image: `localhost/ebpf-fleet-oidc:test` built with
`VITE_OIDC_ISSUER=http://127.0.0.1:8081/dex`

## Topology check

```text
control-plane   Up   HTTP 8082 (behind Caddy), gRPC 9444
dex             Up   HTTPS 5556, issuer http://127.0.0.1:8081/dex
caddy           Up   :8081 same-origin facade
openldap        Up   127.0.0.1:1389
postgres        Up   127.0.0.1:5433
clickhouse      Up   127.0.0.1:8124
relay, agent    Up
```

The control plane logs no TLS or OIDC errors. The agent registered with:

```text
spiffe_id = spiffe://example.org/ebpf-agent/node-1
node_name = node-1
```

## API and RBAC

The harness printed:

```text
ok: control plane ready
ok: admin access token carries the LDAP group
ok: viewer can read events
ok: admin staged and committed a policy
ok: viewer gets 403 on policy staging
ok: wrong audience is rejected
ok: token without a fleet group is rejected
ok: agent registered with its per-node SPIFFE identity
ok: audit rows are visible to the admin
all live OIDC/RBAC/mTLS assertions passed
```

The wrong-audience token came from the second Dex client. Expiry and a token
signed by an unrelated key are covered by `crates/auth` unit tests with a
locally signed fixture.

## Browser flow

Playwright passed the Dex authorization-code flow as `alice`, then checked
the policies and audit tabs. It also staged and committed version 2,
started a one-agent rollout with `min_ratio = 1.0`, waited for `promoted`,
and found the rollout in the dashboard and the
`policy.rollout.promoted` audit row. Screenshot:
[`oidc-dashboard.png`](oidc-dashboard.png).

This is the live end-to-end proof that:

- Dex issuer/JWKS and LDAP group claims work;
- the control plane maps the client certificate SAN to the agent;
- the agent applies the policy and acknowledges after the rule engine
  swap, so the rollout threshold is meaningful;
- the dashboard can complete OIDC and display rollout state.

## Certificate rotation

Replacing the agent certificate/key under the mounted `target/oidc/certs`
directory produced:

```text
TLS material changed; restarting agent
```

The container restarted (`restartcount=1`), the generation changed, and the
agent re-registered with the same SPIFFE SAN. This is restart-based
rotation, not a live TLS connection swap.

## Caveat

The test CA, the fixed passwords in the LDIF, and the root user for the Dex
container are test-only. The CA is trusted only by the control plane's JWKS
client and the test browser process.
