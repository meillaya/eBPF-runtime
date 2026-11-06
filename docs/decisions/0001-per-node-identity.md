# 0001: Per-node certificate identity, SPIRE deferred

- Status: accepted
- Date: 2026-11-06

## Context

The control plane already reads a SPIFFE URI SAN from the agent's client
certificate and uses it as the agent key. The Helm chart expects
`/etc/ebpf-agent/tls/ca.crt`, `tls.crt`, and `tls.key` on each node. The
project does not issue certificates and does not run SPIRE.

The agent read its certificate once at connect time. A short-lived SVID
replacement therefore required a connection or process restart. That is a
real operational gap for short-lived credentials, but it is separate from
the question of where the certificates come from.

## Decision

For the pilot, use certificates from the existing PKI, one certificate per
node, with a URI SAN such as:

```text
spiffe://example.org/ebpf-agent/<node>
```

Do not share one client certificate across agents. The control plane maps
the SAN to one agent row, so a shared certificate would collapse every node
into the same database identity and the same policy acknowledgement.

SPIRE is deferred until at least one of these is true:

- the fleet is larger than a handful of nodes;
- credentials must be short-lived and rotated without operator work;
- agents cross trust boundaries where a shared PKI is not acceptable.

For the first version of rotation, the agent polls the certificate, key,
and CA file metadata. If any file changes, it logs
`TLS material changed; restarting agent`, performs its normal shutdown,
and exits. systemd uses `Restart=always`; Kubernetes restarts the container.
The restarted process reads the new files and registers a new generation.
This is a deliberate restart, not a live TLS connection swap.

## SPIRE path when it is needed

1. Run a SPIRE server and a SPIRE agent on each node.
2. Register one workload entry per node, for example
   `spiffe://example.org/ebpf-agent/<node>`.
3. Run `spiffe-helper` (or an equivalent) to write `ca.crt`, `tls.crt`, and
   `tls.key` into `/etc/ebpf-agent/tls`.
4. Point the control plane's client CA at the SPIRE trust bundle.
5. Test SAN-to-agent mapping and rotation.
6. Replace the restart-on-rotation loop with a reconnecting transport
   manager once live rotation is required.

## Consequences

- A compromised node certificate can be revoked in the existing PKI; there
  is no SPIRE registration API yet.
- Rotation has a short restart gap and drops the active control stream.
- Operators still provision and protect the private key on each node.
- The control plane does not need a SPIRE dependency for the pilot.
