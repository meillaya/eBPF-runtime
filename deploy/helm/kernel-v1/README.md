<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# kernel-v1 Helm Chart

Helm v2 chart for deploying the kernel-v1 eBPF runtime security &
observability platform on Kubernetes. Deploys a capability-minimized
node agent (DaemonSet) and control-plane (Deployment) with external
PostgreSQL, Kafka, ClickHouse, SPIRE, and OIDC integration.

## Architecture

| Component | Kind | PSS Profile | Purpose |
|-----------|------|-------------|---------|
| Agent | DaemonSet | `privileged` (namespace) | eBPF sensor on every node |
| Control-plane | Deployment | `restricted` | Fleet API, query, policy |
| Migrations | Job (hook) | `restricted` | PostgreSQL schema migrations |

**No databases or brokers are embedded.** All external services
(PostgreSQL, Kafka, ClickHouse, SPIRE, OIDC) must be provisioned
separately and configured via `external.*` values.

## Prerequisites

- Kubernetes >= 1.28
- Helm >= 3.8
- External PostgreSQL, Kafka, ClickHouse, SPIRE, and OIDC endpoints
- Pre-created Kubernetes Secrets for credentials (see below)

## Installation

### 1. Label the namespace for Pod Security Standards

The agent DaemonSet requires the `privileged` PSS profile:

```bash
kubectl label namespace kernel-v1 \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/audit=privileged \
  pod-security.kubernetes.io/warn=privileged \
  --overwrite
```

The control-plane runs under the `restricted` profile and needs no
additional labels.

### 2. Create Secrets

```bash
# PostgreSQL credentials
kubectl create secret generic kernel-v1-postgresql \
  --namespace kernel-v1 \
  --from-literal=username=control_app \
  --from-literal=password='<password>'

# OIDC client secret
kubectl create secret generic kernel-v1-oidc \
  --namespace kernel-v1 \
  --from-literal=clientSecret='<secret>'

# Agent storage key (32-byte SQLCipher key)
kubectl create secret generic kernel-v1-agent-key \
  --namespace kernel-v1 \
  --from-file=storage-key=/path/to/32-byte-key

# Optional: Kafka credentials
kubectl create secret generic kernel-v1-kafka \
  --namespace kernel-v1 \
  --from-literal=username='<user>' \
  --from-literal=password='<password>'

# Optional: ClickHouse credentials
kubectl create secret generic kernel-v1-clickhouse \
  --namespace kernel-v1 \
  --from-literal=username='<user>' \
  --from-literal=password='<password>'
```

### 3. Install

```bash
helm install kernel-v1 deploy/helm/kernel-v1 \
  --namespace kernel-v1 \
  --set external.postgresql.host=pg.example.com \
  --set external.kafka.brokers=kafka-1:9092,kafka-2:9092 \
  --set external.clickhouse.host=ch.example.com \
  --set external.spire.serverAddress=spire.example.com:8081 \
  --set external.oidc.issuer=https://auth.example.com \
  --set external.oidc.clientId=kernel-v1 \
  --set secrets.postgresql.name=kernel-v1-postgresql \
  --set secrets.oidc.name=kernel-v1-oidc \
  --set secrets.agentStorageKey.name=kernel-v1-agent-key
```

Or use a values file:

```bash
helm install kernel-v1 deploy/helm/kernel-v1 \
  --namespace kernel-v1 \
  -f my-values.yaml
```

## Upgrade

```bash
helm upgrade kernel-v1 deploy/helm/kernel-v1 \
  --namespace kernel-v1 \
  -f my-values.yaml
```

Migrations run automatically as a `pre-upgrade` Helm hook job before
the new control-plane pods start.

## Rollback

```bash
helm rollback kernel-v1 <revision> --namespace kernel-v1
```

The migration job uses `hook-delete-policy: before-hook-creation`,
so a rollback followed by a re-upgrade will clean up stale jobs.
PostgreSQL migrations use reversible `.up.sql`/`.down.sql` pairs
(in `crates/control-db/migrations/`). For a full schema rollback,
apply the corresponding `.down.sql` files manually after
`helm rollback`.

## Configuration

### External Services

| Key | Default | Description |
|-----|---------|-------------|
| `external.postgresql.host` | `""` | PostgreSQL host |
| `external.postgresql.port` | `5432` | PostgreSQL port |
| `external.postgresql.database` | `kernel_v1` | Database name |
| `external.kafka.brokers` | `""` | Comma-separated broker list |
| `external.clickhouse.host` | `""` | ClickHouse host |
| `external.clickhouse.port` | `8123` | ClickHouse HTTP port |
| `external.spire.serverAddress` | `""` | SPIRE server host:port |
| `external.oidc.issuer` | `""` | OIDC issuer URL |
| `external.oidc.clientId` | `""` | OIDC client ID |

### Secret References

| Key | Default | Description |
|-----|---------|-------------|
| `secrets.postgresql.name` | `""` | Secret with `username`/`password` |
| `secrets.kafka.name` | `""` | Optional Kafka credentials Secret |
| `secrets.clickhouse.name` | `""` | Optional ClickHouse credentials Secret |
| `secrets.oidc.name` | `""` | Secret with `clientSecret` |
| `secrets.agentStorageKey.name` | `""` | Secret with 32-byte `storage-key` |

### Images

All images support digest pinning for production. Set `image.digest`
to a `sha256:...` value; `image.tag` is the dev fallback. The default
tag is `0.1.0` — never `latest`.

| Key | Default | Description |
|-----|---------|-------------|
| `agent.image.repository` | `ghcr.io/kernel-v1/agent` | Agent image |
| `agent.image.digest` | `""` | Pin by digest (production) |
| `agent.image.tag` | `0.1.0` | Tag fallback (dev) |
| `controlPlane.image.repository` | `ghcr.io/kernel-v1/control-plane` | Control-plane image |
| `controlPlane.image.digest` | `""` | Pin by digest (production) |
| `controlPlane.image.tag` | `0.1.0` | Tag fallback (dev) |
| `migrations.image.repository` | `ghcr.io/kernel-v1/control-plane` | Migration image |

### Image Pull Secrets

```yaml
imagePullSecrets:
  - name: my-registry-secret
```

## Pod Security Standards

### Agent DaemonSet — `privileged` namespace profile

**Justification:** The agent loads and attaches eBPF programs, which
requires `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`, and `CAP_NET_ADMIN`.
These capabilities are only available under the `privileged` PSS
namespace profile.

**Mitigations (the pod is NOT privileged):**

| Setting | Value | Reason |
|---------|-------|--------|
| `privileged` | `false` | No unrestricted device access |
| `hostPID` | `false` | Uses read-only `/proc` hostPath mount |
| `hostNetwork` | `false` | Pod networking only |
| `procMount` | `Default` | NOT Unmasked |
| `allowPrivilegeEscalation` | `false` | No setuid escalation |
| `readOnlyRootFilesystem` | `true` | Immutable container FS |
| `capabilities.drop` | `ALL` | Drop everything first |
| `capabilities.add` | `BPF, PERFMON, SYS_ADMIN, NET_ADMIN` | Only 4 needed caps |
| `seccompProfile` | `RuntimeDefault` | Default seccomp |
| `runAsNonRoot` | `true` | UID 1000 |

The agent reads `/proc` via a read-only hostPath mount at `/host/proc`
for process enrichment, instead of sharing the host PID namespace.
Only `bpffs` (`/sys/fs/bpf`) and `tracefs` (`/sys/kernel/debug/tracing`)
are mounted read-write.

### Control-plane — `restricted` profile

The control-plane runs under the `restricted` PSS profile with:
- No elevated capabilities (all dropped)
- Read-only root filesystem
- Non-root user (UID 1000)
- RuntimeDefault seccomp
- No hostPath mounts

### Migrations Job — `restricted` profile

Same hardening as the control-plane. Runs as a Helm hook
(`pre-install`, `pre-upgrade`) and exits after applying migrations.

## RBAC

The chart creates a ClusterRole with **read-only** access to nodes and
pods for event enrichment:

```yaml
rules:
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
```

No cluster-admin. No write access. No secrets access.

## Resource Limits

All containers have resource requests AND limits configured in
`values.yaml`. Adjust for your workload:

```yaml
agent:
  resources:
    requests: {cpu: 100m, memory: 128Mi}
    limits: {cpu: "1", memory: 512Mi}

controlPlane:
  resources:
    requests: {cpu: 250m, memory: 256Mi}
    limits: {cpu: "2", memory: 1Gi}
```

## High Availability

The control-plane supports:
- **Replicas**: `controlPlane.replicas` (default: 2)
- **Topology spread**: distributes pods across nodes
- **PodDisruptionBudget**: `controlPlane.pdb.minAvailable` (default: 1)

## Development

Render templates locally:

```bash
helm template kernel-v1 deploy/helm/kernel-v1 \
  --set external.postgresql.host=localhost \
  --set external.kafka.brokers=localhost:9092

# Lint
helm lint deploy/helm/kernel-v1
```
