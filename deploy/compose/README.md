# Local Development Infrastructure — deploy/compose/

Docker Compose stack and privileged QEMU VM for kernel-v1 integration
testing. Provides PostgreSQL, Kafka (KRaft), ClickHouse, SPIRE
(server + agent), and Dex OIDC on a shared network.

> **SECURITY**: ALL credentials in this stack are **DEV-ONLY**.
> Never use them in production. Production deployment uses
> SPIRE-issued SVIDs, not static tokens.

## Prerequisites

### Compose stack

- Docker Engine 24+ or Podman 5+ with `docker compose` v2 plugin
- ~4 GB RAM available for the containers
- Ports 5432, 8123, 9000, 9092, 8081, 5556 free on 127.0.0.1

### Privileged VM (optional, for BPF testing)

- `qemu-system-x86_64` (package: `qemu-full` or `qemu-desktop`)
- KVM module loaded: `sudo modprobe kvm_intel` (or `kvm_amd`)
- `virtiofsd` (package: `virtiofsd`)
- ~20 GB free disk for the VM image
- SSH key pair: `ssh-keygen -t ed25519`

## Quick Start

```bash
# Enter the devenv shell first (provides docker, qemu, etc.)
devenv shell

# Start the full stack
devenv tasks run infra:up

# Check health
devenv tasks run infra:status

# Tail logs
devenv tasks run infra:logs

# Stop (preserves volumes)
devenv tasks run infra:down

# Destroy everything including data
devenv tasks run infra:reset
```

Or directly with Docker Compose:

```bash
docker compose -f deploy/compose/dev-infra.yml up -d
docker compose -f deploy/compose/dev-infra.yml ps
docker compose -f deploy/compose/dev-infra.yml down
```

## Service Endpoints

| Service    | Host Endpoint              | Container | Notes                              |
|------------|----------------------------|-----------|------------------------------------|
| PostgreSQL | `127.0.0.1:5432`           | k1-postgres | db=`kernel_v1`, user=`control_app`, pass=`dev-only-not-prod` |
| Kafka      | `127.0.0.1:9092`           | k1-kafka  | KRaft mode, no ZooKeeper. Internal: `kafka:9092` |
| ClickHouse | `127.0.0.1:8123` (HTTP)    | k1-clickhouse | Native TCP: `127.0.0.1:9000`   |
| SPIRE      | `127.0.0.1:8081`           | k1-spire-server | trust_domain=`example.org`     |
| Dex OIDC   | `127.0.0.1:5556`           | k1-dex    | issuer=`http://127.0.0.1:5556/dex` |

All host bindings are on **127.0.0.1** (loopback only). Services
communicate over the `kernel-v1-dev` Docker network using container
names (e.g., `kafka:9092`, `spire-server:8081`).

## OIDC Test Users

| Email               | Password   | Groups   |
|---------------------|------------|----------|
| admin@example.com   | `password` | `admin`  |
| viewer@example.com  | `password` | `viewer` |

OIDC client: `kernel-v1-dev` / secret: `dev-secret`
Redirect URI: `http://localhost:8080/callback`

Discovery: `http://127.0.0.1:5556/dex/.well-known/openid-configuration`

## ClickHouse Migrations

The compose stack automatically applies the parameterized migrations
from `deploy/clickhouse/` on first startup via
`config/clickhouse-init.sh`. The migrations use `{param:Type}` macros
that require `--param` flags, so a shell wrapper is necessary (raw
`.sql` files in the Docker init directory cannot pass parameters).

Applied migrations:

| File | Purpose |
|------|---------|
| `0001_events_v1.sql` | Core events table (ReplacingMergeTree) |
| `0002_kafka_consumer.sql` | Kafka engine + materialized view |
| `0003_dlq_metadata.sql` | DLQ metadata table + schema-reject MV |
| `0004_consumer_lag_metrics.sql` | Consumer lag + DLQ rate views |
| `0005_exact_query_helpers.sql` | FINAL/argMax exact-query views |

Dev parameters: `events_ttl_days=30`, `dlq_ttl_days=90`,
`kafka_broker_list=kafka:9092`,
`kafka_consumer_group=clickhouse-events-v1`.

To re-apply migrations manually:

```bash
docker compose -f deploy/compose/dev-infra.yml exec clickhouse \
  bash /docker-entrypoint-initdb.d/00-init.sh
```

## SPIRE Setup

The SPIRE agent uses a custom dev image
(`Dockerfile.spire-agent-dev`) that:

1. Waits for the SPIRE server to become healthy
2. Generates a one-time join token via the server's admin socket
3. Starts the agent with that token

The agent's workload API socket is available at
`/tmp/spire-agent/public/api.sock` inside the `k1-spire-agent`
container (shared via the `k1-spire-agent-socket` volume).

To verify SPIRE is working:

```bash
# Check server health
docker compose -f deploy/compose/dev-infra.yml exec spire-server \
  /opt/spire/bin/spire-server healthcheck

# List registered entries
docker compose -f deploy/compose/dev-infra.yml exec spire-server \
  /opt/spire/bin/spire-server entry show

# Check agent health
docker compose -f deploy/compose/dev-infra.yml exec spire-agent \
  /opt/spire/bin/spire-agent healthcheck
```

## Running Integration Tests

With the stack running:

```bash
# PostgreSQL
psql "postgresql://control_app:dev-only-not-prod@127.0.0.1:5432/kernel_v1" \
  -c "SELECT 1"

# Kafka (create a test topic)
docker compose -f deploy/compose/dev-infra.yml exec kafka \
  kafka-topics --bootstrap-server localhost:9092 \
  --create --topic test.v1 --partitions 1 --replication-factor 1

# ClickHouse HTTP
curl -s "http://127.0.0.1:8123/?query=SELECT+count()+FROM+events_v1"

# ClickHouse native
docker compose -f deploy/compose/dev-infra.yml exec clickhouse \
  clickhouse-client --query "SHOW TABLES"

# Dex OIDC discovery
curl -s http://127.0.0.1:5556/dex/.well-known/openid-configuration | jq .

# Run the Rust integration test suite against the stack
DATABASE_URL="postgresql://control_app:dev-only-not-prod@127.0.0.1:5432/kernel_v1" \
KAFKA_BROKERS="127.0.0.1:9092" \
CLICKHOUSE_URL="http://127.0.0.1:8123" \
DEX_ISSUER="http://127.0.0.1:5556/dex" \
  cargo nextest run --workspace -E 'test(integration)'
```

## Privileged VM for BPF Testing

The QEMU VM provides a privileged Linux environment with BPF
capabilities that the host may lack (`unprivileged_bpf_disabled=2`,
`CapEff=0`).

```bash
# Launch VM with interactive SSH
devenv tasks run infra:privileged

# Or directly:
scripts/dev-vm.sh --ssh

# One-shot command:
scripts/dev-vm.sh --run 'cargo nextest run -E "test(privileged)"'

# Run the privileged test suite:
scripts/dev-vm.sh --run \
  'scripts/run-privileged-tests.sh --kernel current --arch x86_64 --out /tmp/evidence.json'

# Check VM status:
scripts/dev-vm.sh --status

# Destroy VM and all state:
scripts/dev-vm.sh --destroy
```

### VM Specifications

| Resource | Value |
|----------|-------|
| vCPUs | 4 (KVM, host CPU passthrough) |
| RAM | 8 GB |
| Disk | 20 GB qcow2 (Arch Linux cloud image) |
| Workspace | virtio-fs mount at `/home/mei/projects/kernels/kernel-v1` |
| SSH | `127.0.0.1:2222` → guest port 22 |

### Guest Environment

The VM auto-configures on first SSH:

- `kernel.unprivileged_bpf_disabled=0` (persisted in sysctl.d)
- Workspace mounted via virtio-fs (tag=`kernel-v1`, persisted in fstab)
- Packages: `clang`, `llvm`, `lld`, `libbpf`, `bpftool`, `base-devel`
- `rustup` with toolchain 1.95.0

### Disk Image

Two paths to obtain a VM disk image:

**Path A (automatic)**: The script downloads an Arch Linux cloud
image on first run (~600 MB). Set `KERNEL_V1_VM_IMAGE` to a local
qcow2 to skip the download.

**Path B (manual)**: Build with `mkosi` or `pacstrap`:

```bash
# mkosi
mkosi --distribution=arch --format=disk --output=arch-vm.raw
qemu-img convert -f raw -O qcow2 arch-vm.raw disk.qcow2

# pacstrap: see Arch Wiki "Install Arch Linux in a VM"
```

### Environment Overrides

| Variable | Default | Description |
|----------|---------|-------------|
| `KERNEL_V1_VM_DIR` | `~/.local/share/kernel-v1-vm` | VM state directory |
| `KERNEL_V1_VM_IMAGE` | (auto-download) | Pre-built qcow2 path |
| `KERNEL_V1_VM_CPUS` | `4` | vCPU count |
| `KERNEL_V1_VM_RAM` | `8192` | RAM in MB |
| `KERNEL_V1_VM_SSH_PORT` | `2222` | Host SSH port |

## File Layout

```
deploy/compose/
├── dev-infra.yml                    # Docker Compose stack definition
├── Dockerfile.spire-agent-dev       # SPIRE agent with auto join-token
├── README.md                        # This file
└── config/
    ├── dex-config.yaml              # Dex OIDC provider config
    ├── spire-server.conf            # SPIRE server HCL config
    ├── spire-agent.conf             # SPIRE agent HCL config
    ├── spire-agent-entrypoint.sh    # Agent entrypoint (token generation)
    └── clickhouse-init.sh           # ClickHouse migration runner
```

## Troubleshooting

### Kafka fails to start

Kafka KRaft mode requires a clean data directory on first start.
If Kafka crash-loops, reset its volume:

```bash
docker compose -f deploy/compose/dev-infra.yml rm -fsv kafka
docker volume rm k1-kafka-data
docker compose -f deploy/compose/dev-infra.yml up -d kafka
```

### SPIRE agent cannot attest

The agent's entrypoint generates a join token automatically. If it
fails, check the server logs:

```bash
docker compose -f deploy/compose/dev-infra.yml logs spire-server
docker compose -f deploy/compose/dev-infra.yml logs spire-agent
```

### ClickHouse migrations fail

The init script runs only on first startup (empty data directory).
To re-apply:

```bash
docker compose -f deploy/compose/dev-infra.yml exec clickhouse \
  bash /docker-entrypoint-initdb.d/00-init.sh
```

### VM SSH connection refused

Wait for the VM to boot (~30-60s). Check the serial log:

```bash
tail -f ~/.local/share/kernel-v1-vm/serial.log
```

### VM virtio-fs mount fails

Ensure `virtiofsd` is running and the socket exists:

```bash
ls -la ~/.local/share/kernel-v1-vm/virtiofsd.sock
```

Inside the VM, mount manually:

```bash
mount -t virtiofs kernel-v1 /home/mei/projects/kernels/kernel-v1
```
