# Rootful compose smoke test

This is the data-path check: load the two sensors on a real kernel, write
through SQLCipher, deliver over gRPC to PostgreSQL, project through Kafka
into ClickHouse, and render the dashboard. It uses the development compose
file, so OIDC and mTLS are intentionally **not** exercised. The identity
profile is separate.

The current, verified path is the repository VM lab: a disposable Ubuntu
cloud guest under KVM with rootful Docker and Compose inside the guest. The
rootful Podman machine path used before 2026-11-15 is kept below as the
alternative.

## Fast path: repository VM lab (verified 2026-11-15)

### Toolchain

The lab needs QEMU, `cloud-localds` (or `xorriso`), SSH and `jq` on `PATH`.
Inside the dev shell they are provided; on a bare Nix host point the lab at
the store directories:

```bash
export VM_LAB_TOOL_PATH="$(ls -d /nix/store/*-qemu-*/bin | tail -1):$(ls -d /nix/store/*-libisoburn-*/bin | tail -1)"
scripts/vm/lab.sh status
```

### Boot the guest

```bash
scripts/vm/lab.sh up --image ubuntu-24.04 --name compose-vm \
  --cpus 12 --memory 16384 --disk-size 80G
```

Verify the kernel prerequisites inside the guest:

```bash
scripts/vm/lab.sh run --name compose-vm -- '
  uname -r
  test -r /sys/kernel/btf/vmlinux && echo BTF=ok
  cat /sys/kernel/security/lockdown
  cat /proc/sys/kernel/unprivileged_bpf_disabled'
```

Expected: BTF readable and lockdown `[none]`. A lockdown value of
`[integrity]` or `[confidentiality]` blocks the attach and is a host
configuration problem, not an agent bug.

### Guest prerequisites

```bash
scripts/vm/lab.sh run --name compose-vm -- '
  sudo apt-get update
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-v2 docker-buildx
  sudo systemctl enable --now docker
  sudo mount -t bpf bpf /sys/fs/bpf
  sudo mount -t debugfs none /sys/kernel/debug
  docker --version && docker compose version'
```

### Build the image in the guest

BuildKit is required because the Containerfile uses cache mounts, so install
`docker-buildx` (above) and keep `docker buildx` available. Copy the source
without local build output, then build with host networking:

```bash
tar -czf target/vm/ebpf-src.tgz --exclude='./target' --exclude='./.git' \
  --exclude='./.devenv' --exclude='./docs' --exclude='./web/node_modules' \
  --exclude='./web/dist' --exclude='./web/redesign' .
scripts/vm/lab.sh copy --name compose-vm target/vm/ebpf-src.tgz /home/fleet/ebpf-src.tgz
scripts/vm/lab.sh run --name compose-vm -- '
  mkdir -p /home/fleet/src && tar -xzf /home/fleet/ebpf-src.tgz -C /home/fleet/src
  cd /home/fleet/src
  sudo docker build --network=host -f Containerfile -t localhost/ebpf-fleet:test .'
```

The first build is the slow one; later builds reuse the guest's BuildKit
cache and rebuild in seconds.

### Start and drive the stack

The development file uses host networking for the control plane and agent.
That is deliberate: the control plane's `dev = true` validation only allows
loopback binds, and the agent must reach the gRPC listener on loopback.
PostgreSQL and ClickHouse publish loopback ports for the control plane and
relay. ClickHouse's built-in `default` user only accepts loopback by
default, so the dev stack mounts
`deploy/compose/config/clickhouse-users.xml` to allow the bridge relay.

```bash
scripts/vm/lab.sh run --name compose-vm -- '
  cd /home/fleet/src
  sudo docker compose -f compose.yaml up -d --no-build
  curl -fsS http://127.0.0.1:8080/healthz; echo
  curl -fsS http://127.0.0.1:8080/readyz; echo
  sudo docker compose -f compose.yaml exec -T agent /usr/local/bin/ebpf-runtime check

  # Rollout needs a previous committed version as its rollback target, so
  # commit v1 first, then stage + commit v2 and roll it out.
  jq -Rs "{name:\"default\",version:1,content:.}" rules/default/sensitive-files.yaml > /tmp/p1.json
  curl -fsS -X POST http://127.0.0.1:8080/api/v1/policies/stage -H "content-type: application/json" --data-binary @/tmp/p1.json
  curl -fsS -X POST http://127.0.0.1:8080/api/v1/policies/commit -H "content-type: application/json" -d "{\"version\":1}"
  jq -Rs "{name:\"default\",version:2,content:.}" rules/default/sensitive-files.yaml > /tmp/p2.json
  curl -fsS -X POST http://127.0.0.1:8080/api/v1/policies/stage -H "content-type: application/json" --data-binary @/tmp/p2.json
  curl -fsS -X POST http://127.0.0.1:8080/api/v1/policies/commit -H "content-type: application/json" -d "{\"version\":2}"
  curl -fsS -X POST http://127.0.0.1:8080/api/v1/policies/2/rollout -H "content-type: application/json" -d "{\"min_ratio\":1.0,\"timeout_secs\":60}"
  curl -fsS http://127.0.0.1:8080/api/v1/policies/2/rollout'
```

Guest activity against `/etc`, SSH and PAM paths produces genuine alerts
from the default pack; no synthetic events are injected.

Acceptance: every container is up; health and readiness return 200; the
agent table shows process and file attached with zero failed/skipped; the
agent appears in `/agents`; the ClickHouse count rises; relay logs contain
`projected batch` lines; the rollout status is `promoted`.

The 2026-11-15 run recorded:

```text
sensor    status     attached  failed  skipped
process   capable           3       0        0
file      capable           7       0        0

ClickHouse ebpf.events: 36844 -> 37300 over five seconds
rollout v2: promoted (expected 1, applied 1, rejected 0, "threshold reached")
```

### Dashboard access and screenshot from the host

Forward the guest's loopback port with the lab key:

```bash
ssh -i target/vm/keys/id_ed25519 -p 2222 -o StrictHostKeyChecking=no \
  -N -L 127.0.0.1:18080:127.0.0.1:8080 fleet@127.0.0.1
```

Open `http://127.0.0.1:18080`. The dashboard loads a snapshot from the API;
the WebSocket path is the agent-local API and is not served by the control
plane. The screenshot was captured with Playwright at a 1500x1100 viewport:

```bash
cd web && node scripts/shot-stack.mjs http://127.0.0.1:18080
cp ../target/verification/dashboard-rootful.png ../docs/verification/dashboard-rootful.png
```

The capture script is checked in at `web/scripts/shot-stack.mjs`.

### Cleanup

```bash
scripts/vm/lab.sh down --name compose-vm
```

`down` deletes the overlay, the seed and the containers with it; the pinned
base image stays cached under `target/vm/images`.

## Alternative: rootful Podman machine (pre-2026-11-15 path)

The host Podman in this workspace is rootless and `sudo` requires a
password. Do not try to run `sudo podman` on the host. Rootful means a
rootful Podman machine:

```bash
ls -l /dev/kvm
podman machine list
```

The VM needs QEMU, `virtiofsd`, and `gvproxy` on `PATH`. On this host they
came from Nix:

```bash
export PATH=/nix/store/bp9li432ba8adp47dr9z9y0hx56wn8v2-qemu-11.1.2/bin:$PATH
export PATH=/nix/store/8m9bi1ykhh1yjq86a6wkrkk0n9w7b1ny-virtiofsd-1.14.0/bin:$PATH
export PATH=/nix/store/qj0wcnj9kk404b1hmgwb323s7k7aqlaq-gvproxy-0.9.0/bin:$PATH
```

### Create and start the VM

The source is mounted at `/home/core/src`; use a disposable machine name.

```bash
podman machine init --cpus 8 --memory 16384 --disk-size 80 --rootful \
  --volume "/home/mei/Documents/eBPF-runtime:/home/core/src" ebpf-sandbox
podman machine start ebpf-sandbox
```

Verify rootful Podman and the kernel prerequisites **inside** the VM:

```bash
podman machine ssh ebpf-sandbox -- '
  sudo podman info --format "rootless={{.Host.Security.Rootless}}"
  test -r /sys/kernel/btf/vmlinux && echo BTF=ok
  mount | grep -E "/(sys/kernel/debug|sys/fs/bpf)"
  cat /sys/kernel/security/lockdown
  cat /proc/sys/kernel/unprivileged_bpf_disabled
  cat /sys/kernel/security/lsm
'
```

Expected: `rootless=false`, BTF readable, debugfs and bpffs mounted, no
active integrity/confidentiality lockdown, and `bpf` in the LSM list. If a
filesystem is missing, mount it in the VM.

### Compose provider

The VM does not ship a compose provider. Install the static Compose v2
binary into the core user's bin directory:

```bash
podman machine ssh ebpf-sandbox -- '
  mkdir -p /home/core/bin
  curl -fsSL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64 \
    -o /home/core/bin/docker-compose
  chmod +x /home/core/bin/docker-compose
  sudo env PATH="/home/core/bin:$PATH" podman compose version
'
```

`podman compose` prints a notice that it is invoking the external provider;
that is expected.

### Build

Build from the shared source inside the VM. Host networking avoids mirror
and DNS problems in the VM:

```bash
podman machine ssh ebpf-sandbox -- '
  cd /home/core/src
  sudo podman build --network=host -t localhost/ebpf-fleet:test .
'
```

### Start and verify

```bash
podman machine ssh ebpf-sandbox -- '
  cd /home/core/src
  sudo env PATH="/home/core/bin:$PATH" podman compose -f compose.yaml up -d --no-build
  sudo env PATH="/home/core/bin:$PATH" podman compose -f compose.yaml ps
  curl -fsS http://127.0.0.1:8080/healthz; echo
  curl -fsS http://127.0.0.1:8080/readyz; echo
  sudo env PATH="/home/core/bin:$PATH" podman compose -f compose.yaml exec -T agent /usr/local/bin/ebpf-runtime check
  sudo env PATH="/home/core/bin:$PATH" podman compose -f compose.yaml exec -T clickhouse clickhouse-client --query "SELECT count() FROM ebpf.events"
  sleep 5
  sudo env PATH="/home/core/bin:$PATH" podman compose -f compose.yaml exec -T clickhouse clickhouse-client --query "SELECT count() FROM ebpf.events"
'
```

### Dashboard access from the host

```bash
PORT=$(podman machine inspect --format '{{.SSHConfig.Port}}' ebpf-sandbox)
ssh -i ~/.local/share/containers/podman/machine/machine -p "$PORT" -N \
  -L 8080:127.0.0.1:8080 root@127.0.0.1
```

Open `http://127.0.0.1:8080`.

## Common failures

- **Control plane exits with `dev mode must bind loopback only`.** The
  development compose file must use host networking and loopback listeners.
  Do not relax the validation.
- **Relay gets ClickHouse `AUTHENTICATION_FAILED`.** The default user is
  loopback-only. Keep the dev users override mounted, or add explicit
  credentials to the relay client.
- **SELinux denies a bind-mounted config.** Change that mount to `:ro,z` or
  relabel the config directory. The dev and OIDC files already request a
  private label on their config mounts where needed.
- **Compose provider missing under `sudo`.** Put `docker-compose` on root's
  `PATH`, as above.
- **`Operation not permitted` from the agent.** The container is not
  privileged, the host is under lockdown, or debugfs/bpffs is missing.
  Run `ebpf-runtime check` in the agent container and read the attach
  errors.
- **Port 8080 or 9443 is taken.** Stop the other process or tunnel a
  different host port. The OIDC profile uses 8081/9444 to avoid a clash.
- **Rollout returns 409 "a previous committed policy version is required".**
  Commit an earlier version first; the rollout stores it as the rollback
  target.
- **Docker build fails on `RUN --mount=type=cache`.** The legacy builder is
  in use; install `docker-buildx` and build with BuildKit.
