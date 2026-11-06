# Rootful compose smoke test

This is the data-path check: load the two sensors on a real kernel, write
through SQLCipher, deliver over gRPC to PostgreSQL, project through Kafka
into ClickHouse, and render the dashboard. It uses the development compose
file, so OIDC and mTLS are intentionally **not** exercised. The identity
profile is separate.

## Host shape

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

## Create and start the VM

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
filesystem is missing, mount it in the VM. A lockdown value of
`[integrity]` or `[confidentiality]` blocks the attach and is a host
configuration problem, not an agent bug.

## Compose provider

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

## Build

Build from the shared source inside the VM. Host networking avoids mirror
and DNS problems in the VM:

```bash
podman machine ssh ebpf-sandbox -- '
  cd /home/core/src
  sudo podman build --network=host -t localhost/ebpf-fleet:test .
'
```

The first build is the slow one. Later builds reuse the VM's Podman layers
and cargo cache mounts.

## Start

The development file uses host networking for the control plane and agent.
That is deliberate: the control plane's `dev = true` validation only allows
loopback binds, and the agent must reach the gRPC listener on loopback.
PostgreSQL and ClickHouse publish loopback ports for the control plane and
relay. ClickHouse's built-in `default` user only accepts loopback by
default, so the dev stack mounts
`deploy/compose/config/clickhouse-users.xml` to allow the bridge relay.

```bash
podman machine ssh ebpf-sandbox -- '
  cd /home/core/src
  sudo env PATH="/home/core/bin:$PATH" podman compose -f compose.yaml up -d --no-build
'
```

If the image was not pre-built, use `up -d --build` instead.

## Verify

```bash
podman machine ssh ebpf-sandbox -- '
  cd /home/core/src
  sudo env PATH="/home/core/bin:$PATH" podman compose -f compose.yaml ps
  curl -fsS http://127.0.0.1:8080/healthz; echo
  curl -fsS http://127.0.0.1:8080/readyz; echo
  curl -fsS "http://127.0.0.1:8080/api/v1/events?limit=5"; echo
  curl -fsS http://127.0.0.1:8080/api/v1/agents; echo
  sudo env PATH="/home/core/bin:$PATH" podman compose -f compose.yaml exec -T agent /usr/local/bin/ebpf-runtime check
  sudo env PATH="/home/core/bin:$PATH" podman compose -f compose.yaml exec -T clickhouse clickhouse-client --query "SELECT count() FROM ebpf.events"
  sleep 5
  sudo env PATH="/home/core/bin:$PATH" podman compose -f compose.yaml exec -T clickhouse clickhouse-client --query "SELECT count() FROM ebpf.events"
'
```

Acceptance: every container is up; health and readiness return 200; the
agent table shows process and file attached with zero failed/skipped; the
agent appears in `/agents`; the ClickHouse count rises; relay logs contain
`projected batch` lines.

The checked-in verification run recorded:

```text
sensor    status     attached  failed  skipped
process   capable           3       0        0
file      capable           6       0        0

ClickHouse ebpf.events: 22035 -> 23574 over five seconds
```

A dashboard screenshot was taken with Playwright:
`docs/verification/dashboard-rootful.png`.

## Dashboard access from the host

Forward the VM's loopback port:

```bash
PORT=$(podman machine inspect --format '{{.SSHConfig.Port}}' ebpf-sandbox)
ssh -i ~/.local/share/containers/podman/machine/machine -p "$PORT" -N \
  -L 8080:127.0.0.1:8080 root@127.0.0.1
```

Open `http://127.0.0.1:8080`. The dashboard loads a snapshot from the API;
the WebSocket path is the agent-local API and is not served by the control
plane.

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

## Cleanup

```bash
podman machine ssh ebpf-sandbox -- '
  cd /home/core/src
  sudo env PATH="/home/core/bin:$PATH" podman compose -f compose.yaml down -v
  sudo podman image prune -f
'
podman machine stop ebpf-sandbox
podman machine rm -f ebpf-sandbox
```

`down -v` deletes the development database and agent state. Remove the
machine only after saving the evidence and closing any tunnels.
