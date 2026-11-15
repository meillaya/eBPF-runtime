# Rootful compose verification

Date: 2026-11-15
Host: massive, Linux 7.3.3-1-cachyos, x86_64, 16 CPUs, KVM available
VM: Ubuntu 24.04.5 cloud image from `scripts/vm/lab.sh` (12 vCPU, 16 GiB, 80 GiB overlay)
Guest kernel: 6.8.0-147-generic, BTF 6,103,569 bytes at `/sys/kernel/btf/vmlinux`, lockdown `[none]`
Runtime: rootful Docker Engine 29.1.3 with Compose v2.40.3 **inside the VM**
Image: `localhost/ebpf-fleet:test` built in the VM from the repo `Containerfile` (web stage,
cargo release build stage, Arch Linux runtime), 900 MB

This run replaces the earlier 2026-11-06 Podman-machine run and the dashboard screenshot it left
behind. The VM lab boots a disposable cloud-image guest under KVM and the compose stack runs rootful
inside it: no host root, no host bridge, no libvirt, no hostful container engine.

## VM and kernel

```text
rootless=false
BTF=ok
lockdown: [none] integrity confidentiality
unprivileged_bpf_disabled: 2
sensors: process capable 3 attached, file capable 7 attached, 0 failed, 0 skipped
debugfs and bpffs mounted in the guest and bind-mounted into the agent container
```

The guest kernel has no BPF LSM, so the file sensor uses the kprobe/pt_regs fallback; the sensor table
above is the same contract the kernel matrix checks.

## Data path

All six compose services reached steady state with zero restarts:

```text
ebpf-fleet-dev-agent-1           Up
ebpf-fleet-dev-control-plane-1   Up
ebpf-fleet-dev-relay-1           Up
ebpf-fleet-dev-postgres-1        Up (healthy)
ebpf-fleet-dev-kafka-1           Up (healthy)
ebpf-fleet-dev-clickhouse-1      Up (healthy)

/healthz   {"status":"ok"}
/readyz    {"ready":true}
/agents    one row: node_name=compose-vm, sensors=["process","file"]
ClickHouse ebpf.events: 36844 -> 37300 over five seconds
relay      projected batch lines every poll, no errors
```

Analytics buckets from ClickHouse at capture time:

```text
FileOpen    12445
ProcessExit 10634
ProcessFork 10617
ProcessExec  3336
FileUnlink    264
FileRename      4
```

The default sensitive-files rule pack produced real alerts from guest activity (read/creation under
`/etc`, SSH and PAM paths): 167 high-severity alerts in the 24-hour analytics window, all
`sensitive-file-write-intent`, none critical.

Policy distribution was exercised end to end through the HTTP API against the live stack:

```text
stage   default@1 -> committed -> applied by the agent (ack)
stage   default@2 -> committed -> rollout (min_ratio 1.0, timeout 60 s)
rollout status: promoted ("threshold reached"), expected 1, applied 1, rejected 0
acks:            compose-vm-unknown applied
policies:        v2 applied, v1 committed (rollback target)
audit:           policy.stage / policy.commit / policy.rollout rows
```

## Dashboard

The final screenshot is [`dashboard-rootful.png`](dashboard-rootful.png), captured with Playwright at
1500x1100 against the forwarded control-plane port. It shows the current Register dashboard reading the
live stack: 1/1 agents online (`compose-vm`), 34.7k events and 167 alerts in the last 24 hours,
`default v2` applied 1 of 1 with a promoted rollout, recent alerts and events, per-node heartbeat,
event rate and the process/file event mix.

The other surfaces were exercised in the same session (Events with detail drawer, Alerts, Agents,
Policies with stored YAML and acknowledgements, Audit) with no browser console errors.

## Reproduce

```bash
# toolchain from the devenv shell (qemu + libisoburn)
export VM_LAB_TOOL_PATH="$(ls -d /nix/store/*-qemu-10.2.2/bin | tail -1):$(ls -d /nix/store/*-libisoburn-*/bin | tail -1)"

# 1. boot the pinned Ubuntu 24.04 image as a disposable KVM guest
scripts/vm/lab.sh up --image ubuntu-24.04 --name compose-vm \
  --cpus 12 --memory 16384 --disk-size 80G

# 2. inside the guest: docker + compose plugin, mount debugfs/bpffs
scripts/vm/lab.sh run --name compose-vm -- '
  sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 docker-buildx
  sudo systemctl enable --now docker
  sudo mount -t bpf bpf /sys/fs/bpf; sudo mount -t debugfs none /sys/kernel/debug'

# 3. copy the source and build the image in the VM
tar -czf target/vm/ebpf-src.tgz --exclude='./target' --exclude='./.git' \
  --exclude='./.devenv' --exclude='./docs' --exclude='./web/node_modules' \
  --exclude='./web/dist' --exclude='./web/redesign' .
scripts/vm/lab.sh copy --name compose-vm target/vm/ebpf-src.tgz /home/fleet/ebpf-src.tgz
scripts/vm/lab.sh run --name compose-vm -- '
  mkdir -p /home/fleet/src && tar -xzf /home/fleet/ebpf-src.tgz -C /home/fleet/src
  cd /home/fleet/src
  sudo docker build --network=host -f Containerfile -t localhost/ebpf-fleet:test .

# 4. run the stack and drive it
scripts/vm/lab.sh run --name compose-vm -- '
  cd /home/fleet/src
  sudo docker compose -f compose.yaml up -d --no-build
  curl -fsS http://127.0.0.1:8080/readyz

  # policy: stage + commit + rollout (rollout needs a previous committed version for rollback)
  jq -Rs "{name:\"default\",version:1,content:.}" rules/default/sensitive-files.yaml > /tmp/p1.json
  curl -fsS -X POST http://127.0.0.1:8080/api/v1/policies/stage -H "content-type: application/json" --data-binary @/tmp/p1.json
  curl -fsS -X POST http://127.0.0.1:8080/api/v1/policies/commit -H "content-type: application/json" -d "{\"version\":1}"
  jq -Rs "{name:\"default\",version:2,content:.}" rules/default/sensitive-files.yaml > /tmp/p2.json
  curl -fsS -X POST http://127.0.0.1:8080/api/v1/policies/stage -H "content-type: application/json" --data-binary @/tmp/p2.json
  curl -fsS -X POST http://127.0.0.1:8080/api/v1/policies/commit -H "content-type: application/json" -d "{\"version\":2}"
  curl -fsS -X POST http://127.0.0.1:8080/api/v1/policies/2/rollout -H "content-type: application/json" -d "{\"min_ratio\":1.0,\"timeout_secs\":60}"'

# 5. forward the dashboard port and capture the screenshot
ssh -i target/vm/keys/id_ed25519 -p 2222 -o StrictHostKeyChecking=no \
  -N -L 127.0.0.1:18080:127.0.0.1:8080 fleet@127.0.0.1
cd web && node scripts/shot-stack.mjs http://127.0.0.1:18080
```

## Notes

- The dashboard is a snapshot loaded from `/api/v1`; the WebSocket feed is the agent-local API, not a
  control-plane push feed.
- The screenshot is the development compose profile: OIDC and mTLS are intentionally not exercised, so
  the header shows `dev auth`. The OIDC identity profile is covered separately by `e2e/oidc.spec.ts`.
- The rollout endpoint requires an earlier committed version as the rollback target, which is why the
  run stages and commits v1 before rolling out v2.
- The agent's SPIFFE id in the development compose stack is `compose-vm-unknown` (no identity issuer);
  the Agents surface shows it, and the node name is `compose-vm`.
