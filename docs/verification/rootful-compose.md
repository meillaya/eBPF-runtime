# Rootful compose verification

Date: 2026-11-06
Host: CachyOS, Linux 7.2.7, x86_64
Runtime: rootful Podman 5.8.9 inside a Fedora CoreOS 44 Podman machine
Image: `localhost/ebpf-fleet:test` built from `feature/fleet-platform`

## Kernel and VM

```text
rootless=false
BTF=ok
bpf on /sys/fs/bpf type bpf (rw,nosuid,nodev,noexec,relatime,mode=700)
debugfs on /sys/kernel/debug type debugfs (rw,...)
lockdown: [none] integrity confidentiality
unprivileged_bpf_disabled: 2
LSM: lockdown,capability,yama,selinux,bpf,landlock,ipe,ima,evm
```

## Data path

```text
sensor    status     attached  failed  skipped
process   capable           3       0        0
file      capable           6       0        0
```

The development compose file initially failed for two real reasons:

1. The control plane was configured to bind `0.0.0.0` while `dev = true`
   requires loopback. The fix was to put the control plane and agent on
   host networking and keep loopback listeners.
2. ClickHouse rejected the relay's remote `default` user. The dev profile
   now mounts a test-only users override that allows that user from the
   compose bridge.

After those fixes (final run):

```text
/healthz  {"status":"ok"}
/readyz   {"ready":true}
/agents   one row: node_name=localhost.localdomain
/events   rows with FileOpen/ProcessExec/ProcessFork/ProcessExit
relay     projected batch lines, no fatal errors
```

The final rebuilt image was verified again after the rollout and rotation changes:
ClickHouse count rose from `117852` to `119123` over five seconds. The
analytics endpoint returned per-kind counts and alert counts from
ClickHouse. The dashboard screenshot is
[`dashboard-rootful.png`](dashboard-rootful.png).

## Notes

- The dashboard is a snapshot loaded from `/api/v1`; the WebSocket feed is
  the agent-local API, not a control-plane push feed.
- The image build used `--network=host` inside the VM.
- `podman compose` invoked the external `docker-compose` provider from
  `/home/core/bin`.
