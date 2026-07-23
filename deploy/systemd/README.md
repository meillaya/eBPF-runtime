# kernel-v1-agent systemd deployment

Hardened systemd packaging for the kernel-v1 eBPF runtime security &
observability agent.  The service runs as a dedicated unprivileged system
user (`kernel-v1`) and receives exactly four Linux capabilities via
`AmbientCapabilities` — it never runs as root.

## Files

| File | Install target | Purpose |
|------|---------------|---------|
| `kernel-v1-agent.service` | `/etc/systemd/system/` | Hardened unit file |
| `kernel-v1-agent.tmpfiles.d.conf` | `/usr/lib/tmpfiles.d/kernel-v1-agent.conf` | Creates `/run/kernel-v1` at boot |
| `kernel-v1-agent.sysusers.d.conf` | `/usr/lib/sysusers.d/kernel-v1-agent.conf` | Creates `kernel-v1` system user/group |

## Quick install

```bash
# Build the agent binary first
cargo build --release -p agent

# Install everything (requires root)
sudo scripts/install-systemd.sh --binary target/release/agent
```

The install script validates kernel BPF support, creates the system user,
installs all configs, reloads systemd, and enables + starts the service.

### Manual install

```bash
sudo install -m 0644 deploy/systemd/kernel-v1-agent.sysusers.d.conf \
    /usr/lib/sysusers.d/kernel-v1-agent.conf
sudo systemd-sysusers /usr/lib/sysusers.d/kernel-v1-agent.conf

sudo install -m 0644 deploy/systemd/kernel-v1-agent.tmpfiles.d.conf \
    /usr/lib/tmpfiles.d/kernel-v1-agent.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/kernel-v1-agent.conf

sudo install -m 0755 target/release/agent /usr/local/bin/kernel-v1-agent
sudo install -m 0644 deploy/systemd/kernel-v1-agent.service \
    /etc/systemd/system/kernel-v1-agent.service

sudo systemctl daemon-reload
sudo systemctl enable --now kernel-v1-agent
```

## Privilege workflow

### Why not root?

Running a BPF agent as root violates the principle of least privilege.  A
compromised root process can read any file, load kernel modules, modify
networking, and pivot to any other host service.  The kernel-v1 agent needs
only four specific capabilities to do its job — everything else is an
unnecessary attack surface.

### Capability model

The service uses **ambient capabilities** (`AmbientCapabilities=`), which
are inherited across `execve()` by an unprivileged user.  Combined with
`CapabilityBoundingSet=` set to the same four capabilities, the kernel
guarantees the process can never acquire anything beyond this set — even
if the binary is exploited.

```
┌─────────────────────────────────────────────────────────────────┐
│  systemd (PID 1, full capabilities)                            │
│                                                                │
│  1. Forks child as root                                        │
│  2. Sets CapabilityBoundingSet = CAP_BPF CAP_PERFMON           │
│     CAP_SYS_ADMIN CAP_NET_ADMIN                                │
│  3. Sets AmbientCapabilities = same four                       │
│  4. setuid() to kernel-v1 (unprivileged)                       │
│  5. execve(/usr/local/bin/kernel-v1-agent)                     │
│     → child inherits exactly 4 ambient caps                    │
│     → bounding set prevents acquiring anything else            │
└─────────────────────────────────────────────────────────────────┘
```

### Why each capability is needed

| Capability | Bit | Required for |
|-----------|-----|-------------|
| `CAP_BPF` | 39 | Load BPF programs into the kernel, create and pin BPF maps, read BPF map contents.  Without this, `bpf(BPF_PROG_LOAD)` and `bpf(BPF_MAP_CREATE)` return `EPERM`. |
| `CAP_PERFMON` | 38 | Attach BPF programs to perf events, tracepoints, kprobes, and raw tracepoints.  Without this, `perf_event_open()` and BPF link creation for tracing programs fail. |
| `CAP_SYS_ADMIN` | 21 | Mount bpffs (`/sys/fs/bpf`) and tracefs (`/sys/kernel/debug/tracing`), pin BPF objects to the filesystem, and perform other admin operations required by libbpf during program loading. |
| `CAP_NET_ADMIN` | 12 | Attach BPF programs to network hook points (TC ingress/egress, XDP).  Required for network-observability sensors. |

### Capabilities explicitly NOT granted

| Capability | Why excluded |
|-----------|-------------|
| `CAP_SYS_PTRACE` | The agent does not ptrace other processes.  Granting it would allow reading any process's memory. |
| `CAP_DAC_OVERRIDE` | The agent reads only its own state/runtime dirs and kernel virtual filesystems.  DAC override would let it bypass all file permission checks. |
| `CAP_SETUID` | The agent never changes its UID.  Granting it would allow privilege escalation. |
| `CAP_NET_RAW` | The agent uses BPF for network observability, not raw sockets. |
| `CAP_SYS_MODULE` | The agent loads BPF programs, not kernel modules. |

### sd_notify / watchdog integration

The unit uses `Type=notify` with `WatchdogSec=30s`.  The agent binary MUST
implement the sd_notify protocol:

1. **Startup**: send `READY=1` to `$NOTIFY_SOCKET` after initialization
   completes (BPF programs loaded, sockets bound).
2. **Watchdog**: send `WATCHDOG=1` at least every 15 s (half of
   `WatchdogSec`).  If systemd receives no ping within 30 s, it considers
   the service hung and restarts it.
3. **Stopping**: send `STOPPING=1` when beginning graceful shutdown.

In Rust, use the `sd-notify` crate:

```rust
// After initialization:
sd_notify::notify(false, &[sd_notify::NotifyState::Ready])?;

// In the main loop (every ~10 s):
sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog])?;
```

If the agent does not implement sd_notify, change `Type=notify` to
`Type=simple` and remove `WatchdogSec=30s` in the unit file.

## Hardening summary

| Directive | Effect |
|-----------|--------|
| `User=kernel-v1` / `Group=kernel-v1` | Runs as dedicated unprivileged user |
| `NoNewPrivileges=true` | Cannot gain privileges via setuid/setgid binaries |
| `ProtectSystem=strict` | `/usr`, `/boot`, `/efi` are read-only; only explicit `ReadWritePaths` are writable |
| `ProtectHome=true` | `/home`, `/root`, `/run/user` are inaccessible |
| `PrivateTmp=true` | Isolated `/tmp` and `/var/tmp` |
| `ProtectKernelTunables=true` | `/proc/sys`, `/sys` (except explicit paths) are read-only |
| `ProtectControlGroups=true` | cgroup hierarchy is read-only |
| `MemoryDenyWriteExecute=true` | Cannot create writable+executable mappings (blocks JIT shellcode) |
| `RestrictRealtime=true` | Cannot set realtime scheduling priority |
| `LockPersonality=true` | Cannot change execution domain (e.g., to 32-bit) |
| `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK` | Only these socket families allowed |
| `RestrictNamespaces=true` | Cannot create new namespaces |
| `RestrictSUIDSGID=true` | Cannot create setuid/setgid files |
| `SystemCallArchitectures=native` | Blocks non-native syscall ABIs |
| `ProtectClock=true` | Cannot set system clock |
| `ProtectKernelLogs=true` | Cannot read kernel log buffer |
| `ProtectKernelModules=true` | Cannot load/unload kernel modules |
| `UMask=0077` | New files are owner-only by default |

### Writable paths

| Path | Purpose |
|------|---------|
| `/sys/fs/bpf` | BPF filesystem — pinned maps and programs |
| `/sys/kernel/debug/tracing` | tracefs — tracepoint/kprobe attachment |
| `/var/lib/kernel-v1` | `StateDirectory` — persistent agent state |
| `/run/kernel-v1` | `RuntimeDirectory` — runtime sockets, pidfile |

## Auditing

### Verify the service is not running as root

```bash
systemctl show kernel-v1-agent --property=User,Group
# User=kernel-v1
# Group=kernel-v1
```

### Inspect effective capabilities of the running process

```bash
# Find the agent PID
PID=$(systemctl show kernel-v1-agent --property=MainPID --value)

# Decode capabilities
grep Cap /proc/${PID}/status
# CapInh: 0000000000000000
# CapPrm: 000000c000201000   ← only CAP_BPF+CAP_PERFMON+CAP_SYS_ADMIN+CAP_NET_ADMIN
# CapEff: 000000c000201000
# CapBnd: 000000c000201000   ← bounding set matches (nothing else can be acquired)
# CapAmb: 000000c000201000   ← ambient set (inherited across execve)

# Human-readable decode
capsh --decode=000000c000201000
# 0x000000c000201000=cap_net_admin,cap_sys_admin,cap_perfmon,cap_bpf
```

### Verify hardening with systemd-analyze

```bash
systemd-analyze security kernel-v1-agent
```

This prints an exposure score (0.0 = perfectly sandboxed, 10.0 = fully
exposed).  The four BPF capabilities raise the score modestly, but all
other hardening directives keep it well below the default.

### Audit the sysusers/tmpfiles configs

```bash
# Verify the user exists with nologin shell
getent passwd kernel-v1
# kernel-v1:x:990:990:kernel-v1 eBPF agent:/var/lib/kernel-v1:/usr/sbin/nologin

# Verify runtime directory ownership
ls -ld /run/kernel-v1
# drwxr-x--- 2 kernel-v1 kernel-v1 ...

# Verify state directory ownership
ls -ld /var/lib/kernel-v1
# drwx------ 2 kernel-v1 kernel-v1 ...
```

### Monitor service logs

```bash
journalctl -u kernel-v1-agent -f          # follow live
journalctl -u kernel-v1-agent --since "1 hour ago"  # recent
journalctl -u kernel-v1-agent -p err      # errors only
```

## Uninstall

```bash
sudo systemctl disable --now kernel-v1-agent
sudo rm /etc/systemd/system/kernel-v1-agent.service
sudo rm /usr/lib/tmpfiles.d/kernel-v1-agent.conf
sudo rm /usr/lib/sysusers.d/kernel-v1-agent.conf
sudo rm /usr/local/bin/kernel-v1-agent
sudo systemctl daemon-reload

# Optionally remove the user and its data:
sudo userdel -r kernel-v1
sudo groupdel kernel-v1 2>/dev/null || true
```
