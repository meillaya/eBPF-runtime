# Kernel compatibility matrix

Status: **PASS 2/2 pinned Ubuntu rows** on 2026-11-14, including process
exit events on both kernels.

This page records real compatibility evidence for the local-first recorder:
a static `ebpf-fleet` binary is booted and executed on pinned guest kernels
in the local KVM lab, and every measurement below comes from a real VM run.
The compact JSON evidence is checked into
`docs/verification/kernel-matrix/2026-11-14b/`; the raw VM artifacts (guest
bundles, logs, per-check files) remain on the lab host under
`target/vm/matrix/2026-11-14b/`, which is gitignored.

- Host: `massive`, x86_64, host kernel `7.3.3-1-cachyos`, 16 vCPUs,
  `/dev/kvm` usable without sudo.
- Tool under test: static-pie x86_64 `target/release/ebpf-fleet`,
  version `ebpf-fleet 0.1.0`, 134104904 bytes, sha256
  `5f0b2517aba8ba26a1a7c3830f83aa3c5faa674f69453c921c9256612ead07e7`
  (the guest copy is sha256-verified against this file for every row).
- Runner: [`scripts/vm/run-matrix.sh`](../../scripts/vm/run-matrix.sh)
  (boot, binary copy, `doctor`, `record`, `query`, `replay`, process-only
  probe, bundle export, and teardown), built on
  [`scripts/vm/lab.sh`](../../scripts/vm/lab.sh).

## Pinned images

Both images are immutable dated Ubuntu cloud builds whose sha256 values are
pinned in [`scripts/vm/images.json`](../../scripts/vm/images.json). The lab
re-verifies the cached file against the pin before every boot and fails
closed on a mismatch.

| Image key | Guest OS | Kernel series | Immutable build | Image sha256 | Size (bytes) |
| --- | --- | --- | --- | --- | --- |
| `ubuntu-24.04` | Ubuntu 24.04.5 LTS (noble) | 6.8 | `releases/24.04/release-20261017/` | `04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94` | 621284352 |
| `ubuntu-22.04` | Ubuntu 22.04.5 LTS (jammy) | 5.15 | `releases/22.04/release-20261106/` | `f77bc6d59cb8deaa9657095736b5f5003f7705b47055f01823459715c967de6a` | 730617344 |

Source URLs:

- `https://cloud-images.ubuntu.com/releases/24.04/release-20261017/ubuntu-24.04-server-cloudimg-amd64.img`
- `https://cloud-images.ubuntu.com/releases/22.04/release-20261106/ubuntu-22.04-server-cloudimg-amd64.img`

Both were downloaded over HTTPS and checked against the vendor
`SHA256SUMS` manifest for the same dated build.

## What one row does

For each image the runner:

1. verifies/downloads the pinned base image and boots a disposable KVM VM
   (`qemu-system-x86_64 -enable-kvm -cpu host`, no sudo, no libvirt,
   everything under `target/vm/`);
2. polls until cloud-init is `status: done` and `jq`, `tar`, and
   passwordless sudo are available in the guest;
3. copies the static binary with `scripts/vm/lab.sh copy`, sets it
   executable, and requires the guest sha256 to equal the host sha256;
4. runs `sudo -n /tmp/ebpf-fleet doctor --json` and requires exit 0 with
   the `kernel` and `btf` checks ok;
5. runs `sudo -n /tmp/ebpf-fleet record --for 8 --out /tmp/matrix.fleet`
   while a second SSH session runs a deterministic activity generator
   (process spawns/exits and file operations under `/tmp/matrix-probe/`);
6. runs `query` for kind counts and top `FileOpen` paths, then `replay` and
   validates the first JSON line;
7. runs a second, process-only record (`--sensors process --for 4`) and
   checks that fork, exec, and exit are all observed;
8. exports the bundle, writes the row JSON with all checks, and tears the
   VM down — also when the row fails.

A row passes only when every required check passes; measurement assertions
are non-zero events, expected process/file kinds, decoded probe paths, and
replay line counts matching the manifest, not brittle exact counts.

## Exact commands

```bash
cd /home/mei/Documents/eBPF-runtime

# one-time image bootstrap (also done implicitly by the runner; cached after)
nix develop --impure --command scripts/vm/lab.sh bootstrap --image ubuntu-24.04
nix develop --impure --command scripts/vm/lab.sh bootstrap --image ubuntu-22.04

# the recorded matrix run
nix develop --impure --command scripts/vm/run-matrix.sh \
  --image ubuntu-24.04 --image ubuntu-22.04 --stamp 2026-11-14b
```

The run finished with `MATRIX PASS: 2/2 rows` and wrote:

```text
target/vm/matrix/2026-11-14b/
  matrix-summary.json          # rows, host facts, pass/fail counts
  ubuntu-24.04.json            # row evidence (checks + measurements)
  ubuntu-22.04.json
  ubuntu-24.04/                # raw artifacts for the row
  ubuntu-22.04/
  activity.sh, guest-probe.sh  # generated guest helpers used by the rows
```

## Results

| Image | Booted kernel (`uname -r`) | OS | BTF size (bytes) | BTF sha256 | Events | Decode errors | `FileOpen` | `FileUnlink` | `ProcessFork` | `ProcessExec` | `ProcessExit` | Replay lines | Bundle complete | Row |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `ubuntu-24.04` | `6.8.0-147-generic` | Ubuntu 24.04.5 LTS | 6103569 | `8c10e7e174e89c92f1d2708f12bb5268dc381e57e867397534c4e145348622e0` | 3690 | 0 | 2858 | 25 | 268 | 271 | 268 | 3690 | true | **PASS** |
| `ubuntu-22.04` | `5.15.0-203-generic` | Ubuntu 22.04.5 LTS | 5290474 | `36e118be1ee6c3ed13d4813d2e170252fb19d4120cf3940ada382bfe2e38d70c` | 3388 | 0 | 2585 | 24 | 258 | 261 | 260 | 3388 | true | **PASS** |

Process-only probe counts:

| Image | Probe events | `ProcessFork` | `ProcessExec` | `ProcessExit` |
| --- | --- | --- | --- | --- |
| `ubuntu-24.04` | 348 | 115 | 118 | 115 |
| `ubuntu-22.04` | 372 | 123 | 126 | 123 |

## Process exit tracepoint fix

The process sensor previously used `raw_tracepoint/sched_process_exit`.
That attach path failed on both Ubuntu kernels, producing `ProcessFork` and
`ProcessExec` but zero `ProcessExit` events. The sensor now attaches
`tracepoint/sched/sched_process_exit`, derives the thread/process
distinction from `pid != tgid`, and still reads the exit code from
`current->exit_code`. `ProcessExit` is present on both rows and the
process-only probe reports `sensors.exit_tracepoint.attached = true`.

The regular tracepoint context does not expose `group_dead`; the event keeps
the thread flag and exit code but not that raw-tracepoint argument. This is
a deliberate, documented tradeoff.

## File sensor on kernels without BPF LSM

Both pinned Ubuntu cloud kernels expose
`lsm=lockdown,capability,landlock,yama,apparmor` — there is no `bpf` LSM,
so the file sensor's `lsm/file_open` program cannot be the path source and
the kprobe fallback (`kprobe/__x64_sys_openat` and friends, decoding the
syscall argument through `pt_regs`) does the work. This was verified on the
5.15 row (the primary requirement) and on 6.8:

- `FileOpen` is the most frequent kind (2858 / 2585) with decoded paths and
  zero decode errors; the SQL path table contains entries such as
  `/etc/ld.so.cache`, `/lib/x86_64-linux-gnu/libc.so.6`, and
  `/tmp/matrix-probe/created-by-matrix`.
- The deterministic activity marker is decoded on both rows:
  `grep 'matrix-probe/created-by-matrix' .../query-file-paths.txt` shows 25
  opens for both images.
- The row JSON records
  `"sensors": {"file_sensor_path": "kprobe-no-bpf-lsm",
  "security": {"lsm": "lockdown,capability,landlock,yama,apparmor"}}`.
- The replay stream's first line is a `FileOpen` with a concrete path.

## Evidence details

- Bundle manifests mark `complete: true`; `counts.events` matches the
  record stderr line for both the main and process-only bundles.
- The bundle's recorded host facts match the guest: `host.btf_sha256`
  equals the sha256 of `/sys/kernel/btf/vmlinux`, and `host.lsm` matches
  `/sys/kernel/security/lsm`.
- `replay` printed exactly one JSON line per event (3690 and 3388 lines),
  and the first line is a valid event.
- The host binary re-queried exported guest bundles and got the same kind
  counts.
- The compact row JSON is checked in under
  `docs/verification/kernel-matrix/2026-11-14b/`; raw artifacts remain under
  `target/vm/matrix/2026-11-14b/`.

Two small caveats about the row JSON:

- `artifacts.files` is a pre-teardown snapshot, so it omits the console,
  QEMU log, and instance metadata copied during teardown; those files exist
  in the raw artifact directory.
- The runner writes its informational note before the guest facts parse;
  `.kernel.release`, measurements, and checks are unaffected.

## Remaining matrix gaps

| Target | Kernel | Status | Exact blocker / next step |
| --- | --- | --- | --- |
| Debian 12 (`debian-12`) | 6.1 | not run | `images.json` entry is `status: placeholder` with `sha256: null`. Debian publishes only `SHA512SUMS`; download, verify with `sha512sum -c`, record sha256, flip to `pinned`, then run the matrix. |
| Debian 13 (`debian-13`) | 6.12 | not run | same SHA-512-to-SHA-256 pinning step as Debian 12. |
| Fedora 42 (`fedora-42`) | 6.14 | not run | unpinned; Fedora publishes a PGP-signed `CHECKSUM` file and archive URLs, so pinning needs a key/URL decision. |
| arm64 (`ubuntu-24.04-arm64`) | 6.8 | not run | hash is pinned, but this host is x86_64; the lab does not emulate. A native aarch64 KVM host is required. |
| kernel < 5.15 | — | unsupported | project baseline is Linux 5.15+ with BTF. |

Next matrix step: pin Debian 12 and run the same runner, then Debian 13,
Fedora 42, and add an aarch64 host for the arm64 row.
