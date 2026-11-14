# Kernel compatibility matrix

Status: **PASS 4/4 pinned x86_64 rows** on 2026-11-14 (Ubuntu 24.04/22.04,
Debian 12/13), including process exit events, using the 0.2.0 release binary.

This page records real compatibility evidence for the local-first recorder:
a static `ebpf-fleet` binary is booted and executed on pinned guest kernels
in the local KVM lab, and every measurement below comes from a real VM run.
The compact JSON evidence is checked into
`docs/verification/kernel-matrix/2026-11-14e/`; the raw VM artifacts remain
on the lab host under `target/vm/matrix/2026-11-14e/`, which is gitignored.

- Host: `massive`, x86_64, host kernel `7.3.3-1-cachyos`, 16 vCPUs,
  `/dev/kvm` usable without sudo.
- Tool under test: static-pie x86_64 `target/release/ebpf-fleet`,
  version `ebpf-fleet 0.2.0`, 134194760 bytes, sha256
  `bc48014367de000b0557177e03f4a6bdd057202ce2c00527009c631536f4b345`
  (the guest copy is sha256-verified against this file for every row).
- Runner: [`scripts/vm/run-matrix.sh`](../../scripts/vm/run-matrix.sh)
  (boot, binary copy, `doctor`, `record`, `query`, `replay`, process-only
  probe, bundle export, and teardown), built on
  [`scripts/vm/lab.sh`](../../scripts/vm/lab.sh).

## Pinned images

All four rows use immutable dated cloud builds whose SHA-256 values are
pinned in [`scripts/vm/images.json`](../../scripts/vm/images.json). The lab
re-verifies the cached file against the pin before every boot and fails
closed on a mismatch.

| Image key | Guest OS | Kernel series | Immutable build | Image sha256 | Size (bytes) |
| --- | --- | --- | --- | --- | --- |
| `ubuntu-24.04` | Ubuntu 24.04.5 LTS | 6.8 | `releases/24.04/release-20261017/` | `04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94` | 621284352 |
| `ubuntu-22.04` | Ubuntu 22.04.5 LTS | 5.15 | `releases/22.04/release-20261106/` | `f77bc6d59cb8deaa9657095736b5f5003f7705b47055f01823459715c967de6a` | 730617344 |
| `debian-12` | Debian 12 bookworm | 6.1 | `bookworm/20261112-2660/` | `4427c82a9345c93fbc96b3bffefacc6db5e024fcdeb684e01d65112687245063` | 451543040 |
| `debian-13` | Debian 13 trixie | 6.12 | `trixie/20261111-2659/` | `2f07a725b9370b94a9d7d7e8d68e7d424bc6096f7ccb2dbdaad5f203e6244d9b` | 436928512 |

Ubuntu images were checked against the vendor `SHA256SUMS`. Debian images
were checked against the immutable build's `SHA512SUMS` (`sha512sum -c`) and
their verified files were then hashed with SHA-256 for the pin.

Fedora 42 and Ubuntu 24.04 arm64 are pinned in `images.json` but not yet
boot-validated; see [Remaining gaps](#remaining-gaps).

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

A row passes only when every required check passes; assertions are non-zero
events, expected process/file kinds, decoded probe paths, and replay line
counts matching the manifest, not brittle exact counts.

## Exact commands

```bash
cd /home/mei/Documents/eBPF-runtime

# one-time bootstrap (cached after)
nix develop --impure --command scripts/vm/lab.sh bootstrap --image ubuntu-24.04
nix develop --impure --command scripts/vm/lab.sh bootstrap --image ubuntu-22.04
nix develop --impure --command scripts/vm/lab.sh bootstrap --image debian-12
nix develop --impure --command scripts/vm/lab.sh bootstrap --image debian-13

# the unified matrix run
nix develop --impure --command scripts/vm/run-matrix.sh \
  --image ubuntu-24.04 --image ubuntu-22.04 \
  --image debian-12 --image debian-13 --stamp 2026-11-14e
```

The run finished with `MATRIX PASS: 4/4 rows` and wrote:

```text
target/vm/matrix/2026-11-14e/
  matrix-summary.json          # rows, host facts, pass/fail counts
  ubuntu-24.04.json            # row evidence (checks + measurements)
  ubuntu-22.04.json
  debian-12.json
  debian-13.json
  ubuntu-24.04/                # raw artifacts for the row
  ubuntu-22.04/
  debian-12/
  debian-13/
  activity.sh, guest-probe.sh  # generated guest helpers used by the rows
```

## Results

| Image | Booted kernel (`uname -r`) | OS | BTF size (bytes) | Events | Decode errors | `FileOpen` | `FileUnlink` | `ProcessFork` | `ProcessExec` | `ProcessExit` | Replay lines | Bundle complete | Row |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `ubuntu-24.04` | `6.8.0-147-generic` | Ubuntu 24.04.5 LTS | 6103569 | 3445 | 0 | 2693 | 22 | 242 | 244 | 244 | 3445 | true | **PASS** |
| `ubuntu-22.04` | `5.15.0-203-generic` | Ubuntu 22.04.5 LTS | 5290474 | 3095 | 0 | 2375 | 21 | 231 | 234 | 234 | 3095 | true | **PASS** |
| `debian-12` | `6.1.0-54-amd64` | Debian GNU/Linux 12 | 4355537 | 2108 | 0 | 1481 | 22 | 201 | 203 | 201 | 2108 | true | **PASS** |
| `debian-13` | `6.12.116+deb13-amd64` | Debian GNU/Linux 13 | 4956583 | 2368 | 0 | 1725 | 22 | 207 | 207 | 207 | 2368 | true | **PASS** |

BTF SHA-256 values:

- Ubuntu 24.04: `8c10e7e174e89c92f1d2708f12bb5268dc381e57e867397534c4e145348622e0`
- Ubuntu 22.04: `36e118be1ee6c3ed13d4813d2e170252fb19d4120cf3940ada382bfe2e38d70c`
- Debian 12: `8f4d6b553aecc543afe0b987880b05e16c68169fbd9fcf38cc6dc378667d1f16`
- Debian 13: `db58ed1601b73bb4e642cab8bc87126048f0446bab1aca206a4a24b04e478a7a`

Process-only probe counts:

| Image | Probe events | `ProcessFork` | `ProcessExec` | `ProcessExit` |
| --- | --- | --- | --- | --- |
| `ubuntu-24.04` | 301 | 100 | 100 | 101 |
| `ubuntu-22.04` | 377 | 125 | 126 | 126 |
| `debian-12` | 254 | 84 | 86 | 84 |
| `debian-13` | 319 | 106 | 106 | 107 |

### Per-check results

Each row writes required and informational checks. The required checks
include bootstrap, boot, cloud-init readiness, binary upload/runs, doctor,
record, activity, event counts, kind query, FileOpen paths, replay, process
probe, BTF, kernel series, bundle completeness, manifest host facts, and
bundle export. All required checks are green on all four rows. The
`exit_tracepoint` informational check is **true** on all four:

| Check | Ubuntu 24.04 | Ubuntu 22.04 | Debian 12 | Debian 13 |
| --- | --- | --- | --- | --- |
| `exit_tracepoint` | true | true | true | true |
| `file_sensor_path` | `kprobe-no-bpf-lsm` | `kprobe-no-bpf-lsm` | `lsm` | `lsm` |

## Process exit events

The process sensor now attaches `tracepoint/sched/sched_process_exit`. The
previous raw-tracepoint attach path failed on the Ubuntu kernels and produced
zero `ProcessExit` events. The regular tracepoint is present on all four
rows, including the process-only probes above. The context does not expose
`group_dead`, so the event keeps the thread flag and exit code rather than
that raw argument.

## File sensor paths

- Ubuntu cloud kernels expose no `bpf` LSM
  (`lockdown,capability,landlock,yama,apparmor`), so FileOpen paths come from
  the kprobe fallback that decodes syscall arguments through `pt_regs` and
  covers `openat` as well as `openat2`.
- Debian 12/13 include `bpf` in the LSM list and use the LSM `file_open`
  path source. On those kernels the loader skips the syscall-entry open
  fallback, so successful opens are recorded **once** rather than once by
  both the LSM and kprobe programs.
- Every row decodes the deterministic `/tmp/matrix-probe/created-by-matrix`
  path exactly once per activity loop, with a non-zero `FileOpen` count and
  zero decode errors.
- The replay stream's first line is a valid event with a decoded path.

## Evidence details

- Bundle manifests mark `complete: true`; `counts.events` matches the
  record stderr line for both the main and process-only bundles.
- The bundle's recorded host facts match the guest: `host.btf_sha256`
  equals the sha256 of `/sys/kernel/btf/vmlinux`, and `host.lsm` matches
  `/sys/kernel/security/lsm`.
- `replay` printed exactly one JSON line per event (3445, 3095, 2108, 2368),
  and the first line is valid.
- The host binary re-queried exported guest bundles and got the same kind
  counts.
- Compact row JSON is checked in under
  `docs/verification/kernel-matrix/2026-11-14e/`; raw artifacts remain under
  `target/vm/matrix/2026-11-14e/`.

## Remaining gaps

| Target | Kernel | Status | Exact blocker / next step |
| --- | --- | --- | --- |
| Fedora 42 (`fedora-42`) | 6.14 | pinned, not run | The image is pinned in `images.json` but not boot-validated. Run `scripts/vm/lab.sh bootstrap --image fedora-42`, verify the guest, then run one matrix row. |
| arm64 (`ubuntu-24.04-arm64`) | 6.8 | pinned, not run | Hash is pinned, but this host is x86_64; the lab does not emulate. A native aarch64 KVM host is required. |
| kernel < 5.15 | — | unsupported | Project baseline is Linux 5.15+ with BTF. |

The 4/4 x86_64 matrix is the release gate for the local recorder. Fedora and
arm64 are documented follow-ups, not claims that the current evidence proves.
