# Kernel compatibility matrix

Status: **PASS 2/2 pinned Ubuntu rows** on 2026-11-14, with one known
raw-tracepoint limitation recorded (see
[Known limitation](#known-limitation-sched_process_exit-raw-tracepoint)).

This page records real compatibility evidence for the local-first recorder:
a static `ebpf-fleet` binary is booted and executed on pinned guest kernels
in the local KVM lab, and every measurement below comes from a real VM run
whose JSON evidence is checked into
`docs/verification/kernel-matrix/2026-11-14/`; the raw VM artifacts remain
on the lab host. Nothing here is a plan or a projection.

- Host: `massive`, x86_64, host kernel `7.3.3-1-cachyos`, 16 vCPUs,
  `/dev/kvm` usable without sudo.
- Tool under test: static-pie x86_64 `target/release/ebpf-fleet`,
  version `ebpf-fleet 0.1.0`, 130150664 bytes, sha256
  `4f38afb00ed353ec3a79199296de3d99f55e1289613d318141340443b7c3f225`
  (the guest copy is sha256-verified against this file for every row).
- Runner: [`scripts/vm/run-matrix.sh`](../../scripts/vm/run-matrix.sh)
  (boot, binary copy, `doctor`, `record`, `query`, `replay`, process-only
  probe, bundle export and teardown), built on
  [`scripts/vm/lab.sh`](../../scripts/vm/lab.sh).
- Checked-in evidence: `docs/verification/kernel-matrix/2026-11-14/`
  (`matrix-summary.json` plus one `<image>.json` per row). The raw VM
  artifacts (guest bundles, logs, per-check files) remain on the lab host
  under `target/vm/matrix/2026-11-14/`, which is gitignored.

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
`SHA256SUMS` manifest for the same dated build (the cached files re-hash to
the pinned values above).

## What one row does

For each image the runner:

1. verifies/downloads the pinned base image and boots a disposable KVM VM
   (`qemu-system-x86_64 -enable-kvm -cpu host`, no sudo, no libvirt,
   everything under `target/vm/`);
2. polls until cloud-init is `status: done` and `jq`, `tar` and
   passwordless sudo are available in the guest;
3. copies the static binary in with `scripts/vm/lab.sh copy`, sets it
   executable, and requires the guest sha256 to equal the host sha256;
4. runs `sudo -n /tmp/ebpf-fleet doctor --json` and requires exit 0 with
   the `kernel` and `btf` checks ok;
5. runs `sudo -n /tmp/ebpf-fleet record --for 8 --out /tmp/matrix.fleet`
   while a second SSH session runs a deterministic activity generator
   (process spawns and exits, `openat`/`read`/`creat`/`unlink` on
   `/tmp/matrix-probe/`);
6. runs `query` for kind counts and for the top `FileOpen` paths (the
   fixed probe path `/tmp/matrix-probe/created-by-matrix` must be decoded),
   then `replay` and validates the first JSON line;
7. runs a second, process-only record
   (`record --sensors process --for 4`) with the same activity to check
   whether the `sched_process_exit` raw tracepoint attached;
8. exports the bundle, writes the row JSON with all checks, and tears the
   VM down — also when the row fails.

A row passes only when every required check passes; measurement asserts are
"non-zero events", "process and file kinds present", "probe path decoded",
"replay line count matches the manifest" — not brittle exact counts.

## Exact commands

The devenv shell needs `--impure` on this host (`devenv.nix` reads the
current directory; the pure flake evaluation refuses it):

```bash
cd /home/mei/Documents/eBPF-runtime

# one-time image bootstrap (also done implicitly by the runner; cached after)
nix develop --impure --command scripts/vm/lab.sh bootstrap --image ubuntu-24.04
nix develop --impure --command scripts/vm/lab.sh bootstrap --image ubuntu-22.04

# the recorded matrix run
nix develop --impure --command scripts/vm/run-matrix.sh \
  --image ubuntu-24.04 --image ubuntu-22.04 --stamp 2026-11-14
```

The run finished with `MATRIX PASS: 2/2 rows` and wrote:

```
target/vm/matrix/2026-11-14/
  matrix-summary.json          # rows, host facts, pass/fail counts
  ubuntu-24.04.json            # row evidence (checks + measurements)
  ubuntu-22.04.json
  ubuntu-24.04/                # raw artifacts for the row
  ubuntu-22.04/
  activity.sh, guest-probe.sh  # generated guest helpers used by the rows
```

## Results

| Image | Booted kernel (`uname -r`) | OS | BTF size (bytes) | BTF sha256 | Events | Decode errors | `FileOpen` | `ProcessFork` | `ProcessExec` | `ProcessExit` | Replay lines | Bundle complete | Row |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `ubuntu-24.04` | `6.8.0-147-generic` | Ubuntu 24.04.5 LTS | 6103569 | `8c10e7e174e89c92f1d2708f12bb5268dc381e57e867397534c4e145348622e0` | 3492 | 0 | 2927 | 269 | 271 | **0** | 3492 | true | **PASS** |
| `ubuntu-22.04` | `5.15.0-203-generic` | Ubuntu 22.04.5 LTS | 5290474 | `36e118be1ee6c3ed13d4813d2e170252fb19d4120cf3940ada382bfe2e38d70c` | 3225 | 0 | 2663 | 267 | 270 | **0** | 3225 | true | **PASS** |

Both rows booted in 13 s and 18 s respectively (SSH ready), cloud-init was
done in 17 s and 31 s, and the full row (boot → records → queries → export
→ teardown) took 50 s and 71 s on this host with the images already cached.

### Per-check results

Each row has 23 checks: 20 required and 3 informational. For both images the
20 required checks are green:

`bootstrap`, `boot`, `cloud_init_ready`, `binary_upload`, `binary_runs`,
`doctor`, `record`, `activity`, `record_events`, `query_kinds`,
`file_open_paths`, `replay`, `process_probe`, `btf`, `kernel_series`,
`guest_packages`, `bundle_complete`, `probe_bundle_complete`,
`manifest_host_facts`, `bundle_export`.

Informational checks:

| Check | ubuntu-24.04 | ubuntu-22.04 | Meaning |
| --- | --- | --- | --- |
| `exit_tracepoint` | **false** | **false** | known `sched_process_exit` raw-tracepoint limitation, see below |
| `file_sensor_path` | true (`kprobe-no-bpf-lsm`) | true (`kprobe-no-bpf-lsm`) | file paths come from the kprobe/pt_regs fallback |
| `bundle_portable` | true | true | the host binary re-queried the guest-recorded bundle and got identical kind counts |

### Evidence details

- The bundle manifests mark `complete: true` and their `counts.events`
  match the record stderr line (`recorded <n> events (0 decode errors)`)
  for both the main bundle and the process-only probe bundle.
- The bundle's recorded host facts match the guest: `host.btf_sha256`
  equals the sha256 of `/sys/kernel/btf/vmlinux`, and `host.lsm` matches
  `/sys/kernel/security/lsm`.
- `replay` printed exactly one JSON line per event (3492 and 3225 lines),
  the first line is a valid `FileOpen` event, and bundle re-play through
  the host binary produced the same kind counts as the guest query.
- The exported bundles are
  `target/vm/matrix/2026-11-14/ubuntu-24.04/matrix.fleet.tar.gz` (420 KiB)
  and `.../ubuntu-22.04/matrix.fleet.tar.gz` (388 KiB); both extract and
  open locally.

## File sensor on kernels without BPF LSM

The pinned Ubuntu cloud kernels expose
`lsm=lockdown,capability,landlock,yama,apparmor` — there is no `bpf` LSM,
so the file sensor's `lsm/file_open` program cannot be the path source and
the kprobe fallback (`kprobe/__x64_sys_openat` and friends, decoding the
syscall argument through `pt_regs`) has to do the work. This was verified
explicitly on the 5.15 row (the primary requirement) and also on 6.8:

- `FileOpen` is the most frequent kind (2663 / 2927) with decoded paths and
  zero decode errors; the SQL path table contains entries such as
  `/etc/ld.so.cache`, `/lib/x86_64-linux-gnu/libc.so.6` and
  `/tmp/matrix-probe/created-by-matrix`.
- The deterministic activity marker is decoded on both rows:
  `grep 'matrix-probe/created-by-matrix' .../query-file-paths.txt` shows
  25 opens for both images (the scratch file appears 48 times, the probe
  directory 24 times).
- The row JSON records
  `"sensors": {"file_sensor_path": "kprobe-no-bpf-lsm",
  "security": {"lsm": "lockdown,capability,landlock,yama,apparmor"}}`.
- The replay stream's first line is a `FileOpen` with a concrete path,
  which also exercises the pack/replay path with real decoded paths.

## Known limitation: `sched_process_exit` raw tracepoint

The process sensor's `raw_tracepoint/sched_process_exit` program does not
attach on these Ubuntu kernels. It is the known Ubuntu 24.04 issue and it
also reproduces on the 5.15 LTS row — the limitation is therefore not
specific to 6.8 and must be treated as a current matrix-wide gap.

Observable evidence (both rows, same static binary):

- Main 8 s record: `ProcessFork` and `ProcessExec` are present, but
  `ProcessExit` is **0** even though the activity generator spawns and
  reaps short-lived processes throughout the window. `decode_errors` is 0,
  so this is not decoding loss.
- Process-only control record (`record --sensors process --for 4`,
  fresh bundle, same activity) reproduces it:

  | Image | Probe events | `ProcessFork` | `ProcessExec` | `ProcessExit` |
  | --- | --- | --- | --- | --- |
  | `ubuntu-24.04` | 218 | 109 | 109 | **0** |
  | `ubuntu-22.04` | 231 | 114 | 117 | **0** |

- Both probe bundles are complete (`complete: true`) and their manifest
  event counts match the record stderr, so the rest of the process sensor
  and the bundle pipeline are healthy.
- The row JSON records the result in
  `sensors.exit_tracepoint = {"attached": false, "evidence": "process-only
  probe: ProcessFork=..., ProcessExec=..., ProcessExit=0"}`; the row can
  still PASS because this is an informational check, not a required one.

Why it shows up as a missing kind rather than an error string: the loader
marks a sensor `degraded` when some programs attach and some fail, and the
`record` command only prints a warning for a fully `blocked` sensor. The
per-program error is visible in the loader coverage matrix (the
`bpf-loader` binary), not in the `ebpf-fleet record` CLI. The matrix runner
therefore classifies the limitation from the absent `ProcessExit` stream
plus the healthy `ProcessFork`/`ProcessExec` stream, and stores that
evidence explicitly instead of hiding it.

Impact: on the pinned Ubuntu kernels a bundle has no process-exit events
(no exit codes, no `ProcessExit` timeline); readers, rules and dashboards
must not assume `ProcessExit` exists. Everything else measured by the
matrix works. A fix or workaround for the attach path is out of scope for
this matrix round and is a recorded gap.

Reproduce the classification directly (guest or host against an exported
bundle):

```bash
./target/release/ebpf-fleet query \
  target/vm/matrix/2026-11-14/ubuntu-22.04/bundle/matrix.fleet \
  "select kind, count(*) as n from events group by kind order by kind"
# FileOpen | FileUnlink | ProcessExec | ProcessFork   (no ProcessExit)
```

## Artifacts

`target/vm/matrix/2026-11-14/<image>.json` is the row evidence file:

```bash
jq '.status, .kernel.release, .btf.sha256, .record, .sensors,
    .query.file_open_count, .query.probe_path_seen, .failures' \
  target/vm/matrix/2026-11-14/ubuntu-22.04.json
```

The per-row artifact directory keeps the raw inputs for that file:

```
target/vm/matrix/2026-11-14/ubuntu-22.04/
  doctor.json, doctor.err          # doctor --json from the guest
  record.err, record.out           # "recorded 3225 events (0 decode errors) ..."
  activity.out, activity.err       # deterministic activity generator
  query-kinds.txt                  # select kind, count(*) ... order by kind
  query-file-paths.txt             # top FileOpen paths (probe path included)
  replay.jsonl                    # full replayed event stream (one JSON per line)
  replay.err                      # "replayed 3225 events"
  probe-record.err                # process-only control record
  probe-query-kinds.txt           # ProcessFork/ProcessExec, no ProcessExit
  guest-info.txt                  # [uname] [os-release] [btf] [security]
                                  # [bundle] [probe-bundle] [dmesg]
  matrix.fleet.tar.gz             # exported guest bundle (zstd-free tar.gz)
  bundle/matrix.fleet/            # extracted bundle (manifest.json + parquet)
  host-query-kinds.txt            # host binary querying the guest bundle
  console.log, qemu.log           # serial console and QEMU log
  instance.json                   # lab instance metadata (port, pid, paths)
  bootstrap.log, up.log, copy.log, copy-helpers.log, export.log
  cloud-init-status.txt
  json-bad-values.log      # only if a writer fallback was needed (absent on success)
```

Two small caveats about the checked-in JSON evidence from this run:

- `artifacts.files` is a snapshot taken before teardown, so it lists
  `matrix.fleet.tar.gz` and the bundle but not the `console.log`,
  `qemu.log` and `instance.json` that teardown copies in afterwards; those
  files are present in the directory.
- the `notes` text says "reproduced on :" with an empty kernel placeholder
  because the note was emitted before the guest kernel string was parsed.
  `.kernel.release`, all measurement fields and all checks are unaffected;
  the runner now emits the note after parsing the guest facts.

## Runner behaviour and options

```bash
scripts/vm/run-matrix.sh --image <key> [--image <key> ...] [options]
  --all-pinned           every pinned image matching the host architecture
  --name-prefix <p>      instance name prefix (default: matrix)
  --record-seconds <n>   main record window (default: 8, minimum 4)
  --probe-seconds <n>    process-only probe window (default: 4, minimum 3)
  --boot-timeout <n>     SSH boot budget (default: 300)
  --binary <path>        static binary (default: target/release/ebpf-fleet)
  --stamp <stamp>        output directory name (default: UTC timestamp)
  --keep                 leave the VMs running for debugging
```

Fail-closed behaviour: unpinned/unknown images, an architecture mismatch, a
missing or non-static binary, missing `/dev/kvm`, missing host tools, an
existing output directory, a failed boot, a failed record/query/replay, a
bundle without the probe path, or a kernel release that does not match the
pinned kernel series all fail the run. A row failure still writes its JSON
evidence and still tears the VM down; the runner exits non-zero if any row
failed.

## Remaining matrix gaps

| Target | Kernel | Status | Exact blocker / next step |
| --- | --- | --- | --- |
| Debian 12 (`debian-12`) | 6.1 | not run | `images.json` entry is `status: placeholder` with `sha256: null`. Debian publishes only `SHA512SUMS`; the image must be downloaded, verified with `sha512sum -c`, then its sha256 recorded and the entry flipped to `pinned` + boot-validated. The lab refuses an unpinned image, so this row cannot run until that pinning step is done. |
| Debian 13 (`debian-13`) | 6.12 | not run | same sha512-to-sha256 pinning step as Debian 12. |
| Fedora 42 (`fedora-42`) | 6.14 | not run | unpinned; Fedora publishes a PGP-signed `CHECKSUM` file and Fedora 42 has moved to `archive.fedoraproject.org`, so pinning needs a key/URL decision first. |
| arm64 (`ubuntu-24.04-arm64`) | 6.8 | not run | hash is pinned, but the image is aarch64 and this host is x86_64; the lab never emulates, so a native aarch64 KVM host is required. |
| kernel < 5.15 | — | unsupported | project baseline is Linux 5.15+ with BTF; older kernels are out of scope. |
| `sched_process_exit` raw tracepoint | 6.8 and 5.15 | open limitation | reproduced on both pinned rows; needs an attach-path fix or fallback (e.g. a kprobe/tracepoint alternative) before exit events can be promised. |

Next concrete matrix step: pin Debian 12 (sha512 verify → sha256 record in
`scripts/vm/images.json` → `nix develop --impure --command
scripts/vm/run-matrix.sh --image debian-12`), then repeat for Debian 13 and
Fedora, and add an aarch64 host for the arm64 row.
