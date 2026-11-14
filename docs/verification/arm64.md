# arm64 build and functional verification

Status: **cross-build verified and functional row PASS under QEMU TCG system
emulation for 0.3.0** on 2026-11-14. This is a real aarch64 Ubuntu kernel executing
the real aarch64 static binary, but the CPU is emulated: the row is a
**functional smoke only, not a performance measurement**, and it is not a
substitute for a native aarch64 KVM row.

The 0.3 release artifacts are `ebpf-fleet-x86_64` (sha256
`60db4e2f374d07a5ba473e255bef022d8b1eaa446d561104146d558d1c74040d`)
and `ebpf-fleet-aarch64` (sha256
`d9af296d82d2504f029021267965c1397b91f31bdf7d9fc3edff679d88458381`). This page records the aarch64 build path, the
artifact identity, and the functional evidence. The x86_64 artifact keeps
its static-pie release path and the existing kernel matrix.

## Host and tools

| Field | Value |
| --- | --- |
| Host | `massive`, x86_64, Linux `7.3.3-1-cachyos` |
| CPUs / RAM | 16 vCPUs / ~62 GiB |
| KVM | `/dev/kvm` present (`crw-rw-rw-`), used for x86_64 rows only |
| QEMU | QEMU 10.2.2 from the project devenv shell (`qemu-system-aarch64`) |
| AArch64 firmware | `target/vm/firmware/AAVMF_CODE.fd`, sha256 `49e6ca29c0f93037799e8d8ceca8aef70a1a0a6e90912dfbf4cd6acfd1cdf920`, extracted from the Ubuntu `qemu-efi-aarch64` 2024.02-2 package |
| Rust | `rustc 1.95.0` (rust-overlay toolchain named by `rust-toolchain.toml`) |
| Cross C toolchain | nixpkgs `aarch64-unknown-linux-gnu` gcc 15.2.0 |
| Static libc | nixpkgs `glibc-aarch64-unknown-linux-gnu-2.42-51-static` |

There is no native aarch64 KVM host for this project. A native aarch64 host
would take the native branch of `scripts/build-static.sh --arch aarch64`
and `scripts/vm/lab.sh --image ubuntu-24.04-arm64`; neither path needs the
cross toolchain or the TCG firmware described here.

## Cross build

`scripts/build-static.sh --arch aarch64` on an x86_64 host is a real cross
build: aarch64 Rust standard library, aarch64 gcc/binutils, and aarch64
static glibc, all evaluated from the flake inputs pinned in `flake.lock`.

The BPF sensors are the special case. `bpf-build` always compiles CO-RE
objects against the kernel BTF at `/sys/kernel/btf/vmlinux`, and on an
x86_64 host that file describes x86_64 types. The arm64 sensor code reads
`struct pt_regs` fields that only exist in the arm64 BTF, so the build must
see an arm64 kernel BTF. The script resolves `--btf` /
`EBPF_FLEET_ARM64_BTF` (or `target/cross/arm64-vmlinux.btf`), checks the raw
BTF magic (`9feb0100`), and bind-mounts the blob read-only over
`/sys/kernel/btf/vmlinux` inside an unprivileged user+mount namespace for
the duration of the cargo build. The host `/sys` is not modified and no
sudo is used. A private user+mount namespace is required; hosts that
disable unprivileged user namespaces must build on a native aarch64
machine.

The BTF used here is exact, not a lookalike: it is the `.BTF` blob from the
`linux-image-6.8.0-147-generic` arm64 kernel package's decompressed
`vmlinux`, and its SHA-256 is byte-for-byte the guest kernel's
`/sys/kernel/btf/vmlinux`:

```
arm64-vmlinux.btf  6975252 bytes
sha256 ff35ff5afb91dfb3a1cb6db29a417a39f4f598c9ebfba75186592d4a58a1d277
```

Commands and exact build output (a cold cross build is ~6-7 minutes;
subsequent builds of an unchanged tree are cached):

```bash
scripts/build-static.sh --arch aarch64 --btf target/cross/arm64-vmlinux.btf
```

```
build-static: cross build for aarch64 on x86_64
build-static: arm64 BTF: .../target/cross/arm64-vmlinux.btf sha256 ff35ff5afb91dfb3a1cb6db29a417a39f4f598c9ebfba75186592d4a58a1d277
build-static: cross toolchain channel: rust 1.95.0
build-static: cross toolchain: /nix/store/...-ebpf-fleet-aarch64-cross-toolchain
    Finished `release` profile [optimized] target(s) in 6m 53s
build-static: embedded BPF sensors: name: "process", arch: "arm64" name: "file", arch: "arm64"
build-static: arm64 BPF sensor object: ELF 64-bit LSB relocatable, eBPF, version 1 (SYSV), with debug_info, not stripped
build-static: verified target/aarch64-unknown-linux-gnu/release/ebpf-fleet: aarch64 static, ELF 64-bit LSB executable, ARM aarch64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.10.0, stripped, 115M
build-static: asset target/release/ebpf-fleet-aarch64 (115M)
d9af296d82d2504f029021267965c1397b91f31bdf7d9fc3edff679d88458381  ebpf-fleet-aarch64
```

The script proves the embedded sensors are arm64 by reading the generated
`bpf-loader` table under
`target/aarch64-unknown-linux-gnu/release/build/bpf-loader-*/out/embedded_artifacts.rs`
and requiring `arch: "arm64"` for every sensor. It deliberately does not
trust the shared `target/bpf-out/bpf-build.manifest.json`, because that
directory is shared with native x86_64 builds in the same workspace.

Independent checks on the published asset:

```bash
file target/release/ebpf-fleet-aarch64
# ELF 64-bit LSB executable, ARM aarch64, version 1 (GNU/Linux),
# statically linked, for GNU/Linux 3.10.0, stripped
readelf -h target/release/ebpf-fleet-aarch64 | grep Machine
# Machine: AArch64
readelf -d target/release/ebpf-fleet-aarch64 | grep -c NEEDED   # 0
readelf -l target/release/ebpf-fleet-aarch64 | grep -c INTERP   # 0
```

| Field | Value |
| --- | --- |
| Asset | `target/release/ebpf-fleet-aarch64` |
| Size | 120855168 bytes (116 MiB) |
| SHA-256 | `d9af296d82d2504f029021267965c1397b91f31bdf7d9fc3edff679d88458381` |
| ELF | 64-bit AArch64, `ET_EXEC`, statically linked, no `PT_INTERP`, no `NEEDED` |
| Version string | `ebpf-fleet 0.3.0` (workspace version at build time) |
| qemu-user smoke | `qemu-aarch64 target/release/ebpf-fleet-aarch64 --version` → `ebpf-fleet 0.3.0` |

The aarch64 cross link is a plain static executable (`ET_EXEC`), not
static-PIE; the x86_64 native path still produces `static-pie`. Both are
fully static with no runtime interpreter or libc dependency. The
functional row below executes this exact artifact inside the arm64 guest.

Build provenance note: the arm64 sensor compile needs the arm64 BTF work in
this branch. The committed `bpf/sensors/file.bpf.c` defined
`struct user_pt_regs` locally while the arm64 kernel BTF (`vmlinux.h`)
already provides it, so the arm64 build failed with
`error: redefinition of 'user_pt_regs'`. The same failure hits a native
aarch64 build; the unused local definition was removed in `bpf/` (by the
stack-capture owner) and this cross build proves the arm64 sensor path now
compiles. Sensor sources at build time:

```
bpf/sensors/file.bpf.c     sha256 7d0411b7b78ff41ca47280805e855ccf763916bf4d62639ad1ba3372b1fed163
bpf/sensors/process.bpf.c  sha256 7e52d33e0ce3d9cb4f313edd5ad223c980cf0f0f1003d674c14f352b0b8fbd4d
bpf/include/event_abi.h    sha256 7778abb845e4263a8c13bec41e6c23fb1318da129a1d4dd0a1f6bb10e56ed2c2
Cargo.lock                 sha256 227fd4a5ddc5b50fd32076b09a3bec09edc1219603bd13aefd10af9c1821baec
```

## Functional row (QEMU TCG)

The build can only be *proven* by executing on an aarch64 kernel, so
`scripts/vm/run-arm64.sh` boots the pinned arm64 Ubuntu cloud image under
QEMU TCG, copies `ebpf-fleet-aarch64` into the guest over the lab SSH
path, and runs the vertical slice of the x86_64 kernel matrix:

1. `--version` as the unprivileged `fleet` user.
2. `doctor --json` as root; requires exit 0 with the `kernel` and `btf`
   checks ok.
3. `record --for 8 --out /tmp/arm64.fleet` as root while a deterministic
   activity generator creates process and file events over a second SSH
   connection.
4. `query` for kind counts and for the `FileOpen` top paths; requires a
   positive `FileOpen` count and the deterministic probe path
   `/tmp/arm64-probe/created-by-arm64` to decode (from the SQL table or,
   when it does not fit the 25-row window, from the full replay stream).
5. `replay` to JSONL; requires exit 0, a valid first line, and exactly one
   output line per recorded event.

The guest runs the pinned image
`ubuntu-24.04-server-cloudimg-arm64.img`, 616522752 bytes, sha256
`50e24e1fb79e89116e939d90aa7738f7af48c442fa1bc2510131e0b39c50348e`,
from the immutable Ubuntu build `release-20261017`.

```bash
nix develop --impure --command scripts/vm/run-arm64.sh
# -> target/vm/arm64/2026-11-14-0.3.0/row.json
# -> target/vm/arm64/2026-11-14-0.3.0/row.txt
```

Result: **ARM64 FUNCTIONAL ROW PASS** — all 14 required checks passed
(14/14), total wall time 227 s.

| Check | Result |
| --- | --- |
| image pin verified before boot | PASS (sha256 `50e24e1f…`) |
| boot to SSH (QEMU TCG) | PASS, 119 s (900 s budget) |
| cloud-init (lean seed) | PASS, 32 s |
| guest `uname -m` | `aarch64` |
| guest `/sys/kernel/btf/vmlinux` | present, 6975252 bytes, sha256 `ff35ff5a…` |
| binary upload sha256 | guest == host (`d9af296d…`), PASS |
| `--version` | `ebpf-fleet 0.3.0` |
| `doctor --json` | exit 0; kernel ok, btf ok, all 8 checks ok |
| `record --for 8` | exit 0, **3059 events**, **0 decode errors** |
| `query` kind counts | `{"FileOpen":2468,"FileUnlink":18,"ProcessExec":193,"ProcessExit":190,"ProcessFork":190}` |
| `FileOpen` paths | 2468; deterministic probe path `/tmp/arm64-probe/created-by-arm64` decoded (verified in the replay JSONL stream) |
| `replay` | exit 0, **3059 lines** == recorded events, first kind `ProcessFork`, valid JSONL |

Guest facts:

- `uname -a`: `Linux arm64-tcg 6.8.0-147-generic #147-Ubuntu SMP
  PREEMPT_DYNAMIC Thu Sep 24 11:39:52 UTC 2026 aarch64 aarch64 aarch64
  GNU/Linux`
- OS: Ubuntu 24.04.5 LTS.
- LSM list: `lockdown,capability,landlock,yama,apparmor2` — no `bpf` LSM
  on this kernel, so the file sensor used the **kprobe/`pt_regs`
  syscall-argument fallback**. The decoded `FileOpen` paths (for example
  `/lib/aarch64-linux-gnu/libc.so.6`) and the deterministic probe path
  prove the arm64 register layout path works, which is the code path the
  removed duplicate `user_pt_regs` definition was about.
- `doctor` reports `unprivileged_bpf_disabled=2`,
  `lockdown=[none] integrity confidentiality`, `btf_sha256=ff35ff5a…`.

The complete raw run stays under
`target/vm/arm64/2026-11-14-0.3.0/` (gitignored): `row.json`, `row.txt`,
`instance.json`, `console.log`, the guest fact files, `doctor.json`,
`record.err`, `query-kinds.txt`, `query-file-paths.txt`, `replay.jsonl`,
`up.log`, `bootstrap.log` and `copy.log`.

## What this proves and what it does not

Proves:

- the aarch64 release artifact is a static AArch64 ELF that runs on a real
  aarch64 Ubuntu 24.04 kernel whose BTF the cross build used;
- the BPF sensors built for arm64 load, attach, and decode events on that
  kernel (record/query/replay with decoded `FileOpen` paths, zero decode
  errors, and the stack-capture fields present in this build);
- the TCG lab path and the pinned arm64 image work end to end (boot,
  copy, execute, record/query/replay, teardown);
- `scripts/install.sh` maps `uname -m` `aarch64` to the
  `ebpf-fleet-aarch64` asset, verifies its SHA-256, and installs it as
  `ebpf-fleet` (selection tested here with a stand-in binary; the real
  aarch64 artifact was executed in the guest, not on the x86 host);
- an arm64 sensor build compiles against arm64 kernel BTF — the missing
  piece that made arm64 impossible before 0.3.

Does not prove (explicit non-claims):

- any performance characteristic of arm64. TCG emulation is not a
  performance measurement; no arm64 latency/throughput number is claimed.
- a native aarch64 KVM row. This host has no aarch64 KVM; every artifact
  records `emulated: true` and `accelerator: tcg`.
- that the GitHub release matrix has run. `.github/workflows/release.yml`
  builds aarch64 **natively** on `ubuntu-24.04-arm` (GitHub-hosted arm64
  runner for public repositories); no arm64 release has been published from
  it yet.
- that the installer's *keyless* cosign verification was exercised against
  a published aarch64 asset. Locally, the aarch64 asset selection,
  checksum verification, unsupported-arch failure, and checksum-mismatch
  failure were tested, and the keyless path was tested against the x86_64
  release-shape fixture (it rejected a bogus bundle, as intended).

## Reproduce

See [docs/runbooks/vm-lab.md](../runbooks/vm-lab.md#arm64-build-and-tcg-functional-row)
for the AArch64 firmware setup, the BTF extraction, the cross build, and
the runner options. A first boot under TCG takes one to four minutes; the
runner defaults to a 900 s boot budget.
