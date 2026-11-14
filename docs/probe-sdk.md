<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# C probe SDK and verifier diagnostics (0.2)

Status: first 0.2 slice, library plus the `ebpf-fleet probe` CLI. The
`probe` crate and CLI build, verify, and explain a hand-written C probe. It is
**not** a DSL, a compiler, or a loader. Privileged verifier acceptance is
proven by the checked-in VM evidence;
see [probe-sdk-verify.md](verification/probe-sdk-verify.md).

This page is the contract for:

- [`sdk/include/fleet_probe.h`](../sdk/include/fleet_probe.h) — the C SDK header;
- [`sdk/examples/hello_probe.bpf.c`](../sdk/examples/hello_probe.bpf.c) — the
  buildable example probe;
- [`crates/probe`](../crates/probe) — `build`, `verify`, and `explain`.

## What this slice is, and what it is not

| It is | It is not |
| --- | --- |
| A documented header with one fixed event envelope and reserve/submit helpers | A probe DSL or probe language |
| A build wrapper around the pinned clang 19 + the `bpf-build` `vmlinux.h` | A userspace compiler or code generator |
| A libbpf-rs load check with captured verifier diagnostics | A loader/attacher for the running agent |
| A pure verifier-log explainer that runs unprivileged | Kernel acceptance that can be claimed without privileges |

The example probe is a diagnostic fixture. It is not embedded in the runtime,
the runtime does not decode SDK events, and no sensor behavior changed.

## The event contract (version 1)

Every SDK probe emits one record per event through one BPF ring buffer. The
record is a fixed 48-byte header followed by `payload_len` bytes of
probe-defined payload. Multi-byte fields are native-endian because producer and
consumer are the same host.

| off | size | field | notes |
| --: | --: | --- | --- |
| 0 | 4 | `magic` | `0x42525046` = little-endian bytes `FPRB` |
| 4 | 2 | `version` | `1` |
| 6 | 2 | `kind` | probe-defined event kind |
| 8 | 4 | `header_len` | `48` |
| 12 | 4 | `record_len` | `header_len + payload_len`; bytes submitted |
| 16 | 4 | `flags` | reserved, producers set `0` |
| 20 | 4 | `payload_len` | `0..=256` |
| 24 | 8 | `ts_ns` | `bpf_ktime_get_ns()`, `CLOCK_MONOTONIC` |
| 32 | 8 | `pid_tgid` | `bpf_get_current_pid_tgid()` |
| 40 | 8 | `cgroup_id` | `bpf_get_current_cgroup_id()` |
| 48 | ... | payload | `payload_len` bytes, probe-defined |

Rules for producers:

- Use `FLEET_PROBE_RINGBUF(name, FLEET_PROBE_RINGBUF_BYTES)` and name the map
  `<probe>_events`; that is the convention the sensor loader already uses for
  `<sensor>_events`.
- Call `fleet_probe_submit(ringbuf, kind, payload, payload_len)` with a
  **compile-time constant** `payload_len` (`sizeof(payload)`), or use
  `fleet_probe_reserve`/`fleet_probe_submit_reserved` and write every payload
  byte yourself. The verifier needs a known reservation size, and unwritten
  bytes are an information leak.
- `FLEET_PROBE_PAYLOAD_MAX` (256 bytes) is the payload bound. The C struct
  declares a 256-byte payload array so the offset has a compile-time bound, but
  the record size is `header_len + payload_len`, never
  `sizeof(struct fleet_probe_event)`.
- Probe sources loaded into the kernel must carry a GPL-compatible license
  (`char _license[] SEC("license") = "GPL";` and
  `SPDX-License-Identifier: GPL-2.0-only` on the file) because GPL-only helpers
  such as `bpf_probe_read_kernel` are used. The header itself is permissive
  (Apache-2.0 OR MIT) and can be included by a GPL probe.

Rules for consumers (future decoder):

- Reject a record whose `magic` is not `FPRB` or whose `version` is unknown.
- Reject `header_len != 48` or `record_len != header_len + payload_len`; a
  version bump is required for any layout change.
- `flags` is reserved and must be `0` for version 1. New flags require a
  version bump or a documented extension.
- Do not assume payload NUL termination (`comm` is NUL-padded, not a C string
  contract).

This envelope is **separate from** `bpf/include/event_abi.h`. The sensor event
ABI has no custom-probe event kind, and the runtime decoder rejects unknown
kinds, so the SDK owns its own magic/version and keeps the sensor ABI
untouched.

## Toolchain and include resolution

The pinned toolchain is the project dev shell (`nix develop`): Rust 1.95.0,
clang 19.1.7, bpftool. clang 20 and newer are rejected: they lower large
`__builtin_memcpy` calls to an unresolved `memcpy` extern that libbpf cannot
resolve on the supported kernels. This is the same rule as `bpf-build`.

`probe::build(source, output, include_dirs)` runs:

```text
$CLANG -O2 -g -Wall -Wno-missing-declarations -Wno-address-of-packed-member \
       -Wno-comment -target bpf -D__TARGET_ARCH_<host> \
       -I<vmlinux dir> -I<sdk/include> -I<bpf/include> [-I<caller dirs>] \
       -c <source> -o <output>
```

Include directories are resolved in this order:

1. `vmlinux.h` directory:
   - `EBPF_PROBE_VMLINUX_DIR` when set (must contain `vmlinux.h`; for
     cross-kernel work);
   - else `target/bpf-out` from `bpf-build` when it already contains
     `vmlinux.h` (the normal path: the probe build reuses the sensor build's
     generated header);
   - else a cached `target/probe-sdk/include/vmlinux.h` generated with
     `bpftool btf dump file /sys/kernel/btf/vmlinux format c`, refreshed when
     the host BTF is newer than the cache.
2. `sdk/include` — `fleet_probe.h`.
3. `bpf/include` — the project event headers, available for probes that want
   to include `event_abi.h` explicitly.
4. Caller-supplied `include_dirs`, in order.

Environment variables: `CLANG` (clang binary), `BPFTOOL` (only used when a
cached `vmlinux.h` must be made), `EBPF_PROBE_VMLINUX_DIR`,
`EBPF_REPO_ROOT` (same override `bpf-build` honors).

### Gotcha: use the unwrapped clang

Inside `nix develop`, the `clang` on `PATH` is a Nix **wrapper** that forwards
host hardening flags (`-fzero-call-used-regs=used-gpr`,
`-fstack-protector-strong`) which `-target bpf` rejects. The dev shell exports
`CLANG` to the unwrapped clang 19 binary; `probe::build` prefers `CLANG`, so it
works. A manual compile must use `$CLANG`:

```bash
nix develop --no-pure-eval --accept-flake-config --command bash -c \
  '"$CLANG" -target bpf -g -O2 -Wall -D__TARGET_ARCH_x86 \
     -Itarget/bpf-out -Isdk/include \
     -c sdk/examples/hello_probe.bpf.c -o /tmp/hello_probe.bpf.o'
```

The resulting object is a `elf64-bpf` CO-RE object: `.BTF`, `.BTF.ext`, a
`tracepoint/sched/sched_process_exec` section, a `license` section, and a
`.maps` section for `hello_events`.

## Library and CLI API

The crate is the library; `ebpf-fleet probe` is the command-line surface.

```rust
pub fn build(source: &Path, output: &Path, include_dirs: &[PathBuf])
    -> Result<BuildArtifact, BuildError>;

pub fn verify(object: &Path) -> Result<VerifyReport, VerifyError>;

pub fn explain(error_text: &str) -> Explanation;

pub fn workspace_root() -> PathBuf;
pub fn default_out_dir() -> PathBuf; // <workspace>/target/probe-sdk
```

`BuildArtifact` carries `source`, `object`, `clang`, `arch`, resolved
`include_dirs`, and `size_bytes`. `BuildError` distinguishes a missing
source/include directory, a missing/unsupported clang, missing kernel BTF, a
missing `vmlinux.h`, a clang compile failure with the full stderr, and a
missing output object.

`VerifyReport` is returned for every load-time outcome: `status`
(`loaded`, `rejected`, `permission_denied`, `unavailable`), the declared
`programs` (name, section, program type) and `maps` (name, type,
max_entries), the captured `verifier_log`, the `error` text when not loaded,
and short `hints`. `VerifyReport::explanation()` returns the explanation for a
`rejected` report.

`Explanation` has `summary`, `log_retention`, `truncated`, `findings`
(line, cause, matched log line, source-oriented hint), `source_refs`, and the
unmodified `full_log`; `Explanation::render()` is the compact human-readable
form and always ends with the full log.

## Verify: what it proves and what it needs

`probe::verify` opens the object with libbpf-rs, records the program/map names,
and calls the real kernel load path. It never attaches; the loaded object is
dropped immediately so no links or maps from the check survive.

- `loaded` — the kernel verifier accepted every program in the object.
- `rejected` — the verifier refused at least one program; `verifier_log`
  holds the captured log and `explanation()` matches common causes and source
  lines. A rejection is a bug in the probe or a toolchain/kernel mismatch.
- `permission_denied` — the process cannot create BPF maps/programs. Loading
  needs root or `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_ADMIN`, and a host with
  `kernel.unprivileged_bpf_disabled` refuses even map creation. The object was
  opened and parsed, so this is an environment limit, not a verifier verdict.
- `unavailable` — libbpf could not open/parse the object (bad ELF, unreadable
  BTF, bad CO-RE relocation). No kernel verification ran.

Verifier log capture: `verify` installs a `libbpf_rs::set_print` callback at
debug level for the duration of the load, so libbpf's verifier output
(including the kernel's `-- BEGIN PROG LOAD LOG --` block) is captured instead
of printed. The callback is global in libbpf, so `verify` serializes concurrent
load attempts. libbpf retries a failed load at log level 1 with a larger buffer
on `ENOSPC`; the captured text is what libbpf produced, unmodified.

`verify` cannot be exercised end to end without privileges. On this host
(uid 1000, `unprivileged_bpf_disabled=2`) the non-privileged test observes
`permission_denied`; the ignored test is documented below and **has not
passed**.

## Explain: retention and common causes

`explain` is pure and needs no privileges or kernel. It:

1. keeps the complete input in `full_log` (always shown by `render`);
2. extracts the program name from libbpf's `prog '<name>'` preamble;
3. matches a conservative table of common causes: invalid memory access,
   uninitialized reads, unbounded loops, complexity limits, unreachable
   instructions, unknown/invalid helpers, context-access errors, helper
   argument mismatches, stack size, CO-RE relocation failures, invalid pointer
   access, map/object creation failures, privileges/EPERM, memlock limits, and
   unsupported kernel features;
4. extracts the source annotations (`; hello_probe.bpf.c:42`) that exist
   because the object was built with `-g`, and
5. states the log-retention rule: libbpf prints the kernel log between
   `-- BEGIN PROG LOAD LOG --` markers; the kernel truncates at the end of its
   buffer; read backwards from the end because the last instruction or source
   annotation before the failure is the useful one; a captured text that
   mentions a full/truncated buffer must be re-run with a larger log buffer.

The output is compact on purpose (at most 8 findings, at most 16 source
references) and the full log is never truncated by the explainer.

## Example walkthrough

`hello_probe.bpf.c` attaches to the stable
`tracepoint/sched/sched_process_exec` (no host-specific kprobe symbol) and
emits kind `1` with a 24-byte payload: a 16-byte `comm` plus the task
`start_time` read through `BPF_CORE_READ` (a genuine CO-RE relocation).

Build it, as the crate test does:

```bash
nix develop --no-pure-eval --accept-flake-config --command cargo test -p probe
```

The build test writes
`target/probe-sdk/tests/hello_probe.bpf.o` (an `elf64-bpf` object; in this
slice: 1,003,128 bytes, SHA-256
`8e6948361b2cddcef223efe37ec1ced1d0d0b336c1f9df6d06be6bd789033dee`).

The CLI is a thin wrapper over the library:

```bash
ebpf-fleet probe build sdk/examples/hello_probe.bpf.c --out /tmp/hello.bpf.o
ebpf-fleet probe verify /tmp/hello.bpf.o --json
ebpf-fleet probe explain /tmp/verifier.log
```

The equivalent Rust call:

```rust
use probe::VerifyStatus;

let artifact = probe::build(&source, &object, &[])?;
let report = probe::verify(&artifact.object)?;
match report.status {
    VerifyStatus::Loaded => println!("verifier accepted the probe"),
    VerifyStatus::Rejected => {
        print!("{}", report.explanation().expect("rejected has a log").render());
    }
    VerifyStatus::PermissionDenied => {
        for hint in &report.hints {
            println!("{hint}");
        }
    }
    VerifyStatus::Unavailable => println!("object unusable: {:?}", report.error),
}
```

To check the privileged path on a root host or VM:

```bash
cargo test -p probe -- --ignored
```

That is the only test that loads a program into the kernel; it requires root or
`CAP_BPF`/`CAP_PERFMON`/`CAP_SYS_ADMIN` and is excluded from CI.

## Limitations

- The CLI is wired for `build`, `verify`, and `explain`; it is not a probe
  runtime or attacher.
- No runtime loader, attacher, or decoder for SDK events. The example object is
  a fixture and the runtime still consumes only sensor v1 ABI events. A decoder
  needs a magic/version dispatch and a decision about which probe events the
  runtime accepts.
- `verify` proves loadability, not attachability. A program can load and still
  need a cgroup, network device, or attachment context to attach.
- Verification needs privileges. Without them the report is honest about
  `permission_denied` but cannot prove kernel acceptance.
- The envelope is fixed-size: payload must be a compile-time constant and at
  most 256 bytes. Variable-length events, shared maps between probes, and
  per-probe schema metadata are future work.
- `/sys/kernel/btf/vmlinux` is required for the cached `vmlinux.h` fallback;
  cross-kernel work must set `EBPF_PROBE_VMLINUX_DIR` to a `vmlinux.h` built
  from the target kernel.
- clang 19 is mandatory (see the `memcpy` extern limitation above).
- The `probe` crate serializes `verify` calls because libbpf's print callback is
  process-global; it is not intended for concurrent verification from a
  multi-threaded server.

## Checks run for this slice

```text
nix develop --no-pure-eval --accept-flake-config --command cargo test -p probe
  test result: ok. 17 passed; 0 failed; 1 ignored   (+ 4 doc-tests passed)

nix develop --no-pure-eval --accept-flake-config --command \
  cargo clippy -p probe --all-targets -- -D warnings
  Finished (no warnings)

nix develop --no-pure-eval --accept-flake-config --command cargo fmt --all -- --check
  clean

nix develop --no-pure-eval --accept-flake-config --command \
  cargo test -p probe -- --ignored
  expected failure on this host: left PermissionDenied, right Loaded
  (uid 1000, unprivileged_bpf_disabled=2)

Privileged path in the local KVM guest:
  ebpf-fleet probe verify /tmp/hello_probe.bpf.o --json
  status: loaded; tracepoint/sched/sched_process_exec;
  hello_events map; 57 instructions; CO-RE task_struct.start_time applied
  Evidence: docs/verification/probe-sdk-verify.json
```

## CLI usage

```bash
ebpf-fleet probe build <SOURCE> [--out OBJECT] [--include DIR]...
ebpf-fleet probe verify <OBJECT> [--json]
ebpf-fleet probe explain [LOG|-] [--json]
```

`verify` exits non-zero for `rejected`, `unavailable`, and
`permission_denied`; it prints the verifier explanation on rejection and
hints otherwise. `explain` reads a file or stdin. Both reports derive
`serde::Serialize` for `--json`.
