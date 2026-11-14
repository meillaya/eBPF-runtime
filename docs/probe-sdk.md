<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# C probe SDK: build, verify, run (0.3)

Status: 0.3 adds the custom-probe runtime. A hand-written C probe is still an
ordinary libbpf-style CO-RE object, but it is now described by a version 1
manifest, loaded and attached by `crates/bpf-loader`, decoded by the `FPRB`
decoder in `crates/probe`, and written to an optional `probe_events` Parquet
table by `fleet probe run`. Privileged attach/decode is proven on a real KVM
guest; see [probe-runtime.md](verification/probe-runtime.md).

This page is the contract for:

- [`sdk/include/fleet_probe.h`](../sdk/include/fleet_probe.h) — the C SDK header;
- [`sdk/examples/hello_probe.bpf.c`](../sdk/examples/hello_probe.bpf.c) — the
  buildable example probe;
- [`sdk/examples/hello_probe.manifest.yaml`](../sdk/examples/hello_probe.manifest.yaml)
  — the example probe manifest;
- [`crates/probe`](../crates/probe) — `build`, `verify`, `explain`, the
  manifest parser, and the `FPRB` decoder;
- [`crates/bpf-loader`](../crates/bpf-loader) — the embedded sensor loader plus
  the dynamic `open_object`/`load_object` API;
- [`crates/fleet`](../crates/fleet) — the `ebpf-fleet probe run` command and
  `probe_events` query support.

## What this slice is, and what it is not

| It is | It is not |
| --- | --- |
| A documented header with one fixed event envelope and reserve/submit helpers | A probe DSL or probe language |
| A build wrapper around the pinned clang 19 + the `bpf-build` `vmlinux.h` | A userspace compiler or code generator |
| A validated manifest contract for one probe object | A package format, registry, or signature store |
| A single-run, root-only loader/attacher/decoder (`fleet probe run`) | A daemon that auto-loads probes at boot or on a schedule |
| A libbpf-rs load check with captured verifier diagnostics | Kernel acceptance that can be claimed without privileges |
| A pure verifier-log explainer that runs unprivileged | A probe event source in the sensor event ABI |

The sensor path is unchanged: `crates/bpf-loader` still loads the embedded
`process`/`file` sensors, the sensor event ABI is untouched, and the runtime
decodes SDK events with a separate `FPRB` decoder.

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
  `<probe>_events`; the manifest's `ringbuf:` field names it explicitly.
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

Rules the decoder enforces (`probe::decode_record`):

- `magic` must be `FPRB` (`0x42525046`); anything else is rejected.
- `version` must be `1`; a version bump is required for any layout change.
- `header_len` must be `48` and `record_len` must equal
  `header_len + payload_len` and the number of ring-buffer bytes delivered.
- `flags` must be `0` for version 1.
- `payload_len` must be at most `256`.
- `pid`/`tgid` are the low/high 32 bits of `pid_tgid`.

This envelope is **separate from** `bpf/include/event_abi.h`. The sensor event
ABI has no custom-probe event kind, and the runtime decoder rejects unknown
sensor kinds, so the SDK owns its own magic/version and keeps the sensor ABI
untouched.

## The probe manifest (version 1)

A manifest is one YAML document. It is data only: it names the object, states
which section to attach and which ring-buffer map to read, and describes the
event kinds and payload layout. It never names a helper, a command, a URL, or a
network endpoint.

```yaml
version: 1
name: hello
description: Emit one event per successful exec from the sched_process_exec tracepoint.
object: ../../target/probe-sdk/hello_probe.bpf.o
sha256: "…64 lowercase hex characters…"   # optional; see security model
section: tracepoint/sched/sched_process_exec
attach: tracepoint
ringbuf: hello_events
supported_kernel: ">=5.8 (BPF ring buffers and BTF/CO-RE)"
events:
  envelope: fprb
  version: 1
  kinds:
    - kind: 1
      name: exec
      fields:
        - { name: comm, type: string, size: 16 }
        - { name: task_start_ns, type: u64 }
```

| field | required | contract |
| --- | --- | --- |
| `version` | yes | manifest schema version; must be `1` |
| `name` | yes | 1–64 chars from `a-z 0-9 _ -`, starting lowercase/digit; used as the `probe` column |
| `description` | no | non-empty human text |
| `object` | yes | compiled CO-RE object; relative paths resolve against the **manifest's directory**, absolute paths are used as-is; the operator names both files explicitly (root-only) |
| `sha256` | no | 64 lowercase hex characters; the pin over the complete object bytes |
| `section` | yes | ELF section of the program to attach; must start with `<attach>/` |
| `attach` | yes | `tracepoint`, `raw_tracepoint`, `kprobe`, `kretprobe`, `fentry`, `fexit`, `lsm`, `uprobe`, or `uretprobe` |
| `ringbuf` | yes | BPF map name, 1–15 chars from `[A-Za-z0-9_]`; must exist and be a `RingBuf` map |
| `supported_kernel` | no | non-empty informational range; the runtime does not enforce it |
| `events.envelope` | no (default `fprb`) | must be `fprb` |
| `events.version` | no (default `1`) | must be `1` |
| `events.kinds[]` | yes | at least one kind; `kind` values and `name` values must be unique |
| `events.kinds[].fields[]` | no | optional fixed payload layout, decoded in declaration order |

Payload layout rules:

- Field types: `u8`, `u16`, `u32`, `u64`, `i8`, `i16`, `i32`, `i64`, `string`,
  `bytes`. Native-endian integers; `string` is NUL-trimmed and decoded lossily
  as UTF-8; `bytes` becomes a lowercase hex string.
- Integer types have a fixed size; declaring a conflicting `size` is an error.
- `string`/`bytes` require an explicit `size` (1–256).
- The sum of all field sizes must be at most the `FPRB` payload maximum
  (`256`). `FLEET_PROBE_PAYLOAD_MAX` is the same number.
- A kind without a layout decodes to `{"hex":"…"}`; undeclared kinds are
  preserved as `{"undeclared":true,"hex":"…"}` and never fail the run.
- Trailing payload bytes beyond the declared layout are preserved as
  `_extra_hex` so no captured byte is silently dropped.

Validation is fail-closed: unknown YAML fields, unsupported manifest/envelope
versions, unknown attach types, a section that does not match the attach type,
invalid names/paths/ring buffers, duplicate kinds/fields, oversized layouts, and
malformed SHA-256 values are rejected before the object is opened. Errors name
the field to change.

## Runtime: `fleet probe run`

```text
ebpf-fleet probe run --manifest <MANIFEST> [--duration <SECONDS>] [--out <BUNDLE>] [--allow-unpinned]
```

The single-run lifecycle:

1. Read and validate the manifest (no privileges needed).
2. Resolve `object` and verify the `sha256` pin over the complete object bytes.
   An unpinned manifest is refused unless `--allow-unpinned` is passed; a
   mismatch is always an error.
3. Open the object with libbpf and check the manifest's `section` and
   `ringbuf` map against the object before loading anything. A wrong section or
   missing map is an actionable manifest error, not a verifier failure.
4. Enforce the **root-only** rule (effective uid 0), then load the object into
   the kernel and attach the declared section.
5. Poll the ring buffer, validate the `FPRB` envelope, and decode each payload
   with the manifest's layout. Decode failures are counted and reported; a run
   that captures zero decodable events fails instead of writing an empty
   bundle.
6. Stop on `--duration` (0 means until `SIGINT`/`SIGTERM`), detach every attach
   link, close the object and maps, and report the run as JSON.

Output modes:

- **No `--out`:** one JSON object per decoded event on stdout, and the run
  summary as JSON on stderr (stdout stays machine-parseable):

  ```json
  {"probe":"hello","kind":1,"kind_name":"exec","time":"2026-11-14T06:12:34.123456Z","time_unix_ns":1794595954123456000,"pid":4242,"tgid":4242,"cgroup_id":77,"payload":{"comm":"true","task_start_ns":123456},"raw":"46505242..."}
  ```

- **With `--out <BUNDLE>`:** the decoded events go into a new bundle with an
  (empty) `events` table and a `probe_events` table; the summary JSON is
  printed on stdout.

The summary reports the probe name, resolved object and digest, whether the
manifest was pinned, the attached section/program names, event and error counts,
the bundle path and row count, and `"unloaded": true` with the number of links
detached.

### `probe_events` bundle table

The table is optional in the v2 bundle format: a v1/v2 bundle recorded without
probes opens cleanly and queries as an empty table.

| column | type | meaning |
| --- | --- | --- |
| `probe` | Utf8 | manifest `name` |
| `kind` | UInt16 | wire event kind |
| `kind_name` | Utf8 nullable | manifest kind name (`null` when undeclared) |
| `time_unix_ns` | Int64 nullable | wall-clock time derived from `ts_ns` |
| `time` | Utf8 nullable | RFC 3339 wall-clock time |
| `pid` | UInt32 | thread id |
| `tgid` | UInt32 | thread group id |
| `cgroup_id` | UInt64 | cgroup v2 id |
| `payload_json` | Utf8 | decoded payload as a JSON object |
| `raw` | Utf8 nullable | complete `FPRB` record as lowercase hex |

The bundle manifest's `capture.sensors` records the probe name and `counts`
gains `probe_events`. Query it with SQL or the default table mode:

```bash
ebpf-fleet query hello.fleet --table probe_events
ebpf-fleet query hello.fleet \
  "select probe, kind_name, count(*) as n from probe_events \
   group by probe, kind_name order by n desc"
ebpf-fleet query hello.fleet \
  "select time, payload_json from probe_events order by time_unix_ns limit 5"
```

### Run-level errors (negative paths)

The runtime distinguishes and reports:

- manifest read/parse/validation errors (before opening the object);
- SHA-256 pin mismatch, and an unpinned manifest without `--allow-unpinned`;
- an object that libbpf cannot open (bad ELF, unreadable BTF);
- a `section` that is not present in the object, or a `ringbuf` that is not a
  ring-buffer map, both listed with the object's actual sections/maps;
- non-root execution (`root-only` message with the effective uid);
- kernel verifier rejection/permission denial at load (with the libbpf error;
  use `ebpf-fleet probe verify <object> --json` for the verifier log);
- attach failures, ring-buffer build/poll failures, envelope decode errors, and
  payload-layout errors (counted and reported in the summary).

## Security model

The runtime is designed so that loading operator-supplied code is deliberate,
auditable, and hard to trigger accidentally.

- **Root-only.** `fleet probe run` checks the effective uid from
  `/proc/self/status` and refuses to load or attach for anyone else. Loading
  also requires the kernel's BPF privileges; the root-only gate is stricter
  than the capability check and is the only supported path for this command.
  Run-level tests run unprivileged and assert the refusal.
- **No untrusted auto-load.** Nothing in the agent, record path, bundle reader,
  or TUI loads a probe. Custom probes are only loaded by an explicit
  `fleet probe run`, in one short-lived process, from an object path the
  operator named. There is no registry, watch directory, boot hook, network
  fetch, or daemon state to trigger a probe.
- **Hash pinning by default.** A manifest without `sha256` is refused unless
  the operator passes `--allow-unpinned`, which is an explicit acknowledgement
  that the object bytes are not pinned. When a pin is present, a mismatch fails
  before libbpf opens the object, so a rebuilt/replaced/stale object cannot be
  loaded by accident.
- **No manifest escape hatches.** The manifest is data: no shell fragments, no
  environment expansion, and no remote URLs. Object paths resolve against the
  manifest's directory (or are absolute); the root operator explicitly names
  both the manifest and the object it references.
- **Single run, explicit unload.** Every run attaches in its own process and
  detaches its links/closes its object on stop (duration, SIGINT/SIGTERM, or
  error). There is no long-lived daemon to leak or reuse a link.
- **Byte-preserving evidence.** Each row keeps the raw ring-buffer record as
  hex alongside the decoded JSON, so a decoder/layout disagreement leaves the
  captured bytes queryable instead of losing the event.
- **Separate decoders.** SDK `FPRB` events are decoded by the probe crate only;
  the sensor ABI decoder in `runtime` and the sensor loader/embedded objects
  are unchanged.

Root can of course load anything; the guarantee is about accidental or stale
loads driven by manifests and about keeping an operator-supplied probe out of
the long-running recording path.

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

```rust
// crates/probe
pub fn build(source: &Path, output: &Path, include_dirs: &[PathBuf])
    -> Result<BuildArtifact, BuildError>;
pub fn verify(object: &Path) -> Result<VerifyReport, VerifyError>;
pub fn explain(error_text: &str) -> Explanation;
pub fn workspace_root() -> PathBuf;
pub fn default_out_dir() -> PathBuf; // <workspace>/target/probe-sdk

pub struct ProbeManifest {
    pub version: u32,
    pub name: String,
    pub description: Option<String>,
    pub object: PathBuf,
    pub sha256: Option<String>,
    pub section: String,
    pub attach: AttachType,
    pub ringbuf: String,
    pub supported_kernel: Option<String>,
    pub events: Events,
}
impl ProbeManifest {
    pub fn load(path: &Path) -> Result<Self, ManifestError>;
    pub fn from_yaml(text: &str) -> Result<Self, ManifestError>;
    pub fn validate(&self) -> Result<(), ManifestError>;
    pub fn resolve_object(&self, manifest_path: &Path) -> PathBuf;
    pub fn verify_object_sha256(&self, object: &Path) -> Result<String, ManifestError>;
    pub fn pinned(&self) -> bool;
    pub fn kind(&self, kind: u16) -> Option<&EventKind>;
}

pub fn decode_record(record: &[u8]) -> Result<ProbeEvent, DecodeError>;
pub fn decode_payload(kind: &EventKind, payload: &[u8]) -> Result<serde_json::Value, PayloadError>;
```

```rust
// crates/bpf-loader (dynamic path; the embedded sensor API is unchanged)
pub fn open_object(path: impl AsRef<Path>) -> Result<OpenedObject, DynamicObjectError>;
pub fn load_object(path: impl AsRef<Path>) -> Result<LoadedObject, DynamicObjectError>;
// OpenedObject: path, programs, maps, has_section, section_list, has_map,
//               has_ringbuf, map_list, load
// LoadedObject: path, object, programs, maps, links, attach(section),
//               ring_reader(map), unload
impl LoadedObject {
    pub fn attach(&mut self, section: &str) -> Result<Vec<String>, DynamicObjectError>;
    pub fn ring_reader(&self, map: &str)
        -> Result<(RingBuffer<'static>, Receiver<RawRecord>), DynamicObjectError>;
    pub fn unload(self) -> UnloadReport;
}
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
  lines. A rejection is a bug in the probe or a toolchain/kernel mismatch. The
  kernel reports a verifier rejection as `EACCES`, and `verify` classifies by
  the raw errno so a rejection is never mislabeled as a permission problem.
- `permission_denied` — the process cannot create BPF maps/programs and the
  kernel returned `EPERM`. Loading needs root or `CAP_BPF` + `CAP_PERFMON` +
  `CAP_SYS_ADMIN`, and a host with `kernel.unprivileged_bpf_disabled` refuses
  even map creation. The object was opened and parsed, so this is an
  environment limit, not a verifier verdict.
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
`permission_denied`; the ignored test is documented below.

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
`start_time` read through `BPF_CORE_READ` (a genuine CO-RE relocation). Its
manifest declares that payload layout, so `probe run` prints readable JSON.

Build, verify, and run it (the example manifest is unpinned on purpose):

```bash
ebpf-fleet probe build sdk/examples/hello_probe.bpf.c \
  --out target/probe-sdk/hello_probe.bpf.o
ebpf-fleet probe verify target/probe-sdk/hello_probe.bpf.o --json

# root only; --duration 5 stops the run after five seconds
sudo ebpf-fleet probe run \
  --manifest sdk/examples/hello_probe.manifest.yaml \
  --allow-unpinned --duration 5

# or write a bundle and query the decoded events
sudo ebpf-fleet probe run \
  --manifest sdk/examples/hello_probe.manifest.yaml \
  --allow-unpinned --duration 5 --out hello.fleet
ebpf-fleet query hello.fleet --table probe_events
```

Pin the object (the deployment form of the same manifest):

```bash
sha256sum target/probe-sdk/hello_probe.bpf.o
# add to the manifest:
#   sha256: "<the 64 lowercase hex digits>"
sudo ebpf-fleet probe run --manifest sdk/examples/hello_probe.manifest.yaml --duration 5
```

The equivalent Rust calls:

```rust
use probe::{decode_payload, decode_record, ProbeManifest};

let manifest = ProbeManifest::load(&manifest_path)?;
let object = manifest.resolve_object(&manifest_path);
let digest = manifest.verify_object_sha256(&object)?; // enforces sha256 if pinned

// ... after bpf_loader::open_object/load/attach/ring_reader ...
let event = decode_record(&record_bytes)?;
if let Some(kind) = manifest.kind(event.kind) {
    let payload = decode_payload(kind, &event.payload)?;
    println!("kind {} payload {payload}", kind.kind);
}
```

To check the privileged verify path on a root host or VM:

```bash
cargo test -p probe -- --ignored
```

That is the only test that loads a program into the kernel; it requires root or
`CAP_BPF`/`CAP_PERFMON`/`CAP_SYS_ADMIN` and is excluded from CI.

## Single-run lifecycle and deferrals

The 0.3 slice intentionally implements one run lifecycle, not a probe daemon.
Each `fleet probe run` owning its object and links is what makes the unload
story auditable: when the process exits, every link and map is gone. There is
no persistent registry, so there is nothing to show or stop from a second
process:

- `fleet probe list`, `status`, and `stop` are **not implemented** and are
  deferred to the daemon/lifecycle follow-up along with the query/TUI UX work.
- A run is stopped by `--duration`, `SIGINT`, or `SIGTERM`; the summary records
  `stop` as `duration`, `signal`, or `ring-buffer-error`.

## Limitations

- The runtime loads **one probe per process**, root-only, from an explicit
  manifest. There is no long-lived probe manager, no probe restart policy, and
  no cross-process list/status/stop.
- The envelope is fixed-size: payload must be a compile-time constant and at
  most 256 bytes. Variable-length events, multiple ring buffers per probe,
  shared maps between probes, and per-probe schema versions are future work.
- Payload JSON comes from the manifest's fixed layout; it is not a general
  schema language and does not describe nested or variable-length records.
  Unknown/trailing payload bytes are preserved as hex rather than interpreted.
- `verify` proves loadability, not attachability. A program can load and still
  need a cgroup, network device, or attachment context to attach.
- Verification and the run path need privileges. Without them the reports are
  honest about `permission_denied`/root-only but cannot prove kernel
  acceptance.
- `/sys/kernel/btf/vmlinux` is required for the cached `vmlinux.h` fallback;
  cross-kernel work must set `EBPF_PROBE_VMLINUX_DIR` to a `vmlinux.h` built
  from the target kernel.
- clang 19 is mandatory (see the `memcpy` extern limitation above).
- The `probe` crate serializes `verify` calls because libbpf's print callback is
  process-global; it is not intended for concurrent verification from a
  multi-threaded server.

## Checks run for this slice

```text
nix develop --no-pure-eval --accept-flake-config --command cargo fmt --all -- --check
  clean

nix develop --no-pure-eval --accept-flake-config --command cargo test -p probe
  test result: ok. 40 passed; 0 failed; 1 ignored   (+ 5 doc-tests passed)
  (the ignored test is the privileged verifier load; CI excludes it)

cargo test -p bpf-loader
  test result: ok. 15 passed; 0 failed; 0 ignored   (+ 2 doc-tests passed)

cargo test -p bundle
  test result: ok. 13 passed; 0 failed; 0 ignored

cargo test -p fleet
  test result: ok. 6 passed (local_cli) + 9 passed (probe_runtime); 0 failed

cargo clippy -p probe -p bpf-loader -p bundle -p fleet --all-targets -- -D warnings
  Finished, no warnings
cargo clippy --workspace --all-targets -- -D warnings
  Finished, no warnings (plus a pre-existing future-incompat note for sqlx-postgres)

Privileged runtime in the local KVM guest (Ubuntu 24.04.5 LTS, kernel 6.8.0-147-generic):
  static ebpf-fleet sha256 04c5963e1cd9dd5b3edd8f0a6ed535729ada6f9ea7360cb932f721130236d204
  probe verify: loaded; tracepoint/sched/sched_process_exec;
    hello_events RingBuf 262144
  probe run --duration 5 --out hello.fleet: 118 decoded events, 0 decode errors,
    0 payload errors, 1 link detached, unloaded=true
  query --table probe_events: hello/kind 1/exec, 118 rows; payloads decode to
    {"comm":"true"|"sleep","task_start_ns":...}
  bpftool before/after: 0 hello_probe programs, 0 hello_events maps
  negative: non-root refused, sha256 mismatch refused, unpinned manifest refused
    without --allow-unpinned, wrong section refused, verifier rejection reported
    as rejected (verify) / load error (run)
Evidence: docs/verification/probe-runtime.md and docs/verification/probe-runtime.json.
```

## CLI usage

```bash
ebpf-fleet probe build <SOURCE> [--out OBJECT] [--include DIR]...
ebpf-fleet probe verify <OBJECT> [--json]
ebpf-fleet probe explain [LOG|-] [--json]
ebpf-fleet probe run --manifest <MANIFEST> [--duration SECONDS] [--out BUNDLE] [--allow-unpinned]
ebpf-fleet query <BUNDLE> [SQL] [--table events|stacks|probe_events]
```

`verify` exits non-zero for `rejected`, `unavailable`, and
`permission_denied`; it prints the verifier explanation on rejection and
hints otherwise. `explain` reads a file or stdin. Both reports derive
`serde::Serialize` for `--json`. `probe run` exits non-zero on manifest, pin,
object, privilege, load, attach, or capture errors and prints the failing
stage's message on stderr.
