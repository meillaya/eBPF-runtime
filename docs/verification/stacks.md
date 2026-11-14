# Stack capture and symbolization (0.3)

Status: **implemented and VM-verified** on the 0.3 working tree
(2026-11-14). Release 0.3.0 was built from the same code; the VM evidence
below was captured on a pre-release static build, and the 0.3.0 release
binary was independently exercised by the kernel matrix, arm64 row,
probe runtime, and benchmark runs. This page documents the ABI, the BPF maps, the CLI surface,
the bundle schema, the fallback semantics, the overhead tradeoffs, and the
live Ubuntu 24.04 / kernel 6.8 evidence.

## What it does

`ebpf-fleet record` can capture a stack trace at emit time for process and
file events. The BPF sensor stores the raw kernel/user frame addresses in
`BPF_MAP_TYPE_STACK_TRACE` maps and writes one handle into the event's v2
header. At record time the user-space recorder resolves the handle, reads
the frames, symbolizes them with [`blazesym`], and writes a `stacks` table
next to the `events` Parquet parts. `query` and `top` expose both tables.

Raw addresses are always preserved. A frame that cannot be symbolized stays
in the list with a null `symbol`/`file`/`line`; missing symbols never fail
an event.

## CLI

```bash
# 0.3 default: process exec + file open/create/truncate stacks
sudo ebpf-fleet record --for 10 --out incident.fleet

# explicit modes
sudo ebpf-fleet record --stacks off  --out minimal.fleet   # 0.2 overhead
sudo ebpf-fleet record --stacks all  --out full.fleet      # + fork/exit/unlink/rename

# stack capture/symbolization counters as JSON on stdout
sudo ebpf-fleet record --stacks events --for 10 --out incident.fleet --stats

# events-only SQL (v1 bundles still work the same way)
ebpf-fleet query incident.fleet "select kind, count(*) as n from events group by kind"

# the stacks table
ebpf-fleet query incident.fleet --table stacks

# join events to their symbolized stacks on (sensor, stack_id)
ebpf-fleet query incident.fleet "
  select e.kind, e.path, s.frames
  from events e
  join stacks s on e.sensor = s.sensor and e.stack_id = s.stack_id
  order by e.time_unix_ns
"

# bundle top view includes a stack pane/section
ebpf-fleet top incident.fleet
```

`--stacks` accepts `off`, `events`, `all`:

| mode | captures | use |
| --- | --- | --- |
| `off` | nothing; sensors write `stack_id = -1` | minimum overhead / 0.2 parity |
| `events` (default) | process exec, file open/create/truncate | 0.3 default |
| `all` | adds process fork/exit and file unlink/rename | full incident detail |

The mode is recorded in the bundle manifest as `capture.stack_mode`.

## Event ABI v2

`bpf/include/event_abi.h` is the single source of truth. Schema-major 2
extends the fixed header from 96 to 104 bytes:

```text
off size field
 0   4  schema_major         2 for v2 records
 4   4  schema_minor
 8   4  header_len           104 for v2 records
12   4  record_len           104 + payload
16   1  event_kind            (unchanged)
20   1  flags                 (unchanged)
24   8  seq                   (unchanged)
32   8  ts_monotonic_ns       (unchanged)
40  16  boot_id               (unchanged)
56   8  pid_tgid              (unchanged)
64   8  task_start_time_ns    (unchanged)
72   8  cgroup_id             (unchanged)
80   4  processor_id          (unchanged)
84   4  valids                (unchanged)
88   8  ns_pid                (unchanged)
---  96-byte v1 boundary ---
96   4  stack_id              v2 only; kernel stack handle or -1
100  4  user_stack_id         v2 only; user stack handle or -1
```

Both stack ids are optional and independent: a sensor that captures only
one stack class leaves the other `-1`. The v1 layout is frozen: v1 records
still parse (`stack_id = user_stack_id = None`), the
v1 golden fixture is byte-identical, and 0.2 bundles remain readable. The
Rust side is `crates/event-abi` (`Event::stack_id: Option<i32>`,
`HeaderV2`, `STACK_ID_NONE`, `STACK_DEPTH`, `STACK_MAP_ENTRIES`).

## BPF maps

Each sensor object gets its own maps, so the loader can configure capture
per sensor before attach:

| map | type | geometry | purpose |
| --- | --- | --- | --- |
| `<sensor>_stack_config` | array | 1 × u32 | loader-written capture mode (0/1/2) |
| `<sensor>_stack_stats` | per-CPU array | 1 × counters | captures/failures for `--stats` |
| `process_stacks` | stack trace | 16 384 entries × 64 frames | process-sensor kernel stacks |
| `file_stacks` | stack trace | 16 384 entries × 64 frames | file-sensor kernel stacks |
| `file_user_stacks` | stack trace | 16 384 entries × 64 frames | file-sensor user stacks |

A single `bpf_get_stackid()` call walks either the kernel stack or the user
stack (`BPF_F_USER_STACK`), never both. The v2 header has one handle, so:

* process sensor (tracepoint/raw-tracepoint contexts) captures **kernel**
  stacks only; the tracepoint context cannot reliably unwind the current
  user stack for these hooks;
* file sensor kprobes capture a **kernel** stack (handle stored in
  `header.stack_id`) and a **user** stack (handle stored in
  `header.user_stack_id`). The loader reassembles one
  `RawStack { kernel, user }` from the two maps;
* the `file_open` LSM hook does **not** capture: LSM context is hook
  arguments, not `pt_regs`, and `bpf_get_stackid()` would misread it. On
  kernels where the BPF LSM is active the kprobe open fallback is skipped,
  so file-open events have no stack there (documented gap).

Stack capture never blocks or fails an event. `bpf_get_stackid()` failure
(most often `-ENOMEM` when the stack-trace map is full) increments a
counter and leaves `stack_id = -1`. Events always ship well-formed and the
ring-buffer record length is unchanged.

## Symbolization

`crates/runtime/src/symbolize.rs` wraps `blazesym 0.2.7` (pinned,
`rust-version = "1.88"`, below this workspace's 1.95 MSRV) with the
`demangle`, `dwarf`, and `zlib` features and no `backtrace` feature.

* **Kernel frames** use the `Kernel` source: an on-disk `vmlinux` when
  present, otherwise `/proc/kallsyms` plus loaded modules. Root is required
  for readable kallsyms addresses; unprivileged runs fall back to raw
  addresses and count `missing_symbols`.
* **User frames** use the `Process` source for the event's thread group
  while it is still alive. It reads symbolic `/proc/<pid>/maps` paths
  (privileged `map_files` entries are disabled), honors ELF symbols,
  DWARF/debug links, split debug files, and build-id indexed debug files
  under the default debug dirs (`/usr/lib/debug`, `/lib/debug`,
  `.build-id`). A debuginfod client is not enabled (opt-in gap).
* Kernel and user frame batches are symbolized separately; a failure of
  one batch does not discard the other. Any address whose symbol cannot be
  resolved keeps its raw `addr` and is counted as a missing symbol.
* `record --stats` prints JSON with stack capture counters (including
  `stack_map_drops`), stack-map geometry, symbolization coverage
  (`kernel_frames`/`user_frames`, symbolized, `missing_symbols`,
  `truncated_stacks`, `invalid_frames`, batch errors), and bundle row counts.

## Bundle format v2

`ebpf-fleet.bundle/v2` (`ARROW_SCHEMA_VERSION = 2`):

* `events` gains a nullable `stack_id: Int32` column. Everything else is
  unchanged from v1.
* a new `stacks` table:

| column | type | notes |
| --- | --- | --- |
| `stack_id` | `Int32` | matches `events.stack_id` per `sensor` |
| `sensor` | `Utf8` | `process` or `file` |
| `frames` | `List<Struct<addr: UInt64, symbol: Utf8?, file: Utf8?, line: UInt32?, is_kernel: Boolean>>` | innermost first: kernel frames then user frames |
| `truncated` | `Boolean` | capture hit the 64-frame depth |

`events.stack_id` is a recorder-assigned stable key, not the raw BPF map
handle: the recorder de-duplicates on `(sensor, kernel_handle,
user_handle)` and assigns one small sequential id per distinct stack, so
the `stacks` table is small relative to the event count and the
`(sensor, stack_id)` join is exact. Kernel and user stacks are captured
into different BPF maps and a kernel handle is shared by many distinct
user stacks, so the raw handles cannot serve as a bundle key.
`bundle.read_stacks()` returns the typed table.

The reader accepts `ebpf-fleet.bundle/v1` (0.2): it reads the frozen v1
event schema (no `stack_id`) and exposes an empty `stacks` table, so the
same join SQL runs but returns no stack rows. Mixed-version directories are
rejected; the manifest hash/file validation is unchanged.

## Fallbacks and gaps

Resolved:

* missing symbols keep raw addresses and are counted;
* process exit between capture and symbolization degrades user frames to
  raw addresses;
* stack-map failure is counted and non-fatal; a stack that cannot be
  read is removed from the event rather than left as a dangling join key;
* v1 bundles/fixtures keep working.

Known gaps (also listed in the task report):

* user-stack unwinding depends on the target binary's frame pointers or
  unwind info; frames that are not canonical user addresses (garbage from
  a broken frame-pointer walk) are dropped before symbolization and counted
  as `invalid_frames`;
  unwind info; stripped, frame-pointer-less system binaries typically
  yield only the syscall return PC (still symbolized through `.dynsym` or
  section symbols when available);
* kernel frames from the `file_open` LSM hook are unavailable on kernels
  with an active BPF LSM (the kprobe fallback is skipped to avoid
  duplicate events);
* debuginfod is not contacted;
* 16 384 × 64 frames is the fixed geometry; overflow is handled but not
  adjustable at runtime;
* the stack map cannot be deliberately exhausted in a short lab run because
  identical stacks hash to the same handle (evidence below records the
  observed counters instead).

## Overhead notes

Capture modes trade CPU and memory for detail:

* `off`: no stack-map lookups at emit time; one map lookup per event is
  avoided entirely because the capture helper returns before touching the
  config map only after the mode read — events carry `stack_id = -1`.
* `events` (default): two `bpf_get_stackid()` calls per file event (kernel +
  user) and one per process exec; each call walks up to 64 frames and
  hashes the stack. Expect a few microseconds per captured event and a
  bounded memory cost of ~8 MiB per 16 384-entry × 64-frame stack map
  (~16 MiB resident per file sensor, plus ~8 MiB per process sensor).
* `all`: adds capture for fork/exit/unlink/rename, i.e. every event can pay
  the stack-walk cost.
* Symbolization happens in user space once per distinct `(sensor,
  stack_id)`; repeated stacks are free after the first resolution.

## Verification

`crates/event-abi/tests/parse.rs` covers v1/v2 parsing and the stack-id
sentinel; `crates/event-model/src/lib.rs` tests stack decoding and JSON
backward compatibility; `crates/bundle/src/lib.rs` tests the v2 round-trip,
the `(sensor, stack_id)` join, unavailable-symbol preservation, and v1
bundle readability; `crates/fleet/tests/local_cli.rs` tests `query --table
stacks`, the join, and the `top` stack pane; `crates/runtime/src/symbolize.rs`
tests golden ELF symbolization (checked-in fixture under
`crates/runtime/tests/fixtures/symbolize/` with exact symbol/file/line
expectations) plus a live self-process symbolization check and the raw
fallback.

## Live VM evidence

Status: **PASS** on 2026-11-14 (UTC) with a real KVM guest, the 0.3
working-tree static binary, and the released 0.2 binary for the v1
compatibility pass. Raw artifacts are kept under
`target/vm/stack-evidence/` (gitignored): the exported evidence tarball is
`vm-stack-evidence.tar.gz` and the extracted bundles are `stacks.fleet`,
`stacks-all.fleet`, `stacks-off.fleet`, and `legacy.fleet`.

Lab instance: `scripts/vm/lab.sh up --image ubuntu-24.04 --name stack-test`
(instance SSH port 2223; all state under `target/vm/`).

| fact | value |
| --- | --- |
| host | x86_64, local KVM lab, no sudo on the host |
| guest OS | Ubuntu 24.04.5 LTS |
| guest kernel | `6.8.0-147-generic` |
| guest LSM list | `lockdown,capability,landlock,yama,apparmor` (no `bpf` LSM, so the file sensor used its kprobe path) |
| binary under test | static-pie x86_64 `target/release/ebpf-fleet`, `ebpf-fleet 0.2.2` |
| binary sha256 | `205ceacb7a43504e3a186a72ee2f92c01165c866e4aaf873addff27b4cdc9f05` |
| activity helper | statically linked `stack-helper` (gcc `-static -g -O1 -fno-omit-frame-pointer`, raw syscalls, sha256 `83bdc2011d58f639a43e91f8635b8bbc467edd5b0dbeea6b8422a4532af0603c`) |
| release binary for v1 pass | released `ebpf-fleet 0.2.0` static-pie from `target/release/ebpf-fleet-0.2.0/ebpf-fleet-x86_64` |

### Exact commands

Host side (the VM is booted once, then all commands run inside it as root):

```bash
cd /home/mei/Documents/eBPF-runtime
PATH="$PWD/.devenv/profile/bin:$PATH" scripts/vm/lab.sh up --image ubuntu-24.04 --name stack-test
PATH="$PWD/.devenv/profile/bin:$PATH" scripts/vm/lab.sh copy --name stack-test target/release/ebpf-fleet /tmp/ebpf-fleet
PATH="$PWD/.devenv/profile/bin:$PATH" scripts/vm/lab.sh copy --name stack-test target/vm/stack-evidence/stack-helper /tmp/stack-helper
PATH="$PWD/.devenv/profile/bin:$PATH" scripts/vm/lab.sh copy --name stack-test target/release/ebpf-fleet-0.2.0/ebpf-fleet-x86_64 /tmp/ebpf-fleet-0.2
PATH="$PWD/.devenv/profile/bin:$PATH" scripts/vm/lab.sh run --name stack-test -- 'sudo -n bash /tmp/activity.sh'
```

Guest-side activity (abridged; full script in `target/vm/stack-evidence/activity.sh`):

```bash
sudo -n /tmp/ebpf-fleet record --for 12 --stacks events --out /tmp/stacks.fleet --stats   > /tmp/record.stdout 2> /tmp/record.stderr &
sleep 2
/tmp/stack-helper 100000000 &            # long-lived: user ELF/DWARF is readable
for round in $(seq 1 40); do /tmp/stack-helper 4; done   # exec churn for process stacks
wait

sudo -n /tmp/ebpf-fleet query /tmp/stacks.fleet --table stacks
sudo -n /tmp/ebpf-fleet query /tmp/stacks.fleet "
  select e.path, e.stack_id, s.frames
  from events e join stacks s
    on e.sensor = s.sensor and e.stack_id = s.stack_id
  where e.path like '/tmp/stack-activity%' limit 1"
```

### Result 1: real kernel+user stack capture, symbolized

`record --stacks events` (the 0.3 default) recorded 33 026 events with 0
decode errors and wrote 65 distinct stacks. Exact `--stats` output:

```json
{
  "decode_errors": 0,
  "events": 33026,
  "stack_capture": {
    "kernel_captures": 16659,
    "kernel_failures": 0,
    "user_captures": 16617,
    "user_failures": 0
  },
  "stack_map_drops": 0,
  "stack_maps": {
    "file": {"entries": 16384, "frames": 64, "user_entries": 16384, "user_frames": 64},
    "process": {"entries": 16384, "frames": 64, "user_entries": null, "user_frames": null}
  },
  "stack_mode": "events",
  "stack_read_errors": 0,
  "stacks_written": 65,
  "symbolization": {
    "invalid_frames": 43,
    "kernel_errors": 0,
    "kernel_frames": 203,
    "kernel_symbolized": 203,
    "missing_symbols": 187,
    "stacks": 65,
    "truncated_stacks": 0,
    "user_errors": 4,
    "user_frames": 320,
    "user_symbolized": 133
  }
}
```

The join query shows one file-open event with kernel frames **and** user
frames, including source symbols and line numbers resolved from the
helper's local DWARF (this is the required "query that shows frames"):

```text
path: /tmp/stack-activity/file-16   stack_id: 14
frames (abridged from the actual query result; addresses verbatim):
  {addr: 0xffffffff85af4091, symbol: __x64_sys_openat,              is_kernel: true}
  {addr: 0xffffffff86859147, symbol: do_syscall_64,                 is_kernel: true}
  {addr: 0xffffffff86a00130, symbol: entry_SYSCALL_64_after_hwframe, is_kernel: true}
  {addr: 4208561, symbol: touch_open, is_kernel: false,
   file: /home/mei/Documents/eBPF-runtime/target/vm/stack-evidence/stack_helper.c, line: 68}
  {addr: 4208865, symbol: main, is_kernel: false,
   file: /home/mei/Documents/eBPF-runtime/target/vm/stack-evidence/stack_helper.c, line: 115}
  {addr: 4210842, symbol: __libc_start_call_main, is_kernel: false}
  {addr: 0x7ffeae0c8dd7, symbol: null, is_kernel: false}
```

A process-sensor `ProcessExec` event carries the symbolized kernel exec
stack (from the same bundle):

```text
bpf_prog_..._tp_sched_process_exec -> bpf_trace_run3 ->
__bpf_trace_sched_process_exec -> exec_binprm -> bprm_execve.part.0 ->
bprm_execve -> do_execveat_common.isra.0 -> __x64_sys_execve ->
x64_sys_call -> do_syscall_64 -> entry_SYSCALL_64_after_hwframe
```

Join coverage for the recording:

```text
| events | distinct_stack_ids |
| 16598  | 65                 |
```

### Result 2: `--stacks off|all` and top/pack surfaces

`record --stacks off --for 4`:

```text
recorded 18 events and 0 distinct stacks (0 decode errors) into /tmp/stacks-off.fleet
manifest: {"format":"ebpf-fleet.bundle/v2",
           "capture":{"sensors":["process","file"],"duration_ms":4000,"stack_mode":"off"},
           "counts":{"events":18,"alerts":0,"stacks":0,"dropped":{}}}
query: select count(*) from events where stack_id is not null  -> 0
query: select count(*) from stacks                             -> 0
```

`record --stacks all --for 8`: 20 334 events, 0 decode errors, 60 distinct
stacks, `stack_mode: "all"`, and stack ids on every captured event kind:

```text
| kind        | events with stack_id |
| FileOpen    | 10226                |
| FileUnlink  | 10057                |
| ProcessExit | 17                   |
| ProcessFork | 17                   |
| ProcessExec | 17                   |
```

`top` on the event-mode bundle (non-terminal summary) shows the stack pane:

```text
stacks: 65 resolved, 523 frames (187 without symbols), 16598 events carry a stack id

top stacks
        64  __x64_sys_openat
         1  bpf_prog_2ad636a5b92e5260_tp_sched_process_exec
```

`pack`/`unpack` round-trip on the same bundle: `33026 events, 65 stacks`
after re-open and query.

### Result 3: 0.2 bundle compatibility (real released binary)

The released 0.2 static binary wrote a bundle in the same guest:

```text
legacy record: recorded 232 events (0 decode errors) into /tmp/legacy.fleet
manifest: {"format":"ebpf-fleet.bundle/v1",
           "capture":{...,"stack_mode":"off"},"counts":{"events":232,"stacks":0}}
legacy kinds: FileOpen 108, FileUnlink 60, ProcessExit 22, ProcessFork 21, ProcessExec 21
```

The current binary reads it unchanged:

```text
query select count(*) from events  -> 232
query select count(*) from stacks  -> 0        (empty compatibility table)
replay first event: {"time":...,"schema_major":1,"schema_minor":0,...}
```

### Stack-map pressure and overflow

The 16 384-entry × 64-frame geometry held 16 659 kernel and 16 617 user
captures over 65 distinct stacks with **0 kernel failures, 0 user failures,
0 stack-map drops, 0 stack read errors and 0 decode errors**. The overflow
path is implemented and covered by the fallback rules: a failed
`bpf_get_stackid()` (typically `-ENOMEM` when the stack map is full) is
counted, the header keeps `stack_id = -1`, and the event still ships
well-formed; the user-space side keeps raw addresses when a handle has no
frames and drops the event's join reference instead of corrupting it.
The map cannot be deliberately exhausted in a short lab run because
identical stacks hash to the same handle (the activity above produced only
65 unique stacks for ~33k events), so the "no corruption on map overflow"
property is demonstrated by the fail-closed code path plus the
`events_with_dangling_stack_ids_stay_queryable` bundle test and the
`invalid_frames`/empty-stack unit tests rather than by forcing 16 384
distinct stacks.

### Observed gaps

* User frames from a process that exits between capture and symbolization
  cannot be resolved (4 user batches errored on short-lived exec churn);
  their events keep `stack_id` cleared rather than a dangling join key.
  Long-lived processes symbolize correctly (the helper above).
* 43 frames were dropped as non-canonical unwind garbage (`invalid_frames`)
  from the kernel's frame-pointer user unwind; without frame pointers only
  the syscall PC plus recoverable caller frames are captured.
* On this kernel the guest LSM list has no `bpf` LSM, so the kprobe open
  path (which captures both stack classes) was exercised. The LSM-hook
  no-stack gap documented above was not exercised here.
* The unprivileged host run cannot read `/proc/kallsyms` addresses, so the
  in-tree kernel-symbolization unit test skips there; the VM evidence above
  is the real kernel evidence.
