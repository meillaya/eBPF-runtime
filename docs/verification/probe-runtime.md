# Probe runtime privileged evidence

Status: **PASS** on a real Ubuntu 24.04 KVM guest.

The 0.3 custom-probe runtime was exercised end to end inside the local VM lab:
a pinned probe manifest was validated, the object was loaded and attached at
the `sched_process_exec` tracepoint, real `FPRB` events were captured and
decoded, the decoded rows were queried from the bundle's `probe_events` table,
and the program/map were unloaded. The negative paths were exercised on the
same guest.

The compact JSON evidence is checked in as
[`probe-runtime.json`](probe-runtime.json). Raw VM logs and guest artifacts
remain on the lab host under `target/vm/probe-runtime/`, which is gitignored.

- Host: `massive`, x86_64, host kernel `7.3.3-1-cachyos`, `/dev/kvm` usable
  without sudo.
- Guest: Ubuntu 24.04.5 LTS, kernel `6.8.0-147-generic`, BTF present. Image
  `ubuntu-24.04`, pinned sha256 `04e8f246…`.
- Instance: `probe-runtime-test` (dedicated name; removed with
  `scripts/vm/lab.sh down --name probe-runtime-test --purge` after the run).
- Runner: `scripts/vm/lab.sh` from `devenv shell`; VMs are booted with KVM.
- Tool under test: static-pie x86_64 `target/release/ebpf-fleet`, built by
  `scripts/build-static.sh`, 137248296 bytes, sha256
  `04c5963e1cd9dd5b3edd8f0a6ed535729ada6f9ea7360cb932f721130236d204`.
- Object: `sdk/examples/hello_probe.bpf.c` built by
  `ebpf-fleet probe build` with the pinned clang 19.1.7, 1003048 bytes,
  sha256 `9829ccc9f90381d4c46fc59802e2eacb4edfd870359d6da9bd63740a65a1e0fd`.
- Manifest: version 1, `hello`, pinned to the object sha256, section
  `tracepoint/sched/sched_process_exec`, `attach: tracepoint`,
  `ringbuf: hello_events`, kind `1`/`exec` with the 24-byte payload layout
  (`comm` string 16, `task_start_ns` u64). The pinned copy and the unpinned
  variant live under `target/vm/probe-runtime/`.

## Positive lifecycle

Commands (guest, copied binary and fixtures under `/tmp/probe`):

```text
sudo /tmp/probe/ebpf-fleet probe verify /tmp/probe/hello_probe.bpf.o --json
  -> status: loaded; program hello_probe_exec;
     map hello_events (RingBuf, 262144); tracepoint section accepted

sudo bpftool prog show | grep -c hello_probe   -> 0
sudo bpftool map show  | grep -c hello_events  -> 0

( for i in $(seq 1 60); do /bin/true; sleep 0.03; done ) &
sudo /tmp/probe/ebpf-fleet probe run \
  --manifest /tmp/probe/hello.manifest.yaml --duration 5 \
  --out /tmp/probe/hello.fleet
  -> exit 0; attached hello_probe_exec; 118 events; 0 decode errors;
     0 payload errors; bundle /tmp/probe/hello.fleet;
     bundle_probe_events 118; links_detached 1; unloaded true;
     stop duration

sudo /tmp/probe/ebpf-fleet query /tmp/probe/hello.fleet --table probe_events
  -> hello | kind 1 | exec | 118 rows
sudo /tmp/probe/ebpf-fleet query /tmp/probe/hello.fleet \
  "select count(*) as n from probe_events"
  -> 118

sudo bpftool prog show | grep -c hello_probe   -> 0
sudo bpftool map show  | grep -c hello_events  -> 0
```

Decoded rows from the bundle (real payloads, not fixtures), queried with
`select time, pid, tgid, cgroup_id, payload_json from probe_events order by
time_unix_ns, pid limit 3`:

| time | pid | tgid | cgroup_id | payload_json |
| --- | ---: | ---: | ---: | --- |
| 2026-11-14T07:11:01.688479Z | 18041 | 18041 | 12051 | `{"comm":"true","task_start_ns":546358177965}` |
| 2026-11-14T07:11:01.689262Z | 18042 | 18042 | 12051 | `{"comm":"sleep","task_start_ns":546359027725}` |
| 2026-11-14T07:11:01.720409Z | 18043 | 18043 | 12051 | `{"comm":"true","task_start_ns":546390107437}` |

The same probe was also run without `--out`, where decoded events are JSON
lines on stdout and the summary is JSON on stderr:

```text
sudo /tmp/probe/ebpf-fleet probe run \
  --manifest /tmp/probe/hello.manifest.yaml --duration 4
  -> exit 0; 78 stdout JSON lines; 0 decode errors; 0 payload errors;
     links_detached 1; unloaded true; stop duration
```

Example stdout line:

```json
{"probe":"hello","kind":1,"kind_name":"exec","time":"…","time_unix_ns":…,"pid":…,"tgid":…,"cgroup_id":…,"payload":{"comm":"true","task_start_ns":…},"raw":"4650524201000100…"}
```

The explicit unpinned opt-in was also exercised on the guest:

```text
sudo /tmp/probe/ebpf-fleet probe run \
  --manifest /tmp/probe/hello-unpinned.manifest.yaml \
  --allow-unpinned --duration 3
  -> exit 0; 38 stdout JSON lines; pinned false; 0 errors; unloaded true
```

Unload evidence: `bpftool` reported `0` `hello_probe` programs and `0`
`hello_events` maps before and after the runs, and the run summary reported
`links_detached: 1` / `unloaded: true`. The ring buffer and attach link are
gone once the process exits; nothing is pinned in bpffs.

## Negative paths

All negative cases exited non-zero, wrote nothing to stdout, and failed at the
intended stage:

| case | command (guest) | result |
| --- | --- | --- |
| missing privilege | `ebpf-fleet probe run --manifest hello.manifest.yaml` as uid 1000 | `root-only (effective uid 1000)` before any kernel load |
| hash mismatch | `sudo … probe run --manifest hello-wrong-hash.manifest.yaml` | `probe object hash mismatch … manifest pins 000…, object is 9829…` |
| unpinned refused | `sudo … probe run --manifest hello-unpinned.manifest.yaml` (no `--allow-unpinned`) | `has no sha256 pin: refusing to load an unpinned probe object … or pass --allow-unpinned` |
| wrong section | `sudo … probe run --manifest hello-wrong-section.manifest.yaml` | `manifest section kprobe/does_not_exist is not in …; object sections: tracepoint/sched/sched_process_exec` |
| verifier rejection (verify) | `sudo … probe verify /tmp/probe/bad_probe.bpf.o --json` | `status: rejected`, verifier log captured, hints point at the log/explanation |
| verifier rejection (run) | `sudo … probe run --manifest bad.manifest.yaml` | load fails with `… os error 13 …; if the kernel verifier rejected the object, run probe verify …` |

The verifier-rejection fixture is an out-of-bounds stack-read program built
only for this test under `target/vm/`; it is not checked in. The kernel reports
a verifier rejection as `EACCES`, so both `probe verify` and the dynamic loader
classify by the raw errno: `EPERM` is a permission failure, everything else is
a load/verifier failure. The fixture's `probe verify` report has
`status: rejected` (not `permission_denied`), and the run refuses at load.

## What this proves and what it does not

Proven on real hardware virtualization: manifest parsing/validation and pin
enforcement; libbpf open/load/attach of the example CO-RE object; attaching the
declared ELF section; ring-buffer polling; `FPRB` envelope validation; payload
JSON decoding using the manifest layout; bundle writing with a `probe_events`
Parquet table; querying the decoded rows; root-only refusal; and clean
unload/teardown.

Not proven here: long-lived probe management (`probe list`/`status`/`stop` are
deferred, see `docs/probe-sdk.md`), non-`tracepoint` attach types, variable
payload layouts, or multiple probes per process. Those are explicitly out of
the 0.3 single-run lifecycle.

## Reproducing

```bash
devenv shell -- scripts/build-static.sh
devenv shell -- scripts/vm/lab.sh bootstrap
devenv shell -- scripts/vm/lab.sh up --image ubuntu-24.04 \
  --name probe-runtime-test --cpus 4 --memory 4096
# build the object and pinned/unpinned/negative manifests under
# target/vm/probe-runtime/, copy the static binary plus fixtures into the
# guest, then run the positive and negative scripts:
#   target/vm/probe-runtime/run-vm-tests.sh   (host side, instance running)
devenv shell -- scripts/vm/lab.sh down --name probe-runtime-test --purge
```
