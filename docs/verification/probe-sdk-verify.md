# Probe SDK privileged verification

Status: **PASS** on a real Ubuntu 24.04 KVM guest.

The C probe SDK's `verify` path was exercised with root/CAP_BPF inside the
local VM lab, not only as an unprivileged parse check:

- Guest: Ubuntu 24.04.5 LTS, kernel `6.8.0-147-generic`.
- Binary: static `ebpf-fleet` from `scripts/build-static.sh`, sha256
  `5afd446b14aece5b5c9dbc8e25ab1c9145cdc7f89b699664e26f2c7d2486bcb1`.
- Object: `sdk/examples/hello_probe.bpf.c`, built by
  `ebpf-fleet probe build`, 980 KiB CO-RE object.
- Command: `sudo /tmp/ebpf-fleet probe verify /tmp/hello_probe.bpf.o --json`.
- Result: `status: loaded`, program
  `hello_probe_exec` in `tracepoint/sched/sched_process_exec`, map
  `hello_events` (`RingBuf`, 262144 bytes), CO-RE relocation of
  `task_struct.start_time` applied, verifier accepted 57 instructions.

The full JSON report is checked in as
[`probe-sdk-verify.json`](probe-sdk-verify.json). The unprivileged host path
is separately covered by `cargo test -p probe` (it correctly reports
`permission_denied` rather than claiming success).

This proves object build, CO-RE relocation, map creation, and verifier
acceptance. It does not prove attachment or runtime decoding of SDK events;
both are explicitly out of this slice.
