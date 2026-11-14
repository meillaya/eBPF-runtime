# Release 0.2.0 clean-VM test

Status: **PASS** in a clean Ubuntu 24.04.5 LTS KVM guest.

The signed `ebpf-fleet-0.2.0-x86_64.tar.gz` artifact was copied into a
disposable guest, extracted without any toolchain, and exercised:

- `ebpf-fleet-x86_64 --version` → `ebpf-fleet 0.2.0`
- `doctor` → all required checks ok, BTF SHA-256
  `8c10e7e1…`, kernel `6.8.0-147-generic`
- `probe verify /tmp/hello_probe.bpf.o --json` → `status: loaded`,
  `tracepoint/sched/sched_process_exec`, `hello_events` ring buffer
- `record --for 5 --out /tmp/release.fleet` → 18 events, 0 decode errors
- `query` → FileOpen rows
- `replay` → recorded JSON stream

The guest had no Rust, clang, Nix, or project source. The binary is
statically linked. The tarball checksum is recorded in
[release-0.2.0.md](release-0.2.0.md); the probe verifier report is
[release-0.2.0/probe-verify.json](release-0.2.0/probe-verify.json).

The full matrix was run separately with the same binary:
[kernel-matrix.md](kernel-matrix.md) PASS 4/4.
