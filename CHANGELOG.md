# Changelog

## 0.3.0 — 2026-11-14

The daily-driver release: stack traces, custom probes, arm64, and query UX.

- Event ABI v2 and bundle v2: kernel/user stack capture for process/file
  events, blazesym symbolization, a `stacks` table, raw-address fallback,
  stack-map counters, and `record --stacks off|events|all --stats`.
- Custom probe runtime: validated YAML manifests, dynamic load/attach,
  FPRB event decoding, `probe run` to JSON lines or `probe_events`, and
  root-only/pinned/clean-unload lifecycle. Verifier rejection is classified
  by EACCES instead of as a permission error.
- aarch64: cross-built static artifact, installer selection, native arm64
  GitHub release matrix, QEMU TCG functional lab row, and documented
  TCG/native limits.
- Daily UX: query JSON/CSV/Parquet streaming, schema/explain, `inspect`,
  `diff --by process|path|stack`, record JSON/quiet/progress, TUI filters/
  pause/sort/snapshot, PTY test, shell completions, and man pages.
- Benchmark harness plus KVM baselines and measured stack-mode overhead.
- v1 bundles remain readable; v2 adds a stacks table and optional
  probe_events.

## 0.2.2 — 2026-11-14

Trust and clean-build release; no local CLI changes.

- Keyless GitHub Actions release path with cosign, provenance, and SBOM.
- Clean CI sensor builds: autopoint in the dev shell, explicit libbpf
  include discovery, and compatibility with older libbpf headers.
- Poll the durable rollout audit row in the rejected-ack test.
- Release from green `main` rather than a feature tip.

## 0.2.0 — 2026-11-14

The first local-first release. The headline is the `ebpf-fleet` local
recorder; fleet mode remains available as the scale-out path.

### Added

- `ebpf-fleet record/query/replay/diff/pack/unpack/doctor/top`.
- Self-contained incident bundles with Parquet events, manifest validation,
  atomic finalization, and incomplete-bundle rejection.
- DataFusion SQL over local bundles; JSONL replay.
- Live and bundle TUI (`top`) with process, path, kind, and recent-event views.
- `ebpf-fleet policy test` with YAML expectations over recorded bundles.
- C probe SDK (`sdk/`, `crates/probe`) and `ebpf-fleet probe
  build/verify/explain`, with privileged VM verification evidence.
- Local KVM VM lab and kernel matrix runner; Ubuntu 24.04 (6.8), Ubuntu
  22.04 (5.15), Debian 12 (6.1), Debian 13 (6.12), and Fedora 42 (6.14)
  PASS, including process exit events.
- Scoped rootless Podman wrapper; storage, runtime, and images stay under
  `target/podman`.
- Static-pie x86_64 release build, installer, checksums, SBOM, and release
  workflow scaffolding.
- License, DCO, contribution, security, and positioning docs.

### Changed

- The process sensor's exit event uses
  `tracepoint/sched/sched_process_exit` instead of the non-attaching raw
  tracepoint.
- The file sensor's syscall-entry fallback reads arguments through `pt_regs`
  and covers `openat` as well as `openat2`.
- README leads with the local-first workflow and documents fleet mode as a
  separate scale-out path.

### Known limitations

- Stack capture/symbolization is not in 0.2.
- The C probe SDK does not yet decode probe events in the runtime or attach
  custom probes automatically.
- arm64 remains unverified because this lab host is x86_64 and the lab does
  not emulate. The five x86_64 matrix rows are green.
- The keyless GitHub release workflow is blocked by GitHub Actions billing;
  local signing evidence uses an explicitly test release key.
