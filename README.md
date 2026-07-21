# kernel-v1 — eBPF Runtime Security & Observability (greenfield)

This repository is the **greenfield Rust + eBPF workspace** for a Linux runtime
security and observability platform. It hosts C/libbpf CO-RE sensors, a Rust
node agent, a typed rule DSL, an audit-only-by-default enforcement surface, a
fleet control plane with SPIFFE/OIDC identity, a React/TypeScript dashboard,
and root-owned systemd delivery.

This commit (task 1) only establishes the bounded workspace topology. **No
product code, no crate shells, no devenv/flake/preflight/protobuf files are
included yet** — those belong to later tasks (2-60) of the approved plan.

## Status

- Greenfield; the first commit on `feature/ebpf-runtime-security-observability`.
- XL plan, high risk, awaiting declared self-hosted / rootful CI runners for
  privileged sensor/enforcement/compatibility lanes.
- Deterministic lane works on any Linux 5.15+ box once the devenv/flake is
  added (task 2).
- Privileged lane is blocked locally on this host
  (`unprivileged_bpf_disabled=2`, `CapEff=0`); re-open the affected tasks on
  the declared runners.

## Directory layout (task-1 baseline)

| Path        | Purpose                                                                                   |
|-------------|-------------------------------------------------------------------------------------------|
| `bpf/`      | C/libbpf CO-RE sensor sources (`*.bpf.c`), `vmlinux.h`, generated skeletons (later task)  |
| `crates/`   | Rust workspace members (added by their owning later tasks, never as placeholders)         |
| `proto/`    | Versioned Protobuf / Buf schemas for events and control (task 6)                          |
| `web/`      | React + TypeScript + Vite dashboard (later tasks)                                        |
| `deploy/`   | Systemd unit, OCI bake definition, Helm chart (tasks 8, 49-51)                           |
| `tests/`    | Cross-crate integration / fixture suites                                                  |
| `bench/`    | Benchmark harness, raw samples, and the **versioned JSON schemas under `bench/schemas/`** that anchor every numeric constant (the schema is the only source of truth) |
| `scripts/`  | Preflight, validate-evidence, privileged-suite, etc. (tasks 3, 5, 7)                     |
| `schemas/`  | Hand-authored JSON Schemas (preflight, evidence, etc.)                                    |

There is **no nested Cargo workspace** and **no product logic** in task 1.

## Toolchain

- Rust pinned via `rust-toolchain.toml` to channel `1.95.0`
  (rustfmt, clippy, rust-analyzer, rust-src).
- Workspace resolver `2` (see `Cargo.toml`).
- Cargo metadata works today (`cargo metadata --no-deps --format-version 1`).

## Licensing & SPDX policy

The repository is dual-licensed under **Apache-2.0** (`LICENSE-APACHE`) **or
MIT** (`LICENSE-MIT`) at the user's option. User-space Rust code, the rule
DSL, the dashboard, and the agent that loads the BPF objects from outside the
kernel are MIT/Apache-2.0 dual-licensed, consistent with the Rust ecosystem.

### Kernel-side BPF SPDX policy

BPF programs that the kernel loads are governed by the kernel's BPF
licensing rules, **not** by this repository's `LICENSE-*` files. Per the
kernel's `Documentation/bpf/bpf_licensing.rst`
(https://docs.kernel.org/bpf/bpf_licensing.html):

> "LSM and TCP congestion control (struct_ops, as of Aug 2021) ... are required
> to be GPL compatible."

Concretely:

- **Tracing / kprobe / perf-event / raw-tracepoint / TP-btf programs** loaded
  into the kernel are permitted to use **any license** the verifier accepts
  (including `Dual MIT/Apache-2.0`). The kernel treats the program's
  `license` section as a string for non-GPL-only program types.
- **BPF LSM programs** (`BPF_PROG_TYPE_LSM`) and **TCP congestion-control
  `struct_ops`** programs are **required to be GPL-compatible** by the kernel
  verifier. Any LSM hook we add in `bpf/sensors/*.bpf.c` MUST therefore carry
  a GPL-compatible SPDX identifier (e.g. `SPDX-License-Identifier: GPL-2.0
  ONLY` or `GPL-2.0-or-later`). MIT/Apache-only is **not acceptable** for
  those program types and would be rejected at load time.
- **User-space Rust** (loader, agent, fleet, CLI, web build, schemas) stays
  under the dual `Apache-2.0 OR MIT` terms selected at the repo root.
- We **never** ship user-supplied runtime-compiled BPF. All BPF objects are
  built deterministically from `bpf/sensors/*.bpf.c` in CI (task 10).

This split is enforced by later quality gates (task 4) via SPDX-header
linting and the `bpf:build` task that scans every committed `.bpf.c`/`.h` for
a compatible SPDX identifier before declaring an LSM attach.

## Verification (task 1)

Acceptance commands and outputs are recorded in
`.omo/evidence/task-1-ebpf-runtime-security-observability.log`. They cover:

- `git rev-parse --is-inside-work-tree` → `true`
- `cargo metadata --no-deps --format-version 1` → exit 0
- `cargo fmt --all --check` → exit 0 (no Rust source yet, so trivially clean)
- `test -f LICENSE-APACHE -a -f LICENSE-MIT -a -d bpf -a -d web -a -d deploy` → exit 0
- Happy QA: `cargo metadata --format-version 1 | jq -e '.workspace_root | endswith("kernel-v1")'`
- Failure QA: temporarily add a nonexistent workspace member and assert
  `cargo metadata` fails, then restore.

## What this is NOT

This is a development/verification platform under active construction. It
does **not** claim production readiness, a published supported-load SLA,
universal BPF-program compatibility, or anything beyond the scope of the
approved Prometheus plan at `.omo/plans/ebpf-runtime-security-observability.md`.