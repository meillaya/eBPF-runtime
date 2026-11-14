<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Contributing to eBPF fleet

eBPF fleet is an early-stage project. Contributions that improve the
observability path, the tests, the documentation, and the operator
experience are welcome. This guide covers the DCO sign-off, the development
environment, the checks a change must pass, and how to propose a change.

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability. Do not
open a public issue for a security problem.

## Licensing of contributions

The repository is dual-licensed under Apache-2.0 OR MIT at the user's
option; see [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).
By submitting a contribution you agree to license it under those terms.

Kernel-loaded eBPF programs are a special case: they are governed by the
kernel's BPF licensing rules, not by the root `LICENSE-*` files. BPF LSM
programs and TCP congestion-control `struct_ops` programs must be
GPL-compatible and must carry a GPL-compatible SPDX identifier (for example
`GPL-2.0-only`). Do not relicense an existing BPF source file, and do not
add an MIT/Apache-2.0-only LSM program; the verifier rejects it at load
time. The current sensors in `bpf/sensors/` already carry
`SPDX-License-Identifier: GPL-2.0-only`.

## Sign your work (DCO)

Every commit must include a Developer Certificate of Origin 1.1 sign-off.
The full text is in [DCO](DCO). Sign off with `git commit -s`:

```bash
git commit -s -m "agent: describe the change"
```

The resulting trailer must match the commit author:

```text
Signed-off-by: Your Name <you@example.com>
```

Rules:

- Use the name and email address you want recorded in the project history.
- Add the sign-off to every commit in a pull request, not only the first.
- We do not require a CLA.
- If you forgot a sign-off, rewrite the branch before opening the pull
  request: `git rebase --signoff origin/main` for the branch, or
  `git commit --amend -s` for the last commit.
- Do not add a sign-off for another person.

Maintainers may ask you to reword or rebase a branch when a sign-off is
missing, mismatched, or implies a license the project cannot accept.

## Propose a change

1. Open an issue before a large change: a new crate, a control-plane API, a
   storage format, or anything touching the enforcement path. For a small
   fix, a pull request that explains the problem is enough.
2. Keep changes focused. One logical change per pull request; do not mix a
   refactor with a behavior change.
3. Write commit messages in the imperative mood and explain the why in the
   body. A scope prefix such as `agent:` or `control-plane:` is welcome.
4. Open the pull request against `main` and describe:

   - the problem and the approach;
   - the checks you ran;
   - any behavior change, new configuration, migration, or limitation.

Do not commit build output (`target/`, `web/dist/`), editor state, or
generated certificates.

## Development setup

The sensors target Linux and are tested on x86_64. Other components build on
other platforms, but loading sensors requires a Linux kernel with BTF.

Prerequisites for a full build:

- Linux 5.15 or newer with BTF mounted at `/sys/kernel/btf/vmlinux`;
- Nix with flakes enabled, or the equivalents of Rust 1.95 (pinned in
  `rust-toolchain.toml`), clang 19, bpftool, and Bun;
- root, or the BPF capabilities, to load sensors: `CAP_BPF`,
  `CAP_PERFMON`, and `CAP_SYS_ADMIN`;
- a rootful Podman or Docker daemon for the compose stack.

The supported entry point is the flake:

```bash
git clone https://github.com/meillaya/eBPF-runtime
cd eBPF-runtime
nix develop --no-pure-eval --accept-flake-config
```

If you use direnv, run `direnv allow` after entering the checkout. The
shell provides the pinned Rust toolchain, clang 19, bpftool, Bun, and the
native libraries the workspace needs.

Build the workspace and the sensors:

```bash
cargo build
cargo run -p bpf-build -- build
```

Build the dashboard:

```bash
cd web
bun install --frozen-lockfile
bun run build
```

The BPF loader needs privileges. Run the privileged sensor test with:

```bash
sudo -E scripts/run-privileged-tests.sh
```

The development compose stack is for evaluation only: it has no OIDC or
TLS, it binds loopback addresses, and it uses test-only settings. See
[the rootful compose runbook](docs/runbooks/rootful-compose.md).

## Required checks

Run the same checks as CI before opening or updating a pull request. From
the repository root inside `nix develop`:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p bpf-build -- build
(cd web && bun install --frozen-lockfile && bun run build)
nix shell nixpkgs#kubernetes-helm -c helm lint deploy/helm/ebpf-fleet
```

CI runs a PostgreSQL service and sets `DATABASE_URL`; integration tests that
need a database are skipped without it. To reproduce that path locally,
start a scratch database and export the URL before `cargo test`:

```bash
export DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/control
```

`DATABASE_URL` and `CLICKHOUSE_URL` enable the live test paths. Use
throwaway credentials and a scratch database; never point these variables at
shared data.

## Test expectations

- New behavior needs a test. A bug fix needs a test that fails before the
  fix.
- Prefer a focused unit test in the crate. Use the existing integration
  tests under `crates/*/tests/` when the behavior crosses a process, a
  kernel, or a service boundary. Tests that load BPF programs are marked
  `#[ignore]` and run as root.
- Do not weaken assertions, delete a failing test, or mark a failure
  `#[ignore]` just to get a green build. Explain any environment-dependent
  test in the pull request.
- Keep tests deterministic: no sleeps for synchronization, no reliance on
  wall-clock ordering, and no network access beyond the local test
  services.
- Tests must not require secrets. The keys and certificates under
  `crates/*/tests/fixtures/`, and the material that
  `scripts/gen-test-certs.sh` writes under `target/oidc`, are test-only and
  must never be used in a deployment. See [SECURITY.md](SECURITY.md).
- If a change needs a privileged, kernel, or multi-service setup that CI
  cannot run, document the manual verification and the exact commands you
  ran.

## Documentation and claims

- Update the README or the relevant `docs/` page when behavior,
  configuration, or a limitation changes.
- Record cross-cutting design decisions in `docs/decisions/`, operator
  procedures in `docs/runbooks/`, and reproducible evidence in
  `docs/verification/`.
- The sensors are read-only tracing. Do not describe the project as
  enforcing, blocking, or preventing activity while only the process and
  file sensors exist: the rule engine raises alerts, and a deny rule is
  rejected at load time. See [docs/positioning.md](docs/positioning.md) for
  the approved positioning sentence and the enforcement-claim gate.

## Review

A maintainer reviews every pull request, and CI must be green before a
merge. Reviewers check the tests, the DCO sign-offs, the SPDX headers on new
BPF sources, and that the change does not contradict the documented limits.
Keep the branch rebased on `main` while it is open, and be constructive in
review comments; a pull request is a discussion, not an audit.

## Questions

Open a GitHub issue for a usage question or a design discussion that is not
a security report. Do not use the security reporting channel for
non-security questions.
