---
slug: ebpf-runtime-security-observability
status: changes_requested_round_2
intent: clear
review_required: true
pending-action: apply round 2 fix-points (matrix, schema anchors, kill-switch contract, executable criteria, F4 inputs)
approach: Build a C CO-RE sensor suite and Rust node agent first around a versioned loss-accounted event ABI, then add typed rules/guarded LSM enforcement, standalone persistence/operator surfaces, and a SPIRE-authenticated central fleet path through gRPC, Kafka, PostgreSQL, and ClickHouse; finish with Docker/Kubernetes packaging, multi-kernel/multi-arch validation, comparisons, and a falsifiable sub-5% benchmark gate.
---

# Draft: ebpf-runtime-security-observability

## Components (topology ledger)
<!-- Lock the SHAPE before depth. One row per top-level component that can succeed or fail independently. -->
<!-- id | outcome (one line) | status: active|deferred | evidence path -->
| id | outcome | status | evidence path |
| --- | --- | --- | --- |
| C1 | Reproducible devenv/Nix-flake workspace, CI checks, release packaging, and compatibility probes | active | repository root is greenfield; https://devenv.sh/guides/using-with-flakes/ |
| C2 | CO-RE kernel sensors and a versioned event ABI for process, file, network, DNS, syscall-latency, and namespace/cgroup activity | active | https://docs.kernel.org/bpf/libbpf/libbpf_overview.html; https://www.kernel.org/doc/html/latest/bpf/ringbuf.html |
| C3 | Rust node and central event pipelines with bounded ingestion, enrichment/correlation, SQLite/Kafka/ClickHouse sinks, Prometheus metrics, and explicit end-to-end loss/lag accounting | active | https://www.kernel.org/doc/html/latest/bpf/ringbuf.html |
| C4 | Typed detection rules plus audit-first, fail-open eBPF LSM enforcement controls | active | https://docs.kernel.org/bpf/prog_lsm.html; https://falco.org/docs/concepts/rules/ |
| C5 | Fleet control plane and operator surfaces: SPIRE/OIDC identity, policy rollout, CLI, API/stream, and web dashboard for process trees, sockets, DNS, files, syscalls, alerts, agents, and drops | active | user decisions; https://spiffe.io/docs/latest/spire-about/use-cases/; https://grpc.io/docs/guides/flow-control/ |
| C6 | Host/Docker/Kubernetes attribution and deployment, privileged integration tests, comparative benchmarks, and measured overhead report | active | https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/; https://tetragon.io/docs/concepts/tracing-policy/ |

## Open assumptions (announced defaults)
<!-- Record any default you adopt instead of asking, so the user can veto it at the gate. -->
<!-- assumption | adopted default | rationale | reversible? -->
| assumption | adopted default | rationale | reversible? |
| --- | --- | --- | --- |
| Repository shape | Cargo workspace plus `bpf/`, `proto/`, `web/`, `deploy/`, `tests/`, and `bench/`; keep each Rust/TypeScript module under the project size ceiling through domain crates/modules | Separates kernel ABI, node hot path, control plane, UI, and privileged QA so they can be verified independently | yes |
| Kernel ABI | One C header is authoritative; generated Rust bindings are freshness-checked; envelope includes ABI version, record size, type, monotonic timestamp, sequence, CPU, pid/tgid, cgroup and namespace identity, flags, and bounded payload | Prevents unsafe ad-hoc casts and permits backward-compatible decode/reject behavior | no after first public release |
| Hook strategy | Prefer stable sched/syscall/socket tracepoints, BPF LSM, cgroup connect/SKB hooks, and BTF fentry/fexit; capability preflight selects classic TC on 5.15/6.1 and TCX only where available, while missing hooks produce named degraded coverage rather than kprobe guesses | Current libbpf docs deprecate legacy TC in favor of TCX, but the 5.15 support floor requires an explicit fallback matrix | yes as kernels age |
| Event semantics | Distinguish `ATTEMPT`, `RESULT`, `ESTABLISHED`, `DNS_PACKET`, `OWN_LSM_DENY`, `NO_RETURN`, and `ORPHAN_*`; publish an explicit per-kernel operation coverage matrix rather than generic “all file/network/syscall activity” claims | LSM/file hooks, connect hooks, DNS capture, and syscall enter/exit do not represent interchangeable or complete semantics | no after first public release |
| CO-RE contract | CO-RE relocates compatible BTF fields only; startup performs actual load/attach probes and `bpf_core_*_exists` branches, rejects missing/incompatible BTF, and exposes per-hook/per-field valid/degraded states on 5.15/6.1/6.6/current x86_64/arm64 | Internal function signatures, tracepoint arguments, namespace fields, and hook availability change independently of struct offsets | yes as kernels age |
| Delivery semantics | At-least-once from node outbox through gRPC/Kafka; deterministic `event_id` enables idempotent acknowledgement and ClickHouse deduplication; never claim global exactly-once | Survives disconnects without inventing distributed transactions | no after first public release |
| Policy lifecycle | PostgreSQL creates a monotonic, content-digested staged version; agents verify and load inactive maps, ACK `READY`, activate only on an idempotent `COMMIT(version,digest)`, then ACK `APPLIED`; reconnect reports actual active/staged versions, stale/replayed versions are rejected, and last-known-good remains active offline | Two-phase activation prevents a partially distributed policy from silently becoming enforcement truth | no after first public release |
| Enforcement surface | Deny actions are limited to explicitly supported LSM hook families (file access, binary exec, and socket connect); namespace/mount escape indicators remain alert-only until a separately proven hook is safe | Avoids turning heuristic detections into host-wide lockouts | yes through later audited extension |
| Enforcement lifecycle | Enforcement BPF links are never pinned and detach on loader death; observation maps/links may be pinned separately. A versioned BPF config map provides an immediate fail-open kill switch, and every hook preserves prior BPF-program `ret` while claiming only this project's own denial—not final decisions by SELinux/AppArmor/other LSMs | Pinned deny links or ambiguous LSM ordering can lock out a host after agent failure | no after first public release |
| Syscall latency | Aggregate configured syscall allowlists into kernel histograms and emit periodic summaries; do not stream every syscall by default | Required for the p99 overhead budget and bounded cardinality | yes |
| DNS/privacy | Decode DNS headers/questions/answers in user space from bounded TC/cgroup captures; no arbitrary packet payload retention and no plaintext secret capture | Meets observability needs without becoming packet surveillance | yes |
| Data minimization | Capture executable path and bounded argv (4 KiB maximum record payload), disable environment capture by default, apply configured path/argument redaction before local persistence or export, and expose truncation/redaction flags | Runtime telemetry commonly contains tokens and secrets; privacy must precede storage | yes |
| Storage retention | Standalone SQLite defaults to 24 hours or 4 GiB, Kafka to 24 hours, ClickHouse to 30 days; every limit is configurable and pressure is observable | Safe demo/production defaults with bounded disk use | yes |
| Outbox encryption | Use SQLCipher-v4-compatible SQLite with the key supplied before any DB access from a root-readable node key source, startup integrity checks, explicit WAL checkpoints, single-writer ownership, and a tested full-disk/long-reader bound | “Encrypted SQLite” is not satisfied by filesystem permissions or ad-hoc field encryption, and WAL can grow under blocked checkpoints | yes if an equivalent audited encrypted-store implementation replaces it |
| ClickHouse correctness | Preserve Kafka topic/partition/offset and deterministic `event_id`; ingest is at-least-once into a versioned ReplacingMergeTree-compatible schema, while correctness-sensitive queries use explicit dedup (`FINAL`/`argMax`) and malformed messages go to a DLQ | Background merges do not guarantee immediate duplicate removal | yes |
| Dashboard/API | Rust exposes versioned REST for history/control and WebSocket for live data; React/TypeScript/Vite renders process trees, socket/DNS/file/syscall views, alerts, drops, agents, and policy rollout | Browser should not speak privileged agent gRPC directly | yes |
| Fleet protocol | Separate long-lived gRPC control and event streams bind every message to SPIFFE agent ID, cluster, node boot ID, agent generation, monotonic sequence, schema version, batch ID, and deadline; an event batch is ACKed only after durable Kafka acceptance | Prevents telemetry congestion from blocking policy/kill-switch traffic and makes reconnect/replay testable | no after first public release |
| Agent identity lifecycle | Consume complete X.509-SVID/bundle updates from the SPIFFE Workload API over a protected Unix socket, keep the update stream open, immediately replace/redact prior material on each response, rebuild gRPC credentials before expiry, and reject SPIFFE IDs outside the registered node/agent selector policy | A cached certificate file or trust-domain string check bypasses SPIRE's attested workload contract | no after first public release |
| Human authorization | OIDC authorization-code + PKCE for the web UI and RFC 8628 device flow where supported for CLI; validate issuer/signature/audience/expiry/nonce, enforce RBAC in the Rust service, and use PostgreSQL roles/RLS only as defense-in-depth | Prevents token replay/confusion and avoids database-owner-sensitive RLS as the sole boundary | no after first public release |
| Authorization audit | Every mutation writes an append-only audit record in the same PostgreSQL transaction with actor, request ID, action, object/version, before/after digest, outcome, and time; PostgreSQL notifications are hints only and clients re-read authoritative state | Makes policy/RBAC changes reconstructable across retries and failover | no after first public release |
| Dependencies | SPIRE, OIDC provider, PostgreSQL, Kafka, and ClickHouse are external production services; local Docker Compose/Kubernetes test profiles may install pinned ephemeral instances, but the product does not operate them | Keeps the control plane focused and avoids bespoke identity/consensus/data systems | yes |
| Host/Kubernetes privilege | Host install uses a static root-owned service/loader with a bounded capability set and drops unnecessary privileges after attach; Kubernetes defaults to `privileged: false` plus probed `BPF`, `PERFMON`, `NET_ADMIN`, `SYS_RESOURCE` and read-only host mounts, with a separate documented privileged compatibility profile. Never use `procMount: Unmasked`; mount host `/proc` read-only at `/host/proc` and keep `hostPID: false` unless an evidenced feature requires it | Full privileged mode and pinned deny links unnecessarily enlarge the trusted computing base; Kubernetes namespace constraints vary by release | yes as kernel/runtime capability support evolves |
| Preflight evidence | A read-only machine-readable preflight uses actual BPF load/attach probes where privileges permit and reports kernel/BTF/LSM/cgroup/arch/hook/capability/runtime coverage with exit codes `0` capable, `2` degraded, `77` blocked; it never silently falls back or mutates the host | Mirrors the established sibling-project convention and makes support claims inspectable | yes |
| Tenancy | One organization spanning multiple clusters with RBAC and cluster scoping; no SaaS tenant billing or adversarial multi-tenant isolation promise | The request is a production agent, not a hosted SaaS | yes |
| Compatibility | cgroup v1 and v2 attribution adapters are tested on Linux 5.15+; gVisor/Kata guest-process visibility and Windows/macOS sensors are unsupported and reported explicitly | Matches the chosen Linux support promise without pretending host eBPF can see into every VM sandbox | yes |
| Loss SLO | Security-critical synthetic events must have zero loss inside a published supported-load envelope; deliberate saturation is expected to shed but must produce independently polled monotonic kernel/user/outbox/Kafka drop or lag evidence with visible sequence gaps. No unbounded “lossless” claim | Ring-buffer reservations fail non-blockingly and an in-stream loss notice can itself be lost | no after first benchmark contract |
| Benchmark admissibility | The sub-5% claim requires paired randomized no-agent/observe/enforce runs, fixed warmup and sample size, raw percentile/throughput/resource data, confidence intervals, declared outlier handling, pinned environment hashes, an anti-limiter/frozen-agent control, and identical workloads for strace/auditd/Falco comparison | Prevents cherry-picked means, hidden tail regressions, and misleading success logs | no after first public claim |

## Findings (cited - path:lines)
- Repository state: `/home/mei/projects/kernels/kernel-v1` contains no product files; this is a greenfield architecture with no conventions or migrations to preserve.
- Kernel ring buffer: one MPSC `BPF_MAP_TYPE_RINGBUF` preserves cross-CPU temporal ordering, uses non-blocking reservations, and requires explicit failed-reservation/drop accounting; map size must be a power of two. Source: https://www.kernel.org/doc/html/latest/bpf/ringbuf.html.
- CO-RE: BTF plus loader relocations allow one object to adapt field offsets across compatible kernels; libbpf embeds BPF bytecode in generated skeletons and the kernel docs recommend libbpf-rs rather than direct bindings for Rust user space. Source: https://docs.kernel.org/bpf/libbpf/libbpf_overview.html and https://docs.kernel.org/bpf/btf.html.
- Aya is a viable all-Rust alternative with BTF/CO-RE, ring buffers, tracepoints, cgroup programs, fentry/fexit, and LSM support; its ring buffer requires Linux 5.8 or newer. Sources: https://aya-rs.dev/book/, https://docs.rs/aya/latest/aya/programs/index.html, https://docs.rs/aya/latest/aya/maps/ring_buf/struct.RingBuf.html.
- BPF LSM hooks can audit or return an errno to deny; they are privileged system-wide MAC hooks, use BTF-defined contexts, and compose with prior LSM return values. Enforcement therefore needs an explicit fail-open/audit-first control plane and must never become default-on. Source: https://docs.kernel.org/bpf/prog_lsm.html.
- Kubernetes node-wide agents map naturally to a DaemonSet; runtime metadata cannot assume Docker/dockershim and must key attribution through cgroups/namespaces plus CRI/containerd-compatible enrichment. Sources: https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/ and https://kubernetes.io/docs/tasks/administer-cluster/migrating-from-dockershim/migrating-telemetry-and-security-agents/.
- A production rule surface should provide versioning, reusable lists/macros, exceptions, tags, and engine compatibility checks; Falco uses this model, while Tetragon warns that low-level kernel policies can introduce TOCTOU issues. Sources: https://falco.org/docs/concepts/rules/ and https://tetragon.io/docs/concepts/tracing-policy/.
- devenv supports Rust toolchains, packages, DAG tasks, tests, containers, and pinned inputs; its official docs recommend the dedicated CLI for full functionality while flakes can expose the same module as a `devShell`. Sources: https://devenv.sh/, https://devenv.sh/tasks/, https://devenv.sh/guides/using-with-flakes/.
- Context7 documentation lookup was attempted but unavailable because the connected service quota is exhausted; primary official documentation was used instead.
- Local execution host is CachyOS on Linux `7.1.3-2-cachyos`, x86_64/AMD Ryzen 7 5700X, with kernel BTF at `/sys/kernel/btf/vmlinux`, active `bpf` LSM, cgroup v2, `CONFIG_BPF_LSM`, ftrace/kprobe/perf support, JIT enabled, and kernel headers installed. It is a suitable privileged development and benchmark host.
- The current user has no effective capabilities, unprivileged BPF is disabled, `/sys/fs/bpf` is root-only, and passwordless sudo is unavailable. Development/QA must therefore use an explicit root-owned systemd service, approved sudo invocation, or rootful VM/CI runner; tests must never assume ordinary unprivileged loading.
- Installed local toolchain includes Clang/LLVM 22.1.8, bpftool 7.8.0, libbpf 1.7/1.8, Rust 1.95+, Cargo, Nix flakes/devenv, Docker/Kubernetes tooling, and 62 GiB RAM. Sibling projects provide C/libbpf conventions, while this repository has no prior Aya code.
- Kernel event attribution must treat `(boot_id, cgroup_id, pid/tgid, process_start_time, namespace inode tuple)` as raw identity and perform asynchronous CRI/Kubernetes enrichment; a PID, cgroup path, container name, or Kubernetes namespace is never sufficient alone. Sources: Linux cgroup/namespace contracts and Kubernetes CRI API, corroborated by Tetragon/Falco/Tracee architectures.
- Process fork/exec/exit ordering favors a shared MPSC ring buffer; every reserve failure must increment a per-event/per-reason BPF counter because ring buffers do not emit an automatic loss record. Bounded user-space channels, encrypted node outbox, Kafka acknowledgements, and ClickHouse ingestion each need independent lag/drop metrics.
- DNS is application-protocol decoding, not a syscall fact: capture bounded packet metadata at TC/cgroup socket hooks, decode DNS safely in user space, cap names/record counts, mark truncation, and never retain arbitrary payloads by default.
- SPIRE requires server, per-node agent, node/workload attestation, registration, and Workload API consumption; it provides short-lived automatically rotated X.509-SVIDs suitable for mTLS. Source: https://spiffe.io/docs/latest/spire-about/use-cases/.
- gRPC transport flow control protects a streaming receiver from a faster sender but application writes may block and manual symmetric write-without-read patterns can deadlock; protocol tasks therefore need independent read/write loops, bounded queues, deadlines, health, and explicit application-level batch ACKs. Source: https://grpc.io/docs/guides/flow-control/.
- ClickHouse's Kafka table engine is at-least-once and can duplicate after insert-before-offset-commit failures or rebalances; materialized views persist to MergeTree tables, and consumer count cannot exceed topic partitions. The plan must preserve topic/partition/offset plus deterministic event IDs and prove deduplication rather than claim exactly-once. Source: https://clickhouse.com/docs/integrations/kafka/kafka-table-engine.
- PostgreSQL row-level security can default-deny once enabled but owners/superusers normally bypass it and policy subqueries can race; control-plane authorization must be enforced in the Rust service as the primary boundary, with database roles/RLS as defense-in-depth and explicit tests for bypass paths. Source: https://www.postgresql.org/docs/current/ddl-rowsecurity.html.
- Independent workspace verification proved that the local host can generate `vmlinux.h`, compile a C CO-RE object with Clang's BPF target, and build a vendored `libbpf-rs` crate. It also found that the Docker CLI is installed but the daemon is not running, and `kind`/`minikube`/QEMU are absent; privileged/Kubernetes/kernel-matrix QA therefore needs devenv-provided tools and/or dedicated runners rather than assuming this shell is ready.
- Kernel-version verification found stable sched fork/exec hooks but a changed `sched_process_exit` argument shape in current kernels, internal function signature drift such as `inet_csk_accept`, namespace-field changes, and only conditional BPF LSM availability. CO-RE cannot make absent fields/hooks or changed semantics stable; actual load/attach probes and per-field validity bits are mandatory.
- BPF LSM programs can authoritatively report their own deny result but generally cannot claim the final decision of another LSM because hook ordering and short-circuit behavior can prevent or precede observation. Scope and event names must distinguish `OWN_LSM_DENY` from syscall errno with unknown deny source.
- File, network, DNS, and syscall hooks are semantically narrower than generic labels: file open is not complete file activity, cgroup connect is an attempt not a final connection result, DNS packet parsing is not a DNS lookup, and syscalls such as successful exec/exit_group do not produce normal exit-latency pairs. The public schema and dashboard must preserve these distinctions.

## Decisions (with rationale)
- Topology: lock the six proposed independently verifiable components (C1-C6); user approved the recommended boundary.
- eBPF implementation: C CO-RE programs loaded from Rust through libbpf-rs/libbpf-cargo skeletons; user chose the kernel-documented mature path over all-Rust Aya.
- Persistence: SQLite WAL is the embedded node/local event store and outbox, Prometheus is metrics-only, and ClickHouse is optional in standalone mode but required as the fleet-history store when the selected Kafka-backed central control plane is enabled; the user chose this over mandatory ClickHouse for every installation or SQLite-only operation.
- Enforcement: include real eBPF LSM deny actions only behind audit-by-default, explicit global opt-in plus per-rule deny action, compatibility preflight, fail-open uncertainty handling, complete decision telemetry, and an immediate kill switch.
- Compatibility: publish Linux 5.15+ with kernel BTF as the base contract, test representative 5.15/6.1/6.6/current kernels, build x86_64 and arm64, and report unsupported/degraded hooks instead of silently losing coverage.
- Verification: use contract-first TDD for the event ABI, decoders, rules, storage, and APIs; pair each built probe/deployment with real privileged kernel/VM/Kubernetes tests.
- Dashboard: ship a purpose-built React/TypeScript live UI backed by the Rust API rather than Grafana-only dashboards.
- Rule surface: define a versioned, JSON-Schema-backed native YAML DSL with typed fields, predicates, reusable lists, exceptions, sequence windows, severity/tags, and audit/deny actions; explicitly do not claim Falco syntax compatibility.
- Fleet shape: include a full central control plane for agent enrollment, event ingestion, policy distribution, fleet query, and dashboard operation, while retaining standalone node-local mode.
- Agent identity: require SPIFFE/SPIRE node/workload attestation and automatically rotated short-lived X.509-SVIDs; the project integrates with SPIRE rather than owning a bespoke CA.
- Human access: implement provider-neutral OIDC discovery plus CLI device authorization where supported, with server-side RBAC roles (`viewer`, `analyst`, `policy-admin`, `admin`) and a loopback-only no-auth development mode.
- Fleet data path: agents use bidirectional gRPC over mTLS, retain a bounded encrypted SQLite outbox for disconnects, the control plane acknowledges idempotent batches and publishes to Kafka, and ClickHouse consumes validated events through a controlled ingestion layer. Direct agent-to-ClickHouse credentials are forbidden.
- Central state: PostgreSQL is authoritative for agents, SPIFFE identity references, policy versions and rollout acknowledgements, OIDC group-to-role mappings, configuration, and append-only administrative audit records. The control plane remains stateless and horizontally scalable above PostgreSQL; it does not implement custom consensus.
- Licensing: user-space Rust, TypeScript, and operational assets use `Apache-2.0 OR MIT`; C eBPF sources that attach to LSM hooks or call kfuncs use `GPL-2.0-only`, with SPDX headers and generated third-party notices.
- Performance claim: release/resume wording may say “sub-5%” only when repeatable controlled runs show both p99 latency increase and throughput decrease below 5% against no-agent baseline across defined CPU, file-I/O, network, and container workloads; security-critical synthetic events must have zero observed loss, bulk loss must be measured, and raw machine-readable results must be published.

## Scope IN
- Reproducible greenfield bootstrap: Git repository, Cargo workspace, pinned Rust/Clang/LLVM/libbpf/bpftool/Bun toolchains, `devenv.yaml`, `devenv.nix`, lockfiles, `flake.nix`, format/lint/license/supply-chain checks, CI, and deterministic generated artifacts.
- C/libbpf CO-RE sensors for process fork/exec/exit, file open/write-intent and mutations, connect/accept/state changes, bounded DNS capture, selected syscall latency, credential/capability changes, cgroup/namespace activity, and supported BPF LSM audit/deny hooks.
- Versioned C-to-Rust kernel event ABI, ring-buffer ingestion, explicit per-reason loss counters, compatibility preflight, attach/degrade matrix, bpffs lifecycle, graceful detach, and verifier diagnostics.
- Rust node agent: bounded pipeline, raw-to-normalized parsing, process/socket/DNS/container correlation, CRI/containerd/CRI-O/Docker adapters, Kubernetes API enrichment, Prometheus metrics, structured logs, health/readiness, and encrypted SQLite WAL/outbox.
- Typed YAML rule engine with JSON Schema, semantic validation, lists, exceptions, event predicates, temporal sequences, severity/tags, test fixtures, sensitive-file/reverse-shell/container-escape rules, and complete alert/enforcement decision records.
- Guarded eBPF LSM enforcement: audit-only default, explicit global and per-rule opt-in, fail-open uncertainty handling, staged/atomic map updates, stale-policy rejection, last-known-good offline behavior, local/global kill switch, rollback, and negative-path tests that prove ordinary host operations remain available.
- Standalone and fleet modes: protobuf/gRPC APIs, SPIFFE/SPIRE mTLS identity, OIDC/RBAC, PostgreSQL control state and audit trail, policy rollout/ACK, Kafka event bus, ClickHouse ingestion/query/retention, backpressure, replay/idempotency, disconnect/reconnect, and multi-cluster scoping.
- Operator experience: Rust CLI for status/events/process tree/sockets/DNS/files/syscall latency/alerts/rules/policy rollout; built-in React/TypeScript dashboard with live and historical views; loopback-only local mode and authenticated fleet mode.
- Delivery: root-owned systemd host service, standalone Docker image/Compose profile, multi-arch OCI images, Kubernetes Helm chart with DaemonSet and control-plane Deployments, feature-probed capability-minimized and documented privileged profiles, external-service integration values, upgrades/rollbacks, and supply-chain artifacts/SBOM/provenance.
- Verification: contract-first unit/property tests, C/Rust ABI checks, BPF compile/verifier tests, privileged kernel/VM tests on representative 5.15/6.1/6.6/current x86_64 and arm64, Docker/CRI/Kubernetes e2e, policy/enforcement fault injection, OIDC/RBAC/security tests, Kafka/PostgreSQL/ClickHouse durability tests, frontend/browser tests, loss saturation tests, and raw evidence artifacts.
- Benchmark/report suite comparing no-agent, observe mode, enforce mode, `strace`, `auditd`, and Falco-style tracing on defined CPU/file/network/container workloads; report p50/p95/p99/p99.9 latency, throughput, CPU, RSS, event rate, loss, environment, warmup/sample method, and confidence intervals. Publish the sub-5% resume bullet only if the chosen gate passes.

## Scope OUT (Must NOT have)
- No Windows/macOS sensor, kernel module, custom kernel patch, runtime source compilation on target nodes, or support promise below Linux 5.15 with readable compatible BTF.
- No arbitrary packet capture, TLS/plaintext secret inspection, command stdout/stderr capture, keystroke logging, or unbounded argument/environment collection.
- No default-on or default-deny enforcement, no deny action sourced from heuristic-only enrichment, no silent fail-closed behavior, no remote command execution/shell feature, and no claim that eBPF replaces SELinux/AppArmor/seccomp/network policy.
- No Falco rule-syntax compatibility claim, no general-purpose policy programming language, no arbitrary kernel hook supplied by users, and no kernel-side dynamic expression compiler.
- No bespoke certificate authority, OIDC provider, relational database, Kafka broker, ClickHouse cluster, consensus algorithm, Kubernetes distribution, or container runtime implementation; integrations and ephemeral test deployments only.
- No direct agent database credentials, no direct browser-to-node privileged API, no unauthenticated non-loopback listener, and no long-lived static agent/user token path in production mode.
- No exactly-once global delivery claim, no invisible event loss, no silently repaired or guessed container attribution, and no mutable historical event rewrite; duplicates and unknown attribution remain explicit.
- No generic “complete file access,” “DNS lookup,” “all syscall latency,” or “final LSM denial” event whose underlying hook cannot prove that semantic; coverage, no-return/orphan pairs, truncation, and unknown deny source remain explicit.
- No multi-region active-active disaster recovery, SaaS billing/tenant administration, machine-learning anomaly detection, automated remediation beyond the explicitly supported LSM deny surface, or broad endpoint-management/control-plane features.
- No claim of guest-process visibility for VM-isolated runtimes such as Kata/gVisor where host hooks expose only the sandbox boundary; compatibility output must state the limitation.

## Open questions
- None. All owner-level forks are resolved; announced defaults above remain vetoable at the approval gate.

## Approval gate
status: changes_requested_round_2
approved-action: round 1 returned CHANGES REQUIRED; round 2 returned CHANGES REQUIRED with overlapping matrix, schema, kill-switch, F4, and executable-criteria fix-points; user must either request another review round or directly approve before implementation.
plan_path: .omo/plans/ebpf-runtime-security-observability.md
plan_sha256: <sha256-of-revised-plan>
review_round_id: round-2026-07-20-ebpf-runtime-security-observability-2
round_status: changes_requested_round_2
next-action: apply round 2 fix-points and request a fresh review round, or proceed if user confirms.
review:
  momus_round2:
    status: changes_requested
    workspace_root: /home/mei/projects/kernels/kernel-v1
    runtime_home: null
    target: .omo/plans/ebpf-runtime-security-observability.md
    round_id: round-2026-07-20-ebpf-runtime-security-observability-2
    launch_id: momus-launch-2
    session: ses_07d515496ffeCzYQbvRGmxyIaq
    findings:
      - F1-F4 now have role/input/executable/pass/fail/evidence-path
      - Sub-5% gate is encoded as paired p99+throughput upper 95% CI bound
      - Dependency matrix rows 2,3,4,5,37 contradict in-task Blocks/Blocked by text
      - Magic numbers in tasks 17,24,25,26,30-33,40,45,54,60 are not all schema-anchored
      - 5-second kill-switch has no schema anchor and no source-rationale
      - F1 input excludes .png evidence paths
      - F4 hardcoded list omits several guardrails and the `hostPID: true` check is overly strict
      - Duplicate machine TL;DR follows the human TL;DR
    result: CHANGES REQUIRED
  oracle_round2:
    status: changes_requested
    workspace_root: /home/mei/projects/kernels/kernel-v1
    runtime_home: null
    target: .omo/plans/ebpf-runtime-security-observability.md
    round_id: round-2026-07-20-ebpf-runtime-security-observability-2
    launch_id: independent-launch-2
    session: ses_07d514352ffeK74APoW6gLPZ6L
    findings:
      - Same dependency matrix contradictions (rows 2,3,4,5,37)
      - Same unanchored numeric constants and YAML-vs-JSON-schema conflict
      - Same kill-switch contract gap
      - Same F4 input scope and guardrail completeness gap
      - F4 hard `hostPID: true` rejection conflicts with scoped guardrail allowance
      - Compatibility success-criterion text conflicts with plan body
      - Many acceptance criteria and QA scenarios still fixture-only prose without exact commands
    result: CHANGES REQUIRED
round2-fix-points-to-apply:
  - "Reconcile dependency matrix rows 2,3,4,5,37 with in-task Blocks/Blocked by text; add F1-F4 dependency rows + Parallelization text"
  - "Reanchor every magic number in tasks 17,24,25,26,30-33,40,45,54,60 (and F1-F4) under bench/schemas/*.v1.json; replace supported-load.yaml with bench/schemas/supported-load.v1.json#default_rate"
  - "Add bench/schemas/enforcement.v1.json#kill_switch_max_ms default 5000 with source-rationale; reference from tasks 33,34,54,F3"
  - "Expand F1 input to every evidence extension listed in the plan; expand F4 input to full source/manifest; derive F4 guardrail list from `## Must NOT have`; change F4 hostPID to reject without evidence"
  - "Remove the duplicate machine TL;DR that follows the human TL;DR; reconcile the compatibility success-criterion text with the body"
  - "Replace fixture-only prose acceptance criteria/QA scenarios in tasks 12-18, 21-23, 28-43 with exact devenv/cargo nextest/privileged-runner/script invocations, expected exit, and artifact name"
approach: Bootstrap the reproducible workspace and evidence contracts; build/version/test the C CO-RE ABI and sensors; implement the bounded Rust node pipeline, local encrypted store, correlation and typed rules; add guarded two-phase LSM enforcement; implement the SPIRE/OIDC/PostgreSQL/gRPC/Kafka/ClickHouse fleet path; deliver CLI/dashboard/systemd/Docker/Helm packaging; close with the privileged compatibility, failure-injection, comparative, and sub-5% benchmark gates.
review-offer-after-plan: true
