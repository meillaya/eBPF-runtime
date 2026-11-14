<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Positioning

- Status: approved
- Applies to: the 0.2 fleet line and all public material

## Approved public sentence

> eBPF fleet: record Linux kernel activity once, query it locally, replay it anywhere, and roll policy across the fleet.

Use this sentence verbatim as the one-line description in the GitHub
repository description, release notes, talk abstracts, and the top of the
README. Do not reword, extend, or add claims to it. The rest of the public
material expands it; nothing may contradict it.

## README hierarchy and message levels

The README is the canonical expansion of the approved sentence. It sits in
a hierarchy of message levels: each level may repeat or narrow the claims of
the level below it, but no level may widen a claim, and the more specific
level wins.

| Level | Where it lives | Job |
| --- | --- | --- |
| 1. Positioning | This page; GitHub repository description | The approved sentence, and only that sentence. |
| 2. README lead | `README.md` title and opening paragraphs | Name the product and expand the sentence into the pipeline: sensors, local store, control plane, dashboard, relay. |
| 3. README body | `README.md` sections: How it fits together, Control plane and policies, Dashboard, Deployment, Commands, Limits, Build and test | Explain the mechanics, commands, verification, and limits. |
| 4. Detailed docs | `docs/decisions/` (why), `docs/runbooks/` (how to operate), `docs/verification/` (evidence), plus `docs/figures/` for diagrams | Record decisions, procedures, and measured evidence. |

Rules for all levels:

- The README lead is the only place that expands the product one-liner; the
  sentence above is the only approved tagline. Do not add a second one.
- `README.md#limits` is authoritative for what the project does not do. If
  a README section, a talk, or a doc conflicts with it, the limits win.
- Every public claim should be traceable to the README or to a
  `docs/decisions/` or `docs/verification/` document.
- Auxiliary READMEs (`crates/event-abi/fuzz/README.md` and
  `crates/rules/fuzz/README.md`) are fuzzing notes only; they do not carry
  product claims.
- Write the same product name everywhere: `eBPF fleet` in prose and in the
  root README title, `ebpf-*` only for binary names.

## What the project can claim today

The only producers are the process lifecycle sensor (fork, exec, exit) and
the file activity sensor (open, create, unlink, rename, truncate). Both are
read-only tracing programs. On top of them the project can truthfully claim:

- records process and file activity from the kernel once per node;
- decodes the events and stores them locally in an encrypted SQLCipher
  database;
- queries that local data through the agent's loopback API;
- ships committed batches to a control plane that commits to PostgreSQL
  before acknowledging, and projects them to Kafka and ClickHouse;
- replays the recorded data through the dashboard, the HTTP API, and the
  CLI (`ebpfctl`);
- evaluates YAML rules and raises alerts;
- stages, commits, and rolls policy configuration across the fleet with
  acknowledgements and rollback;
- redacts configured path prefixes and secrets before storage.

"Policy" in this project means the rule configuration that the control
plane stages, commits, and rolls out to agents. It is not kernel
enforcement.

## The enforcement-claim gate

Do not claim that the project enforces, blocks, prevents, stops, or
mitigates activity until an eBPF LSM producer actually exists in `bpf/` and
is documented and tested. For network claims, a network producer must exist
as well. The ABI defines network, DNS, syscall, identity, and LSM records,
but no BPF program emits them. A deny rule is rejected at load time. The
current sensors are read-only, and the README says so.

Until the gate is lifted, public material must use observation language:

| Avoid | Use instead |
| --- | --- |
| blocks malicious syscalls | records syscall-related activity and raises alerts |
| enforces network policy | observes process and file activity; network producers do not exist yet |
| prevents data exfiltration | records file and process activity for later query and alerting |
| stops privilege escalation | detects and alerts on rule matches |
| LSM security enforcement | the ABI defines an LSM record type; no LSM producer exists yet |
| EDR, antivirus, or prevention platform | kernel activity recorder, local query surface, and fleet policy rollout |
| production-ready enterprise security control | early-stage observability and policy-distribution platform |
| blocks or kills processes | raises alerts for a human or an external system to act on |

The gate is lifted only when all of these are true:

1. at least one LSM producer is committed under `bpf/`, attached, and
   covered by tests, and a network producer exists for network claims;
2. the loader, agent, and control plane have a documented enforcement
   decision path, including failure behavior;
3. the change is recorded in `docs/decisions/` and this page is updated;
4. the README lead, `README.md#limits`, and the runbooks agree with the new
   claim.

Kernel LSM programs must be GPL-compatible and must carry a
GPL-compatible SPDX identifier (for example `GPL-2.0-only`). The
contributor rules in [CONTRIBUTING.md](../CONTRIBUTING.md) apply.

## Hard rules for public material

- Do not claim production readiness, a supported-load SLA, universal
  kernel compatibility, or features that exist only in the ABI. The README
  limits are the source of truth.
- Do not present the development compose stack (loopback-only, no OIDC, no
  TLS) as a secure deployment.
- Do not describe test certificates or test passwords as production
  material; see [SECURITY.md](../SECURITY.md).
- Keep the approved sentence exactly as written; it is the only public
  one-liner.
- When a claim in this document and the code disagree, the code and the
  verification evidence win, and this document must be fixed.

## Review checklist

Before publishing a README change, release note, talk abstract, or website
copy:

- [ ] The approved sentence appears verbatim where a one-liner is needed.
- [ ] No phrase from the enforcement-claim table claims a capability the
      project does not have.
- [ ] Links point into [README.md](../README.md),
      [docs/decisions/](decisions/), [docs/runbooks/](runbooks/), or
      [docs/verification/](verification/).
- [ ] The material does not contradict [README.md#limits](../README.md#limits).
