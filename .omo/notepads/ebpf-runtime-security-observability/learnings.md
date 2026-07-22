# Learnings — eBPF Runtime Security & Observability

## Task 30: Sensitive-file access rule pack

### Rule schema constraints (schemas/rule-v1.schema.json)
- `schema_version` must be exactly 1 (semantic validator enforces).
- `engine_version` must share major version with engine and not be newer (currently "1.0.0").
- `deny` action is ONLY permitted when ALL condition fields are kernel-observable (`kernel_observable: true` in fields.rs catalog). `enrichment.*` fields are NOT kernel-observable and will cause `DenyOnHeuristicOnly` rejection.
- List names must be globally unique across the entire ruleset (not per-rule). Two rules cannot share a list name.
- The semantic validator checks `in`/`not_in` values as `Value::Array` — list-name string references in condition values are rejected at validation time (list resolution happens only at evaluation time in the predicate evaluator). Therefore, conditions must inline array values; lists serve as documentation/configuration reference.
- Condition nesting depth is bounded by `max_nested_expressions` (default 16).

### Field catalog (crates/rules/src/fields.rs)
- File sensor fields: `file.path` (String, kernel-observable), `file.kind` (String, kernel-observable).
- `file.kind` values match the Kind enum string representations: `FileOpen`, `FileCreate`, `FileUnlink`, `FileRename`, `FileTruncate`.
- Identity fields (`identity.cgroup_id`, `identity.ns_mnt`, `identity.ns_pid`, `identity.ns_net`, `identity.ns_user`) are all Integer and kernel-observable.
- Process fields: `process.exec_path` (String), `process.argv` (Array), `process.pid`/`process.uid`/`process.gid` (Integer) — all kernel-observable.

### Predicate evaluator null/unknown handling (crates/rules/src/predicates/event.rs)
- Event has three field states: present (in `fields`), null (in `null_fields`), unknown (in neither).
- Both null and unknown resolve to `None` via `Event::lookup()`, and a leaf predicate over a missing value is a non-match (`false`).
- This is the mechanism that prevents rules from firing on truncated/unresolved paths: if the file sensor (task 12) marks `file.path` as null (truncated) or the field is unknown (syscall fallback without path resolution), the rule condition evaluates to false. No explicit "validity flag" field is needed in the rule — the Event structure handles it.

### Exception evaluation
- Exceptions are part of the Rule AST (`exceptions: Vec<Exception>`) but are NOT evaluated by the predicate evaluator (`PredicateEvaluator::evaluate_condition` only evaluates `Condition` trees).
- The bench script must evaluate exceptions separately: construct a leaf condition from each exception's {field, operator, value} and evaluate it against the event. If any exception matches, the rule is suppressed.
- Each exception is a valid leaf condition and can be passed directly to `predicates-cli evaluate`.

### Fixture design for precision/recall
- Fixture format: `{"name", "description", "event": {"fields", "null_fields"}, "expect": {"match", "rule_id", "action"}}`.
- For precision=1.0 and recall=1.0: every fixture must be correctly classified (no FP, no FN).
- "Allowed read" fixture: use a non-sensitive path with FileOpen (no rule fires because path doesn't match).
- "Truncated path" fixture: put `file.path` in `null_fields` (evaluator returns non-match).
- "Unknown path" fixture: omit `file.path` from both `fields` and `null_fields` (evaluator returns non-match).
- Exception fixtures: include `process.exec_path` matching a package manager or config management tool.

### Bench script pattern
- The `fixture_min_precision_and_recall` property does not exist in `bench/schemas/rule-budget.v1.json` yet; the bench script reads it with `jq -r '.properties.fixture_min_precision_and_recall.default // 1.0'` (fallback to 1.0).
- The bench script uses `rules-cli parse` to get the ruleset as JSON, then `predicates-cli evaluate` for each rule's condition and exceptions against each fixture event.
- Precision/recall computed with awk for floating-point; threshold comparison also via awk.

### Safety invariants enforced by rule design
- No broad path prefix (/etc) is ever denied — only specific sensitive files and directories.
- FileOpen gets `alert` (not `deny`) because it may be a read-only open.
- FileRename/FileUnlink get `deny` because they are unambiguously destructive.
- Deny conditions reference ONLY kernel-observable fields (file.path, file.kind) — never enrichment data.
- Null/unknown file.path → non-match, so syscall-fallback events with unresolved paths never trigger deny.

## Task 31: Reverse-shell behavior rule pack

### Sequence engine (crates/rules/src/sequences.rs) is the detection core
- A reverse shell is detected as a bounded ORDERED sequence (shell exec → socket connect → stdio dup2/dup3), NOT as any single shell+network coincidence. The rule declares `sequences:` (schema `$defs/sequence`: name, steps[], window_seconds); each `step` is a SINGLE field predicate {field, operator, value} (scoped operator subset).
- `SequenceEvaluator` matches steps as an ordered SUBSEQUENCE: non-matching interleaved events are skipped, but steps must be satisfied in order. `sequences-cli replay <events.json> --sequences <seq.json>` resets state and processes a `Vec<Event>`, emitting a `SequenceMatch` per event: {sequence_name, group_key, steps[], completed, uncertain}.
- A rule FIRES only when a SequenceMatch has `completed==true AND uncertain==false`. Uncertain (missing/late/out-of-order step, or a step beyond `started_at + window_seconds`) NEVER fires — this is the gap/loss-attribution safety invariant. Once completed, a sequence stays completed (late events after completion re-emit completed, never flip to uncertain).
- Group key is extracted from the EVENT (priority: `process.generation` u64 → `container.id` String → `socket.inode` u64 → Custom("default")). NEVER a bare PID. All steps must share one group key, which ties exec/connect/dup to one process lineage.
- Ordering/windowing uses the monotonic `ts` field (Integer seconds) read from the event; `event.id` (String) is captured per matched step as the evidence explanation. `ts`, `process.generation`, `event.id`, `container.id`, `socket.inode` are read directly from events and are NOT rule predicates.

### CRITICAL: sequence steps ARE validated against the field catalog
- `validate_rule` (crates/rules/src/validate.rs:71-82) validates EVERY sequence step field against `default_field_catalog()`, exactly like conditions and exceptions. So steps may only reference catalog fields: process.exec_path/argv/pid/tgid/uid/gid, file.path/kind, network.dst_ip/dst_port/family, dns.qname/qtype, syscall.nr/latency_ns, identity.*, enrichment.*.
- Therefore `process.generation`, `socket.inode`, `container.id`, `ts`, `event.id` CANNOT appear as step fields (not in catalog) — but they CAN be carried on events for the engine's group-key/ordering/evidence extraction. Design steps around catalog fields (exec_path, dst_port, syscall.nr) and let the engine read generation/ts from the events.
- There is NO parent-identity or TTY field in the catalog. "server-parent identity" and "no-TTY/interactive context" are expressed today via `process.argv` (a login shell's argv[0] is conventionally "-bash"/"-sh"/... ; a reverse shell runs non-login like ["bash","-i"]). Documented as a refinement for when the sensor captures parent/TTY directly.

### Predicate evaluator array semantics (crates/rules/src/predicates/predicate.rs)
- `contains` on an Array field = ELEMENT membership (exact `values_eq` per element), not substring. So `process.argv contains "-bash"` matches only if "-bash" is an exact argv element; argv ["bash","-i"] does NOT match. `contains` on a String field = substring.
- `in`/`not_in` require an array value; element types must match the field type without coercion (Integer field ↔ Integer array elements).
- Exceptions are evaluated by the harness, not by `evaluate_condition`: each exception is a leaf {field,operator,value} passed to `predicates-cli evaluate`. An exception over an unknown/null field never applies (non-match).

### Bench harness model (bench/rules-reverse-shell.sh)
- Mirrors bench/rules-sensitive-files.sh but drives the SEQUENCE engine. A rule fires on a fixture when ALL of: (1) the rule's named sequence completes cleanly (completed && !uncertain) via `sequences-cli replay`; (2) the deterministic condition matches ≥1 event via `predicates-cli evaluate`; (3) NO exception matches ANY event in the stream. First firing rule wins.
- Threshold read from schema, NOT hardcoded: `jq -r '.properties.fixture_min_precision_and_recall.default // 1.0'`. The property is absent from bench/schemas/rule-budget.v1.json today, so it falls back to 1.0 (same as task 30).
- Rule's sequences are extracted with `jq '[.rules[].sequences[]]'` from `rules-cli parse` output and round-trip cleanly into `sequences-cli` (same AST serde). Per-rule sequence names via `jq -c '[.rules[ri].sequences[].name]'`.
- Fixture format differs from sensitive-files: `events: [Event, ...]` (a stream) instead of a single `event`. Each Event is `{"fields": {...}, "null_fields": [...]}` and carries `ts`, `process.generation`, `event.id` plus the step fields.

### Fixture mechanisms (precision=recall=1.0, 1 TP / 6 TN)
- positive-reverse-shell (TP): bash(argv=["bash","-i"]) exec → connect dst_port 4444 → dup2 (syscall.nr 33), all gen=42 within 60s. Sequence completes cleanly; condition matches; no exception. Evidence: ev-exec -> ev-connect -> ev-dup2.
- negative-ssh-session (TN): login shell (argv=["-bash"]) connects to port 22 (not a monitored callback port) → sequence step 2 never matches → incomplete. Also SSH-port + login-shell exceptions would suppress.
- negative-socat-sidecar (TN): socat is not a shell → step 1 (exec_path in shells) never matches → sequence never starts. socat also in admin/session exception list.
- negative-interactive-shell (TN): login shell (argv=["-bash"]) → connect 4444 → dup2; sequence WOULD complete, but the login-shell exception (argv contains "-bash") suppresses. Isolates the exception mechanism.
- negative-network-without-shell (TN): curl (not a shell) connects → step 1 fails and condition matches no event.
- negative-shell-without-socket (TN): bash exec + dup2 but NO connect event → step 2 never matches → incomplete.
- negative-gap-attribution (TN): exec + connect, but dup2 arrives at ts 260 > started_at 100 + window 60 → sequence uncertain → never fires.

### Safety invariants enforced by reverse-shell rule design
- Action is `alert` ONLY — never deny from this behavioral heuristic (alert/audit-only constraint).
- No payload inspection: matches only kernel-observable metadata (exec_path, argv, dst_port, syscall.nr); nothing to redact (task 23 privacy).
- No bare-PID correlation: group key is process.generation (unique across PID reuse).
- Uncertain sequences (gap/late/out-of-order) never alert.
- SSH/debug/admin/interactive exceptions honored (evaluated against every event in the correlated stream).
- syscall.nr dup values (33=dup2, 292=dup3) are x86_64 ABI; documented that a portable deployment normalizes per-arch in the sensor.

## Task 32: Container-escape indicator rule pack

### Container context via enrichment.container_id (the key design decision)
- Every container-escape rule requires BOTH a suspicious action AND resolved container context: `enrichment.container_id ne ""`. This is the CRI enrichment layer's (task 22) resolution of cgroup/namespace IDs to a container identity.
- The `ne ""` operator works because: (1) if enrichment.container_id is present and non-empty → `values_eq(field, "")` is false → `ne` is true (match); (2) if the field is null (in null_fields) or unknown (absent) → `Event::lookup()` returns None → evaluator returns false (non-match) BEFORE reaching evaluate_predicate. So unresolved attribution NEVER alerts.
- This is why a single setns/unshare is NOT called an escape: the condition requires container context. A host process (runc creating a container) has null/empty enrichment.container_id → non-match → no alert.
- enrichment.* fields are NOT kernel-observable, so deny is never permitted on them — consistent with the alert-only design. All 6 rules use `action: alert`.

### Rule pack structure (6 alert-only rules)
1. **container-escape-namespace-switch**: syscall.nr in [258 (setns), 272 (unshare)] + container context. Exceptions: runc, containerd, crio, dockerd, CNI plugins (/opt/cni/bin/, /usr/libexec/cni/).
2. **container-escape-runtime-socket**: file.path in [docker.sock, containerd.sock, crio.sock paths] + container context. Exceptions: runtime daemons, debug pods (pod_name contains "debug").
3. **container-escape-proc-root**: file.path starts_with "/proc/1/root" + container context. Exceptions: debug pods.
4. **container-escape-host-device**: file.path in [/dev/sda, /dev/sdb, /dev/vda, /dev/nvme0n1, /dev/mem, /dev/kmem, /dev/port] + container context. Exceptions: runtime daemons. NEVER uses broad /dev prefix.
5. **container-escape-cloud-metadata**: network.dst_ip eq "169.254.169.254" + container context. Exceptions: metadata-proxy pods.
6. **container-escape-credential-change**: syscall.nr in [105 (setuid), 106 (setgid), 107 (setreuid), 108 (setregid)] + container context. Exceptions: runtime daemons.

### CRI/Kubernetes identity and exceptions
- Runtime exceptions use `process.exec_path in [...]` for runc, containerd, crio, dockerd (both /usr/bin/ and /usr/sbin/ paths).
- CNI exceptions use `process.exec_path starts_with "/opt/cni/bin/"` and `"/usr/libexec/cni/"` (standard CNI plugin locations).
- Debug workload exceptions use `enrichment.pod_name contains "debug"` (Kubernetes convention for debug pods: "debugger-*", "*-debug-*").
- Cloud metadata proxy exception uses `enrichment.pod_name contains "metadata-proxy"`.

### Fixture design (18 fixtures: 9 TP + 9 TN, precision=recall=1.0)
- Positive fixtures: each has enrichment.container_id set to a non-empty hex string (resolved container), identity fields (cgroup_id, ns_mnt, ns_pid, ns_net, ns_user) for attribution validity, and the relevant syscall/file/network field matching a rule condition. process.exec_path is a non-excepted binary (python3, bash, curl, cat, dd, exploit).
- Negative fixtures cover: (1) host context (enrichment.container_id in null_fields), (2) runtime exception (runc exec_path), (3) CNI exception (/opt/cni/bin/bridge), (4) runtime daemon accessing own socket (containerd), (5) debug pod exception (pod_name contains "debug"), (6) host device from host (null container_id), (7) cloud metadata from host (null container_id), (8) unresolved attribution (null container_id with suspicious syscall), (9) normal file access in container (non-suspicious path).
- The "unresolved attribution" fixture is critical: it has a suspicious syscall (setns) with identity fields present but enrichment.container_id null → no alert. This validates the "unresolved => no alert" invariant.

### Bench script (bench/rules-container-escape.sh)
- Modeled on bench/rules-sensitive-files.sh (single-event evaluation, no sequences). Each fixture has one "event" (not an "events" array).
- Threshold read from schema: `jq -r '.properties.fixture_min_precision_and_recall.default // 1.0'`. The property was ADDED to bench/schemas/rule-budget.v1.json in this task (default 1.0).
- The `fixture_min_precision_and_recall` property is NOT in the schema's `required` array, so existing rule-budget objects remain valid.

### Schema update (bench/schemas/rule-budget.v1.json)
- Added `fixture_min_precision_and_recall` property (type: number, min: 0, max: 1, default: 1.0). This is the single source of truth for the precision/recall threshold that bench harnesses read. Previously the property was absent and harnesses fell back to 1.0 via jq's `// 1.0`.

### Scope boundaries (per plan)
- gVisor/Kata guest-internal activity is OUT OF SCOPE: these rules operate on the host kernel's observable surface only.
- Host/sandbox/Pod namespace confusion is prevented by requiring enrichment.container_id resolution (the enrichment layer distinguishes these).
- No deny action anywhere in the pack: container-escape detection is behavioral and contextual; blocking would risk denying legitimate runtime/CNI/debug operations.

## Task 33: Audit-first BPF LSM deny engine (bpf/sensors/lsm.bpf.c)

### The central truthfulness invariant: own-denial attribution
- `deny_source` in an LSM decision event is `OWN_LSM` ONLY when THIS BPF program returns an errno (decision == DENY). A nonzero incoming `ret` means a prior LSM (SELinux/AppArmor/another BPF program) already decided → record `PRIOR_LSM`, preserve that `ret` byte-for-byte, NEVER relabel OWN_LSM. An audit-mode match records `NONE`. This mirrors file.bpf.c's producer-side deny_source truth (a record that says SYSCALL/NONE may not be relabeled OWN_LSM downstream).
- The own-denial semantic lives in the decision PAYLOAD's `deny_source`/`result_flags` fields, NOT in the section name. The `KERNEL_V1_LSM_RESULT_OWN_LSM` bit (0x02) is set only on the deny path.

### CRITICAL: section names must NOT contain "OWN_LSM_DENY"
- The task-18 loader (crates/bpf-loader/src/lib.rs::probe_and_load) REFUSES to attach any hook whose section name (or ladder rung section) contains the substring "OWN_LSM_DENY" — it returns `LoaderError::DenyLinkAttachDisallowed`. Therefore the LSM hooks use the canonical libbpf section names `lsm/file_open`, `lsm/bprm_check_security`, `lsm/socket_connect`. The loader's deny-link guard stays satisfied and deny links are never pinned (the loader pins nothing for this sensor; loader_state.rs guarantees `pinned_deny_links_count() == 0`).
- The loader's `default_sensor_names()` / `ladder_for()` do NOT include an "lsm" sensor, so the loader never tries to attach this object — consistent with audit-first + "deny links must not be pinned". Wiring the LSM object into the attach path is a later wave; this task ships the BPF object + decision logic + bench only.

### LSM hook signatures (BPF_PROG trailing `ret` = prior LSM return)
- `lsm/file_open`: `int BPF_PROG(name, struct file *file, int ret)`. Selector = `file->f_path.dentry->d_name.name` (the kernel-observable dentry name component; full-path prefix walking is a documented refinement — file.bpf.c reads the same field).
- `lsm/bprm_check_security`: `int BPF_PROG(name, struct linux_binprm *bprm, int ret)`. Selector = `bprm->filename` (the FULL path passed to execve — authoritative).
- `lsm/socket_connect`: `int BPF_PROG(name, struct socket *sock, struct sockaddr *address, int addrlen, int ret)`. Selector = the sockaddr bytes read from `address` (bounded to addrlen, capped at 256).
- BPF LSM hooks compose: the trampoline passes the running return value as the trailing `ret`. If `ret != 0` on entry, a prior hook already denied → return `ret` UNCHANGED (never override another LSM).

### Decision engine branch order (lsm_decide — the bench mirrors this EXACTLY)
1. `prior_ret != 0` → PRESERVE_PRIOR, deny_source=PRIOR_LSM, return prior_ret unchanged.
2. selector invalid (read fault / unknown family) → FAIL_OPEN_UNKNOWN, return 0.
3. policy map lookup misses → ALLOW, return 0 (missing map never denies).
4. policy `hook_family` mismatch OR empty selector → ALLOW, return 0.
5. observed selector does NOT prefix-match policy selector (or obs shorter than policy) → ALLOW, return 0 (wrong selector never denies).
6. mode == AUDIT (0) → AUDIT_MATCH, return 0 (audit-first: NEVER changes the syscall result).
7. mode == DENY (1): if kill_switch.deny_disabled → DENY_SUPPRESSED_KILLSWITCH, return 0; else return policy `deny_errno` (forced negative; default -13 EACCES) and record OWN_LSM. This is the ONLY path that changes the result.
8. unknown mode value → FAIL_OPEN_UNKNOWN, return 0 (never deny on an unrecognised encoding).

### Maps (the "agent maps" — the agent populates these via bpf_map_update_elem)
- `lsm_policy` (ARRAY, max_entries=4): one authoritative selector per hook family (slot 0 reserved; 1=file_open, 2=bprm_exec, 3=socket_connect). Value `struct lsm_policy_entry` (288 bytes, packed) carries the EXPLICIT mode/version/generation triple + deny_errno + selector[256]. The version/generation let the staged validated-map path (task 34) atomically promote a policy and let the consumer correlate a decision to the exact policy generation.
- `lsm_kill_switch` (ARRAY, 1 slot): `struct lsm_kill_switch` (16 bytes) { deny_disabled u8, last_toggle_ns u64 }. deny_disabled=1 degrades every deny to audit-only. Single map lookup → deny-disabled takes effect within kill_switch_max_ms (default 5000) of the gRPC command reaching the agent.
- `lsm_events` (RINGBUF 256 KiB) + `lsm_seq` (PERCPU_ARRAY). A failed ringbuf reserve (ring full) drops the RECORD but NOT the decision — the hook still returns the correct errno and the own-denial is still attributed (fixture ring-full-still-decides proves this).
- The Rust-side typed mirror of these map structs is task-34's staging work; this task ships the C map ABI (documented here + _Static_assert'd in lsm.bpf.c).

### Event ABI: event_kind 15 (LSM_DENY_OWN) is the LSM-decision carrier
- The ABI (event_abi.h) has exactly one LSM semantic kind: `KERNEL_V1_EVENT_LSM_DENY_OWN = 15`. lsm.bpf.c uses it as the carrier for ALL LSM decision records (allow/audit/deny/preserve/killswitch/fail-open); the own-denial semantic is FIELD-gated (deny_source==OWN_LSM AND result_flags & OWN_LSM), set only when the program returns an errno. The fixed 320-byte payload `struct kernel_v1_lsm_decision_payload` (_Static_assert'd) carries hook_family, decision, deny_source, mode, version, generation, result_errno, prior_ret, selector_len, result_flags, selector[256]. Mirrors the file/network/dns fixed-payload precedent.
- No new validity bits were added: the decision reuses KERNEL_V1_VALID_FILE_DENY_SOURCE for the deny_source field. Header identity bits match file.bpf.c (CGROUP/PID/TASK_START/PROCESSOR; boot_id NOT set — the task-16 identity event owns it).

### BPF stack limit (512 bytes) — the one real compile bug hit
- The first version put a 256-byte `sel_buf` in the hook AND a 256-byte `tmp` temp inside the inlined `emit_decision` → "BPF stack limit exceeded". FIX: write the selector DIRECTLY into the ring-buffer-reserved memory (`ev->payload.selector[i] = sel_buf[i]` in a constant-bound loop), never a stack temp. The ringbuf reservation is heap-like (not stack). file.bpf.c uses the same pattern. Each hook frame is then ~280 bytes (sel_buf + locals) < 512.
- The 256-iteration prefix-match and selector-copy loops are written with a COMPILE-TIME constant bound (`for (i=0; i<KERNEL_V1_LSM_SELECTOR_MAX; i++) if (i<cmp_len) ...`) so the verifier's bounds analysis stays trivial. Section sizes are ~30 KB/program (loops not fully unrolled by -O2); the verifier instruction count is a refine-on-privileged-runner concern (cannot load here).
- The benign `-Waddress-of-packed-member` warning on `&ev->header` is identical to file.bpf.c's pattern (header is the first, naturally-aligned member of the packed event struct) — left as-is for consistency.

### Bench harness model (bench/enforcement-audit.sh) — logic validated WITHOUT BPF load
- BLOCKER: this host cannot load BPF (unprivileged_bpf_disabled=2, CapEff=0). The harness reimplements `lsm_decide` deterministically in jq (branch-for-branch) and evaluates the synthetic corpus in tests/fixtures/enforcement/ (19 fixtures: 6 own-denial TP + 13 TN). It asserts BOTH per-fixture exact-match AND five global safety invariants: (a) audit mode never changes the result; (b) nonzero prior ret preserved verbatim AND labeled prior_lsm; (c) invalid selector / missing map never deny; (d) own-denial recorded only when returned < 0 AND decision == deny; (e) deny_source own_lsm only with decision deny.
- Precision/recall over the own-denial class (positive = own_denial_recorded) must meet `fixture_min_precision_and_recall` (read from schema, NOT hardcoded; default 1.0). Result: precision=recall=1.0, all invariants 0, exit 0.
- Negative QA verified: tampering a fail-open fixture to expect an own-denial drops recall to 0.8571 and exact_ok=0 → exit 1. The harness is not vacuously passing.
- The privileged half (real syscall-result change, errno delivery, prior-LSM composition, kill-switch p99 <= kill_switch_max_ms over kill_switch_benchmark_pairs via bench/kill-switch.sh) is printed as BLOCKED and deferred to the declared self-hosted runner. kill-switch.sh does not exist yet (a later task); the schema anchors its constants (kill_switch_max_ms=5000, kill_switch_benchmark_pairs=10).

### Schema (bench/schemas/enforcement.v1.json) — single source of truth
- Anchors every enforcement constant: audit_first_default_mode=0 (the audit-first invariant; the bench asserts the schema default is 0), mode_audit=0/mode_deny=1, supported_hook_families=[file_open,bprm_check_security,socket_connect], hook_family_* wire encodings (1/2/3), max_policy_entries=4, selector_max_bytes=256, lsm_payload_len=320, deny_errno_default=-13, kill_switch_max_ms=5000, kill_switch_benchmark_pairs=10, fixture_min_precision_and_recall=1.0. Modeled on rule-budget.v1.json (no $schema key; properties/defaults; additionalProperties:false).

### Scope boundaries honored
- No SELinux/AppArmor attribution (only own BPF LSM program → OWN_LSM; everything prior → PRIOR_LSM).
- No deny from user-space enrichment/heuristics — selectors are kernel-observable only (file path component, bprm->filename, sockaddr).
- No SIGKILL — LSM errno return is the enforcement mechanism.
- No mode change without staged validated maps — every policy ships mode=0; promotion is task 34.
- Deny links never pinned (loader pins nothing for this sensor).
- Files touched only under bpf/sensors/, bench/, tests/fixtures/enforcement/, .omo/notepads/ (crates/bpf-loader/ was in-scope but deliberately untouched to avoid the deny-link policy test and build; the Rust map mirror is task 34).

## Task 34: Agent-side staged policy maps, kill switch, and loader-death fail-open lifecycle

### State machine design (crates/enforcement/src/state_machine.rs)
- The enforcement lifecycle is `Idle → Staged → Ready → Committed → Applied` with `Rejected` reachable from Staged (digest mismatch) or any state (explicit rejection). STAGE writes to the inactive buffer; VERIFY recomputes the SHA-256 digest; COMMIT atomically flips active/inactive.
- STAGE is valid from Idle, Staged (idempotent re-stage), Rejected (re-attempt), and Applied (new rollout with higher version). STAGE is NOT valid from Ready or Committed (mid-transition).
- COMMIT is valid ONLY from Ready. COMMIT before READY is `InvalidTransition`. Duplicate COMMIT after Applied with the same version is a safe no-op (idempotent).
- The monotonic version check happens AFTER the state check: commands with version ≤ `monotonic_version` are rejected as `VersionReplay`. This covers both stale (version < current) and exact replay (version == current).
- After COMMIT, `staged_version` is NOT cleared — this enables the idempotent duplicate COMMIT check. But it means a re-STAGE with the same version after Applied hits the monotonic check (version ≤ monotonic_version) and is correctly rejected as a replay.

### CRITICAL: digest computation must mirror stage() exactly
- `compute_digest_for_entries()` MUST set `slot.generation` and `slot.version` on each entry, exactly as `stage()` does. If it doesn't, the digest computed by the caller (for the STAGE command's `content_digest` field) won't match the digest recomputed by `verify()` from the inactive buffer, causing a false `DigestMismatch` rejection. This was the root cause of 3 test failures during development.
- The digest covers: generation (u64 LE) + per-entry [mode, hook_family, version (u64 LE), generation (u64 LE), deny_errno (i32 LE), selector_len (u32 LE), selector bytes]. The `_pad` fields are NOT included (they are zero-filled and carry no semantic content).

### Double-buffered PolicyMap (crates/enforcement/src/policy.rs)
- `PolicyMap` holds `active`, `inactive`, and `previous` (rollback target). `flip()` uses a 3-step `std::mem::replace` chain: (1) stash old_active, (2) swap inactive into active, (3) allocate fresh inactive at generation+1, store old_active as previous. The `next_gen` for the fresh inactive is `inactive.generation + 1` (NOT `active.generation + 1` — that would produce a duplicate generation number).
- `rollback()` swaps active back to previous; the current active becomes the new inactive. Returns false if no previous exists.
- `deny_links_pinned()` always returns false — this is a compile-time invariant, not a runtime check.

### Kill switch (crates/enforcement/src/kill_switch.rs)
- Wire-compatible with `struct lsm_kill_switch` (16 bytes): deny_disabled at offset 0, last_toggle_ns at offset 8. The `to_wire()`/`from_wire()` methods match the C struct layout exactly.
- User-space engage latency is sub-microsecond (memory write). The real gRPC→BPF-map latency requires privileged BPF load and is BLOCKED on this host.
- `benchmark_kill_switch(pairs, threshold_ms)` runs engage/disengage cycles, computes p99, and compares against the threshold. The bench script reads `kill_switch_max_ms` and `kill_switch_benchmark_pairs` from the schema (NOT hardcoded).

### Persistence (crates/enforcement/src/persistence.rs)
- Last-known-good is a JSON-serialized `PolicyGeneration` written atomically (write-to-temp + rename). The `PersistenceManager` wraps a path and provides save/load.
- On restore (`from_persisted`), EVERY entry is forced to `PolicyMode::Audit` (startup audit-only invariant). The monotonic version is set to the max entry version, preventing replay of old commands.
- Disconnect does NOT auto-relax LKG: `on_loader_death()` sets `loader_alive = false` but does NOT modify the persisted file. Only explicit ROLLBACK or KILL SWITCH commands change enforcement state.

### Loader-death fail-open
- `on_loader_death()` sets `loader_alive = false`, transitions to Idle, and records the event in the transition log. Subsequent STAGE commands return `Err(LoaderDead)`.
- Deny links are never pinned by construction (`deny_links_pinned == false` always), so loader death cannot leave stale deny links attached. Observation links may use distinct pin roots (separate from enforcement).

### Bench harness (bench/enforcement-state-machine.sh)
- Phase 1: `cargo test -p enforcement` (54 tests covering all transitions, digest, version, idempotency, rollback, kill switch, persistence, loader death).
- Phase 2: validates 12 fixture files in tests/fixtures/enforcement-state-machine/ are present and valid JSON.
- Phase 3: kill-switch latency benchmark (user-space simulation; real gRPC latency BLOCKED).
- Phase 4: 11 safety invariants checklist.
- Privileged half (real BPF map ops, real kill-switch p99, forced SIGKILL) reported as BLOCKED.

### Schema anchor (bench/schemas/enforcement.v1.json)
- All constants read from schema, NOT hardcoded: kill_switch_max_ms=5000, kill_switch_benchmark_pairs=10, audit_first_default_mode=0.
- The bench script asserts `audit_first_default_mode == 0` as a precondition.

### Files created
- `crates/enforcement/` — new crate (Cargo.toml, src/{lib,error,policy,digest,state_machine,kill_switch,persistence}.rs)
- `bench/enforcement-state-machine.sh` — bench harness
- `tests/fixtures/enforcement-state-machine/` — 12 JSON fixtures covering all transitions
- Workspace `Cargo.toml` updated to include `crates/enforcement`

## Task 35: Typed fleet protocol state machines (crates/protocol)

### Hand-written Rust mirror of proto contracts (buf codegen disabled)
- Task 6 intentionally disabled buf codegen (`buf.gen.yaml` has `enabled: false`). Task 35 provides the typed Rust surface as hand-written types that mirror `proto/kernel/v1/events/v1/events.proto` and `proto/kernel/v1/control/v1/control.proto` field-by-field.
- The `PROTO_SCHEMA_DIGEST` constant (`42da5dcee9cc8a8de2fdf472dd2e325d5e6fd0759e0fab864c6a6dc5985349b5`) is the SHA-256 of the concatenated proto source files. The `proto_freshness_check` test recomputes the digest from `include_str!` and asserts equality — if the protos change, the test fails and the Rust types + digest must be updated.
- serde `#[serde(rename = "EVENT_KIND_...")]` attributes on `EventKind` variants match the proto JSON enum names exactly, so the existing `tests/fixtures/proto/events/happy.json` fixture deserializes without modification. This is the Rust/TypeScript interop anchor: both sides serialize to the same proto JSON enum names.

### Policy activation state machine (state_machine.rs)
- Mirrors the enforcement crate's `Idle → Staged → Ready → Committed → Applied` lifecycle with `Rejected` reachable from Staged (digest mismatch) or any non-Idle state (explicit rejection).
- STAGE is valid from Idle, Staged (idempotent re-stage), Rejected (re-attempt), Applied (new rollout with higher version). NOT valid from Ready or Committed (mid-transition).
- COMMIT is valid ONLY from Ready. Duplicate COMMIT after Applied with the same version is a safe no-op (idempotent).
- The monotonic version check happens BEFORE the state check in `stage()`: commands with version ≤ `monotonic_version` are rejected as `VersionReplay`. In `commit()`, the version must match the staged version AND be strictly greater than monotonic_version.
- `PolicyActivationState` converts to `PolicyStatus` (the control.proto enum) via `From`, bridging the protocol-level SM to the wire contract.

### Batch ACK state machine (batch_ack.rs)
- States: `Pending → Accepted / Rejected`. Every batch carries an `IdempotencyKey`. Duplicate submissions are detected by the `IdempotencyTracker` and rejected with `DuplicateIdempotencyKey`.
- Validation order: (1) idempotency key uniqueness, (2) schema major ≥ 1, (3) batch bounds (message count, per-message size). This ordering ensures a duplicate ID is caught before any payload inspection.
- The `MessageBounds` struct anchors `max_message_size_bytes` (default 1 MiB) and `max_batch_messages` (default 1000) from `bench/schemas/protocol.v1.json`.

### Idempotency keys (idempotency.rs)
- Format: UUID v4 string or monotonic u64 counter rendered as decimal string (anchored as `idempotency_key_format` in protocol.v1.json).
- `IdempotencyTracker` uses a `HashSet<IdempotencyKey>` bounded to `MAX_TRACKED_KEYS` (100,000). At capacity, the tracker clears entirely (cheaper than LRU for the MVP; the window is large enough for legitimate retries).

### Deadline propagation (deadline.rs)
- Deadlines are absolute epoch-millisecond timestamps. `is_expired()` takes an explicit `now` parameter to avoid hidden clock reads in tests.
- `propagate()` implements the gRPC deadline inheritance rule: the child inherits `min(parent_remaining, child_default)`. An expired parent propagates a zero-budget child (immediately expired).
- `saturating_add` prevents overflow when computing deadlines near `u64::MAX`.

### Typed error codes (error.rs)
- `ProtocolError` has 10 variants covering every QA failure case: `InvalidTransition`, `VersionReplay`, `DigestMismatch`, `OversizedMessage`, `OversizedBatch`, `ExpiredDeadline`, `DuplicateIdempotencyKey`, `StaleProtocolMajor`, `UnknownField`, `InvalidPolicy`.
- No free strings for state transitions — all states are typed enums (`PolicyActivationState`, `BatchAckState`, `PolicyStatus`, `EventKind`).

### Schema anchor (bench/schemas/protocol.v1.json)
- Anchors: `max_message_size_bytes`=1048576, `max_batch_messages`=1000, `deadline_default_ms`=30000, `idempotency_key_format`="uuid_v4_or_monotonic_u64", `max_tracked_idempotency_keys`=100000, `compression_algorithm`="none", `schema_major`=1, `schema_minor`=0, `fixture_min_precision_and_recall`=1.0.
- Modeled on `enforcement.v1.json` (no `$schema` key; `properties`/`defaults`; `additionalProperties: false`).

### Files created
- `crates/protocol/` — new crate (Cargo.toml, src/{lib,error,events,control,bounds,deadline,idempotency,state_machine,batch_ack,identity}.rs)
- `bench/schemas/protocol.v1.json` — protocol constants schema
- `tests/fixtures/protocol/` — 7 JSON fixtures (policy-activation-happy, batch-ack-happy, oversized-batch, stale-major, illegal-transition, duplicate-id, expired-deadline)
- Workspace `Cargo.toml` updated to include `crates/protocol`
- 75 tests pass (`cargo test -p protocol`), including proto freshness check and happy.json fixture interop

## Task 36: SPIFFE Workload API identity and rotating gRPC mTLS credentials (crates/identity-spiffe)

### Architecture: transport-abstracted Workload API client
- The `SvidStream` trait abstracts the FetchX509SVID gRPC stream transport. `FixtureSvidStream` provides deterministic test streams; a real `GrpcSvidStream` (Unix socket + tonic) is deferred to the declared self-hosted runner with SPIRE deployed.
- `WorkloadApiClient` manages the stream lifecycle: connect → stream → validate → complete-set replace → reconnect with backoff. The `run_with_reconnect` method takes a stream factory closure, enabling test injection without a live SPIRE agent.
- The client reads `SPIFFE_ENDPOINT_SOCKET` env var (falls back to `/run/spire/agent-sockets/api.sock`). No insecure bootstrap: if the endpoint is unreachable, the client fails closed (no credentials, no plaintext fallback).

### Complete-set replace/redact semantics (the central safety invariant)
- Each `X509SVIDResponse` from the Workload API is a COMPLETE snapshot. The new set REPLACES the old entirely — no partial merge. On replacement, `SvidSet::redact_all()` zeroizes all private key material in the old set via `Zeroizing<Vec<u8>>`.
- After redaction, `private_key_pem()` and `private_key_der()` return `Err(MaterialRedacted)`. Certificate chains (public material) remain accessible. The `Debug` impl shows `[REDACTED]` for key fields — private key bytes NEVER appear in logs.
- `X509Svid` implements `Drop` which calls `redact()`, ensuring key material is zeroed even on unexpected scope exit.

### SPIFFE ID validation: exact trust-domain match, NEVER substring
- `SpiffeId::parse()` validates: scheme `spiffe://`, non-empty trust domain (no whitespace, no `/`), optional path starting with `/`, no fragment/query, no empty path segments (`//`).
- `assert_trust_domain()` uses `!=` (exact equality). `SpiffeIdSelector::validate()` rejects substring matches: `kernel-v1` does NOT match `kernel-v1-evil` or `kernel-v1.test`.
- Selectors support exact path match and path prefix match. The authorization callback expects `/agent/<cluster>/<node>` structure.

### Credential manager: rustls mTLS with fail-closed semantics
- `CredentialManager` builds `rustls::ServerConfig` (with `WebPkiClientVerifier` for mTLS) and `rustls::ClientConfig` from the current SVID set. Trust bundles are used ONLY for SVID authentication (peer cert verification), never for arbitrary TLS.
- Fail-closed: `rebuild()` returns `Err(SvidExpired)` if the SVID is expired, `Err(MaterialRedacted)` if key material is redacted, `Err(NoCredentials)` if no SVID set exists. No fallback to expired/redacted/static material.
- Hot-rebuild: `needs_rebuild()` triggers on rotation count change OR when SVID approaches expiry (80% of default 1-hour lifetime elapsed).

### Authorization callback: SPIFFE ID → agent/node/cluster binding
- `AuthorizationCallback::authorize()` decomposes `spiffe://<td>/agent/<cluster>/<node>` into an `AgentBinding` struct. Validates exact trust domain, path structure, and optional cluster/node restrictions.
- `to_register_request()` bridges to the protocol crate's `RegisterRequest`, enabling `AgentIdentity::register()` with the SPIFFE-derived node/cluster identity.

### Pinned ephemeral fixtures (tests/fixtures/spiffe/)
- Generated with OpenSSL 3.6 EC P-256 keys. CA cert (bundle.pem) valid 10 years. Agent SVIDs signed by CA with SPIFFE URI SAN.
- `svid-agent.pem` / `svid-agent-rotated.pem`: valid SVIDs with `spiffe://kernel-v1.test/agent/prod/node-1` (different keys, same ID — proves rotation).
- `svid-expired.pem`: notAfter=2024-01-02 (already expired — proves fail-closed).
- `svid-wrong-td.pem`: signed by a separate evil CA with `spiffe://evil.example/agent/prod/node-1` (proves trust-domain rejection).
- The expired fixture uses OpenSSL 3.x `-not_before`/`-not_after` flags to pin dates in the past.

### BLOCKER: no live SPIRE agent on this host
- The gRPC streaming transport (Unix socket → SPIRE agent) cannot be tested end-to-end. All stream logic is validated via `FixtureSvidStream`. Live integration re-opens on the declared self-hosted runner.
- The `run_with_reconnect` test uses `std::thread::sleep` with real backoff delays (100ms base). Tests complete in <1s total.

### Dependencies added to workspace
- `x509-parser = "0.17"` — X.509 certificate parsing (SAN URI extraction, notAfter timestamp).
- `rustls = "0.23"` (ring backend) — TLS config building for mTLS.
- `zeroize = "1"` (derive feature) — zeroizing memory for private keys.
- All other deps (tokio, prometheus, parking_lot, thiserror, tracing) were already in the workspace lock file.

### Files created
- `crates/identity-spiffe/` — new crate (Cargo.toml, src/{lib,error,spiffe_id,svid,backoff,workload,credentials,authorization,metrics}.rs, tests/integration.rs)
- `tests/fixtures/spiffe/` — 13 PEM fixtures (ca, bundle, agent SVID, rotated SVID, expired SVID, wrong-td SVID + keys)
- Workspace `Cargo.toml` updated to include `crates/identity-spiffe`
- 82 tests pass (`cargo test -p identity-spiffe`): 61 unit + 21 integration

## Task 37: OIDC PKCE/device authentication and server-side RBAC (crates/auth)

### Architecture: fixture-driven auth without a live OIDC provider
- BLOCKER: this host has no running OIDC provider (Dex/Keycloak). All flows are implemented and tested with pinned fixtures: test JWKS (RSA 2048 + EC P-256 keys generated via OpenSSL), a pinned Dex-compatible discovery document, and device-flow fixture data. Live OIDC integration re-opens on the declared self-hosted runner.
- The `test_support` module (cfg(test)-only) signs JWTs with the fixture private keys using ring, enabling full signature-validation round-trip tests without a live provider.

### OIDC discovery: exact issuer pin (the central anti-spoofing invariant)
- `OidcDiscovery::validate_pinned()` uses `!=` (exact equality). The issuer `https://dex.kernel-v1.test` does NOT match `https://dex.kernel-v1` (prefix), `https://dex.kernel-v1.test.evil` (suffix), `https://DEX.KERNEL-V1.TEST` (case), or `https://dex.kernel-v1.test/` (trailing slash). This mirrors the SPIFFE crate's exact trust-domain matching.
- The discovery fixture explicitly excludes implicit flow response types (`id_token`, `token`); only `code` is supported.

### PKCE: S256 only, never plain
- `PkceVerifier::generate()` produces 32 random bytes → base64url (43 chars). The S256 challenge is `BASE64URL(SHA256(verifier))` per RFC 7636.
- The RFC 7636 Appendix B test vector (`dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` → `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM`) is pinned as a test.
- Verifier length is validated (43..=128). The `plain` method is structurally absent.

### JWKS + JWT validation: ring-based, no external JWT library
- `Jwks::resolve_key()` validates the algorithm BEFORE key lookup (RS256/ES256 only; `none`/HS256 rejected as `UnsupportedAlgorithm`). This ordering ensures precise error types.
- RSA public keys are encoded as PKCS#1 DER (`SEQUENCE { INTEGER n, INTEGER e }`) for ring's `RSA_PKCS1_2048_8192_SHA256`. NOT SubjectPublicKeyInfo — ring expects the inner RSAPublicKey structure. This was the root cause of 8 test failures during development.
- EC P-256 keys use the uncompressed point format (`0x04 || x || y`) for ring's `ECDSA_P256_SHA256_ASN1`.
- JWT validation order: (1) parse header, (2) reject unsupported alg, (3) verify signature via JWKS, (4) parse claims, (5) exact issuer match, (6) audience contains client_id, (7) azp match if present, (8) expiry check, (9) iat future check with 120s skew, (10) nonce match if expected.
- The `aud` claim deserializes from both single-string and array forms (OIDC spec allows both).

### RFC 8628 device flow: state machine with backoff
- States: `Idle → Pending → Authorized / Expired / Denied`. The `slow_down` response increases the polling interval by 5 seconds per RFC 8628 §3.5.
- Expiry is checked on every `poll()` call against `started_at + expires_in`. The device code has a bounded lifetime (1800s in the fixture).
- `TokenPollResponse::from_error()` maps OAuth2 error strings to typed variants; unknown errors map to `Denied` (fail closed).

### RBAC: four roles, group/sub bindings, NEVER email
- Roles: `viewer < analyst < policy-admin < admin` (total order via `Ord`).
- Actions: `Read` (all roles), `Write` (analyst+), `Admin` (policy-admin+), `SuperAdmin` (admin only).
- Role resolution: sub bindings and group bindings are both checked; the HIGHEST matching role wins. Multiple group memberships compose (e.g., `["viewers", "admins"]` → Admin).
- Authorization is NEVER by email. A user with an email but no group/sub binding is denied (`NoRoleBinding`).
- The default control-plane policy maps routes to actions mirroring task 6 OpenAPI annotations: `/api/v1/policies/stage` → Admin, `/api/v1/config` → SuperAdmin, `/api/v1/agents/register` → Write, everything else → Read.

### Session management: short-lived, revocable, group-change-aware
- Default TTL is 900 seconds (15 minutes). Sessions are NEVER static production tokens.
- `invalidate_on_group_change()` revokes all sessions for a sub whose groups differ from the stored snapshot. This is the mechanism that enforces "group removal → session invalidation".
- `revoke_all_for_sub()` provides explicit full revocation for a user.

### Middleware: loopback-only dev bypass
- `AuthMiddleware::dev_bypass()` REFUSES non-loopback bind addresses at construction time. `0.0.0.0`, `10.0.0.1`, `::` are all rejected. Only `127.0.0.1` and `::1` are accepted.
- In OIDC mode, every route authorization validates the session (existence → expiry → revocation → RBAC). Mutations (non-Read actions) emit an actor-bound audit intent.
- The loopback check mirrors the agent API's existing pattern (crates/agent/src/api.rs:243).

### Audit intent: actor-bound, append-only
- Every mutation emits an `AuditIntent` binding actor (sub), action, resource, and a monotonic sequence number. Read-only operations do NOT emit intents.
- The `AuditSink` is append-only with `parking_lot::Mutex` for thread safety.

### Pinned fixtures (tests/fixtures/oidc/)
- `discovery.json`: pinned Dex-compatible discovery document with issuer `https://dex.kernel-v1.test`, device authorization endpoint, PKCE S256 support, NO implicit flow.
- `jwks.json`: RSA 2048 (kid=test-rsa-key-1, alg=RS256) + EC P-256 (kid=test-ec-key-1, alg=ES256) public keys.
- `keys/rsa-test.pem`, `keys/ec-test.pem`: OpenSSL-generated PKCS#8 private keys for test JWT signing.
- `device-flow.json`: RFC 8628 fixture data with polling sequence (pending → slow_down → success).

### Dependencies added to workspace
- `ring = "0.17"` — RS256/ES256 signature verification and test JWT signing.
- `base64 = "0.22"` — JWT/JWKS base64url encoding/decoding.
- `sha2 = "0.10"` — PKCE S256 challenge computation.
- `rand = "0.9"` — PKCE verifier and nonce/state generation.
- `parking_lot = "0.12"` — thread-safe audit sink.
- All other deps (serde, serde_json, thiserror, tracing, uuid) were already in the workspace.

### Files created
- `crates/auth/` — new crate (Cargo.toml, src/{lib,error,discovery,pkce,jwks,jwt,device,session,rbac,middleware,audit,test_support}.rs)
- `tests/fixtures/oidc/` — discovery.json, jwks.json, device-flow.json, keys/{rsa-test.pem,ec-test.pem,rsa-test-pub.pem,ec-test-pub.pem}
- Workspace `Cargo.toml` updated to include `crates/auth`
- 94 tests pass (`cargo test -p auth`): covering PKCE happy/failure, device flow lifecycle, JWT validation (RS256+ES256 happy, expired/wrong-issuer/wrong-audience/wrong-azp/wrong-nonce/iat-future/tampered-sig/alg-none failures), RBAC negative matrix (all 4 roles × denied actions), session expiry/revocation/group-change, middleware loopback/non-loopback, audit intent emission

## Task 38: PostgreSQL authoritative fleet state and append-only audit (crates/control-db)

### Architecture: trait-based repositories with SQLx + in-memory mocks
- BLOCKER: this host has no running PostgreSQL instance. All repository logic is validated via in-memory mock repositories (`test_support` module). Live PostgreSQL integration (testcontainers/ephemeral) re-opens on the declared self-hosted runner.
- Each repository is a trait (`FleetRepository`, `CursorRepository`, `PolicyRepository`, `AuthRepository`, `AuditRepository`, `NotifyChannel`) with two implementations: `Sqlx*Repository` (live PostgreSQL, runtime-checked queries) and `Mock*Repository` (in-memory, for logic validation).
- SQLx queries use runtime checking (not compile-time `query!` macro) because no `DATABASE_URL` is available at build time. The `sqlx::migrate!("./migrations")` macro embeds migration SQL at compile time.

### Migration design (7 up/down pairs)
- `0001_fleet_state`: clusters/nodes/agents with SPIFFE identity references (`spiffe_id TEXT UNIQUE`), version columns for optimistic concurrency, `UNIQUE(cluster_id, name)` on nodes.
- `0002_event_cursors`: per-agent sequence tracking with `UNIQUE(agent_id, sequence)` and `UNIQUE(agent_id, idempotency_key)` for idempotent ingestion.
- `0003_policy_rollout`: policies/policy_versions/rollout_targets/rollouts/rollout_acks. `UNIQUE(policy_version_id)` on rollouts ensures one active rollout per version. `UNIQUE(rollout_id, agent_id)` on acks ensures one ack per agent per rollout.
- `0004_oidc_auth`: oidc_role_bindings/oidc_sessions/oidc_revocations. CHECK constraints enforce valid roles (viewer/analyst/policy-admin/admin) and binding types (group/sub).
- `0005_audit_log`: append-only audit_log with `audit_log_seq` sequence for monotonic ordering. NO UPDATE/DELETE grants to control_app role.
- `0006_rls_policies`: RLS enabled on ALL tables. Cluster isolation via `current_setting('app.cluster_id', true)`. Role-gated writes via `current_setting('app.role', true)`. Audit log has INSERT + SELECT policies ONLY (no UPDATE/DELETE policy = RLS default-deny).
- `0007_roles_privileges`: Three least-privilege roles: `control_app` (DML, INSERT-only on audit, NOBYPASSRLS), `control_audit` (read + insert audit, NOBYPASSRLS), `control_migrate` (DDL, BYPASSRLS for migrations).

### Optimistic concurrency pattern
- Every mutable table has a `version BIGINT NOT NULL DEFAULT 1` column.
- Updates use `UPDATE ... SET version = version + 1 WHERE id = $1 AND version = $expected RETURNING ...`.
- If no row is returned, the version didn't match → `ControlDbError::VersionConflict { table, expected, found }`.
- The caller must re-read and retry. `is_retryable()` returns true for VersionConflict.

### Idempotency pattern
- Unique constraints + `ON CONFLICT DO UPDATE SET col = EXCLUDED.col` (no-op update) for safe retries.
- For event cursors: `UNIQUE(agent_id, sequence)` and `UNIQUE(agent_id, idempotency_key)` → duplicate insert returns `IdempotentDuplicate`.
- For rollouts: `UNIQUE(policy_version_id)` → second creation attempt returns `IdempotentDuplicate`.
- For acks: `UNIQUE(rollout_id, agent_id)` → duplicate ack returns `IdempotentDuplicate`.
- `is_idempotent_duplicate()` returns true for IdempotentDuplicate (safe no-op, not an error).

### Advisory locks: bounded keys only
- `advisory_key_for_cluster(cluster_id)` computes `i64::from_be_bytes(first_8_bytes).unsigned_abs() % MAX_ADVISORY_LOCK_KEY` (1,000,000).
- Used in `create_node` to serialize node creation within a cluster (prevents duplicate names under concurrency).
- Lock is `pg_advisory_xact_lock` (transaction-scoped, released at COMMIT/ROLLBACK). Short transactions only.

### Same-transaction audit writes
- Every state-changing operation (agent.register, policy.stage, rollout.create, rollout.complete, policy status transitions) writes its audit entry in the SAME transaction.
- Pattern: `BEGIN → state change → nextval('audit_log_seq') → INSERT audit_log → COMMIT`.
- If the transaction rolls back, NEITHER the state change NOR the audit entry persists. No orphaned audits.

### LISTEN/NOTIFY as wake hint only
- Two channels: `control_fleet_state`, `control_policy_rollout`.
- NOTIFY payload is a hint (e.g. "nodes:<uuid>"), NOT state. Max 7999 bytes (pg_notify limit).
- Consumer pattern: LISTEN → on wake → SELECT latest state from table. Periodic polling covers lost notifications.
- `SqlxNotifyChannel::notify_in_tx()` sends NOTIFY in the same transaction as the state change.
- Lost notifications are SAFE: the consumer falls back to polling and always re-reads authoritative state.

### RLS defense-in-depth (NOT primary authz)
- Service RBAC (task 37 auth crate) is the PRIMARY authorization mechanism.
- Database RLS provides defense-in-depth: even if service logic is bypassed, the database prevents cross-cluster mutations and insufficient-role writes.
- Cluster isolation: `app.cluster_id` session variable gates access to cluster-scoped rows.
- Role gating: `app.role` session variable gates write access to policies/rollouts.
- Owner bypass risk documented: without RLS context (superuser), all operations succeed. Mitigated by `ALTER ROLE control_app NOBYPASSRLS`.

### Audit immutability (triple enforcement)
1. **Repository API**: `AuditRepository` trait exposes ONLY `append` and read methods. `attempt_update`/`attempt_delete` always return `AuditImmutable`.
2. **Database role**: `control_app` has `SELECT, INSERT` on audit_log. NO `UPDATE`/`DELETE` grants.
3. **RLS**: audit_log has INSERT and SELECT policies ONLY. No UPDATE/DELETE policy → RLS default-deny.

### Policy version monotonic enforcement
- Mirrors the protocol crate's `PolicyActivation` state machine: version must be strictly greater than current max.
- `stage_version()` checks `SELECT MAX(version) FROM policy_versions WHERE policy_id = $1` before insert.
- Version ≤ max → `VersionConflict { expected: max+1, found: version }` (replay rejected).
- Status transitions use `UPDATE ... WHERE status = $from_status` (optimistic on status).

### Test coverage (36 tests: 7 unit + 29 integration)
- Optimistic concurrency: cluster update conflict, agent health conflict.
- Idempotency: cluster creation, agent registration, cursor advance, rollout creation.
- Concurrent rollout race: one winner, loser gets IdempotentDuplicate.
- Rollout ack: idempotent + aggregate count updates.
- Rollout completion: optimistic version check.
- Policy version: monotonic enforcement, status transitions (staged→ready→committed→applied).
- Audit atomicity: same-transaction writes verified.
- Audit immutability: UPDATE/DELETE always fail with AuditImmutable.
- Audit monotonic sequence: seq always increases.
- RLS negative matrix: cross-cluster read denied, cross-cluster node creation denied, viewer policy write denied, analyst policy stage denied, policy-admin can write, owner bypass risk documented.
- Notification loss recovery: re-read pattern, wake hint not state.
- Migration rollback: documented (7 down migrations in reverse order).
- Fixture loading: 4 JSON fixtures validated.

### Dependencies added to workspace
- `sqlx = "0.8"` (runtime-tokio, postgres, uuid, chrono, migrate features) — PostgreSQL driver + migrations.
- `parking_lot = "0.12"` — thread-safe mock state (already in workspace lock).
- All other deps (tokio, serde, serde_json, thiserror, tracing, uuid, chrono) were already in the workspace.

### Files created
- `crates/control-db/` — new crate (Cargo.toml, src/{lib,error,models,pool,fleet,cursors,policy,auth,audit,notify,test_support}.rs, tests/integration.rs)
- `crates/control-db/migrations/` — 7 up/down SQL pairs (0001-0007)
- `tests/fixtures/control-db/` — 4 JSON fixtures (concurrent-rollout-race, audit-atomicity, rls-denial-matrix, notification-loss-recovery)
- Workspace `Cargo.toml` updated to include `crates/control-db`
- 36 tests pass (`cargo test -p control-db`): 7 unit + 29 integration

## Task 39: Agent/control-plane transport with separate deadline-bound streams (crates/transport)

### Architecture: separate channels, independent backpressure
- The transport uses TWO completely independent channels: `ControlChannel` (low-volume, high-priority: kill-switch, policy, registration) and `EventChannel` (high-volume: event batches). Each has its own bounded `tokio::sync::mpsc` queue, its own shutdown `Notify`, and its own metrics.
- Event backpressure NEVER blocks control delivery. Filling the event queue to capacity (tested with `event_queue_capacity: 2`) does not prevent the control channel from accepting a kill-switch command. This is the central safety invariant: the kill-switch must always be deliverable regardless of telemetry volume.
- Both channels use `try_send` (non-blocking) for backpressure. `QueueFull` is returned immediately when the queue is at capacity — the caller drops or buffers, never blocks. This prevents deadlock by construction.

### Deadlock-free read/write loops
- Each channel's write loop (drains outbound queue) and read loop (processes inbound ACKs/responses) run in separate tokio tasks. Communication is via `tokio::sync::mpsc` (async, non-blocking) and `tokio::sync::Notify` (shutdown). Neither task holds a lock while awaiting the other.
- The write loops check `protocol::Deadline` before sending; expired messages are dropped with a metric (`dropped_expired`). The ACK read loop validates `durable: true` on every inbound ACK; receipt-only ACKs are rejected and logged.
- `tokio::select!` is used for shutdown signaling: the loop exits on `shutdown.notified()` OR when the channel closes. No busy-waiting.

### Deterministic batch ACK after durable Kafka acceptance (the central ACK invariant)
- `AckTracker` enforces a strict state machine: `AwaitingKafkaAcceptance → KafkaAccepted → AckedAndDeleted`. There is NO path from `AwaitingKafkaAcceptance` directly to `AckedAndDeleted`.
- `try_receipt_only_ack()` ALWAYS returns `Err(ReceiptOnlyAck)` — receipt-only ACK is structurally forbidden, not just discouraged.
- `complete_ack()` requires prior `KafkaAccepted` state. Attempting to complete an ACK before Kafka acceptance returns `Err(ReceiptOnlyAck)`.
- `KafkaAcceptance` carries topic, partition, and offset — the offset confirms durability (the batch is committed to the Kafka log).
- After `complete_ack()`, the outbox row is deleted via the `OutboxDeleter` trait. The trait abstracts the storage backend so the transport crate does not depend on `storage-local` directly (avoiding a circular dependency through the agent crate). The agent wires up the concrete `LocalStorage` implementation at startup.

### Outbox deletion via trait abstraction
- `OutboxDeleter` trait: `fn delete_outbox_row(&self, batch_id: &str) -> TransportResult<bool>`. Returns true if a row was deleted.
- `MockOutboxDeleter` provides an in-memory implementation for tests. The mock tracks remaining rows, enabling assertions on which batches were deleted vs retained.
- The transport crate does NOT depend on `storage-local` or `rusqlite`. The agent crate (which depends on both) wires up the concrete implementation. This keeps the transport crate's dependency graph clean.

### Sequence reconciliation (boot/agent generation)
- `SequenceTracker` tracks `boot_id_hex`, `agent_generation`, `next_seq`, and `last_acked_seq`. On reconnect, `reconcile()` compares the agent's state with the server's reported last-ACKed sequence.
- Four reconciliation actions: `Continue` (contiguous), `ReplayFrom { replay_from_seq }` (gap detected), `SkipDuplicate` (already ACKed), `GenerationReset` (boot/agent generation changed → full reset to seq 0).
- Gap detection: if `next_seq > server_seq + 1`, the agent replays from `server_seq + 1`. This covers batches lost in transit.
- Generation change: if `boot_id` or `agent_generation` differs, the sequence resets to 0. This handles agent reboots and upgrades.
- `saturating_add` prevents overflow at `u64::MAX`.

### SPIFFE peer authorization (fail-closed)
- `PeerAuthorizer` wraps `identity-spiffe`'s `AuthorizationCallback`. Trust domain matching is EXACT (inherited): `kernel-v1.test` does NOT match `kernel-v1.test.evil` or `kernel-v1`.
- The transport is fail-closed: `authorize_peer()` must succeed before any data flows. Invalid SPIFFE ID → `PeerUnauthorized` → transport remains `Disconnected`.
- Cluster and node restrictions are optional: `with_cluster("prod")` and `with_node("node-1")` narrow the authorization scope.

### Reconnection with backoff (no redial storm)
- `ReconnectPolicy` wraps `identity-spiffe`'s `ExponentialBackoff` (base 100ms, max 30s, multiplier 2.0, full jitter). The backoff resets on successful connection.
- Circuit breaker: after `max_reconnect_attempts` consecutive failures, the circuit opens and `record_failure()` returns `Err(ReconnectExhausted)`. The transport transitions to `CircuitOpen` state.
- SVID max-age rotation: `needs_rotation(connection_age)` returns true when the connection age exceeds `max_connection_age_ms` (default 1 hour). Force-closing the connection picks up rotated SVIDs.
- `record_disconnect()` sets state to `CircuitOpen` (not `Reconnecting`) when the circuit breaker trips — the `?` operator on `record_failure()` would otherwise return early before the state update.

### Configuration (anchored to protocol.v1.json)
- `TransportConfig` composes protocol-crate constants (`MessageBounds`, `DEFAULT_DEADLINE_MS`) with transport-specific settings (queue capacities, keepalive, backoff, max-age, ACK deadline).
- Defaults: event queue 4096, control queue 64, deadline 30s, keepalive 30s/10s, max-age 1h, backoff 100ms/30s/2.0x, max reconnect 20, ACK deadline 60s.
- `validate()` returns a list of validation errors (empty = valid). Catches zero capacities, invalid backoff parameters, etc.

### BLOCKER: no live gRPC server or Kafka broker
- This host has no running gRPC server or Kafka broker. All transport logic is validated with in-memory mocks and fixtures. Live gRPC/Kafka integration re-opens on the declared self-hosted runner.
- The write loops "send" by incrementing metrics (no actual gRPC stream). The ACK read loop processes `AckMessage` structs fed via `mpsc::Sender` in tests.
- The `OutboxDeleter` trait abstracts the SQLite outbox; `MockOutboxDeleter` provides the test implementation.

### Dependencies added to workspace
- `parking_lot = "0.12"` — thread-safe metrics and mock state (already in workspace lock).
- All other deps (tokio, serde, serde_json, thiserror, tracing, protocol, identity-spiffe) were already in the workspace.

### Files created
- `crates/transport/` — new crate (Cargo.toml, src/{lib,error,config,sequence,queue,ack,peer,reconnect,channel,transport}.rs)
- `tests/fixtures/transport/` — 8 JSON fixtures (ack-ordering-happy, ack-ordering-receipt-only-rejected, reconciliation-gap-replay, reconciliation-generation-reset, queue-pressure-separate-channels, deadline-expiry-drop, backoff-no-redial-storm, peer-authorization-trust-domain)
- Workspace `Cargo.toml` updated to include `crates/transport`
- 90 tests pass (`cargo test -p transport`): covering ACK ordering, receipt-only rejection, outbox deletion, sequence reconciliation (gap/generation reset/contiguous), queue pressure independence, deadline expiry, backoff/circuit breaker, SPIFFE peer authorization, channel shutdown independence

## Task 40: Idempotent Kafka event publisher (crates/event-bus-kafka)

### Architecture: control-plane-only publisher with mock broker
- BLOCKER: this host has no running Kafka broker. All publisher logic is validated via `MockKafkaProducer` which simulates the idempotent producer contract (producer ID + per-partition sequence numbers, broker-side deduplication, acks=all durability, bounded in-flight, retry with backoff, leader failover). Live Kafka integration (real rdkafka producer against a KRaft cluster) re-opens on the declared self-hosted runner.
- The publisher runs EXCLUSIVELY in the control plane. Agents never see Kafka — no agent credentials beyond the control plane. The gRPC ACK to the agent is gated on the durable-delivery callback, which fires ONLY after the mock broker confirms acks=all acceptance.

### Idempotent producer invariants (config.rs)
- `acks = "all"`: every produce request waits for all in-sync replicas. Non-"all" values are rejected at config validation.
- `enable.idempotence = true`: the producer assigns a producer ID and sequence numbers per partition, enabling broker-side deduplication. Disabling is rejected.
- `max.in.flight.requests.per.connection <= 5`: required by Kafka's idempotent producer to guarantee ordering with retries. Values > 5 or 0 are rejected.
- `max_retries = i32::MAX` (Kafka default): the producer retries transient failures indefinitely. The mock caps at 10 attempts for test tractability.
- All constants anchored in `bench/schemas/kafka.v1.json` (default_broker_count=3, acks=all, enable_idempotence=true, max_in_flight_requests=5, topic_events=events.v1, topic_dlq=events.dlq.v1, delivery_semantics=at-least-once).

### Per-agent partition ordering (partition.rs)
- Partition key = `{cluster}/{agent_path}` (e.g., `prod/agent/prod/node-1`). SHA-256 of the key, first 8 bytes as big-endian u64, mod partition_count. Deterministic: same (cluster, agent) ALWAYS maps to the same partition for a given partition count.
- This guarantees all events from a single agent land on the same partition, preserving per-agent ordering. Different agents may share a partition (hash collision), but events from one agent are NEVER split across partitions.
- Default partition count is 12 (anchored in schema).

### Protobuf schema/version headers (headers.rs)
- Every record carries 5 headers: `schema_major` (u32 BE), `schema_minor` (u32 BE), `event_kind` (UTF-8 proto enum name from protocol crate's `EventKind::as_proto_name()`), `batch_id` (UTF-8), `idempotency_key` (UTF-8).
- Downstream consumers validate `schema_major` BEFORE deserializing the payload. A mismatch routes the batch to `events.dlq.v1` (the DLQ path). This is the "rejected schema at downstream" requirement.
- Header validation catches: missing schema_major, non-u32 value, major version mismatch.

### Mock Kafka producer with idempotent semantics (producer.rs)
- `MockKafkaProducer` simulates: per-partition offset assignment, (producer_id, sequence) deduplication, bounded in-flight tracking, transient failure injection, broker-down simulation, leader failover/recovery.
- Idempotent deduplication: if the broker sees a (producer_id, partition, sequence) triple it already committed, it returns the original offset with `is_duplicate: true` (DECLARED duplicate, not hidden).
- `produce_with_retry()` retries on `BrokerUnavailable` up to max_attempts (capped at 10 for tests). Non-retryable errors (QueueFull, SerializationFailed) return immediately.
- `FailureMode` enum: None, Transient{fail_count}, BrokerDown, QueueFull — enables deterministic testing of all failure paths.

### Durable-delivery callback (publisher.rs)
- `DurableDeliveryCallback = Box<dyn FnMut(DurableAcceptance) + Send + Sync>`. Fires ONLY after the broker confirms durable acceptance. The gRPC ACK to the agent is gated on this callback.
- Receipt-only callbacks are structurally absent — there is no code path that fires the callback without a `DurableAcceptance` from the producer.
- ACK ordering matches publish order for batches on the same partition (per-agent ordering guarantee).

### DLQ routing (dlq.rs)
- `DlqRouter` routes schema-rejected batches to `events.dlq.v1`. The DLQ record preserves the original payload and headers, plus 3 metadata headers: `dlq_reason`, `dlq_original_topic`, `dlq_original_partition`.
- No schema-rejected batch is silently dropped. Every DLQ routing increments the `batches_dlq` metric.

### Zero hidden loss invariant (metrics.rs)
- `verify_no_hidden_loss()`: `submitted == accepted + timed_out + queue_full + dlq + declared_duplicates + unrecoverable + broker_unavailable + in_flight`. Every submitted batch is accounted for.
- All duplicates are DECLARED (idempotent producer deduplication). No cross-session exactly-once claim.
- Metrics: batches_submitted, batches_accepted, batches_timed_out, batches_rejected_queue_full, batches_dlq, declared_duplicates, retries_total, unrecoverable_errors, broker_unavailable_events, in_flight (gauge), peak_in_flight.

### Deterministic event/batch IDs
- Batch ID = `batch-{idempotency_key}` (from protocol crate's `IdempotencyKey`). Deterministic: the same idempotency key always produces the same batch ID, enabling replay and reconciliation.
- Event IDs come from the protocol crate's `Event.event_id` (UUIDv7 or platform-equivalent).

### Integration with protocol and transport crates
- Depends on `protocol` for `Batch`, `Event`, `EventKind`, `IdempotencyKey`, `SCHEMA_MAJOR`, `SCHEMA_MINOR`.
- Mirrors `transport::ack::KafkaAcceptance` with `DurableAcceptance` (topic, partition, offset, is_duplicate). The transport crate's `AckTracker` gates the gRPC ACK on Kafka acceptance; this publisher provides the acceptance signal.
- Does NOT depend on transport directly at the type level (avoids circular dependency); the control plane wires the publisher's `DurableAcceptance` into the transport's `AckTracker.record_kafka_acceptance()`.

### Bench harness (bench/kafka-resilience.sh)
- Phase 0: schema preconditions (acks=all, enable.idempotence=true, default_broker_count>=1, topics correct, delivery=at-least-once).
- Phase 1: `cargo test -p event-bus-kafka` (67 tests).
- Phase 2: fixture validation (9 JSON fixtures, all valid).
- Phase 3: required fixture coverage (partition-ordering, idempotent-retry, ack-ordering, dlq-schema-rejection, queue-full, broker-failover, producer-restart, malformed-headers, zero-hidden-loss).
- Phase 4: 12 safety invariants checklist.
- Phase 5: live Kafka integration reported as BLOCKED.
- Usage: `bench/kafka-resilience.sh --schema bench/schemas/kafka.v1.json --brokers 3 --workload publish-burst`.

### Compile bug hit: FailureMode::Transient is a struct variant
- `FailureMode::Transient { fail_count: u32 }` is a struct variant, not a unit variant. Cannot compare with `==` directly. FIX: use `matches!(self.failure_mode, FailureMode::Transient { .. })` instead of `self.failure_mode == FailureMode::Transient`.

### Compile bug hit: HEADER_DLQ_REASON defined in dlq.rs, not headers.rs
- The DLQ metadata header constants (`HEADER_DLQ_REASON`, `HEADER_DLQ_ORIGINAL_TOPIC`, `HEADER_DLQ_ORIGINAL_PARTITION`) are defined in `dlq.rs`, not `headers.rs`. The test module in dlq.rs imports them via `use super::*` (parent module), not from `crate::headers`.

### Files created
- `crates/event-bus-kafka/` — new crate (Cargo.toml, src/{lib,error,config,partition,headers,producer,dlq,metrics,publisher}.rs)
- `bench/schemas/kafka.v1.json` — Kafka publisher constants schema
- `bench/kafka-resilience.sh` — resilience bench harness
- `tests/fixtures/kafka/` — 9 JSON fixtures (partition-ordering, idempotent-retry, ack-ordering, dlq-schema-rejection, queue-full, broker-failover, producer-restart, malformed-headers, zero-hidden-loss)
- Workspace `Cargo.toml` updated to include `crates/event-bus-kafka`
- 67 tests pass (`cargo test -p event-bus-kafka`): covering config validation, partition ordering/determinism/distribution, schema header round-trip/validation, idempotent deduplication, transient retry, leader failover/recovery, queue full backpressure, broker down, DLQ routing, durable callback firing/ordering, zero hidden loss across mixed outcomes

## Task 41: ClickHouse event ingestion with explicit deduplication and DLQ (deploy/clickhouse/, crates/analytics-clickhouse)

### Architecture: Kafka → ClickHouse pipeline with ReplacingMergeTree
- BLOCKER: this host has no running ClickHouse or Kafka instance. All SQL/config is defined for deployment; all Rust query logic is validated via in-memory mocks and fixtures. Live integration re-opens on the declared self-hosted runner.
- Pipeline: `events.v1` (Kafka) → `events_v1_kafka` (Kafka engine table, consumer group) → `events_v1_mv` (materialized view) → `events_v1` (ReplacingMergeTree). Schema-rejected messages route to `events_dlq_v1` via a separate MV.
- ClickHouse is control-plane only: agents never connect directly. No agent credentials stored.

### ReplacingMergeTree deduplication: FINAL/argMax, NOT background merges
- `events_v1` uses `ReplacingMergeTree(_version)` with `ORDER BY (event_id)`. The `_version` column is set to `kafka_offset` (monotonically increasing proxy: re-delivered messages get higher offsets, so latest delivery wins).
- CRITICAL: background merges do NOT guarantee immediate uniqueness. Exact queries MUST use `FINAL` (merge-on-read) or `argMax(col, _version) ... GROUP BY event_id` (aggregate dedup). The `events_v1_exact_final` and `events_v1_exact_argmax` views encode these patterns.
- The `events_v1_duplicates` view exposes physical duplicates before merge (count > 1 per event_id). Fixture test proves: replay same event_id 100 times → 100 physical rows visible → exact query returns 1 logical row with version 99.

### Schema design (0001_events_v1.sql)
- Columns mirror protocol crate's `Event`/`Batch`: event_id, batch_id, seq, schema_major/minor, event_kind (LowCardinality), sensor, agent_generation, node_name, cluster (all LowCardinality), ts_monotonic_ns, boot_id_hex (FixedString(32)), pid_tgid, cgroup_id, uid, gid.
- Kafka transport metadata preserved: kafka_topic, kafka_partition, kafka_offset, kafka_timestamp — for forensics and lag tracking.
- Bounded payload: `substring(payload, 1, 65536)` in the MV caps at 64 KiB. The Rust crate's `EventRow::truncate_payload()` mirrors this.
- TTL: `_ttl_expires_at = now() + INTERVAL {events_ttl_days:UInt16} DAY` (default 30d, configurable via macro, 0 = disabled). Partitioned by `toYYYYMMDD(ingested_at)`.
- Secondary bloom_filter indexes on (node_name, event_kind) and (batch_id).

### Kafka consumer + materialized view (0002_kafka_consumer.sql)
- `events_v1_kafka` uses `ENGINE = Kafka()` with `kafka_format = 'JSONEachRow'`, `kafka_group_name = '{kafka_consumer_group:String}'`, `kafka_skip_broken_messages = 0` (strict: parse failures stop consumer).
- The MV transforms raw Kafka messages: `toLowCardinality()` for dimensions, `toFixedString(boot_id_hex, 32)`, `substring(payload, 1, 65536)`, `_offset AS _version`.
- Consumer group configurable per-environment via macro. Default: `clickhouse-events-v1`.

### DLQ routing (0003_dlq_metadata.sql)
- `events_dlq_v1` captures: original_topic/partition/offset (for forensic replay), dlq_reason (LowCardinality), best-effort parsed fields, raw_payload (bounded 64 KiB), raw_key.
- `events_dlq_schema_rejected_mv` fires on `schema_major != 1` (the supported version from protocol::SCHEMA_MAJOR). Mirrors the event-bus-kafka DlqRouter metadata headers (dlq_reason, dlq_original_topic, dlq_original_partition).
- DLQ TTL: 90 days (longer than events for forensic analysis). Configurable via `{dlq_ttl_days}` macro.
- Malformed messages are NEVER silently dropped. Consumer continues after DLQ routing (fixture-validated).

### Consumer lag metrics (0004_consumer_lag_metrics.sql)
- `events_v1_consumed_offsets`: per-partition high-water mark from events_v1.
- `events_v1_consumer_lag`: joins consumed offsets against latest available. Bounded lag threshold: 10,000 messages/partition (anchored in Rust crate's `ConsumerLagMetrics::is_within_bounds()`).
- `events_dlq_v1_rate`: DLQ routing rate per reason category (for alerting on schema drift).
- BLOCKER: live lag metrics require a running Kafka broker. View returns `estimated_lag = 0` on this host.

### Exact-query helpers (0005_exact_query_helpers.sql)
- `events_v1_exact_final`: `SELECT * FROM events_v1 FINAL` — merge-on-read, correct but slower for large scans.
- `events_v1_exact_argmax`: `SELECT argMax(col, _version) ... GROUP BY event_id` — aggregate dedup, faster for analytics.
- `events_v1_duplicates`: `HAVING count() > 1` — shows physical duplicates before merge.

### Cluster-compatible replication (config.xml)
- Single-node: plain `ReplacingMergeTree` (no ZooKeeper needed).
- Cluster: switch to `ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/events_v1', '{replica}', _version)` with macros from config.xml.
- config.xml defines macros (cluster/shard/replica), Kafka defaults, MergeTree settings (replicated_deduplication_window=1000), and commented-out remote_servers/zookeeper sections.
- NO live cluster operated — configuration only.

### Migration repeatability (migration.rs)
- All 5 migrations use `CREATE TABLE/VIEW IF NOT EXISTS` and `ADD INDEX IF NOT EXISTS`. No DROP/TRUNCATE/INSERT/DELETE/UPDATE.
- The Rust `migration::validate_repeatable()` strips SQL comments before checking for destructive patterns (prevents false positives from comments mentioning "INSERT INTO" etc.).
- `migration::embedded_migrations()` uses `include_str!` to embed all 5 SQL files at compile time. Tests validate repeatability and ordering.

### Rust crate structure (crates/analytics-clickhouse)
- `schema.rs`: `EventRow` (mirrors events_v1 DDL), `EventKind` (mirrors protocol crate), `EventRowBuilder` (Kafka metadata injection + validation + payload truncation).
- `query.rs`: `ExactQueryBuilder` with `Final`/`ArgMax` strategies, SQL injection escaping, `build_duplicate_detector_query()`, `build_exact_count_query()`.
- `dedup.rs`: `DeduplicationEngine` — in-memory mirror of ReplacingMergeTree semantics. Stores all physical rows, provides `exact_rows()` (max version per event_id) and `duplicated_event_ids()`.
- `dlq.rs`: `DlqRouter` with `route_schema_rejected()`, `route_malformed()`, `route_unknown_event_kind()`. `DlqReason` enum with `as_reason_string()` matching ClickHouse DLQ reason format.
- `consumer.rs`: `PartitionLag`, `ConsumerLagMetrics` (bounded threshold 10,000/partition), `ConsumerConfig` (mirrors Kafka engine SETTINGS).
- `migration.rs`: `validate_repeatable()`, `validate_ordering()`, `embedded_migrations()`.

### Compile bug hit: SQL comments trigger destructive pattern false positives
- The migration validator initially flagged `0002_kafka_consumer.sql` because a comment contained "INSERT into events_v1_kafka". FIX: strip SQL `--` comments before pattern matching in `validate_repeatable()`.

### Compile bug hit: fixture paths relative to crate dir, not workspace root
- Integration tests use `CARGO_MANIFEST_DIR` to resolve fixture paths: `{manifest}/../../tests/fixtures/clickhouse/{name}`. Without this, `std::fs::read_to_string("tests/fixtures/...")` fails because the test binary's CWD is the crate directory.

### Files created
- `deploy/clickhouse/` — 5 SQL migrations (0001-0005), config.xml, README.md
- `crates/analytics-clickhouse/` — new crate (Cargo.toml, src/{lib,error,schema,query,dedup,dlq,migration,consumer}.rs, tests/integration.rs)
- `tests/fixtures/clickhouse/` — 5 JSON fixtures (valid-batch, duplicate-replay, malformed-dlq, ttl-config, consumer-lag)
- Workspace `Cargo.toml` updated to include `crates/analytics-clickhouse`
- 75 tests pass (`cargo test -p analytics-clickhouse`): 66 unit + 9 integration

## Task 42: Authenticated stateless control-plane query and live-stream API (crates/control-plane)

### Architecture: stateless JWT auth, cluster-scoped queries, bounded everything
- BLOCKER: this host has no live PostgreSQL, ClickHouse, or Kafka. All API logic is validated via in-memory mocks from `control-db::test_support` and fixture-driven tests. Live integration re-opens on the declared self-hosted runner.
- The control-plane is a query/fanout API layer, NOT an HTTP server. It provides typed handler functions, a route table with RBAC enforcement, and a live event hub. An HTTP framework (axum/actix) wires these into a running server in a later task.
- Data source hierarchy: PostgreSQL = control truth (fleet, policies, rollouts, audit), ClickHouse = event history (historical queries with dedup), Kafka/gRPC = live hints ONLY (not authoritative).

### Stateless JWT auth (no server-side sessions)
- The `RequestContext` carries sub, groups, resolved role, and cluster scope. No `SessionStore` is used at the API layer — the auth crate's session management is for the OIDC login flow, not per-request validation.
- `authorize_request()` resolves the role via `RbacPolicy::resolve_role()`, checks the route's required action, and guards viewer roles from mutations (defense in depth: even if the action check passes, viewers are blocked from mutation routes).
- Denied mutations emit audit intents with `denied:` prefix for security monitoring.

### RBAC negative matrix (all 4 roles × denied actions)
- Viewer denied: policies/stage, policies/commit, policies/rollback, agents/register, config (all mutations).
- Analyst denied: policies/stage, policies/commit, policies/rollback, config (Admin+ routes).
- Policy-admin denied: config (SuperAdmin route).
- Unbound subject (no group binding): denied everything with `NoRoleBinding`.
- The route table mirrors task 6 OpenAPI action annotations exactly.

### Cluster scoping invariant (every query is cluster-scoped)
- `resolve_cluster_scope()` requires either an explicit cluster UUID or a configured default. Missing scope → `MissingClusterScope` (HTTP 400).
- `get_agent()` and `get_node()` verify the returned entity's `cluster_id` matches the expected scope. Mismatch → `CrossClusterDenied` (HTTP 400).
- The mock repositories enforce RLS cluster isolation at the data layer (defense in depth).

### Bounded query limits (pagination, max window)
- `PageRequest` with opaque base64 cursors (URL-safe, no pad). Cursor encodes `{offset, v}` as JSON → base64. Forward-compatible via version tag.
- Page size clamped to `max_page_size` (default 200, hard cap 10,000). Zero clamped to 1.
- Time window validated: `end - start <= max_window_s` (default 86,400s = 24h, hard cap 30 days). Oversized → `WindowExceeded` (HTTP 400).
- ClickHouse queries use `ExactQueryBuilder` from analytics-clickhouse with mandatory cluster filter.

### Redacted live event fanout (LiveHub)
- Per-cluster ring buffers with bounded capacity (default 256 per subscriber, stream retention = 4× buffer cap).
- Cursor-based reconnect: subscriber provides last-seen seq, receives all events after that seq still retained. Cursor older than oldest retained → `LiveCursorExpired` (HTTP 410, must fall back to ClickHouse historical query).
- Slow-client shedding: if a subscriber's buffer is full for `slow_client_threshold` consecutive publishes (default 8), the subscriber is shed (disconnected, buffer cleared). Drain returns `SlowClientShed` (HTTP 429).
- Drain resets the missed counter — a subscriber that consumes events recovers.
- Live events are HINTS: they carry redacted payloads and event IDs for cross-referencing with ClickHouse. NOT authoritative.

### API-boundary redaction (redact.rs)
- Every `EventRow` from ClickHouse is redacted before crossing the API boundary. The raw payload is NEVER returned.
- Secret patterns match the privacy crate's defaults: AWS keys (AKIA...), Stripe keys (sk_live/test_...), api_key assignments, Bearer tokens, password/token assignments.
- Payload truncated to 4 KiB (MAX_RESPONSE_PAYLOAD_BYTES). Oversized → truncated + `payload_redacted: true`.
- Fail-closed: if a regex pattern fails to compile, the entire payload is withheld (`[PAYLOAD_WITHHELD]`).
- The `RedactedEventRow` struct has NO raw payload field — structurally impossible to leak.

### Audit hooks (every mutation emits actor-bound intent)
- `AuditHook` wraps `auth::AuditSink`. Mutations call `record_mutation(actor, action, resource)`. Denied mutations call `record_denied(actor, action, resource, reason)`.
- Read-only operations do NOT emit intents.
- Sequence numbers are monotonic (assigned by the sink).

### Static UI serving (ui.rs)
- Path traversal protection: `..` components and absolute paths are blocked. Leading `/` is stripped (URL root, not filesystem).
- Content-type detection by extension (html, js, css, json, svg, png, woff2, wasm, etc.).
- Cache-Control: HTML gets `no-cache, must-revalidate`; hashed assets (js/css/woff2/wasm) get `public, max-age=31536000, immutable`.

### Compile bug hit: LiveHub publish fanned out seq=0 events
- `publish()` stored the seq-assigned event in the cluster stream but fanned out the ORIGINAL event (seq=0) to subscribers. FIX: assign `event.seq = seq` BEFORE fanning out, so subscribers receive the seq-assigned version.

### Dependencies
- `auth` (path) — RBAC policy, roles, actions, audit sink.
- `control-db` (path) — FleetRepository, PolicyRepository, AuditRepository traits + mock implementations.
- `analytics-clickhouse` (path) — ExactQueryBuilder, EventRow, EventKind.
- `regex = "1"` — API-boundary secret pattern matching.
- `base64 = "0.22"` — opaque cursor encoding.
- All other deps (serde, serde_json, thiserror, tracing, uuid, chrono, parking_lot) already in workspace.

### Files created
- `crates/control-plane/` — new crate (Cargo.toml, src/{lib,error,config,pagination,health,redact,inventory,history,control,live,audit,router,ui}.rs)
- `tests/fixtures/control-plane/` — 3 JSON fixtures (rbac-negative-matrix, cluster-isolation, redaction)
- Workspace `Cargo.toml` updated to include `crates/control-plane`
- 114 tests pass (`cargo test -p control-plane`): covering RBAC negative matrix (all roles × denied actions), cluster isolation (cross-cluster denied), redaction (AWS/Stripe/Bearer/password masking, truncation, fail-closed), pagination (cursor round-trip, limit clamping, window bounds), live hub (fanout, cluster isolation, slow-client shedding, cursor reconnect, cursor expiry, sequence monotonicity), health/compatibility, audit emission, static UI (path traversal, content-type, cache-control), config validation
