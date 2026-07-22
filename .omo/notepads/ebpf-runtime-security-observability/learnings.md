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
