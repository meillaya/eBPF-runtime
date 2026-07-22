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
