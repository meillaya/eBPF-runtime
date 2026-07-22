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
