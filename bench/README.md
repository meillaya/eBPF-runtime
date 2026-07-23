# bench/ — Comparative Benchmark Harness

Reproducible, fair benchmark harness that measures the overhead of the
kernel-v1 agent (observe and enforce modes) against the no-agent baseline
and traditional alternatives (strace, auditd, Falco). Produces the
sub-5% release-gate evidence required by task 60.

## Quick start

```bash
# 1. Validate the harness without running workloads:
bench/benchmark.sh --dry-run

# 2. Run the full suite (all workloads × all comparators):
bench/benchmark.sh

# 3. Run a subset:
bench/benchmark.sh --workloads cpu,syscall --comparators no-agent,observe

# 4. Analyze results:
bench/analyze.sh --in bench/bench-out/
```

## Prerequisites

| Tool | Required | Used by |
|------|----------|---------|
| `jq` | **yes** | All scripts (schema parsing, JSONL tagging) |
| `python3` | **yes** | Workload generators, statistical analysis |
| `shellcheck` | dev | Lint all scripts (`shellcheck bench/**/*.sh`) |
| `strace` | optional | `comparators/strace.sh` (skips if missing) |
| `auditctl` | optional | `comparators/auditd.sh` (skips if missing, needs root) |
| `falco` | optional | `comparators/falco.sh` (skips if missing) |
| `target/debug/agent` | optional | `comparators/observe.sh`, `comparators/enforce.sh` (skips if missing) |

Build the agent binary:

```bash
cargo build -p agent
```

## Directory layout

```
bench/
├── benchmark.sh              # Main orchestrator
├── analyze.sh                # Statistical analysis pipeline
├── README.md                 # This file
├── schemas/
│   └── runs.v1.json          # Source of truth for all constants
├── workloads/
│   ├── cpu.sh                # SHA-256 compute loop
│   ├── io.sh                 # Sequential write + random read
│   ├── net.sh                # TCP loopback echo
│   └── syscall.sh            # getpid/gettimeofday/open/close/stat
├── comparators/
│   ├── no-agent.sh           # Baseline (bare workload)
│   ├── observe.sh            # Agent in dev/audit mode
│   ├── enforce.sh            # Agent with deny policy
│   ├── strace.sh             # strace -f -e trace=all
│   ├── auditd.sh             # auditctl -w watch
│   └── falco.sh              # Falco with default rules
└── bench-out/                # Output (gitignored)
    ├── runs.jsonl            # Raw run data (one JSON line per iteration)
    ├── manifest.json         # Run metadata (schema, env, flags)
    ├── skipped.json          # Comparators skipped with reason
    └── analysis.json         # Statistical analysis + gate verdict
```

## Schema: `bench/schemas/runs.v1.json`

Every numeric constant the harness uses is anchored in this schema.
The harness refuses to start if the schema is missing or malformed.

| Constant | Default | Description |
|----------|---------|-------------|
| `sample_size` | 30 | Measured iterations per (workload, comparator) pair |
| `warmup_iterations` | 5 | Warmup iterations (discarded) |
| `ops_per_iteration` | 10000 | Operations per measured iteration |
| `confidence_level` | 0.95 | CI confidence level |
| `default_p99_latency_max_pct` | 5 | Release gate: max p99 increase % |
| `default_throughput_decrease_max_pct` | 5 | Release gate: max throughput decrease % |
| `workloads` | `[cpu, io, net, syscall]` | Workload identifiers |
| `comparators` | `[no-agent, observe, enforce, strace, auditd, falco]` | Comparator identifiers |

## Output format

### `runs.jsonl` — one JSON line per measured iteration

```json
{"ts":"2026-07-22T12:00:00+0000","workload":"cpu","comparator":"no-agent","iteration":1,"p50_ns":1234,"p95_ns":2345,"p99_ns":3456,"p999_ns":4567,"throughput_ops":123456.78,"cpu_pct":95.2,"rss_kb":8192}
```

### `analysis.json` — statistical analysis + gate verdict

```json
{
  "schema_version": 1,
  "analysis": [
    {
      "workload": "cpu",
      "comparator": "observe",
      "n": 30,
      "baseline_p99_ns": 3456.0,
      "comparator_p99_ns": 3535.0,
      "p99_increase_pct": 2.29,
      "p99_ci_upper_pct": 4.12,
      "baseline_throughput_ops": 123456.78,
      "comparator_throughput_ops": 121234.56,
      "throughput_decrease_pct": 1.80,
      "throughput_ci_upper_pct": 3.50,
      "confidence_level": 0.95,
      "p99_latency_max_pct": 5.0,
      "throughput_decrease_max_pct": 5.0,
      "pass": true
    }
  ],
  "gate_summary": {
    "total_pairs": 8,
    "passed": 8,
    "failed": 0,
    "all_pass": true
  }
}
```

## Statistical method

For each (workload, comparator) pair, the analysis computes **paired
differences** against the no-agent baseline, aligned by iteration index:

1. `d_i = comparator_p99_i - baseline_p99_i` for each iteration `i`
2. Mean difference `d̄` and standard error `SE = s(d) / √n`
3. 95% CI upper bound: `d̄ + t_{0.975, n-1} × SE`
4. Percentage: `d̄ / baseline_mean × 100`
5. **Pass** iff the CI upper bound ≤ schema threshold (5% default)

The t critical value uses a Cornish-Fisher expansion for the
t-distribution, accurate for n ≥ 3.

## Comparator notes

- **no-agent**: Bare workload. The mandatory baseline.
- **observe**: Agent in `--dev` mode (audit-first default: every policy
  starts at mode=0; the LSM hook never changes the syscall result).
- **enforce**: Agent with a deny policy active. Currently runs the agent
  in dev mode; a true enforce measurement requires loading a deny policy
  via the control-plane API (wired in a future task).
- **strace**: `strace -f -e trace=all -o /dev/null`. Full ptrace-based
  syscall tracing. Expected to show 10-100× overhead.
- **auditd**: `auditctl -w /tmp/bench-auditd -p wa`. Kernel audit
  subsystem watch. Requires root.
- **falco**: Falco with default rules. Requires root and a kernel probe.
  Skips gracefully if not installed.

## Reproducibility

- All workloads use fixed seeds and deterministic code paths.
- Warmup iterations prime caches before measurement.
- The schema anchors every constant; changing a threshold requires
  updating the schema (not the scripts).
- The manifest records kernel release, BTF hash, and schema path for
  environment reproducibility.

## Lint

```bash
shellcheck bench/benchmark.sh bench/analyze.sh \
  bench/workloads/*.sh bench/comparators/*.sh
```

<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
