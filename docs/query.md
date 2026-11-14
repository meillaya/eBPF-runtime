# Querying, inspecting, and exploring bundles

Local incident bundles are self-contained directories: a `manifest.json` and
columnar Parquet parts. `ebpf-fleet` reads them with SQL (DataFusion) and has
first-class surfaces for machine output, bundle inspection, before/after
diffing, and an interactive terminal view. Everything here works offline and
does not require fleet mode or any external service.

Run `ebpf-fleet --help` (or `ebpf-fleet <command> --help`) for the complete
flag list. This page covers the daily workflow.

## `query`: SQL with output formats

```bash
ebpf-fleet query BUNDLE [SQL] [--format table|json|csv|parquet] [--out FILE]
                        [--table events|stacks|probe_events] [--limit N]
                        [--schema] [--explain]
```

The legacy behaviour is unchanged: with no SQL, `query` prints a kind-count
summary table, and positional SQL runs over the `events` table.

```bash
# default: aligned table, kind summary
ebpf-fleet query /tmp/incident.fleet

# SQL as before
ebpf-fleet query /tmp/incident.fleet \
  "select path, count(*) as n from events where kind='FileOpen' group by path order by n desc limit 10"
```

### Tables

| table | contents |
| --- | --- |
| `events` | decoded process/file events (and, in v1 bundles, the frozen 0.2 columns) |
| `stacks` | resolved stacks: `stack_id`, `sensor`, `frames` (list of struct), `truncated` |
| `probe_events` | decoded custom-probe rows: `probe`, `kind`, `kind_name`, `time_unix_ns`, `time`, `pid`, `tgid`, `cgroup_id`, `payload_json`, `raw` |

Every table is always registered. A 0.2 (v1) bundle exposes an empty
`stacks` table, and a bundle without custom probes exposes an empty
`probe_events` table, so the same SQL shape works across versions. Join
events to their stacks on `(sensor, stack_id)`:

```bash
ebpf-fleet query /tmp/incident.fleet "
  select e.kind, e.path, s.frames
  from events e
  join stacks s on e.sensor = s.sensor and e.stack_id = s.stack_id
  order by e.time_unix_ns limit 5"
```

`--table` selects the default SQL/schema when no SQL is given, e.g.
`--table stacks` prints the stack table and `--table probe_events` groups
custom-probe counts.

### Formats

`--format` selects the row encoding. Streaming is used for `json`, `csv`,
and `parquet`: rows are written batch by batch, and `--limit` stops the
stream early. `table` collects the (bounded) result before aligning columns.

| format | shape | notes |
| --- | --- | --- |
| `table` (default) | aligned text table | the 0.2 output; `no rows` on stderr for empty results |
| `json` | **newline-delimited JSON**, one object per row | streamable; array output was rejected so a 10M-row query never needs 10M objects in memory |
| `csv` | RFC 4180 with a header row | proper quoting/escaping; header emitted even for zero rows |
| `parquet` | one Parquet file | requires `--out`; schema comes from the query, so empty results still produce a valid file |

```bash
# one JSON object per line
ebpf-fleet query /tmp/incident.fleet \
  "select kind, path from events limit 3" --format json

# CSV for spreadsheets
ebpf-fleet query /tmp/incident.fleet \
  "select path, count(*) as n from events group by path" --format csv --out counts.csv

# Parquet for other Arrow tools
ebpf-fleet query /tmp/incident.fleet \
  "select * from events" --format parquet --out events.parquet
```

`--out FILE` writes the payload to a file (stdout stays empty) and prints a
one-line summary on stderr. `--limit N` caps the emitted rows (`--limit 0`
emits no rows; omitting it means unlimited). For `json`/`csv`/`parquet` a
cropped final batch is sliced, so the limit is exact.

### Schema and plans

```bash
# Arrow schema of a table (default: events)
ebpf-fleet query /tmp/incident.fleet --schema
ebpf-fleet query /tmp/incident.fleet --schema --table stacks

# DataFusion logical + physical plan, no execution
ebpf-fleet query /tmp/incident.fleet \
  "select count(*) from events" --explain
```

`--schema` works on empty bundles (it needs no data parts). `--explain`
prints the `logical_plan` and `physical_plan` rows of `EXPLAIN`; it does not
apply `--format`/`--limit` and does not execute the query.

## `inspect`: one-screen bundle summary

```bash
ebpf-fleet inspect BUNDLE [--json]
```

`inspect` opens the bundle (which already validates the manifest, the path
layout, and every part SHA-256) and reports:

- format/version (`ebpf-fleet.bundle/v1` or `/v2`, Arrow schema version),
  creation time, tool version/commit, complete flag, integrity verdict;
- host facts recorded at capture time (arch, kernel release, boot id,
  lockdown, LSM list, BTF hash);
- capture parameters (sensors, duration, `stack_mode`);
- manifest counts (events, stacks, probe rows, dropped counters);
- per-table part file counts, row counts, and bytes;
- stack coverage (kernel/user frames, symbolized frames, missing symbols,
  truncated stacks, sensors) computed from the `stacks` table;
- custom-probe rows and their probe names.

```bash
ebpf-fleet inspect /tmp/incident.fleet
ebpf-fleet inspect /tmp/incident.fleet --json | jq '.counts, .stack_coverage'
```

## `diff`: compare two bundles

```bash
ebpf-fleet diff A B [--by kind|process|path|stack] [--limit N] [--json]
```

Without `--by`, the output is the 0.2 kind-count table (`kind`, `before`,
`after`, `delta`). `--by` groups by:

| `--by` | key |
| --- | --- |
| `kind` | event kind (same counts as the default, sorted by delta) |
| `process` | process executable, falling back to the event path, then `?` |
| `path` | file path, falling back to the old path, then `?` |
| `stack` | first symbolized frame of the joined stack (`sensor#id` when unsymbolized) |

`--by` modes sort by absolute delta (largest change first), so `--limit N`
keeps the most interesting rows. `--json` emits:

```json
{
  "by": "kind",
  "limit": 10,
  "before_bundle": "before.fleet",
  "after_bundle": "after.fleet",
  "rows": [{"key": "FileOpen", "before": 1, "after": 3, "delta": 2}],
  "totals": {"before": 1, "after": 3, "delta": 2}
}
```

## `record --json/--quiet` and live progress

`record` keeps writing a bundle, the stderr summary, and `--stats` JSON.
Two UX flags were added:

- `--json` prints one machine-readable object on stdout (bundle path, format,
  event/stack/dropped counts, decode and stack-read errors, elapsed
  milliseconds, stack mode, and the full `--stats` object under `stats`).
  It can be combined with `--stats` (a single object is printed; the separate
  stats block is suppressed).
- `--quiet` suppresses the progress line and final stderr summary; errors
  still print.

On a TTY stderr, `record` shows a live progress line
(`recording: N events, S distinct stacks, E decode errors`) at most twice a
second. Non-TTY stderr keeps the 0.2 behaviour: only the final summary line.

```bash
sudo ebpf-fleet record --for 10 --out /tmp/incident.fleet --json | jq .
sudo ebpf-fleet record --for 10 --out /tmp/incident.fleet --stats --quiet
```

## `top`: interactive TUI

```bash
ebpf-fleet top BUNDLE          # explore a recorded bundle
ebpf-fleet top                 # live view of the local sensors (root)
ebpf-fleet top BUNDLE --refresh-ms 250
```

Bundle mode loads the events once so filters can be re-applied locally.
Live mode counts events as they arrive. Panes: top processes, top file
paths, event kinds, recent events, resolved stacks, plus a header with
counters/sort/pause/filter state and a footer prompt/status line.

| key | action |
| --- | --- |
| `space` | pause/resume (live: events are drained but not counted; bundle: indicator only) |
| `s` | cycle sort order: by count (default) or by name |
| `p` | prompt for a process substring filter |
| `f` | prompt for a path substring filter |
| `k` | prompt for an event kind substring filter |
| `x` | clear all filters |
| `w` | save a JSON snapshot (`top-snapshot-<epoch>.json` in the current directory) |
| `q` / `esc` | quit |

Filter prompts are case-insensitive substring matches; `enter` applies and
`esc` cancels. In bundle mode filters re-apply to the already-loaded rows;
in live mode a filter change resets the view and matching starts from that
moment. The stack pane always shows the bundle-wide stacks table.

When stdout is not a terminal (pipes, CI), `top BUNDLE` prints a plain text
summary instead of the TUI; live `top` without a terminal prints an error
suggesting `record` + `top BUNDLE`.

Snapshot JSON contains the filtered counters, filters, sort mode, and
generated-at epoch, so a TUI session can be archived or diffed.

## Shell completions and man pages

```bash
# print completions on stdout
ebpf-fleet completions bash
ebpf-fleet completions zsh
ebpf-fleet completions fish
ebpf-fleet completions powershell

# print the main man page, or write one page per subcommand
ebpf-fleet man
ebpf-fleet man --out /tmp/man
```

The `man --out DIR` form writes `ebpf-fleet.1` plus one page per subcommand
(for example `ebpf-fleet-query.1`, `ebpf-fleet-record.1`,
`ebpf-fleet-inspect.1`). Suggested install locations:

```bash
# bash completion (system-wide)
sudo ebpf-fleet completions bash > /usr/share/bash-completion/completions/ebpf-fleet

# zsh / fish
sudo ebpf-fleet completions zsh > "${fpath[1]}/_ebpf-fleet"
sudo ebpf-fleet completions fish > ~/.config/fish/completions/ebpf-fleet.fish

# man pages
sudo ebpf-fleet man --out /usr/local/share/man/man1
sudo mandb
```

## Compatibility notes

- Existing defaults are preserved: `query` with no SQL still prints the
  kind summary; positional SQL is unchanged; `diff A B` without `--by` is
  byte-compatible with the 0.2 table; non-TTY `top` output is unchanged.
- v1 (0.2) bundles are read with the frozen event schema and empty
  `stacks`/`probe_events` tables.
- Parquet output requires `--out`; JSON is newline-delimited (not a JSON
  array); CSV headers are always written.
- `record --json` prints a single JSON object on stdout; human-readable
  warnings stay on stderr.
