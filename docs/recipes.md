# Kernel-debugging recipes

Practical queries against a local `ebpf-fleet` bundle. All commands use the
release binary and the event columns in the bundle's `events` table.

```bash
sudo ebpf-fleet record --for 30s --out /tmp/incident.fleet
```

## 1. What just executed?

```bash
ebpf-fleet query /tmp/incident.fleet \
  "select time, pid, parent_pid, process_exec from events
   where kind = 'ProcessExec' order by time desc limit 30"
```

## 2. Which processes are doing the most work?

```bash
ebpf-fleet query /tmp/incident.fleet \
  "select pid, process_exec, count(*) as events
   from events where process_exec is not null
   group by pid, process_exec order by events desc limit 20"
```

## 3. Which files are being opened most often?

```bash
ebpf-fleet query /tmp/incident.fleet \
  "select path, count(*) as n from events
   where kind = 'FileOpen' and path is not null
   group by path order by n desc limit 20"
```

## 4. What did one process open?

```bash
ebpf-fleet query /tmp/incident.fleet \
  "select time, path, open_flags from events
   where kind = 'FileOpen' and process_exec like '%nginx%'
   order by time"
```

## 5. What was deleted?

```bash
ebpf-fleet query /tmp/incident.fleet \
  "select time, pid, process_exec, path from events
   where kind = 'FileUnlink' order by time"
```

## 6. Did anything exit non-zero?

```bash
ebpf-fleet query /tmp/incident.fleet \
  "select time, pid, process_exec, exit_code from events
   where kind = 'ProcessExit' and exit_code != 0 order by time"
```

## 7. Parent/child process trail

```bash
ebpf-fleet query /tmp/incident.fleet \
  "select time, pid, parent_pid, child_pid, process_exec
   from events where kind in ('ProcessFork','ProcessExec')
   order by time limit 100"
```

## 8. Event-kind overview

```bash
ebpf-fleet query /tmp/incident.fleet \
  "select kind, count(*) as n from events group by kind order by n desc"
```

## 9. Fast top view

```bash
ebpf-fleet top /tmp/incident.fleet
```

For a live view, omit the bundle. `q` quits.

## 10. Compare before and after

```bash
ebpf-fleet diff /tmp/before.fleet /tmp/after.fleet
```

`diff` currently compares event-kind counts. Per-process and per-path deltas
are planned for 0.3.

## 11. Share the evidence

```bash
ebpf-fleet pack /tmp/incident.fleet /tmp/incident.tar.zst
ebpf-fleet unpack /tmp/incident.tar.zst /tmp/incident-restored.fleet
ebpf-fleet query /tmp/incident-restored.fleet "select count(*) from events"
```

The bundle is self-contained. A crash or SIGKILL leaves an incomplete
bundle and `query` rejects it rather than returning partial data.

## Notes

- `argv` is a list column; it is available in `raw_json` and in the decoded
  event JSON. Use `select argv` to inspect it directly.
- `time` is RFC 3339 in UTC; `time_unix_ns` is available for arithmetic.
- Stack columns and per-process diff output arrive in 0.3; this page will be
  updated with those queries rather than documenting them prematurely.
