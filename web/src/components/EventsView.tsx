import { useDeferredValue, useMemo, useState } from "react";
import type { Event } from "../types";
import {
  download,
  eventSearchText,
  formatClock,
  kindTone,
  relativeTime,
  titleCase,
} from "../lib/format";
import { Badge, Button, Card, EmptyState, SearchInput, TableShell } from "./ui";

export function EventsView({
  events,
  onEvent,
}: {
  events: Event[];
  onEvent: (event: Event) => void;
}) {
  const [search, setSearch] = useState("");
  const [kind, setKind] = useState("all");
  const deferredSearch = useDeferredValue(search.trim().toLowerCase());
  const kinds = useMemo(() => {
    const values = new Set(events.map((event) => event.kind));
    return [...values].sort();
  }, [events]);
  const filtered = useMemo(
    () =>
      events.filter((event) => {
        if (kind !== "all" && event.kind !== kind) return false;
        return !deferredSearch || eventSearchText(event).includes(deferredSearch);
      }),
    [deferredSearch, events, kind],
  );

  const exportCsv = () => {
    const header = "time,kind,sensor,pid,tgid,event_id,process_exec,path";
    const lines = filtered.map((event) =>
      [
        event.time,
        event.kind,
        event.sensor,
        event.pid,
        event.tgid,
        event.event_id,
        event.process_exec ?? "",
        event.path ?? "",
      ]
        .map((value) => `"${String(value).replace(/"/g, '""')}"`)
        .join(","),
    );
    download("ebpf-events.csv", [header, ...lines].join("\n"), "text/csv");
  };

  return (
    <div className="view">
      <Card
        title="Event explorer"
        subtitle={`${filtered.length} shown${filtered.length !== events.length ? ` of ${events.length}` : ""} · newest first`}
        actions={
          <div className="toolbar-actions">
            <Button
              variant="ghost"
              size="sm"
              icon="download"
              onClick={() => download("ebpf-events.json", JSON.stringify(filtered, null, 2))}
            >
              JSON
            </Button>
            <Button variant="ghost" size="sm" icon="download" onClick={exportCsv}>
              CSV
            </Button>
          </div>
        }
        bodyClassName="table-body"
      >
        <div className="table-toolbar">
          <SearchInput
            value={search}
            onChange={setSearch}
            placeholder="Search path, process, kind, pid…"
          />
          <label className="select-wrap">
            <span className="sr-only">Filter by event kind</span>
            <select value={kind} onChange={(event) => setKind(event.target.value)}>
              <option value="all">All kinds</option>
              {kinds.map((value) => (
                <option value={value} key={value}>
                  {value}
                </option>
              ))}
            </select>
            <span className="select-chevron">▾</span>
          </label>
          {search || kind !== "all" ? (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setSearch("");
                setKind("all");
              }}
            >
              Clear
            </Button>
          ) : null}
        </div>

        {filtered.length ? (
          <TableShell>
            <table className="data-table">
              <thead>
                <tr>
                  <th className="time-col">Time</th>
                  <th>Kind</th>
                  <th>Process</th>
                  <th className="hide-sm">Path</th>
                  <th className="hide-sm">PID</th>
                  <th className="hide-sm">Sensor</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((event) => (
                  <tr
                    key={event.event_id}
                    className="clickable-row"
                    tabIndex={0}
                    onClick={() => onEvent(event)}
                    onKeyDown={(keyboard) => {
                      if (keyboard.key === "Enter" || keyboard.key === " ") {
                        keyboard.preventDefault();
                        onEvent(event);
                      }
                    }}
                  >
                    <td className="mono muted-cell time-col" title={event.time}>
                      {formatClock(event.time)}
                      <span className="row-sub">{relativeTime(Date.parse(event.time) / 1000)}</span>
                    </td>
                    <td>
                      <Badge tone={kindTone(event.kind)}>{event.kind}</Badge>
                    </td>
                    <td className="mono process-cell" title={event.process_exec}>
                      {event.process_exec ?? "—"}
                    </td>
                    <td className="path-cell hide-sm" title={event.path ?? event.old_path}>
                      {event.path ?? event.old_path ?? "—"}
                    </td>
                    <td className="mono muted-cell hide-sm">{event.pid}</td>
                    <td className="muted-cell hide-sm">{titleCase(event.sensor)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableShell>
        ) : (
          <EmptyState
            icon="search"
            title={events.length ? "No events match" : "No events yet"}
            description={
              events.length
                ? "Try a different search term or clear the kind filter."
                : "Once the agent forwards its first batch, events appear here."
            }
            action={
              search || kind !== "all" ? (
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    setSearch("");
                    setKind("all");
                  }}
                >
                  Clear filters
                </Button>
              ) : undefined
            }
          />
        )}
      </Card>
    </div>
  );
}
