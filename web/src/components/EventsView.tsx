import { useDeferredValue, useMemo, useState } from "react";
import type { Event } from "../types";
import {
  download,
  eventSearchText,
  formatClock,
  formatDuration,
  formatNumber,
} from "../lib/format";
import {
  EmptyRow,
  LinkButton,
  Measure,
  MeasureBand,
  SearchField,
  Section,
  SelectField,
  Table,
  TableButton,
} from "./ui";

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

  const sampleTimes = useMemo(
    () =>
      events
        .map((event) => Date.parse(event.time))
        .filter((timestamp) => Number.isFinite(timestamp)),
    [events],
  );
  const oldestMs = sampleTimes.length ? Math.min(...sampleTimes) : null;
  const newestMs = sampleTimes.length ? Math.max(...sampleTimes) : null;
  const spanSeconds =
    oldestMs !== null && newestMs !== null ? Math.max(0, (newestMs - oldestMs) / 1000) : 0;
  const clockOf = (milliseconds: number) => formatClock(new Date(milliseconds).toISOString());

  const clearFilters = () => {
    setSearch("");
    setKind("all");
  };

  const exportJson = () => {
    download("ebpf-events.json", JSON.stringify(filtered, null, 2));
  };

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
    <div>
      <MeasureBand sub>
        <Measure value={formatNumber(events.length)} label="events in sample" note="newest first" />
        <Measure
          value={formatDuration(spanSeconds)}
          label="sample span"
          note={
            oldestMs !== null && newestMs !== null
              ? `${clockOf(oldestMs)} to ${clockOf(newestMs)}`
              : undefined
          }
        />
      </MeasureBand>

      <div style={{ marginTop: 26 }}>
        <Section
          title="Event register"
          meta={`${filtered.length} of ${events.length}, newest first`}
        >
          <div className="tools">
            <SearchField
              value={search}
              onChange={setSearch}
              label="Search"
              placeholder="path, process, kind, pid"
            />
            <SelectField
              value={kind}
              onChange={setKind}
              label="Kind"
              options={[
                { value: "all", label: "All kinds" },
                ...kinds.map((value) => ({ value, label: value })),
              ]}
            />
            <div className="tools-end">
              <TableButton type="button" onClick={exportJson}>
                Export JSON
              </TableButton>
              <TableButton type="button" onClick={exportCsv}>
                Export CSV
              </TableButton>
            </div>
          </div>

          <Table minWidth={760} label="Event register">
            <colgroup>
              <col style={{ width: "10%" }} />
              <col style={{ width: "14%" }} />
              <col style={{ width: "25%" }} />
              <col style={{ width: "43%" }} />
              <col style={{ width: "8%" }} />
            </colgroup>
            <thead>
              <tr>
                <th scope="col">Time</th>
                <th scope="col">Kind</th>
                <th scope="col">Process</th>
                <th scope="col">Path</th>
                <th scope="col" className="n">
                  PID
                </th>
              </tr>
            </thead>
            <tbody>
              {filtered.length ? (
                filtered.map((event) => {
                  const path = event.path ?? event.old_path;
                  return (
                    <tr
                      key={event.event_id}
                      data-row="event"
                      tabIndex={0}
                      onClick={() => onEvent(event)}
                      onKeyDown={(keyboard) => {
                        if (keyboard.key === "Enter" || keyboard.key === " ") {
                          keyboard.preventDefault();
                          onEvent(event);
                        }
                      }}
                    >
                      <td className="nowrap" title={event.time}>
                        {formatClock(event.time)}
                      </td>
                      <td>{event.kind}</td>
                      <td style={{ overflowWrap: "anywhere" }}>{event.process_exec ?? "—"}</td>
                      <td className="rule-cell">
                        {path ? <span title={path}>{path}</span> : "—"}
                      </td>
                      <td className="n">{event.pid}</td>
                    </tr>
                  );
                })
              ) : (
                <EmptyRow colSpan={5}>
                  {events.length
                    ? "No events match this filter."
                    : "No events have been recorded yet."}
                  {events.length ? (
                    <>
                      {" "}
                      <LinkButton type="button" onClick={clearFilters}>
                        Clear filters
                      </LinkButton>
                    </>
                  ) : null}
                </EmptyRow>
              )}
            </tbody>
          </Table>
        </Section>
      </div>
    </div>
  );
}
