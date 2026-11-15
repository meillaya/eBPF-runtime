import { useDeferredValue, useMemo, useState } from "react";
import type { AuditRow, Role } from "../types";
import { roleAtLeast } from "../auth";
import { formatClock, formatNumber } from "../lib/format";
import {
  CopyButton,
  DetailBlock,
  Drawer,
  EmptyRow,
  FilterTabs,
  KeyValue,
  LinkButton,
  Measure,
  MeasureBand,
  RawJSON,
  SearchField,
  Section,
  Table,
} from "./ui";

type ResultFilter = "all" | "success" | "failure";

const clockOf = (epochSeconds: number) => formatClock(new Date(epochSeconds * 1000).toISOString());

/* The register stamps times as YYYY-MM-DD HH:MM:SS, local time. */
function stamp(epochSeconds: number): string {
  const date = new Date(epochSeconds * 1000);
  if (!Number.isFinite(date.getTime())) return "—";
  const pad = (part: number) => String(part).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

export function AuditView({ audit, role }: { audit: AuditRow[]; role: Role | null }) {
  const [search, setSearch] = useState("");
  const [result, setResult] = useState<ResultFilter>("all");
  const [selected, setSelected] = useState<AuditRow | null>(null);
  const deferredSearch = useDeferredValue(search.trim().toLowerCase());
  const allowed = roleAtLeast(role, "admin");

  const filtered = useMemo(
    () =>
      audit.filter((row) => {
        if (result === "success" && !row.success) return false;
        if (result === "failure" && row.success) return false;
        if (!deferredSearch) return true;
        return `${row.actor} ${row.action} ${row.resource}`.toLowerCase().includes(deferredSearch);
      }),
    [audit, deferredSearch, result],
  );
  const failures = audit.filter((row) => !row.success).length;

  const clearFilters = () => {
    setSearch("");
    setResult("all");
  };

  if (!allowed) {
    return <p className="notice">Audit requires the admin role.</p>;
  }

  return (
    <div>
      <MeasureBand sub>
        <Measure value={formatNumber(audit.length)} label="rows" note="newest first" />
        <Measure
          value={
            failures > 0 ? <span className="sig">{formatNumber(failures)}</span> : formatNumber(failures)
          }
          label="failures"
          note="recorded result"
        />
      </MeasureBand>

      <div style={{ marginTop: 26 }}>
        <Section
          title="Audit trail"
          meta={`${filtered.length} of ${audit.length}, newest first`}
        >
          <div className="tools">
            <SearchField
              value={search}
              onChange={setSearch}
              label="Search"
              placeholder="actor, action, resource"
            />
            <div className="field" style={{ gap: 4 }}>
              <span>Result</span>
              <FilterTabs<ResultFilter>
                ariaLabel="Filter audit by result"
                value={result}
                onChange={setResult}
                options={[
                  { value: "all", label: "All" },
                  { value: "success", label: "Success" },
                  { value: "failure", label: "Failure" },
                ]}
              />
            </div>
          </div>

          <Table minWidth={620} label="Audit register">
            <colgroup>
              <col style={{ width: "10%" }} />
              <col style={{ width: "22%" }} />
              <col style={{ width: "28%" }} />
              <col style={{ width: "24%" }} />
              <col style={{ width: "16%" }} />
            </colgroup>
            <thead>
              <tr>
                <th scope="col">Time</th>
                <th scope="col">Actor</th>
                <th scope="col">Action</th>
                <th scope="col">Resource</th>
                <th scope="col">Result</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length ? (
                filtered.map((row, index) => (
                  <tr
                    key={`${row.action}-${row.created_at_epoch}-${index}`}
                    data-row="audit"
                    tabIndex={0}
                    onClick={() => setSelected(row)}
                    onKeyDown={(keyboard) => {
                      if (keyboard.key === "Enter" || keyboard.key === " ") {
                        keyboard.preventDefault();
                        setSelected(row);
                      }
                    }}
                  >
                    <td className="nowrap" title={stamp(row.created_at_epoch)}>
                      {clockOf(row.created_at_epoch)}
                    </td>
                    <td className="rule-cell">{row.actor}</td>
                    <td className="nowrap">{row.action}</td>
                    <td className="nowrap">{row.resource}</td>
                    <td className="nowrap">
                      {row.success ? "success" : <span className="result-fail">failure</span>}
                    </td>
                  </tr>
                ))
              ) : (
                <EmptyRow colSpan={5}>
                  {audit.length ? "No audit rows match this filter." : "No audit rows."}{" "}
                  {audit.length ? (
                    <LinkButton type="button" onClick={clearFilters}>
                      Clear filters
                    </LinkButton>
                  ) : null}
                </EmptyRow>
              )}
            </tbody>
          </Table>
        </Section>
      </div>

      <Drawer
        open={selected !== null}
        onClose={() => setSelected(null)}
        title={selected ? selected.action : "Audit row"}
        subtitle={
          selected
            ? `${selected.resource}, ${stamp(selected.created_at_epoch)}`
            : undefined
        }
        footer={
          selected ? (
            <CopyButton value={JSON.stringify(selected.detail ?? {}, null, 2)} />
          ) : undefined
        }
      >
        {selected ? (
          <>
            <KeyValue
              className="detail"
              rows={[
                ["Actor", selected.actor],
                ["Action", selected.action],
                ["Resource", selected.resource],
                [
                  "Result",
                  selected.success ? "success" : <span className="result-fail">failure</span>,
                ],
                ["Time", stamp(selected.created_at_epoch)],
              ]}
            />
            <DetailBlock title="Recorded detail">
              <RawJSON value={selected.detail ?? {}} />
            </DetailBlock>
          </>
        ) : null}
      </Drawer>
    </div>
  );
}
