import { useDeferredValue, useMemo, useState } from "react";
import type { AuditRow, Role } from "../types";
import { roleAtLeast } from "../auth";
import { formatTimestamp, relativeTime, titleCase } from "../lib/format";
import {
  Badge,
  Button,
  Card,
  Drawer,
  EmptyState,
  KeyValue,
  SearchInput,
} from "./ui";

export function AuditView({ audit, role }: { audit: AuditRow[]; role: Role | null }) {
  const [search, setSearch] = useState("");
  const [success, setSuccess] = useState<"all" | "success" | "failure">("all");
  const [selected, setSelected] = useState<AuditRow | null>(null);
  const deferredSearch = useDeferredValue(search.trim().toLowerCase());
  const allowed = roleAtLeast(role, "admin");

  const filtered = useMemo(
    () =>
      audit.filter((row) => {
        if (success === "success" && !row.success) return false;
        if (success === "failure" && row.success) return false;
        if (!deferredSearch) return true;
        return `${row.actor} ${row.action} ${row.resource}`
          .toLowerCase()
          .includes(deferredSearch);
      }),
    [audit, deferredSearch, success],
  );

  if (!allowed) {
    return (
      <div className="view">
        <Card>
          <EmptyState
            icon="lock"
            title="Audit requires the admin role"
            description="The control plane only returns audit rows to an OIDC identity with an ebpf-admins or fleet-admins group."
          />
        </Card>
      </div>
    );
  }

  return (
    <div className="view">
      <Card
        title="Audit trail"
        subtitle={`${filtered.length} shown${filtered.length !== audit.length ? ` of ${audit.length}` : ""} · newest first`}
        bodyClassName="table-body"
      >
        <div className="table-toolbar">
          <SearchInput
            value={search}
            onChange={setSearch}
            placeholder="Search actor, action, resource…"
          />
          <div className="segmented segmented-sm" role="group" aria-label="Filter audit result">
            {(["all", "success", "failure"] as const).map((value) => (
              <button
                type="button"
                key={value}
                className={success === value ? "active" : ""}
                onClick={() => setSuccess(value)}
                aria-pressed={success === value}
              >
                {titleCase(value)}
              </button>
            ))}
          </div>
          {search || success !== "all" ? (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setSearch("");
                setSuccess("all");
              }}
            >
              Clear
            </Button>
          ) : null}
        </div>
        {filtered.length ? (
          <div className="table-shell">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th className="hide-sm">Actor</th>
                  <th>Action</th>
                  <th className="hide-sm">Resource</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((row, index) => (
                  <tr
                    key={`${row.action}-${row.created_at_epoch}-${index}`}
                    className="clickable-row"
                    tabIndex={0}
                    onClick={() => setSelected(row)}
                    onKeyDown={(keyboard) => {
                      if (keyboard.key === "Enter" || keyboard.key === " ") {
                        keyboard.preventDefault();
                        setSelected(row);
                      }
                    }}
                  >
                    <td className="muted-cell" title={formatTimestamp(row.created_at_epoch)}>
                      {relativeTime(row.created_at_epoch)}
                    </td>
                    <td className="mono hide-sm">{row.actor}</td>
                    <td>{row.action}</td>
                    <td className="muted-cell hide-sm">{row.resource}</td>
                    <td>
                      <Badge tone={row.success ? "emerald" : "rose"} dot>
                        {row.success ? "success" : "failure"}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            icon="list"
            title={audit.length ? "No audit rows match" : "No audit rows"}
            description={
              audit.length
                ? "Clear the search or result filter."
                : "Stage, commit, and rollout actions are recorded here."
            }
          />
        )}
      </Card>

      <Drawer
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title={selected ? selected.action : "Audit row"}
        subtitle={selected ? `${selected.resource} · ${formatTimestamp(selected.created_at_epoch)}` : undefined}
      >
        {selected ? (
          <div className="detail-stack">
            <KeyValue
              rows={[
                ["Actor", selected.actor],
                ["Action", selected.action],
                ["Resource", selected.resource],
                ["Result", selected.success ? "success" : "failure"],
                ["Time", formatTimestamp(selected.created_at_epoch)],
              ]}
            />
            <div>
              <span className="eyebrow">Detail</span>
              <pre className="json-block">{JSON.stringify(selected.detail ?? {}, null, 2)}</pre>
            </div>
          </div>
        ) : null}
      </Drawer>
    </div>
  );
}
