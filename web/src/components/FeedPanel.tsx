// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Shared table-panel shell for the telemetry views: renders the DESIGN.md
// §8 state ladder (error → loading → empty → degraded → live) around one
// DataTable, with the live/historical meta strip, pause/older actions,
// and the bounded-buffer + degraded-data alerts.
import type { ReactNode } from "react";
import type { EventsFeed, FeedMode } from "../hooks/useEvents";
import { formatInt } from "../lib/format";
import { Alert } from "../ui/Alert";
import { ConnectionBadge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Panel } from "../ui/Card";
import { EmptyRows, ErrorPanel, TableSkeleton } from "../ui/QueryStates";
import { type Column, DataTable } from "../ui/Table";

export interface FeedPanelProps<T> {
  title: string;
  feed: EventsFeed;
  mode: FeedMode;
  rows: ReadonlyArray<T>;
  columns: ReadonlyArray<Column<T>>;
  rowKey: (row: T) => string;
  ariaLabel: string;
  errorScope: string;
  emptyTitle: string;
  emptyHint: string;
  skeletonCols: number;
  /** View-specific filter control rendered before the mode action. */
  filterControl?: ReactNode;
  onCursor: (cursor: string | undefined) => void;
}

export function connectionStatus(feed: EventsFeed): "live" | "reconnecting" | "offline" | "idle" {
  if (feed.status === "live") return "live";
  if (feed.status === "paused") return "idle";
  if (feed.status === "failed" || feed.status === "error") return "offline";
  return "reconnecting";
}

/** Degraded / feed-lost / buffer-eviction banners shared by all feeds. */
export function FeedAlerts({ feed, mode }: { feed: EventsFeed; mode: FeedMode }) {
  const failed = feed.status === "error" || feed.status === "failed";
  return (
    <>
      {feed.status === "degraded" && (
        <Alert tone="warning" title="Showing cached data — refresh failed">
          {feed.error?.message ?? "unknown error"}
        </Alert>
      )}
      {failed && feed.events.length > 0 && (
        <Alert tone="warning" title="Feed lost — showing last retained rows">
          {feed.error?.message ?? "unknown error"}
        </Alert>
      )}
      {feed.droppedTotal > 0 && mode === "live" && (
        <Alert
          tone="warning"
          title={`${formatInt(feed.droppedTotal)} events evicted from the buffer`}
        >
          The live buffer is bounded; use historical mode for full recall.
        </Alert>
      )}
    </>
  );
}

export function FeedPanel<T>({
  title,
  feed,
  mode,
  rows,
  columns,
  rowKey,
  ariaLabel,
  errorScope,
  emptyTitle,
  emptyHint,
  skeletonCols,
  filterControl,
  onCursor,
}: FeedPanelProps<T>) {
  const failed = feed.status === "error" || feed.status === "failed";
  if (failed && rows.length === 0) {
    return <ErrorPanel error={feed.error} onRetry={feed.refetch} scope={errorScope} />;
  }
  const loading = feed.status === "loading" || feed.status === "connecting";

  return (
    <>
      <FeedAlerts feed={feed} mode={mode} />
      <Panel
        title={title}
        flush
        meta={
          mode === "live" ? (
            <>
              <ConnectionBadge status={connectionStatus(feed)} />
              <span>buffer {formatInt(rows.length)}</span>
            </>
          ) : (
            <span>{formatInt(rows.length)} on page</span>
          )
        }
        actions={
          <>
            {filterControl}
            {mode === "live" ? (
              <Button
                size="sm"
                variant="ghost"
                onClick={feed.togglePause}
                aria-pressed={feed.status === "paused"}
              >
                {feed.status === "paused" ? "Resume" : "Pause"}
              </Button>
            ) : (
              feed.nextCursor !== undefined && (
                <Button size="sm" variant="ghost" onClick={() => onCursor(feed.nextCursor)}>
                  Older →
                </Button>
              )
            )}
          </>
        }
      >
        {rows.length === 0 && loading ? (
          <TableSkeleton rows={8} cols={skeletonCols} />
        ) : (
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={rowKey}
            ariaLabel={ariaLabel}
            focusable
            empty={<EmptyRows title={emptyTitle} hint={emptyHint} />}
          />
        )}
      </Panel>
    </>
  );
}
