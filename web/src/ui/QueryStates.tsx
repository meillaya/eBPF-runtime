// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Composable first-class state blocks (DESIGN.md §8). Views wire these
// to QueryState so loading/empty/degraded/error render consistently.
import { ApiError } from "../api/client";
import { formatInt } from "../lib/format";
import { Alert } from "./Alert";
import { Button } from "./Button";
import { EmptyState } from "./EmptyState";

export function ErrorPanel({
  error,
  onRetry,
  scope = "feed",
}: {
  error: Error | null;
  onRetry: () => void;
  scope?: string;
}) {
  const status = error instanceof ApiError ? `HTTP ${error.status}` : "network";
  return (
    <div className="well well--error" role="alert">
      <p className="well-title">Unable to reach the {scope}</p>
      <p className="well-hint">
        The control plane did not answer. Check the agent/proxy, then retry — nothing on this page
        is stale because nothing loaded.
      </p>
      <p className="well-detail">
        {status}: {error?.message ?? "unknown error"}
      </p>
      <Button variant="secondary" onClick={onRetry}>
        Retry request
      </Button>
    </div>
  );
}

export function DegradedBanner({ error, staleRows }: { error: Error | null; staleRows?: number }) {
  return (
    <Alert tone="warning" title="Showing cached data — live refresh failed">
      {staleRows !== undefined && `${formatInt(staleRows)} rows retained. `}
      {error?.message ?? "unknown error"} — retrying in the background.
    </Alert>
  );
}

/** Shimmer skeleton mimicking a dense table while the first page loads. */
export function TableSkeleton({ rows = 8, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="tbl-skeleton" role="status" aria-busy="true" aria-label="Loading rows">
      {Array.from({ length: rows }, (_, r) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: stable skeleton placeholder
        <div key={r} className="tbl-skeleton-row">
          {Array.from({ length: cols }, (_, c) => {
            const width = `${58 + ((r * 7 + c * 13) % 34)}%`;
            return (
              // biome-ignore lint/suspicious/noArrayIndexKey: static placeholder grid, no per-cell state
              <span key={c} className="skeleton" style={{ width }} />
            );
          })}
        </div>
      ))}
      <span className="visually-hidden">Loading rows</span>
    </div>
  );
}

export function EmptyRows({ title, hint }: { title: string; hint: string }) {
  return (
    <div className="tbl-empty">
      <EmptyState title={title} hint={hint} />
    </div>
  );
}
