// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Minimal query cache (zero extra deps). Every view renders exactly one
// of the first-class states (DESIGN.md §8):
//   loading  — no data yet
//   ready    — fresh data
//   degraded — fetch failed but stale data is still shown (amber banner)
//   error    — fetch failed and there is nothing to show
import { useCallback, useEffect, useRef, useSyncExternalStore } from "react";

export type QueryStatus = "loading" | "ready" | "degraded" | "error";

interface CacheEntry {
  data: unknown;
  error: Error | null;
  status: QueryStatus;
  fetchedAt: number;
}

const EMPTY: CacheEntry = { data: null, error: null, status: "loading", fetchedAt: 0 };

const cache = new Map<string, CacheEntry>();
const listeners = new Map<string, Set<() => void>>();
const inflight = new Map<string, Promise<void>>();

function notify(key: string): void {
  const set = listeners.get(key);
  if (set !== undefined) {
    for (const fn of set) fn();
  }
}

/** Fetch through the cache; downgrades to `degraded` when stale data exists. */
export function refresh<T>(key: string, fetcher: () => Promise<T>): Promise<void> {
  const running = inflight.get(key);
  if (running !== undefined) return running;
  const run = (async () => {
    const prev = cache.get(key);
    try {
      const data = await fetcher();
      cache.set(key, { data, error: null, status: "ready", fetchedAt: Date.now() });
    } catch (cause) {
      const error = cause instanceof Error ? cause : new Error(String(cause));
      if (prev !== undefined && prev.data !== null) {
        cache.set(key, { data: prev.data, error, status: "degraded", fetchedAt: prev.fetchedAt });
      } else {
        cache.set(key, { data: null, error, status: "error", fetchedAt: Date.now() });
      }
    } finally {
      inflight.delete(key);
      notify(key);
    }
  })();
  inflight.set(key, run);
  return run;
}

export interface QueryState<T> {
  data: T | null;
  status: QueryStatus;
  error: Error | null;
  fetchedAt: number;
  refetch: () => void;
}

/**
 * Subscribe to a cached query. Fetches on mount / key change, and polls
 * when `refreshMs` is set. The fetcher identity is tracked via ref so
 * inline arrows do not retrigger fetches.
 */
export function useQuery<T>(
  key: string,
  fetcher: () => Promise<T>,
  refreshMs?: number,
): QueryState<T> {
  const sub = useCallback(
    (onChange: () => void): (() => void) => {
      let set = listeners.get(key);
      if (set === undefined) {
        set = new Set();
        listeners.set(key, set);
      }
      set.add(onChange);
      return () => {
        set.delete(onChange);
      };
    },
    [key],
  );
  const entry = useSyncExternalStore(sub, () => cache.get(key) ?? EMPTY);

  const fetcherRef = useRef(fetcher);
  useEffect(() => {
    fetcherRef.current = fetcher;
  });

  useEffect(() => {
    void refresh(key, () => fetcherRef.current());
  }, [key]);

  useEffect(() => {
    if (refreshMs === undefined) return;
    const id = globalThis.setInterval(() => {
      void refresh(key, () => fetcherRef.current());
    }, refreshMs);
    return () => globalThis.clearInterval(id);
  }, [key, refreshMs]);

  const refetch = useCallback(() => {
    void refresh(key, () => fetcherRef.current());
  }, [key]);

  return {
    data: entry.data as T | null,
    status: entry.status,
    error: entry.error,
    fetchedAt: entry.fetchedAt,
    refetch,
  };
}

/** Ticking clock hook for relative timestamps / reconnect countdowns. */
export function useNow(intervalMs = 1000): number {
  const sub = useCallback(
    (onChange: () => void) => {
      const id = globalThis.setInterval(onChange, intervalMs);
      return () => globalThis.clearInterval(id);
    },
    [intervalMs],
  );
  return useSyncExternalStore(sub, () => Math.floor(Date.now() / intervalMs));
}
