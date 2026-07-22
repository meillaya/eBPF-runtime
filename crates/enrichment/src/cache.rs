// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Node-local TTL-bounded enrichment cache.
//!
//! The cache wraps a `dyn RuntimeProvider` and short-circuits repeated
//! lookups for the same `(cgroup_id, generation)` pair. The `generation`
//! counter comes from the loader (task 18) — every attach cycle increments
//! it. When a cgroup is recycled across PID-reuse, the new generation
//! naturally evicts the stale entry without manual cleanup.
//!
//! Eviction policy: bounded capacity with LRU eviction. The capacity is
//! deliberately conservative because the working set is "pods the node
//! hosts", not "pods ever created". A node with a few hundred pods
//! comfortably fits inside `DEFAULT_CAPACITY`.
//!
//! The cache deliberately exposes a tri-state `CacheResult` instead of
//! `Result<ContainerRecord, ProviderError>` so the agent can distinguish
//! a cold-miss provider call from an in-flight provider outage. On a
//! provider outage, the cache surfaces `Unavailable(reason)` so the agent
//! degrades to `AttributionScope::Unknown` rather than caching the failure
//! as if it were a hit.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::{ContainerRecord, ProviderError, RuntimeProvider};

/// Default cache TTL: 300 seconds. Re-exported for tests.
pub const DEFAULT_TTL_SECONDS: u64 = 300;

/// Default cache capacity: 4096 entries.
pub const DEFAULT_CAPACITY: usize = 4096;

/// The tri-state cache result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheResult<T> {
    /// The key was found in the cache and the TTL has not expired.
    Hit(T),
    /// The key was not in the cache; the provider was consulted and returned
    /// the supplied value (which the caller may now choose to insert).
    Miss(T),
    /// The provider returned `ProviderError::Unavailable`. The cache does
    /// NOT insert this into the table — outages must not pollute future
    /// lookups once the runtime recovers.
    Unavailable(String),
}

#[derive(Debug)]
struct CacheEntry<T> {
    value: T,
    inserted_at: Instant,
    generation: u64,
}

#[derive(Debug)]
struct Inner {
    capacity: usize,
    ttl: Duration,
    entries: HashMap<u64, CacheEntry<ContainerRecord>>,
    // Bumped every `invalidate`/`invalidate_all` so the LRU order can be
    // re-derived without disturbing the value hashes.
    tick: u64,
    tick_entries: HashMap<u64, u64>,
}

/// TTL-bounded enrichment cache. The provider reference is shared via `Arc`
/// so the same cache can back multiple readers (the agent pipeline + the
/// health surface) without contending on a single `Mutex`.
#[derive(Clone)]
pub struct EnrichmentCache {
    provider: Arc<dyn RuntimeProvider>,
    ttl: Duration,
    capacity: usize,
    state: Arc<Mutex<Inner>>,
}

impl std::fmt::Debug for EnrichmentCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrichmentCache")
            .field("ttl", &self.ttl)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl EnrichmentCache {
    /// Construct a cache around the given provider with the default TTL and
    /// capacity.
    pub fn new(provider: Arc<dyn RuntimeProvider>) -> Self {
        Self::with_options(provider, Duration::from_secs(DEFAULT_TTL_SECONDS), DEFAULT_CAPACITY)
    }

    /// Construct a cache with explicit TTL and capacity. Used by tests to
    /// exercise TTL expiry deterministically.
    pub fn with_options(provider: Arc<dyn RuntimeProvider>, ttl: Duration, capacity: usize) -> Self {
        assert!(capacity > 0, "EnrichmentCache capacity must be > 0");
        Self {
            provider,
            ttl,
            capacity,
            state: Arc::new(Mutex::new(Inner {
                capacity,
                ttl,
                entries: HashMap::new(),
                tick: 0,
                tick_entries: HashMap::new(),
            })),
        }
    }

    /// Bump the cache generation for the supplied `cgroup_id`. Used by the
    /// loader when it observes that the cgroup has been recycled (e.g. PID
    /// reuse). After this call, the next `lookup_container_with_cache` sees
    /// an empty slot for `(cgroup_id, new_generation)`.
    pub fn invalidate(&self, cgroup_id: u64, generation: u64) {
        let mut inner = self.state.lock();
        inner.entries.remove(&cgroup_id);
        inner.tick_entries.insert(cgroup_id, generation);
        inner.tick = inner.tick.wrapping_add(1);
    }

    /// Drop every cached entry. Used on agent shutdown / config reload.
    pub fn invalidate_all(&self) {
        let mut inner = self.state.lock();
        inner.entries.clear();
        inner.tick_entries.clear();
        inner.tick = inner.tick.wrapping_add(1);
    }

    /// Look up the container record for `cgroup_id`, consulting the cache
    /// first and falling through to the provider on miss/expired entry.
    pub async fn lookup_container_with_cache(
        &self,
        cgroup_id: u64,
        generation: u64,
    ) -> CacheResult<ContainerRecord> {
        // Fast path: cache hit at the requested generation, TTL valid.
        {
            let inner = self.state.lock();
            if let Some(entry) = inner.entries.get(&cgroup_id) {
                if entry.generation == generation && entry.inserted_at.elapsed() < inner.ttl {
                    return CacheResult::Hit(entry.value.clone());
                }
            }
        }

        // Slow path: provider lookup.
        match self.provider.lookup_container(cgroup_id).await {
            Ok(record) => {
                self.insert(cgroup_id, generation, record.clone());
                CacheResult::Miss(record)
            }
            Err(ProviderError::Unavailable(reason)) => CacheResult::Unavailable(reason),
            Err(other) => {
                // For non-`Unavailable` errors (NotFound, AuthDenied, Retriable,
                // Timeout) we also propagate as `Unavailable` so the agent
                // degrades to `AttributionScope::Unknown`. The cache does not
                // poison itself with non-fatal errors.
                CacheResult::Unavailable(format!("{other}"))
            }
        }
    }

    fn insert(&self, cgroup_id: u64, generation: u64, record: ContainerRecord) {
        let mut inner = self.state.lock();
        if inner.entries.len() >= inner.capacity {
            // LRU eviction: drop the entry with the smallest `tick`.
            if let Some((victim, _)) = inner
                .tick_entries
                .iter()
                .min_by_key(|(_, tick)| **tick)
                .map(|(k, _)| (*k, ()))
            {
                inner.entries.remove(&victim);
                inner.tick_entries.remove(&victim);
            }
        }
        let tick = inner.tick.wrapping_add(1);
        inner.tick = tick;
        inner.entries.insert(
            cgroup_id,
            CacheEntry {
                value: record,
                inserted_at: Instant::now(),
                generation,
            },
        );
        inner.tick_entries.insert(cgroup_id, tick);
    }

    /// Number of cached entries (for tests and the health surface).
    pub fn len(&self) -> usize {
        self.state.lock().entries.len()
    }

    /// Returns true if the cache is empty (for tests).
    pub fn is_empty(&self) -> bool {
        self.state.lock().entries.is_empty()
    }
}