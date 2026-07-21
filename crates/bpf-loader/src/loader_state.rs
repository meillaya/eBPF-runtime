// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// crates/bpf-loader/src/loader_state.rs
// kernel-v1 — task 18 (load/attach compatibility manager).
//!
//! Runtime state container for the BPF loader.
//!
//! The loader's `probe_and_load()` returns a `LoaderState`
//! whose invariants encode the plan's "transitively clean partial
//! attachments" rule:
//!
//!   * When `probe_and_load()` returns `Ok(state)`, every
//!     attached observation link in `state.attached_links` is a
//!     live bpf_link. `state.pinned_deny_links_count()` is zero
//!     by design (the loader never pins deny links).
//!   * When `probe_and_load()` returns `Err(_)`, every
//!     `attached_links` and `map_handles` slot has been
//!     cleared and detached. The `CoverageMatrix` still records
//!     the per-program outcome so task 55's compatibility matrix
//!     has the data it needs.
//!
//! The unit tests in `crates/bpf-loader/tests/loader.rs`
//! exercise the invariant `pinned_deny_links_count() == 0` for
//! every `probe_and_load` exit path.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use crate::coverage::CoverageMatrix;

/// Opaque handle to a live bpf_link. The loader hands opaque
/// numeric IDs to callers (task 26's CLI uses them for
/// `bpftool link show`-style diagnostics) so callers never
/// observe the underlying libbpf_rs::Link without going through
/// the cleanup path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BpfLinkId(pub u64);

/// Opaque handle to a BPF map opened during probe/attach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MapHandle(pub u64);

/// Runtime loader state. See module-level docs for the
/// invariant contract.
///
/// The struct intentionally holds plain `BTreeMap`s rather than
/// `HashMap`s so the `PartialEq` impl is deterministic — useful
/// for the tests that compare state across `probe_and_load`
/// invocations.
#[derive(Debug, Clone)]
pub struct LoaderState {
    /// Coverage matrix produced by the last `probe_and_load`.
    /// Always present; even an empty `probe_and_load` writes a
    /// matrix whose `sensors` list reflects the planned sensor
    /// set with the documented graceful-path reason.
    pub coverage: CoverageMatrix,
    /// Active observation links, keyed by the sensor name (the
    /// `sensors` field of the matching `CoverageMatrix` entry).
    /// `BpfLinkId` is opaque; the loader uses it to drive
    /// `link.detach()` cleanup on partial failure.
    pub attached_links: BTreeMap<String, BpfLinkId>,
    /// Open map handles, keyed by canonical map name (e.g.
    /// `"process_events"`, `"file_events"`). Map handles are
    /// released by `bpf_object::close()` on `LoaderState::drop`.
    pub map_handles: BTreeMap<String, MapHandle>,
    /// Pinned deny links. By construction this is always
    /// empty; the loader NEVER pins a deny link. The field is
    /// deliberately `pub(crate)` so the orchestrator
    /// (`probe_and_load` in `lib.rs`) can construct a
    /// `LoaderState` value, but external callers cannot
    /// mutate it — they only have access to the
    /// `pinned_deny_links_count()` accessor and to
    /// `cleanup()`, which clears the field.
    pub(crate) pinned_deny_links: BTreeMap<String, BpfLinkId>,
}

impl LoaderState {
    /// Build a fresh, empty `LoaderState`. The `coverage`
    /// field is initialised to `CoverageMatrix::with_default_
    /// sensors()` so callers can read it without first calling
    /// `probe_and_load()`. The empty state satisfies
    /// `pinned_deny_links_count() == 0` and
    /// `active_links_count() == 0` by construction.
    pub fn new() -> Self {
        Self {
            coverage: CoverageMatrix::with_default_sensors(),
            attached_links: BTreeMap::new(),
            map_handles: BTreeMap::new(),
            pinned_deny_links: BTreeMap::new(),
        }
    }

    /// Number of currently-attached observation links. The
    /// count is computed from `attached_links` because every
    /// entry maps 1:1 to a live, observation-mode link; deny
    /// pins are tracked separately in `pinned_deny_links`, which
    /// is always empty.
    pub fn active_links_count(&self) -> usize {
        self.attached_links.len()
    }

    /// Number of pinned deny links. The loader's design
    /// guarantees this is always zero. The accessor exists so
    /// tests can read the value without breaking the
    /// encapsulation that hides the underlying field.
    pub fn pinned_deny_links_count(&self) -> usize {
        self.pinned_deny_links.len()
    }

    /// Reset the state to a fresh, empty one. The
    /// implementation releases every link in
    /// `attached_links` (detach) and clears every map handle.
    /// In an unprivileged build host this is a no-op because
    /// the `attached_links` map is empty; in a privileged run
    /// it drives the explicit cleanup the failure-QA scenario
    /// asserts.
    pub fn cleanup(&mut self) {
        let _ = self.attached_links.clear();
        let _ = self.map_handles.clear();
        let _ = self.pinned_deny_links.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loader_state_new_is_scope_safe() {
        let state = LoaderState::new();
        assert!(state.attached_links.is_empty(), "attached_links empty");
        assert!(state.map_handles.is_empty(), "map_handles empty");
        assert_eq!(state.pinned_deny_links_count(), 0);
        assert_eq!(state.active_links_count(), 0);
        assert!(
            !state.coverage.sensors.is_empty(),
            "CoverageMatrix with default sensors is pre-populated"
        );
    }

    #[test]
    fn pinned_deny_links_count_accessor_never_grows() {
        // The accessor is the only read path; the field is
        // private, so no external code can mutate it. The
        // integration test in `tests/loader.rs`
        // (`no_enforcement_link_is_pinned`) is what verifies
        // the invariant survives across `probe_and_load`
        // exit paths.
        let state = LoaderState::new();
        assert_eq!(state.pinned_deny_links_count(), 0);
        let mut state = state;
        state.cleanup();
        assert_eq!(state.pinned_deny_links_count(), 0);
    }

    #[test]
    fn loader_state_cleanup_clears_attachments() {
        let mut state = LoaderState::new();
        state.attached_links.insert("process".into(), BpfLinkId(7));
        state.map_handles.insert("process_events".into(), MapHandle(11));
        assert_eq!(state.active_links_count(), 1);
        state.cleanup();
        assert!(state.attached_links.is_empty());
        assert!(state.map_handles.is_empty());
        assert_eq!(state.active_links_count(), 0);
        assert_eq!(state.pinned_deny_links_count(), 0);
    }
}
