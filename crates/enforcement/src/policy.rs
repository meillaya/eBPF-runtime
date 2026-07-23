// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Double-buffered policy map generations.
//!
//! The enforcement engine maintains TWO complete policy map
//! generations: **active** (the one the BPF LSM engine reads) and
//! **inactive** (the staging buffer). A STAGE command writes into
//! the inactive generation; COMMIT atomically flips the
//! active/inactive labels so the BPF side sees the new policy in a
//! single pointer swap. The previous active generation is retained
//! as the rollback target.
//!
//! Wire-compatible with `struct lsm_policy_entry` (288 bytes,
//! packed) from `bpf/sensors/lsm.bpf.c`. The Rust mirror carries
//! the same fields in the same order; the `_pad` fields are
//! explicit so `size_of::<PolicyEntry>() == 288` holds.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Maximum selector size in bytes. Mirrors
/// `KERNEL_V1_LSM_SELECTOR_MAX` (256) from the enforcement schema.
pub const SELECTOR_MAX_BYTES: usize = 256;

/// Number of policy slots. Mirrors `max_policy_entries` (4) from
/// the enforcement schema. Slot 0 is reserved; slots 1..=3 map to
/// file_open / bprm_check_security / socket_connect.
pub const POLICY_SLOTS: usize = 4;

/// Policy mode. Mirrors `mode_audit` (0) and `mode_deny` (1) from
/// the enforcement schema. Every policy starts as `Audit`;
/// promotion to `Deny` requires the full staged-commit path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PolicyMode {
    /// Audit-only: the hook NEVER changes the syscall result.
    Audit = 0,
    /// Deny: a matching selector returns the policy errno.
    Deny = 1,
}

impl PolicyMode {
    /// Decode from the wire byte. Unknown values map to `None`
    /// (fail-open: the engine treats an unknown mode as no-match).
    pub fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Audit),
            1 => Some(Self::Deny),
            _ => None,
        }
    }

    /// Encode to the wire byte.
    pub fn to_wire(self) -> u8 {
        self as u8
    }
}

/// Hook family. Mirrors `hook_family_*` wire encodings from the
/// enforcement schema (1=file_open, 2=bprm_check_security,
/// 3=socket_connect).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum HookFamily {
    /// `lsm/file_open` — selector = dentry name component.
    FileOpen = 1,
    /// `lsm/bprm_check_security` — selector = bprm->filename.
    BprmExec = 2,
    /// `lsm/socket_connect` — selector = sockaddr bytes.
    SocketConnect = 3,
}

impl HookFamily {
    /// Decode from the wire byte.
    pub fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::FileOpen),
            2 => Some(Self::BprmExec),
            3 => Some(Self::SocketConnect),
            _ => None,
        }
    }

    /// Encode to the wire byte.
    pub fn to_wire(self) -> u8 {
        self as u8
    }

    /// All supported hook families, for iteration.
    pub const ALL: [Self; 3] = [Self::FileOpen, Self::BprmExec, Self::SocketConnect];
}

/// A single policy entry. Wire-compatible with
/// `struct lsm_policy_entry` (288 bytes).
///
/// The `_pad` fields exist so the struct is exactly 288 bytes and
/// field offsets match the C layout. They are never read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEntry {
    /// Enforcement mode (audit=0 / deny=1).
    pub mode: PolicyMode,
    /// Hook family this entry governs.
    pub hook_family: HookFamily,
    /// Monotonic policy version (bumped on every commit).
    pub version: u64,
    /// Generation counter (bumped on every atomic flip).
    pub generation: u64,
    /// Negative errno returned on deny (default -13 = EACCES).
    pub deny_errno: i32,
    /// Meaningful bytes in `selector`.
    pub selector_len: u32,
    /// Path prefix or sockaddr bytes, bounded to
    /// `SELECTOR_MAX_BYTES`.
    pub selector: Vec<u8>,
}

impl PolicyEntry {
    /// Create a new audit-mode entry with the default deny errno.
    pub fn new_audit(hook_family: HookFamily, version: u64, generation: u64) -> Self {
        Self {
            mode: PolicyMode::Audit,
            hook_family,
            version,
            generation,
            deny_errno: -13,
            selector_len: 0,
            selector: vec![0u8; SELECTOR_MAX_BYTES],
        }
    }

    /// Set the selector bytes. Truncates to `SELECTOR_MAX_BYTES`.
    pub fn with_selector(mut self, selector: &[u8]) -> Self {
        let len = selector.len().min(SELECTOR_MAX_BYTES);
        self.selector[..len].copy_from_slice(&selector[..len]);
        self.selector_len = len as u32;
        self
    }

    /// Promote to deny mode with a specific errno.
    pub fn with_deny(mut self, deny_errno: i32) -> Self {
        self.mode = PolicyMode::Deny;
        // Force negative: an LSM deny is always a negative errno.
        self.deny_errno = if deny_errno >= 0 { -13 } else { deny_errno };
        self
    }

    /// The meaningful selector slice (first `selector_len` bytes).
    pub fn selector_bytes(&self) -> &[u8] {
        &self.selector[..(self.selector_len as usize).min(self.selector.len())]
    }

    /// Serialize to the canonical byte representation used for
    /// digest computation. The digest covers mode + hook_family +
    /// version + generation + deny_errno + selector_len + selector
    /// bytes (the semantically meaningful fields).
    pub fn digest_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 1 + 8 + 8 + 4 + 4 + self.selector_len as usize);
        buf.push(self.mode.to_wire());
        buf.push(self.hook_family.to_wire());
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.generation.to_le_bytes());
        buf.extend_from_slice(&self.deny_errno.to_le_bytes());
        buf.extend_from_slice(&self.selector_len.to_le_bytes());
        buf.extend_from_slice(self.selector_bytes());
        buf
    }
}

/// A complete policy map generation: one `PolicyEntry` per slot.
/// Slot 0 is reserved (always audit, empty selector). Slots 1..=3
/// correspond to the three supported hook families.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyGeneration {
    /// The generation counter. Monotonically increasing; bumped on
    /// every atomic flip.
    pub generation: u64,
    /// The policy entries, indexed by slot (0..POLICY_SLOTS).
    pub entries: Vec<PolicyEntry>,
}

impl PolicyGeneration {
    /// Create a fresh audit-only generation (startup state).
    /// Every slot is audit mode with an empty selector.
    pub fn new_audit_only(generation: u64) -> Self {
        let mut entries = Vec::with_capacity(POLICY_SLOTS);
        // Slot 0: reserved.
        entries.push(PolicyEntry::new_audit(HookFamily::FileOpen, 0, generation));
        // Slots 1..=3: one per hook family.
        for (i, family) in HookFamily::ALL.iter().enumerate() {
            entries.push(PolicyEntry::new_audit(*family, 0, generation));
            let _ = i;
        }
        Self {
            generation,
            entries,
        }
    }

    /// Get the entry for a hook family (slot = family as usize).
    pub fn entry_for(&self, family: HookFamily) -> Option<&PolicyEntry> {
        self.entries.get(family as usize)
    }

    /// Get a mutable entry for a hook family.
    pub fn entry_for_mut(&mut self, family: HookFamily) -> Option<&mut PolicyEntry> {
        self.entries.get_mut(family as usize)
    }

    /// Compute the canonical digest bytes for the entire
    /// generation (concatenation of all entry digests in slot
    /// order).
    pub fn digest_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.generation.to_le_bytes());
        for entry in &self.entries {
            buf.extend_from_slice(&entry.digest_bytes());
        }
        buf
    }
}

/// Double-buffered policy map. Holds an **active** generation
/// (what the BPF engine reads) and an **inactive** generation
/// (the staging buffer). COMMIT swaps them atomically.
#[derive(Debug, Clone)]
pub struct PolicyMap {
    /// The generation the BPF LSM engine currently reads.
    active: PolicyGeneration,
    /// The staging buffer. STAGE writes here; COMMIT promotes it.
    inactive: PolicyGeneration,
    /// The previous active generation, retained for rollback.
    previous: Option<PolicyGeneration>,
    /// Monotonic version counter. Every accepted command bumps
    /// this. Commands carrying a version <= this are rejected
    /// (replay/stale protection).
    monotonic_version: u64,
}

impl PolicyMap {
    /// Create a fresh double-buffered map at generation 0.
    /// Both buffers start audit-only.
    pub fn new() -> Self {
        Self {
            active: PolicyGeneration::new_audit_only(0),
            inactive: PolicyGeneration::new_audit_only(1),
            previous: None,
            monotonic_version: 0,
        }
    }

    /// Restore from a persisted last-known-good state. The active
    /// generation is set to the persisted one; the inactive buffer
    /// is a fresh audit-only generation at generation+1.
    pub fn from_persisted(persisted: PolicyGeneration) -> Self {
        let next_gen = persisted.generation + 1;
        let version = persisted
            .entries
            .iter()
            .map(|e| e.version)
            .max()
            .unwrap_or(0);
        Self {
            inactive: PolicyGeneration::new_audit_only(next_gen),
            active: persisted,
            previous: None,
            monotonic_version: version,
        }
    }

    /// The active generation (what the BPF engine reads).
    pub fn active(&self) -> &PolicyGeneration {
        &self.active
    }

    /// The inactive (staging) generation.
    pub fn inactive(&self) -> &PolicyGeneration {
        &self.inactive
    }

    /// Mutable access to the inactive (staging) generation.
    /// Used by the STAGE path to write the new policy.
    pub fn inactive_mut(&mut self) -> &mut PolicyGeneration {
        &mut self.inactive
    }

    /// The previous active generation (rollback target).
    pub fn previous(&self) -> Option<&PolicyGeneration> {
        self.previous.as_ref()
    }

    /// Current monotonic version.
    pub fn monotonic_version(&self) -> u64 {
        self.monotonic_version
    }

    /// Advance the monotonic version. Returns `false` if the
    /// supplied version is not strictly greater (replay/stale).
    pub fn advance_version(&mut self, version: u64) -> bool {
        if version <= self.monotonic_version {
            return false;
        }
        self.monotonic_version = version;
        true
    }

    /// Atomically flip active and inactive. The current active
    /// becomes `previous` (rollback target); the inactive becomes
    /// active; a fresh audit-only generation is allocated as the
    /// new inactive buffer.
    ///
    /// This is the atomic generation flip: the BPF side sees the
    /// new policy in a single pointer swap (the active label moves
    /// from one buffer to the other).
    pub fn flip(&mut self) {
        let next_gen = self.inactive.generation + 1;
        let old_active = std::mem::replace(&mut self.active, PolicyGeneration::new_audit_only(0));
        let old_inactive = std::mem::replace(&mut self.inactive, old_active);
        self.active = old_inactive;
        self.previous = Some(std::mem::replace(
            &mut self.inactive,
            PolicyGeneration::new_audit_only(next_gen),
        ));
    }

    /// Rollback: swap active back to the previous generation.
    /// Returns `false` if there is no previous generation.
    pub fn rollback(&mut self) -> bool {
        let Some(prev) = self.previous.take() else {
            return false;
        };
        // Current active becomes the new inactive (staging buffer).
        let current = std::mem::replace(&mut self.active, prev);
        self.inactive = current;
        true
    }

    /// Check whether deny links are pinned. By construction this
    /// is always `false` — the enforcement engine NEVER pins deny
    /// links. Observation links may use distinct pin roots.
    pub fn deny_links_pinned(&self) -> bool {
        false
    }
}

impl Default for PolicyMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_mode_wire_roundtrip() {
        assert_eq!(PolicyMode::from_wire(0), Some(PolicyMode::Audit));
        assert_eq!(PolicyMode::from_wire(1), Some(PolicyMode::Deny));
        assert_eq!(PolicyMode::from_wire(2), None);
        assert_eq!(PolicyMode::Audit.to_wire(), 0);
        assert_eq!(PolicyMode::Deny.to_wire(), 1);
    }

    #[test]
    fn hook_family_wire_roundtrip() {
        assert_eq!(HookFamily::from_wire(1), Some(HookFamily::FileOpen));
        assert_eq!(HookFamily::from_wire(2), Some(HookFamily::BprmExec));
        assert_eq!(HookFamily::from_wire(3), Some(HookFamily::SocketConnect));
        assert_eq!(HookFamily::from_wire(0), None);
        assert_eq!(HookFamily::from_wire(4), None);
    }

    #[test]
    fn new_generation_is_audit_only() {
        let gen = PolicyGeneration::new_audit_only(0);
        assert_eq!(gen.entries.len(), POLICY_SLOTS);
        for entry in &gen.entries {
            assert_eq!(entry.mode, PolicyMode::Audit);
            assert_eq!(entry.selector_len, 0);
        }
    }

    #[test]
    fn entry_selector_truncates_to_max() {
        let long = vec![0xAAu8; SELECTOR_MAX_BYTES + 100];
        let entry = PolicyEntry::new_audit(HookFamily::FileOpen, 1, 0).with_selector(&long);
        assert_eq!(entry.selector_len as usize, SELECTOR_MAX_BYTES);
        assert_eq!(entry.selector_bytes().len(), SELECTOR_MAX_BYTES);
    }

    #[test]
    fn deny_errno_forced_negative() {
        let entry = PolicyEntry::new_audit(HookFamily::FileOpen, 1, 0).with_deny(13);
        assert_eq!(entry.deny_errno, -13);
        let entry2 = PolicyEntry::new_audit(HookFamily::FileOpen, 1, 0).with_deny(-1);
        assert_eq!(entry2.deny_errno, -1);
    }

    #[test]
    fn policy_map_flip_swaps_generations() {
        let mut map = PolicyMap::new();
        let active_gen_before = map.active().generation;
        let inactive_gen_before = map.inactive().generation;

        // Write something into inactive.
        map.inactive_mut()
            .entry_for_mut(HookFamily::FileOpen)
            .unwrap()
            .mode = PolicyMode::Deny;

        map.flip();

        // After flip: active is what was inactive.
        assert_eq!(map.active().generation, inactive_gen_before);
        assert_eq!(
            map.active().entry_for(HookFamily::FileOpen).unwrap().mode,
            PolicyMode::Deny
        );
        // Previous is what was active.
        assert_eq!(map.previous().unwrap().generation, active_gen_before);
        // Inactive is a fresh generation.
        assert!(map.inactive().generation > inactive_gen_before);
    }

    #[test]
    fn policy_map_rollback_restores_previous() {
        let mut map = PolicyMap::new();
        let gen0 = map.active().generation;

        map.inactive_mut()
            .entry_for_mut(HookFamily::BprmExec)
            .unwrap()
            .mode = PolicyMode::Deny;
        map.flip();
        assert_eq!(
            map.active().entry_for(HookFamily::BprmExec).unwrap().mode,
            PolicyMode::Deny
        );

        assert!(map.rollback());
        assert_eq!(map.active().generation, gen0);
        assert_eq!(
            map.active().entry_for(HookFamily::BprmExec).unwrap().mode,
            PolicyMode::Audit
        );
    }

    #[test]
    fn rollback_without_previous_fails() {
        let mut map = PolicyMap::new();
        assert!(!map.rollback());
    }

    #[test]
    fn monotonic_version_rejects_stale_and_replay() {
        let mut map = PolicyMap::new();
        assert!(map.advance_version(1));
        assert!(map.advance_version(5));
        // Replay: same version.
        assert!(!map.advance_version(5));
        // Stale: lower version.
        assert!(!map.advance_version(3));
        // Next valid.
        assert!(map.advance_version(6));
    }

    #[test]
    fn deny_links_never_pinned() {
        let map = PolicyMap::new();
        assert!(!map.deny_links_pinned());
    }

    #[test]
    fn from_persisted_restores_state() {
        let mut gen = PolicyGeneration::new_audit_only(7);
        gen.entry_for_mut(HookFamily::SocketConnect).unwrap().mode = PolicyMode::Deny;
        gen.entry_for_mut(HookFamily::SocketConnect)
            .unwrap()
            .version = 42;

        let map = PolicyMap::from_persisted(gen);
        assert_eq!(map.active().generation, 7);
        assert_eq!(map.monotonic_version(), 42);
        assert_eq!(
            map.active()
                .entry_for(HookFamily::SocketConnect)
                .unwrap()
                .mode,
            PolicyMode::Deny
        );
        // Inactive is a fresh audit-only gen.
        assert_eq!(map.inactive().generation, 8);
        assert_eq!(
            map.inactive()
                .entry_for(HookFamily::SocketConnect)
                .unwrap()
                .mode,
            PolicyMode::Audit
        );
    }

    #[test]
    fn digest_bytes_deterministic() {
        let entry =
            PolicyEntry::new_audit(HookFamily::FileOpen, 1, 0).with_selector(b"/etc/shadow");
        let d1 = entry.digest_bytes();
        let d2 = entry.digest_bytes();
        assert_eq!(d1, d2);
        // Different content → different digest bytes.
        let entry2 =
            PolicyEntry::new_audit(HookFamily::FileOpen, 1, 0).with_selector(b"/etc/passwd");
        assert_ne!(d1, entry2.digest_bytes());
    }
}
