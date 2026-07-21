// src/parser_helpers.rs — event-abi
//
// Small, allocation-free helpers used by the safe parser. No public API
// churn outside the crate. These are the building blocks the public
// `lib.rs` re-exports.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::generated::{Header, Valid, HEADER_LEN};

/// `True` iff the field's valid bit is set in `header.valids`.
pub fn verify_field(header: &Header, field: Valid) -> bool {
    header.valids & (field as u32) != 0
}

/// `True` iff the truncation flag (header byte `flags` bit 0) is set.
pub fn is_truncated(header: &Header) -> bool {
    header.flags & crate::generated::EVENT_FLAG_TRUNC != 0
}

/// `True` iff the redaction flag (header byte `flags` bit 1) is set.
pub fn is_redacted(header: &Header) -> bool {
    header.flags & crate::generated::EVENT_FLAG_REDACTED != 0
}

/// Compute the wire record length needed for a header + payload of
/// `payload_len` bytes. Clamps to `[HEADER_LEN, HEADER_LEN + PAYLOAD_MAX]`.
pub fn compute_record_len(payload_len: usize) -> usize {
    let total = HEADER_LEN.saturating_add(payload_len);
    let max = HEADER_LEN + crate::generated::PAYLOAD_MAX;
    if total > max {
        max
    } else {
        total
    }
}

/// Format the valid-bit mask as a short human-readable list of named
/// bits. Used by the `DecodeReport` and by `tests/parse.rs` for the
/// round-trip diagnostic.
pub fn format_valids(valids: u32) -> String {
    let names: &[(u32, &str)] = &[
        (Valid::BootId as u32, "boot_id"),
        (Valid::CgroupId as u32, "cgroup_id"),
        (Valid::PidTgid as u32, "pid_tgid"),
        (Valid::NsPid as u32, "ns_pid"),
        (Valid::NsMnt as u32, "ns_mnt"),
        (Valid::NsNet as u32, "ns_net"),
        (Valid::NsUser as u32, "ns_user"),
        (Valid::NsUts as u32, "ns_uts"),
        (Valid::NsIpc as u32, "ns_ipc"),
        (Valid::NsTime as u32, "ns_time"),
        (Valid::TaskStart as u32, "task_start"),
        (Valid::Processor as u32, "processor"),
        (Valid::PayloadTrunc as u32, "payload_trunc"),
        (Valid::Redacted as u32, "redacted"),
        (Valid::KfuncUsed as u32, "kfunc_used"),
        // TASK-12 additions — the `Valid` enum carries five new file
        // bits at positions 0x8000..0x80000; format them here so the
        // diagnostic surfaces the new file-sensor validity bits.
        (Valid::FilePath as u32, "file_path"),
        (Valid::FileFlags as u32, "file_flags"),
        (Valid::FileMode as u32, "file_mode"),
        (Valid::FileDenySource as u32, "file_deny_source"),
        (Valid::FileErrno as u32, "file_errno"),
    ];
    let mut s = String::new();
    for (bit, name) in names {
        if valids & bit != 0 {
            if !s.is_empty() {
                s.push('|');
            }
            s.push_str(name);
        }
    }
    if s.is_empty() {
        s.push_str("(none)");
    }
    s
}
