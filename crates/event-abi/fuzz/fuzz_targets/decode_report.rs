// fuzz_targets/decode_report.rs — event-abi
//
// Exercises the FULL decode surface on any successfully-parsed record:
// `report()` aggregation, the truncation/redaction flag accessors,
// `kind_name()`, and `verify_field()` across a spread of validity bits
// (identity, file, and network namespaces). Asserts the bound invariants:
// payload never exceeds the buffer and always equals `record_len - HEADER_LEN`,
// and the report's kind_name agrees with the header. Every accessor must be
// panic-free for any decoded record. No unsafe in this target.
//
// Run: cargo fuzz run decode_report -- -max_len=65536
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_main]

use event_abi::{Header, Valid, HEADER_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(ev) = event_abi::parse(data) else {
        return;
    };

    let report = ev.report();

    // BOUNDS: payload never exceeds the buffer; equals record_len - HEADER_LEN.
    assert!(report.payload_len <= data.len(), "payload must fit in buffer");
    assert_eq!(
        report.payload_len + HEADER_LEN,
        report.record_len as usize,
        "payload_len must equal record_len - HEADER_LEN"
    );
    assert!(
        report.record_len as usize <= data.len(),
        "record_len must not exceed buffer"
    );

    // Report agrees with the decoded header.
    assert_eq!(report.kind, ev.header.event_kind);
    assert_eq!(report.kind_name, Header::kind_name(report.kind));
    assert_eq!(report.payload_len, ev.payload.len());

    // Flag + validity accessors must never panic on a decoded record.
    let _ = ev.is_truncated();
    let _ = ev.is_redacted();
    let _ = ev.kind_name();

    // Spread of validity bits across identity / file / network namespaces.
    const BITS: &[Valid] = &[
        Valid::BootId,
        Valid::CgroupId,
        Valid::PidTgid,
        Valid::NsPid,
        Valid::TaskStart,
        Valid::Processor,
        Valid::PayloadTrunc,
        Valid::Redacted,
        Valid::FilePath,
        Valid::FileFlags,
        Valid::NetDstIp,
        Valid::NetNewState,
    ];
    for bit in BITS {
        let _ = ev.verify_field(*bit);
    }
});
