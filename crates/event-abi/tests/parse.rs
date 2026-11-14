// tests/parse.rs: event-abi
//
// Exhaustive round-trip + hostile-input tests for the safe parser.
// Covers every `EventKind` plus the failure paths required by the
// documented contract: too-short buffer, length mismatch (low + high), unknown
// schema major, unknown event kind, truncated record, and the
// truncation / redaction flag bits. The v1/v2 compatibility tests live in
// the `v1_v2_compat` section at the bottom.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use event_abi::{
    parse, DecodeError, EventKind, Header, HeaderV2, Valid, EVENT_FLAG_REDACTED, EVENT_FLAG_TRUNC,
    HEADER_LEN, HEADER_LEN_V1, PAYLOAD_MAX, SCHEMA_MAJOR, SCHEMA_MINOR, SCHEMA_V1_MAJOR,
    STACK_DEPTH, STACK_ID_NONE, STACK_MAP_ENTRIES,
};

/// Build a version-1 Header with sane defaults and a configurable
/// kind / payload.
fn make_header(kind: EventKind, payload_len: usize, valids: u32) -> Header {
    let mut boot_id = [0u8; 16];
    boot_id[0] = 0xAB;
    boot_id[1] = 0xCD;
    boot_id[14] = 0x12;
    boot_id[15] = 0x34;
    Header {
        schema_major: SCHEMA_V1_MAJOR,
        schema_minor: SCHEMA_MINOR,
        header_len: HEADER_LEN_V1 as u32,
        record_len: (HEADER_LEN_V1 + payload_len) as u32,
        event_kind: kind as u8,
        _pad0: [0u8; 3],
        flags: 0,
        _pad1: [0u8; 3],
        seq: 0x0102_0304_0506_0708,
        ts_monotonic_ns: 0x1112_1314_1516_1718,
        boot_id,
        pid_tgid: 0x2122_2324_2526_2728,
        task_start_time_ns: 0x3132_3334_3536_3738,
        cgroup_id: 0x4142_4344_4546_4748,
        processor_id: 3,
        valids,
        ns_pid: 0x5152_5354_5556_5758,
    }
}

/// Serialise a version-1 Header into a 96-byte buffer.
fn header_to_bytes(h: &Header) -> [u8; HEADER_LEN_V1] {
    let bytes: [u8; HEADER_LEN_V1] = unsafe {
        // SAFETY: the const_assert in lib.rs pins the size to 96 and
        // the struct is `#[repr(C)]`.
        core::ptr::read(core::ptr::addr_of!(*h) as *const [u8; HEADER_LEN_V1])
    };
    bytes
}

fn build_record(kind: EventKind, payload_len: usize, valids: u32) -> Vec<u8> {
    let h = make_header(kind, payload_len, valids);
    let mut buf = Vec::with_capacity(HEADER_LEN_V1 + payload_len);
    buf.extend_from_slice(&header_to_bytes(&h));
    buf.extend(std::iter::repeat_n(0xAAu8, payload_len));
    buf
}

// ---------------------------------------------------------------------------
// Happy paths: round-trip every EventKind
// ---------------------------------------------------------------------------

#[test]
fn round_trip_every_kind() {
    let kinds = [
        EventKind::ProcessFork,
        EventKind::ProcessExecResult,
        EventKind::ProcessExit,
        EventKind::FileOpen,
        EventKind::FileCreate,
        EventKind::FileUnlink,
        EventKind::FileRename,
        EventKind::FileTruncate,
        EventKind::NetworkConnect,
        EventKind::NetworkAccept,
        EventKind::NetworkState,
        EventKind::DnsPacket,
        EventKind::LsmDenyOwn,
        EventKind::Identity,
        EventKind::SyscallEnter,
        EventKind::SyscallExit,
    ];
    for kind in kinds {
        let k = kind as u8;
        let buf = build_record(kind, 16, 0x0001_0002);
        let ev = parse(&buf).expect("happy record must parse");
        assert_eq!(ev.header.event_kind, kind as u8, "kind round-trip #{k}");
        assert_eq!(ev.payload.len(), 16);
        assert_eq!(ev.kind_name(), Header::kind_name(kind as u8));
        // Every field round-trips byte-for-byte.
        assert_eq!(ev.header.seq, 0x0102_0304_0506_0708);
        assert_eq!(ev.header.ts_monotonic_ns, 0x1112_1314_1516_1718);
        assert_eq!(ev.header.pid_tgid, 0x2122_2324_2526_2728);
        assert_eq!(ev.header.cgroup_id, 0x4142_4344_4546_4748);
        assert_eq!(ev.header.processor_id, 3);
        assert_eq!(ev.header.ns_pid, 0x5152_5354_5556_5758);
        // Report aggregates the same facts.
        let report = ev.report();
        assert_eq!(report.kind, kind as u8);
        assert_eq!(report.payload_len, 16);
        assert!(!report.truncated);
        assert!(!report.redacted);
    }
}

#[test]
fn syscall_contract_matches_c_header() {
    assert_eq!(EventKind::SyscallEnter as u8, 25);
    assert_eq!(EventKind::SyscallExit as u8, 26);
    assert_eq!(event_abi::syscall_valid::NR, 0x4000_0000);
    assert_eq!(event_abi::syscall_valid::LATENCY, 0x8000_0000);
    assert_eq!(event_abi::syscall_valid::FLAGS, 0x1_0000_0000);
    assert_eq!(core::mem::size_of::<event_abi::SyscallEventPayload>(), 32);
}

#[test]
fn happy_fixture_round_trips() {
    let bytes = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/event-abi/v1-happy.binpb"),
    )
    .expect("happy fixture must exist (run `cargo run -p event-abi --bin emit-fixture`)");
    let ev = parse(&bytes).expect("happy fixture must parse");
    assert_eq!(ev.header.event_kind, EventKind::ProcessExecResult as u8);
    assert_eq!(ev.payload.len(), 32);
    assert_eq!(ev.kind_name(), "PROCESS_EXEC_RESULT");
}

// ---------------------------------------------------------------------------
// Hostile inputs: typed errors, no panic
// ---------------------------------------------------------------------------

#[test]
fn short_buffer_returns_short_buffer_error() {
    for n in 0..HEADER_LEN_V1 {
        let buf = vec![0u8; n];
        let err = parse(&buf).expect_err("short buffer must fail");
        match err {
            DecodeError::ShortBuffer { have, need } => {
                assert_eq!(have, n);
                assert_eq!(need, HEADER_LEN_V1);
            }
            other => panic!("expected ShortBuffer, got {other:?}"),
        }
    }
}

#[test]
fn record_len_below_header_len_returns_length_mismatch() {
    let buf = build_record(EventKind::FileOpen, 16, 0);
    let bytes = header_to_bytes(&parse(&buf).unwrap().header);
    // Re-write record_len to a value < HEADER_LEN_V1
    let mut bad = vec![0u8; HEADER_LEN_V1 + 8];
    bad[..HEADER_LEN_V1].copy_from_slice(&bytes);
    // Overwrite the record_len field (offset 12, u32, little-endian)
    bad[12] = 0x10;
    bad[13] = 0x00;
    bad[14] = 0x00;
    bad[15] = 0x00;
    let err = parse(&bad).expect_err("under-length must fail");
    assert!(matches!(err, DecodeError::LengthMismatch { .. }), "{err:?}");
}

#[test]
fn record_len_above_buffer_len_returns_length_mismatch() {
    let mut buf = build_record(EventKind::FileOpen, 16, 0);
    // The header's record_len is HEADER_LEN_V1 + 16 = 112; we have
    // HEADER_LEN_V1 + 8 = 104 bytes in the buffer.
    buf.truncate(HEADER_LEN_V1 + 8);
    let err = parse(&buf).expect_err("oversized record_len must fail");
    assert!(matches!(err, DecodeError::LengthMismatch { .. }), "{err:?}");
}

#[test]
fn unknown_schema_major_returns_unknown_schema_major() {
    let mut buf = build_record(EventKind::FileOpen, 0, 0);
    // Overwrite schema_major (offset 0, u32) with 99.
    buf[0] = 99;
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;
    let err = parse(&buf).expect_err("unknown major must fail");
    match err {
        DecodeError::UnknownSchemaMajor { got, expected } => {
            assert_eq!(got, 99);
            assert_eq!(expected, SCHEMA_MAJOR);
        }
        other => panic!("expected UnknownSchemaMajor, got {other:?}"),
    }
}

#[test]
fn unknown_event_kind_returns_unknown_event_kind() {
    let mut buf = build_record(EventKind::FileOpen, 0, 0);
    // event_kind is at offset 16 (u8). Set to 99.
    buf[16] = 99;
    let err = parse(&buf).expect_err("unknown kind must fail");
    match err {
        DecodeError::UnknownEventKind { byte, max } => {
            assert_eq!(byte, 99);
            assert_eq!(max, EventKind::MAX_DISCRIMINANT);
        }
        other => panic!("expected UnknownEventKind, got {other:?}"),
    }
}

#[test]
fn event_kind_zero_returns_unknown_event_kind() {
    let mut buf = build_record(EventKind::FileOpen, 0, 0);
    buf[16] = 0;
    let err = parse(&buf).expect_err("UNSPECIFIED kind must fail");
    assert!(matches!(err, DecodeError::UnknownEventKind { .. }));
}

#[test]
fn truncation_flag_is_detected() {
    let mut buf = build_record(EventKind::FileOpen, 16, 0);
    buf[20] = EVENT_FLAG_TRUNC;
    let ev = parse(&buf).expect("trunc flag must still parse");
    assert!(ev.is_truncated());
    assert!(!ev.is_redacted());
    // The truncation flag and the PayloadTrunc valid bit are
    // independent signals: the flag is set by the sensor's
    // privacy/transport layer, the valid bit is set by the
    // payload-truncation reasoning. The test covers the flag here;
    // `required_valid_bits_have_documented_meaning` covers the
    // valids bitmask.
}

#[test]
fn redaction_flag_is_detected() {
    let mut buf = build_record(EventKind::FileOpen, 16, 0);
    buf[20] = EVENT_FLAG_REDACTED;
    let ev = parse(&buf).expect("redact flag must still parse");
    assert!(!ev.is_truncated());
    assert!(ev.is_redacted());
}

#[test]
fn truncated_record_payload_is_clipped() {
    // header says record_len = HEADER_LEN_V1 + 16; buffer has only
    // HEADER_LEN_V1 + 8 bytes. The parser refuses to advance past the
    // recorded length, so this fails LengthMismatch first.
    let buf = build_record(EventKind::FileOpen, 16, 0);
    let buf = &buf[..HEADER_LEN_V1 + 8];
    let err = parse(buf).expect_err("must fail with LengthMismatch");
    assert!(matches!(err, DecodeError::LengthMismatch { .. }), "{err:?}");
}

#[test]
fn payload_at_max_length_is_accepted() {
    let buf = build_record(EventKind::DnsPacket, PAYLOAD_MAX, 0);
    let ev = parse(&buf).expect("max payload must parse");
    assert_eq!(ev.payload.len(), PAYLOAD_MAX);
}

// ---------------------------------------------------------------------------
// Validity bitmask cross-check
// ---------------------------------------------------------------------------

#[test]
fn required_valid_bits_have_documented_meaning() {
    let buf = build_record(EventKind::ProcessFork, 0, event_abi::VALID_REQUIRED);
    let ev = parse(&buf).expect("valid process event must parse");
    assert!(ev.verify_field(Valid::BootId));
    assert!(ev.verify_field(Valid::CgroupId));
    assert!(ev.verify_field(Valid::PidTgid));
    assert!(ev.verify_field(Valid::TaskStart));
}

// ---------------------------------------------------------------------------
// Version / constant sanity
// ---------------------------------------------------------------------------

#[test]
fn schema_constants_are_stable() {
    // v1 is frozen and still accepted; v2 is what current producers emit.
    assert_eq!(SCHEMA_V1_MAJOR, 1);
    assert_eq!(HEADER_LEN_V1, 96);
    assert_eq!(SCHEMA_MAJOR, 2);
    assert_eq!(SCHEMA_MINOR, 0);
    assert_eq!(HEADER_LEN, 104);
    assert_eq!(PAYLOAD_MAX, 4096);
    assert_eq!(STACK_ID_NONE, -1);
    assert_eq!(STACK_DEPTH, 64);
    assert_eq!(STACK_MAP_ENTRIES, 16_384);
}

#[test]
fn header_struct_size_matches_constant() {
    assert_eq!(core::mem::size_of::<Header>(), HEADER_LEN_V1);
    assert_eq!(core::mem::align_of::<Header>(), 8);
    assert_eq!(core::mem::size_of::<HeaderV2>(), HEADER_LEN);
    assert_eq!(core::mem::align_of::<HeaderV2>(), 8);
}

// ---------------------------------------------------------------------------
// DNS sensor: DNS packet sensor ABI additions.
// ---------------------------------------------------------------------------

use event_abi::{
    dns_valid, DnsDirection, DnsPacket, DnsProtocol, DnsTruncationReason, DNS_PAYLOAD_LEN,
    DNS_QNAME_MAX,
};

#[test]
fn dns_payload_size_and_qname_max_match_c_header() {
    assert_eq!(DNS_PAYLOAD_LEN, 320);
    assert_eq!(DNS_QNAME_MAX, 253);
    assert_eq!(core::mem::size_of::<DnsPacket>(), DNS_PAYLOAD_LEN);
}

#[test]
fn dns_payload_layout_matches_c_header_struct() {
    let pkt: DnsPacket = unsafe { core::mem::zeroed() };
    let bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            (&pkt as *const DnsPacket) as *const u8,
            core::mem::size_of::<DnsPacket>(),
        )
    };
    assert_eq!(bytes.len(), DNS_PAYLOAD_LEN);
    assert!(bytes.len() >= 8 + DNS_QNAME_MAX);
    const _: () = assert!(DNS_PAYLOAD_LEN >= 320);
}

#[test]
fn dns_validity_bit_constants_match_header() {
    assert_eq!(dns_valid::QNAME, 0x0200_0000);
    assert_eq!(dns_valid::QTYPE, 0x0400_0000);
    assert_eq!(dns_valid::FLAGS, 0x0800_0000);
    assert_eq!(dns_valid::COUNTS, 0x1000_0000);
    assert_eq!(dns_valid::DST_IP, 0x2000_0000);
    assert_eq!(dns_valid::PAYLOAD_TRUNC, 0x4000_0000);
}

#[test]
fn dns_validity_bits_compose_into_valids() {
    let all: u32 = dns_valid::QNAME
        | dns_valid::QTYPE
        | dns_valid::FLAGS
        | dns_valid::COUNTS
        | dns_valid::DST_IP
        | dns_valid::PAYLOAD_TRUNC;
    assert_eq!(all, 0x7E00_0000);
}

#[test]
fn dns_enum_mapping_is_well_defined() {
    assert_eq!(DnsDirection::from_byte(0) as u8, DnsDirection::Query as u8);
    assert_eq!(
        DnsDirection::from_byte(1) as u8,
        DnsDirection::Response as u8
    );
    assert_eq!(
        DnsDirection::from_byte(0xff) as u8,
        DnsDirection::Query as u8
    );
    assert_eq!(DnsProtocol::from_byte(0) as u8, DnsProtocol::Udp as u8);
    assert_eq!(DnsProtocol::from_byte(1) as u8, DnsProtocol::Tcp as u8);
    assert_eq!(DnsProtocol::from_byte(0xff) as u8, DnsProtocol::Udp as u8);
    assert_eq!(
        DnsTruncationReason::from_byte(0) as u8,
        DnsTruncationReason::None as u8
    );
    assert_eq!(
        DnsTruncationReason::from_byte(1) as u8,
        DnsTruncationReason::NameTooLong as u8
    );
    assert_eq!(
        DnsTruncationReason::from_byte(2) as u8,
        DnsTruncationReason::HeaderTooShort as u8
    );
    assert_eq!(
        DnsTruncationReason::from_byte(0xff) as u8,
        DnsTruncationReason::InternalBpfError as u8
    );
    assert!(!DnsTruncationReason::None.is_truncation());
    assert!(DnsTruncationReason::NameTooLong.is_truncation());
    assert!(DnsTruncationReason::HeaderTooShort.is_truncation());
    assert!(DnsTruncationReason::InternalBpfError.is_truncation());
}

#[test]
fn dns_packet_event_with_max_qname_parses() {
    let buf = build_record(EventKind::DnsPacket, DNS_PAYLOAD_LEN, 0);
    let ev = parse(&buf).expect("DNS_PACKET max-length payload must parse");
    assert_eq!(ev.header.event_kind, EventKind::DnsPacket as u8);
    assert_eq!(ev.payload.len(), DNS_PAYLOAD_LEN);
}

// ---------------------------------------------------------------------------
// v1 / v2 compatibility (0.3 stack-id header extension)
// ---------------------------------------------------------------------------

/// Build a version-2 header with a configurable stack id.
fn make_header_v2(kind: EventKind, payload_len: usize, stack_id: i32) -> HeaderV2 {
    let v1 = Header {
        schema_major: SCHEMA_MAJOR,
        schema_minor: SCHEMA_MINOR,
        header_len: HEADER_LEN as u32,
        record_len: (HEADER_LEN + payload_len) as u32,
        ..make_header(kind, payload_len, 0)
    };
    HeaderV2 {
        v1,
        stack_id,
        user_stack_id: STACK_ID_NONE,
    }
}

fn header_v2_to_bytes(h: &HeaderV2) -> [u8; HEADER_LEN] {
    unsafe { core::ptr::read(core::ptr::addr_of!(*h) as *const [u8; HEADER_LEN]) }
}

fn build_v2_record(kind: EventKind, payload: &[u8], stack_id: i32) -> Vec<u8> {
    let header = make_header_v2(kind, payload.len(), stack_id);
    let mut buf = Vec::with_capacity(HEADER_LEN + payload.len());
    buf.extend_from_slice(&header_v2_to_bytes(&header));
    buf.extend_from_slice(payload);
    buf
}

#[test]
fn v2_round_trip_with_stack_id() {
    let payload = vec![0x5Au8; 24];
    let buf = build_v2_record(EventKind::FileOpen, &payload, 42);
    let ev = parse(&buf).expect("v2 record must parse");
    assert_eq!(ev.header.schema_major, 2);
    assert_eq!(ev.header.header_len as usize, HEADER_LEN);
    assert_eq!(ev.stack_id, Some(42));
    assert_eq!(ev.user_stack_id, None);
    assert_eq!(ev.payload, &payload[..]);
    assert_eq!(ev.report().stack_id, Some(42));
    assert_eq!(ev.kind_name(), "FILE_OPEN");
}

#[test]
fn v2_user_stack_id_is_separate_from_kernel_stack_id() {
    let payload = vec![0x5Au8; 16];
    let header = HeaderV2 {
        v1: make_header_v2(EventKind::FileOpen, payload.len(), 42).v1,
        stack_id: 42,
        user_stack_id: 17,
    };
    let mut buf = Vec::new();
    buf.extend_from_slice(&header_v2_to_bytes(&header));
    buf.extend_from_slice(&payload);
    let ev = parse(&buf).expect("v2 record must parse");
    assert_eq!(ev.stack_id, Some(42));
    assert_eq!(ev.user_stack_id, Some(17));
    assert_eq!(ev.report().user_stack_id, Some(17));
}

#[test]
fn v2_no_stack_sentinel_decodes_as_none() {
    let buf = build_v2_record(EventKind::ProcessExecResult, &[0u8; 8], STACK_ID_NONE);
    let ev = parse(&buf).expect("v2 record must parse");
    assert_eq!(ev.stack_id, None);
    assert_eq!(ev.user_stack_id, None);
    assert_eq!(ev.report().stack_id, None);
}

#[test]
fn v2_stack_id_zero_is_a_valid_stack() {
    // bpf_get_stackid() returns 0 for the first captured stack, so 0 MUST
    // NOT be treated as "no stack" (the sentinel is -1).
    let buf = build_v2_record(EventKind::FileCreate, &[], 0);
    let ev = parse(&buf).expect("v2 record must parse");
    assert_eq!(ev.stack_id, Some(0));
}

#[test]
fn v1_fixture_still_parses_without_stack_id() {
    let bytes = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/event-abi/v1-happy.binpb"),
    )
    .expect("v1 fixture must exist");
    let ev = parse(&bytes).expect("v1 fixture must keep parsing");
    assert_eq!(ev.header.schema_major, SCHEMA_V1_MAJOR);
    assert_eq!(ev.header.header_len as usize, HEADER_LEN_V1);
    assert_eq!(ev.stack_id, None);
    assert_eq!(ev.user_stack_id, None);
    assert_eq!(ev.payload.len(), 32);
}

#[test]
fn v2_fixture_parses_with_stack_id() {
    let bytes = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/event-abi/v2-happy.binpb"),
    )
    .expect("v2 fixture must exist (run `cargo run -p event-abi --bin emit-fixture`)");
    let ev = parse(&bytes).expect("v2 fixture must parse");
    assert_eq!(ev.header.schema_major, 2);
    assert_eq!(ev.stack_id, Some(7));
    assert_eq!(ev.payload.len(), 32);
    assert_eq!(ev.kind_name(), "PROCESS_EXEC_RESULT");
}

#[test]
fn v2_requires_the_v2_header_extension() {
    // A v2 record that claims the v1 header length must be rejected: the
    // stack id word would overlap the payload.
    let mut buf = build_v2_record(EventKind::FileOpen, &[0u8; 16], 1);
    buf[8..12].copy_from_slice(&(HEADER_LEN_V1 as u32).to_le_bytes());
    let err = parse(&buf).expect_err("v2 record with header_len=96 must fail");
    assert!(matches!(err, DecodeError::LengthMismatch { .. }), "{err:?}");
}

#[test]
fn v2_buffer_shorter_than_extended_header_is_short_buffer() {
    for n in HEADER_LEN_V1..HEADER_LEN {
        let mut buf = vec![0u8; n];
        buf[0..4].copy_from_slice(&SCHEMA_MAJOR.to_le_bytes());
        buf[8..12].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
        let err = parse(&buf).expect_err("short v2 header must fail");
        match err {
            DecodeError::ShortBuffer { have, need } => {
                assert_eq!(have, n);
                assert_eq!(need, HEADER_LEN);
            }
            other => panic!("expected ShortBuffer, got {other:?}"),
        }
    }
}

#[test]
fn v2_forward_compatible_header_len_is_read_from_header() {
    // A future schema-minor record may append header fields; the parser
    // reads stack_id from the fixed v2 offset and the payload from
    // header_len. Here header_len = 112 (8 future bytes, zeroed).
    let payload = [0x77u8; 5];
    let mut buf = build_v2_record(EventKind::FileTruncate, &payload, 9);
    let future_header_len = HEADER_LEN + 8;
    let record_len = future_header_len + payload.len();
    buf[8..12].copy_from_slice(&(future_header_len as u32).to_le_bytes());
    buf[12..16].copy_from_slice(&(record_len as u32).to_le_bytes());
    buf.splice(HEADER_LEN..HEADER_LEN, [0u8; 8]);
    let ev = parse(&buf).expect("forward-compatible v2 header must parse");
    assert_eq!(ev.header.header_len as usize, future_header_len);
    assert_eq!(ev.stack_id, Some(9));
    assert_eq!(ev.payload, &payload[..]);
}

#[test]
fn unknown_schema_major_still_rejected_with_v2_expected() {
    let mut buf = build_record(EventKind::FileOpen, 0, 0);
    buf[0..4].copy_from_slice(&3u32.to_le_bytes());
    match parse(&buf).expect_err("schema major 3 must fail") {
        DecodeError::UnknownSchemaMajor { got, expected } => {
            assert_eq!(got, 3);
            assert_eq!(expected, SCHEMA_MAJOR);
        }
        other => panic!("expected UnknownSchemaMajor, got {other:?}"),
    }
}
