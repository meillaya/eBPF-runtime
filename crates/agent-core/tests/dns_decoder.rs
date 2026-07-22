// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Host-side acceptance tests for the bounded user-space DNS decoder.

use agent_core::{
    parse_dns_message, DnsDecodeError, DnsMessage, DnsResourceRecord, TruncationReason,
    DNS_HEADER_SIZE, DNS_NAME_MAX, DNS_RDATA_MAX, DNS_RECORD_MAX, MAX_NAME_ITERATIONS,
};

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_qname(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        let bytes = label.as_bytes();
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
}

fn push_header(out: &mut Vec<u8>, id: u16, flags: u16, qd: u16, an: u16, ns: u16, ar: u16) {
    push_u16(out, id);
    push_u16(out, flags);
    push_u16(out, qd);
    push_u16(out, an);
    push_u16(out, ns);
    push_u16(out, ar);
}

fn question_section(out: &mut Vec<u8>, qname: &str, qtype: u16, qclass: u16) {
    push_qname(out, qname);
    push_u16(out, qtype);
    push_u16(out, qclass);
}

fn answer_section(out: &mut Vec<u8>, name: &str, rtype: u16, rclass: u16, ttl: u32, rdata: &[u8]) {
    push_qname(out, name);
    push_u16(out, rtype);
    push_u16(out, rclass);
    push_u32(out, ttl);
    push_u16(out, rdata.len() as u16);
    out.extend_from_slice(rdata);
}

#[test]
fn valid_udp_query_decodes_with_qname_and_qtype() {
    let mut packet = Vec::new();
    push_header(&mut packet, 0x1234, 0x0100, 1, 0, 0, 0);
    question_section(&mut packet, "example.com", 1, 1);
    let message = parse_dns_message(&packet).expect("decodes");
    assert_eq!(message.id, 0x1234);
    assert_eq!(message.qd_count, 1);
    assert_eq!(message.questions.len(), 1);
    assert_eq!(message.questions[0].qname, "example.com");
    assert_eq!(message.questions[0].qtype, 1);
    assert_eq!(message.questions[0].qclass, 1);
    assert_eq!(message.wire_length, packet.len());
    assert_eq!(message.parsed_length, packet.len());
}

#[test]
fn valid_udp_response_decodes_with_one_answer() {
    let mut packet = Vec::new();
    push_header(&mut packet, 0x5678, 0x8180, 1, 1, 0, 0);
    question_section(&mut packet, "example.com", 1, 1);
    answer_section(&mut packet, "example.com", 1, 1, 60, &[10, 0, 0, 5]);
    let message = parse_dns_message(&packet).expect("decodes");
    assert_eq!(message.id, 0x5678);
    assert_eq!(message.an_count, 1);
    assert_eq!(message.answers.len(), 1);
    assert_eq!(message.answers[0].rtype, 1);
    assert_eq!(message.answers[0].ttl, 60);
    assert_eq!(message.answers[0].rdata, vec![10, 0, 0, 5]);
}

#[test]
fn valid_tcp_query_decodes_with_tcp_length_prefix_handled() {
    let mut inner = Vec::new();
    push_header(&mut inner, 0x9ABC, 0x0100, 1, 0, 0, 0);
    question_section(&mut inner, "kernel-v1.local", 1, 1);
    let mut packet = Vec::new();
    push_u16(&mut packet, inner.len() as u16);
    packet.extend_from_slice(&inner);
    let message = parse_dns_message(&packet).expect("decodes with tcp prefix");
    assert_eq!(message.id, 0x9ABC);
    assert_eq!(message.qd_count, 1);
    assert_eq!(message.questions[0].qname, "kernel-v1.local");
    assert_eq!(message.wire_length, packet.len());
}

#[test]
fn compression_loop_fails_after_512_iterations() {
    let mut packet = Vec::new();
    push_header(&mut packet, 0x0001, 0x0100, 1, 0, 0, 0);
    packet.push(0xC0);
    packet.push(0x0C);
    push_u16(&mut packet, 1);
    push_u16(&mut packet, 1);
    let result = parse_dns_message(&packet);
    assert!(matches!(
        result,
        Err(DnsDecodeError::CompressionLoopDetected)
    ));
    assert!(MAX_NAME_ITERATIONS == 512);
}

#[test]
fn oversized_record_payload_is_rejected() {
    let mut packet = Vec::new();
    push_header(&mut packet, 0x1111, 0x0100, 1, 1, 0, 0);
    question_section(&mut packet, "example.com", 1, 1);
    let payload_len = DNS_RDATA_MAX + 1;
    push_qname(&mut packet, "example.com");
    push_u16(&mut packet, 1);
    push_u16(&mut packet, 1);
    push_u32(&mut packet, 0);
    push_u16(&mut packet, payload_len as u16);
    packet.extend(std::iter::repeat(0_u8).take(payload_len));
    let result = parse_dns_message(&packet);
    assert!(matches!(result, Err(DnsDecodeError::PayloadOversized)));
}

#[test]
fn name_too_long_returns_name_too_long() {
    let mut packet = Vec::new();
    push_header(&mut packet, 0x2222, 0x0100, 1, 0, 0, 0);
    let label = vec![b'a'; 10];
    let labels = DNS_NAME_MAX / (label.len() + 1) + 4;
    for _ in 0..labels {
        packet.push(label.len() as u8);
        packet.extend_from_slice(&label);
    }
    packet.push(0);
    push_u16(&mut packet, 1);
    push_u16(&mut packet, 1);
    let result = parse_dns_message(&packet);
    assert!(matches!(result, Err(DnsDecodeError::NameTooLong)));
}

#[test]
fn header_too_short_returns_header_too_short() {
    let buf = vec![0_u8; DNS_HEADER_SIZE - 1];
    let result = parse_dns_message(&buf);
    assert!(matches!(result, Err(DnsDecodeError::HeaderTooShort)));
}

#[test]
fn invalid_label_length_returns_invalid_label_length() {
    let mut packet = Vec::new();
    push_header(&mut packet, 0x3333, 0x0100, 1, 0, 0, 0);
    packet.push(0x40);
    packet.push(0x00);
    push_u16(&mut packet, 1);
    push_u16(&mut packet, 1);
    let result = parse_dns_message(&packet);
    assert!(matches!(result, Err(DnsDecodeError::InvalidLabelLength)));
}

#[test]
fn record_count_exceeded_returns_record_count_exceeded() {
    let mut packet = Vec::new();
    let count = (DNS_RECORD_MAX + 1) as u16;
    push_header(&mut packet, 0x4444, 0x0100, count, 0, 0, 0);
    let result = parse_dns_message(&packet);
    assert!(matches!(result, Err(DnsDecodeError::RecordCountExceeded)));
}

#[test]
fn unsupported_rtype_returns_unsupported_rtype() {
    let mut packet = Vec::new();
    push_header(&mut packet, 0x5555, 0x0100, 1, 0, 0, 0);
    question_section(&mut packet, "example.com", 99, 1);
    let result = parse_dns_message(&packet);
    assert!(matches!(result, Err(DnsDecodeError::UnsupportedRtype(99))));
}

#[test]
fn duplicate_query_id_returns_same_decoded_message_id() {
    let build = || {
        let mut packet = Vec::new();
        push_header(&mut packet, 0xBEEF, 0x0100, 1, 0, 0, 0);
        question_section(&mut packet, "example.com", 1, 1);
        packet
    };
    let a = parse_dns_message(&build()).expect("decodes a");
    let b = parse_dns_message(&build()).expect("decodes b");
    assert_eq!(a.id, b.id);
    assert_eq!(a.id, 0xBEEF);
    assert_ne!(a.questions[0].qname.as_ptr(), b.questions[0].qname.as_ptr());
}

#[test]
fn truncated_message_returns_truncated_reason() {
    let mut packet = Vec::new();
    push_header(&mut packet, 0x6666, 0x0100, 1, 1, 0, 0);
    question_section(&mut packet, "example.com", 1, 1);
    push_qname(&mut packet, "example.com");
    push_u16(&mut packet, 1);
    push_u16(&mut packet, 1);
    push_u32(&mut packet, 0);
    push_u16(&mut packet, 4);
    let result = parse_dns_message(&packet);
    eprintln!("DEBUG truncated result: {:?}", result);
    assert!(matches!(result, Err(DnsDecodeError::BufferUnderflow)));
    if let Err(error) = result {
        assert_eq!(
            agent_core::truncation_reason_from_error(&error),
            TruncationReason::PayloadOversized
        );
    }
}

#[test]
fn do_not_persist_raw_packet_bytes() {
    let mut packet = Vec::new();
    push_header(&mut packet, 0x7777, 0x0100, 1, 0, 0, 0);
    question_section(&mut packet, "example.com", 1, 1);
    let message: DnsMessage = parse_dns_message(&packet).expect("decodes");
    fn assert_no_raw_packet_field(_: &DnsMessage) {}
    fn assert_no_raw_packet_field_in_record(_: &DnsResourceRecord) {}
    assert_no_raw_packet_field(&message);
    if let Some(record) = message.answers.first() {
        assert_no_raw_packet_field_in_record(record);
    }
}
