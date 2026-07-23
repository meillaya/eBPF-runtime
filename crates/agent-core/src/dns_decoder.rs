// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded user-space DNS decoder.
//!
//! Parses DNS messages from a wire-format byte slice with strict limits:
//! * Header length must be exactly `DNS_HEADER_SIZE`.
//! * `qd_count + an_count + ns_count + ar_count <= DNS_RECORD_MAX`.
//! * Each qname is read with a bounded loop (`MAX_NAME_ITERATIONS = 512`)
//!   so malicious compression loops are detected and rejected.
//! * Each rdata is bounded to `DNS_RDATA_MAX = 4 KiB`.
//! * The decoder NEVER persists the raw packet bytes — only the parsed
//!   fields. The DNS sensor (task 14) bounded the raw packet at capture
//!   time; this decoder is the user-space safety net for replay.
//!
//! The decoder uses only allocations inside the parsed structs
//! (`DnsMessage`/`DnsQuestion`/`DnsResourceRecord`) and a fixed array for
//! compression-offset tracking, so it is no_std-friendly.

use crate::dns_name::{read_name, Cursor};

pub const DNS_HEADER_SIZE: usize = 12;
pub const DNS_NAME_MAX: usize = 253;
pub const DNS_RECORD_MAX: usize = 4_096;
pub const DNS_RDATA_MAX: usize = 4 * 1_024;
pub const MAX_NAME_ITERATIONS: u32 = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TruncationReason {
    None,
    NameTooLong,
    HeaderTooShort,
    RecordCountExceeded,
    PayloadOversized,
    CompressionLoopDetected,
    InvalidLabelLength,
    InternalError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsDecodeError {
    HeaderTooShort,
    RecordCountExceeded,
    NameTooLong,
    CompressionLoopDetected,
    InvalidLabelLength,
    PayloadOversized,
    UnsupportedRtype(u16),
    BufferUnderflow,
    RecordCountMismatch,
    Truncated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResourceRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rd_length: u16,
    pub rdata: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub flags: u16,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsResourceRecord>,
    pub truncation_reason: TruncationReason,
    pub parsed_length: usize,
    pub wire_length: usize,
}

fn classify_rtype(rtype: u16) -> Result<u16, DnsDecodeError> {
    match rtype {
        1 | 2 | 5 | 6 | 12 | 15 | 28 | 33 | 41 | 252 | 255 => Ok(rtype),
        other => Err(DnsDecodeError::UnsupportedRtype(other)),
    }
}

pub fn parse_dns_message(buf: &[u8]) -> Result<DnsMessage, DnsDecodeError> {
    let wire_length = buf.len();
    if buf.len() < DNS_HEADER_SIZE {
        return Err(DnsDecodeError::HeaderTooShort);
    }
    let dns_buf: &[u8] = if buf.len() >= DNS_HEADER_SIZE + 2 {
        let prefix = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if prefix == buf.len() - 2 {
            &buf[2..]
        } else {
            buf
        }
    } else {
        buf
    };
    let effective_wire = dns_buf.len();
    if dns_buf.len() < DNS_HEADER_SIZE {
        return Err(DnsDecodeError::HeaderTooShort);
    }
    let mut cursor = Cursor::new(dns_buf);
    let id = cursor.read_u16()?;
    let flags = cursor.read_u16()?;
    let qd_count = cursor.read_u16()?;
    let an_count = cursor.read_u16()?;
    let ns_count = cursor.read_u16()?;
    let ar_count = cursor.read_u16()?;
    let total = (qd_count as u32)
        .saturating_add(an_count as u32)
        .saturating_add(ns_count as u32)
        .saturating_add(ar_count as u32);
    if total > DNS_RECORD_MAX as u32 {
        return Err(DnsDecodeError::RecordCountExceeded);
    }
    let mut questions = Vec::with_capacity(qd_count as usize);
    for _ in 0..qd_count {
        let qname = read_name(&mut cursor, DNS_NAME_MAX)?;
        let qtype = cursor.read_u16()?;
        let qclass = cursor.read_u16()?;
        classify_rtype(qtype)?;
        questions.push(DnsQuestion {
            qname,
            qtype,
            qclass,
        });
    }
    let mut answers = Vec::with_capacity((an_count + ns_count + ar_count) as usize);
    let rr_total = an_count + ns_count + ar_count;
    for _ in 0..rr_total {
        let name = read_name(&mut cursor, DNS_NAME_MAX)?;
        let rtype = cursor.read_u16()?;
        let rclass = cursor.read_u16()?;
        let ttl = cursor.read_u32()?;
        let rd_length = cursor.read_u16()?;
        if rd_length as usize > DNS_RDATA_MAX {
            return Err(DnsDecodeError::PayloadOversized);
        }
        if cursor.remaining() < rd_length as usize {
            return Err(DnsDecodeError::BufferUnderflow);
        }
        let rdata = cursor.buf[cursor.pos..cursor.pos + rd_length as usize].to_vec();
        cursor.pos += rd_length as usize;
        classify_rtype(rtype)?;
        answers.push(DnsResourceRecord {
            name,
            rtype,
            rclass,
            ttl,
            rd_length,
            rdata,
        });
    }
    let parsed_length = cursor.pos;
    if parsed_length != effective_wire {
        return Err(DnsDecodeError::RecordCountMismatch);
    }
    Ok(DnsMessage {
        id,
        flags,
        qd_count,
        an_count,
        ns_count,
        ar_count,
        questions,
        answers,
        truncation_reason: TruncationReason::None,
        parsed_length,
        wire_length,
    })
}

pub fn truncation_reason_from_error(error: &DnsDecodeError) -> TruncationReason {
    match error {
        DnsDecodeError::HeaderTooShort => TruncationReason::HeaderTooShort,
        DnsDecodeError::RecordCountExceeded => TruncationReason::RecordCountExceeded,
        DnsDecodeError::NameTooLong => TruncationReason::NameTooLong,
        DnsDecodeError::CompressionLoopDetected => TruncationReason::CompressionLoopDetected,
        DnsDecodeError::InvalidLabelLength => TruncationReason::InvalidLabelLength,
        DnsDecodeError::PayloadOversized => TruncationReason::PayloadOversized,
        DnsDecodeError::UnsupportedRtype(_) => TruncationReason::InternalError,
        DnsDecodeError::BufferUnderflow => TruncationReason::PayloadOversized,
        DnsDecodeError::RecordCountMismatch => TruncationReason::PayloadOversized,
        DnsDecodeError::Truncated => TruncationReason::InternalError,
    }
}
