// SPDX-License-Identifier: Apache-2.0 OR MIT
use event_abi::{EventKind, Valid};

pub fn synthetic_record(seq: u64) -> Vec<u8> {
    let mut bytes = vec![0_u8; event_abi::HEADER_LEN + 8];
    let record_len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    bytes[0..4].copy_from_slice(&event_abi::SCHEMA_MAJOR.to_le_bytes());
    bytes[4..8].copy_from_slice(&event_abi::SCHEMA_MINOR.to_le_bytes());
    bytes[8..12].copy_from_slice(&(event_abi::HEADER_LEN as u32).to_le_bytes());
    bytes[12..16].copy_from_slice(&record_len.to_le_bytes());
    bytes[16] = EventKind::ProcessExit as u8;
    bytes[24..32].copy_from_slice(&seq.to_le_bytes());
    bytes[32..40].copy_from_slice(&seq.saturating_mul(1_000_000).to_le_bytes());
    bytes[40..56].copy_from_slice(&[0x42; 16]);
    bytes[56..64].copy_from_slice(&1_u64.to_le_bytes());
    bytes[64..72].copy_from_slice(&1_u64.to_le_bytes());
    bytes[72..80].copy_from_slice(&1_u64.to_le_bytes());
    bytes[84..88]
        .copy_from_slice(&(event_abi::VALID_REQUIRED | Valid::Processor as u32).to_le_bytes());
    bytes
}
