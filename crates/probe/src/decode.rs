// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Decode the fixed `FPRB` event envelope and manifest-declared payloads.
//!
//! [`decode_record`] validates one ring-buffer record against the version 1
//! envelope in `sdk/include/fleet_probe.h` and returns its header fields and
//! payload. [`decode_payload`] then turns the payload into JSON using the
//! fixed layout the manifest declares for that event kind. Everything is
//! bounds checked: a malformed record is a typed error, never a panic or a
//! partially decoded value.
//!
//! The envelope contract is deliberately separate from the sensors' event ABI
//! in `bpf/include/event_abi.h`; this decoder only accepts `FPRB` records.
//!
//! ```text
//! off  size  field
//!  0    4   magic        le32 'FPRB' == 0x42525046
//!  4    2   version      1
//!  6    2   kind         probe-defined
//!  8    4   header_len   48
//! 12    4   record_len   header_len + payload_len
//! 16    4   flags        0
//! 20    4   payload_len  0..=256
//! 24    8   ts_ns        bpf_ktime_get_ns(), CLOCK_MONOTONIC
//! 32    8   pid_tgid     bpf_get_current_pid_tgid()
//! 40    8   cgroup_id    bpf_get_current_cgroup_id()
//! 48    ..  payload      probe-defined
//! ```

use serde_json::Map;
use serde_json::Value;
use thiserror::Error;

use crate::manifest::EventKind;
use crate::manifest::FieldSpec;
use crate::manifest::FieldType;
use crate::manifest::PAYLOAD_MAX;

/// Event envelope magic: little-endian bytes `F`,`P`,`R`,`B`.
pub const MAGIC: u32 = 0x4252_5046;
/// Event envelope version this decoder accepts.
pub const VERSION: u16 = 1;
/// Fixed envelope header size in bytes; payload starts here.
pub const HEADER_LEN: usize = 48;

/// One validated SDK event from the ring buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeEvent {
    /// Envelope version (always 1 for a decoded record).
    pub version: u16,
    /// Probe-defined event kind.
    pub kind: u16,
    /// Reserved flags; 0 in version 1.
    pub flags: u32,
    /// Monotonic `bpf_ktime_get_ns()` timestamp.
    pub ts_ns: u64,
    /// Thread id (low 32 bits of `bpf_get_current_pid_tgid`).
    pub pid: u32,
    /// Thread group id (high 32 bits of `bpf_get_current_pid_tgid`).
    pub tgid: u32,
    /// Cgroup v2 id.
    pub cgroup_id: u64,
    /// `payload_len` payload bytes.
    pub payload: Vec<u8>,
}

/// Why a ring-buffer record is not a valid `FPRB` version 1 event.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
    /// The record is shorter than the fixed header.
    #[error("record is {actual} bytes, shorter than the {HEADER_LEN}-byte FPRB header")]
    TooShort {
        /// Record length observed.
        actual: usize,
    },
    /// The magic does not identify an SDK event.
    #[error("bad record magic {actual:#010x}; expected FPRB ({MAGIC:#010x})")]
    BadMagic {
        /// Magic observed.
        actual: u32,
    },
    /// The envelope version is not supported by this build.
    #[error("unsupported FPRB version {actual}; this build decodes version {VERSION}")]
    UnsupportedVersion {
        /// Version observed.
        actual: u16,
    },
    /// The fixed header length is wrong; a layout change needs a version bump.
    #[error("header_len is {actual}; version {VERSION} requires {HEADER_LEN}")]
    BadHeaderLen {
        /// Header length observed.
        actual: u32,
    },
    /// Reserved flags were not zero.
    #[error("flags is {actual}; version {VERSION} reserves flags and requires 0")]
    Flags {
        /// Flags observed.
        actual: u32,
    },
    /// The payload exceeds the SDK maximum.
    #[error("payload_len {actual} exceeds the {PAYLOAD_MAX}-byte SDK payload maximum")]
    PayloadTooLarge {
        /// Payload length observed.
        actual: u32,
    },
    /// `record_len` disagrees with `header_len + payload_len`.
    #[error("record_len {record_len} does not equal header_len + payload_len ({expected})")]
    RecordLenMismatch {
        /// Required record length.
        expected: u32,
        /// Record length carried in the header.
        record_len: u32,
    },
    /// `record_len` disagrees with the bytes the kernel ring buffer delivered.
    #[error("record_len {record_len} does not match the {actual}-byte ring-buffer record")]
    RecordLenBuffer {
        /// Record length carried in the header.
        record_len: u32,
        /// Bytes delivered by the ring buffer.
        actual: usize,
    },
}

/// Decode one SDK event record.
///
/// Returns [`DecodeError`] for a record that does not satisfy the version 1
/// envelope: wrong magic, unsupported version, non-zero reserved flags, a
/// payload over [`PAYLOAD_MAX`], or a length that disagrees with the header or
/// the delivered bytes.
pub fn decode_record(record: &[u8]) -> Result<ProbeEvent, DecodeError> {
    if record.len() < HEADER_LEN {
        return Err(DecodeError::TooShort {
            actual: record.len(),
        });
    }

    let magic = read_u32(record, 0);
    if magic != MAGIC {
        return Err(DecodeError::BadMagic { actual: magic });
    }
    let version = read_u16(record, 4);
    if version != VERSION {
        return Err(DecodeError::UnsupportedVersion { actual: version });
    }
    let kind = read_u16(record, 6);
    let header_len = read_u32(record, 8);
    if header_len as usize != HEADER_LEN {
        return Err(DecodeError::BadHeaderLen { actual: header_len });
    }
    let record_len = read_u32(record, 12);
    let flags = read_u32(record, 16);
    if flags != 0 {
        return Err(DecodeError::Flags { actual: flags });
    }
    let payload_len = read_u32(record, 20);
    if payload_len as usize > PAYLOAD_MAX {
        return Err(DecodeError::PayloadTooLarge {
            actual: payload_len,
        });
    }
    let expected = header_len.saturating_add(payload_len);
    if record_len != expected {
        return Err(DecodeError::RecordLenMismatch {
            expected,
            record_len,
        });
    }
    if record.len() != record_len as usize {
        return Err(DecodeError::RecordLenBuffer {
            record_len,
            actual: record.len(),
        });
    }

    let pid_tgid = read_u64(record, 32);
    Ok(ProbeEvent {
        version,
        kind,
        flags,
        ts_ns: read_u64(record, 24),
        pid: pid_tgid as u32,
        tgid: (pid_tgid >> 32) as u32,
        cgroup_id: read_u64(record, 40),
        payload: record[HEADER_LEN..].to_vec(),
    })
}

/// Why a payload does not match the kind's declared fixed layout.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PayloadError {
    /// The payload is shorter than the declared fields.
    #[error(
        "payload for kind {kind} (`{name}`) is {actual} bytes but the manifest layout needs \
         {needed}"
    )]
    Short {
        /// Event kind.
        kind: u16,
        /// Declared kind name.
        name: String,
        /// Bytes the declared fields need.
        needed: usize,
        /// Payload bytes received.
        actual: usize,
    },
}

/// Decode a payload into JSON using a kind's declared fixed layout.
///
/// A kind without a layout produces `{"hex": "..."}` with the whole payload.
/// Declared fields are decoded in declaration order; trailing bytes the layout
/// does not cover are preserved as an `_extra_hex` string so no captured byte
/// is silently dropped. `string` fields are trimmed at the first NUL and
/// decoded lossily as UTF-8; `bytes` fields become lowercase hex strings.
pub fn decode_payload(kind: &EventKind, payload: &[u8]) -> Result<Value, PayloadError> {
    if kind.fields.is_empty() {
        return Ok(serde_json::json!({ "hex": hex(payload) }));
    }

    let needed = kind.layout_len();
    if payload.len() < needed {
        return Err(PayloadError::Short {
            kind: kind.kind,
            name: kind.name.clone(),
            needed,
            actual: payload.len(),
        });
    }

    let mut output = Map::new();
    let mut offset = 0usize;
    for field in &kind.fields {
        let size = field.size_bytes();
        let end = offset.saturating_add(size);
        let bytes = payload.get(offset..end).unwrap_or_default();
        output.insert(field.name.clone(), decode_field(field, bytes));
        offset = end;
    }
    if let Some(extra) = payload.get(offset..).filter(|extra| !extra.is_empty()) {
        output.insert("_extra_hex".to_string(), Value::String(hex(extra)));
    }
    Ok(Value::Object(output))
}

fn decode_field(field: &FieldSpec, bytes: &[u8]) -> Value {
    match field.field_type {
        FieldType::U8 => Value::from(bytes.first().copied().unwrap_or_default()),
        FieldType::U16 => Value::from(read_u16_at(bytes)),
        FieldType::U32 => Value::from(read_u32_at(bytes)),
        FieldType::U64 => Value::from(read_u64_at(bytes)),
        FieldType::I8 => Value::from(bytes.first().copied().unwrap_or_default() as i8),
        FieldType::I16 => Value::from(read_u16_at(bytes) as i16),
        FieldType::I32 => Value::from(read_u32_at(bytes) as i32),
        FieldType::I64 => Value::from(read_u64_at(bytes) as i64),
        FieldType::String => {
            let text = bytes.split(|byte| *byte == 0).next().unwrap_or_default();
            Value::String(String::from_utf8_lossy(text).into_owned())
        }
        FieldType::Bytes => Value::String(hex(bytes)),
    }
}

/// Lowercase hex encoding used by payload and raw-record columns.
pub fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        output.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    output
}

fn read_u16(record: &[u8], offset: usize) -> u16 {
    let mut bytes = [0u8; 2];
    bytes.copy_from_slice(&record[offset..offset + 2]);
    u16::from_ne_bytes(bytes)
}

fn read_u32(record: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&record[offset..offset + 4]);
    u32::from_ne_bytes(bytes)
}

fn read_u64(record: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&record[offset..offset + 8]);
    u64::from_ne_bytes(bytes)
}

fn read_u16_at(bytes: &[u8]) -> u16 {
    let mut value = [0u8; 2];
    value.copy_from_slice(bytes.get(..2).unwrap_or(&[0u8; 2]));
    u16::from_ne_bytes(value)
}

fn read_u32_at(bytes: &[u8]) -> u32 {
    let mut value = [0u8; 4];
    value.copy_from_slice(bytes.get(..4).unwrap_or(&[0u8; 4]));
    u32::from_ne_bytes(value)
}

fn read_u64_at(bytes: &[u8]) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(bytes.get(..8).unwrap_or(&[0u8; 8]));
    u64::from_ne_bytes(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::ProbeManifest;

    fn record(kind: u16, ts_ns: u64, pid_tgid: u64, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_LEN + payload.len());
        bytes.extend_from_slice(&MAGIC.to_ne_bytes());
        bytes.extend_from_slice(&VERSION.to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&(HEADER_LEN as u32).to_ne_bytes());
        bytes.extend_from_slice(&((HEADER_LEN + payload.len()) as u32).to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        bytes.extend_from_slice(&(payload.len() as u32).to_ne_bytes());
        bytes.extend_from_slice(&ts_ns.to_ne_bytes());
        bytes.extend_from_slice(&pid_tgid.to_ne_bytes());
        bytes.extend_from_slice(&0xabcdu64.to_ne_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    fn hello_manifest() -> ProbeManifest {
        ProbeManifest::from_yaml(
            r#"
version: 1
name: hello
object: hello_probe.bpf.o
section: tracepoint/sched/sched_process_exec
attach: tracepoint
ringbuf: hello_events
events:
  kinds:
    - kind: 1
      name: exec
      fields:
        - { name: comm, type: string, size: 16 }
        - { name: task_start_ns, type: u64 }
"#,
        )
        .expect("fixture manifest")
    }

    #[test]
    fn decodes_the_fixed_header() {
        let event = decode_record(&record(7, 42, (9u64 << 32) | 3, b"abc")).expect("valid record");
        assert_eq!(event.version, 1);
        assert_eq!(event.kind, 7);
        assert_eq!(event.ts_ns, 42);
        assert_eq!(event.pid, 3);
        assert_eq!(event.tgid, 9);
        assert_eq!(event.cgroup_id, 0xabcd);
        assert_eq!(event.payload, b"abc");
    }

    #[test]
    fn decodes_an_empty_payload() {
        let event = decode_record(&record(1, 1, 0, &[])).expect("valid record");
        assert!(event.payload.is_empty());
    }

    #[test]
    fn rejects_records_that_violate_the_envelope() {
        let base = record(1, 1, 0, b"x");

        let mut short = base.clone();
        short.truncate(HEADER_LEN - 1);
        assert_eq!(
            decode_record(&short),
            Err(DecodeError::TooShort {
                actual: HEADER_LEN - 1
            })
        );

        let mut bad_magic = base.clone();
        bad_magic[0] = b'X';
        assert!(matches!(
            decode_record(&bad_magic),
            Err(DecodeError::BadMagic { .. })
        ));

        let mut version_2 = base.clone();
        version_2[4..6].copy_from_slice(&2u16.to_ne_bytes());
        assert_eq!(
            decode_record(&version_2),
            Err(DecodeError::UnsupportedVersion { actual: 2 })
        );

        let mut bad_header = base.clone();
        bad_header[8..12].copy_from_slice(&40u32.to_ne_bytes());
        assert_eq!(
            decode_record(&bad_header),
            Err(DecodeError::BadHeaderLen { actual: 40 })
        );

        let mut flags = base.clone();
        flags[16..20].copy_from_slice(&1u32.to_ne_bytes());
        assert_eq!(decode_record(&flags), Err(DecodeError::Flags { actual: 1 }));

        let mut too_large = base.clone();
        too_large[20..24].copy_from_slice(&(PAYLOAD_MAX as u32 + 1).to_ne_bytes());
        assert_eq!(
            decode_record(&too_large),
            Err(DecodeError::PayloadTooLarge {
                actual: PAYLOAD_MAX as u32 + 1
            })
        );

        let mut length_mismatch = base.clone();
        length_mismatch[12..16].copy_from_slice(&(HEADER_LEN as u32 + 2).to_ne_bytes());
        assert!(matches!(
            decode_record(&length_mismatch),
            Err(DecodeError::RecordLenMismatch { .. })
        ));

        let mut buffer_mismatch = base.clone();
        buffer_mismatch.push(0);
        assert_eq!(
            decode_record(&buffer_mismatch),
            Err(DecodeError::RecordLenBuffer {
                record_len: HEADER_LEN as u32 + 1,
                actual: HEADER_LEN + 2
            })
        );
    }

    #[test]
    fn decodes_a_declared_payload_layout() {
        let manifest = hello_manifest();
        let kind = manifest.kind(1).expect("declared kind");
        let mut payload = Vec::new();
        payload.extend_from_slice(b"bash\0\0\0\0\0\0\0\0\0\0\0\0");
        payload.extend_from_slice(&123_456u64.to_ne_bytes());
        let json = decode_payload(kind, &payload).expect("payload decodes");
        assert_eq!(json["comm"], "bash");
        assert_eq!(json["task_start_ns"], 123_456u64);
        assert!(json.get("_extra_hex").is_none());
    }

    #[test]
    fn payload_short_of_the_layout_is_an_error() {
        let manifest = hello_manifest();
        let kind = manifest.kind(1).expect("declared kind");
        let error = decode_payload(kind, b"short").expect_err("must fail");
        assert_eq!(
            error,
            PayloadError::Short {
                kind: 1,
                name: "exec".to_string(),
                needed: 24,
                actual: 5,
            }
        );
    }

    #[test]
    fn trailing_payload_bytes_are_preserved() {
        let manifest = hello_manifest();
        let kind = manifest.kind(1).expect("declared kind");
        let mut payload = vec![0u8; 24];
        payload.extend_from_slice(b"extra");
        let json = decode_payload(kind, &payload).expect("payload decodes");
        assert_eq!(json["_extra_hex"], hex(b"extra"));
    }

    #[test]
    fn kind_without_a_layout_uses_hex() {
        let manifest = ProbeManifest::from_yaml(
            r#"
version: 1
name: opaque
object: opaque.bpf.o
section: kprobe/do_sys_open
attach: kprobe
ringbuf: opaque_events
events:
  kinds:
    - kind: 2
      name: opaque
"#,
        )
        .expect("fixture manifest");
        let kind = manifest.kind(2).expect("declared kind");
        let json = decode_payload(kind, &[0xde, 0xad, 0xbe, 0xef]).expect("payload decodes");
        assert_eq!(json["hex"], "deadbeef");
    }

    #[test]
    fn integer_and_byte_fields_decode() {
        let manifest = ProbeManifest::from_yaml(
            r#"
version: 1
name: integers
object: integers.bpf.o
section: kprobe/do_sys_open
attach: kprobe
ringbuf: integers_events
events:
  kinds:
    - kind: 3
      name: integers
      fields:
        - { name: u8, type: u8 }
        - { name: i16, type: i16 }
        - { name: u32, type: u32 }
        - { name: i64, type: i64 }
        - { name: blob, type: bytes, size: 2 }
"#,
        )
        .expect("fixture manifest");
        let kind = manifest.kind(3).expect("declared kind");
        let mut payload = Vec::new();
        payload.push(255);
        payload.extend_from_slice(&(-2i16).to_ne_bytes());
        payload.extend_from_slice(&7u32.to_ne_bytes());
        payload.extend_from_slice(&(-9i64).to_ne_bytes());
        payload.extend_from_slice(&[0x00, 0xff]);
        let json = decode_payload(kind, &payload).expect("payload decodes");
        assert_eq!(json["u8"], 255);
        assert_eq!(json["i16"], -2);
        assert_eq!(json["u32"], 7);
        assert_eq!(json["i64"], -9);
        assert_eq!(json["blob"], "00ff");
    }

    #[test]
    fn lossy_strings_and_nul_trimming_are_documented_behavior() {
        let manifest = ProbeManifest::from_yaml(
            r#"
version: 1
name: strings
object: strings.bpf.o
section: kprobe/do_sys_open
attach: kprobe
ringbuf: strings_events
events:
  kinds:
    - kind: 4
      name: strings
      fields:
        - { name: text, type: string, size: 8 }
"#,
        )
        .expect("fixture manifest");
        let kind = manifest.kind(4).expect("declared kind");
        let payload = [b'o', b'k', 0, b'x', 0, 0, 0, 0xff];
        let json = decode_payload(kind, &payload).expect("payload decodes");
        assert_eq!(json["text"], "ok");
    }

    #[test]
    fn hex_encoding_is_lowercase() {
        assert_eq!(hex(&[0x00, 0x0f, 0xab, 0xff]), "000fabff");
        assert_eq!(hex(&[]), "");
    }
}
