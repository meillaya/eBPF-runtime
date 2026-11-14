// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The probe manifest: the declarative contract between a compiled probe
//! object and the runtime that loads it.
//!
//! A manifest is one YAML document (version 1) that names the object, pins
//! its SHA-256 when the operator has one, states which ELF section to attach,
//! declares the ring-buffer map the probe emits on, and describes the event
//! kinds and payload layout the decoder should use. It is data only: loading
//! is always an explicit, root-only `fleet probe run` action, and the manifest
//! never names a helper, a command, or a path outside the object file.
//!
//! ```yaml
//! version: 1
//! name: hello
//! object: target/probe-sdk/hello_probe.bpf.o
//! sha256: "…64 lowercase hex…"
//! section: tracepoint/sched/sched_process_exec
//! attach: tracepoint
//! ringbuf: hello_events
//! events:
//!   envelope: fprb
//!   version: 1
//!   kinds:
//!     - kind: 1
//!       name: exec
//!       fields:
//!         - { name: comm, type: string, size: 16 }
//!         - { name: task_start_ns, type: u64 }
//! ```
//!
//! Every value is validated before any object is opened: unknown fields,
//! unknown versions, unknown attach types, a section that does not match the
//! declared attach type, oversized payload layouts, and malformed SHA-256
//! pins are rejected with an error that says what to change.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Manifest schema version this build accepts.
pub const MANIFEST_VERSION: u32 = 1;
/// Event envelope name this build decodes.
pub const ENVELOPE: &str = "fprb";
/// Event envelope version this build decodes.
pub const ENVELOPE_VERSION: u16 = 1;
/// Largest payload the FPRB envelope allows (`FLEET_PROBE_PAYLOAD_MAX`).
pub const PAYLOAD_MAX: usize = 256;
/// Largest map name a BPF object can carry (kernel `BPF_OBJ_NAME_LEN - 1`).
pub const MAP_NAME_MAX: usize = 15;

/// A validated probe manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeManifest {
    /// Manifest schema version; must be [`MANIFEST_VERSION`].
    pub version: u32,
    /// Probe name used as the `probe` column and in run reports.
    pub name: String,
    /// Optional human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Compiled CO-RE object. Relative paths are resolved against the
    /// manifest's directory.
    pub object: PathBuf,
    /// Optional SHA-256 pin of the object bytes. `fleet probe run` refuses
    /// to load a manifest without one unless `--allow-unpinned` is passed.
    #[serde(default)]
    pub sha256: Option<String>,
    /// ELF section of the program to attach.
    pub section: String,
    /// Attach type; must match the `section` prefix.
    pub attach: AttachType,
    /// Name of the BPF ring-buffer map the probe emits on.
    pub ringbuf: String,
    /// Optional informational kernel range, for example `>=5.8`.
    #[serde(default)]
    pub supported_kernel: Option<String>,
    /// Event envelope and decoded event kinds.
    pub events: Events,
}

/// Program attach types the runtime will attach by section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachType {
    /// `tracepoint/<group>/<name>`.
    Tracepoint,
    /// `raw_tracepoint/<name>`.
    RawTracepoint,
    /// `kprobe/<symbol>`.
    Kprobe,
    /// `kretprobe/<symbol>`.
    Kretprobe,
    /// `fentry/<symbol>`.
    Fentry,
    /// `fexit/<symbol>`.
    Fexit,
    /// `lsm/<hook>`.
    Lsm,
    /// `uprobe/<path>:<symbol>`.
    Uprobe,
    /// `uretprobe/<path>:<symbol>`.
    Uretprobe,
}

impl AttachType {
    /// ELF section prefix that must start the manifest's `section`.
    pub fn section_prefix(self) -> &'static str {
        match self {
            Self::Tracepoint => "tracepoint/",
            Self::RawTracepoint => "raw_tracepoint/",
            Self::Kprobe => "kprobe/",
            Self::Kretprobe => "kretprobe/",
            Self::Fentry => "fentry/",
            Self::Fexit => "fexit/",
            Self::Lsm => "lsm/",
            Self::Uprobe => "uprobe/",
            Self::Uretprobe => "uretprobe/",
        }
    }

    /// Stable lowercase name used in reports and docs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tracepoint => "tracepoint",
            Self::RawTracepoint => "raw_tracepoint",
            Self::Kprobe => "kprobe",
            Self::Kretprobe => "kretprobe",
            Self::Fentry => "fentry",
            Self::Fexit => "fexit",
            Self::Lsm => "lsm",
            Self::Uprobe => "uprobe",
            Self::Uretprobe => "uretprobe",
        }
    }
}

/// Event-envelope declaration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Events {
    /// Envelope name; must be [`ENVELOPE`].
    #[serde(default = "default_envelope")]
    pub envelope: String,
    /// Envelope version; must be [`ENVELOPE_VERSION`].
    #[serde(default = "default_envelope_version")]
    pub version: u16,
    /// One or more probe-defined event kinds.
    pub kinds: Vec<EventKind>,
}

impl Default for Events {
    fn default() -> Self {
        Self {
            envelope: default_envelope(),
            version: default_envelope_version(),
            kinds: Vec::new(),
        }
    }
}

fn default_envelope() -> String {
    ENVELOPE.to_string()
}

fn default_envelope_version() -> u16 {
    ENVELOPE_VERSION
}

/// One probe-defined event kind plus its optional fixed payload layout.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventKind {
    /// Wire `kind` value (the `FPRB` header `kind` field).
    pub kind: u16,
    /// Name used in reports and the `kind_name` bundle column.
    pub name: String,
    /// Optional fixed payload layout. When empty the decoder emits the
    /// payload as a hex string.
    #[serde(default)]
    pub fields: Vec<FieldSpec>,
}

impl EventKind {
    /// Total payload bytes the declared fields consume.
    pub fn layout_len(&self) -> usize {
        self.fields.iter().map(FieldSpec::size_bytes).sum()
    }
}

/// One field of a fixed payload layout, decoded in declaration order.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldSpec {
    /// JSON key emitted by the decoder.
    pub name: String,
    /// Integer, string, or opaque bytes.
    #[serde(rename = "type")]
    pub field_type: FieldType,
    /// Explicit size in bytes for `string` and `bytes` fields.
    #[serde(default)]
    pub size: Option<usize>,
}

impl FieldSpec {
    /// Bytes this field consumes in the payload.
    pub fn size_bytes(&self) -> usize {
        self.field_type
            .fixed_size()
            .or(self.size)
            .unwrap_or_default()
    }
}

/// Payload field types the decoder understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    /// Unsigned 8-bit.
    U8,
    /// Unsigned 16-bit.
    U16,
    /// Unsigned 32-bit.
    U32,
    /// Unsigned 64-bit.
    U64,
    /// Signed 8-bit.
    I8,
    /// Signed 16-bit.
    I16,
    /// Signed 32-bit.
    I32,
    /// Signed 64-bit.
    I64,
    /// NUL-padded byte string; decoded lossily as UTF-8.
    String,
    /// Opaque bytes; decoded as a lowercase hex string.
    Bytes,
}

impl FieldType {
    /// Fixed size for integer types; `None` for `string` and `bytes`.
    pub fn fixed_size(self) -> Option<usize> {
        match self {
            Self::U8 | Self::I8 => Some(1),
            Self::U16 | Self::I16 => Some(2),
            Self::U32 | Self::I32 => Some(4),
            Self::U64 | Self::I64 => Some(8),
            Self::String | Self::Bytes => None,
        }
    }

    /// Stable lowercase name used in error messages.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::I8 => "i8",
            Self::I16 => "i16",
            Self::I32 => "i32",
            Self::I64 => "i64",
            Self::String => "string",
            Self::Bytes => "bytes",
        }
    }
}

/// Errors from reading, parsing, or validating a manifest, and from checking
/// the object pin.
#[derive(Debug, Error)]
pub enum ManifestError {
    /// The manifest file could not be read.
    #[error("cannot read probe manifest {path}: {source}")]
    Read {
        /// Manifest path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The YAML could not be deserialized into the manifest v1 shape.
    #[error("invalid probe manifest YAML: {0}")]
    Yaml(String),
    /// The manifest parsed but a value is unsafe, unknown, or inconsistent.
    #[error("invalid probe manifest: {0}")]
    Invalid(String),
    /// The object named by the manifest could not be read for hashing.
    #[error("cannot read probe object {path}: {source}")]
    ObjectRead {
        /// Object path that failed.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The object bytes do not match the manifest's SHA-256 pin.
    #[error(
        "probe object hash mismatch for {path}: manifest pins {expected}, object is {actual}; \
         rebuild the object or update the pin with `sha256sum {path}`"
    )]
    HashMismatch {
        /// Object path checked.
        path: PathBuf,
        /// Pinned digest from the manifest.
        expected: String,
        /// Digest of the object on disk.
        actual: String,
    },
}

impl ProbeManifest {
    /// Read and validate a manifest from `path`.
    pub fn load(path: &Path) -> Result<Self, ManifestError> {
        let text = fs::read_to_string(path).map_err(|source| ManifestError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let manifest: Self = serde_yaml::from_str(&text)
            .map_err(|error| ManifestError::Yaml(format!("{}: {error}", path.display())))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Parse and validate a manifest from YAML text.
    pub fn from_yaml(text: &str) -> Result<Self, ManifestError> {
        let manifest: Self =
            serde_yaml::from_str(text).map_err(|error| ManifestError::Yaml(error.to_string()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validate every value that is not already enforced by the YAML shape.
    ///
    /// [`load`][Self::load] and [`from_yaml`][Self::from_yaml] call this; a
    /// manifest built by hand should call it before use.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.version != MANIFEST_VERSION {
            return Err(invalid(format!(
                "unsupported manifest version {}: this build supports version {MANIFEST_VERSION}",
                self.version
            )));
        }
        if !is_identifier(&self.name, 64) {
            return Err(invalid(format!(
                "invalid probe name `{}`: use 1-64 characters from a-z, 0-9, `_` and `-`, \
                 starting with a lowercase letter or digit",
                self.name
            )));
        }
        if let Some(description) = &self.description {
            if description.trim().is_empty() {
                return Err(invalid(
                    "description must not be empty when present; remove the field or write text",
                ));
            }
        }
        if let Some(kernel) = &self.supported_kernel {
            if kernel.trim().is_empty() {
                return Err(invalid(
                    "supported_kernel must not be empty when present; remove the field or write \
                     the kernel range this probe expects",
                ));
            }
        }
        self.validate_object_path()?;
        self.validate_sha256()?;
        self.validate_section()?;
        self.validate_ringbuf()?;
        self.validate_events()?;
        Ok(())
    }

    fn validate_object_path(&self) -> Result<(), ManifestError> {
        if self.object.as_os_str().is_empty() {
            return Err(invalid(
                "object must name the compiled probe object, for example \
                 target/probe-sdk/hello_probe.bpf.o",
            ));
        }
        // Normal relative traversal (`../..`) is allowed: the manifest is
        // operator-supplied, root-only data that names an object explicitly,
        // so this is not a trust boundary. The checked-in example manifest
        // lives in sdk/examples and points at target/probe-sdk.
        Ok(())
    }

    fn validate_sha256(&self) -> Result<(), ManifestError> {
        if let Some(pin) = &self.sha256 {
            if pin.len() != 64
                || !pin
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(invalid(format!(
                    "sha256 must be exactly 64 lowercase hex characters, got `{pin}`; \
                     compute it with `sha256sum {}`",
                    self.object.display()
                )));
            }
        }
        Ok(())
    }

    fn validate_section(&self) -> Result<(), ManifestError> {
        if self.section.trim().is_empty() {
            return Err(invalid(
                "section must name the ELF section of the program to attach, for example \
                 tracepoint/sched/sched_process_exec",
            ));
        }
        if self.section.chars().any(char::is_whitespace) {
            return Err(invalid(format!(
                "section `{}` must not contain whitespace; it is the ELF section name",
                self.section
            )));
        }
        let prefix = self.attach.section_prefix();
        if !self.section.starts_with(prefix) || self.section.len() == prefix.len() {
            return Err(invalid(format!(
                "section `{}` does not match attach type `{}`: sections of this type start with \
                 `{prefix}` and name the target after it",
                self.section,
                self.attach.as_str()
            )));
        }
        Ok(())
    }

    fn validate_ringbuf(&self) -> Result<(), ManifestError> {
        let valid = !self.ringbuf.is_empty()
            && self.ringbuf.len() <= MAP_NAME_MAX
            && self
                .ringbuf
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        if !valid {
            return Err(invalid(format!(
                "ringbuf `{}` is not a BPF map name: use 1-{MAP_NAME_MAX} characters from \
                 [A-Za-z0-9_]; name the ring buffer map `<probe>_events` in the C source",
                self.ringbuf
            )));
        }
        Ok(())
    }

    fn validate_events(&self) -> Result<(), ManifestError> {
        if self.events.envelope != ENVELOPE {
            return Err(invalid(format!(
                "unsupported event envelope `{}`: the probe SDK defines `{ENVELOPE}`",
                self.events.envelope
            )));
        }
        if self.events.version != ENVELOPE_VERSION {
            return Err(invalid(format!(
                "unsupported event envelope version {}: the probe SDK defines version \
                 {ENVELOPE_VERSION}",
                self.events.version
            )));
        }
        if self.events.kinds.is_empty() {
            return Err(invalid(
                "events.kinds must declare at least one probe-defined event kind",
            ));
        }

        let mut kinds = std::collections::BTreeSet::new();
        let mut names = std::collections::BTreeSet::new();
        for kind in &self.events.kinds {
            if !kinds.insert(kind.kind) {
                return Err(invalid(format!(
                    "duplicate event kind {} in events.kinds",
                    kind.kind
                )));
            }
            if !is_identifier(&kind.name, 64) {
                return Err(invalid(format!(
                    "invalid event kind name `{}`: use 1-64 characters from a-z, 0-9, `_` and \
                     `-`, starting with a lowercase letter or digit",
                    kind.name
                )));
            }
            if !names.insert(kind.name.clone()) {
                return Err(invalid(format!(
                    "duplicate event kind name `{}` in events.kinds",
                    kind.name
                )));
            }
            validate_fields(kind)?;
        }
        Ok(())
    }

    /// Resolve the object path: relative paths are resolved against the
    /// manifest's directory, absolute paths are used as-is.
    pub fn resolve_object(&self, manifest_path: &Path) -> PathBuf {
        if self.object.is_absolute() {
            return self.object.clone();
        }
        let directory = manifest_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        directory.join(&self.object)
    }

    /// SHA-256 of the object bytes, after checking any manifest pin.
    ///
    /// Returns the digest of the object on disk. With a pin present and a
    /// mismatch this is [`ManifestError::HashMismatch`]; without a pin the
    /// caller decides whether unpinned loading is allowed.
    pub fn verify_object_sha256(&self, object: &Path) -> Result<String, ManifestError> {
        let bytes = fs::read(object).map_err(|source| ManifestError::ObjectRead {
            path: object.to_path_buf(),
            source,
        })?;
        let actual = sha256_hex(&bytes);
        if let Some(expected) = &self.sha256 {
            if expected != &actual {
                return Err(ManifestError::HashMismatch {
                    path: object.to_path_buf(),
                    expected: expected.clone(),
                    actual,
                });
            }
        }
        Ok(actual)
    }

    /// True when the manifest pins the object bytes.
    pub fn pinned(&self) -> bool {
        self.sha256.is_some()
    }

    /// Look up a declared event kind.
    pub fn kind(&self, kind: u16) -> Option<&EventKind> {
        self.events
            .kinds
            .iter()
            .find(|declared| declared.kind == kind)
    }
}

fn validate_fields(kind: &EventKind) -> Result<(), ManifestError> {
    let mut names = std::collections::BTreeSet::new();
    for field in &kind.fields {
        if !is_identifier(&field.name, 64) {
            return Err(invalid(format!(
                "event kind `{}`: invalid field name `{}`: use 1-64 characters from a-z, 0-9, \
                 `_` and `-`, starting with a lowercase letter or digit",
                kind.name, field.name
            )));
        }
        if !names.insert(field.name.clone()) {
            return Err(invalid(format!(
                "event kind `{}`: duplicate field name `{}`",
                kind.name, field.name
            )));
        }
        match field.field_type.fixed_size() {
            Some(fixed) => {
                if let Some(size) = field.size {
                    if size != fixed {
                        return Err(invalid(format!(
                            "event kind `{}`: field `{}` type `{}` is {fixed} bytes, but size \
                             {size} was declared; remove size or use {fixed}",
                            kind.name,
                            field.name,
                            field.field_type.as_str()
                        )));
                    }
                }
            }
            None => match field.size {
                None => {
                    return Err(invalid(format!(
                        "event kind `{}`: field `{}` of type `{}` needs an explicit size in \
                         bytes (1-{PAYLOAD_MAX})",
                        kind.name,
                        field.name,
                        field.field_type.as_str()
                    )))
                }
                Some(0) => {
                    return Err(invalid(format!(
                        "event kind `{}`: field `{}` size must be at least 1 byte",
                        kind.name, field.name
                    )))
                }
                Some(size) if size > PAYLOAD_MAX => {
                    return Err(invalid(format!(
                        "event kind `{}`: field `{}` size {size} exceeds the {PAYLOAD_MAX}-byte \
                         envelope payload maximum",
                        kind.name, field.name
                    )))
                }
                Some(_) => {}
            },
        }
    }
    let layout = kind.layout_len();
    if layout > PAYLOAD_MAX {
        return Err(invalid(format!(
            "event kind `{}` (`{}`): payload layout is {layout} bytes, but the FPRB envelope \
             allows at most {PAYLOAD_MAX}",
            kind.kind, kind.name
        )));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> ManifestError {
    ManifestError::Invalid(message.into())
}

fn is_identifier(value: &str, max_len: usize) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= max_len
        && (first.is_ascii_lowercase() || first.is_ascii_digit())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
version: 1
name: hello
object: hello_probe.bpf.o
sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
section: tracepoint/sched/sched_process_exec
attach: tracepoint
ringbuf: hello_events
supported_kernel: ">=5.8"
events:
  envelope: fprb
  version: 1
  kinds:
    - kind: 1
      name: exec
      fields:
        - { name: comm, type: string, size: 16 }
        - { name: task_start_ns, type: u64 }
"#;

    fn valid() -> ProbeManifest {
        ProbeManifest::from_yaml(VALID).expect("fixture must be valid")
    }

    #[test]
    fn parses_a_valid_manifest() {
        let manifest = valid();
        assert_eq!(manifest.version, 1);
        assert_eq!(manifest.name, "hello");
        assert_eq!(manifest.attach, AttachType::Tracepoint);
        assert_eq!(manifest.ringbuf, "hello_events");
        assert!(manifest.pinned());
        assert_eq!(
            manifest.kind(1).map(|kind| kind.name.as_str()),
            Some("exec")
        );
        assert_eq!(manifest.events.kinds[0].layout_len(), 24);
        assert_eq!(manifest.kind(2), None);
    }

    #[test]
    fn optional_fields_may_be_omitted() {
        let text = r#"
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
"#;
        let manifest = ProbeManifest::from_yaml(text).expect("defaults must apply");
        assert!(!manifest.pinned());
        assert_eq!(manifest.events.envelope, ENVELOPE);
        assert_eq!(manifest.events.version, ENVELOPE_VERSION);
        assert!(manifest.events.kinds[0].fields.is_empty());
        assert_eq!(manifest.description, None);
        assert_eq!(manifest.supported_kernel, None);
    }

    fn replace_top_level_field(text: &str, field: &str, replacement: &str) -> String {
        let mut lines: Vec<&str> = text
            .lines()
            .filter(|line| !line.starts_with(&format!("{field}:")))
            .collect();
        lines.push(replacement);
        lines.join("\n")
    }

    #[test]
    fn unknown_and_unsafe_values_are_rejected() {
        let cases = [
            ("version", "version: 2", "unsupported manifest version 2"),
            ("name", "name: Bad Name", "invalid probe name"),
            ("name", "name: \"\"", "invalid probe name"),
            (
                "object",
                "object: \"\"",
                "object must name the compiled probe object",
            ),
            (
                "sha256",
                "sha256: deadbeef",
                "sha256 must be exactly 64 lowercase hex characters",
            ),
            (
                "supported_kernel",
                "supported_kernel: \"\"",
                "supported_kernel must not be empty",
            ),
            (
                "description",
                "description: \"\"",
                "description must not be empty",
            ),
        ];
        for (field, replacement, expected) in cases {
            let text = replace_top_level_field(VALID, field, replacement);
            let error = ProbeManifest::from_yaml(&text).expect_err("must be rejected");
            assert!(
                error.to_string().contains(expected),
                "expected `{expected}` in error for `{replacement}`: {error}"
            );
        }
    }

    #[test]
    fn section_must_match_the_attach_type() {
        let text = VALID.replace(
            "section: tracepoint/sched/sched_process_exec",
            "section: kprobe/do_sys_open",
        );
        let error = ProbeManifest::from_yaml(&text).expect_err("must be rejected");
        assert!(
            error
                .to_string()
                .contains("does not match attach type `tracepoint`"),
            "{error}"
        );

        let unknown = VALID.replace("attach: tracepoint", "attach: teleport");
        let error = ProbeManifest::from_yaml(&unknown).expect_err("must be rejected");
        assert!(error.to_string().contains("unknown variant"), "{error}");
    }

    #[test]
    fn unknown_manifest_fields_are_rejected() {
        let mut text = VALID.to_string();
        text.push_str("auto_load: true\n");
        let error = ProbeManifest::from_yaml(&text).expect_err("must be rejected");
        assert!(error.to_string().contains("unknown field"), "{error}");
    }

    #[test]
    fn ring_buffer_map_names_are_validated() {
        for name in ["", "hello-events", "hello events", "this_name_is_too_long"] {
            let text = VALID.replace("ringbuf: hello_events", &format!("ringbuf: \"{name}\""));
            let error = ProbeManifest::from_yaml(&text).expect_err("must be rejected");
            assert!(error.to_string().contains("ringbuf"), "{error}");
        }
        let text = VALID.replace("ringbuf: hello_events", "ringbuf: a");
        assert!(ProbeManifest::from_yaml(&text).is_ok());
    }

    #[test]
    fn envelope_and_kinds_are_validated() {
        let text = VALID.replace("envelope: fprb", "envelope: pcap");
        assert!(ProbeManifest::from_yaml(&text)
            .expect_err("must be rejected")
            .to_string()
            .contains("unsupported event envelope"));

        let text = VALID.replace(
            "envelope: fprb\n  version: 1",
            "envelope: fprb\n  version: 9",
        );
        assert!(ProbeManifest::from_yaml(&text)
            .expect_err("must be rejected")
            .to_string()
            .contains("unsupported event envelope version"));

        let duplicate = VALID.replace(
            "    - kind: 1\n      name: exec",
            "    - kind: 1\n      name: exec\n    - kind: 1\n      name: exec2",
        );
        assert!(ProbeManifest::from_yaml(&duplicate)
            .expect_err("must be rejected")
            .to_string()
            .contains("duplicate event kind 1"));
    }

    #[test]
    fn payload_layouts_are_validated() {
        let oversized = VALID.replace(
            "        - { name: comm, type: string, size: 16 }\n        - { name: task_start_ns, type: u64 }",
            "        - { name: blob, type: bytes, size: 200 }\n        - { name: blob2, type: bytes, size: 200 }",
        );
        assert!(ProbeManifest::from_yaml(&oversized)
            .expect_err("must be rejected")
            .to_string()
            .contains("payload layout is 400 bytes"));

        let missing_size = VALID.replace(
            "{ name: comm, type: string, size: 16 }",
            "{ name: comm, type: string }",
        );
        assert!(ProbeManifest::from_yaml(&missing_size)
            .expect_err("must be rejected")
            .to_string()
            .contains("needs an explicit size"));

        let mismatched = VALID.replace(
            "name: task_start_ns, type: u64",
            "name: task_start_ns, type: u64, size: 4",
        );
        assert!(ProbeManifest::from_yaml(&mismatched)
            .expect_err("must be rejected")
            .to_string()
            .contains("is 8 bytes, but size 4 was declared"));
    }

    #[test]
    fn kind_zero_is_probe_defined() {
        let text = VALID.replace("- kind: 1", "- kind: 0");
        let manifest = ProbeManifest::from_yaml(&text).expect("kind 0 is probe-defined");
        assert_eq!(manifest.events.kinds[0].kind, 0);
    }

    #[test]
    fn object_paths_resolve_against_the_manifest_directory() {
        let manifest = valid();
        assert_eq!(
            manifest.resolve_object(Path::new("sdk/examples/hello_probe.manifest.yaml")),
            Path::new("sdk/examples/hello_probe.bpf.o")
        );
        let relative = manifest.resolve_object(Path::new("manifest.yaml"));
        assert_eq!(
            relative.file_name(),
            Some(std::ffi::OsStr::new("hello_probe.bpf.o"))
        );

        // Normal relative traversal is allowed: the checked-in example lives
        // in sdk/examples and points at the build output under target/.
        let mut nested = valid();
        nested.object = PathBuf::from("../../target/probe-sdk/hello.bpf.o");
        assert!(nested
            .resolve_object(Path::new("sdk/examples/hello_probe.manifest.yaml"))
            .ends_with("target/probe-sdk/hello.bpf.o"));

        let mut absolute = valid();
        absolute.object = PathBuf::from("/tmp/hello_probe.bpf.o");
        assert_eq!(
            absolute.resolve_object(Path::new("irrelevant.yaml")),
            Path::new("/tmp/hello_probe.bpf.o")
        );
    }

    #[test]
    fn object_sha256_pins_are_verified() {
        let directory = std::env::temp_dir().join(format!(
            "probe-manifest-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default()
        ));
        fs::create_dir_all(&directory).expect("create temp dir");
        let object = directory.join("probe.bpf.o");
        fs::write(&object, b"object bytes").expect("write object");

        let manifest = valid();
        let error = manifest
            .verify_object_sha256(&object)
            .expect_err("pin must not match");
        assert!(matches!(error, ManifestError::HashMismatch { .. }));
        assert!(error.to_string().contains("manifest pins"));

        let unpinned = ProbeManifest::from_yaml(&VALID.replace(
            "sha256: \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n",
            "",
        ))
        .expect("unpinned fixture");
        assert_eq!(
            unpinned.verify_object_sha256(&object).expect("hash"),
            sha256_hex(b"object bytes")
        );

        let mut pinned = unpinned.clone();
        pinned.sha256 = Some(sha256_hex(b"object bytes"));
        assert!(pinned.verify_object_sha256(&object).is_ok());

        let missing = directory.join("missing.bpf.o");
        let error = pinned
            .verify_object_sha256(&missing)
            .expect_err("missing object");
        assert!(matches!(error, ManifestError::ObjectRead { .. }));

        fs::remove_dir_all(&directory).expect("cleanup temp dir");
    }

    #[test]
    fn the_checked_in_example_manifest_is_valid() {
        let path = crate::workspace_root().join("sdk/examples/hello_probe.manifest.yaml");
        let manifest = ProbeManifest::load(&path).expect("example manifest must validate");
        assert_eq!(manifest.name, "hello");
        assert_eq!(manifest.attach, AttachType::Tracepoint);
        assert_eq!(manifest.ringbuf, "hello_events");
        assert!(!manifest.pinned(), "the checked-in example stays unpinned");
        assert_eq!(
            manifest.kind(1).map(|kind| kind.name.as_str()),
            Some("exec")
        );
        assert_eq!(manifest.events.kinds[0].layout_len(), 24);
        assert!(manifest
            .resolve_object(&path)
            .ends_with("target/probe-sdk/hello_probe.bpf.o"));
    }

    #[test]
    fn missing_manifest_is_a_read_error() {
        let error = ProbeManifest::load(Path::new("/nonexistent/probe.manifest.yaml"))
            .expect_err("must fail");
        assert!(matches!(error, ManifestError::Read { .. }));
        assert!(error.to_string().contains("cannot read probe manifest"));
    }
}
