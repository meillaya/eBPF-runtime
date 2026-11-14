// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Build, verify, explain, and decode custom C probes for the eBPF fleet SDK.
//!
//! This crate is the tool half of the 0.3 C probe SDK. It does not compile a
//! probe DSL; it gives a developer (and the `fleet probe` CLI) the operations
//! that turn a hand-written C file into decoded events:
//!
//! - [`build`] compiles one hand-written C probe with the pinned clang 19
//!   into a relocatable CO-RE object, reusing the `vmlinux.h` and header
//!   layout that the `bpf-build` sensor pipeline produces.
//! - [`verify`] opens the object with libbpf and attempts to load it through
//!   the kernel verifier, returning the program/map names and the captured
//!   verifier log. Loading requires root or the BPF capabilities; the report
//!   distinguishes a verifier rejection from a permission failure.
//! - [`explain`] turns a verifier log into a compact, source-oriented
//!   explanation with the log-retention rule and the common causes matched.
//! - [`ProbeManifest`] is the validated YAML v1 contract for a probe: object,
//!   optional SHA-256 pin, section and attach type, ring-buffer map, and the
//!   declared event kinds and payload layout.
//! - [`decode_record`] and [`decode_payload`] turn a ring-buffer record that
//!   follows the `FPRB` envelope in `sdk/include/fleet_probe.h` into header
//!   fields and manifest-declared JSON.
//!
//! Loading and attaching an object into the kernel is the runtime's job:
//! `bpf_loader::load_object`/`LoadedObject` keep the object, programs, maps,
//! links, and ring buffers alive for `fleet probe run` (root-only, explicit
//! opt-in). This crate never auto-loads anything.
//!
//! The C side lives in `sdk/include/fleet_probe.h` with a buildable example in
//! `sdk/examples/hello_probe.bpf.c` and an example manifest in
//! `sdk/examples/hello_probe.manifest.yaml`. See `docs/probe-sdk.md` for the
//! contract and limitations.
//!
//! # Example
//!
//! Build the example probe into the probe SDK's output directory:
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let root = probe::workspace_root();
//! let source = root.join("sdk/examples/hello_probe.bpf.c");
//! let object = probe::default_out_dir().join("hello_probe.bpf.o");
//! let artifact = probe::build(&source, &object, &[])?;
//! println!("built {} ({} bytes)", artifact.object.display(), artifact.size_bytes);
//! # Ok(())
//! # }
//! ```
//!
//! Validate a manifest, check its object pin, and decode a record:
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let manifest_path = std::path::Path::new("sdk/examples/hello_probe.manifest.yaml");
//! # let record: &[u8] = &[];
//! let manifest = probe::ProbeManifest::load(manifest_path)?;
//! let object = manifest.resolve_object(manifest_path);
//! let digest = manifest.verify_object_sha256(&object)?; // enforces sha256 when pinned
//! println!("{} -> {} ({})", manifest.name, object.display(), digest);
//!
//! let event = probe::decode_record(record)?;
//! if let Some(kind) = manifest.kind(event.kind) {
//!     let payload = probe::decode_payload(kind, &event.payload)?;
//!     println!("kind {} payload {payload}", kind.kind);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Verify an object and explain a rejection (the verify call needs
//! privileges; `explain` is pure and can run anywhere):
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let object = std::path::Path::new("target/probe-sdk/hello_probe.bpf.o");
//! let report = probe::verify(object)?;
//! if let Some(explanation) = report.explanation() {
//!     println!("{}", explanation.render());
//! }
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

mod build;
mod decode;
mod explain;
mod manifest;
mod verify;

pub use crate::build::build;
pub use crate::build::default_out_dir;
pub use crate::build::workspace_root;
pub use crate::build::BuildArtifact;
pub use crate::build::BuildError;
pub use crate::decode::decode_payload;
pub use crate::decode::decode_record;
pub use crate::decode::hex;
pub use crate::decode::DecodeError;
pub use crate::decode::PayloadError;
pub use crate::decode::ProbeEvent;
pub use crate::decode::HEADER_LEN;
pub use crate::decode::MAGIC;
pub use crate::decode::VERSION;
pub use crate::explain::explain;
pub use crate::explain::Explanation;
pub use crate::explain::Finding;
pub use crate::manifest::AttachType;
pub use crate::manifest::EventKind;
pub use crate::manifest::Events;
pub use crate::manifest::FieldSpec;
pub use crate::manifest::FieldType;
pub use crate::manifest::ManifestError;
pub use crate::manifest::ProbeManifest;
pub use crate::manifest::ENVELOPE;
pub use crate::manifest::ENVELOPE_VERSION;
pub use crate::manifest::MANIFEST_VERSION;
pub use crate::manifest::MAP_NAME_MAX;
pub use crate::manifest::PAYLOAD_MAX;
pub use crate::verify::verify;
pub use crate::verify::MapSummary;
pub use crate::verify::ProgramSummary;
pub use crate::verify::VerifyError;
pub use crate::verify::VerifyReport;
pub use crate::verify::VerifyStatus;

/// clang major version the probe build requires, re-exported from `bpf-build`.
///
/// clang 20 and newer lower large `__builtin_memcpy` calls to an unresolved
/// `memcpy` extern that libbpf cannot resolve on the supported kernels, so the
/// sensor build and the probe SDK both pin 19.
pub const REQUIRED_CLANG_MAJOR: u32 = bpf_build::REQUIRED_CLANG_MAJOR;
