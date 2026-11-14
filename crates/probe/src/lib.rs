// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Build, verify, and explain custom C probes for the eBPF fleet SDK.
//!
//! This crate is the tool half of the 0.2 C probe SDK. It does not compile a
//! probe DSL and it does not load probes into the running agent; it gives a
//! developer (and the future `fleet probe` CLI) three honest operations:
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
//!
//! The C side lives in `sdk/include/fleet_probe.h` with a buildable example
//! in `sdk/examples/hello_probe.bpf.c`. See `docs/probe-sdk.md` for the
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
mod explain;
mod verify;

pub use crate::build::build;
pub use crate::build::default_out_dir;
pub use crate::build::workspace_root;
pub use crate::build::BuildArtifact;
pub use crate::build::BuildError;
pub use crate::explain::explain;
pub use crate::explain::Explanation;
pub use crate::explain::Finding;
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
