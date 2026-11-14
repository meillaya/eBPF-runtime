// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Load a compiled probe object with libbpf and report verifier diagnostics.
//!
//! [`verify`] opens the object with libbpf, parses its declared programs and
//! maps, and attempts a real kernel load. It never attaches the programs: the
//! object is dropped as soon as the load result is known. A load proves that
//! the verifier accepts every program in the object; an attach needs a
//! section-specific context and belongs to the runtime, not to this check.
//!
//! Loading BPF maps and programs requires root or the BPF capabilities. The
//! report distinguishes that environment limit ([`VerifyStatus::PermissionDenied`])
//! from a real verifier rejection ([`VerifyStatus::Rejected`]) and from an
//! object that libbpf cannot even open ([`VerifyStatus::Unavailable`]), so an
//! unprivileged caller can test the build path honestly without faking a
//! kernel verification.

use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::PoisonError;

use libbpf_rs::ObjectBuilder;
use libbpf_rs::PrintLevel;
use serde::Serialize;
use thiserror::Error;

use crate::explain::explain;
use crate::explain::Explanation;

/// Serializes load attempts: libbpf's print callback is process-global.
static VERIFY_LOCK: Mutex<()> = Mutex::new(());

/// Log messages libbpf emitted during the current (locked) load attempt.
static CAPTURED_LOG: Mutex<String> = Mutex::new(String::new());

/// What the load attempt proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyStatus {
    /// libbpf opened the object and the kernel verifier accepted every
    /// program. The object is safe to attach with the right context.
    Loaded,
    /// The kernel verifier rejected at least one program.
    Rejected,
    /// The process lacks the privileges to create BPF maps or load programs.
    PermissionDenied,
    /// libbpf could not open or parse the object (bad ELF, missing BTF, bad
    /// CO-RE relocation, or a similar open-time failure).
    Unavailable,
}

impl VerifyStatus {
    /// True when the object loaded and the verifier accepted every program.
    pub fn is_loaded(self) -> bool {
        matches!(self, Self::Loaded)
    }
}

/// One program declared in the object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProgramSummary {
    /// Program name (the C function name).
    pub name: String,
    /// ELF section that decides the attach type, for example
    /// `tracepoint/sched/sched_process_exec`.
    pub section: String,
    /// libbpf's program type for that section, for example `TracePoint`.
    pub prog_type: String,
}

/// One map declared in the object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MapSummary {
    /// Map name.
    pub name: String,
    /// Map type, for example `RingBuf`.
    pub map_type: String,
    /// Maximum number of entries.
    pub max_entries: u32,
}

/// Structured result of one [`verify`] call.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    /// Object that was checked.
    pub object: PathBuf,
    /// What the load attempt proved.
    pub status: VerifyStatus,
    /// Programs declared in the object, even when the load failed.
    pub programs: Vec<ProgramSummary>,
    /// Maps declared in the object, even when the load failed.
    pub maps: Vec<MapSummary>,
    /// Verifier and libbpf log captured during the load attempt.
    pub verifier_log: String,
    /// Load error text when the attempt did not succeed.
    pub error: Option<String>,
    /// Short next steps for the reported status.
    pub hints: Vec<String>,
}

impl VerifyReport {
    /// True when the object loaded and the verifier accepted every program.
    pub fn loaded(&self) -> bool {
        self.status.is_loaded()
    }

    /// Explain the captured verifier log when the kernel rejected a program.
    ///
    /// Returns `None` for every other status: a permission failure has no
    /// verifier log to explain, and a successful load needs no explanation.
    pub fn explanation(&self) -> Option<Explanation> {
        match self.status {
            VerifyStatus::Rejected => Some(explain(&self.verifier_log)),
            _ => None,
        }
    }
}

/// Errors from [`verify`] that happen before libbpf touches the object.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// The object does not exist yet; build it first.
    #[error("probe object {0} does not exist; build it with probe::build first")]
    ObjectMissing(PathBuf),
    /// The object path exists but is not a regular file.
    #[error("probe object is not a regular file: {0}")]
    NotAFile(PathBuf),
    /// The object exists but its metadata could not be read.
    #[error("cannot read probe object {path}: {source}")]
    ObjectUnreadable {
        /// Object path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
}

/// Open `object` with libbpf and attempt a real kernel load.
///
/// The returned [`VerifyReport`] is `Ok` for every load-time outcome,
/// including a verifier rejection and a missing-privilege failure; the
/// [`VerifyStatus`] and the captured verifier log carry the diagnosis. An
/// `Err` means the object file itself could not be read.
///
/// # Errors
///
/// Returns [`VerifyError`] when `object` is missing, is not a file, or its
/// metadata cannot be read.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let object = std::path::Path::new("target/probe-sdk/hello_probe.bpf.o");
/// let report = probe::verify(object)?;
/// if let Some(explanation) = report.explanation() {
///     println!("{}", explanation.render());
/// } else {
///     println!("{:?}: {}", report.status, report.hints.join(" "));
/// }
/// # Ok(())
/// # }
/// ```
pub fn verify(object: &Path) -> Result<VerifyReport, VerifyError> {
    let metadata = fs::metadata(object).map_err(|source| match source.kind() {
        io::ErrorKind::NotFound => VerifyError::ObjectMissing(object.to_path_buf()),
        _ => VerifyError::ObjectUnreadable {
            path: object.to_path_buf(),
            source,
        },
    })?;
    if !metadata.is_file() {
        return Err(VerifyError::NotAFile(object.to_path_buf()));
    }

    let _guard = VERIFY_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    reset_captured_log();
    let previous = libbpf_rs::set_print(Some((PrintLevel::Debug, capture)));
    let report = verify_object(object);
    libbpf_rs::set_print(previous);
    Ok(report)
}

/// Linux `EPERM`; the kernel uses it when the process lacks the privilege to
/// load BPF. A verifier rejection is reported as `EACCES`, which libbpf-rs
/// also classifies as a permission error, so the raw errno decides between
/// [`VerifyStatus::PermissionDenied`] and [`VerifyStatus::Rejected`].
const EPERM: i32 = 1;

fn classify_load_error(error: &libbpf_rs::Error) -> VerifyStatus {
    match raw_os_error(error) {
        Some(EPERM) => VerifyStatus::PermissionDenied,
        _ => VerifyStatus::Rejected,
    }
}

/// Extract the underlying OS error code from a libbpf error.
///
/// libbpf-rs does not expose the raw errno and its source chain hides the
/// inner `io::Error`, but its `Display` form ends an `io::Error` with the
/// standard `(os error N)` suffix. Parsing that suffix is the only way to
/// distinguish `EPERM` (missing privileges) from `EACCES` (verifier
/// rejection) after libbpf-rs has folded both into `PermissionDenied`.
fn raw_os_error(error: &libbpf_rs::Error) -> Option<i32> {
    let text = error.to_string();
    let marker = "(os error ";
    let start = text.rfind(marker)? + marker.len();
    let rest = &text[start..];
    let end = rest.find(')')?;
    rest[..end].parse().ok()
}

/// libbpf print callback that appends every message to [`CAPTURED_LOG`].
fn capture(_level: PrintLevel, message: String) {
    if let Ok(mut log) = CAPTURED_LOG.lock() {
        log.push_str(&message);
    }
}

/// Take and clear the captured libbpf log.
fn take_captured_log() -> String {
    let mut log = CAPTURED_LOG.lock().unwrap_or_else(PoisonError::into_inner);
    std::mem::take(&mut *log)
}

/// Clear any log left by a previous attempt before installing the callback.
fn reset_captured_log() {
    let mut log = CAPTURED_LOG.lock().unwrap_or_else(PoisonError::into_inner);
    log.clear();
}

/// The unlocked body of [`verify`]; the caller holds [`VERIFY_LOCK`] and has
/// the log callback installed.
fn verify_object(object: &Path) -> VerifyReport {
    let mut report = VerifyReport {
        object: object.to_path_buf(),
        status: VerifyStatus::Unavailable,
        programs: Vec::new(),
        maps: Vec::new(),
        verifier_log: String::new(),
        error: None,
        hints: Vec::new(),
    };

    let mut builder = ObjectBuilder::default();
    let opened = match builder.open_file(object) {
        Ok(opened) => opened,
        Err(error) => {
            report.error = Some(format!("open: {error}"));
            report.verifier_log = take_captured_log();
            report.hints = vec![
                "libbpf could not open the object: it is not a CO-RE BPF ELF, or its BTF/line info is unreadable".to_string(),
                "rebuild it with probe::build (clang 19, -target bpf -g -O2) and check the CO-RE relocations against the target kernel BTF".to_string(),
            ];
            return report;
        }
    };

    report.programs = opened
        .progs()
        .map(|program| ProgramSummary {
            name: program.name().to_string_lossy().into_owned(),
            section: program.section().to_string_lossy().into_owned(),
            prog_type: format!("{:?}", program.prog_type()),
        })
        .collect();
    report.maps = opened
        .maps()
        .map(|map| MapSummary {
            name: map.name().to_string_lossy().into_owned(),
            map_type: format!("{:?}", map.map_type()),
            max_entries: map.max_entries(),
        })
        .collect();

    match opened.load() {
        Ok(_loaded) => {
            report.status = VerifyStatus::Loaded;
            report.verifier_log = take_captured_log();
            report.hints = vec![
                "the kernel verifier accepted every program in the object".to_string(),
                "verify does not attach programs; attaching needs the section-specific context and belongs to the runtime".to_string(),
            ];
        }
        Err(error) => {
            report.verifier_log = take_captured_log();
            report.status = classify_load_error(&error);
            report.error = Some(format!("load: {error}"));
            report.hints = match report.status {
                VerifyStatus::PermissionDenied => vec![
                    "creating BPF maps and loading programs requires root (uid 0) or CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN".to_string(),
                    "the object was opened and its programs/maps were parsed, so this is an environment privilege limit, not a verifier rejection".to_string(),
                    "re-run as root or inside scripts/run-privileged-tests.sh / the VM test harness before treating the object as verified".to_string(),
                ],
                _ => vec![
                    "the kernel verifier rejected at least one program; call VerifyReport::explanation() or probe::explain(&report.verifier_log) for the matched causes and source lines".to_string(),
                    "the last instruction or source annotation in the verifier log is closest to the failure".to_string(),
                    "fix the C source and rebuild; do not patch the object".to_string(),
                ],
            };
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::default_out_dir;

    fn example_object(name: &str) -> PathBuf {
        let root = crate::workspace_root();
        let source = root.join("sdk/examples/hello_probe.bpf.c");
        let object = default_out_dir().join("tests").join(name);
        crate::build(&source, &object, &[]).expect("the example probe must compile");
        object
    }

    #[test]
    fn missing_object_is_an_error() {
        let path = default_out_dir().join("tests/does-not-exist.bpf.o");
        let error = verify(&path).expect_err("a missing object must be an error");
        assert!(matches!(error, VerifyError::ObjectMissing(_)));
    }

    #[test]
    fn non_elf_object_is_unavailable() {
        let path = default_out_dir().join("tests/not-an-elf.bpf.o");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create test output directory");
        }
        fs::write(&path, b"this is not an ELF object").expect("write fixture");
        let report = verify(&path).expect("an unreadable object is a report, not an error");
        assert_eq!(report.status, VerifyStatus::Unavailable);
        assert!(report.programs.is_empty());
        assert!(report.maps.is_empty());
        assert!(report.error.is_some());
        assert!(!report.hints.is_empty());
    }

    /// The non-privileged path: the object parses and the load is attempted,
    /// but this process almost certainly cannot create BPF maps. The test
    /// proves the report shape and never claims a kernel verification that
    /// did not happen.
    #[test]
    fn verify_reports_the_unprivileged_load_path() {
        let object = example_object("verify-hello_probe.bpf.o");
        let report = verify(&object).expect("an existing object must produce a report");

        assert_ne!(report.status, VerifyStatus::Unavailable);
        assert_eq!(report.programs.len(), 1);
        assert_eq!(report.programs[0].name, "hello_probe_exec");
        assert_eq!(
            report.programs[0].section,
            "tracepoint/sched/sched_process_exec"
        );
        assert_eq!(report.maps.len(), 1);
        assert_eq!(report.maps[0].name, "hello_events");
        assert_eq!(report.maps[0].map_type, "RingBuf");
        assert_eq!(report.maps[0].max_entries, 256 * 1024);

        if report.status == VerifyStatus::PermissionDenied {
            assert!(report.hints.iter().any(|hint| hint.contains("CAP_BPF")));
            assert!(report.explanation().is_none());

            // The captured libbpf log is real text, not a fixture. explain()
            // must keep it intact and recognize the EPERM failure as a
            // privilege problem rather than a verifier rejection.
            assert!(!report.verifier_log.is_empty());
            let explanation = crate::explain(&report.verifier_log);
            assert_eq!(explanation.full_log, report.verifier_log);
            if report.verifier_log.contains("-EPERM") {
                assert!(explanation
                    .findings
                    .iter()
                    .any(|finding| finding.cause == "privileges"));
            }
        } else {
            assert!(
                report.status == VerifyStatus::Loaded || report.status == VerifyStatus::Rejected
            );
        }
    }

    /// Loads a real program into the kernel. Requires root or CAP_BPF +
    /// CAP_PERFMON + CAP_SYS_ADMIN; run with
    /// `cargo test -p probe -- --ignored` on a privileged host. CI must not
    /// run this, and the unprivileged test above must not pretend it did.
    #[test]
    #[ignore = "loads a real BPF program; requires root or CAP_BPF/CAP_PERFMON/CAP_SYS_ADMIN"]
    fn privileged_load_accepts_the_example_probe() {
        let object = example_object("ignored-hello_probe.bpf.o");
        let report = verify(&object).expect("an existing object must produce a report");
        assert_eq!(
            report.status,
            VerifyStatus::Loaded,
            "verifier log:\n{}",
            report.verifier_log
        );
        assert!(
            report.verifier_log.contains("BEGIN PROG LOAD LOG") || report.verifier_log.is_empty()
        );
        assert!(report.loaded());
    }
}
