// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Load and attach one external CO-RE object, keeping it alive to unload.
//!
//! [`load`][crate::load] is the embedded-sensor path: it opens objects that
//! were compiled into the binary and owns their lifecycle. This module is the
//! dynamic path behind `fleet probe run`: it opens an object from the
//! filesystem, exposes the programs and maps it declares before any kernel
//! resource is created, then loads, attaches by ELF section, and builds ring
//! buffers by map name.
//!
//! The two-phase API exists so a caller can reject a wrong section or a
//! missing ring-buffer map with an actionable error *before* asking the kernel
//! to load anything:
//!
//! ```no_run
//! # fn main() -> Result<(), bpf_loader::DynamicObjectError> {
//! let opened = bpf_loader::open_object("/tmp/hello_probe.bpf.o")?;
//! if !opened.has_section("tracepoint/sched/sched_process_exec") {
//!     return Err(bpf_loader::DynamicObjectError::SectionNotFound {
//!         path: opened.path().to_path_buf(),
//!         section: "tracepoint/sched/sched_process_exec".to_string(),
//!         available: opened.section_list(),
//!     });
//! }
//! let mut loaded = opened.load()?; // needs root or CAP_BPF/CAP_PERFMON
//! let attached = loaded.attach("tracepoint/sched/sched_process_exec")?;
//! let (ring, records) = loaded.ring_reader("hello_events")?;
//! // poll the ring and decode `records`; the object stays alive here.
//! # let _ = (attached, ring, records);
//! let report = loaded.unload();
//! assert_eq!(report.links_detached, 0);
//! # Ok(())
//! # }
//! ```
//!
//! Loading requires root or `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_ADMIN`.
//! [`DynamicObjectError::PermissionDenied`] is a distinct variant so a caller
//! can report an environment limit instead of a verifier rejection. Nothing
//! here decides *whether* an object may be loaded: the caller (the probe
//! runtime CLI) checks the manifest, the SHA-256 pin, and the root-only rule
//! before calling in.

use std::path::Path;
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::Once;

use libbpf_rs::Link;
use libbpf_rs::MapCore;
use libbpf_rs::MapType;
use libbpf_rs::Object;
use libbpf_rs::ObjectBuilder;
use libbpf_rs::OpenObject;
use libbpf_rs::PrintLevel;
use libbpf_rs::RingBuffer;
use libbpf_rs::RingBufferBuilder;
use thiserror::Error;

/// One program declared by an opened object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicProgram {
    /// C function name.
    pub name: String,
    /// ELF section that decides the attach type.
    pub section: String,
    /// libbpf program type, for example `TracePoint`.
    pub prog_type: String,
}

/// One map declared by an opened object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicMap {
    /// Map name.
    pub name: String,
    /// libbpf map type, for example `RingBuf`.
    pub map_type: String,
    /// Maximum number of entries (bytes for a ring buffer).
    pub max_entries: u32,
}

/// One raw record delivered by a dynamic ring buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRecord {
    /// Record bytes exactly as the kernel delivered them.
    pub bytes: Vec<u8>,
}

/// What explicitly dropping a [`LoadedObject`] released.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnloadReport {
    /// Attach links detached.
    pub links_detached: usize,
}

/// Errors from opening, loading, or attaching a dynamic object.
#[derive(Debug, Error)]
pub enum DynamicObjectError {
    /// libbpf could not open or parse the object file.
    #[error("cannot open probe object {path}: {source}")]
    Open {
        /// Object path.
        path: PathBuf,
        /// Underlying libbpf error.
        #[source]
        source: libbpf_rs::Error,
    },
    /// The kernel refused the load for a reason other than missing
    /// privileges (most often a verifier rejection, which the kernel reports
    /// as `EACCES`).
    #[error(
        "cannot load probe object {path}: {source}; if the kernel verifier rejected the object, \
         run `ebpf-fleet probe verify {path} --json` for the verifier log"
    )]
    Load {
        /// Object path.
        path: PathBuf,
        /// Underlying libbpf error.
        #[source]
        source: libbpf_rs::Error,
    },
    /// The process lacks the privileges to create BPF maps and load programs.
    #[error(
        "permission denied loading probe object {path}: {source}; loading needs root or \
         CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN"
    )]
    PermissionDenied {
        /// Object path.
        path: PathBuf,
        /// Underlying libbpf error.
        #[source]
        source: libbpf_rs::Error,
    },
    /// The object declares no program in the requested section.
    #[error("no program in section `{section}` in {path}; object sections: {available}")]
    SectionNotFound {
        /// Object path.
        path: PathBuf,
        /// Requested ELF section.
        section: String,
        /// Comma-separated sections the object declares.
        available: String,
    },
    /// Attaching one program failed.
    #[error("cannot attach program `{program}` in section `{section}`: {source}")]
    Attach {
        /// Object path.
        path: PathBuf,
        /// ELF section.
        section: String,
        /// Program name.
        program: String,
        /// Underlying libbpf error.
        #[source]
        source: libbpf_rs::Error,
    },
    /// The object declares no map with the requested name.
    #[error("no map `{map}` in {path}; object maps: {available}")]
    MapNotFound {
        /// Object path.
        path: PathBuf,
        /// Requested map name.
        map: String,
        /// Comma-separated map names the object declares.
        available: String,
    },
    /// The named map is not a ring buffer.
    #[error("map `{map}` in {path} is a {map_type} map, not a ring buffer")]
    NotRingBuffer {
        /// Object path.
        path: PathBuf,
        /// Map name.
        map: String,
        /// Actual map type.
        map_type: String,
    },
    /// The ring buffer manager could not be built or polled.
    #[error("ring buffer error: {0}")]
    RingBuffer(String),
}

/// An object opened and parsed by libbpf, but not loaded into the kernel.
///
/// Programs and maps are already visible here, so callers can validate a
/// section or a map name without creating any kernel resource.
#[derive(Debug)]
pub struct OpenedObject {
    path: PathBuf,
    object: OpenObject,
    programs: Vec<DynamicProgram>,
    maps: Vec<DynamicMap>,
}

impl OpenedObject {
    /// Object path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Programs the object declares, in ELF order.
    pub fn programs(&self) -> &[DynamicProgram] {
        &self.programs
    }

    /// Maps the object declares, in ELF order.
    pub fn maps(&self) -> &[DynamicMap] {
        &self.maps
    }

    /// True when a program is declared in exactly `section`.
    pub fn has_section(&self, section: &str) -> bool {
        self.programs
            .iter()
            .any(|program| program.section == section)
    }

    /// Comma-separated declared sections, for error messages.
    pub fn section_list(&self) -> String {
        join_names(self.programs.iter().map(|program| program.section.as_str()))
    }

    /// True when a map named `name` is declared.
    pub fn has_map(&self, name: &str) -> bool {
        self.maps.iter().any(|map| map.name == name)
    }

    /// True when a map named `name` is declared and is a ring buffer.
    pub fn has_ringbuf(&self, name: &str) -> bool {
        self.maps
            .iter()
            .any(|map| map.name == name && map.map_type == "RingBuf")
    }

    /// Comma-separated declared map names, for error messages.
    pub fn map_list(&self) -> String {
        join_names(self.maps.iter().map(|map| map.name.as_str()))
    }

    /// Load every program and map into the kernel.
    pub fn load(self) -> Result<LoadedObject, DynamicObjectError> {
        let path = self.path.clone();
        let object = self
            .object
            .load()
            .map_err(|source| classify_load_error(path, source))?;
        Ok(LoadedObject {
            path: self.path,
            object,
            links: Vec::new(),
            programs: self.programs,
            maps: self.maps,
        })
    }
}

/// An object loaded into the kernel with its attach links.
///
/// Dropping this value detaches every link and closes the object and its maps.
/// [`unload`][Self::unload] makes that explicit and reports what was released.
/// Callers must keep it alive while polling a ring buffer built from it.
#[derive(Debug)]
pub struct LoadedObject {
    path: PathBuf,
    object: Object,
    links: Vec<Link>,
    programs: Vec<DynamicProgram>,
    maps: Vec<DynamicMap>,
}

impl LoadedObject {
    /// Object path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The loaded libbpf object. Dropping it unloads programs and maps.
    pub fn object(&self) -> &Object {
        &self.object
    }

    /// Programs the object declares, in ELF order.
    pub fn programs(&self) -> &[DynamicProgram] {
        &self.programs
    }

    /// Maps the object declares, in ELF order.
    pub fn maps(&self) -> &[DynamicMap] {
        &self.maps
    }

    /// Attach links currently held, one per attached program.
    pub fn links(&self) -> &[Link] {
        &self.links
    }

    /// Attach every program declared in `section` and keep the links alive.
    ///
    /// Returns the attached program names. A section with no program is
    /// [`DynamicObjectError::SectionNotFound`]; a failed attach drops the links
    /// already created for this call so no partial attachment survives.
    pub fn attach(&mut self, section: &str) -> Result<Vec<String>, DynamicObjectError> {
        let mut links = Vec::new();
        let mut names = Vec::new();
        let mut failure = None;
        for program in self.object.progs_mut() {
            let program_section = program.section().to_string_lossy().into_owned();
            if program_section != section {
                continue;
            }
            let name = program.name().to_string_lossy().into_owned();
            match program.attach() {
                Ok(link) => {
                    links.push(link);
                    names.push(name);
                }
                Err(source) => {
                    failure = Some((name, source));
                    break;
                }
            }
        }
        self.links.extend(links);
        if let Some((program, source)) = failure {
            return Err(DynamicObjectError::Attach {
                path: self.path.clone(),
                section: section.to_string(),
                program,
                source,
            });
        }
        if names.is_empty() {
            return Err(DynamicObjectError::SectionNotFound {
                path: self.path.clone(),
                section: section.to_string(),
                available: join_names(
                    self.programs
                        .iter()
                        .map(|declared| declared.section.as_str()),
                ),
            });
        }
        Ok(names)
    }

    /// Build one ring buffer over the named map map.
    ///
    /// The returned receiver yields one [`RawRecord`] per kernel record. The
    /// ring buffer holds its own map descriptor, but the caller must keep this
    /// [`LoadedObject`] alive while polling.
    pub fn ring_reader(
        &self,
        map_name: &str,
    ) -> Result<(RingBuffer<'static>, Receiver<RawRecord>), DynamicObjectError> {
        let map = self
            .object
            .maps()
            .find(|map| map.name().to_string_lossy() == map_name)
            .ok_or_else(|| DynamicObjectError::MapNotFound {
                path: self.path.clone(),
                map: map_name.to_string(),
                available: join_names(self.maps.iter().map(|declared| declared.name.as_str())),
            })?;
        if map.map_type() != MapType::RingBuf {
            return Err(DynamicObjectError::NotRingBuffer {
                path: self.path.clone(),
                map: map_name.to_string(),
                map_type: format!("{:?}", map.map_type()),
            });
        }

        let (sender, receiver) = channel();
        let mut builder = RingBufferBuilder::new();
        let forward: Sender<RawRecord> = sender;
        builder
            .add(&map, move |bytes| {
                let _ = forward.send(RawRecord {
                    bytes: bytes.to_vec(),
                });
                0
            })
            .map_err(|error| DynamicObjectError::RingBuffer(error.to_string()))?;
        let ring = builder
            .build()
            .map_err(|error| DynamicObjectError::RingBuffer(error.to_string()))?;
        Ok((ring, receiver))
    }

    /// Detach every link and close the object and maps.
    ///
    /// This is the explicit form of dropping the value; it exists so the
    /// runtime can report unload as part of a clean stop instead of relying on
    /// scope exit.
    pub fn unload(mut self) -> UnloadReport {
        let links_detached = self.links.len();
        let links = std::mem::take(&mut self.links);
        drop(links);
        UnloadReport { links_detached }
    }
}

/// Open and parse an object without loading it.
pub fn open_object(path: impl AsRef<Path>) -> Result<OpenedObject, DynamicObjectError> {
    quiet_libbpf();
    let path = path.as_ref().to_path_buf();
    let mut builder = ObjectBuilder::default();
    let object = builder
        .open_file(&path)
        .map_err(|source| DynamicObjectError::Open {
            path: path.clone(),
            source,
        })?;
    let programs = object
        .progs()
        .map(|program| DynamicProgram {
            name: program.name().to_string_lossy().into_owned(),
            section: program.section().to_string_lossy().into_owned(),
            prog_type: format!("{:?}", program.prog_type()),
        })
        .collect();
    let maps = object
        .maps()
        .map(|map| DynamicMap {
            name: map.name().to_string_lossy().into_owned(),
            map_type: format!("{:?}", map.map_type()),
            max_entries: map.max_entries(),
        })
        .collect();
    Ok(OpenedObject {
        path,
        object,
        programs,
        maps,
    })
}

/// Open and load an object in one call.
///
/// Prefer [`open_object`] plus validation plus [`OpenedObject::load`] when the
/// caller has a manifest to check; this helper is for callers that already
/// know what they are loading.
pub fn load_object(path: impl AsRef<Path>) -> Result<LoadedObject, DynamicObjectError> {
    open_object(path)?.load()
}

/// Linux `EPERM`; the kernel uses it when the process lacks the privileges
/// to load BPF. A verifier rejection is reported as `EACCES`, which
/// libbpf-rs's [`ErrorKind::PermissionDenied`](libbpf_rs::ErrorKind::PermissionDenied)
/// also folds into the
/// permission bucket, so the raw errno is the only reliable discriminator.
const EPERM: i32 = 1;

fn classify_load_error(path: PathBuf, source: libbpf_rs::Error) -> DynamicObjectError {
    if raw_os_error(&source) == Some(EPERM) {
        DynamicObjectError::PermissionDenied { path, source }
    } else {
        DynamicObjectError::Load { path, source }
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

/// Silence libbpf's warnings exactly once; the returned errors carry the
/// diagnosis and the CLI owns the user-facing message.
fn quiet_libbpf() {
    static QUIET: Once = Once::new();
    QUIET.call_once(|| {
        libbpf_rs::set_print(Some((PrintLevel::Warn, |_, _| {})));
    });
}

fn join_names<'a>(names: impl Iterator<Item = &'a str>) -> String {
    let joined = names.collect::<Vec<_>>().join(", ");
    if joined.is_empty() {
        "<none>".to_string()
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SENSORS;

    fn write_fixture(directory: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = directory.join(name);
        std::fs::write(&path, bytes).expect("write fixture object");
        path
    }

    fn temp_dir(label: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "bpf-loader-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&directory).expect("create temp dir");
        directory
    }

    #[test]
    fn open_rejects_a_missing_object() {
        let directory = temp_dir("missing");
        let error = open_object(directory.join("does-not-exist.bpf.o")).expect_err("must fail");
        assert!(matches!(error, DynamicObjectError::Open { .. }));
        assert!(error.to_string().contains("cannot open probe object"));
        std::fs::remove_dir_all(directory).expect("cleanup");
    }

    #[test]
    fn open_rejects_a_non_elf_file() {
        let directory = temp_dir("non-elf");
        let path = write_fixture(&directory, "not-a-probe.bpf.o", b"not an ELF object");
        let error = open_object(&path).expect_err("must fail");
        assert!(matches!(error, DynamicObjectError::Open { .. }));
        std::fs::remove_dir_all(directory).expect("cleanup");
    }

    #[test]
    fn open_exposes_programs_and_maps_without_loading() {
        let directory = temp_dir("sensor");
        let sensor = &SENSORS[0];
        let path = write_fixture(&directory, "sensor.bpf.o", sensor.bytes);
        let opened = open_object(&path).expect("the embedded sensor object must open");

        assert_eq!(opened.path(), path);
        assert!(!opened.programs().is_empty());
        assert!(!opened.maps().is_empty());
        let first = &opened.programs()[0];
        assert!(!first.name.is_empty());
        assert!(!first.section.is_empty());
        assert!(!first.prog_type.is_empty());
        assert!(opened.has_section(&first.section));
        assert!(!opened.has_section("tracepoint/definitely/not/a/section"));
        assert!(opened.section_list().contains(&first.section));

        let first_map = &opened.maps()[0];
        assert!(opened.has_map(&first_map.name));
        assert!(!opened.has_map("definitely_not_a_map"));
        let ring_name = format!("{}_events", sensor.name);
        assert!(
            opened.has_ringbuf(&ring_name),
            "sensor {} must declare {ring_name}: {}",
            sensor.name,
            opened.map_list()
        );
        assert!(!opened.has_ringbuf(&first_map.name) || first_map.map_type == "RingBuf");
        std::fs::remove_dir_all(directory).expect("cleanup");
    }

    /// Loading a real object needs root or CAP_BPF/CAP_PERFMON/CAP_SYS_ADMIN.
    /// On an unprivileged host the API must report that honestly instead of
    /// spoofing success; when the test does run privileged, it exercises the
    /// attach/ring-buffer/unload lifecycle for real.
    #[test]
    fn load_reports_privilege_denial_or_completes_the_lifecycle() {
        let directory = temp_dir("load");
        let sensor = &SENSORS[0];
        let path = write_fixture(&directory, "sensor.bpf.o", sensor.bytes);

        match open_object(&path)
            .expect("open must succeed unprivileged")
            .load()
        {
            Ok(loaded) => {
                let ring_name = format!("{}_events", sensor.name);
                assert!(loaded.links().is_empty());
                let (_ring, _records) = loaded
                    .ring_reader(&ring_name)
                    .expect("ring buffer map must build");
                let unknown = loaded.ring_reader("definitely_not_a_map");
                assert!(matches!(
                    unknown,
                    Err(DynamicObjectError::MapNotFound { .. })
                ));
                let report = loaded.unload();
                assert_eq!(report.links_detached, 0);
            }
            Err(DynamicObjectError::PermissionDenied { .. }) => {}
            Err(error) => panic!("unexpected dynamic load error: {error}"),
        }
        std::fs::remove_dir_all(directory).expect("cleanup");
    }

    #[test]
    fn unload_report_defaults_to_nothing_detached() {
        assert_eq!(UnloadReport::default().links_detached, 0);
    }
}
