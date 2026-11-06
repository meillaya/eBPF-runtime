// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Load the compiled sensors and attach their programs.
//!
//! [`load`] opens each embedded object, loads it into the kernel, and
//! attaches every program libbpf can attach without extra context. The
//! result records one entry per sensor: attached programs, skipped
//! sections, and the error for every failed attach.
//!
//! A sensor that attaches no program is dropped, so a caller never holds
//! an object that observes nothing. Programs in `cgroup/`, `cgroup_skb/`,
//! and `classifier` sections need a cgroup or network device handle; this
//! loader skips them and says so in the coverage entry.
//!
//! ```no_run
//! # fn main() -> Result<(), bpf_loader::LoaderError> {
//! let sensors = bpf_loader::load(&[])?;
//! let (ring, events) = sensors.ring_reader()?;
//! loop {
//!     sensors.poll(&ring, std::time::Duration::from_millis(200))?;
//!     for sample in events.try_iter() {
//!         println!("{} {} bytes", sample.sensor, sample.bytes.len());
//!     }
//! }
//! # }
//! ```

#![forbid(unsafe_code)]

use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Once;
use std::time::Duration;

use libbpf_rs::{Link, MapCore, Object, RingBuffer, RingBufferBuilder};
use serde::Serialize;
use thiserror::Error;

/// One compiled sensor embedded at build time.
pub struct EmbeddedSensor {
    /// Sensor name, for example `process`.
    pub name: &'static str,
    /// Architecture the object was compiled for.
    pub arch: &'static str,
    /// SHA-256 of the object bytes.
    pub sha256: &'static str,
    /// Raw CO-RE object.
    pub bytes: &'static [u8],
}

mod embedded {
    use super::EmbeddedSensor;
    include!(env!("EBPF_EMBEDDED_ARTIFACTS"));
}

/// Every sensor compiled into this binary.
pub use embedded::SENSORS;

/// Status of one sensor after loading and attaching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SensorStatus {
    /// Every attachable program attached.
    Capable,
    /// At least one program attached and at least one failed.
    Degraded,
    /// No program attached.
    Blocked,
}

/// Per-sensor result.
#[derive(Debug, Clone, Serialize)]
pub struct SensorCoverage {
    /// Sensor name.
    pub name: String,
    /// Object SHA-256.
    pub sha256: String,
    /// Attach verdict.
    pub status: SensorStatus,
    /// Programs that attached, as `section:program`.
    pub programs: Vec<String>,
    /// Sections this loader does not attach without extra context.
    pub skipped: Vec<String>,
    /// Errors from programs that failed to attach.
    pub errors: Vec<String>,
}

/// Coverage for one load call.
#[derive(Debug, Clone, Serialize)]
pub struct CoverageMatrix {
    /// Matrix schema version.
    pub schema_version: u32,
    /// Architecture of the embedded objects.
    pub arch: String,
    /// One entry per embedded sensor the call considered.
    pub sensors: Vec<SensorCoverage>,
}

/// A sensor object kept alive for the lifetime of the process.
pub struct LoadedSensor {
    /// Sensor name.
    pub name: String,
    /// Loaded object. Dropping it detaches every program and closes maps.
    pub object: Object,
    /// Attached program links.
    pub links: Vec<Link>,
    /// Attach result for this sensor.
    pub coverage: SensorCoverage,
}

/// All sensors loaded by one call.
pub struct LoadedSensors {
    /// Architecture of the objects.
    pub arch: String,
    /// Sensors that attached at least one program.
    pub sensors: Vec<LoadedSensor>,
    /// Coverage for every sensor, including blocked ones.
    pub coverage: CoverageMatrix,
}

/// One raw record from a ring buffer.
#[derive(Debug, Clone)]
pub struct RawSample {
    /// Sensor that produced the record.
    pub sensor: String,
    /// Record bytes.
    pub bytes: Vec<u8>,
}

/// Errors from loading.
#[derive(Debug, Error)]
pub enum LoaderError {
    /// No embedded sensor matched the requested names.
    #[error("no sensor matched the request")]
    NoSensors,
    /// A requested sensor is not embedded in this binary.
    #[error("sensor `{0}` is not embedded in this binary")]
    UnknownSensor(String),
    /// The ring buffer could not be built.
    #[error("ring buffer error: {0}")]
    RingBuffer(String),
}

/// Load every embedded sensor for the host architecture.
pub fn load_all() -> Result<LoadedSensors, LoaderError> {
    load(&[])
}

/// Load the named sensors. An empty slice loads every embedded sensor.
///
/// A sensor that fails to load or attach is recorded in the coverage
/// matrix and omitted from [`LoadedSensors::sensors`]. The call returns
/// an error only when no requested sensor is embedded or when a requested
/// name is unknown.
pub fn load(names: &[&str]) -> Result<LoadedSensors, LoaderError> {
    static QUIET: Once = Once::new();
    QUIET.call_once(|| {
        libbpf_rs::set_print(Some((libbpf_rs::PrintLevel::Warn, |_, _| {})));
    });

    let host_arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => {
            return Err(LoaderError::RingBuffer(format!(
                "unsupported host architecture `{other}`"
            )))
        }
    }
    .to_string();

    if SENSORS.is_empty() {
        return Err(LoaderError::NoSensors);
    }

    let selected: Vec<&EmbeddedSensor> = if names.is_empty() {
        SENSORS.iter().collect()
    } else {
        let mut selected = Vec::new();
        for name in names {
            let sensor = SENSORS
                .iter()
                .find(|sensor| sensor.name == *name)
                .ok_or_else(|| LoaderError::UnknownSensor((*name).to_string()))?;
            selected.push(sensor);
        }
        selected
    };

    let mut loaded = Vec::new();
    let mut coverage_entries = Vec::new();

    for sensor in selected {
        let coverage = load_one(sensor, &mut loaded);
        coverage_entries.push(coverage);
    }

    if coverage_entries.is_empty() {
        return Err(LoaderError::NoSensors);
    }

    Ok(LoadedSensors {
        arch: host_arch.clone(),
        sensors: loaded,
        coverage: CoverageMatrix {
            schema_version: 1,
            arch: host_arch,
            sensors: coverage_entries,
        },
    })
}

fn load_one(sensor: &EmbeddedSensor, loaded: &mut Vec<LoadedSensor>) -> SensorCoverage {
    let mut coverage = SensorCoverage {
        name: sensor.name.to_string(),
        sha256: sensor.sha256.to_string(),
        status: SensorStatus::Blocked,
        programs: Vec::new(),
        skipped: Vec::new(),
        errors: Vec::new(),
    };

    let object = match libbpf_rs::ObjectBuilder::default().open_memory(sensor.bytes) {
        Ok(object) => match object.load() {
            Ok(object) => object,
            Err(error) => {
                coverage.errors.push(format!("load: {error}"));
                return coverage;
            }
        },
        Err(error) => {
            coverage.errors.push(format!("open: {error}"));
            return coverage;
        }
    };

    let mut links = Vec::new();
    for program in object.progs_mut() {
        let section = program.section().to_string_lossy().into_owned();
        let name = program.name().to_string_lossy().into_owned();
        let label = format!("{section}:{name}");

        if needs_context(&section) {
            coverage.skipped.push(label);
            continue;
        }

        match program.attach() {
            Ok(link) => {
                links.push(link);
                coverage.programs.push(label);
            }
            Err(error) => coverage.errors.push(format!("{label}: {error}")),
        }
    }

    coverage.status = match (coverage.programs.is_empty(), coverage.errors.is_empty()) {
        (true, _) => SensorStatus::Blocked,
        (false, true) => SensorStatus::Capable,
        (false, false) => SensorStatus::Degraded,
    };

    if !coverage.programs.is_empty() {
        loaded.push(LoadedSensor {
            name: sensor.name.to_string(),
            object,
            links,
            coverage: coverage.clone(),
        });
    }

    coverage
}

/// Sections that need a cgroup or network device handle to attach.
fn needs_context(section: &str) -> bool {
    section.starts_with("cgroup/")
        || section.starts_with("cgroup_skb/")
        || section.starts_with("classifier")
        || section.starts_with("xdp")
        || section.starts_with("tc/")
}

impl LoadedSensors {
    /// Build one ring buffer over every loaded sensor.
    ///
    /// The returned receiver yields one [`RawSample`] per kernel record.
    /// The ring buffer holds raw map file descriptors, so it does not
    /// borrow the sensor objects. The caller must keep `self` alive while
    /// polling.
    pub fn ring_reader(&self) -> Result<(RingBuffer<'static>, Receiver<RawSample>), LoaderError> {
        let (sender, receiver) = channel();
        let mut maps = Vec::new();

        for sensor in &self.sensors {
            let map_name = format!("{}_events", sensor.name);
            let map = sensor
                .object
                .maps()
                .find(|map| map.name().to_string_lossy() == map_name);
            match map {
                Some(map) => maps.push((sensor.name.clone(), map)),
                None => {
                    return Err(LoaderError::RingBuffer(format!(
                        "sensor {} has no ring buffer map {}",
                        sensor.name, map_name
                    )))
                }
            }
        }

        if maps.is_empty() {
            return Err(LoaderError::NoSensors);
        }

        let mut builder = RingBufferBuilder::new();
        for (sensor, map) in &maps {
            let sender: Sender<RawSample> = sender.clone();
            let sensor = sensor.clone();
            builder
                .add(map, move |bytes| {
                    let _ = sender.send(RawSample {
                        sensor: sensor.clone(),
                        bytes: bytes.to_vec(),
                    });
                    0
                })
                .map_err(|error| LoaderError::RingBuffer(error.to_string()))?;
        }

        let ring = builder
            .build()
            .map_err(|error| LoaderError::RingBuffer(error.to_string()))?;
        drop(maps);
        Ok((ring, receiver))
    }

    /// Coverage as pretty JSON.
    pub fn coverage_as_json(&self) -> String {
        serde_json::to_string_pretty(&self.coverage).unwrap_or_else(|_| "{}".to_string())
    }

    /// Poll every ring buffer once. The call blocks up to `timeout`.
    pub fn poll(&self, ring: &RingBuffer<'_>, timeout: Duration) -> Result<(), LoaderError> {
        ring.poll(timeout)
            .map_err(|error| LoaderError::RingBuffer(error.to_string()))
    }
}

impl RawSample {
    /// Event kind byte from the ABI header, if the record is long enough.
    pub fn kind(&self) -> Option<u8> {
        self.bytes.get(16).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_sensor_is_embedded_with_bytes() {
        assert_eq!(SENSORS.len(), 2);
        for sensor in SENSORS {
            assert!(!sensor.bytes.is_empty(), "{} has no object", sensor.name);
            assert_eq!(sensor.sha256.len(), 64, "{} has a bad digest", sensor.name);
            assert!(sensor.arch == "amd64" || sensor.arch == "arm64");
        }
    }

    #[test]
    fn cgroup_and_classifier_sections_are_skipped() {
        assert!(needs_context("cgroup/connect4"));
        assert!(needs_context("cgroup_skb/ingress"));
        assert!(needs_context("classifier"));
        assert!(!needs_context("raw_tracepoint/sched_process_exec"));
        assert!(!needs_context("lsm/file_open"));
        assert!(!needs_context("kprobe/__x64_sys_openat2"));
    }

    #[test]
    fn unknown_sensor_is_rejected() {
        let error = load(&["does-not-exist"]).err().expect("must fail");
        assert!(matches!(error, LoaderError::UnknownSensor(_)));
    }

    #[test]
    fn coverage_serializes_with_lowercase_status() {
        let json = serde_json::to_string(&SensorStatus::Capable).unwrap();
        assert_eq!(json, "\"capable\"");
    }
}
