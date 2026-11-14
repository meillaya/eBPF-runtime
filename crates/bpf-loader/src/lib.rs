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

use libbpf_rs::{Link, Map, MapCore, MapFlags, Object, RingBuffer, RingBufferBuilder};
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
    /// Stack capture mode the loader configured.
    pub stack_mode: StackMode,
}

/// One raw record from a ring buffer.
#[derive(Debug, Clone)]
pub struct RawSample {
    /// Sensor that produced the record.
    pub sensor: String,
    /// Record bytes.
    pub bytes: Vec<u8>,
}

/// Stack capture mode for [`load_with_options`].
///
/// * `Off` is the 0.2 behavior and the minimum-overhead path.
/// * `Events` captures the 0.3 default event set: process exec and file
///   open/create/truncate.
/// * `All` captures every event the sensors emit (adds fork/exit and
///   file unlink/rename).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StackMode {
    /// No stack capture; sensors emit `stack_id = -1`.
    #[default]
    Off,
    /// Capture the default event set.
    Events,
    /// Capture every event.
    All,
}

impl StackMode {
    /// Parse the CLI string form (`off`, `events`, `all`).
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "off" => Some(Self::Off),
            "events" => Some(Self::Events),
            "all" => Some(Self::All),
            _ => None,
        }
    }

    /// String form recorded in the bundle manifest.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Events => "events",
            Self::All => "all",
        }
    }

    /// Value written into the BPF `stack_config` map
    /// (`KERNEL_V2_STACK_MODE_*` in `bpf/include/event_abi.h`).
    pub fn bpf_mode(self) -> u32 {
        match self {
            Self::Off => 0,
            Self::Events => 1,
            Self::All => 2,
        }
    }

    /// True when capture is enabled.
    pub fn enabled(self) -> bool {
        self != Self::Off
    }
}

impl std::fmt::Display for StackMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Options for [`load_with_options`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoadOptions {
    /// Stack capture mode written into every loaded sensor.
    pub stack_mode: StackMode,
}

impl LoadOptions {
    /// Options with stack capture off (the 0.2 behavior).
    pub fn new() -> Self {
        Self::default()
    }

    /// Options with the given stack capture mode.
    pub fn with_stack_mode(stack_mode: StackMode) -> Self {
        Self { stack_mode }
    }
}

/// One sensor stack resolved from the kernel stack-trace maps.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RawStack {
    /// Kernel frames, innermost first, exactly as captured (addresses).
    pub kernel: Vec<u64>,
    /// User frames, innermost first, exactly as captured (addresses).
    /// Empty when the sensor/context could not capture a user stack.
    pub user: Vec<u64>,
    /// True when a stack hit the 64-frame map depth.
    pub truncated: bool,
}

impl RawStack {
    /// Total captured frames.
    pub fn len(&self) -> usize {
        self.kernel.len() + self.user.len()
    }

    /// True when no frame was captured.
    pub fn is_empty(&self) -> bool {
        self.kernel.is_empty() && self.user.is_empty()
    }
}

/// Per-sensor stack capture counters summed over all CPUs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct StackCounters {
    /// Stacks successfully stored in the kernel stack-trace map.
    pub kernel_captures: u64,
    /// Kernel captures that failed (most often the stack map is full;
    /// these are the "stack-map drops" reported by `record --stats`).
    pub kernel_failures: u64,
    /// User stacks successfully stored.
    pub user_captures: u64,
    /// User captures that failed.
    pub user_failures: u64,
}

/// Capacity of the stack-trace maps a sensor exposes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct StackMapInfo {
    /// Kernel stack map entry capacity.
    pub entries: u32,
    /// Kernel stack map frames per stack.
    pub frames: u32,
    /// User stack map entry capacity, when the sensor captures user stacks.
    pub user_entries: Option<u32>,
    /// User stack map frames per stack, when available.
    pub user_frames: Option<u32>,
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
    /// A stack map could not be read or configured.
    #[error("stack map error: {0}")]
    Stack(String),
}

/// Load every embedded sensor for the host architecture.
pub fn load_all() -> Result<LoadedSensors, LoaderError> {
    load(&[])
}

/// Load the named sensors with stack capture off (the 0.2 behavior).
///
/// See [`load_with_options`].
pub fn load(names: &[&str]) -> Result<LoadedSensors, LoaderError> {
    load_with_options(names, LoadOptions::default())
}

/// Load the named sensors. An empty slice loads every embedded sensor.
///
/// A sensor that fails to load or attach is recorded in the coverage
/// matrix and omitted from [`LoadedSensors::sensors`]. The call returns
/// an error only when no requested sensor is embedded or when a requested
/// name is unknown.
pub fn load_with_options(
    names: &[&str],
    options: LoadOptions,
) -> Result<LoadedSensors, LoaderError> {
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

    let lsm_bpf_active = bpf_lsm_active();
    let mut loaded = Vec::new();
    let mut coverage_entries = Vec::new();

    for sensor in selected {
        let coverage = load_one(sensor, &mut loaded, lsm_bpf_active, options);
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
        stack_mode: options.stack_mode,
    })
}

/// True when the running kernel has the BPF LSM active.
///
/// On such kernels the file sensor's `lsm/file_open` program observes opens
/// directly. Attaching the syscall-entry `openat` fallback as well would
/// record every successful open twice, so the loader skips the open
/// fallback when the LSM path is available. Kernels without the BPF LSM
/// (for example the pinned Ubuntu cloud kernels) keep the kprobe fallback.
fn bpf_lsm_active() -> bool {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|value| value.split(',').any(|name| name.trim() == "bpf"))
        .unwrap_or(false)
}

fn skips_open_fallback(sensor: &str, section: &str, lsm_bpf_active: bool) -> bool {
    lsm_bpf_active
        && sensor == "file"
        && (section.starts_with("kprobe/__x64_sys_openat")
            || section.starts_with("kprobe/__arm64_sys_openat"))
}

fn load_one(
    sensor: &EmbeddedSensor,
    loaded: &mut Vec<LoadedSensor>,
    lsm_bpf_active: bool,
    options: LoadOptions,
) -> SensorCoverage {
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

    if let Err(error) = configure_stack_mode(&object, sensor.name, options.stack_mode) {
        coverage.errors.push(error);
    }

    let mut links = Vec::new();
    for program in object.progs_mut() {
        let section = program.section().to_string_lossy().into_owned();
        let name = program.name().to_string_lossy().into_owned();
        let label = format!("{section}:{name}");

        if needs_context(&section) || skips_open_fallback(sensor.name, &section, lsm_bpf_active) {
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

/// Find a map by name in a loaded object.
fn sensor_map<'a>(object: &'a Object, name: &str) -> Option<Map<'a>> {
    object
        .maps()
        .find(|map| map.name().to_string_lossy() == name)
}

/// Write the loader-selected stack mode into a sensor's `stack_config`
/// map. Sensors without the map are only an error when capture is
/// enabled: with capture off the 0.2 behavior is preserved even for an
/// object built before the stack feature.
fn configure_stack_mode(object: &Object, sensor: &str, mode: StackMode) -> Result<(), String> {
    let map_name = format!("{sensor}_stack_config");
    let Some(map) = sensor_map(object, &map_name) else {
        if mode.enabled() {
            return Err(format!(
                "{sensor}: object has no {map_name} map; rebuild the sensors"
            ));
        }
        return Ok(());
    };
    let value = mode.bpf_mode().to_ne_bytes();
    map.update(&0u32.to_ne_bytes(), &value, MapFlags::ANY)
        .map_err(|error| format!("{sensor}: cannot set {map_name}: {error}"))
}

/// Decode one stack-trace-map value into frame addresses.
///
/// A stack-trace map value is an array of native-endian 64-bit addresses,
/// innermost frame first, zero-padded after the last frame. Trailing zero
/// words terminate the frame list.
fn decode_stack_frames(raw: &[u8]) -> Vec<u64> {
    let mut frames = Vec::with_capacity(raw.len() / 8);
    for chunk in raw.chunks_exact(8) {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(chunk);
        let addr = u64::from_ne_bytes(bytes);
        if addr == 0 {
            break;
        }
        frames.push(addr);
    }
    frames
}

fn read_stack_frames(map: &Map<'_>, stack_id: u32) -> Result<Vec<u64>, LoaderError> {
    let key = stack_id.to_ne_bytes();
    let raw = map
        .lookup(&key, MapFlags::ANY)
        .map_err(|error| LoaderError::Stack(format!("lookup stack {stack_id}: {error}")))?;
    Ok(raw.as_deref().map(decode_stack_frames).unwrap_or_default())
}

impl LoadedSensors {
    /// Resolve one event's stack handles against a sensor's stack-trace
    /// maps. `kernel_id` is the v2 header `stack_id`; `user_id` is the v2
    /// header `user_stack_id` (both `None` when the corresponding capture
    /// was disabled or failed).
    ///
    /// The returned [`RawStack`] carries the raw kernel and user frame
    /// addresses; the recorder keeps them even when symbolization fails.
    /// A handle whose map entry vanished yields an empty frame list rather
    /// than an error, and a missing user-stack map is treated as "no user
    /// frames" for forward compatibility with kernel-only sensors.
    pub fn read_stack(
        &self,
        sensor: &str,
        kernel_id: Option<i32>,
        user_id: Option<i32>,
    ) -> Result<RawStack, LoaderError> {
        if kernel_id.is_none() && user_id.is_none() {
            return Err(LoaderError::Stack(format!(
                "sensor {sensor} event has no stack handles"
            )));
        }
        let loaded = self
            .sensors
            .iter()
            .find(|loaded| loaded.name == sensor)
            .ok_or_else(|| {
                LoaderError::Stack(format!("sensor {sensor} is not loaded; cannot read stacks"))
            })?;

        let mut kernel = Vec::new();
        let mut user = Vec::new();
        let mut truncated = false;

        if let Some(kernel_id) = kernel_id {
            let stack_map =
                sensor_map(&loaded.object, &format!("{sensor}_stacks")).ok_or_else(|| {
                    LoaderError::Stack(format!("sensor {sensor} has no {sensor}_stacks map"))
                })?;
            kernel = read_stack_frames(&stack_map, kernel_id as u32)?;
            truncated |= kernel.len() >= stack_map.value_size() as usize / 8;
        }
        if let Some(user_id) = user_id {
            if let Some(user_map) = sensor_map(&loaded.object, &format!("{sensor}_user_stacks")) {
                user = read_stack_frames(&user_map, user_id as u32)?;
                truncated |= user.len() >= user_map.value_size() as usize / 8;
            }
        }

        Ok(RawStack {
            kernel,
            user,
            truncated,
        })
    }

    /// Sum the per-CPU stack counters of every loaded sensor.
    ///
    /// `kernel_failures` is the stack-map drop count reported by
    /// `record --stats`; failures are non-fatal and never corrupt an
    /// event (the header keeps `stack_id = -1`).
    pub fn stack_counters(&self) -> std::collections::BTreeMap<String, StackCounters> {
        let mut counters = std::collections::BTreeMap::new();
        for loaded in &self.sensors {
            let Some(map) = sensor_map(&loaded.object, &format!("{}_stack_stats", loaded.name))
            else {
                continue;
            };
            let Ok(Some(per_cpu)) = map.lookup_percpu(&0u32.to_ne_bytes(), MapFlags::ANY) else {
                continue;
            };
            let mut summed = StackCounters::default();
            for cpu in per_cpu {
                for (index, chunk) in cpu.chunks_exact(8).enumerate() {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(chunk);
                    let value = u64::from_ne_bytes(bytes);
                    match index {
                        0 => summed.kernel_captures = summed.kernel_captures.saturating_add(value),
                        1 => summed.kernel_failures = summed.kernel_failures.saturating_add(value),
                        2 => summed.user_captures = summed.user_captures.saturating_add(value),
                        3 => summed.user_failures = summed.user_failures.saturating_add(value),
                        _ => {}
                    }
                }
            }
            counters.insert(loaded.name.clone(), summed);
        }
        counters
    }

    /// Capacity of a sensor's stack-trace maps, for `record --stats`.
    pub fn stack_map_info(&self, sensor: &str) -> Option<StackMapInfo> {
        let loaded = self.sensors.iter().find(|loaded| loaded.name == sensor)?;
        let kernel = sensor_map(&loaded.object, &format!("{sensor}_stacks"))?;
        let user = sensor_map(&loaded.object, &format!("{sensor}_user_stacks"));
        Some(StackMapInfo {
            entries: kernel.max_entries(),
            frames: kernel.value_size() / 8,
            user_entries: user.as_ref().map(|map| map.max_entries()),
            user_frames: user.as_ref().map(|map| map.value_size() / 8),
        })
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
    use super::skips_open_fallback;

    #[test]
    fn skips_open_fallback_only_when_bpf_lsm_is_active() {
        assert!(skips_open_fallback("file", "kprobe/__x64_sys_openat", true));
        assert!(skips_open_fallback(
            "file",
            "kprobe/__x64_sys_openat2",
            true
        ));
        assert!(!skips_open_fallback(
            "file",
            "kprobe/__x64_sys_openat",
            false
        ));
        assert!(!skips_open_fallback("file", "kprobe/__x64_sys_creat", true));
        assert!(!skips_open_fallback(
            "process",
            "kprobe/__x64_sys_openat",
            true
        ));
    }

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

    #[test]
    fn stack_mode_round_trips_and_maps_to_bpf_values() {
        assert_eq!(StackMode::default(), StackMode::Off);
        assert_eq!(StackMode::parse("off"), Some(StackMode::Off));
        assert_eq!(StackMode::parse("events"), Some(StackMode::Events));
        assert_eq!(StackMode::parse("all"), Some(StackMode::All));
        assert_eq!(StackMode::parse("bogus"), None);
        assert_eq!(StackMode::Off.bpf_mode(), 0);
        assert_eq!(StackMode::Events.bpf_mode(), 1);
        assert_eq!(StackMode::All.bpf_mode(), 2);
        assert!(!StackMode::Off.enabled());
        assert!(StackMode::Events.enabled());
        assert!(StackMode::All.enabled());
        assert_eq!(StackMode::Events.to_string(), "events");
        assert_eq!(serde_json::to_string(&StackMode::All).unwrap(), "\"all\"");
        assert_eq!(
            LoadOptions::with_stack_mode(StackMode::Events).stack_mode,
            StackMode::Events
        );
    }

    #[test]
    fn stack_frame_decoding_stops_at_zero_padding() {
        let mut value = [0u8; 512];
        for (index, addr) in [0xffff_ffff_8100_0000u64, 0xffff_ffff_8100_0100, 0x7f00_0000]
            .iter()
            .enumerate()
        {
            value[index * 8..index * 8 + 8].copy_from_slice(&addr.to_ne_bytes());
        }
        let frames = decode_stack_frames(&value);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0], 0xffff_ffff_8100_0000);
        assert_eq!(frames[2], 0x7f00_0000);
    }

    #[test]
    fn stack_frame_decoding_accepts_a_full_depth_stack() {
        let mut value = [0u8; 512];
        for index in 0..64 {
            value[index * 8..index * 8 + 8]
                .copy_from_slice(&(0x1000u64 + index as u64).to_ne_bytes());
        }
        let frames = decode_stack_frames(&value);
        assert_eq!(frames.len(), 64);
    }

    #[test]
    fn empty_stack_value_has_no_frames() {
        assert!(decode_stack_frames(&[0u8; 512]).is_empty());
        assert!(decode_stack_frames(&[]).is_empty());
    }

    #[test]
    fn raw_stack_counts_kernel_and_user_frames() {
        let raw = RawStack {
            kernel: vec![1, 2],
            user: vec![3],
            truncated: false,
        };
        assert_eq!(raw.len(), 3);
        assert!(!raw.is_empty());
        assert!(RawStack::default().is_empty());
    }
}
