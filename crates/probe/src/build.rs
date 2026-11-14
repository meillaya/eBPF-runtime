// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Compile one custom C probe into a CO-RE BPF object.
//!
//! The sensor pipeline (`bpf-build`) and the probe SDK must agree on the
//! compiler and on `vmlinux.h`; they compile different sources with the same
//! flags. This module reuses what `bpf-build` exposes publicly:
//!
//! - [`bpf_build::REQUIRED_CLANG_MAJOR`] for the pinned clang version;
//! - [`bpf_build::target_arch`] for the host architecture;
//! - [`bpf_build::default_out_dir`] (and, when present, its generated
//!   `vmlinux.h`) so a probe build never diverges from the sensor build.
//!
//! `bpf-build` keeps its clang/bpftool discovery private, so the small
//! discovery helpers here mirror its policy instead of forking the sensor
//! pipeline. When `target/bpf-out/vmlinux.h` exists it is used as-is; when it
//! does not (a checkout that never built a sensor) the probe crate generates
//! one cached copy under `target/probe-sdk/include/` and refreshes it when the
//! host BTF is newer. `EBPF_PROBE_VMLINUX_DIR` overrides the include directory
//! for cross-kernel work; `EBPF_REPO_ROOT` is honored like `bpf-build` does.

use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::sync::PoisonError;

use bpf_build::REQUIRED_CLANG_MAJOR;
use thiserror::Error;

/// Path of the host kernel BTF file.
const KERNEL_BTF: &str = "/sys/kernel/btf/vmlinux";

/// Compile flags shared with `bpf-build`. `-Wno-comment` is needed because
/// generated `vmlinux.h` carries comment forms that clang 19 warns about.
const CLANG_FLAGS: &[&str] = &[
    "-O2",
    "-g",
    "-Wall",
    "-Wno-missing-declarations",
    "-Wno-address-of-packed-member",
    "-Wno-comment",
    "-target",
    "bpf",
];

/// One compiled probe object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildArtifact {
    /// The C source that was compiled.
    pub source: PathBuf,
    /// The CO-RE object that clang wrote.
    pub object: PathBuf,
    /// The clang binary that was used.
    pub clang: PathBuf,
    /// Architecture artifact name, `amd64` or `arm64`.
    pub arch: String,
    /// Include directories passed to clang, in search order.
    pub include_dirs: Vec<PathBuf>,
    /// Object size in bytes.
    pub size_bytes: u64,
}

/// Errors from a probe build.
#[derive(Debug, Error)]
pub enum BuildError {
    /// The probe source does not exist.
    #[error("probe source {0} does not exist")]
    MissingSource(PathBuf),
    /// A caller-supplied include directory does not exist.
    #[error("include directory {0} does not exist")]
    MissingIncludeDir(PathBuf),
    /// A required tool was not found or returned no usable version.
    #[error("toolchain error: {0}")]
    Toolchain(String),
    /// clang is present but not the pinned major version.
    #[error("clang {found} is not supported; the fleet builds BPF with clang {required}. clang 20 and newer emit a memcpy extern that libbpf cannot resolve on the supported kernels")]
    UnsupportedClang {
        /// Major version found.
        found: u32,
        /// Major version required.
        required: u32,
    },
    /// The host has no readable kernel BTF and no cached `vmlinux.h`.
    #[error("kernel BTF is not readable at /sys/kernel/btf/vmlinux; install a kernel with CONFIG_DEBUG_INFO_BTF and mount debugfs, or point EBPF_PROBE_VMLINUX_DIR at a directory containing vmlinux.h")]
    BtfUnavailable,
    /// The configured `vmlinux.h` location has no `vmlinux.h`.
    #[error("{path} is missing; rebuild the sensors with `cargo run -p bpf-build -- build` or remove EBPF_PROBE_VMLINUX_DIR")]
    MissingVmlinux {
        /// Expected `vmlinux.h` path.
        path: PathBuf,
    },
    /// clang rejected the probe source.
    #[error("clang failed for {path}:\n{stderr}")]
    Compile {
        /// Source that failed.
        path: PathBuf,
        /// Captured clang diagnostics.
        stderr: String,
    },
    /// clang reported success but wrote no object.
    #[error("clang reported success but wrote no object at {0}")]
    MissingOutput(PathBuf),
    /// A file operation failed.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Repository root: `EBPF_REPO_ROOT` when set, otherwise the compile-time
/// parent of the `crates/probe` crate.
pub fn workspace_root() -> PathBuf {
    if let Some(root) = std::env::var_os("EBPF_REPO_ROOT") {
        return PathBuf::from(root);
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| manifest.to_path_buf(), Path::to_path_buf)
}

/// Default probe output directory, `<workspace>/target/probe-sdk`.
pub fn default_out_dir() -> PathBuf {
    workspace_root().join("target/probe-sdk")
}

/// Compile `source` into `output` as a CO-RE BPF object.
///
/// `include_dirs` are appended after the SDK include directories. The source
/// is compiled with the pinned clang 19 using `-target bpf -g -O2` and
/// `-D__TARGET_ARCH_<host>`, against the same `vmlinux.h` the sensor build
/// uses. The output parent directory is created when missing.
///
/// The call is build-only: it never loads, verifies, or attaches the object.
/// Use [`crate::verify`] for the kernel verifier step.
///
/// # Errors
///
/// Returns [`BuildError`] when the source/include directory is missing, the
/// pinned toolchain is unavailable, the kernel BTF cannot be found, or clang
/// rejects the source. The returned error carries the full clang stderr on a
/// compile failure.
pub fn build(
    source: &Path,
    output: &Path,
    include_dirs: &[PathBuf],
) -> Result<BuildArtifact, BuildError> {
    if !source.is_file() {
        return Err(BuildError::MissingSource(source.to_path_buf()));
    }
    for include_dir in include_dirs {
        if !include_dir.is_dir() {
            return Err(BuildError::MissingIncludeDir(include_dir.clone()));
        }
    }

    let clang = find_clang()?;
    let arch =
        bpf_build::target_arch().map_err(|error| BuildError::Toolchain(error.to_string()))?;
    let arch_macro = arch_macro(&arch)?;

    let mut resolved_include_dirs = Vec::with_capacity(include_dirs.len() + 3);
    resolved_include_dirs.push(vmlinux_dir()?);
    let sdk_headers = workspace_root().join("sdk/include");
    if sdk_headers.is_dir() {
        resolved_include_dirs.push(sdk_headers);
    }
    let fleet_headers = workspace_root().join("bpf/include");
    if fleet_headers.is_dir() {
        resolved_include_dirs.push(fleet_headers);
    }
    resolved_include_dirs.extend(include_dirs.iter().cloned());

    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let mut command = Command::new(&clang);
    command.args(CLANG_FLAGS);
    command.arg(format!("-D__TARGET_ARCH_{arch_macro}"));
    for include_dir in &resolved_include_dirs {
        command.arg(format!("-I{}", include_dir.display()));
    }
    let result = command
        .arg("-c")
        .arg(source)
        .arg("-o")
        .arg(output)
        .output()?;

    if !result.status.success() {
        return Err(BuildError::Compile {
            path: source.to_path_buf(),
            stderr: String::from_utf8_lossy(&result.stderr).trim().to_string(),
        });
    }

    let size_bytes = fs::metadata(output)?.len();
    if size_bytes == 0 {
        return Err(BuildError::MissingOutput(output.to_path_buf()));
    }

    Ok(BuildArtifact {
        source: source.to_path_buf(),
        object: output.to_path_buf(),
        clang,
        arch,
        include_dirs: resolved_include_dirs,
        size_bytes,
    })
}

/// Directory that holds the `vmlinux.h` used for a probe build.
///
/// Order: `EBPF_PROBE_VMLINUX_DIR`, then the sensor build's
/// `target/bpf-out`, then a cached copy under `target/probe-sdk/include`
/// generated from the host BTF.
fn vmlinux_dir() -> Result<PathBuf, BuildError> {
    if let Some(dir) = std::env::var_os("EBPF_PROBE_VMLINUX_DIR") {
        let dir = PathBuf::from(dir);
        if dir.join("vmlinux.h").is_file() {
            return Ok(dir);
        }
        return Err(BuildError::MissingVmlinux {
            path: dir.join("vmlinux.h"),
        });
    }

    let sensor_out = bpf_build::default_out_dir();
    if sensor_out.join("vmlinux.h").is_file() {
        return Ok(sensor_out);
    }

    cached_vmlinux_dir()
}

/// Cached `vmlinux.h` generation, serialized so parallel tests do not write
/// the same file twice.
fn cached_vmlinux_dir() -> Result<PathBuf, BuildError> {
    static VMLINUX_LOCK: Mutex<()> = Mutex::new(());

    let dir = default_out_dir().join("include");
    let vmlinux = dir.join("vmlinux.h");
    let _guard = VMLINUX_LOCK.lock().unwrap_or_else(PoisonError::into_inner);

    if vmlinux.is_file() && !vmlinux_is_stale(&vmlinux) {
        return Ok(dir);
    }
    generate_vmlinux(&vmlinux)?;
    Ok(dir)
}

/// True when the host BTF is newer than the cached `vmlinux.h`.
fn vmlinux_is_stale(vmlinux: &Path) -> bool {
    let Ok(btf_metadata) = fs::metadata(KERNEL_BTF) else {
        return false;
    };
    let Ok(vmlinux_metadata) = fs::metadata(vmlinux) else {
        return true;
    };
    match (btf_metadata.modified(), vmlinux_metadata.modified()) {
        (Ok(btf_time), Ok(vmlinux_time)) => vmlinux_time < btf_time,
        _ => false,
    }
}

/// Generate `vmlinux.h` with bpftool, the same command `bpf-build` runs.
fn generate_vmlinux(vmlinux: &Path) -> Result<(), BuildError> {
    let btf = Path::new(KERNEL_BTF);
    if !btf.is_file() {
        return Err(BuildError::BtfUnavailable);
    }
    let bpftool = find_bpftool()?;
    let output = Command::new(&bpftool)
        .args(["btf", "dump", "file"])
        .arg(btf)
        .args(["format", "c"])
        .output()?;
    if !output.status.success() {
        return Err(BuildError::Toolchain(format!(
            "bpftool btf dump failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    if let Some(parent) = vmlinux.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(vmlinux, &output.stdout)?;
    if fs::metadata(vmlinux)
        .map(|metadata| metadata.len())
        .unwrap_or(0)
        == 0
    {
        return Err(BuildError::BtfUnavailable);
    }
    Ok(())
}

/// Find clang and require the pinned major version.
fn find_clang() -> Result<PathBuf, BuildError> {
    let mut candidates = Vec::new();
    if let Ok(clang) = std::env::var("CLANG") {
        candidates.push(PathBuf::from(clang));
    }
    candidates.push(PathBuf::from("clang-19"));
    candidates.push(PathBuf::from("/usr/lib/llvm19/bin/clang"));
    candidates.push(PathBuf::from("clang"));

    let mut found_other = None;
    for candidate in candidates {
        let output = match Command::new(&candidate).arg("--version").output() {
            Ok(output) if output.status.success() => output,
            _ => continue,
        };
        let text = String::from_utf8_lossy(&output.stdout);
        match parse_clang_major(&text) {
            Some(REQUIRED_CLANG_MAJOR) => return Ok(candidate),
            Some(found) => {
                found_other.get_or_insert(found);
            }
            None => {
                return Err(BuildError::Toolchain(format!(
                    "could not parse the version of {}",
                    candidate.display()
                )))
            }
        }
    }

    if let Some(found) = found_other {
        return Err(BuildError::UnsupportedClang {
            found,
            required: REQUIRED_CLANG_MAJOR,
        });
    }
    Err(BuildError::Toolchain(
        "clang 19 not found; set CLANG to a clang 19 binary".to_string(),
    ))
}

/// Find a usable bpftool, used only when a cached `vmlinux.h` must be made.
fn find_bpftool() -> Result<PathBuf, BuildError> {
    let candidates = [
        std::env::var("BPFTOOL").ok().map(PathBuf::from),
        Some(PathBuf::from("bpftool")),
    ];
    for candidate in candidates.into_iter().flatten() {
        let works = Command::new(&candidate)
            .arg("version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);
        if works {
            return Ok(candidate);
        }
    }
    Err(BuildError::Toolchain(
        "bpftool not found; install bpftool or set BPFTOOL".to_string(),
    ))
}

/// Parse the major version from `clang --version` output.
fn parse_clang_major(version_output: &str) -> Option<u32> {
    if !version_output.to_ascii_lowercase().contains("clang") {
        return None;
    }
    let mut words = version_output.split_whitespace();
    while let Some(word) = words.next() {
        if word == "version" {
            let version = words.next()?;
            let major = version.split('.').next()?;
            return major.parse().ok();
        }
    }
    None
}

/// Map an artifact architecture name to the clang target macro suffix.
fn arch_macro(arch: &str) -> Result<&'static str, BuildError> {
    match arch {
        "amd64" => Ok("x86"),
        "arm64" => Ok("arm64"),
        other => Err(BuildError::Toolchain(format!(
            "unsupported target architecture `{other}`"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_clang_version_line() {
        assert_eq!(parse_clang_major("clang version 19.1.7"), Some(19));
        assert_eq!(
            parse_clang_major("Ubuntu clang version 18.1.3 (1ubuntu1)"),
            Some(18)
        );
        assert_eq!(parse_clang_major("gcc version 15.1.0"), None);
    }

    #[test]
    fn unsupported_arch_is_rejected() {
        assert!(arch_macro("riscv64").is_err());
        assert_eq!(arch_macro("amd64").expect("amd64"), "x86");
        assert_eq!(arch_macro("arm64").expect("arm64"), "arm64");
    }

    #[test]
    fn workspace_root_is_the_repository() {
        let root = workspace_root();
        assert!(root.join("sdk/include/fleet_probe.h").is_file());
        assert!(root.join("sdk/examples/hello_probe.bpf.c").is_file());
        assert!(root.join("bpf/sensors").is_dir());
    }

    #[test]
    fn default_out_dir_is_under_target() {
        assert!(default_out_dir().ends_with("target/probe-sdk"));
    }

    #[test]
    fn missing_source_is_rejected() {
        let output = default_out_dir().join("tests/never-built.bpf.o");
        let error = build(Path::new("/nonexistent/probe.bpf.c"), &output, &[]);
        assert!(matches!(error, Err(BuildError::MissingSource(_))));
    }

    #[test]
    fn compile_error_carries_clang_stderr() {
        let dir = default_out_dir().join("tests");
        fs::create_dir_all(&dir).expect("create test output directory");
        let source = dir.join("broken.bpf.c");
        fs::write(
            &source,
            "#include \"fleet_probe.h\"\nint broken(void) { return missing_symbol(); }\n",
        )
        .expect("write fixture");
        let output = dir.join("broken.bpf.o");
        match build(&source, &output, &[]) {
            Err(BuildError::Compile { stderr, .. }) => {
                assert!(stderr.contains("error"), "clang stderr: {stderr}");
            }
            other => panic!("expected a clang compile error, got {other:?}"),
        }
    }

    #[test]
    fn missing_include_dir_is_rejected() {
        let source = workspace_root().join("sdk/examples/hello_probe.bpf.c");
        let output = default_out_dir().join("tests/never-built.bpf.o");
        let include = PathBuf::from("/nonexistent/probe-sdk-include");
        let error = build(&source, &output, &[include]);
        assert!(matches!(error, Err(BuildError::MissingIncludeDir(_))));
    }

    /// The SDK example must compile with the pinned host clang 19. This test
    /// runs in `nix develop` (the same requirement as the sensor build) and
    /// does not need root: building an object is a userspace operation.
    #[test]
    fn builds_the_example_probe() {
        let source = workspace_root().join("sdk/examples/hello_probe.bpf.c");
        let output = default_out_dir().join("tests/hello_probe.bpf.o");
        let artifact = build(&source, &output, &[]).expect("the example probe must compile");

        assert_eq!(artifact.source, source);
        assert_eq!(artifact.object, output);
        assert!(artifact.size_bytes > 0);
        assert!(artifact.arch == "amd64" || artifact.arch == "arm64");
        assert!(artifact
            .include_dirs
            .iter()
            .any(|dir| dir.join("vmlinux.h").is_file()));

        let bytes = fs::read(&artifact.object).expect("the object must be readable");
        assert_eq!(&bytes[..4], b"\x7fELF", "the output must be an ELF object");
        assert!(
            bytes
                .windows(b"hello_events".len())
                .any(|window| window == b"hello_events"),
            "the ring buffer map name must be in the object"
        );
    }
}
