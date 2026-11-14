// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Compile the C sensor programs in `bpf/sensors` into CO-RE objects.
//!
//! The build runs clang once per sensor and writes a manifest with the
//! compiler version, the kernel BTF digest, and a SHA-256 for each object.
//!
//! There is no pinned kernel BTF digest. A CO-RE object is valid on any
//! kernel whose BTF has the fields the sensor reads. Pinning one digest
//! made the build fail on every machine except the one that recorded it.
//!
//! clang 20 and newer lower large `__builtin_memcpy` calls to an
//! unresolved `memcpy` extern. libbpf cannot resolve that extern against
//! the kernel BTF on the kernels tested here, so the object fails to
//! open. The build rejects a compiler other than clang 19 instead of
//! producing an object that cannot load.

use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Every sensor the build compiles.
pub const SENSORS: &[&str] = &["process", "file"];

/// The clang major version this build supports.
pub const REQUIRED_CLANG_MAJOR: u32 = 19;

/// One compiled BPF object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfArtifact {
    /// Sensor name, for example `process`.
    pub sensor: String,
    /// Architecture name used for the artifact file, `amd64` or `arm64`.
    pub arch: String,
    /// Source file the object came from.
    pub source: PathBuf,
    /// Compiled object.
    pub object: PathBuf,
    /// SHA-256 of the object bytes, lower-case hex.
    pub sha256: String,
}

/// Errors from the build.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// A required tool was not found or returned no version.
    #[error("toolchain error: {0}")]
    Toolchain(String),
    /// clang is present but not the supported major version.
    #[error("clang {found} is not supported; this build requires clang {required}. clang 20 and newer emit a memcpy extern that libbpf cannot resolve on the supported kernels")]
    UnsupportedClang {
        /// Major version found.
        found: u32,
        /// Major version required.
        required: u32,
    },
    /// The running kernel does not expose BTF.
    #[error("kernel BTF is not readable at /sys/kernel/btf/vmlinux; install a kernel with CONFIG_DEBUG_INFO_BTF and mount debugfs")]
    BtfUnavailable,
    /// A sensor failed to compile.
    #[error("clang failed for {sensor}:\n{stderr}")]
    Compile {
        /// Sensor that failed.
        sensor: String,
        /// Captured stderr from clang.
        stderr: String,
    },
    /// clang reported success but wrote no object.
    #[error("clang wrote no object for {sensor} at {path}")]
    MissingOutput {
        /// Sensor that produced no output.
        sensor: String,
        /// Expected output path.
        path: PathBuf,
    },
    /// A file operation failed.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Compile every sensor for the target architecture into the default
/// directory, `target/bpf-out`.
pub fn build() -> Result<Vec<BpfArtifact>, BuildError> {
    build_to(&default_out_dir())
}

/// Compile every sensor for the target architecture into `out_dir`.
pub fn build_to(out_dir: &Path) -> Result<Vec<BpfArtifact>, BuildError> {
    let root = repo_root();
    let sensors_dir = root.join("bpf/sensors");
    let include_dir = root.join("bpf/include");

    fs::create_dir_all(out_dir)?;

    let clang = find_clang()?;
    let bpftool = find_bpftool()?;
    let arch = target_arch()?;
    let arch_macro = arch_macro(&arch)?;

    write_vmlinux(&bpftool, out_dir)?;
    strip_libbpf_1_6_conflicts(&out_dir.join("vmlinux.h"))?;
    let btf_sha = sha256_file(Path::new("/sys/kernel/btf/vmlinux")).ok();

    let mut artifacts = Vec::with_capacity(SENSORS.len());
    for sensor in SENSORS {
        let source = sensors_dir.join(format!("{sensor}.bpf.c"));
        if !source.is_file() {
            return Err(BuildError::Toolchain(format!(
                "missing sensor source {}",
                source.display()
            )));
        }

        let object = out_dir.join(format!("{sensor}.{arch}.bpf.o"));
        let mut args: Vec<String> = vec![
            "-O2".to_string(),
            "-g".to_string(),
            "-Wall".to_string(),
            "-Wno-missing-declarations".to_string(),
            "-Wno-address-of-packed-member".to_string(),
            "-Wno-comment".to_string(),
            "-target".to_string(),
            "bpf".to_string(),
            format!("-D__TARGET_ARCH_{arch_macro}"),
            format!("-I{}", include_dir.display()),
            format!("-I{}", out_dir.display()),
        ];
        for include in libbpf_include_dirs() {
            args.push(format!("-I{}", include.display()));
        }
        args.push("-c".to_string());
        let output = Command::new(&clang)
            .args(&args)
            .arg(&source)
            .arg("-o")
            .arg(&object)
            .output()?;

        if !output.status.success() {
            return Err(BuildError::Compile {
                sensor: (*sensor).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }

        if fs::metadata(&object).map(|m| m.len()).unwrap_or(0) == 0 {
            return Err(BuildError::MissingOutput {
                sensor: (*sensor).to_string(),
                path: object,
            });
        }

        artifacts.push(BpfArtifact {
            sensor: (*sensor).to_string(),
            arch: arch.clone(),
            source,
            sha256: sha256_file(&object)?,
            object,
        });
    }

    write_manifest(
        out_dir,
        &clang,
        &bpftool,
        &arch,
        btf_sha.as_deref(),
        &artifacts,
    )?;
    Ok(artifacts)
}

/// Path of the build manifest written by [`build_to`].
pub fn manifest_path() -> PathBuf {
    default_out_dir().join("bpf-build.manifest.json")
}

/// Default output directory, `<workspace>/target/bpf-out`.
pub fn default_out_dir() -> PathBuf {
    repo_root().join("target/bpf-out")
}

/// Architecture name used in artifact file names.
pub fn target_arch() -> Result<String, BuildError> {
    let raw = std::env::var("CARGO_CFG_TARGET_ARCH")
        .unwrap_or_else(|_| std::env::consts::ARCH.to_string());
    match raw.as_str() {
        "x86_64" => Ok("amd64".to_string()),
        "aarch64" => Ok("arm64".to_string()),
        other => Err(BuildError::Toolchain(format!(
            "unsupported target architecture `{other}`; sensors build for x86_64 and aarch64"
        ))),
    }
}

fn repo_root() -> PathBuf {
    if let Ok(root) = std::env::var("EBPF_REPO_ROOT") {
        return PathBuf::from(root);
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or(manifest_dir)
}

fn arch_macro(arch: &str) -> Result<&'static str, BuildError> {
    match arch {
        "amd64" => Ok("x86"),
        "arm64" => Ok("arm64"),
        other => Err(BuildError::Toolchain(format!(
            "unsupported artifact architecture `{other}`"
        ))),
    }
}

/// Include directories that provide libbpf's BPF helper headers.
///
/// `bpf-build` invokes clang directly, so it cannot rely on a compiler
/// wrapper's implicit Nix include flags. Ask pkg-config for libbpf's include
/// path; fall back to the standard system path when pkg-config is absent.
/// This keeps sensor builds working in CI as well as inside the Nix shell.
pub fn libbpf_include_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(output) = Command::new("pkg-config")
        .args(["--cflags-only-I", "libbpf"])
        .output()
    {
        if output.status.success() {
            for token in String::from_utf8_lossy(&output.stdout).split_whitespace() {
                if let Some(path) = token.strip_prefix("-I") {
                    dirs.push(PathBuf::from(path));
                }
            }
        }
    }
    if dirs.is_empty() && Path::new("/usr/include/bpf/bpf_helpers.h").is_file() {
        dirs.push(PathBuf::from("/usr/include"));
    }
    dirs
}

fn find_clang() -> Result<PathBuf, BuildError> {
    let mut candidates = Vec::new();
    if let Ok(clang) = std::env::var("CLANG") {
        candidates.push(PathBuf::from(clang));
    }
    candidates.push(PathBuf::from("clang-19"));
    candidates.push(PathBuf::from("/usr/lib/llvm19/bin/clang"));
    candidates.push(PathBuf::from("clang"));

    let mut seen = Vec::new();
    for candidate in candidates {
        let output = match Command::new(&candidate).arg("--version").output() {
            Ok(output) if output.status.success() => output,
            _ => continue,
        };
        let text = String::from_utf8_lossy(&output.stdout);
        match parse_clang_major(&text) {
            Some(REQUIRED_CLANG_MAJOR) => return Ok(candidate),
            Some(found) => seen.push(found),
            None => {
                return Err(BuildError::Toolchain(format!(
                    "could not parse the version of {}",
                    candidate.display()
                )))
            }
        }
    }

    if let Some(found) = seen.first() {
        return Err(BuildError::UnsupportedClang {
            found: *found,
            required: REQUIRED_CLANG_MAJOR,
        });
    }
    Err(BuildError::Toolchain(
        "clang 19 not found; set CLANG to a clang 19 binary".to_string(),
    ))
}

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

fn find_bpftool() -> Result<PathBuf, BuildError> {
    let candidates = [
        std::env::var("BPFTOOL").ok().map(PathBuf::from),
        Some(PathBuf::from("bpftool")),
    ];
    for candidate in candidates.into_iter().flatten() {
        if Command::new(&candidate)
            .arg("version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
        {
            return Ok(candidate);
        }
    }
    Err(BuildError::Toolchain(
        "bpftool not found; install bpftool or set BPFTOOL".to_string(),
    ))
}

fn write_vmlinux(bpftool: &Path, out_dir: &Path) -> Result<(), BuildError> {
    let btf = Path::new("/sys/kernel/btf/vmlinux");
    if !btf.is_file() {
        return Err(BuildError::BtfUnavailable);
    }

    let output = Command::new(bpftool)
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

    let vmlinux = out_dir.join("vmlinux.h");
    fs::write(&vmlinux, output.stdout)?;
    if fs::metadata(&vmlinux).map(|m| m.len()).unwrap_or(0) == 0 {
        return Err(BuildError::BtfUnavailable);
    }
    Ok(())
}

/// Remove kernel kfunc declarations that conflict with the libbpf headers
/// shipped by older nixpkgs revisions.
///
/// libbpf 1.6's `bpf_helpers.h` declares `bpf_stream_vprintk` without the
/// `__weak __ksym` attributes that newer `vmlinux.h` files carry, so clang
/// reports conflicting types. The sensors do not call this kfunc; dropping
/// the generated declaration keeps CO-RE builds working with both the older
/// Nix libbpf and the newer Arch/container libbpf.
fn strip_libbpf_1_6_conflicts(path: &Path) -> Result<(), BuildError> {
    let text = fs::read_to_string(path)?;
    if !text.contains("bpf_stream_vprintk") {
        return Ok(());
    }
    let filtered: String = text
        .lines()
        .filter(|line| !line.contains("bpf_stream_vprintk"))
        .map(|line| format!("{line}\n"))
        .collect();
    fs::write(path, filtered)?;
    Ok(())
}

fn write_manifest(
    out_dir: &Path,
    clang: &Path,
    bpftool: &Path,
    arch: &str,
    btf_sha: Option<&str>,
    artifacts: &[BpfArtifact],
) -> Result<(), BuildError> {
    let mut json = String::from("{\n");
    json.push_str("  \"schema_version\": 1,\n");
    json.push_str(&format!("  \"arch\": \"{arch}\",\n"));
    json.push_str(&format!(
        "  \"clang\": \"{}\",\n",
        json_escape(&clang.display().to_string())
    ));
    json.push_str(&format!(
        "  \"clang_version\": \"{}\",\n",
        json_escape(clang_version(clang).as_deref().unwrap_or("unknown"))
    ));
    json.push_str(&format!(
        "  \"bpftool\": \"{}\",\n",
        json_escape(&bpftool.display().to_string())
    ));
    json.push_str(&format!(
        "  \"vmlinux_btf_sha256\": \"{}\",\n",
        btf_sha.unwrap_or("unavailable")
    ));
    json.push_str("  \"sensors\": [\n");
    for (index, artifact) in artifacts.iter().enumerate() {
        let comma = if index + 1 == artifacts.len() {
            ""
        } else {
            ","
        };
        json.push_str(&format!(
            "    {{\"sensor\": \"{}\", \"source\": \"{}\", \"object\": \"{}\", \"sha256\": \"{}\"}}{comma}\n",
            artifact.sensor,
            json_escape(&artifact.source.display().to_string()),
            json_escape(&artifact.object.display().to_string()),
            artifact.sha256,
        ));
    }
    json.push_str("  ]\n}\n");
    fs::write(out_dir.join("bpf-build.manifest.json"), json)?;
    Ok(())
}

fn clang_version(clang: &Path) -> Option<String> {
    let output = Command::new(clang).arg("--version").output().ok()?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .map(str::trim)
        .map(str::to_string)
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let bytes = fs::read(path)?;
    let digest = Sha256::digest(&bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    Ok(hex)
}

fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_declared_sensor_has_a_source_file() {
        let root = repo_root();
        for sensor in SENSORS {
            let source = root.join("bpf/sensors").join(format!("{sensor}.bpf.c"));
            assert!(source.is_file(), "missing {}", source.display());
        }
    }

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
    fn target_arch_is_known() {
        let arch = target_arch().expect("host architecture must be supported");
        assert!(arch == "amd64" || arch == "arm64");
        assert!(arch_macro(&arch).is_ok());
    }

    #[test]
    fn unsupported_arch_is_rejected() {
        assert!(arch_macro("riscv64").is_err());
    }

    #[test]
    fn manifest_path_is_in_workspace_target() {
        assert!(manifest_path().ends_with("target/bpf-out/bpf-build.manifest.json"));
    }
}
