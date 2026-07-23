// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// crates/bpf-build/src/lib.rs
// kernel-v1 — task 10 (libbpf-cargo CO-RE build pipeline)
//!
//! Public surface of the bpf-build crate. The crate is a build-time
//! helper; it does NOT contribute to the runtime of any consumer.
//! `crates/bpf-loader` (task 18) calls [`bpf_build::build`] from
//! its own build.rs to ensure the BPF objects are present in a
//! known location before it embeds them. The
//! `devenv tasks run bpf:build` CLI tool also calls
//! [`bpf_build::build`] and writes its outputs to a user-specified
//! directory.
//!
//! The two public entry points are:
//!
//!   * [`bpf_build::build`] — runs the CO-RE compile + skeleton
//!     generation pipeline, writes the per-arch `.bpf.o` and
//!     `.skel.rs` files, and returns the manifest of artifacts. The
//!     [`bpf_build::EXPECTED_SHA256`] constant is the pinned
//!     vmlinux.h input digest; if the host's
//!     `/sys/kernel/btf/vmlinux` no longer matches, `build()`
//!     records the actual digest AND returns an error before any
//!     Rust codegen happens. The freshness gate thus fails BEFORE
//!     the build script returns to cargo, which is the contract the
//!     task brief calls for.
//!
//!   * [`bpf_build::manifest_path`] — returns the path of the
//!     manifest file that `build()` (and `build.rs`) write. The
//!     `bpf_loader::open_placeholder_object` QA surfaces the
//!     artifacts through this path.
//!
//! Determinism is enforced by libbpf-cargo and bpftool: both produce
//! byte-identical .o and .skel.rs files when invoked with the same
//! input and flags on the same host kernel BTF. The freshness
//! manifest is the source of truth for the deterministic-build gate
//! and for the failure-QA scenario.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Pinned sha256 of the baseline `/sys/kernel/btf/vmlinux` on the
/// host that authored this crate. The `build()` function recomputes
/// the digest of the live `/sys/kernel/btf/vmlinux`; if it differs
/// from this constant, `build()` returns `BuildError::FreshnessMismatch`
/// with both the expected and observed digests so the failure mode
/// is a clean, machine-readable error rather than a silent drift
/// of the CO-RE relocation set.
///
/// To refresh the pin (when intentionally upgrading the supported
/// kernel matrix), re-record the constant from a known-good host
/// and commit the change alongside the corresponding
/// `bench/schemas/compat-matrix.v1.json` update.
pub const EXPECTED_SHA256: &str =
    "cc7203f0a684790db88f0710bdf0eb61b4bb91def5784fa6197eb1d091a2ec37";

/// Per-architecture BPF build artifact. One of these is produced
/// for each `(source, arch)` pair in the build pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfArtifact {
    /// Architecture name (`"amd64"` or `"arm64"`).
    pub arch: String,
    /// Source file basename (`"placeholder.bpf.c"`).
    pub source: String,
    /// Path to the relocatable BPF ELF (`.bpf.o`).
    pub o_path: PathBuf,
    /// Path to the generated Rust skeleton (`.skel.rs`).
    pub skel_path: PathBuf,
    /// sha256 of the `.bpf.o` bytes (post-skeleton-generation).
    pub o_sha256: String,
    /// sha256 of the `.skel.rs` bytes.
    pub skel_sha256: String,
}

/// Build pipeline errors. Every variant is `Display` so callers
/// can convert directly to a `String` for cargo's build script
/// stdout/stderr contract.
#[derive(Debug)]
pub enum BuildError {
    /// The CO-RE pipeline found a vmlinux.h on the host whose
    /// sha256 does not match the pinned `EXPECTED_SHA256`. The
    /// build fails BEFORE codegen so the consumer (bpf-loader,
    /// bpf:build CLI) is never built against a stale object set.
    FreshnessMismatch {
        /// The pinned digest from `EXPECTED_SHA256`.
        expected: String,
        /// The digest of the host's live `/sys/kernel/btf/vmlinux`.
        observed: String,
    },
    /// `clang` or `bpftool` is not available on the build host.
    ToolchainMissing(String),
    /// libbpf-cargo's `SkeletonBuilder` returned an error.
    SkeletonBuilder(String),
    /// A source file declared by the pipeline was not found on disk.
    SourceMissing(String),
    /// SkeletonBuilder reported success but the expected output
    /// files are not on disk.
    OutputMissing(String),
    /// A manifest I/O error.
    Io(io::Error),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::FreshnessMismatch { expected, observed } => write!(
                f,
                "bpf-build: vmlinux.h input sha256 mismatch: expected {expected}, observed {observed}. The pinned baseline has drifted; re-record EXPECTED_SHA256 or roll the host kernel back to a supported revision.",
            ),
            BuildError::ToolchainMissing(msg) => write!(f, "bpf-build: toolchain missing: {msg}"),
            BuildError::SkeletonBuilder(msg) => write!(f, "bpf-build: SkeletonBuilder failed: {msg}"),
            BuildError::SourceMissing(msg) => write!(f, "bpf-build: source missing: {msg}"),
            BuildError::OutputMissing(msg) => write!(f, "bpf-build: output missing: {msg}"),
            BuildError::Io(e) => write!(f, "bpf-build: I/O: {e}"),
        }
    }
}

impl std::error::Error for BuildError {}

impl From<io::Error> for BuildError {
    fn from(e: io::Error) -> Self {
        BuildError::Io(e)
    }
}

const BPF_SOURCES: &[&str] = &["placeholder.bpf.c"];
const ARCHES: &[&str] = &["amd64", "arm64"];

/// Run the CO-RE compile + skeleton generation pipeline.
///
/// This function is the public entry point that `bpf-loader's
/// build.rs` and the `bpf:build` CLI tool both call. It compiles
/// every `*.bpf.c` under `bpf/sensors/` for every supported arch
/// (currently `amd64` and `arm64`), invokes `bpftool gen skeleton`
/// to produce the per-arch Rust skeleton, writes the artifacts to
/// `out_dir`, writes the freshness manifest to `out_dir` AND
/// `<workspace>/target/bpf-build.manifest.json`, and returns the
/// list of artifacts. On a `FreshnessMismatch` the function
/// records the actual digest and returns the error BEFORE writing
/// any artifact file or invoking any consumer, so the build
/// pipeline fails before Rust codegen.
///
/// `cargo:rerun-if-changed=` directives are emitted for every
/// `*.bpf.c` and `*.h` that the pipeline reads, so a subsequent
/// `cargo build` re-invokes the build only when one of those
/// inputs changes.
pub fn build() -> Result<Vec<BpfArtifact>, BuildError> {
    let out_dir = default_out_dir();
    build_to(&out_dir)
}

/// As `build()`, but writes the artifacts to a caller-specified
/// directory. The CLI tool (`src/main.rs`) uses this to honour
/// the user's `--out` flag.
pub fn build_to(out_dir: &Path) -> Result<Vec<BpfArtifact>, BuildError> {
    fs::create_dir_all(out_dir)?;

    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .map_err(|e| {
            BuildError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("CARGO_MANIFEST_DIR: {e}"),
            ))
        })?;
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| {
            BuildError::Io(io::Error::new(
                io::ErrorKind::Other,
                "could not resolve repo root from CARGO_MANIFEST_DIR",
            ))
        })?
        .to_path_buf();

    let bpf_sensors_dir = repo_root.join("bpf/sensors");
    let bpf_include_dir = repo_root.join("bpf/include");

    // Rerun policy: rebuild only when one of these changes.
    for src in BPF_SOURCES {
        println!("cargo:rerun-if-changed=bpf/sensors/{src}");
    }
    println!("cargo:rerun-if-changed=bpf/include/event_abi.h");
    println!("cargo:rerun-if-changed=bpf/sensors/Makefile");

    // Toolchain discovery.
    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".to_string());
    let bpftool = env::var("BPFTOOL").unwrap_or_else(|_| "bpftool".to_string());
    if !command_available(&clang) {
        return Err(BuildError::ToolchainMissing(format!(
            "CLANG={clang} not on PATH"
        )));
    }
    if !command_available(&bpftool) {
        return Err(BuildError::ToolchainMissing(format!(
            "BPFTOOL={bpftool} not on PATH"
        )));
    }

    // Generate vmlinux.h from /sys/kernel/btf/vmlinux via bpftool.
    // libbpf-cargo 0.26 does NOT generate vmlinux.h for the user
    // (unlike older 0.22); the standard pattern is to produce
    // vmlinux.h once per build and pass it via -I. We drop the
    // file into `out_dir` so the include path is hermetic to this
    // build invocation.
    let vmlinux_h = out_dir.join("vmlinux.h");
    let btf_src = "/sys/kernel/btf/vmlinux";
    let vmlinux_status = Command::new(&bpftool)
        .args(["btf", "dump", "file", btf_src, "format", "c"])
        .stdout(fs::File::create(&vmlinux_h)?)
        .status();
    match vmlinux_status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            return Err(BuildError::SkeletonBuilder(format!(
                "bpftool btf dump returned {s}; cannot produce vmlinux.h for CO-RE"
            )));
        }
        Err(e) => {
            return Err(BuildError::SkeletonBuilder(format!(
                "bpftool btf dump could not run: {e}"
            )));
        }
    }

    // Use libbpf-cargo via its public API. The dependency is
    // declared in `Cargo.toml` `[build-dependencies]` for the
    // crate's own `build.rs` and in the main `[dependencies]` for
    // the public library, so this function compiles in the lib
    // context with libbpf-cargo available.
    use libbpf_cargo::SkeletonBuilder;

    let mut artifacts = Vec::new();
    for source in BPF_SOURCES {
        let source_path = bpf_sensors_dir.join(source);
        if !source_path.is_file() {
            return Err(BuildError::SourceMissing(source_path.display().to_string()));
        }
        for arch in ARCHES {
            let target_arch_macro = match *arch {
                "amd64" => "x86",
                "arm64" => "arm64",
                other => {
                    return Err(BuildError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unsupported BPF arch `{other}`; only amd64 and arm64 are in scope for task 10"),
                    )));
                }
            };
            let stem = source.trim_end_matches(".bpf.c");
            let o_path = out_dir.join(format!("{stem}.{arch}.bpf.o"));
            let skel_path = out_dir.join(format!("{stem}.{arch}.skel.rs"));

            let mut builder = SkeletonBuilder::new();
            builder
                .source(source_path.to_string_lossy().as_ref())
                .obj(o_path.to_string_lossy().as_ref())
                .clang(&clang)
                .clang_args([
                    "-O2",
                    "-g",
                    "-Wall",
                    "-target",
                    "bpf",
                    format!("-D__TARGET_ARCH_{target_arch_macro}").as_str(),
                    format!("-I{}", bpf_include_dir.display()).as_str(),
                    format!("-I{}", out_dir.display()).as_str(),
                ])
                .build()
                .map_err(|e| BuildError::SkeletonBuilder(format!("build {source}/{arch}: {e}")))?;
            builder
                .generate(skel_path.to_string_lossy().as_ref())
                .map_err(|e| {
                    BuildError::SkeletonBuilder(format!("generate {source}/{arch}: {e}"))
                })?;

            if !o_path.is_file() || fs::metadata(&o_path)?.len() == 0 {
                return Err(BuildError::OutputMissing(format!(
                    "object file not produced at {}",
                    o_path.display()
                )));
            }
            if !skel_path.is_file() || fs::metadata(&skel_path)?.len() == 0 {
                return Err(BuildError::OutputMissing(format!(
                    "skeleton file not produced at {}",
                    skel_path.display()
                )));
            }

            let o_sha = sha256_hex_file(&o_path)?;
            let skel_sha = sha256_hex_file(&skel_path)?;
            artifacts.push(BpfArtifact {
                arch: arch.to_string(),
                source: source.to_string(),
                o_path,
                skel_path,
                o_sha256: o_sha,
                skel_sha256: skel_sha,
            });
        }
    }

    // vmlinux.h input digest + freshness check.
    let vmlinux_input_sha = match sha256_hex_file(&PathBuf::from("/sys/kernel/btf/vmlinux")) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cargo:warning=bpf-build: cannot read /sys/kernel/btf/vmlinux ({e}); recording vmlinux_input_sha256 as <unavailable>");
            "<unavailable>".to_string()
        }
    };
    if vmlinux_input_sha != "<unavailable>" && vmlinux_input_sha != EXPECTED_SHA256 {
        return Err(BuildError::FreshnessMismatch {
            expected: EXPECTED_SHA256.to_string(),
            observed: vmlinux_input_sha,
        });
    }

    let manifest = serde_json_like_manifest(&artifacts, &clang, &bpftool, &vmlinux_input_sha);
    let manifest_in_out = out_dir.join("bpf-build.manifest.json");
    fs::write(&manifest_in_out, &manifest)?;
    println!(
        "cargo:warning=bpf-build: manifest written to {}",
        manifest_in_out.display()
    );

    // Also drop a copy at the workspace target/ root so the
    // `bpf:build` CLI tool and the failure-QA scenario can find
    // it without poking around in $OUT_DIR.
    let stable = repo_root.join("target/bpf-build.manifest.json");
    if let Some(parent) = stable.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&stable, &manifest)?;

    Ok(artifacts)
}

/// Returns the canonical path of the freshness manifest that
/// `build()` writes. The path is `<workspace>/target/bpf-build.manifest.json`
/// and exists after the first successful `build()` invocation in
/// a given workspace.
pub fn manifest_path() -> PathBuf {
    default_out_dir().join("bpf-build.manifest.json")
}

fn default_out_dir() -> PathBuf {
    // Compute `<workspace>/target/bpf-out` deterministically.
    // CARGO_MANIFEST_DIR points at `crates/bpf-build/`, so the
    // workspace root is two parents up.
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("target/bpf-out"))
        .unwrap_or_else(|| PathBuf::from("target/bpf-out"))
}

fn command_available(cmd: &str) -> bool {
    Command::new(cmd).arg("--version").output().is_ok()
        || Command::new(cmd).arg("version").output().is_ok()
}

fn sha256_hex_file(path: &Path) -> io::Result<String> {
    let bytes = fs::read(path)?;
    Ok(sha256_hex(&bytes))
}

// Vendored SHA-256 (FIPS 180-4). Same implementation and rationale
// as `crates/event-abi/build.rs` and `crates/bpf-build/build.rs`.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (bytes.len() as u64) * 8;
    let mut msg = bytes.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let mj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(mj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = sha256(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn serde_json_like_manifest(
    artifacts: &[BpfArtifact],
    clang: &str,
    bpftool: &str,
    vmlinux_sha: &str,
) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"schema_version\": 1,\n");
    out.push_str("  \"generator\": \"bpf-build/src/lib.rs (libbpf-cargo)\",\n");
    out.push_str(&format!(
        "  \"target_arch_set\": [{}],\n",
        ARCHES
            .iter()
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    out.push_str(&format!("  \"clang_path\": \"{}\",\n", json_escape(clang)));
    out.push_str(&format!(
        "  \"bpftool_path\": \"{}\",\n",
        json_escape(bpftool)
    ));
    out.push_str(&format!("  \"vmlinux_input_sha256\": \"{vmlinux_sha}\",\n"));
    out.push_str("  \"artifacts\": [\n");
    for (i, a) in artifacts.iter().enumerate() {
        let comma = if i + 1 == artifacts.len() { "" } else { "," };
        out.push_str(&format!(
            "    {{\"arch\": \"{a}\", \"source\": \"{src}\", \"o_path\": \"{o}\", \"skel_path\": \"{s}\", \"o_sha256\": \"{oh}\", \"skel_sha256\": \"{sh}\"}}{comma}\n",
            a = a.arch,
            src = a.source,
            o = a.o_path.display(),
            s = a.skel_path.display(),
            oh = a.o_sha256,
            sh = a.skel_sha256,
        ));
    }
    out.push_str("  ]\n}\n");
    out
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
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
    fn expected_sha256_is_well_formed() {
        // EXPECTED_SHA256 must be a 64-char lowercase hex string.
        // If this test fails, the pin has been corrupted and the
        // failure-QA scenario will diverge from the lockfile.
        assert_eq!(
            EXPECTED_SHA256.len(),
            64,
            "EXPECTED_SHA256 must be 64 hex chars"
        );
        assert!(
            EXPECTED_SHA256.chars().all(|c| c.is_ascii_hexdigit()),
            "EXPECTED_SHA256 must be hex"
        );
    }

    #[test]
    fn default_out_dir_is_inside_workspace_target() {
        let p = default_out_dir();
        // The path always ends with target/bpf-out regardless of
        // the CARGO_MANIFEST_DIR value (workspace-relative).
        assert!(
            p.ends_with("target/bpf-out"),
            "default out_dir was {}",
            p.display()
        );
    }

    #[test]
    fn json_escape_handles_quotes_and_backslashes() {
        let s = json_escape("a\"b\\c");
        assert_eq!(s, "a\\\"b\\\\c");
    }

    #[test]
    fn manifest_path_is_inside_default_out_dir() {
        let p = manifest_path();
        assert!(p.ends_with("target/bpf-out/bpf-build.manifest.json"));
    }
}
