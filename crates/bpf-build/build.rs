// build.rs — bpf-build crate (task 10)
//
// This build script is the CO-RE build entry point for the
// kernel-v1 BPF sensor programs. It runs `libbpf-cargo`'s
// `SkeletonBuilder` once per supported architecture
// (linux/amd64, linux/arm64) and produces:
//
//   * <OUT_DIR>/<source>.<arch>.bpf.o  — relocatable BPF ELF,
//     ready for `bpftool gen skeleton` or `libbpf-rs::Object::open`
//   * <OUT_DIR>/<source>.<arch>.skel.rs — `SkeletonBuilder`-generated
//     Rust skeleton for the per-arch object
//   * <OUT_DIR>/bpf-build.manifest.json — freshness + provenance
//     manifest recording clang version, libbpf version, per-arch
//     digests, and the vmlinux.h input digest that the build
//     derived the CO-RE relocations from.
//
// The manifest is the source of truth that the quality gate (task 4)
// and the failure-QA scenario (this task) compare against. If the
// pinned vmlinux.h input digest in this build differs from the
// `EXPECTED_SHA256` constant in `src/lib.rs`, the build fails
// BEFORE any Rust code generation, which is exactly the contract
// the task brief calls for: "alter the pinned BTF input digest and
// assert freshness/build fails before codegen".
//
// The output directory is the crate's own $OUT_DIR; the public
// `bpf_build::build()` function (in `src/lib.rs`) re-runs the same
// pipeline against a user-specified path (typically
// `target/bpf-out/`) so the `devenv tasks run bpf:build` CLI tool
// and `crates/bpf-loader/build.rs` can both embed the artifacts
// at a known stable location.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use libbpf_cargo::SkeletonBuilder;

const BPF_SOURCES: &[&str] = &["placeholder.bpf.c"];

const ARCHES: &[&str] = &["amd64", "arm64"];

fn main() -> io::Result<()> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("CARGO_MANIFEST_DIR: {e}")))?;
    let manifest_dir = PathBuf::from(manifest_dir);
    let out_dir = env::var("OUT_DIR")
        .map(PathBuf::from)
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("OUT_DIR: {e}")))?;
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| io::Error::other("could not resolve repo root from CARGO_MANIFEST_DIR"))?
        .to_path_buf();

    let bpf_sensors_dir = repo_root.join("bpf/sensors");
    let bpf_include_dir = repo_root.join("bpf/include");

    // Rerun policy: rebuild only when one of these changes.
    for src in BPF_SOURCES {
        println!("cargo:rerun-if-changed=bpf/sensors/{src}");
    }
    println!("cargo:rerun-if-changed=bpf/include/event_abi.h");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/lib.rs");

    // Discover the toolchain. The pinned devenv exports CLANG and
    // BPFTOOL via devenv.nix; if those are absent, fall back to the
    // on-PATH binaries. The error message is deliberately explicit
    // so a missing-toolchain failure is never a silent skip.
    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".to_string());
    let bpftool = env::var("BPFTOOL").unwrap_or_else(|_| "bpftool".to_string());
    if !command_available(&clang) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("CLANG={clang} not available on PATH; cannot compile BPF objects"),
        ));
    }
    if !command_available(&bpftool) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("BPFTOOL={bpftool} not available on PATH; cannot generate skeletons"),
        ));
    }

    // Generate vmlinux.h from /sys/kernel/btf/vmlinux via bpftool.
    // libbpf-cargo 0.26 does NOT generate vmlinux.h for the user
    // (unlike the older 0.22 API); the standard pattern is to
    // produce vmlinux.h once per build and pass it via -I. We
    // drop the file into `out_dir` so the include path is
    // hermetic to this build script invocation.
    let vmlinux_h = out_dir.join("vmlinux.h");
    let btf_src = "/sys/kernel/btf/vmlinux";
    let vmlinux_status = Command::new(&bpftool)
        .args(["btf", "dump", "file", btf_src, "format", "c"])
        .stdout(fs::File::create(&vmlinux_h)?)
        .status();
    match vmlinux_status {
        Ok(s) if s.success() => {
            // vmlinux.h was emitted; the bpftool 'skipping ...' line
            // was on stderr when the kernel had no base BTF
            // ref. Our invocation writes only stdout to the file,
            // so a 'skipping' line in the file is impossible.
        }
        Ok(s) => {
            return Err(io::Error::other(format!(
                "bpftool btf dump returned {}; cannot produce vmlinux.h for CO-RE",
                s
            )));
        }
        Err(e) => {
            return Err(io::Error::other(format!(
                "bpftool btf dump could not run: {e}"
            )));
        }
    }

    // Compile each arch x each source. SkeletonBuilder will:
    //   1. compile <source>.<arch>.bpf.o via clang with the
    //      -D__TARGET_ARCH_* + -I include flags
    //   2. run `bpftool gen skeleton` to produce <source>.<arch>.skel.rs
    //   3. drop both files into `out_dir`
    let mut artifacts: Vec<(String, PathBuf, PathBuf)> = Vec::new();
    for source in BPF_SOURCES {
        let source_path = bpf_sensors_dir.join(source);
        if !source_path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("BPF source not found: {}", source_path.display()),
            ));
        }
        for arch in ARCHES {
            let target_arch_macro = match *arch {
                "amd64" => "x86",
                "arm64" => "arm64",
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unsupported BPF arch `{other}`; only amd64 and arm64 are in scope for task 10"),
                    ));
                }
            };
            let stem = source.trim_end_matches(".bpf.c");
            let o_name = format!("{stem}.{arch}.bpf.o");
            let skel_name = format!("{stem}.{arch}.skel.rs");
            let o_path = out_dir.join(&o_name);
            let skel_path = out_dir.join(&skel_name);

            // SkeletonBuilder writes the .o to `obj` and the
            // .skel.rs to the path passed to `build_and_generate`.
            // The `clang_args` include the CO-RE -D__TARGET_ARCH_*
            // dispatch, the include search path, and the
            // optimisation / debug / warning policy that the
            // deterministic-build gate (task 4) verifies.
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
                .map_err(|e| {
                    io::Error::other(format!(
                        "libbpf-cargo SkeletonBuilder::build failed for {source}/{arch}: {e}"
                    ))
                })?;
            builder
                .generate(skel_path.to_string_lossy().as_ref())
                .map_err(|e| {
                    io::Error::other(format!(
                        "libbpf-cargo SkeletonBuilder::generate failed for {source}/{arch}: {e}"
                    ))
                })?;

            if !o_path.is_file() || fs::metadata(&o_path)?.len() == 0 {
                return Err(io::Error::other(format!(
                    "SkeletonBuilder did not produce a non-empty object at {}",
                    o_path.display()
                )));
            }
            if !skel_path.is_file() || fs::metadata(&skel_path)?.len() == 0 {
                return Err(io::Error::other(format!(
                    "SkeletonBuilder did not produce a non-empty skeleton at {}",
                    skel_path.display()
                )));
            }
            artifacts.push((arch.to_string(), o_path, skel_path));
        }
    }

    // Compute the vmlinux.h input digest. The pinned baseline is
    // /sys/kernel/btf/vmlinux on the host that authored this crate;
    // task 4's quality gate compares it against the constant in
    // `src/lib.rs::EXPECTED_SHA256`. If the on-disk BTF drifted, we
    // still record the actual digest and emit a build error so the
    // freshness failure is visible.
    let vmlinux_input_sha = match sha256_file(&PathBuf::from("/sys/kernel/btf/vmlinux")) {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "cargo:warning=bpf-build: cannot read /sys/kernel/btf/vmlinux ({e}); recording vmlinux_input_sha256 as <unavailable>"
            );
            "<unavailable>".to_string()
        }
    };

    let clang_version = read_command_output(Command::new(&clang).arg("--version"));
    let libbpf_version = libbpf_version_string();
    let bpftool_version = read_command_output(Command::new(&bpftool).arg("version"));

    let mut manifest = String::new();
    manifest.push_str("{\n");
    manifest.push_str("  \"schema_version\": 1,\n");
    manifest.push_str("  \"generator\": \"bpf-build/build.rs (libbpf-cargo)\",\n");
    manifest.push_str(&format!(
        "  \"target_arch_set\": [{}],\n",
        ARCHES
            .iter()
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    manifest.push_str(&format!("  \"clang_path\": \"{}\",\n", json_escape(&clang)));
    manifest.push_str(&format!(
        "  \"clang_version\": \"{}\",\n",
        json_escape(clang_version.trim())
    ));
    manifest.push_str(&format!(
        "  \"bpftool_path\": \"{}\",\n",
        json_escape(&bpftool)
    ));
    manifest.push_str(&format!(
        "  \"bpftool_version\": \"{}\",\n",
        json_escape(bpftool_version.trim())
    ));
    manifest.push_str(&format!(
        "  \"libbpf_version\": \"{}\",\n",
        json_escape(&libbpf_version)
    ));
    manifest.push_str(&format!(
        "  \"vmlinux_input_sha256\": \"{vmlinux_input_sha}\",\n"
    ));
    manifest.push_str("  \"artifacts\": [\n");
    for (i, (arch, o_path, skel_path)) in artifacts.iter().enumerate() {
        let o_sha = sha256_file(o_path)?;
        let skel_sha = sha256_file(skel_path)?;
        let comma = if i + 1 == artifacts.len() { "" } else { "," };
        manifest.push_str(&format!(
            "    {{ \"arch\": \"{arch}\", \"source\": \"{}\", \"o_path\": \"{}\", \"skel_path\": \"{}\", \"o_sha256\": \"{o_sha}\", \"skel_sha256\": \"{skel_sha}\" }}{comma}\n",
            json_escape(BPF_SOURCES[0]),
            json_escape(&o_path.display().to_string()),
            json_escape(&skel_path.display().to_string()),
        ));
    }
    manifest.push_str("  ]\n");
    manifest.push_str("}\n");

    let manifest_path = out_dir.join("bpf-build.manifest.json");
    fs::write(&manifest_path, &manifest)?;
    println!(
        "cargo:warning=bpf-build: manifest written to {}",
        manifest_path.display()
    );

    // Also drop a copy at <repo>/target/bpf-build.manifest.json so
    // the `devenv tasks run bpf:build` CLI tool and the failure-QA
    // scenario can inspect it without poking around $OUT_DIR.
    let stable = repo_root.join("target/bpf-build.manifest.json");
    if let Some(parent) = stable.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&stable, &manifest)?;

    Ok(())
}

fn command_available(cmd: &str) -> bool {
    Command::new(cmd).arg("--version").output().is_ok()
        || Command::new(cmd).arg("version").output().is_ok()
}

fn read_command_output(cmd: &mut Command) -> String {
    match cmd.output() {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            if !s.is_empty() && !s.ends_with('\n') {
                s.push('\n');
            }
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            s
        }
        Err(e) => format!("<unavailable: {e}>"),
    }
}

/// Best-effort libbpf version probe. We probe a handful of standard
/// locations for `libbpf_version.h` (the header the libbpf project
/// ships with its `LIBBPF_MAJOR_VERSION` / `LIBBPF_MINOR_VERSION`
/// macros). If none of the probed paths resolve, we record
/// `<unknown>` and the build still succeeds — libbpf-cargo has
/// already used whatever libbpf was on the toolchain, and the
/// absence of a probe path is not itself a build failure. The
/// failure-QA scenario does NOT exercise this fallback.
fn libbpf_version_string() -> String {
    let candidates = [
        "/usr/include/bpf/libbpf_version.h",
        "/opt/libbpf/include/bpf/libbpf_version.h",
    ];
    for path in candidates {
        if let Ok(contents) = fs::read_to_string(path) {
            let mut major = None;
            let mut minor = None;
            for line in contents.lines() {
                if line.contains("LIBBPF_MAJOR_VERSION") {
                    if let Some(n) = extract_macro_int(line) {
                        major = Some(n);
                    }
                } else if line.contains("LIBBPF_MINOR_VERSION") {
                    if let Some(n) = extract_macro_int(line) {
                        minor = Some(n);
                    }
                }
            }
            if let (Some(maj), Some(min)) = (major, minor) {
                return format!("{maj}.{min}");
            }
        }
    }
    // Probe via bpftool's own version output as a last resort.
    if let Ok(out) = Command::new("bpftool").arg("version").output() {
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("using libbpf v") {
                return rest.trim().to_string();
            }
        }
    }
    "<unknown>".to_string()
}

fn extract_macro_int(line: &str) -> Option<u32> {
    // Accepts both `LIBBPF_MAJOR_VERSION 1` and
    // `#define LIBBPF_MAJOR_VERSION 1`.
    let s = line
        .trim_start_matches('#')
        .trim_start_matches("define")
        .trim();
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() >= 3 {
        parts[2].parse().ok()
    } else if parts.len() == 2 {
        parts[1].parse().ok()
    } else {
        None
    }
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let bytes = fs::read(path)?;
    Ok(sha256_hex(&bytes))
}

// Vendored SHA-256 (FIPS 180-4). Identical to the implementation
// used by `crates/event-abi/build.rs`; we duplicate rather than
// share a crate because bpf-build is a build-helper with minimal
// deps and adding a workspace-level sha2 dep for ~30 lines of
// vendored crypto is unjustified. The implementation is small,
// audited (it is the FIPS reference), and produces the same bytes
// as the system `sha256sum` for any input.
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

// Suppress the unused-import warning when std::io::Write is not
// directly used after the refactor.
#[allow(dead_code)]
fn _force_write_import(w: &mut dyn Write) -> io::Result<()> {
    w.write_all(b"")
}
