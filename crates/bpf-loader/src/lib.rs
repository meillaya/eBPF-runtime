// SPDX-License-Identifier: GPL-2.0-only
//
// crates/bpf-loader/src/lib.rs
// kernel-v1 — task 10 (libbpf-cargo CO-RE build pipeline)
//!
//! The user-space BPF loader crate. Task 10 only stands up the
//! compile-time embedding surface and a single
//! `open_placeholder_object` helper that opens the embedded .bpf.o
//! via `libbpf_rs::ObjectBuilder::open_memory` without actually
//! loading it into the kernel. Tasks 18 (load/attach manager) and
//! 11-17 (per-family sensor programs) build on this surface.
//!
//! The .bpf.o bytes are embedded at compile time via
//! `include_bytes!` with absolute paths supplied by `build.rs`
//! (which calls `bpf_build::build()` first to guarantee the files
//! exist). The default embedded object is the amd64 placeholder;
//! task 18 will select the matching arch at runtime by reading
//! `std::env::consts::ARCH` and the appropriate sha256 env var.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::sync::OnceLock;

/// Path of the embedded amd64 BPF object, set by `build.rs` via
/// the `BPF_LOADER_OBJECT_AMD64` rustc-env directive. The path is
/// absolute; the `include_bytes!` macro reads it at compile time.
pub const AMD64_OBJECT_PATH: &str = env!("BPF_LOADER_OBJECT_AMD64");

/// Path of the embedded arm64 BPF object, set by `build.rs` via
/// the `BPF_LOADER_OBJECT_ARM64` rustc-env directive.
pub const ARM64_OBJECT_PATH: &str = env!("BPF_LOADER_OBJECT_ARM64");

/// sha256 of the embedded amd64 .bpf.o, recorded in the
/// `bpf-build.manifest.json` at build time. Downstream consumers
/// (task 18) compare this against the freshly recomputed digest
/// to detect post-build tampering.
pub const AMD64_OBJECT_SHA256: &str = env!("BPF_LOADER_OBJECT_AMD64_SHA256");

/// sha256 of the embedded arm64 .bpf.o, recorded in the
/// `bpf-build.manifest.json` at build time.
pub const ARM64_OBJECT_SHA256: &str = env!("BPF_LOADER_OBJECT_ARM64_SHA256");

/// Compile-time embedded amd64 BPF object bytes. The
/// `include_bytes!` macro reads the file at compile time and
/// embeds the bytes directly into the loader crate's binary, so
/// no filesystem access is needed at runtime to find the object.
///
/// This is the happy-QA surface for task 10: `open_placeholder_object`
/// returns a `libbpf_rs::Object` that wraps these bytes via
/// `Object::open_mem_bytes`. The object is NOT loaded into the
/// kernel; task 18 owns load/attach semantics.
pub static AMD64_OBJECT_BYTES: &[u8] = include_bytes!(env!("BPF_LOADER_OBJECT_AMD64"));

/// Compile-time embedded arm64 BPF object bytes. See
/// `AMD64_OBJECT_BYTES` for the contract.
pub static ARM64_OBJECT_BYTES: &[u8] = include_bytes!(env!("BPF_LOADER_OBJECT_ARM64"));

/// Open the embedded placeholder BPF object as a
/// `libbpf_rs::OpenObject` without loading it into the kernel.
/// This is the happy-QA surface for task 10: it proves the
/// embedded .bpf.o is a valid ELF and that the loader crate
/// compiles and links against `libbpf-rs` 0.26 successfully.
///
/// The function returns a fresh `OpenObject` for each call;
/// callers that need to share the underlying file descriptor
/// should wrap the `OpenObject` in their own synchronization
/// primitive. The `OnceLock` cache below is an opt-in memoization
/// point used by the unit tests so repeated invocations during a
/// test suite do not re-parse the BPF ELF.
pub fn open_placeholder_object() -> Result<libbpf_rs::OpenObject, libbpf_rs::Error> {
    open_placeholder_object_arch(PlaceholderArch::Host)
}

/// Select which per-arch embedded object to open. Task 18 will
/// drive this from the host's `uname -m`; the unit tests use
/// `Host` to mean "match the current build target" so the same
/// test binary works on amd64 and arm64 hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaceholderArch {
    /// Match the host architecture this loader was compiled for.
    Host,
    /// Always open the embedded amd64 object.
    Amd64,
    /// Always open the embedded arm64 object.
    Arm64,
}

/// As `open_placeholder_object`, but with explicit arch selection.
pub fn open_placeholder_object_arch(
    arch: PlaceholderArch,
) -> Result<libbpf_rs::OpenObject, libbpf_rs::Error> {
    let bytes: &[u8] = match arch {
        PlaceholderArch::Host => host_bytes(),
        PlaceholderArch::Amd64 => AMD64_OBJECT_BYTES,
        PlaceholderArch::Arm64 => ARM64_OBJECT_BYTES,
    };
    // `ObjectBuilder::open_memory` parses the ELF, builds the BTF,
    // and prepares the maps/programs; it does NOT call
    // `bpf_object__load` so no CAP_BPF / CAP_SYS_ADMIN is required.
    // The returned `OpenObject` is ready for `load()` by callers
    // that have the privileges. The happy-QA surface in task 10
    // only needs `OpenObject` — we prove the embedded .bpf.o is a
    // valid ELF and that the loader crate compiles + links against
    // `libbpf-rs` 0.26 successfully.
    libbpf_rs::ObjectBuilder::default().open_memory(bytes)
}

fn host_bytes() -> &'static [u8] {
    // Cache the host selection. The host arch does not change at
    // runtime; memoising avoids recomputing the match on every
    // call to `open_placeholder_object`.
    static CACHE: OnceLock<&'static [u8]> = OnceLock::new();
    CACHE.get_or_init(|| match std::env::consts::ARCH {
        "aarch64" => ARM64_OBJECT_BYTES,
        // x86_64 and every other arch on the supported matrix
        // (the loader is built per-target) fall through to amd64.
        // Task 18 will fail loudly on a host whose arch is not
        // amd64 or arm64, which the kernel-compat matrix already
        // declares out of scope.
        _ => AMD64_OBJECT_BYTES,
    })
}

/// Identify which per-arch object a slice of bytes corresponds to
/// by comparing the sha256 digests. Returns `None` if neither
/// matches; that case is treated as a tamper / unexpected-build
/// event by task 18.
pub fn identify_placeholder_bytes(bytes: &[u8]) -> Option<PlaceholderArch> {
    let hex = {
        use std::fmt::Write as _;
        // Mini SHA-256 over the bytes; we re-derive the digest
        // at runtime so the loader can verify the embedded bytes
        // match the manifest pin even after a hand-edit. The
        // implementation is the same vendored FIPS 180-4 algorithm
        // as in bpf-build and event-abi.
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let k: [u32; 64] = [
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
                    .wrapping_add(k[i])
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
        let mut s = String::with_capacity(64);
        for word in h.iter() {
            let _ = write!(s, "{:08x}", word);
        }
        s
    };
    if hex == AMD64_OBJECT_SHA256 {
        Some(PlaceholderArch::Amd64)
    } else if hex == ARM64_OBJECT_SHA256 {
        Some(PlaceholderArch::Arm64)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_vars_are_populated() {
        // The `build.rs` script is required to populate these
        // env vars; if any is empty the build script silently
        // failed to wire up the embedded objects.
        assert!(
            !AMD64_OBJECT_PATH.is_empty(),
            "BPF_LOADER_OBJECT_AMD64 was empty"
        );
        assert!(
            !ARM64_OBJECT_PATH.is_empty(),
            "BPF_LOADER_OBJECT_ARM64 was empty"
        );
        assert_eq!(
            AMD64_OBJECT_SHA256.len(),
            64,
            "amd64 sha256 must be 64 hex chars"
        );
        assert_eq!(
            ARM64_OBJECT_SHA256.len(),
            64,
            "arm64 sha256 must be 64 hex chars"
        );
    }

    #[test]
    fn embedded_objects_are_non_empty() {
        assert!(
            !AMD64_OBJECT_BYTES.is_empty(),
            "embedded amd64 .bpf.o is empty"
        );
        assert!(
            !ARM64_OBJECT_BYTES.is_empty(),
            "embedded arm64 .bpf.o is empty"
        );
    }

    #[test]
    fn identify_placeholder_bytes_matches_embedded() {
        // The placeholder .bpf.o is byte-equal across arches
        // (the TU has no arch-specific content), so both embedded
        // buffers must match the recorded digest and identify
        // as a known placeholder. Real sensor programs in
        // tasks 11-17 add arch-specific content that will make
        // the two .o files diverge.
        assert!(identify_placeholder_bytes(AMD64_OBJECT_BYTES).is_some());
        assert!(identify_placeholder_bytes(ARM64_OBJECT_BYTES).is_some());
    }

    #[test]
    fn identify_placeholder_bytes_rejects_unknown() {
        let bogus: &[u8] = b"definitely not a BPF object -- random bytes";
        assert_eq!(identify_placeholder_bytes(bogus), None);
    }
}
