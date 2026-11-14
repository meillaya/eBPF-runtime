// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Record-time stack symbolization.
//!
//! The BPF sensors store kernel and user frame addresses in
//! `BPF_MAP_TYPE_STACK_TRACE` maps; [`Symbolizer`] turns a
//! [`bpf_loader::RawStack`] into the symbolized [`event_model::Stack`] that
//! the bundle writer persists.
//!
//! Design rules:
//!
//! * **Raw addresses are forever.** Every [`event_model::StackFrame`] keeps
//!   `addr` exactly as captured. Symbolization only fills `symbol`, `file`,
//!   and `line`; a frame that cannot be resolved stays in the list with
//!   those fields `None` (the on-bundle "symbols unavailable" marker).
//!   A symbolization failure never fails the event.
//! * **Kernel frames** are resolved with blazesym's `Kernel` source, which
//!   prefers an on-disk `vmlinux` and falls back to `/proc/kallsyms` plus
//!   loaded modules. The kernel cache is held by one [`Symbolizer`] for the
//!   life of a recording.
//! * **User frames** are resolved with the `Process` source for the event's
//!   thread group while it is still alive. The source honors embedded ELF
//!   symbols, split debug info referenced by debug links, and build-id
//!   indexed files under `/usr/lib/debug/.build-id` (the default debug
//!   dirs are `/usr/lib/debug` and `/lib/debug`). It reads symbolic
//!   `/proc/<pid>/maps` paths instead of privileged `map_files` entries.
//!   Once a process exits, its user frames degrade to raw addresses — the
//!   documented 0.3 gap.
//! * Counters in [`SymbolizeStats`] back `ebpf-fleet record --stats`.
//!
//! The module is intentionally process-local: it neither contacts a
//! debuginfod server (a future opt-in) nor writes anything.

use std::path::Path;

use blazesym::symbolize::source::{Elf, Kernel, Process, Source};
use blazesym::symbolize::{Input, Symbolized, Symbolizer as BlazeSymbolizer};
use blazesym::Pid;
use bpf_loader::RawStack;
use event_model::{Stack, StackFrame};
use serde::Serialize;
use thiserror::Error;

/// Counters collected while symbolizing. Serialized by `record --stats`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct SymbolizeStats {
    /// Stacks symbolized (one per resolved event stack id).
    pub stacks: u64,
    /// Kernel frames seen.
    pub kernel_frames: u64,
    /// Kernel frames resolved to a symbol.
    pub kernel_symbolized: u64,
    /// User frames seen.
    pub user_frames: u64,
    /// User frames resolved to a symbol.
    pub user_symbolized: u64,
    /// Frames dropped because they are not canonical addresses for their
    /// class (garbage from a broken frame-pointer unwind, e.g. an ASCII
    /// stack value interpreted as a user return address).
    pub invalid_frames: u64,
    /// Frames that kept their raw address but got no symbol.
    pub missing_symbols: u64,
    /// Stacks that hit the 64-frame capture depth.
    pub truncated_stacks: u64,
    /// Kernel symbolization batches that failed wholesale.
    pub kernel_errors: u64,
    /// User symbolization batches that failed wholesale (typically a
    /// process that already exited between capture and symbolization).
    pub user_errors: u64,
}

impl SymbolizeStats {
    /// Frames seen at all.
    pub fn total_frames(&self) -> u64 {
        self.kernel_frames.saturating_add(self.user_frames)
    }

    /// Frames resolved to at least a symbol.
    pub fn total_symbolized(&self) -> u64 {
        self.kernel_symbolized.saturating_add(self.user_symbolized)
    }
}

/// Errors from the standalone ELF-offset entry point. The record-time
/// [`Symbolizer::symbolize`] path is infallible by design and reports
/// problems through [`SymbolizeStats`] instead.
#[derive(Debug, Error)]
pub enum SymbolizeError {
    /// blazesym rejected the source or the request.
    #[error("symbolization failed: {0}")]
    Failed(String),
    /// blazesym returned a different number of results than inputs.
    #[error("symbolization returned {got} results for {expected} addresses")]
    LengthMismatch { got: usize, expected: usize },
}

/// Highest user-space virtual address accepted from an unwind (56-bit
/// canonical user range; values above this are kernel addresses or garbage
/// left on the stack and are filtered before symbolization).
const USER_ADDR_LIMIT: u64 = 0x0100_0000_0000_0000;
/// Lowest canonical kernel virtual address accepted from a kernel-stack
/// unwind.
const KERNEL_ADDR_START: u64 = 0xffff_8000_0000_0000;

/// True for a canonical user-space address.
pub fn is_valid_user_addr(addr: u64) -> bool {
    addr < USER_ADDR_LIMIT
}

/// True for a canonical kernel-space address.
pub fn is_valid_kernel_addr(addr: u64) -> bool {
    addr >= KERNEL_ADDR_START
}

/// Record-time stack symbolizer. One instance is reused for a recording so
/// the kernel/ELF caches stay warm.
pub struct Symbolizer {
    inner: BlazeSymbolizer,
    kernel: Kernel,
    stats: SymbolizeStats,
}

impl Default for Symbolizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Symbolizer {
    /// Create a symbolizer with code-info lookup and demangling enabled and
    /// inlined-function expansion disabled (the bundle schema stores one
    /// frame per captured address).
    pub fn new() -> Self {
        let inner = BlazeSymbolizer::builder()
            .enable_code_info(true)
            .enable_inlined_fns(false)
            .enable_demangling(true)
            .build();
        Self {
            inner,
            kernel: Kernel::default(),
            stats: SymbolizeStats::default(),
        }
    }

    /// Counters collected so far.
    pub fn stats(&self) -> SymbolizeStats {
        self.stats
    }

    /// Turn one captured raw stack into a symbolized [`Stack`].
    ///
    /// Kernel frames come first (the order the sensors captured them), then
    /// user frames. `pid` is the thread group id of the emitting process;
    /// it is only used for user frames and only while that process is
    /// alive. This method never fails.
    pub fn symbolize(&mut self, sensor: &str, stack_id: i32, pid: u32, raw: &RawStack) -> Stack {
        let mut frames = self.kernel_frames(&raw.kernel);
        frames.extend(self.user_frames(pid, &raw.user));
        if raw.truncated {
            self.stats.truncated_stacks = self.stats.truncated_stacks.saturating_add(1);
        }
        self.stats.stacks = self.stats.stacks.saturating_add(1);
        Stack {
            stack_id,
            sensor: sensor.to_string(),
            frames,
            truncated: raw.truncated,
        }
    }

    /// Symbolize virtual offsets inside one ELF file without a live
    /// process. Used by the golden fixture test and by future offline /
    /// debuginfod workflows. `addr` on the returned frames carries the
    /// input virtual offset.
    pub fn symbolize_elf_offsets(
        &mut self,
        path: &Path,
        offsets: &[u64],
    ) -> Result<Vec<StackFrame>, SymbolizeError> {
        let source = Source::Elf(Elf::new(path));
        let symbolized = self
            .inner
            .symbolize(&source, Input::VirtOffset(offsets))
            .map_err(|error| SymbolizeError::Failed(error.to_string()))?;
        if symbolized.len() != offsets.len() {
            return Err(SymbolizeError::LengthMismatch {
                got: symbolized.len(),
                expected: offsets.len(),
            });
        }
        Ok(frames_from_symbolized(
            offsets,
            &symbolized,
            false,
            &mut self.stats,
        ))
    }

    fn kernel_frames(&mut self, addrs: &[u64]) -> Vec<StackFrame> {
        if addrs.is_empty() {
            return Vec::new();
        }
        let addrs = sanitize_addrs(addrs, is_valid_kernel_addr, &mut self.stats);
        if addrs.is_empty() {
            return Vec::new();
        }
        self.stats.kernel_frames = self.stats.kernel_frames.saturating_add(addrs.len() as u64);
        let source = Source::Kernel(self.kernel.clone());
        let result = self.inner.symbolize(&source, Input::AbsAddr(&addrs));
        match result {
            Ok(symbolized) if symbolized.len() == addrs.len() => {
                frames_from_symbolized(&addrs, &symbolized, true, &mut self.stats)
            }
            Ok(symbolized) => {
                self.stats.kernel_errors = self.stats.kernel_errors.saturating_add(1);
                unresolved_frames(&addrs, true, symbolized.len(), &mut self.stats)
            }
            Err(_) => {
                self.stats.kernel_errors = self.stats.kernel_errors.saturating_add(1);
                unresolved_frames(&addrs, true, 0, &mut self.stats)
            }
        }
    }

    fn user_frames(&mut self, pid: u32, addrs: &[u64]) -> Vec<StackFrame> {
        if addrs.is_empty() {
            return Vec::new();
        }
        let addrs = sanitize_addrs(addrs, is_valid_user_addr, &mut self.stats);
        if addrs.is_empty() {
            return Vec::new();
        }
        self.stats.user_frames = self.stats.user_frames.saturating_add(addrs.len() as u64);
        if pid == 0 {
            // A zero pid cannot reference a process; keep the raw frames.
            self.stats.user_errors = self.stats.user_errors.saturating_add(1);
            return unresolved_frames(&addrs, false, 0, &mut self.stats);
        }
        let mut process = Process::new(Pid::from(pid));
        process.debug_syms = true;
        process.perf_map = false;
        // `map_files` needs SYS_ADMIN on many hosts; symbolic /proc maps
        // paths are enough for local symbolization.
        process.map_files = false;
        process.vdso = true;
        let source = Source::Process(process);
        let result = self.inner.symbolize(&source, Input::AbsAddr(&addrs));
        match result {
            Ok(symbolized) if symbolized.len() == addrs.len() => {
                frames_from_symbolized(&addrs, &symbolized, false, &mut self.stats)
            }
            Ok(symbolized) => {
                self.stats.user_errors = self.stats.user_errors.saturating_add(1);
                unresolved_frames(&addrs, false, symbolized.len(), &mut self.stats)
            }
            Err(_) => {
                self.stats.user_errors = self.stats.user_errors.saturating_add(1);
                unresolved_frames(&addrs, false, 0, &mut self.stats)
            }
        }
    }
}

/// Drop addresses that cannot be valid for their class and count them.
fn sanitize_addrs(addrs: &[u64], keep: fn(u64) -> bool, stats: &mut SymbolizeStats) -> Vec<u64> {
    let kept: Vec<u64> = addrs.iter().copied().filter(|addr| keep(*addr)).collect();
    let dropped = addrs.len().saturating_sub(kept.len()) as u64;
    stats.invalid_frames = stats.invalid_frames.saturating_add(dropped);
    kept
}

/// Build resolved frames one-to-one with `addrs`.
fn frames_from_symbolized(
    addrs: &[u64],
    symbolized: &[Symbolized<'_>],
    is_kernel: bool,
    stats: &mut SymbolizeStats,
) -> Vec<StackFrame> {
    let mut frames = Vec::with_capacity(addrs.len());
    for (addr, resolved) in addrs.iter().zip(symbolized.iter()) {
        let mut frame = StackFrame {
            addr: *addr,
            symbol: None,
            file: None,
            line: None,
            is_kernel,
        };
        if let Symbolized::Sym(sym) = resolved {
            if !sym.name.is_empty() {
                frame.symbol = Some(sym.name.to_string());
            }
            if let Some(code_info) = sym.code_info.as_ref() {
                let path = code_info.to_path();
                if !path.as_os_str().is_empty() {
                    frame.file = Some(path.to_string_lossy().into_owned());
                }
                frame.line = code_info.line;
            }
        }
        if frame.symbol.is_some() {
            if is_kernel {
                stats.kernel_symbolized = stats.kernel_symbolized.saturating_add(1);
            } else {
                stats.user_symbolized = stats.user_symbolized.saturating_add(1);
            }
        } else {
            stats.missing_symbols = stats.missing_symbols.saturating_add(1);
        }
        frames.push(frame);
    }
    frames
}

/// Raw-address fallback for every frame: used when a whole symbolization
/// batch fails. Missing symbols are counted so `record --stats` still tells
/// the truth.
fn unresolved_frames(
    addrs: &[u64],
    is_kernel: bool,
    resolved: usize,
    stats: &mut SymbolizeStats,
) -> Vec<StackFrame> {
    let missing = addrs.len().saturating_sub(resolved);
    stats.missing_symbols = stats.missing_symbols.saturating_add(missing as u64);
    addrs
        .iter()
        .map(|addr| StackFrame {
            addr: *addr,
            symbol: None,
            file: None,
            line: None,
            is_kernel,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/symbolize")
    }

    /// A stable marker function whose address is captured as a "user
    /// frame" in the live self-process test below.
    #[inline(never)]
    fn golden_user_symbolization_marker() -> u64 {
        golden_user_symbolization_marker as *const () as usize as u64
    }

    fn raw_user(addrs: Vec<u64>) -> RawStack {
        RawStack {
            kernel: Vec::new(),
            user: addrs,
            truncated: false,
        }
    }

    #[test]
    fn golden_elf_fixture_symbolizes_symbol_file_and_line() {
        let dir = fixture_dir();
        let elf = dir.join("libstack_fixture.so");
        assert!(
            elf.is_file(),
            "missing golden ELF fixture at {}",
            elf.display()
        );
        let golden: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("golden.json")).unwrap()).unwrap();
        let symbols = golden["symbols"].as_array().expect("symbols array");

        let offsets: Vec<u64> = symbols
            .iter()
            .map(|symbol| symbol["virt_offset"].as_u64().expect("virt_offset"))
            .collect();
        let mut symbolizer = Symbolizer::new();
        let frames = symbolizer
            .symbolize_elf_offsets(&elf, &offsets)
            .expect("golden ELF must symbolize");

        assert_eq!(frames.len(), symbols.len());
        for (frame, expected) in frames.iter().zip(symbols) {
            assert_eq!(
                frame.symbol.as_deref(),
                expected["name"].as_str(),
                "symbol mismatch for virtual offset {:#x}",
                frame.addr
            );
            let file = frame
                .file
                .as_deref()
                .expect("golden frame must carry a file");
            assert!(
                file.ends_with(expected["file"].as_str().unwrap()),
                "unexpected file {file}"
            );
            assert_eq!(
                frame.line,
                expected["line"].as_u64().map(|line| line as u32),
                "line mismatch for {file}"
            );
            assert!(!frame.is_kernel);
        }
        assert_eq!(symbolizer.stats().missing_symbols, 0);
        assert_eq!(symbolizer.stats().user_symbolized, symbols.len() as u64);
    }

    #[test]
    fn golden_live_user_frame_symbolizes_from_the_running_process() {
        let marker = golden_user_symbolization_marker();
        let mut symbolizer = Symbolizer::new();
        let stack = symbolizer.symbolize("file", 7, std::process::id(), &raw_user(vec![marker]));
        assert_eq!(stack.stack_id, 7);
        assert_eq!(stack.sensor, "file");
        assert_eq!(stack.frames.len(), 1);
        let frame = &stack.frames[0];
        assert!(!frame.is_kernel);
        assert_eq!(frame.addr, marker, "raw address must be preserved");
        let symbol = frame
            .symbol
            .as_deref()
            .expect("own test-binary frame must symbolize");
        assert!(
            symbol.contains("golden_user_symbolization_marker"),
            "unexpected symbol {symbol}"
        );
        let file = frame.file.as_deref().expect("test binary has debug info");
        assert!(file.ends_with("symbolize.rs"), "unexpected file {file}");
        assert!(frame.line.is_some(), "expected a source line, got none");
        assert_eq!(symbolizer.stats().missing_symbols, 0);
    }

    #[test]
    fn unmapped_user_address_keeps_raw_addr_and_marks_missing_symbol() {
        let mut symbolizer = Symbolizer::new();
        let stack = symbolizer.symbolize("file", 3, std::process::id(), &raw_user(vec![0x1000]));
        assert_eq!(stack.frames.len(), 1);
        assert_eq!(stack.frames[0].addr, 0x1000);
        assert_eq!(stack.frames[0].symbol, None);
        assert!(!stack.frames[0].is_kernel);
        assert!(symbolizer.stats().missing_symbols >= 1);
        assert!(symbolizer.stats().user_errors + symbolizer.stats().missing_symbols >= 1);
    }

    #[test]
    fn empty_and_truncated_raw_stacks_are_preserved() {
        let mut symbolizer = Symbolizer::new();
        let empty = symbolizer.symbolize("process", 1, 0, &RawStack::default());
        assert!(empty.frames.is_empty());
        assert!(!empty.truncated);

        let truncated = RawStack {
            kernel: vec![0xffff_ffff_8100_0000],
            user: Vec::new(),
            truncated: true,
        };
        let stack = symbolizer.symbolize("process", 2, 0, &truncated);
        assert!(stack.truncated);
        assert_eq!(stack.frames.len(), 1);
        assert!(stack.frames[0].is_kernel);
        assert_eq!(symbolizer.stats().truncated_stacks, 1);
    }

    #[test]
    fn address_class_filter_drops_unwind_garbage() {
        assert!(is_valid_user_addr(0x7f00_0000_1234));
        assert!(is_valid_user_addr(0x0041_bbd7));
        // ASCII bytes picked up by a broken frame-pointer walk.
        assert!(!is_valid_user_addr(0x6570_6f6e_2f70_6d74));
        assert!(is_valid_kernel_addr(0xffff_ffff_8100_0000));
        assert!(!is_valid_kernel_addr(0x7f00_0000_1234));

        let mut symbolizer = Symbolizer::new();
        let stack = symbolizer.symbolize(
            "file",
            1,
            std::process::id(),
            &raw_user(vec![0x0041_bbd7, 0x6570_6f6e_2f70_6d74]),
        );
        assert_eq!(stack.frames.len(), 1, "garbage frame must be dropped");
        assert_eq!(stack.frames[0].addr, 0x0041_bbd7);
        assert_eq!(symbolizer.stats().invalid_frames, 1);
    }

    #[test]
    fn zero_pid_keeps_user_frames_raw() {
        let mut symbolizer = Symbolizer::new();
        let stack = symbolizer.symbolize("file", 1, 0, &raw_user(vec![0x7f00_0000_1234]));
        assert_eq!(stack.frames[0].addr, 0x7f00_0000_1234);
        assert_eq!(stack.frames[0].symbol, None);
        assert_eq!(symbolizer.stats().user_errors, 1);
    }

    /// Golden kernel-symbolization check. `/proc/kallsyms` zeroes addresses
    /// for unprivileged readers, so the test skips (rather than fails) when
    /// the running host cannot expose kernel addresses. In the lab VM the
    /// recorder runs as root and the kernel path is covered end to end by
    /// the recorded bundle evidence instead.
    #[test]
    fn kernel_symbolization_matches_kallsyms_when_readable() {
        let Ok(kallsyms) = std::fs::read_to_string("/proc/kallsyms") else {
            return;
        };
        let mut target: Option<(u64, String)> = None;
        for line in kallsyms.lines() {
            let mut fields = line.split_whitespace();
            let Some(address) = fields.next() else {
                continue;
            };
            let Some(kind) = fields.next() else { continue };
            let Some(name) = fields.next() else { continue };
            if kind != "T" && kind != "t" {
                continue;
            }
            if name == "schedule" || name == "do_syscall_64" {
                if let Ok(address) = u64::from_str_radix(address, 16) {
                    if address != 0 {
                        target = Some((address, name.to_string()));
                        break;
                    }
                }
            }
        }
        let Some((address, expected)) = target else {
            // Unprivileged process: kernel addresses are hidden.
            return;
        };
        let mut symbolizer = Symbolizer::new();
        let stack = symbolizer.symbolize(
            "process",
            1,
            0,
            &RawStack {
                kernel: vec![address],
                user: Vec::new(),
                truncated: false,
            },
        );
        let symbol = stack.frames[0]
            .symbol
            .as_deref()
            .expect("kernel kallsyms address must symbolize");
        assert!(
            symbol == expected || symbol.starts_with(&expected),
            "expected symbol {expected}, got {symbol}"
        );
        assert!(stack.frames[0].is_kernel);
    }
}
