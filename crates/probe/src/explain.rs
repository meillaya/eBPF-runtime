// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Turn a captured verifier log into a compact, source-oriented explanation.
//!
//! [`explain`] is pure: it never loads a program and never needs privileges,
//! so it can run in CI and on an unprivileged workstation. It matches a
//! conservative table of common verifier causes, extracts the source
//! annotations (`; probe.bpf.c:42`) that libbpf prints for objects built with
//! `-g`, states how the captured log may be incomplete, and keeps the full
//! input text untouched.

use serde::Serialize;

/// Upper bound on matched causes in one explanation. A long verifier log can
/// repeat the same cause; the compact report stops at this many findings.
const MAX_FINDINGS: usize = 8;

/// Upper bound on distinct source annotations reported.
const MAX_SOURCE_REFS: usize = 16;

/// Upper bound on causes reported for one log line. A libbpf line can carry
/// both context (`failed to create`) and the real errno (`Operation not
/// permitted`); two findings keep both without flooding the report.
const MAX_CAUSES_PER_LINE: usize = 2;

/// One matched common verifier cause.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// 1-based line number in the original log.
    pub line: usize,
    /// Short cause name, for example `invalid memory access`.
    pub cause: String,
    /// The log line that matched, trimmed.
    pub log_line: String,
    /// Source-oriented next step for this cause.
    pub hint: String,
}

/// A compact explanation of one verifier log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Explanation {
    /// One-line summary that names the program when the log does.
    pub summary: String,
    /// How libbpf captured the log and when it can be incomplete.
    pub log_retention: String,
    /// Whether the captured text itself reports a full or truncated buffer.
    pub truncated: bool,
    /// Common causes matched in log order, at most 8.
    pub findings: Vec<Finding>,
    /// Source annotations printed by the verifier (`probe.bpf.c:42`), in
    /// first-seen order and deduplicated.
    pub source_refs: Vec<String>,
    /// The complete input text, unmodified.
    pub full_log: String,
}

/// A table entry for one common verifier cause.
struct Cause {
    /// Lower-case substring to match in a log line.
    needle: &'static str,
    /// Short cause name reported to the user.
    cause: &'static str,
    /// Source-oriented next step.
    hint: &'static str,
}

/// Common verifier causes, most specific first. At most one cause is reported
/// per log line so a single generic line cannot flood the report.
const CAUSES: &[Cause] = &[
    Cause {
        needle: "invalid mem access",
        cause: "invalid memory access",
        hint: "the verifier could not prove the access is in bounds or the pointer has the wrong type. Check every pointer before dereference, reserve and write ring-buffer records with the same compile-time size, and pass only constant sizes to fleet_probe_submit().",
    },
    Cause {
        needle: "!read_ok",
        cause: "uninitialized read",
        hint: "a stack slot or map value is read before it is written. Initialize payload structs (for example `= {0}`) and write every byte of the record you submit.",
    },
    Cause {
        needle: "back-edge",
        cause: "unbounded loop",
        hint: "every loop must have a bound the verifier can prove. Use a literal trip count or `#pragma unroll` for small fixed loops; a bound read from a payload or map value is not provable.",
    },
    Cause {
        needle: "processed ",
        cause: "complexity limit",
        hint: "the program exceeded the verifier's instruction/complexity budget. Reduce unrolling, split the probe into smaller programs, or move work to userspace.",
    },
    Cause {
        needle: "unreachable insn",
        cause: "unreachable instruction",
        hint: "a branch makes code unreachable (usually a constant condition). Remove it; some kernels reject the program instead of pruning it silently.",
    },
    Cause {
        needle: "unknown func",
        cause: "unknown helper",
        hint: "the kernel does not know this helper ID. Check the helper against the target kernel release and program type; some helpers are GPL-only or newer than the kernel.",
    },
    Cause {
        needle: "invalid func",
        cause: "invalid helper call",
        hint: "the program type cannot call this helper, or the helper ABI differs. Check bpf_helper_defs.h from the target libbpf and the target kernel release.",
    },
    Cause {
        needle: "invalid bpf_context access",
        cause: "context access",
        hint: "the program read a context field the attach type does not expose, or used the wrong context layout. For tracepoints read the tracepoint record through helpers instead of assuming a vmlinux struct layout.",
    },
    Cause {
        needle: "arg#",
        cause: "helper argument mismatch",
        hint: "a helper argument has the wrong type, size, or provenance (for example a stack pointer where a map-value pointer is required). Check the helper prototype in bpf_helper_defs.h.",
    },
    Cause {
        needle: "stack limit",
        cause: "stack size",
        hint: "the BPF stack is 512 bytes per program and shared with callees. Shrink local buffers or keep the payload struct off the stack.",
    },
    Cause {
        needle: "relo",
        cause: "CO-RE relocation",
        hint: "a CO-RE relocation could not be applied to the target kernel BTF. Rebuild vmlinux.h from the target kernel's BTF (`cargo run -p bpf-build -- build`) or guard the field access with bpf_core_field_exists().",
    },
    Cause {
        needle: "cannot access ptr",
        cause: "invalid pointer access",
        hint: "a pointer with unknown provenance was dereferenced. Only access pointers the verifier knows: stack, map values, ring-buffer reservations, context, or pointers returned by helpers.",
    },
    Cause {
        needle: "-eperm",
        cause: "privileges",
        hint: "the kernel refused a BPF operation with EPERM. Loading BPF objects requires root or CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN, and a host that sets kernel.unprivileged_bpf_disabled refuses even map creation. Re-run privileged; this is not a verifier rejection.",
    },
    Cause {
        needle: "rlimit_memlock",
        cause: "memlock limit",
        hint: "libbpf could not raise RLIMIT_MEMLOCK. Raise the limit explicitly (ulimit -l unlimited) or run privileged; kernels with memcg BPF accounting usually still allow the load once the process has CAP_BPF.",
    },
    Cause {
        needle: "couldn't load trivial bpf program",
        cause: "BPF syscall unavailable",
        hint: "the kernel refused libbpf's minimal BPF feature probe. Check CONFIG_BPF_SYSCALL, the process capabilities, and kernel.unprivileged_bpf_disabled; a locked-down host cannot verify any object without privileges.",
    },
    Cause {
        needle: "failed to create",
        cause: "map or object creation",
        hint: "the kernel refused to create a map (or another object) declared by the probe. Check the map type/flags against the target kernel and raise RLIMIT_MEMLOCK if the map is large.",
    },
    Cause {
        needle: "operation not permitted",
        cause: "privileges",
        hint: "loading BPF objects requires root or CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN. Re-run with the required capabilities; this is not a verifier rejection.",
    },
    Cause {
        needle: "permission denied",
        cause: "privileges",
        hint: "loading BPF objects requires root or CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN. Re-run with the required capabilities; this is not a verifier rejection.",
    },
    Cause {
        needle: "not supported",
        cause: "unsupported kernel feature",
        hint: "the target kernel or program type does not support this feature. Check the supported-release matrix before relying on it.",
    },
];

/// Explain a captured verifier log.
///
/// The returned [`Explanation`] always contains the full input in
/// [`Explanation::full_log`]; [`Explanation::render`] produces the compact
/// human-readable form. The call is pure and never needs privileges, so it is
/// safe to run on an unprivileged workstation or in CI.
///
/// # Example
///
/// ```
/// let log = "libbpf: prog 'hello_probe_exec': BPF program load failed: Permission denied\n\
///            ; hello_probe.bpf.c:56\n\
///            invalid mem access 'r2'";
/// let explanation = probe::explain(log);
/// assert!(explanation.findings.iter().any(|finding| finding.cause == "invalid memory access"));
/// assert_eq!(explanation.source_refs, vec!["hello_probe.bpf.c:56"]);
/// assert_eq!(explanation.full_log, log);
/// ```
pub fn explain(error_text: &str) -> Explanation {
    let empty = error_text.trim().is_empty();
    let mut findings = Vec::new();
    let mut source_refs: Vec<String> = Vec::new();
    let mut truncated = false;

    for (index, raw_line) in error_text.lines().enumerate() {
        let line = raw_line.trim();
        let lower = line.to_ascii_lowercase();

        if lower.contains("log buffer")
            || lower.contains("log_buf")
            || lower.contains("enospc")
            || lower.contains("truncated")
        {
            truncated = true;
        }

        if !empty {
            let mut matched_on_line = 0;
            for cause in CAUSES {
                if findings.len() >= MAX_FINDINGS || matched_on_line >= MAX_CAUSES_PER_LINE {
                    break;
                }
                if lower.contains(cause.needle) {
                    findings.push(Finding {
                        line: index + 1,
                        cause: cause.cause.to_string(),
                        log_line: line.to_string(),
                        hint: cause.hint.to_string(),
                    });
                    matched_on_line += 1;
                }
            }
        }

        if source_refs.len() < MAX_SOURCE_REFS {
            if let Some(source) = source_reference(line) {
                if !source_refs.iter().any(|seen| seen == source) {
                    source_refs.push(source.to_string());
                }
            }
        }
    }

    Explanation {
        summary: summarize(error_text, &findings, &source_refs),
        log_retention: retention_text(empty, truncated),
        truncated,
        findings,
        source_refs,
        full_log: error_text.to_string(),
    }
}

impl Explanation {
    /// Render the compact, human-readable explanation.
    ///
    /// The output names the matched causes with their log lines and hints,
    /// lists the source annotations, states the log-retention rules, and ends
    /// with the full captured log unchanged.
    pub fn render(&self) -> String {
        let mut rendered = String::new();
        rendered.push_str(&self.summary);
        rendered.push('\n');

        if !self.findings.is_empty() {
            rendered.push_str("\nmatched causes:\n");
            for finding in &self.findings {
                rendered.push_str(&format!(
                    "  line {}: {}\n    > {}\n    hint: {}\n",
                    finding.line, finding.cause, finding.log_line, finding.hint
                ));
            }
        }

        if !self.source_refs.is_empty() {
            rendered.push_str("\nsource references: ");
            rendered.push_str(&self.source_refs.join(", "));
            rendered.push('\n');
        }

        rendered.push_str("\nlog retention:\n");
        rendered.push_str(&self.log_retention);
        rendered.push_str("\n\nfull verifier log:\n");
        rendered.push_str(self.full_log.trim_end());
        rendered.push('\n');
        rendered
    }
}

/// One-line summary that names the program when the log does.
fn summarize(error_text: &str, findings: &[Finding], source_refs: &[String]) -> String {
    if error_text.trim().is_empty() {
        return "no verifier log to explain".to_string();
    }
    let program = program_name(error_text);
    match program {
        Some(program) => format!(
            "verifier log for program `{program}`: {} matched cause(s), {} source reference(s)",
            findings.len(),
            source_refs.len()
        ),
        None => format!(
            "verifier log: {} matched cause(s), {} source reference(s)",
            findings.len(),
            source_refs.len()
        ),
    }
}

/// Extract the program name from libbpf's `prog '<name>':` preamble.
fn program_name(error_text: &str) -> Option<String> {
    let after_marker = error_text.split("prog '").nth(1)?;
    let end = after_marker.find('\'')?;
    let name = &after_marker[..end];
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Extract a `probe.bpf.c:42` source annotation from a verifier log line.
fn source_reference(line: &str) -> Option<&str> {
    let rest = line.strip_prefix(';')?.trim();
    let token_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let token = &rest[..token_end];
    let (file, line_number) = token.rsplit_once(':')?;
    let source_file = file.ends_with(".c") || file.ends_with(".h");
    if source_file && !line_number.is_empty() && line_number.chars().all(|c| c.is_ascii_digit()) {
        Some(token)
    } else {
        None
    }
}

/// Explain how the captured log was produced and when it can be incomplete.
fn retention_text(empty: bool, truncated: bool) -> String {
    if empty {
        return "no verifier log was captured. An empty log usually means the load failed before the verifier ran (missing privileges, an invalid object, or a map-creation failure), or that libbpf's log callback was not installed. Re-run the load with log capture enabled before reading a verifier diagnosis.".to_string();
    }

    let mut text = String::from(
        "libbpf captures the kernel verifier log for a failed load and prints it between `-- BEGIN PROG LOAD LOG --` and `-- END PROG LOAD LOG --`; the full log below is that captured text, unmodified. The kernel writes the log only into the buffer it is given and stops at the end, so a very large program or an explicit small log buffer can cut it short; libbpf retries with a larger buffer on ENOSPC. Read backwards from the end: the last instruction or source annotation before the failure is the useful one. Source annotations (`; probe.bpf.c:42`) exist because the object was built with `-g`.",
    );
    if truncated {
        text.push_str(" This captured text mentions a full or truncated log buffer: re-run with a larger log buffer before trusting the tail.");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_LOG: &str = "\
libbpf: prog 'hello_probe_exec': BPF program load failed: Invalid argument
libbpf: prog 'hello_probe_exec': -- BEGIN PROG LOAD LOG --
0: (b7) r1 = 0
; hello_probe.bpf.c:34
1: (85) call bpf_get_current_comm#16
; hello_probe.bpf.c:39
invalid mem access 'r2'
processed 12 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 1
-- END PROG LOAD LOG --
";

    #[test]
    fn matches_common_causes_and_source_refs() {
        let explanation = explain(SAMPLE_LOG);
        assert_eq!(explanation.full_log, SAMPLE_LOG);
        assert!(!explanation.truncated);
        assert!(explanation
            .findings
            .iter()
            .any(|finding| finding.cause == "invalid memory access"));
        assert!(explanation
            .findings
            .iter()
            .any(|finding| finding.cause == "complexity limit"));
        assert_eq!(
            explanation.source_refs,
            vec!["hello_probe.bpf.c:34", "hello_probe.bpf.c:39"]
        );
        assert!(explanation.summary.contains("hello_probe_exec"));
        assert!(explanation.render().contains("full verifier log:"));
    }

    #[test]
    fn empty_log_is_explained_without_findings() {
        let explanation = explain("   \n");
        assert!(explanation.findings.is_empty());
        assert!(explanation.source_refs.is_empty());
        assert!(explanation.log_retention.contains("no verifier log"));
        assert_eq!(explanation.summary, "no verifier log to explain");
    }

    #[test]
    fn mentions_truncated_buffer() {
        let explanation = explain("log buffer is full; verifier output truncated");
        assert!(explanation.truncated);
        assert!(explanation.log_retention.contains("larger log buffer"));
    }

    #[test]
    fn permission_failure_is_matched_as_privileges() {
        let explanation =
            explain("libbpf: map 'hello_events': failed to create: Operation not permitted\n");
        assert!(explanation
            .findings
            .iter()
            .any(|finding| finding.cause == "privileges"));
        assert!(explanation.render().contains("CAP_BPF"));
    }

    #[test]
    fn findings_are_bounded() {
        let log = "invalid mem access\n".repeat(50);
        let explanation = explain(&log);
        assert_eq!(explanation.findings.len(), MAX_FINDINGS);
    }

    #[test]
    fn source_reference_requires_a_line_number() {
        assert_eq!(
            source_reference("; hello_probe.bpf.c:42"),
            Some("hello_probe.bpf.c:42")
        );
        assert_eq!(source_reference("; hello_probe.bpf.c"), None);
        assert_eq!(source_reference("invalid mem access"), None);
    }
}
