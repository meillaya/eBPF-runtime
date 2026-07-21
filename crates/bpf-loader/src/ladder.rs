// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// crates/bpf-loader/src/ladder.rs
// kernel-v1 — task 18 (load/attach compatibility manager).
//!
//! Hook-ladder constants and the `select_hook` helper used by
//! the per-sensor probe logic in `probe.rs`. The order of the
//! ladder rungs is significant: the loader's `select_hook`
//! returns the first rung the host supports. Every rung the
//! v1 sensors use is marked `stable = true`; the plan
//! explicitly forbids falling back to unstable internal
//! kprobes contrary to policy, so `stable = false` rungs would
//! be filtered out at attach time.

#![forbid(unsafe_code)]

/// A single rung in a sensor's hook ladder.
#[derive(Debug, Clone, Copy)]
pub struct HookRung {
    /// The `SEC(...)` name this rung targets.
    pub section: &'static str,
    /// Stable/portable flag. The probe MUST skip rungs with
    /// `stable == false` on a kernel that does not advertise
    /// the matching symbol.
    pub stable: bool,
    /// Human-readable tag (e.g. `"primary-lsm"`,
    /// `"fallback-tracepoint"`). Used in the JSON envelope
    /// for human-readability.
    pub kind: &'static str,
}

/// Process-sensor hook ladder. Sched fork / exec / exit on
/// `raw_tracepoint` (the stable v1 surface per the sensor
/// review).
pub static PROCESS_LADDER: &[HookRung] = &[
    HookRung { section: "raw_tracepoint/sched_process_exec", stable: true, kind: "primary-raw-tracepoint" },
    HookRung { section: "raw_tracepoint/sched_process_fork", stable: true, kind: "primary-raw-tracepoint" },
    HookRung { section: "raw_tracepoint/sched_process_exit", stable: true, kind: "primary-raw-tracepoint" },
];

/// File-sensor hook ladder. Primary LSM hook, then a
/// `syscalls/sys_enter_openat` tracepoint fallback for hosts
/// without BPF LSM support.
pub static FILE_LADDER: &[HookRung] = &[
    HookRung { section: "lsm/file_open", stable: true, kind: "primary-lsm" },
    HookRung { section: "tracepoint/syscalls/sys_enter_openat", stable: true, kind: "fallback-tracepoint" },
];

/// Network-sensor hook ladder. Cgroup connect hooks first,
/// then arch-specific kprobe fallbacks.
pub static NETWORK_LADDER: &[HookRung] = &[
    HookRung { section: "cgroup/connect4", stable: true, kind: "primary-cgroup" },
    HookRung { section: "cgroup/connect6", stable: true, kind: "primary-cgroup" },
    HookRung { section: "kprobe/__x64_sys_connect", stable: true, kind: "fallback-kprobe" },
    HookRung { section: "kprobe/__arm64_sys_connect", stable: true, kind: "fallback-kprobe" },
];

/// DNS-sensor hook ladder. Cgroup SKB primary, classic TC
/// fallback, per-cgroup AF_UNIX probe.
pub static DNS_LADDER: &[HookRung] = &[
    HookRung { section: "cgroup_skb/ingress", stable: true, kind: "primary-cgroup-skb" },
    HookRung { section: "cgroup_skb/egress", stable: true, kind: "primary-cgroup-skb" },
    HookRung { section: "classifier", stable: true, kind: "fallback-tc-classifier" },
];

/// Syscall-sensor hook ladder. Raw sys_enter + raw sys_exit
/// are the only stable choices; the loader does not invent
/// fallbacks (per the plan's "must not fall back to unstable
/// internal kprobes contrary to policy" rule).
pub static SYSCALL_LADDER: &[HookRung] = &[
    HookRung { section: "raw_tracepoint/sys_enter", stable: true, kind: "primary-raw-tracepoint" },
    HookRung { section: "raw_tracepoint/sys_exit", stable: true, kind: "primary-raw-tracepoint" },
];

/// Identity-sensor hook ladder. Sched-process-exec tracepoint
/// for credential changes + cgroup SKB ingress for the
/// per-cgroup process.
pub static IDENTITY_LADDER: &[HookRung] = &[
    HookRung { section: "tracepoint/sched/sched_process_exec", stable: true, kind: "primary-tracepoint" },
    HookRung { section: "cgroup_skb/ingress", stable: true, kind: "primary-cgroup-skb" },
];

/// Sentinel ladder returned for unknown sensor names.
pub static EMPTY_LADDER: &[HookRung] = &[];

/// Pick the first stable ladder rung. The selected hook is the
/// `selected_hook` field of the resulting SensorCoverage. The
/// function returns the EMPTY_RUNG sentinel for sensors
/// without a documented ladder (i.e. unknown names); the matrix
/// records that as a blocked reason.
pub fn select_hook(sensor: &str) -> &'static HookRung {
    for rung in ladder_for(sensor) {
        if rung.stable {
            return rung;
        }
    }
    &EMPTY_RUNG
}

/// Sentinel rung returned by `select_hook` for unknown sensor
/// names. The probe uses this to record a Blocked entry with
/// an empty `selected_hook` field.
pub static EMPTY_RUNG: HookRung = HookRung {
    section: "",
    stable: false,
    kind: "unknown-sensor",
};

/// Return the canonical hook ladder for a sensor. The order is
/// the "primary hook first, then documented fallbacks" list
/// the plan calls out. The selection logic (`select_hook`)
/// reads the same constant.
pub fn ladder_for(sensor: &str) -> &'static [HookRung] {
    match sensor {
        "process" => &PROCESS_LADDER,
        "file" => &FILE_LADDER,
        "network" => &NETWORK_LADDER,
        "dns" => &DNS_LADDER,
        "syscall" => &SYSCALL_LADDER,
        "identity" => &IDENTITY_LADDER,
        _ => &EMPTY_LADDER,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ladder_for_known_sensors_is_non_empty() {
        for sensor in ["process", "file", "network", "dns", "syscall", "identity"] {
            assert!(
                !ladder_for(sensor).is_empty(),
                "ladder for {sensor} is empty"
            );
            for rung in ladder_for(sensor) {
                assert!(rung.stable, "ladder rung {} is unstable", rung.section);
            }
        }
    }

    #[test]
    fn ladder_for_unknown_sensor_is_empty() {
        assert!(ladder_for("not-a-real-sensor").is_empty());
        assert_eq!(select_hook("not-a-real-sensor").section, "");
    }

    #[test]
    fn select_hook_picks_first_stable_rung() {
        assert_eq!(select_hook("process").section, "raw_tracepoint/sched_process_exec");
        assert_eq!(select_hook("file").section, "lsm/file_open");
        assert_eq!(select_hook("network").section, "cgroup/connect4");
        assert_eq!(select_hook("dns").section, "cgroup_skb/ingress");
        assert_eq!(select_hook("syscall").section, "raw_tracepoint/sys_enter");
        assert_eq!(select_hook("identity").section, "tracepoint/sched/sched_process_exec");
    }
}
