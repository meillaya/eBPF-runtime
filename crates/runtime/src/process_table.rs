// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Track the executable behind each thread group.
//!
//! File and network events carry a pid, not a path. The process sensor
//! reports exec events, so the runtime keeps a small map from tgid to the
//! last binary the group executed. A file event can then name the program
//! that opened the file, which the default rules use in their exceptions.

use crate::decode::DecodedEvent;
use std::collections::HashMap;
use std::path::PathBuf;

/// Maximum number of processes tracked at once.
const MAX_PROCESSES: usize = 16_384;

/// A bounded tgid to executable map.
pub struct ProcessTable {
    executables: HashMap<u32, String>,
    proc_root: PathBuf,
}

impl ProcessTable {
    /// Create an empty table.
    pub fn new() -> Self {
        Self::with_proc_root("/proc")
    }

    /// Create a table that reads executables from `proc_root`.
    pub fn with_proc_root(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            executables: HashMap::new(),
            proc_root: proc_root.into(),
        }
    }

    /// Update the table from an event and fill `process_exec` when the
    /// executable is known.
    pub fn observe(&mut self, event: &mut DecodedEvent) {
        if event.kind == "ProcessExec" {
            if let Some(path) = &event.path {
                self.insert(event.tgid, path.clone());
            }
        } else if event.kind == "ProcessFork" {
            if let Some((child, path)) =
                event
                    .child_pid
                    .zip(event.parent_pid)
                    .and_then(|(child, parent)| {
                        self.executables
                            .get(&parent)
                            .cloned()
                            .map(|path| (child, path))
                    })
            {
                self.insert(child, path);
            }
        } else if event.kind == "ProcessExit" && event.thread != Some(true) {
            if event.process_exec.is_none() {
                event.process_exec = self.executables.get(&event.tgid).cloned();
            }
            self.executables.remove(&event.tgid);
        }

        if event.process_exec.is_none() && event.kind != "ProcessExec" {
            event.process_exec = self.lookup(event.tgid);
        }
    }

    fn insert(&mut self, tgid: u32, path: String) {
        if self.executables.len() >= MAX_PROCESSES {
            self.executables.clear();
        }
        self.executables.insert(tgid, path);
    }

    fn lookup(&mut self, tgid: u32) -> Option<String> {
        if let Some(path) = self.executables.get(&tgid) {
            return Some(path.clone());
        }

        let path = std::fs::read_link(self.proc_root.join(tgid.to_string()).join("exe"))
            .ok()
            .map(|path| path.to_string_lossy().into_owned())?;
        self.insert(tgid, path.clone());
        Some(path)
    }
}

impl Default for ProcessTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::DecodedEvent;
    use chrono::Utc;

    fn event(kind: &str, tgid: u32) -> DecodedEvent {
        DecodedEvent {
            time: Utc::now().to_rfc3339(),
            sensor: "process".to_string(),
            kind: kind.to_string(),
            pid: tgid,
            tgid,
            cgroup_id: 0,
            monotonic_ns: 0,
            task_start_ns: None,
            path: None,
            old_path: None,
            process_exec: None,
            argv: None,
            parent_pid: None,
            child_pid: None,
            exit_code: None,
            thread: None,
            flags: None,
            open_flags: None,
            mode: None,
            length: None,
            network: None,
            syscall: None,
            identity: None,
            dns: None,
            lsm: None,
            ..Default::default()
        }
    }

    #[test]
    fn exec_updates_the_table() {
        let mut table = ProcessTable::new();
        let mut exec = event("ProcessExec", 10);
        exec.path = Some("/usr/bin/cat".to_string());
        table.observe(&mut exec);
        assert_eq!(exec.process_exec, None);
        assert_eq!(
            table.executables.get(&10).map(String::as_str),
            Some("/usr/bin/cat")
        );
    }

    #[test]
    fn later_events_reuse_the_exec_path() {
        let mut table = ProcessTable::new();
        let mut exec = event("ProcessExec", 10);
        exec.path = Some("/usr/bin/cat".to_string());
        table.observe(&mut exec);

        let mut file = event("FileOpen", 10);
        table.observe(&mut file);
        assert_eq!(file.process_exec.as_deref(), Some("/usr/bin/cat"));
    }

    #[test]
    fn fork_inherits_the_parent_executable() {
        let mut table = ProcessTable::new();
        let mut exec = event("ProcessExec", 10);
        exec.path = Some("/usr/bin/bash".to_string());
        table.observe(&mut exec);

        let mut fork = event("ProcessFork", 10);
        fork.parent_pid = Some(10);
        fork.child_pid = Some(11);
        table.observe(&mut fork);
        assert_eq!(fork.process_exec.as_deref(), Some("/usr/bin/bash"));
    }

    #[test]
    fn exit_forgets_the_process() {
        let mut table = ProcessTable::new();
        let mut exec = event("ProcessExec", 10);
        exec.path = Some("/usr/bin/cat".to_string());
        table.observe(&mut exec);

        let mut exit = event("ProcessExit", 10);
        exit.thread = Some(false);
        table.observe(&mut exit);
        assert!(!table.executables.contains_key(&10));
    }
}
