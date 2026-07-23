// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Truthful process-generation cache and ancestry graph.

use std::collections::HashMap;

const DEFAULT_CAPACITY: usize = 10_000;
const DEFAULT_TTL_SECONDS: u64 = 3_600;
const EXEC_PATH_LIMIT: usize = 256;
const ARGV_LIMIT: usize = 4 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessIdentity {
    pub boot_id: [u8; 16],
    pub pid: u32,
    pub start_time: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    Alive,
    Exited,
    Reaped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessNode {
    pub identity: ProcessIdentity,
    pub parent: Option<ProcessIdentity>,
    pub children: Vec<ProcessIdentity>,
    pub exec_path: Option<String>,
    pub argv_bytes: Option<Vec<u8>>,
    pub argv_truncated: bool,
    pub exit_code: Option<i32>,
    pub thread_flag: bool,
    pub state: NodeState,
    pub first_seen_seq: u64,
    pub last_updated_seq: u64,
    pub ancestry_status: AncestryStatus,
    exited_at_seconds: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AncestryStatus {
    Known,
    Missing,
    AncestryIncomplete,
    DuplicateFork,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessGraphOpts {
    pub capacity: usize,
    pub ttl_seconds: u64,
}

impl Default for ProcessGraphOpts {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_CAPACITY,
            ttl_seconds: DEFAULT_TTL_SECONDS,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProcessGraph {
    nodes: HashMap<ProcessIdentity, ProcessNode>,
    opts: ProcessGraphOpts,
    now_seconds: u64,
}

impl ProcessGraph {
    pub fn new(opts: ProcessGraphOpts) -> Self {
        Self {
            nodes: HashMap::new(),
            opts: ProcessGraphOpts {
                capacity: opts.capacity.max(1),
                ..opts
            },
            now_seconds: 0,
        }
    }

    pub fn on_fork(
        &mut self,
        child: ProcessIdentity,
        parent: ProcessIdentity,
        seq: u64,
    ) -> AncestryStatus {
        self.evict();
        if self.nodes.contains_key(&child) {
            return AncestryStatus::DuplicateFork;
        }
        let parent_known = self.nodes.contains_key(&parent);
        let status = if parent_known {
            AncestryStatus::Known
        } else {
            AncestryStatus::Missing
        };
        let thread_flag = self.nodes.get(&parent).is_some_and(|node| node.thread_flag);
        let leader = if thread_flag {
            self.nodes
                .get(&parent)
                .and_then(|node| node.parent)
                .or(Some(parent))
        } else {
            Some(parent)
        };
        self.nodes.insert(
            child,
            ProcessNode {
                identity: child,
                parent: if parent_known { leader } else { None },
                children: Vec::new(),
                exec_path: None,
                argv_bytes: None,
                argv_truncated: false,
                exit_code: None,
                thread_flag: false,
                state: NodeState::Alive,
                first_seen_seq: seq,
                last_updated_seq: seq,
                ancestry_status: status,
                exited_at_seconds: None,
            },
        );
        if let Some(parent_node) = self.nodes.get_mut(&parent) {
            parent_node.children.push(child);
        }
        self.evict_capacity();
        status
    }

    pub fn on_exec(
        &mut self,
        identity: ProcessIdentity,
        exec_path: String,
        argv_bytes: Vec<u8>,
        seq: u64,
    ) {
        self.evict();
        let node = self.nodes.entry(identity).or_insert_with(|| ProcessNode {
            identity,
            parent: None,
            children: Vec::new(),
            exec_path: None,
            argv_bytes: None,
            argv_truncated: false,
            exit_code: None,
            thread_flag: false,
            state: NodeState::Alive,
            first_seen_seq: seq,
            last_updated_seq: seq,
            ancestry_status: AncestryStatus::Missing,
            exited_at_seconds: None,
        });
        node.exec_path = Some(
            exec_path
                .bytes()
                .take(EXEC_PATH_LIMIT)
                .map(char::from)
                .collect(),
        );
        node.argv_truncated = argv_bytes.len() > ARGV_LIMIT;
        node.argv_bytes = Some(argv_bytes.into_iter().take(ARGV_LIMIT).collect());
        node.state = NodeState::Alive;
        node.last_updated_seq = seq;
        node.exit_code = None;
        node.exited_at_seconds = None;
        self.evict_capacity();
    }

    pub fn on_exit(&mut self, identity: ProcessIdentity, exit_code: i32, seq: u64) {
        self.evict();
        if let Some(node) = self.nodes.get_mut(&identity) {
            node.exit_code = Some(exit_code);
            node.state = NodeState::Exited;
            node.last_updated_seq = seq;
            node.exited_at_seconds = Some(self.now_seconds);
        }
        self.evict_capacity();
    }

    pub fn snapshot(&self) -> Vec<ProcessNode> {
        let mut nodes: Vec<_> = self.nodes.values().cloned().collect();
        nodes.sort_by_key(|node| node.first_seen_seq);
        nodes
    }

    pub fn ancestry_status(&self, identity: &ProcessIdentity) -> AncestryStatus {
        self.nodes
            .get(identity)
            .map_or(AncestryStatus::Missing, |node| node.ancestry_status)
    }

    pub fn lookup(&self, identity: &ProcessIdentity) -> Option<&ProcessNode> {
        self.nodes.get(identity)
    }

    pub fn path(&self, identity: &ProcessIdentity) -> Option<Vec<ProcessIdentity>> {
        let mut path = Vec::new();
        let mut current = *identity;
        loop {
            let node = self.nodes.get(&current)?;
            path.push(current);
            match node.parent {
                Some(parent) => current = parent,
                None => break,
            }
        }
        path.reverse();
        Some(path)
    }

    pub fn mark_thread(&mut self, identity: &ProcessIdentity) -> bool {
        self.nodes.get_mut(identity).is_some_and(|node| {
            node.thread_flag = true;
            true
        })
    }

    pub fn advance_time(&mut self, seconds: u64) {
        self.now_seconds = self.now_seconds.saturating_add(seconds);
        self.evict();
    }

    pub fn tick(&mut self) {
        self.evict();
    }

    fn evict(&mut self) {
        let expired: Vec<_> = self
            .nodes
            .iter()
            .filter_map(|(identity, node)| {
                node.exited_at_seconds
                    .filter(|when| self.now_seconds.saturating_sub(*when) > self.opts.ttl_seconds)
                    .map(|_| *identity)
            })
            .collect();
        for identity in expired {
            self.remove_node(&identity);
        }
        self.evict_capacity();
    }

    fn evict_capacity(&mut self) {
        while self.nodes.len() > self.opts.capacity {
            let victim = self
                .nodes
                .values()
                .filter(|node| node.state != NodeState::Alive)
                .min_by_key(|node| node.first_seen_seq)
                .map(|node| node.identity);
            let Some(identity) = victim else { break };
            self.remove_node(&identity);
        }
    }

    fn remove_node(&mut self, identity: &ProcessIdentity) {
        let Some(node) = self.nodes.remove(identity) else {
            return;
        };
        if let Some(parent) = node.parent.and_then(|parent| self.nodes.get_mut(&parent)) {
            parent.children.retain(|child| child != identity);
        }
        for child in node.children {
            if let Some(child_node) = self.nodes.get_mut(&child) {
                child_node.parent = None;
                child_node.ancestry_status = AncestryStatus::AncestryIncomplete;
            }
        }
    }
}
