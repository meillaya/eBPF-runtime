// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded socket lifecycle and DNS correlation table.
//!
//! Identity = `(cgroup_id, namespace_tuple[8], cookie)`. Two sockets are the
//! same identity only if all four match. Each identity holds a `Vec` of
//! generations so cookie reuse after close yields a new entry instead of
//! overwriting the old one. TTL and capacity eviction never overwrite a live
//! entry; capacity eviction drops the closed entry with the smallest
//! `connect_attempt_seq` first.

use crate::socket_entry::{
    SocketEntry, SocketFamily, SocketIdentity, SocketState, NAMESPACE_KIND_COUNT,
};
use crate::socket_opts::{CorrelationSet, SocketTableOpts};
use std::collections::HashMap;

const UNASSIGNED_FD: i32 = -1;

#[derive(Debug, Clone)]
pub struct SocketTable {
    entries: HashMap<SocketIdentity, Vec<SocketEntry>>,
    opts: SocketTableOpts,
    now_seconds: u64,
}

impl SocketTable {
    pub fn new(opts: SocketTableOpts) -> Self {
        Self {
            entries: HashMap::new(),
            opts: SocketTableOpts {
                capacity: opts.capacity.max(1),
                ..opts
            },
            now_seconds: 0,
        }
    }

    pub fn on_connect_attempt(
        &mut self,
        identity: SocketIdentity,
        pid_tgid: u64,
        dst_ip: [u8; 16],
        dst_port: u16,
        family: SocketFamily,
        seq: u64,
    ) -> SocketState {
        self.evict();
        let vec = self.entries.entry(identity).or_default();
        let reuse = vec
            .last()
            .is_some_and(|e| e.state != SocketState::Closed && e.dst_ip == dst_ip);
        if reuse {
            if let Some(entry) = vec.last_mut() {
                entry.pid_tgid = pid_tgid;
                entry.dst_ip = dst_ip;
                entry.dst_port = dst_port;
                entry.family = family;
                entry.flags = 0;
                entry.connect_attempt_seq = seq;
                entry.state = SocketState::Connecting;
            }
        } else {
            let generation = vec.last().map_or(0, |e| e.generation + 1);
            vec.push(SocketEntry {
                identity,
                pid_tgid,
                state: SocketState::Connecting,
                family,
                dst_ip,
                dst_port,
                flags: 0,
                connect_attempt_seq: seq,
                connect_result_seq: 0,
                accept_result_seq: 0,
                generation,
                fd: UNASSIGNED_FD,
                closed_at: None,
            });
        }
        self.evict_capacity();
        SocketState::Connecting
    }

    pub fn on_connect_result(
        &mut self,
        identity: SocketIdentity,
        result: i32,
        seq: u64,
    ) -> SocketState {
        self.evict();
        let new_state = if result >= 0 {
            SocketState::Connected
        } else {
            SocketState::Closed
        };
        if let Some(entry) = self.entries.get_mut(&identity).and_then(|v| v.last_mut()) {
            entry.connect_result_seq = seq;
            entry.state = new_state;
            entry.fd = UNASSIGNED_FD;
            if new_state == SocketState::Closed {
                entry.closed_at = Some(self.now_seconds);
            }
        }
        self.evict_capacity();
        new_state
    }

    pub fn on_accept(
        &mut self,
        identity: SocketIdentity,
        peer_pid_tgid: u64,
        fd: i32,
        seq: u64,
    ) -> SocketState {
        self.evict();
        let new_state = if fd >= 0 {
            SocketState::Accepted
        } else {
            SocketState::Closed
        };
        let vec = self.entries.entry(identity).or_default();
        if vec
            .last()
            .is_some_and(|e| e.state == SocketState::Connecting)
        {
            if let Some(entry) = vec.last_mut() {
                entry.pid_tgid = peer_pid_tgid;
                entry.family = SocketFamily::INET;
                entry.accept_result_seq = seq;
                entry.fd = fd;
                entry.state = new_state;
                if new_state == SocketState::Closed {
                    entry.closed_at = Some(self.now_seconds);
                }
            }
            self.evict_capacity();
            return new_state;
        }
        let generation = vec.last().map_or(0, |e| e.generation + 1);
        let closed_at = (new_state == SocketState::Closed).then_some(self.now_seconds);
        vec.push(SocketEntry {
            identity,
            pid_tgid: peer_pid_tgid,
            state: new_state,
            family: SocketFamily::INET,
            dst_ip: [0; 16],
            dst_port: 0,
            flags: 0,
            connect_attempt_seq: seq,
            connect_result_seq: 0,
            accept_result_seq: seq,
            generation,
            fd,
            closed_at,
        });
        self.evict_capacity();
        new_state
    }

    pub fn on_close(&mut self, identity: SocketIdentity, _seq: u64) -> SocketState {
        self.evict();
        if let Some(entry) = self.entries.get_mut(&identity).and_then(|v| v.last_mut()) {
            if entry.state != SocketState::Closed {
                entry.state = SocketState::Closed;
                entry.closed_at = Some(self.now_seconds);
            }
        }
        self.evict_capacity();
        SocketState::Closed
    }

    pub fn snapshot(&self) -> Vec<SocketEntry> {
        let mut all: Vec<SocketEntry> = self.entries.values().flatten().copied().collect();
        all.sort_by_key(|entry| (entry.connect_attempt_seq, entry.generation));
        all
    }
    pub fn socket_lookup(
        &self,
        cgroup_id: u64,
        namespace_tuple: [u64; NAMESPACE_KIND_COUNT],
        cookie: u64,
    ) -> Option<&SocketEntry> {
        let identity = SocketIdentity::new(cgroup_id, namespace_tuple, cookie);
        self.entries.get(&identity)?.last()
    }
    pub fn correlation_set(
        &self,
        cgroup_id: u64,
        namespace_tuple: [u64; NAMESPACE_KIND_COUNT],
        cookie: u64,
    ) -> CorrelationSet {
        let identity = SocketIdentity::new(cgroup_id, namespace_tuple, cookie);
        let mut set = CorrelationSet::default();
        if let Some(vec) = self.entries.get(&identity) {
            for entry in vec {
                if entry.accept_result_seq == 0 {
                    set.attempts.push(*entry);
                }
                if entry.connect_result_seq != 0 {
                    set.connects.push(*entry);
                }
                if entry.accept_result_seq != 0 {
                    set.accepts.push(*entry);
                }
                if entry.state == SocketState::Closed {
                    set.closes.push(*entry);
                }
            }
        }
        set
    }

    pub fn advance_time(&mut self, seconds: u64) {
        self.now_seconds = self.now_seconds.saturating_add(seconds);
        self.evict();
    }
    pub fn tick(&mut self) {
        self.evict();
    }

    pub fn len(&self) -> usize {
        self.entries.values().map(Vec::len).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn evict(&mut self) {
        let ttl = self.opts.ttl_seconds;
        let now = self.now_seconds;
        let expired: Vec<SocketEntry> = self
            .entries
            .values()
            .flat_map(|v| v.iter())
            .copied()
            .filter(|e| e.closed_at.is_some_and(|w| now.saturating_sub(w) > ttl))
            .collect();
        for entry in expired {
            self.remove_entry(entry.identity, entry.generation);
        }
        self.evict_capacity();
    }

    fn evict_capacity(&mut self) {
        while self.len() > self.opts.capacity {
            let victim = self
                .entries
                .values()
                .flat_map(|v| v.iter())
                .filter(|e| e.state == SocketState::Closed)
                .min_by_key(|e| (e.connect_attempt_seq, e.generation))
                .copied();
            let Some(victim) = victim else { break };
            self.remove_entry(victim.identity, victim.generation);
        }
    }

    fn remove_entry(&mut self, identity: SocketIdentity, generation: u32) {
        if let Some(vec) = self.entries.get_mut(&identity) {
            if let Some(pos) = vec.iter().position(|e| e.generation == generation) {
                vec.remove(pos);
            }
            if vec.is_empty() {
                self.entries.remove(&identity);
            }
        }
    }
}
