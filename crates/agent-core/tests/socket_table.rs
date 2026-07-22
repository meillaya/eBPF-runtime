// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Host-side acceptance tests for the bounded socket lifecycle table.

use agent_core::{
    CorrelationSet, SocketEntry, SocketFamily, SocketIdentity, SocketState, SocketTable,
    SocketTableOpts, NAMESPACE_KIND_COUNT, NS_CGROUP, NS_IPC, NS_MNT, NS_NET, NS_PID, NS_TIME,
    NS_USER, NS_UTS,
};

fn ns_tuple(seed: u64) -> [u64; NAMESPACE_KIND_COUNT] {
    [
        seed.wrapping_add(NS_PID as u64),
        seed.wrapping_add(NS_MNT as u64),
        seed.wrapping_add(NS_NET as u64),
        seed.wrapping_add(NS_USER as u64),
        seed.wrapping_add(NS_UTS as u64),
        seed.wrapping_add(NS_IPC as u64),
        seed.wrapping_add(NS_TIME as u64),
        seed.wrapping_add(NS_CGROUP as u64),
    ]
}

fn identity(cgroup: u64, cookie: u64) -> SocketIdentity {
    SocketIdentity::new(cgroup, ns_tuple(cgroup), cookie)
}

fn ipv4(bytes: [u8; 4]) -> [u8; 16] {
    let mut out = [0_u8; 16];
    out[..4].copy_from_slice(&bytes);
    out
}

#[test]
fn connect_attempt_then_result_records_attempt_and_result_with_same_cookie() {
    let mut table = SocketTable::new(SocketTableOpts::default());
    let id = identity(0xA1, 0xC0_FFEE);
    let dst = ipv4([10, 0, 0, 5]);
    table.on_connect_attempt(id, 0x1234, dst, 443, SocketFamily::INET, 1);
    let new_state = table.on_connect_result(id, 0, 2);
    assert_eq!(new_state, SocketState::Connected);
    let entry = table
        .socket_lookup(id.cgroup_id, id.namespace_tuple, id.cookie)
        .expect("entry present");
    assert_eq!(entry.connect_attempt_seq, 1);
    assert_eq!(entry.connect_result_seq, 2);
    assert_eq!(entry.dst_port, 443);
    assert_eq!(entry.dst_ip[..4], [10, 0, 0, 5]);
    assert_eq!(entry.state, SocketState::Connected);
}

#[test]
fn connect_attempt_then_failed_records_attempt_with_errno_in_closed_state() {
    let mut table = SocketTable::new(SocketTableOpts::default());
    let id = identity(0xA1, 0xC0_FFEE);
    let dst = ipv4([10, 0, 0, 5]);
    table.on_connect_attempt(id, 0x1234, dst, 443, SocketFamily::INET, 1);
    let new_state = table.on_connect_result(id, -111, 2);
    assert_eq!(new_state, SocketState::Closed);
    let entry = table
        .socket_lookup(id.cgroup_id, id.namespace_tuple, id.cookie)
        .expect("entry present");
    assert_eq!(entry.state, SocketState::Closed);
    assert_eq!(entry.connect_attempt_seq, 1);
    assert_eq!(entry.connect_result_seq, 2);
}

#[test]
fn accept_after_connect_records_two_generations_with_different_seq() {
    let mut table = SocketTable::new(SocketTableOpts::default());
    let id = identity(0xA1, 0xC0_FFEE);
    let dst = ipv4([10, 0, 0, 5]);
    table.on_connect_attempt(id, 0x1234, dst, 443, SocketFamily::INET, 10);
    table.on_connect_result(id, 0, 11);
    let new_state = table.on_accept(id, 0xB33F, 7, 12);
    assert_eq!(new_state, SocketState::Accepted);
    let snap = table.snapshot();
    assert_eq!(snap.len(), 2);
    let gen0 = snap
        .iter()
        .find(|e| e.generation == 0)
        .expect("gen 0 present");
    let gen1 = snap
        .iter()
        .find(|e| e.generation == 1)
        .expect("gen 1 present");
    assert_eq!(gen0.connect_attempt_seq, 10);
    assert_eq!(gen0.state, SocketState::Connected);
    assert_eq!(gen1.accept_result_seq, 12);
    assert_eq!(gen1.fd, 7);
    assert_eq!(gen1.state, SocketState::Accepted);
}

#[test]
fn cookie_reuse_after_close_records_new_generation_not_overwrite() {
    let mut table = SocketTable::new(SocketTableOpts::default());
    let id = identity(0xA1, 0xC0_FFEE);
    let dst = ipv4([10, 0, 0, 5]);
    table.on_connect_attempt(id, 0x1234, dst, 443, SocketFamily::INET, 1);
    table.on_connect_result(id, 0, 2);
    table.on_close(id, 3);
    table.on_connect_attempt(id, 0xCAFE, dst, 80, SocketFamily::INET, 4);
    let snap = table.snapshot();
    assert_eq!(snap.len(), 2);
    let gen0 = snap
        .iter()
        .find(|e| e.generation == 0)
        .expect("gen 0 present");
    let gen1 = snap
        .iter()
        .find(|e| e.generation == 1)
        .expect("gen 1 present");
    assert_eq!(gen0.state, SocketState::Closed);
    assert_eq!(gen0.connect_attempt_seq, 1);
    assert_eq!(gen1.state, SocketState::Connecting);
    assert_eq!(gen1.connect_attempt_seq, 4);
    assert_eq!(gen1.pid_tgid, 0xCAFE);
}

#[test]
fn cookie_reuse_after_close_records_different_fd_for_same_identity() {
    let mut table = SocketTable::new(SocketTableOpts::default());
    let id = identity(0xA1, 0xC0_FFEE);
    let dst = ipv4([10, 0, 0, 5]);
    table.on_connect_attempt(id, 0x1234, dst, 443, SocketFamily::INET, 1);
    table.on_connect_result(id, 0, 2);
    table.on_close(id, 3);
    table.on_connect_attempt(id, 0x1234, dst, 443, SocketFamily::INET, 4);
    table.on_accept(id, 0xB33F, 9, 5);
    let snap = table.snapshot();
    assert_eq!(snap.len(), 2);
    let gen0 = snap
        .iter()
        .find(|e| e.generation == 0)
        .expect("gen 0 present");
    let gen1 = snap
        .iter()
        .find(|e| e.generation == 1)
        .expect("gen 1 present");
    assert_eq!(gen0.fd, -1);
    assert_eq!(gen1.fd, 9);
    assert_eq!(gen1.state, SocketState::Accepted);
}

#[test]
fn cookie_reuse_across_namespaces_does_not_collide() {
    let mut table = SocketTable::new(SocketTableOpts::default());
    let ns_a = ns_tuple(0x1);
    let ns_b = ns_tuple(0x2);
    let id_a = SocketIdentity::new(0xC0_FFEE, ns_a, 0xABCD);
    let id_b = SocketIdentity::new(0xC0_FFEE, ns_b, 0xABCD);
    let dst = ipv4([10, 0, 0, 5]);
    table.on_connect_attempt(id_a, 0x1234, dst, 443, SocketFamily::INET, 1);
    table.on_connect_attempt(id_b, 0x5678, dst, 80, SocketFamily::INET, 2);
    let snap = table.snapshot();
    assert_eq!(snap.len(), 2);
    assert_eq!(snap[0].identity.namespace_tuple, ns_a);
    assert_eq!(snap[1].identity.namespace_tuple, ns_b);
    assert_ne!(
        snap[0].identity.namespace_tuple,
        snap[1].identity.namespace_tuple
    );
}

#[test]
fn capacity_eviction_removes_oldest_closed_entry() {
    let opts = SocketTableOpts {
        capacity: 3,
        ..SocketTableOpts::default()
    };
    let mut table = SocketTable::new(opts);
    for i in 0..4 {
        let id = identity(0xA1, 0x1000 + i);
        let dst = ipv4([10, 0, 0, (i & 0xFF) as u8]);
        table.on_connect_attempt(id, 0x1000 + i, dst, 443, SocketFamily::INET, i + 1);
        table.on_connect_result(id, 0, i + 2);
        table.on_close(id, i + 3);
    }
    assert!(table.len() <= 3);
    let snap = table.snapshot();
    let oldest_seq = snap
        .iter()
        .map(|e| e.connect_attempt_seq)
        .min()
        .unwrap_or(0);
    assert!(oldest_seq >= 2);
}

#[test]
fn capacity_eviction_skips_live_entries() {
    let opts = SocketTableOpts {
        capacity: 2,
        ..SocketTableOpts::default()
    };
    let mut table = SocketTable::new(opts);
    let id_live = identity(0xA1, 0x1000);
    let id_closed_1 = identity(0xA1, 0x2000);
    let id_closed_2 = identity(0xA1, 0x3000);
    let dst = ipv4([10, 0, 0, 1]);
    table.on_connect_attempt(id_live, 0x1000, dst, 443, SocketFamily::INET, 1);
    table.on_connect_attempt(id_closed_1, 0x2000, dst, 80, SocketFamily::INET, 2);
    table.on_connect_result(id_closed_1, 0, 3);
    table.on_close(id_closed_1, 4);
    table.on_connect_attempt(id_closed_2, 0x3000, dst, 8080, SocketFamily::INET, 5);
    table.on_connect_result(id_closed_2, 0, 6);
    table.on_close(id_closed_2, 7);
    assert!(table
        .socket_lookup(id_live.cgroup_id, id_live.namespace_tuple, id_live.cookie)
        .is_some());
    assert!(table.len() <= 2);
}

#[test]
fn ttl_eviction_removes_old_closed_entries() {
    let opts = SocketTableOpts {
        ttl_seconds: 5,
        ..SocketTableOpts::default()
    };
    let mut table = SocketTable::new(opts);
    for i in 0..4 {
        let id = identity(0xA1, 0x4000 + i);
        let dst = ipv4([10, 0, 0, i as u8]);
        table.on_connect_attempt(id, 0x4000 + i, dst, 443, SocketFamily::INET, i + 1);
        table.on_connect_result(id, 0, i + 2);
        table.on_close(id, i + 3);
    }
    table.advance_time(10);
    assert!(table.is_empty());
}

#[test]
fn snapshot_returns_entries_ordered_by_connect_seq() {
    let mut table = SocketTable::new(SocketTableOpts::default());
    for seq in [5, 1, 3, 2, 4] {
        let id = identity(0xA1, 0x5000 + seq);
        let dst = ipv4([10, 0, 0, seq as u8]);
        table.on_connect_attempt(id, 0x5000 + seq, dst, 443, SocketFamily::INET, seq);
    }
    let snap = table.snapshot();
    let seqs: Vec<u64> = snap.iter().map(|e| e.connect_attempt_seq).collect();
    assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
}

#[test]
fn correlation_set_returns_all_matching_entries_for_cookie_reuse() {
    let mut table = SocketTable::new(SocketTableOpts::default());
    let id = identity(0xA1, 0xCAFE);
    let dst = ipv4([10, 0, 0, 1]);
    table.on_connect_attempt(id, 0x1234, dst, 443, SocketFamily::INET, 1);
    table.on_connect_result(id, 0, 2);
    table.on_accept(id, 0xB33F, 5, 3);
    table.on_close(id, 4);
    table.on_connect_attempt(id, 0xCAFE, dst, 80, SocketFamily::INET, 5);
    table.on_connect_result(id, 0, 6);
    table.on_close(id, 7);
    let set: CorrelationSet = table.correlation_set(id.cgroup_id, id.namespace_tuple, id.cookie);
    assert_eq!(set.attempts.len(), 2);
    assert_eq!(set.connects.len(), 2);
    assert_eq!(set.accepts.len(), 1);
    assert_eq!(set.closes.len(), 2);
}

#[test]
fn correlation_set_returns_empty_for_unknown_cookie() {
    let table = SocketTable::new(SocketTableOpts::default());
    let id = identity(0xA1, 0xDEAD);
    let set = table.correlation_set(id.cgroup_id, id.namespace_tuple, id.cookie);
    assert!(set.attempts.is_empty());
    assert!(set.connects.is_empty());
    assert!(set.accepts.is_empty());
    assert!(set.closes.is_empty());
}

#[test]
fn dual_stack_connect_attempt_v4_v6_with_same_cookie_records_two_entries() {
    let mut table = SocketTable::new(SocketTableOpts::default());
    let id = identity(0xA1, 0xBEEF);
    let dst_v4 = ipv4([10, 0, 0, 1]);
    let mut dst_v6 = [0_u8; 16];
    dst_v6[..6].copy_from_slice(&[0xFE, 0x80, 0, 0, 0, 0]);
    dst_v6[6..16].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    table.on_connect_attempt(id, 0x1234, dst_v4, 443, SocketFamily::INET, 1);
    let same_id_again = SocketIdentity::new(id.cgroup_id, id.namespace_tuple, id.cookie);
    table.on_connect_attempt(same_id_again, 0x1234, dst_v6, 443, SocketFamily::INET6, 2);
    let snap = table.snapshot();
    assert_eq!(snap.len(), 2);
    let mut entries = snap.iter().collect::<Vec<&SocketEntry>>();
    entries.sort_by_key(|e| e.generation);
    assert_eq!(entries[0].family, SocketFamily::INET);
    assert_eq!(entries[1].family, SocketFamily::INET6);
}
