// SPDX-License-Identifier: Apache-2.0 OR MIT
use agent_core::{AncestryStatus, NodeState, ProcessGraph, ProcessGraphOpts, ProcessIdentity};

fn id(pid: u32, start_time: u64) -> ProcessIdentity {
    ProcessIdentity {
        boot_id: [7; 16],
        pid,
        start_time,
    }
}
fn root(graph: &mut ProcessGraph) {
    graph.on_exec(id(1, 1), "/sbin/init".to_owned(), b"init".to_vec(), 1);
}

#[test]
fn fork_exec_exit_fixture_yields_three_node_tree() {
    let mut graph = ProcessGraph::new(ProcessGraphOpts::default());
    root(&mut graph);
    graph.on_fork(id(100, 10), id(1, 1), 10);
    graph.on_exec(id(100, 10), "/bin/true".to_owned(), b"true".to_vec(), 11);
    graph.on_exit(id(100, 10), 0, 12);
    let node = graph.lookup(&id(100, 10)).expect("child exists");
    assert_eq!(graph.snapshot().len(), 2);
    assert_eq!(node.parent, Some(id(1, 1)));
    assert_eq!(node.exec_path.as_deref(), Some("/bin/true"));
    assert_eq!(node.exit_code, Some(0));
    assert_eq!(node.state, NodeState::Exited);
    assert_eq!(node.first_seen_seq, 10);
    assert_eq!(node.last_updated_seq, 12);
}

#[test]
fn thread_distinction_fixture_marks_thread_flag() {
    let mut graph = ProcessGraph::new(ProcessGraphOpts::default());
    root(&mut graph);
    graph.on_fork(id(100, 10), id(1, 1), 10);
    assert!(graph.mark_thread(&id(100, 10)));
    graph.on_exec(
        id(100, 10),
        "/bin/thread".to_owned(),
        b"thread".to_vec(),
        11,
    );
    assert!(
        graph
            .lookup(&id(100, 10))
            .expect("thread exists")
            .thread_flag
    );
    assert_ne!(id(100, 10), id(1, 1));
}

#[test]
fn parent_before_after_fixture_records_partial_history() {
    let mut graph = ProcessGraph::new(ProcessGraphOpts::default());
    assert_eq!(
        graph.on_fork(id(100, 10), id(1, 1), 10),
        AncestryStatus::Missing
    );
    assert_eq!(
        graph.lookup(&id(100, 10)).expect("orphan exists").parent,
        None
    );
    assert_eq!(graph.ancestry_status(&id(100, 10)), AncestryStatus::Missing);
}

#[test]
fn missing_parent_fixture_returns_ancestry_incomplete() {
    let mut graph = ProcessGraph::new(ProcessGraphOpts::default());
    graph.on_fork(id(100, 10), id(1, 1), 10);
    assert_eq!(graph.ancestry_status(&id(100, 10)), AncestryStatus::Missing);
}

#[test]
fn sequence_gap_fixture_evicts_no_live_node() {
    let mut graph = ProcessGraph::new(ProcessGraphOpts {
        capacity: 50,
        ..ProcessGraphOpts::default()
    });
    root(&mut graph);
    for pid in 2..102 {
        graph.on_fork(id(pid, u64::from(pid)), id(1, 1), u64::from(pid));
        if pid >= 52 {
            graph.on_exit(id(pid, u64::from(pid)), 0, u64::from(pid) + 100);
        }
    }
    for pid in 2..52 {
        assert!(graph.lookup(&id(pid, u64::from(pid))).is_some());
    }
}

#[test]
fn pid_reuse_fixture_preserves_ancestry_via_start_time() {
    let mut graph = ProcessGraph::new(ProcessGraphOpts::default());
    root(&mut graph);
    let old = id(100, 10);
    let new = id(100, 20);
    graph.on_fork(old, id(1, 1), 10);
    graph.on_exit(old, 1, 11);
    graph.on_fork(new, id(1, 1), 12);
    assert_eq!(
        graph.lookup(&old).expect("old generation").state,
        NodeState::Exited
    );
    assert_ne!(old, new);
    assert_eq!(
        graph.lookup(&new).expect("new generation").parent,
        Some(id(1, 1))
    );
}

#[test]
fn three_generation_fixture_yields_correct_tree() {
    let mut graph = ProcessGraph::new(ProcessGraphOpts::default());
    root(&mut graph);
    let bash = id(100, 10);
    let leaf = id(101, 11);
    graph.on_fork(bash, id(1, 1), 10);
    graph.on_exec(bash, "/bin/bash".to_owned(), b"bash".to_vec(), 11);
    graph.on_fork(leaf, bash, 12);
    graph.on_exec(leaf, "/bin/true".to_owned(), b"true".to_vec(), 13);
    assert_eq!(graph.path(&leaf), Some(vec![id(1, 1), bash, leaf]));
    assert_eq!(
        graph.lookup(&bash).expect("bash").exec_path.as_deref(),
        Some("/bin/bash")
    );
}

#[test]
fn capacity_eviction_lru_skips_live_nodes() {
    let mut graph = ProcessGraph::new(ProcessGraphOpts {
        capacity: 50,
        ..ProcessGraphOpts::default()
    });
    root(&mut graph);
    for pid in 2..102 {
        let identity = id(pid, u64::from(pid));
        graph.on_fork(identity, id(1, 1), u64::from(pid));
        if pid < 12 {
            graph.on_exec(
                identity,
                "/bin/live".to_owned(),
                Vec::new(),
                u64::from(pid) + 100,
            );
        } else {
            graph.on_exit(identity, 0, u64::from(pid) + 100);
        }
    }
    for pid in 2..12 {
        assert!(graph.lookup(&id(pid, u64::from(pid))).is_some());
    }
}

#[test]
fn ttl_eviction_removes_old_exited_nodes() {
    let mut graph = ProcessGraph::new(ProcessGraphOpts {
        ttl_seconds: 3,
        ..ProcessGraphOpts::default()
    });
    root(&mut graph);
    for pid in 2..12 {
        let identity = id(pid, u64::from(pid));
        graph.on_fork(identity, id(1, 1), u64::from(pid));
        graph.on_exit(identity, 0, u64::from(pid) + 1);
    }
    graph.advance_time(4);
    assert!(graph.snapshot().len() <= 1);
}

#[test]
fn pid_reuse_across_different_boot_does_not_collide() {
    let mut graph = ProcessGraph::new(ProcessGraphOpts::default());
    let a = id(100, 10);
    let mut b = id(100, 20);
    b.boot_id = [8; 16];
    graph.on_exec(a, "/a".to_owned(), Vec::new(), 1);
    graph.on_exec(b, "/b".to_owned(), Vec::new(), 2);
    assert!(graph.lookup(&a).is_some());
    assert!(graph.lookup(&b).is_some());
}
