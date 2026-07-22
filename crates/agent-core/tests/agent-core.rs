// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Host-side acceptance tests for the bounded normalized pipeline.

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use agent_core::{
    normalize_bytes, synthetic_record, AgentCore, AgentCoreOpts, BoundedChannel, ControlEvent,
    EventPriority, KillSwitchReason, KillSwitchState, PriorityBoundedChannel, SendError,
};
use event_abi::DecodeError;

#[test]
fn bounded_channel_drops_when_full() {
    // Given: a bounded queue and an independently owned drop counter.
    let channel = BoundedChannel::new(8);
    let drops = AtomicU64::new(0);
    // When: the producer fills all eight slots and attempts one more send.
    for value in 0..8 {
        assert_eq!(channel.try_send(value), Ok(()));
    }
    let ninth = channel.try_send(9);
    if ninth.is_err() {
        drops.fetch_add(1, Ordering::Relaxed);
    }
    // Then: the message is returned, depth stays bounded, and loss is explicit.
    assert_eq!(ninth, Err(SendError(9)));
    assert_eq!(channel.len(), 8);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}

#[test]
fn priority_channel_routes_control_messages_in_order() {
    // Given: data already waiting in the lower-priority lane.
    let channel = PriorityBoundedChannel::new(8, 8);
    assert_eq!(
        channel.try_send_with_priority(1, EventPriority::Data),
        Ok(())
    );
    assert_eq!(
        channel.try_send_with_priority(2, EventPriority::Data),
        Ok(())
    );
    // When: a control message arrives later.
    assert_eq!(
        channel.try_send_with_priority(7, EventPriority::Control),
        Ok(())
    );
    // Then: the consumer receives control first and preserves data order.
    assert_eq!(channel.try_recv(), Some(7));
    assert_eq!(channel.try_recv(), Some(1));
    assert_eq!(channel.try_recv(), Some(2));
}

#[test]
fn decoder_rejects_unknown_major_returns_decode_error() {
    // Given: an otherwise valid record with a future incompatible major.
    let mut bytes = synthetic_record(1);
    bytes[0..4].copy_from_slice(&99_u32.to_le_bytes());
    // When: the safe boundary parser normalizes it.
    let result = std::panic::catch_unwind(|| normalize_bytes(&bytes));
    // Then: it returns the typed error without unwinding.
    assert!(matches!(
        result,
        Ok(Err(DecodeError::UnknownSchemaMajor { got: 99, .. }))
    ));
}

#[test]
fn decoder_rejects_unknown_event_kind_returns_decode_error() {
    // Given: a valid v1 envelope with an unknown event discriminant.
    let mut bytes = synthetic_record(1);
    bytes[16] = 99;
    // When: normalization dispatches on the kind.
    let result = std::panic::catch_unwind(|| normalize_bytes(&bytes));
    // Then: the typed unknown-kind error is returned without panic.
    assert!(matches!(
        result,
        Ok(Err(DecodeError::UnknownEventKind { byte: 99, .. }))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn sequence_gap_detection_increments_counter() {
    // Given: an active replay pipeline with exact sequence tracking.
    let core = AgentCore::start_replay(AgentCoreOpts::default())
        .await
        .expect("pipeline starts");
    // When: sequence 42 is followed by sequence 50.
    core.ingest_bytes(&synthetic_record(42))
        .expect("first record parses");
    core.ingest_bytes(&synthetic_record(50))
        .expect("second record parses");
    core.shutdown().await;
    // Then: one gap decision is recorded.
    assert_eq!(core.seq_gap_count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn kill_switch_drains_channels_without_panic() {
    // Given: a delayed sink with one hundred queued data records.
    let opts = AgentCoreOpts {
        data_capacity: 128,
        emit_delay: Duration::from_millis(1),
        ..AgentCoreOpts::default()
    };
    let core = AgentCore::start_replay(opts)
        .await
        .expect("pipeline starts");
    for seq in 1..=100 {
        core.ingest_bytes(&synthetic_record(seq))
            .expect("record parses");
    }
    core.send_control(ControlEvent::Status);
    // When: the control-plane kill switch bypasses data backpressure.
    core.trigger_kill_switch(KillSwitchReason("test".to_owned()))
        .await;
    // Then: both lanes drain, all joins are clean, and state is triggered.
    assert_eq!(core.queue_depth(), 0);
    assert_eq!(core.panic_count(), 0);
    assert_eq!(core.kill_switch_state(), KillSwitchState::Triggered);
    assert!(core.control_emitted_count() >= 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn stress_test_consumes_published_supported_rate_with_zero_loss() {
    // Given: the published 1000 ev/s envelope for a five-second corpus.
    let opts = AgentCoreOpts {
        data_capacity: 8_192,
        ..AgentCoreOpts::default()
    };
    let core = AgentCore::start_replay(opts)
        .await
        .expect("pipeline starts");
    // When: all 5000 ordered synthetic records are offered.
    for seq in 1..=5_000 {
        core.ingest_bytes(&synthetic_record(seq))
            .expect("record parses");
    }
    core.shutdown().await;
    // Then: the bounded budget absorbs the corpus without loss or panic.
    assert_eq!(core.drop_count(), 0);
    assert_eq!(core.seq_gap_count(), 0);
    assert_eq!(core.panic_count(), 0);
    assert_eq!(core.emitted_count(), 5_000);
}

#[tokio::test(flavor = "multi_thread")]
async fn stress_test_above_published_rate_sheds_with_monotonic_drop_counter() {
    // Given: a blocked downstream and a 5000 ev/s five-second corpus.
    let opts = AgentCoreOpts {
        data_capacity: 128,
        emit_delay: Duration::from_millis(1),
        ..AgentCoreOpts::default()
    };
    let core = AgentCore::start_replay(opts)
        .await
        .expect("pipeline starts");
    // When: producer pressure exceeds the bounded lane twice.
    for seq in 1..=5_000 {
        core.ingest_bytes(&synthetic_record(seq))
            .expect("record parses");
    }
    let first = core.drop_count();
    for seq in 5_001..=25_000 {
        core.ingest_bytes(&synthetic_record(seq))
            .expect("record parses");
    }
    let second = core.drop_count();
    core.shutdown().await;
    // Then: shedding is visible and its counter never moves backward.
    assert!(first > 0);
    assert!(second >= first);
    assert_eq!(core.panic_count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_is_idempotent() {
    // Given: a running pipeline.
    let core = AgentCore::start_replay(AgentCoreOpts::default())
        .await
        .expect("pipeline starts");
    // When: shutdown is requested twice.
    core.shutdown().await;
    core.shutdown().await;
    // Then: no task panic is observed.
    assert_eq!(core.panic_count(), 0);
    assert_eq!(core.queue_depth(), 0);
}
