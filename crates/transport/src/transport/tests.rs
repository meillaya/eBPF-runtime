// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Tests for the transport orchestrator.

use super::*;
use crate::ack::{AckState, KafkaAcceptance, MockOutboxDeleter};
use crate::channel::{AckMessage, ControlMessage};
use crate::config::TransportConfig;
use crate::error::TransportError;
use crate::sequence::ReconciliationAction;

const TD: &str = "kernel-v1.test";
const BOOT: &str = "00000000000000000000000000000000";
const GEN: &str = "gen-1";
const PEER: &str = "spiffe://kernel-v1.test/agent/prod/node-1";

fn transport() -> Transport {
    Transport::new(TransportConfig::default(), TD, BOOT, GEN)
}

#[test]
fn initial_state_disconnected() {
    let t = transport();
    assert_eq!(t.state(), TransportState::Disconnected);
}

#[test]
fn authorize_valid_peer() {
    let mut t = transport();
    t.authorize_peer(PEER).unwrap();
    assert_eq!(t.state(), TransportState::Connected);
    assert!(t.peer_binding().is_some());
    assert_eq!(t.peer_binding().unwrap().cluster, "prod");
}

#[test]
fn authorize_invalid_peer_rejected() {
    let mut t = transport();
    let err = t
        .authorize_peer("spiffe://evil.example/agent/prod/node-1")
        .unwrap_err();
    assert!(matches!(err, TransportError::PeerUnauthorized { .. }));
    assert_eq!(t.state(), TransportState::Disconnected);
}

#[test]
fn send_control_requires_connected() {
    let t = transport();
    let err = t
        .send_control(ControlMessage::HealthPing { timestamp_ms: 1 }, 1000)
        .unwrap_err();
    assert!(matches!(
        err,
        TransportError::ChannelClosed { channel: "control" }
    ));
}

#[test]
fn send_control_when_connected() {
    let mut t = transport();
    t.authorize_peer(PEER).unwrap();
    assert!(t
        .send_control(ControlMessage::HealthPing { timestamp_ms: 1 }, 1000)
        .is_ok());
}

#[test]
fn send_event_batch_assigns_seq() {
    let mut t = transport();
    t.authorize_peer(PEER).unwrap();
    let seq0 = t.send_event_batch("b-0", 10, 1024, 1000).unwrap();
    let seq1 = t.send_event_batch("b-1", 5, 512, 1000).unwrap();
    assert_eq!(seq0, 0);
    assert_eq!(seq1, 1);
    assert_eq!(t.sequence().next_seq(), 2);
}

#[test]
fn send_event_batch_registers_in_ack_tracker() {
    let mut t = transport();
    t.authorize_peer(PEER).unwrap();
    t.send_event_batch("b-0", 10, 1024, 1000).unwrap();
    assert_eq!(
        t.ack_tracker().state("b-0"),
        Some(AckState::AwaitingKafkaAcceptance)
    );
}

#[test]
fn kafka_acceptance_completes_ack() {
    let mut t = transport();
    t.authorize_peer(PEER).unwrap();
    t.send_event_batch("b-0", 10, 1024, 1000).unwrap();

    t.process_kafka_acceptance(KafkaAcceptance {
        batch_id: "b-0".into(),
        topic: "events".into(),
        partition: 0,
        offset: 100,
    })
    .unwrap();

    assert_eq!(
        t.ack_tracker().state("b-0"),
        Some(AckState::AckedAndDeleted)
    );
}

#[test]
fn receipt_only_ack_rejected() {
    let mut t = transport();
    t.authorize_peer(PEER).unwrap();
    t.send_event_batch("b-0", 10, 1024, 1000).unwrap();

    let err = t
        .process_inbound_ack(AckMessage {
            batch_id: "b-0".into(),
            seq: 0,
            durable: false,
        })
        .unwrap_err();
    assert!(matches!(err, TransportError::ReceiptOnlyAck { .. }));
}

#[test]
fn durable_ack_updates_sequence() {
    let mut t = transport();
    t.authorize_peer(PEER).unwrap();
    t.send_event_batch("b-0", 10, 1024, 1000).unwrap();
    t.send_event_batch("b-1", 5, 512, 1000).unwrap();

    t.process_inbound_ack(AckMessage {
        batch_id: "b-1".into(),
        seq: 1,
        durable: true,
    })
    .unwrap();

    assert_eq!(t.sequence().last_acked_seq(), Some(1));
}

#[test]
fn reconcile_on_connect_gap() {
    let mut t = transport();
    // Simulate sending 10 batches.
    for i in 0..10 {
        t.sequence_mut().assign_seq();
        let _ = i;
    }
    // Server only ACKed through 3.
    let action = t.reconcile_on_connect(Some(3), BOOT, GEN);
    assert_eq!(
        action,
        ReconciliationAction::ReplayFrom { replay_from_seq: 4 }
    );
}

#[test]
fn reconcile_on_connect_generation_change() {
    let mut t = transport();
    t.sequence_mut().assign_seq();
    let action = t.reconcile_on_connect(Some(0), &"ff".repeat(16), GEN);
    assert!(matches!(
        action,
        ReconciliationAction::GenerationReset { .. }
    ));
}

#[test]
fn disconnect_and_reconnect() {
    let mut t = transport();
    t.authorize_peer(PEER).unwrap();
    assert_eq!(t.state(), TransportState::Connected);

    let delay = t.record_disconnect().unwrap();
    assert_eq!(t.state(), TransportState::Reconnecting);
    assert!(delay.as_millis() > 0);

    t.record_reconnect_success();
    assert_eq!(t.state(), TransportState::Connected);
}

#[test]
fn circuit_breaker_opens_after_max_failures() {
    let config = TransportConfig {
        max_reconnect_attempts: 3,
        ..Default::default()
    };
    let mut t = Transport::new(config, TD, BOOT, GEN);
    t.authorize_peer(PEER).unwrap();

    for _ in 0..3 {
        t.record_disconnect().unwrap();
        t.record_reconnect_success();
    }
    // The 4th failure should trip the circuit breaker.
    // But record_success resets the backoff, so we need
    // consecutive failures.
    let mut t2 = Transport::new(
        TransportConfig {
            max_reconnect_attempts: 3,
            ..Default::default()
        },
        TD,
        BOOT,
        GEN,
    );
    t2.authorize_peer(PEER).unwrap();
    t2.record_disconnect().unwrap();
    // Don't call record_reconnect_success — consecutive failures.
    t2.state = TransportState::Reconnecting;
    t2.record_disconnect().unwrap();
    t2.state = TransportState::Reconnecting;
    t2.record_disconnect().unwrap();
    // 4th failure: circuit breaker.
    t2.state = TransportState::Reconnecting;
    let err = t2.record_disconnect().unwrap_err();
    assert!(matches!(err, TransportError::ReconnectExhausted { .. }));
    assert_eq!(t2.state(), TransportState::CircuitOpen);
}

#[test]
fn shutdown_transitions_state() {
    let mut t = transport();
    t.authorize_peer(PEER).unwrap();
    t.shutdown();
    assert_eq!(t.state(), TransportState::Shutdown);
}

#[test]
fn outbox_deletion_after_matching_ack() {
    let deleter = MockOutboxDeleter::new(vec!["b-0".into(), "b-1".into()]);
    let mut t = Transport::with_outbox_deleter(
        TransportConfig::default(),
        TD,
        BOOT,
        GEN,
        Box::new(deleter),
    );
    t.authorize_peer(PEER).unwrap();

    t.send_event_batch("b-0", 10, 1024, 1000).unwrap();
    t.send_event_batch("b-1", 5, 512, 1000).unwrap();

    // ACK b-0 only.
    t.process_kafka_acceptance(KafkaAcceptance {
        batch_id: "b-0".into(),
        topic: "events".into(),
        partition: 0,
        offset: 100,
    })
    .unwrap();

    assert_eq!(
        t.ack_tracker().state("b-0"),
        Some(AckState::AckedAndDeleted)
    );
    assert_eq!(
        t.ack_tracker().state("b-1"),
        Some(AckState::AwaitingKafkaAcceptance)
    );
}

#[test]
fn event_backpressure_does_not_block_control() {
    let config = TransportConfig {
        event_queue_capacity: 2,
        control_queue_capacity: 4,
        ..Default::default()
    };
    let mut t = Transport::new(config, TD, BOOT, GEN);
    t.authorize_peer(PEER).unwrap();

    // Fill the event queue.
    t.send_event_batch("b-0", 1, 100, 1000).unwrap();
    t.send_event_batch("b-1", 1, 100, 1000).unwrap();
    // Event queue is now full.
    let err = t.send_event_batch("b-2", 1, 100, 1000).unwrap_err();
    assert!(matches!(err, TransportError::QueueFull { .. }));

    // Control channel is still responsive.
    assert!(t
        .send_control(
            ControlMessage::KillSwitch {
                deny_disabled: true,
                toggle_seq: 1,
            },
            1000,
        )
        .is_ok());
}
