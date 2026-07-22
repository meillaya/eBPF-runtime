// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn test_event(event_id: &str, cluster: &str) -> LiveEvent {
    LiveEvent {
        seq: 0, // assigned by hub
        event_id: event_id.to_string(),
        event_kind: "EVENT_KIND_FILE_OPEN".to_string(),
        node_name: "node-1".to_string(),
        cluster: cluster.to_string(),
        ts_monotonic_ns: 1_000_000,
        payload: r#"{"path":"/etc/hostname"}"#.to_string(),
    }
}

#[test]
fn subscribe_and_publish() {
    let hub = LiveHub::new(16, 4);
    let sub_id = hub.subscribe("prod");

    let seq = hub.publish("prod", test_event("evt-001", "prod"));
    assert_eq!(seq, 1);

    let events = hub.drain(sub_id, 10).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_id, "evt-001");
    assert_eq!(events[0].seq, 1);
}

#[test]
fn cluster_isolation_in_fanout() {
    let hub = LiveHub::new(16, 4);
    let sub_prod = hub.subscribe("prod");
    let sub_staging = hub.subscribe("staging");

    hub.publish("prod", test_event("evt-001", "prod"));
    hub.publish("staging", test_event("evt-002", "staging"));

    let prod_events = hub.drain(sub_prod, 10).unwrap();
    assert_eq!(prod_events.len(), 1);
    assert_eq!(prod_events[0].event_id, "evt-001");

    let staging_events = hub.drain(sub_staging, 10).unwrap();
    assert_eq!(staging_events.len(), 1);
    assert_eq!(staging_events[0].event_id, "evt-002");
}

#[test]
fn slow_client_shed() {
    let hub = LiveHub::new(2, 2); // buffer cap 2, threshold 2
    let sub_id = hub.subscribe("prod");

    // Fill the buffer (cap = 2).
    hub.publish("prod", test_event("evt-001", "prod"));
    hub.publish("prod", test_event("evt-002", "prod"));

    // Buffer is now full. Next publishes increment missed.
    hub.publish("prod", test_event("evt-003", "prod")); // missed = 1
    assert!(!hub.is_shed(sub_id));

    hub.publish("prod", test_event("evt-004", "prod")); // missed = 2 >= threshold
    assert!(hub.is_shed(sub_id));

    // Draining a shed subscriber returns an error.
    let result = hub.drain(sub_id, 10);
    assert!(matches!(
        result.unwrap_err(),
        ControlPlaneError::SlowClientShed { .. }
    ));
}

#[test]
fn drain_resets_missed_counter() {
    let hub = LiveHub::new(2, 3);
    let sub_id = hub.subscribe("prod");

    // Fill buffer.
    hub.publish("prod", test_event("evt-001", "prod"));
    hub.publish("prod", test_event("evt-002", "prod"));

    // One missed publish.
    hub.publish("prod", test_event("evt-003", "prod"));

    // Drain to reset.
    let events = hub.drain(sub_id, 10).unwrap();
    assert_eq!(events.len(), 2);

    // Now the subscriber can receive again.
    hub.publish("prod", test_event("evt-004", "prod"));
    let events = hub.drain(sub_id, 10).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_id, "evt-004");
}

#[test]
fn cursor_reconnect() {
    let hub = LiveHub::new(16, 4);
    let _sub_id = hub.subscribe("prod");

    // Publish 5 events.
    for i in 1..=5 {
        hub.publish("prod", test_event(&format!("evt-{i:03}"), "prod"));
    }

    // Reconnect from cursor 3 (get events 4 and 5).
    let events = hub.reconnect("prod", 3).unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].seq, 4);
    assert_eq!(events[1].seq, 5);
}

#[test]
fn cursor_reconnect_from_zero() {
    let hub = LiveHub::new(16, 4);
    let _sub_id = hub.subscribe("prod");

    hub.publish("prod", test_event("evt-001", "prod"));
    hub.publish("prod", test_event("evt-002", "prod"));

    // Cursor 0 means "give me everything".
    let events = hub.reconnect("prod", 0).unwrap();
    assert_eq!(events.len(), 2);
}

#[test]
fn cursor_expired_when_too_old() {
    let hub = LiveHub::new(4, 4); // small buffer
    let _sub_id = hub.subscribe("prod");

    // Publish more events than the stream cap (4 * 4 = 16).
    for i in 1..=20 {
        hub.publish("prod", test_event(&format!("evt-{i:03}"), "prod"));
    }

    // The oldest retained event should be > 1.
    let oldest = hub.oldest_seq("prod").unwrap();
    assert!(oldest > 1);

    // Reconnecting with a cursor older than oldest fails.
    let result = hub.reconnect("prod", 1);
    assert!(matches!(
        result.unwrap_err(),
        ControlPlaneError::LiveCursorExpired { .. }
    ));
}

#[test]
fn reconnect_unknown_cluster() {
    let hub = LiveHub::new(16, 4);
    let result = hub.reconnect("nonexistent", 0);
    assert!(matches!(
        result.unwrap_err(),
        ControlPlaneError::NoLiveStream { .. }
    ));
}

#[test]
fn unsubscribe_removes_subscriber() {
    let hub = LiveHub::new(16, 4);
    let sub_id = hub.subscribe("prod");
    assert_eq!(hub.active_subscriber_count("prod"), 1);

    hub.unsubscribe(sub_id);
    assert_eq!(hub.active_subscriber_count("prod"), 0);
}

#[test]
fn multiple_subscribers_receive_same_events() {
    let hub = LiveHub::new(16, 4);
    let sub1 = hub.subscribe("prod");
    let sub2 = hub.subscribe("prod");

    hub.publish("prod", test_event("evt-001", "prod"));

    let events1 = hub.drain(sub1, 10).unwrap();
    let events2 = hub.drain(sub2, 10).unwrap();
    assert_eq!(events1.len(), 1);
    assert_eq!(events2.len(), 1);
    assert_eq!(events1[0].event_id, events2[0].event_id);
}

#[test]
fn sequence_numbers_are_monotonic() {
    let hub = LiveHub::new(16, 4);
    let sub_id = hub.subscribe("prod");

    for i in 1..=5 {
        let seq = hub.publish("prod", test_event(&format!("evt-{i}"), "prod"));
        assert_eq!(seq, i as u64);
    }

    let events = hub.drain(sub_id, 10).unwrap();
    for (i, event) in events.iter().enumerate() {
        assert_eq!(event.seq, (i + 1) as u64);
    }
}
