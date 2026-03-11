#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Meta-tests that verify the SCP test harness itself works correctly.
//!
//! These tests exercise the clock, relay, behavior modes, topology, builder,
//! assertion primitives, and preset scenarios to ensure the harness
//! infrastructure is sound before building higher-level integration tests on
//! top of it.

use std::sync::{Arc, Mutex};

use scp_testing::assertions::{
    AssertionError, assert_complete_delivery, assert_correct_ordering, assert_no_suppression,
    assert_pseudonym_unlinkability, assert_suppression_detected,
};
use scp_testing::builder::{BuilderError, ScenarioBuilder};
use scp_testing::clock::{Clock, SimulatedClock};
use scp_testing::presets;
use scp_testing::relay::behavior::{ReplayConfig, SuppressionConfig};
use scp_testing::relay::{BehaviorMode, InMemoryRelay};
use scp_testing::simulator::NetworkTopology;

// ===========================================================================
// SimulatedClock tests
// ===========================================================================

#[tokio::test]
async fn clock_advance_fires_timers_in_order() {
    let clock = SimulatedClock::new(0);
    let order = Arc::new(Mutex::new(Vec::<u64>::new()));

    // Register 3 timers at different times (out of chronological order).
    for &t in &[3000u64, 1000, 2000] {
        let o = Arc::clone(&order);
        clock.register_timer(
            t,
            Box::new(move || {
                o.lock().unwrap().push(t);
            }),
        );
    }

    // Advance past all three.
    clock.advance_millis(4000);

    let recorded = order.lock().unwrap().clone();
    assert_eq!(recorded, vec![1000, 2000, 3000]);
}

#[tokio::test]
async fn clock_advance_to_fires_during_advance() {
    let clock = SimulatedClock::new(0);
    let fired = Arc::new(Mutex::new(false));

    let f = Arc::clone(&fired);
    clock.register_timer(
        500,
        Box::new(move || {
            *f.lock().unwrap() = true;
        }),
    );

    clock.advance_to(1000);
    assert!(*fired.lock().unwrap());
}

#[tokio::test]
async fn clock_cancel_prevents_fire() {
    let clock = SimulatedClock::new(0);
    let fired = Arc::new(Mutex::new(false));

    let f = Arc::clone(&fired);
    let handle = clock.register_timer(
        500,
        Box::new(move || {
            *f.lock().unwrap() = true;
        }),
    );

    assert!(clock.cancel_timer(handle));
    clock.advance_millis(1000);
    assert!(!*fired.lock().unwrap());
}

#[tokio::test]
async fn clock_pending_timers_count() {
    let clock = SimulatedClock::new(0);

    let h1 = clock.register_timer(100, Box::new(|| {}));
    clock.register_timer(200, Box::new(|| {}));
    clock.register_timer(300, Box::new(|| {}));

    assert_eq!(clock.pending_timers(), 3);

    clock.cancel_timer(h1);
    assert_eq!(clock.pending_timers(), 2);
}

// ===========================================================================
// InMemoryRelay tests
// ===========================================================================

#[tokio::test]
async fn relay_store_deliver_roundtrip() {
    let mut relay = InMemoryRelay::new();
    let routing_id = [1u8; 32];

    // Subscribe first so delivery works.
    let (_sub_id, mut rx) = relay.subscribe(routing_id);

    // Store a blob.
    let data = b"hello world".to_vec();
    let blob_id = relay.store(routing_id, data.clone(), None, 100);

    // Verify delivery.
    let msg = rx.try_recv().unwrap();
    assert_eq!(msg.data, data);
    assert_eq!(msg.blob_id, blob_id);
    assert_eq!(msg.routing_id, routing_id);
}

#[tokio::test]
async fn relay_ttl_expiry() {
    let mut relay = InMemoryRelay::new();
    let routing_id = [2u8; 32];

    // Store with TTL of 60 seconds at timestamp 100.
    relay.store(routing_id, b"ephemeral".to_vec(), Some(60), 100);
    assert_eq!(relay.blob_count(), 1);

    // Expire at now=161 (100 + 60 + 1 => expired).
    let expired = relay.expire_blobs(161);
    assert_eq!(expired, 1);
    assert_eq!(relay.blob_count(), 0);
}

#[tokio::test]
async fn relay_subscribe_backfill() {
    let mut relay = InMemoryRelay::new();
    let routing_id = [3u8; 32];

    // Store 2 blobs before subscribing.
    relay.store(routing_id, b"pre1".to_vec(), None, 100);
    relay.store(routing_id, b"pre2".to_vec(), None, 101);

    // Subscribe now.
    let (_sub_id, mut rx) = relay.subscribe(routing_id);

    // Store 1 more after subscribing.
    relay.store(routing_id, b"post1".to_vec(), None, 102);

    // Only the post-subscribe message should arrive (no backfill).
    let msg = rx.try_recv().unwrap();
    assert_eq!(msg.data, b"post1".to_vec());

    // Nothing else in the channel.
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn relay_unsubscribe_stops_delivery() {
    let mut relay = InMemoryRelay::new();
    let routing_id = [4u8; 32];

    let (sub_id, mut rx) = relay.subscribe(routing_id);

    // Unsubscribe.
    assert!(relay.unsubscribe(&routing_id, sub_id));

    // Store after unsubscribe.
    relay.store(routing_id, b"missed".to_vec(), None, 100);

    // Nothing should be delivered.
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn relay_query_returns_stored() {
    let mut relay = InMemoryRelay::new();
    let routing_id = [5u8; 32];

    relay.store(routing_id, b"a".to_vec(), None, 100);
    relay.store(routing_id, b"b".to_vec(), None, 101);
    relay.store(routing_id, b"c".to_vec(), None, 102);

    let results = relay.query(&routing_id);
    assert_eq!(results.len(), 3);
}

#[tokio::test]
async fn relay_delete_removes() {
    let mut relay = InMemoryRelay::new();
    let routing_id = [6u8; 32];

    let blob_id = relay.store(routing_id, b"deleteme".to_vec(), None, 100);
    assert_eq!(relay.blob_count(), 1);

    assert!(relay.delete(&blob_id));
    assert_eq!(relay.blob_count(), 0);
    assert!(relay.query(&routing_id).is_empty());
}

// ===========================================================================
// BehaviorMode tests
// ===========================================================================

#[tokio::test]
async fn behavior_suppressing_drops() {
    // Suppressing(drop_nth=2) drops messages 2, 4.
    let mut relay =
        InMemoryRelay::with_behavior(BehaviorMode::Suppressing(SuppressionConfig { drop_nth: 2 }));
    let routing_id = [10u8; 32];

    let (_sub_id, mut rx) = relay.subscribe(routing_id);

    // Store 4 messages. Messages 2 and 4 are dropped.
    for i in 0..4u8 {
        relay.store(routing_id, vec![i], None, u64::from(i));
    }

    // Collect delivered messages.
    let mut delivered = Vec::new();
    while let Ok(msg) = rx.try_recv() {
        delivered.push(msg.data[0]);
    }

    // Messages 1 and 3 delivered (0-indexed data, 1-indexed message counter).
    // Message counter: 1, 2, 3, 4. drop_nth=2 drops counters 2 and 4.
    // So data[0] (counter 1) and data[2] (counter 3) are delivered.
    assert_eq!(delivered.len(), 2);
    assert_eq!(delivered, vec![0, 2]);
}

#[tokio::test]
#[allow(clippy::significant_drop_tightening)]
async fn behavior_equivocating_diverges() {
    use scp_testing::relay::behavior::EquivocationConfig;

    let mut relay = InMemoryRelay::with_behavior(BehaviorMode::Equivocating(EquivocationConfig {
        diverge_after: 2,
    }));
    let routing_id = [11u8; 32];

    // Two subscribers.
    let (_sub1, mut rx1) = relay.subscribe(routing_id);
    let (_sub2, mut rx2) = relay.subscribe(routing_id);

    // Store 4 messages. First 2 are faithful, after that divergence begins.
    for i in 0..4u8 {
        relay.store(routing_id, vec![i + 1], None, u64::from(i));
    }

    // Collect all messages from both subscribers.
    let mut msgs1 = Vec::new();
    while let Ok(msg) = rx1.try_recv() {
        msgs1.push(msg.data.clone());
    }
    let mut msgs2 = Vec::new();
    while let Ok(msg) = rx2.try_recv() {
        msgs2.push(msg.data.clone());
    }

    // Both should have received 4 messages.
    assert_eq!(msgs1.len(), 4);
    assert_eq!(msgs2.len(), 4);

    // First 2 should be identical (before diverge_after threshold).
    assert_eq!(msgs1[0], msgs2[0]);
    assert_eq!(msgs1[1], msgs2[1]);

    // After diverge_after=2, subscriber at index 1 (rx2) gets flipped data.
    // Messages 3 and 4 (msg_num > 2) should differ.
    assert_ne!(msgs1[2], msgs2[2]);
    assert_ne!(msgs1[3], msgs2[3]);
}

#[tokio::test]
async fn behavior_replaying_duplicates() {
    let mut relay =
        InMemoryRelay::with_behavior(BehaviorMode::Replaying(ReplayConfig { replay_count: 1 }));
    let routing_id = [12u8; 32];

    let (_sub_id, mut rx) = relay.subscribe(routing_id);

    relay.store(routing_id, b"once".to_vec(), None, 100);

    // Should receive the message 2 times (1 original + 1 replay).
    let mut count = 0;
    while rx.try_recv().is_ok() {
        count += 1;
    }
    assert_eq!(count, 2);
}

#[tokio::test]
async fn behavior_deletion_noncompliant() {
    let mut relay = InMemoryRelay::with_behavior(BehaviorMode::DeletionNonCompliant);
    let routing_id = [13u8; 32];

    let blob_id = relay.store(routing_id, b"persistent".to_vec(), None, 100);

    // Delete returns false (non-compliant).
    assert!(!relay.delete(&blob_id));

    // Blob is still there.
    assert_eq!(relay.query(&routing_id).len(), 1);
}

#[tokio::test]
async fn behavior_composite() {
    // Composite applies the first delivery-affecting mode it finds.
    // Non-delivery modes (DeletionNonCompliant, Delayed) still take
    // effect but don't change delivery count.

    // Suppressing + DeletionNonCompliant: Suppressing is first
    // delivery-affecting mode; DeletionNonCompliant affects deletion.
    let mut relay = InMemoryRelay::with_behavior(BehaviorMode::Composite(vec![
        BehaviorMode::Suppressing(SuppressionConfig { drop_nth: 3 }),
        BehaviorMode::DeletionNonCompliant,
    ]));
    let routing_id = [14u8; 32];

    let (_sub_id, mut rx) = relay.subscribe(routing_id);

    // Store 3 messages. Suppressing(3) drops every 3rd.
    for i in 0..3u8 {
        relay.store(routing_id, vec![i], None, u64::from(i));
    }

    let mut count = 0;
    while rx.try_recv().is_ok() {
        count += 1;
    }
    // msg1 (ok), msg2 (ok), msg3 (dropped by suppression) = 2
    assert_eq!(count, 2);

    // DeletionNonCompliant still applies: delete should be a no-op.
    relay.store(routing_id, vec![99], None, 99);
    let stored = relay.query(&routing_id);
    let blob_id = stored.last().unwrap().blob_id;
    relay.delete(&blob_id);
    // Blob should still be there (DeletionNonCompliant).
    let after_delete = relay.query(&routing_id);
    assert!(after_delete.iter().any(|b| b.blob_id == blob_id));
}

// ===========================================================================
// NetworkTopology tests
// ===========================================================================

#[tokio::test]
async fn topology_connect_reach() {
    let mut topo = NetworkTopology::new();
    topo.connect("a", "b");
    assert!(topo.can_reach("a", "b"));
    assert!(topo.can_reach("b", "a"));
}

#[tokio::test]
async fn topology_partition_blocks() {
    let mut topo = NetworkTopology::new();
    topo.connect("a", "b");
    topo.partition("a", "b");
    assert!(!topo.can_reach("a", "b"));
    assert!(!topo.can_reach("b", "a"));
}

#[tokio::test]
async fn topology_isolate_blocks_all() {
    let mut topo = NetworkTopology::new();
    topo.connect("a", "b");
    topo.connect("a", "c");
    topo.isolate("a");
    assert!(!topo.can_reach("b", "a"));
    assert!(!topo.can_reach("c", "a"));
    assert!(!topo.can_reach("a", "b"));
    assert!(!topo.can_reach("a", "c"));
}

#[tokio::test]
async fn topology_heal_restores() {
    let mut topo = NetworkTopology::new();
    topo.connect("a", "b");
    topo.partition("a", "b");
    assert!(!topo.can_reach("a", "b"));
    topo.heal("a", "b");
    assert!(topo.can_reach("a", "b"));
    assert!(topo.can_reach("b", "a"));
}

// ===========================================================================
// ScenarioBuilder tests
// ===========================================================================

#[tokio::test]
async fn builder_creates_relay_and_identity() {
    let sim = ScenarioBuilder::new()
        .relay("r1")
        .identity("alice")
        .build()
        .unwrap();

    assert!(sim.relay("r1").is_some());
    assert!(sim.identity("alice").is_some());
}

#[tokio::test]
async fn builder_full_mesh() {
    let sim = ScenarioBuilder::new()
        .relay("r1")
        .relay("r2")
        .relay("r3")
        .identity("alice")
        .full_mesh()
        .build()
        .unwrap();

    assert!(sim.topology().can_reach("r1", "r2"));
    assert!(sim.topology().can_reach("r2", "r3"));
    assert!(sim.topology().can_reach("r1", "r3"));
    assert!(sim.topology().can_reach("r1", "alice"));
    assert!(sim.topology().can_reach("r2", "alice"));
    assert!(sim.topology().can_reach("r3", "alice"));
}

#[tokio::test]
async fn builder_duplicate_label_errors() {
    let result = ScenarioBuilder::new()
        .relay("r1")
        .relay("r1")
        .identity("alice")
        .build();

    assert!(matches!(result, Err(BuilderError::DuplicateLabel(_))));
}

// ===========================================================================
// Assertion tests
// ===========================================================================

#[tokio::test]
async fn assertion_delivery_passes() {
    assert!(assert_complete_delivery(5, 5).is_ok());
}

#[tokio::test]
async fn assertion_delivery_fails() {
    let err = assert_complete_delivery(5, 3).unwrap_err();
    assert!(matches!(
        err,
        AssertionError::IncompleteDelivery {
            expected: 5,
            actual: 3
        }
    ));
}

#[tokio::test]
async fn assertion_ordering_passes() {
    assert!(assert_correct_ordering(&[1, 2, 3, 4]).is_ok());
}

#[tokio::test]
async fn assertion_ordering_fails() {
    let err = assert_correct_ordering(&[1, 3, 2, 4]).unwrap_err();
    assert!(matches!(err, AssertionError::OrderingViolation { .. }));
}

#[tokio::test]
async fn assertion_suppression_detected() {
    // Gap at position 3: [1, 2, 4, 5] is missing 3.
    assert!(assert_suppression_detected(&[1, 2, 4, 5]).is_ok());
}

#[tokio::test]
async fn assertion_no_suppression() {
    assert!(assert_no_suppression(&[1, 2, 3, 4]).is_ok());
}

#[tokio::test]
async fn assertion_pseudonym_unlinkability() {
    // 3 different routing IDs should pass.
    let rid_one = [1u8; 32];
    let rid_two = [2u8; 32];
    let rid_three = [3u8; 32];
    assert!(assert_pseudonym_unlinkability(&[&rid_one, &rid_two, &rid_three]).is_ok());

    // 2 identical routing IDs should fail.
    let rid_dup1 = [4u8; 32];
    let rid_dup2 = [4u8; 32];
    let err = assert_pseudonym_unlinkability(&[&rid_dup1, &rid_dup2]).unwrap_err();
    assert!(matches!(err, AssertionError::PseudonymLinkable { .. }));
}

// ===========================================================================
// Preset tests
// ===========================================================================

#[tokio::test]
async fn preset_two_party_creates_relay() {
    let scenario = presets::two_party_basic();
    assert_eq!(scenario.relays.len(), 1);
    // Relay should be Normal behavior.
    assert!(scenario.relay().lock().unwrap().behavior().is_normal());
}

#[tokio::test]
#[allow(clippy::significant_drop_tightening)]
async fn preset_suppression_has_behavior() {
    let scenario = presets::suppression_scenario();
    assert_eq!(scenario.relays.len(), 1);
    let relay = scenario.relay().lock().unwrap();
    assert!(matches!(relay.behavior(), BehaviorMode::Suppressing(_)));
}
