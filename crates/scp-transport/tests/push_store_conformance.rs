//! Shared behaviour suite for the relay push registration store (PUSH-006).
//!
//! Every behaviour runs against both arms of `PushRegistrationStore`: the
//! shipped SQLite arm and the `testing`-only in-memory arm. A last test proves
//! the SQLite arm keeps registrations across a reopen.
//!
//! The `[[test]]` entry in `Cargo.toml` requires `push-store` and `testing`, so
//! a build without them skips this target instead of compiling it empty.

use std::marker::PhantomData;

use scp_protocol::discovery::push::PushPlatform;
use scp_relay_client::code;
use scp_transport::relay::push_store::{
    CountFrom, INVALID_TOKEN_REMOVAL_THRESHOLD, InvalidTokenOutcome,
    MAX_REGISTRATIONS_PER_REGISTRANT, PushRegistrationKey, PushRegistrationRecord,
    PushRegistrationStore, PushStoreError, UpsertOutcome,
};
use tempfile::TempDir;

const A: [u8; 32] = [0xA1; 32];
const B: [u8; 32] = [0xB2; 32];
const C: [u8; 32] = [0xC3; 32];

type Outcome = Result<(), PushStoreError>;

/// Holds the SQLite arm's directory alive for the test's duration.
struct Arm {
    store: PushRegistrationStore,
    _dir: Option<TempDir>,
}

fn sqlite_arm() -> Result<Arm, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = PushRegistrationStore::open_sqlite(&dir.path().join("push.db"))?;
    assert!(matches!(store, PushRegistrationStore::Sqlite(_)));
    Ok(Arm {
        store,
        _dir: Some(dir),
    })
}

fn in_memory_arm() -> Arm {
    let store = PushRegistrationStore::in_memory();
    assert!(matches!(store, PushRegistrationStore::InMemory(_)));
    Arm { store, _dir: None }
}

fn record(
    registrant: &str,
    token: &[u8],
    routing_ids: &[[u8; 32]],
    timestamp: u64,
) -> PushRegistrationRecord {
    PushRegistrationRecord {
        registrant: registrant.to_owned(),
        platform: PushPlatform::Apns,
        token: token.to_vec(),
        routing_ids: routing_ids.to_vec(),
        timestamp,
    }
}

fn keys(records: &[PushRegistrationRecord]) -> Vec<PushRegistrationKey> {
    records.iter().map(PushRegistrationRecord::key).collect()
}

const APNS: PushPlatform = PushPlatform::Apns;

async fn newer_timestamp_replaces_registration_and_index(store: PushRegistrationStore) -> Outcome {
    let first = record("did:dht:alice", b"tok-1", &[A, B], 1);
    assert_eq!(store.upsert(first.clone()).await?, UpsertOutcome::Inserted);

    let second = record("did:dht:alice", b"tok-1", &[C, B], 2);
    assert_eq!(store.upsert(second).await?, UpsertOutcome::Replaced);

    let stored = record("did:dht:alice", b"tok-1", &[B, C], 2);
    assert_eq!(store.get(&first.key()).await?, Some(stored.clone()));
    assert!(store.tokens_for_routing_id(&A).await?.is_empty());
    assert_eq!(store.tokens_for_routing_id(&B).await?, vec![stored.clone()]);
    assert_eq!(store.tokens_for_routing_id(&C).await?, vec![stored]);
    Ok(())
}

async fn identical_routing_set_leaves_index_unchanged(store: PushRegistrationStore) -> Outcome {
    let first = record("did:dht:alice", b"tok-1", &[A, B], 1);
    store.upsert(first.clone()).await?;
    assert_eq!(
        store
            .record_invalid_token(APNS, b"tok-1", CountFrom::Stored)
            .await?,
        InvalidTokenOutcome::Counted { failures: 1 }
    );
    let before_a = keys(&store.tokens_for_routing_id(&A).await?);
    let before_b = keys(&store.tokens_for_routing_id(&B).await?);

    // Same token, same set (reordered and with a duplicate), newer timestamp.
    let again = record("did:dht:alice", b"tok-1", &[B, A, A], 9);
    assert_eq!(store.upsert(again).await?, UpsertOutcome::Refreshed);

    assert_eq!(keys(&store.tokens_for_routing_id(&A).await?), before_a);
    assert_eq!(keys(&store.tokens_for_routing_id(&B).await?), before_b);
    assert!(store.tokens_for_routing_id(&C).await?.is_empty());
    assert_eq!(
        store.get(&first.key()).await?,
        Some(record("did:dht:alice", b"tok-1", &[A, B], 9))
    );
    // A re-registration says nothing about token validity.
    assert_eq!(store.invalid_token_failures(APNS, b"tok-1").await?, Some(1));
    Ok(())
}

async fn equal_or_older_timestamp_is_stale(store: PushRegistrationStore) -> Outcome {
    let first = record("did:dht:alice", b"tok-1", &[A], 5);
    store.upsert(first.clone()).await?;

    assert_eq!(
        store
            .upsert(record("did:dht:alice", b"tok-1", &[B], 5))
            .await,
        Err(PushStoreError::Stale {
            last_accepted: 5,
            offered: 5
        })
    );
    assert_eq!(
        store
            .upsert(record("did:dht:alice", b"tok-1", &[B], 4))
            .await,
        Err(PushStoreError::Stale {
            last_accepted: 5,
            offered: 4
        })
    );
    assert_eq!(store.get(&first.key()).await?, Some(first));
    assert!(store.tokens_for_routing_id(&B).await?.is_empty());
    Ok(())
}

async fn new_key_past_per_registrant_cap_is_refused(store: PushRegistrationStore) -> Outcome {
    assert_eq!(MAX_REGISTRATIONS_PER_REGISTRANT, 16);
    for i in 0..MAX_REGISTRATIONS_PER_REGISTRANT {
        let token = format!("tok-{i}");
        assert_eq!(
            store
                .upsert(record("did:dht:alice", token.as_bytes(), &[A], 1))
                .await?,
            UpsertOutcome::Inserted
        );
    }
    let refused = store
        .upsert(record("did:dht:alice", b"tok-extra", &[A], 1))
        .await;
    assert_eq!(refused, Err(PushStoreError::LimitReached { cap: 16 }));
    assert_eq!(
        refused.err().map(|e| e.wire_code()),
        Some(code::PUSH_REGISTRATION_LIMIT),
        "the relay answers a refusal by the cap with 4064"
    );
    // An FCM token for the same registrant is a new key and counts too.
    let mut fcm = record("did:dht:alice", b"tok-0", &[A], 1);
    fcm.platform = PushPlatform::Fcm;
    assert_eq!(
        store.upsert(fcm).await,
        Err(PushStoreError::LimitReached { cap: 16 })
    );
    // A key the registrant already holds is not refused by the cap.
    assert_eq!(
        store
            .upsert(record("did:dht:alice", b"tok-0", &[B], 2))
            .await?,
        UpsertOutcome::Replaced
    );
    // Another registrant has its own allowance.
    assert_eq!(
        store
            .upsert(record("did:dht:bob", b"tok-extra", &[A], 1))
            .await?,
        UpsertOutcome::Inserted
    );
    // Removing one frees a slot.
    assert!(
        store
            .remove(&record("did:dht:alice", b"tok-3", &[A], 1).key())
            .await?
    );
    assert_eq!(
        store
            .upsert(record("did:dht:alice", b"tok-extra", &[A], 1))
            .await?,
        UpsertOutcome::Inserted
    );
    // On A: alice's 16 keys less tok-0 (moved to B) and tok-3 (removed), plus
    // alice's tok-extra and bob's tok-extra.
    assert_eq!(store.tokens_for_routing_id(&A).await?.len(), 16);
    Ok(())
}

async fn remove_deletes_registration_and_index(store: PushRegistrationStore) -> Outcome {
    let gone = record("did:dht:alice", b"tok-1", &[A, B], 1);
    let kept = record("did:dht:alice", b"tok-2", &[B], 1);
    store.upsert(gone.clone()).await?;
    store.upsert(kept.clone()).await?;
    store
        .record_invalid_token(APNS, b"tok-1", CountFrom::Stored)
        .await?;

    assert!(store.remove(&gone.key()).await?);
    assert_eq!(store.get(&gone.key()).await?, None);
    assert!(store.tokens_for_routing_id(&A).await?.is_empty());
    assert_eq!(store.tokens_for_routing_id(&B).await?, vec![kept]);
    assert_eq!(store.invalid_token_failures(APNS, b"tok-1").await?, None);
    assert!(!store.remove(&gone.key()).await?);

    // The removed registration's timestamp stays as the key's floor, so the
    // same registration replayed is stale.
    assert_eq!(store.accepted_timestamp(&gone.key()).await?, Some(1));
    assert_eq!(
        store.upsert(gone.clone()).await,
        Err(PushStoreError::Stale {
            last_accepted: 1,
            offered: 1
        })
    );

    // A newer registration under the removed key starts fresh, with a zero
    // failure count.
    let back = record("did:dht:alice", b"tok-1", &[A, B], 2);
    assert_eq!(store.upsert(back.clone()).await?, UpsertOutcome::Inserted);
    assert_eq!(store.invalid_token_failures(APNS, b"tok-1").await?, Some(0));
    assert_eq!(store.accepted_timestamp(&back.key()).await?, Some(2));
    Ok(())
}

async fn tokens_for_routing_id_returns_each_registration_once(
    store: PushRegistrationStore,
) -> Outcome {
    let one = record("did:dht:alice", b"tok-1", &[A, A, B], 1);
    let two = record("did:dht:bob", b"tok-2", &[A], 1);
    let mut three = record("did:dht:alice", b"tok-1", &[A], 1);
    three.platform = PushPlatform::Fcm;
    let other = record("did:dht:carol", b"tok-3", &[C], 1);
    for r in [&one, &two, &three, &other] {
        store.upsert(r.clone()).await?;
    }

    let found = store.tokens_for_routing_id(&A).await?;
    assert_eq!(
        keys(&found),
        vec![one.key(), three.key(), two.key()],
        "each registration once, ordered by (registrant, platform, token)"
    );
    assert_eq!(found[0].routing_ids, vec![A, B]);
    assert_eq!(
        keys(&store.tokens_for_routing_id(&B).await?),
        vec![one.key()]
    );
    assert!(store.tokens_for_routing_id(&[0; 32]).await?.is_empty());
    Ok(())
}

/// The wake lookup returns each distinct (platform, token) on the routing ID
/// once, whoever registered it, and stops at the limit. Over the limit it
/// samples afresh on each call, so no token that sorts first holds the slot
/// forever.
async fn wake_tokens_returns_each_token_once_up_to_the_limit(
    store: PushRegistrationStore,
) -> Outcome {
    let one = record("did:dht:alice", b"tok-2", &[A, B], 1);
    let shared = record("did:dht:bob", b"tok-2", &[A], 1);
    let two = record("did:dht:bob", b"tok-1", &[A], 1);
    let mut fcm = record("did:dht:alice", b"tok-0", &[A], 1);
    fcm.platform = PushPlatform::Fcm;
    let other = record("did:dht:carol", b"tok-3", &[C], 1);
    for r in [&one, &shared, &two, &fcm, &other] {
        store.upsert(r.clone()).await?;
    }
    let found = |tokens: Vec<scp_transport::relay::push_store::WakeToken>| {
        let mut out = tokens
            .into_iter()
            .map(|t| (t.platform.tag_byte(), t.token.to_vec()))
            .collect::<Vec<_>>();
        out.sort();
        out
    };
    let all = vec![
        (APNS.tag_byte(), b"tok-1".to_vec()),
        (APNS.tag_byte(), b"tok-2".to_vec()),
        (PushPlatform::Fcm.tag_byte(), b"tok-0".to_vec()),
    ];
    let mut all_sorted = all.clone();
    all_sorted.sort();
    assert_eq!(found(store.wake_tokens(&A, 10).await?), all_sorted);
    let two = found(store.wake_tokens(&A, 2).await?);
    assert_eq!(two.len(), 2, "{two:?}");
    assert!(
        two[0] != two[1] && two.iter().all(|t| all.contains(t)),
        "{two:?}"
    );
    assert_eq!(
        found(store.wake_tokens(&B, 10).await?),
        vec![(APNS.tag_byte(), b"tok-2".to_vec())]
    );
    assert!(store.wake_tokens(&[0; 32], 10).await?.is_empty());
    assert!(store.wake_tokens(&A, 0).await?.is_empty());
    // With room for one, 64 calls reach every token: a fixed order would
    // return the same one each time (chance of a false failure: 3 * (2/3)^64).
    let mut seen = Vec::new();
    for _ in 0..64 {
        seen.extend(found(store.wake_tokens(&A, 1).await?));
    }
    seen.sort();
    seen.dedup();
    assert_eq!(seen, all_sorted);
    Ok(())
}

/// `CountFrom::Zero` resets the stored count and counts this failure in one
/// write, so a delivery whose reset was lost still breaks the run.
async fn count_from_zero_restarts_the_run(store: PushRegistrationStore) -> Outcome {
    let r = record("did:dht:alice", b"tok-1", &[A], 1);
    store.upsert(r.clone()).await?;
    for _ in 1..INVALID_TOKEN_REMOVAL_THRESHOLD {
        store
            .record_invalid_token(APNS, b"tok-1", CountFrom::Stored)
            .await?;
    }
    assert_eq!(
        store
            .record_invalid_token(APNS, b"tok-1", CountFrom::Zero)
            .await?,
        InvalidTokenOutcome::Counted { failures: 1 }
    );
    assert!(store.get(&r.key()).await?.is_some());
    assert_eq!(
        store
            .record_invalid_token(APNS, b"tok-none", CountFrom::Zero)
            .await?,
        InvalidTokenOutcome::NotRegistered
    );
    Ok(())
}

/// `clear_all_invalid_tokens` resets every token's count and keeps every
/// registration.
async fn clear_all_resets_every_count(store: PushRegistrationStore) -> Outcome {
    let one = record("did:dht:alice", b"tok-1", &[A], 1);
    let two = record("did:dht:bob", b"tok-2", &[B], 1);
    store.upsert(one.clone()).await?;
    store.upsert(two.clone()).await?;
    for token in [b"tok-1".as_slice(), b"tok-2".as_slice()] {
        for _ in 1..INVALID_TOKEN_REMOVAL_THRESHOLD {
            store
                .record_invalid_token(APNS, token, CountFrom::Stored)
                .await?;
        }
    }
    store.clear_all_invalid_tokens().await?;
    assert_eq!(store.invalid_token_failures(APNS, b"tok-1").await?, Some(0));
    assert_eq!(store.invalid_token_failures(APNS, b"tok-2").await?, Some(0));
    assert!(store.get(&one.key()).await?.is_some());
    assert!(store.get(&two.key()).await?.is_some());
    assert_eq!(
        store
            .record_invalid_token(APNS, b"tok-1", CountFrom::Stored)
            .await?,
        InvalidTokenOutcome::Counted { failures: 1 }
    );
    Ok(())
}

async fn invalid_token_counter_counts_consecutive_failures(
    store: PushRegistrationStore,
) -> Outcome {
    let r = record("did:dht:alice", b"tok-1", &[A], 1);
    store.upsert(r.clone()).await?;

    assert_eq!(store.invalid_token_failures(APNS, b"tok-1").await?, Some(0));
    for failures in 1..INVALID_TOKEN_REMOVAL_THRESHOLD {
        assert_eq!(
            store
                .record_invalid_token(APNS, b"tok-1", CountFrom::Stored)
                .await?,
            InvalidTokenOutcome::Counted { failures }
        );
    }
    // A delivery the push service accepted resets the run.
    assert!(store.clear_invalid_tokens(APNS, b"tok-1").await?);
    assert_eq!(store.invalid_token_failures(APNS, b"tok-1").await?, Some(0));
    assert_eq!(
        store
            .record_invalid_token(APNS, b"tok-1", CountFrom::Stored)
            .await?,
        InvalidTokenOutcome::Counted { failures: 1 }
    );
    assert!(store.get(&r.key()).await?.is_some());

    // The count belongs to (platform, token): the same bytes on FCM are a
    // different token, and an unregistered token counts nothing.
    assert_eq!(
        store
            .record_invalid_token(PushPlatform::Fcm, b"tok-1", CountFrom::Stored)
            .await?,
        InvalidTokenOutcome::NotRegistered
    );
    assert_eq!(
        store
            .invalid_token_failures(PushPlatform::Fcm, b"tok-1")
            .await?,
        None
    );
    assert_eq!(
        store
            .record_invalid_token(APNS, b"tok-none", CountFrom::Stored)
            .await?,
        InvalidTokenOutcome::NotRegistered
    );
    assert!(!store.clear_invalid_tokens(APNS, b"tok-none").await?);
    assert_eq!(store.invalid_token_failures(APNS, b"tok-none").await?, None);
    Ok(())
}

/// Three consecutive invalid-token responses for one token remove every
/// registration holding it, whoever registered it, and leave each key's
/// registration timestamp as its deregistration floor (§10.7.1
/// `PushDeregistration`).
async fn third_invalid_token_removes_every_registration_for_the_token(
    store: PushRegistrationStore,
) -> Outcome {
    let alice = record("did:dht:alice", b"tok-shared", &[A, B], 4);
    let bob = record("did:dht:bob", b"tok-shared", &[B], 6);
    let other = record("did:dht:alice", b"tok-other", &[A], 4);
    let mut same_bytes_fcm = record("did:dht:carol", b"tok-shared", &[C], 4);
    same_bytes_fcm.platform = PushPlatform::Fcm;
    for r in [&alice, &bob, &other, &same_bytes_fcm] {
        store.upsert(r.clone()).await?;
    }

    // The count is per token, not per registrant: alternating which key the
    // response is attributed to does not matter, because the call names only
    // the token.
    assert_eq!(
        store
            .record_invalid_token(APNS, b"tok-shared", CountFrom::Stored)
            .await?,
        InvalidTokenOutcome::Counted { failures: 1 }
    );
    assert_eq!(
        store
            .record_invalid_token(APNS, b"tok-shared", CountFrom::Stored)
            .await?,
        InvalidTokenOutcome::Counted { failures: 2 }
    );
    assert!(store.get(&alice.key()).await?.is_some());
    assert_eq!(
        store
            .record_invalid_token(APNS, b"tok-shared", CountFrom::Stored)
            .await?,
        InvalidTokenOutcome::Removed { registrations: 2 }
    );

    assert_eq!(store.get(&alice.key()).await?, None);
    assert_eq!(store.get(&bob.key()).await?, None);
    assert_eq!(
        keys(&store.tokens_for_routing_id(&A).await?),
        vec![other.key()]
    );
    assert!(store.tokens_for_routing_id(&B).await?.is_empty());
    assert_eq!(
        keys(&store.tokens_for_routing_id(&C).await?),
        vec![same_bytes_fcm.key()],
        "the same bytes on another platform are another token"
    );
    assert_eq!(
        store.invalid_token_failures(APNS, b"tok-shared").await?,
        None
    );
    assert_eq!(store.accepted_timestamp(&alice.key()).await?, Some(4));
    assert_eq!(store.accepted_timestamp(&bob.key()).await?, Some(6));
    assert_eq!(
        store.upsert(bob.clone()).await,
        Err(PushStoreError::Stale {
            last_accepted: 6,
            offered: 6
        }),
        "the removed registration replayed is stale"
    );

    // A newer registration of the token starts a fresh count.
    let back = record("did:dht:bob", b"tok-shared", &[B], 7);
    assert_eq!(store.upsert(back).await?, UpsertOutcome::Inserted);
    assert_eq!(
        store.invalid_token_failures(APNS, b"tok-shared").await?,
        Some(0)
    );
    Ok(())
}

/// The count survives one registrant's removal while another registrant still
/// holds the token, and is dropped once none does.
async fn token_count_outlives_one_holder_but_not_the_last(store: PushRegistrationStore) -> Outcome {
    let alice = record("did:dht:alice", b"tok-shared", &[A], 1);
    let bob = record("did:dht:bob", b"tok-shared", &[A], 1);
    store.upsert(alice.clone()).await?;
    store.upsert(bob.clone()).await?;
    store
        .record_invalid_token(APNS, b"tok-shared", CountFrom::Stored)
        .await?;
    store
        .record_invalid_token(APNS, b"tok-shared", CountFrom::Stored)
        .await?;

    assert!(store.deregister(&alice.key(), 2).await?);
    assert_eq!(
        store.invalid_token_failures(APNS, b"tok-shared").await?,
        Some(2)
    );
    assert_eq!(
        store
            .record_invalid_token(APNS, b"tok-shared", CountFrom::Stored)
            .await?,
        InvalidTokenOutcome::Removed { registrations: 1 }
    );
    assert_eq!(store.get(&bob.key()).await?, None);

    let carol = record("did:dht:carol", b"tok-shared", &[A], 1);
    store.upsert(carol.clone()).await?;
    assert_eq!(
        store.invalid_token_failures(APNS, b"tok-shared").await?,
        Some(0)
    );
    assert!(store.remove(&carol.key()).await?);
    assert_eq!(
        store.invalid_token_failures(APNS, b"tok-shared").await?,
        None
    );
    Ok(())
}

async fn malformed_records_are_refused(store: PushRegistrationStore) -> Outcome {
    assert_eq!(
        store
            .upsert(record("did:dht:alice", b"tok-1", &[], 1))
            .await,
        Err(PushStoreError::EmptyRoutingIds)
    );
    let too_late = i64::MAX.unsigned_abs() + 1;
    assert_eq!(
        store
            .upsert(record("did:dht:alice", b"tok-1", &[A], too_late))
            .await,
        Err(PushStoreError::TimestampOutOfRange(too_late))
    );
    assert_eq!(
        store
            .get(&record("did:dht:alice", b"tok-1", &[A], 1).key())
            .await?,
        None
    );
    Ok(())
}

async fn each_device_on_one_platform_holds_its_own_registration(
    store: PushRegistrationStore,
) -> Outcome {
    // The key is (registrant, platform, token): two tokens of one identity on
    // one platform are two registrations, and so are one token on two
    // platforms.
    let phone = record("did:dht:alice", b"tok-phone", &[A], 1);
    let tablet = record("did:dht:alice", b"tok-tablet", &[B], 1);
    let mut fcm = record("did:dht:alice", b"tok-phone", &[C], 1);
    fcm.platform = PushPlatform::Fcm;
    for r in [&phone, &tablet, &fcm] {
        assert_eq!(store.upsert(r.clone()).await?, UpsertOutcome::Inserted);
    }
    assert_eq!(store.get(&phone.key()).await?, Some(phone.clone()));
    assert_eq!(store.get(&tablet.key()).await?, Some(tablet.clone()));
    assert_eq!(store.get(&fcm.key()).await?, Some(fcm.clone()));

    // A registration under one key leaves the others alone.
    let moved = record("did:dht:alice", b"tok-phone", &[B], 2);
    assert_eq!(store.upsert(moved.clone()).await?, UpsertOutcome::Replaced);
    assert_eq!(store.get(&tablet.key()).await?, Some(tablet.clone()));
    assert_eq!(store.get(&fcm.key()).await?, Some(fcm.clone()));
    assert_eq!(
        keys(&store.tokens_for_routing_id(&B).await?),
        vec![moved.key(), tablet.key()]
    );
    // The store keeps the 32-byte routing IDs it was given.
    assert_eq!(
        store.get(&fcm.key()).await?.map(|r| r.routing_ids),
        Some(vec![C])
    );
    Ok(())
}

async fn deregister_removes_only_its_own_key(store: PushRegistrationStore) -> Outcome {
    let phone = record("did:dht:alice", b"tok-phone", &[A, B], 1);
    let tablet = record("did:dht:alice", b"tok-tablet", &[A], 1);
    let mut fcm = record("did:dht:alice", b"tok-phone", &[A], 1);
    fcm.platform = PushPlatform::Fcm;
    let bob = record("did:dht:bob", b"tok-phone", &[A], 1);
    for r in [&phone, &tablet, &fcm, &bob] {
        store.upsert(r.clone()).await?;
    }

    assert!(store.deregister(&phone.key(), 2).await?);
    assert_eq!(store.get(&phone.key()).await?, None);
    assert!(store.tokens_for_routing_id(&B).await?.is_empty());
    assert_eq!(
        keys(&store.tokens_for_routing_id(&A).await?),
        vec![tablet.key(), fcm.key(), bob.key()]
    );
    for kept in [&tablet, &fcm, &bob] {
        assert_eq!(store.get(&kept.key()).await?, Some(kept.clone()));
    }
    Ok(())
}

async fn registration_replayed_after_deregistration_is_stale(
    store: PushRegistrationStore,
) -> Outcome {
    let reg = record("did:dht:alice", b"tok-1", &[A], 10);
    let key = reg.key();
    store.upsert(reg.clone()).await?;

    // A deregistration at or below the registration's timestamp is stale and
    // changes nothing.
    assert_eq!(
        store.deregister(&key, 10).await,
        Err(PushStoreError::Stale {
            last_accepted: 10,
            offered: 10
        })
    );
    assert_eq!(store.get(&key).await?, Some(reg.clone()));

    assert!(store.deregister(&key, 20).await?);
    assert_eq!(store.accepted_timestamp(&key).await?, Some(20));
    // The original registration, and any registration up to the
    // deregistration's timestamp, is refused.
    for offered in [10, 20] {
        let replay = record("did:dht:alice", b"tok-1", &[A], offered);
        let refused = store.upsert(replay).await;
        assert_eq!(
            refused,
            Err(PushStoreError::Stale {
                last_accepted: 20,
                offered
            })
        );
        assert_eq!(
            refused.err().map(|e| e.wire_code()),
            Some(code::PUSH_REGISTRATION_STALE)
        );
    }
    assert_eq!(store.get(&key).await?, None);
    assert!(store.tokens_for_routing_id(&A).await?.is_empty());

    // A replayed deregistration is stale too; a newer one raises the floor.
    assert_eq!(
        store.deregister(&key, 20).await,
        Err(PushStoreError::Stale {
            last_accepted: 20,
            offered: 20
        })
    );
    assert!(!store.deregister(&key, 25).await?);
    assert_eq!(store.accepted_timestamp(&key).await?, Some(25));

    // A deregistration for a key the store never held still keeps its
    // timestamp as the floor, so an older registration arriving later is stale.
    let never = record("did:dht:alice", b"tok-never", &[A], 1).key();
    assert!(!store.deregister(&never, 30).await?);
    assert_eq!(store.accepted_timestamp(&never).await?, Some(30));
    assert_eq!(
        store
            .upsert(record("did:dht:alice", b"tok-never", &[A], 5))
            .await,
        Err(PushStoreError::Stale {
            last_accepted: 30,
            offered: 5
        })
    );
    assert_eq!(
        store
            .upsert(record("did:dht:alice", b"tok-never", &[A], 31))
            .await?,
        UpsertOutcome::Inserted
    );

    // An invalid-token removal of a key the store never held records nothing.
    let unheld = record("did:dht:alice", b"tok-unheld", &[A], 1).key();
    assert!(!store.remove(&unheld).await?);
    assert_eq!(store.accepted_timestamp(&unheld).await?, None);

    // A newer registration is accepted and replaces the floor.
    let fresh = record("did:dht:alice", b"tok-1", &[B], 26);
    assert_eq!(store.upsert(fresh.clone()).await?, UpsertOutcome::Inserted);
    assert_eq!(store.accepted_timestamp(&key).await?, Some(26));
    assert_eq!(store.get(&key).await?, Some(fresh));
    Ok(())
}

async fn prune_drops_only_floors_below_the_bound(store: PushRegistrationStore) -> Outcome {
    let old = record("did:dht:alice", b"tok-old", &[A], 100);
    let recent = record("did:dht:alice", b"tok-recent", &[A], 100);
    let live = record("did:dht:alice", b"tok-live", &[A], 50);
    for r in [&old, &recent, &live] {
        store.upsert(r.clone()).await?;
    }
    store.deregister(&old.key(), 200).await?;
    store.deregister(&recent.key(), 300).await?;

    assert_eq!(store.prune_deregistrations(300).await?, 1);
    assert_eq!(store.accepted_timestamp(&old.key()).await?, None);
    assert_eq!(store.accepted_timestamp(&recent.key()).await?, Some(300));
    // A stored registration is no floor and is never pruned.
    assert_eq!(store.get(&live.key()).await?, Some(live.clone()));
    assert_eq!(store.prune_deregistrations(300).await?, 0);
    assert_eq!(store.prune_deregistrations(u64::MAX).await?, 1);
    assert_eq!(store.accepted_timestamp(&recent.key()).await?, None);
    assert_eq!(store.get(&live.key()).await?, Some(live));
    Ok(())
}

async fn deregistration_timestamp_out_of_range_is_refused(store: PushRegistrationStore) -> Outcome {
    let reg = record("did:dht:alice", b"tok-1", &[A], 1);
    store.upsert(reg.clone()).await?;
    let too_late = i64::MAX.unsigned_abs() + 1;
    assert_eq!(
        store.deregister(&reg.key(), too_late).await,
        Err(PushStoreError::TimestampOutOfRange(too_late))
    );
    assert_eq!(store.get(&reg.key()).await?, Some(reg));
    Ok(())
}

macro_rules! both_arms {
    ($($name:ident),* $(,)?) => {
        mod sqlite {
            $(
                #[tokio::test]
                async fn $name() -> Result<(), Box<dyn std::error::Error>> {
                    let arm = super::sqlite_arm()?;
                    super::$name(arm.store.clone()).await?;
                    Ok(())
                }
            )*
        }
        mod in_memory {
            $(
                #[tokio::test]
                async fn $name() -> Result<(), Box<dyn std::error::Error>> {
                    let arm = super::in_memory_arm();
                    super::$name(arm.store.clone()).await?;
                    Ok(())
                }
            )*
        }
    };
}

both_arms!(
    newer_timestamp_replaces_registration_and_index,
    identical_routing_set_leaves_index_unchanged,
    equal_or_older_timestamp_is_stale,
    new_key_past_per_registrant_cap_is_refused,
    remove_deletes_registration_and_index,
    tokens_for_routing_id_returns_each_registration_once,
    wake_tokens_returns_each_token_once_up_to_the_limit,
    count_from_zero_restarts_the_run,
    clear_all_resets_every_count,
    invalid_token_counter_counts_consecutive_failures,
    third_invalid_token_removes_every_registration_for_the_token,
    token_count_outlives_one_holder_but_not_the_last,
    malformed_records_are_refused,
    each_device_on_one_platform_holds_its_own_registration,
    deregister_removes_only_its_own_key,
    registration_replayed_after_deregistration_is_stale,
    prune_drops_only_floors_below_the_bound,
    deregistration_timestamp_out_of_range_is_refused,
);

#[tokio::test]
async fn sqlite_arm_keeps_registrations_across_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("push.db");
    let one = record("did:dht:alice", b"tok-1", &[A, B], 3);
    let two = record("did:dht:bob", b"tok-2", &[B], 4);
    {
        let store = PushRegistrationStore::open_sqlite(&path)?;
        store.upsert(one.clone()).await?;
        store.upsert(two.clone()).await?;
        store
            .record_invalid_token(APNS, b"tok-2", CountFrom::Stored)
            .await?;
        store
            .record_invalid_token(APNS, b"tok-2", CountFrom::Stored)
            .await?;
        let gone = record("did:dht:carol", b"tok-3", &[C], 5);
        store.upsert(gone.clone()).await?;
        store.deregister(&gone.key(), 7).await?;
    }

    let store = PushRegistrationStore::open_sqlite(&path)?;
    assert!(matches!(store, PushRegistrationStore::Sqlite(_)));
    assert_eq!(store.get(&one.key()).await?, Some(one.clone()));
    assert_eq!(store.get(&two.key()).await?, Some(two.clone()));
    assert_eq!(store.tokens_for_routing_id(&A).await?, vec![one.clone()]);
    assert_eq!(
        store.tokens_for_routing_id(&B).await?,
        vec![one, two.clone()]
    );
    assert_eq!(store.invalid_token_failures(APNS, b"tok-2").await?, Some(2));
    assert_eq!(
        store
            .upsert(record("did:dht:alice", b"tok-1", &[C], 3))
            .await,
        Err(PushStoreError::Stale {
            last_accepted: 3,
            offered: 3
        }),
        "the stored timestamp survives the reopen"
    );
    assert_eq!(
        store
            .upsert(record("did:dht:carol", b"tok-3", &[C], 7))
            .await,
        Err(PushStoreError::Stale {
            last_accepted: 7,
            offered: 7
        }),
        "the deregistration floor survives the reopen"
    );
    Ok(())
}

/// Reads the inherent `IS_DEFAULT = true` only when `T: Default`; otherwise
/// path resolution falls back to the blanket trait's `false`.
struct DefaultProbe<T>(PhantomData<T>);

trait NotDefault {
    const IS_DEFAULT: bool = false;
}

impl<T> NotDefault for DefaultProbe<T> {}

impl<T: Default> DefaultProbe<T> {
    const IS_DEFAULT: bool = true;
}

// The store selection type implements no `Default` (spec §17.17.1
// SCP-CAPSEL-8000). Adding one stops this file compiling. The second assertion
// shows the probe reads `true` for a type that does implement `Default`.
const _: () = assert!(!DefaultProbe::<PushRegistrationStore>::IS_DEFAULT);
const _: () = assert!(DefaultProbe::<Vec<u8>>::IS_DEFAULT);
