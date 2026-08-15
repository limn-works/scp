//! The production DHT client reports a typed error when the DHT does not
//! answer (`.docs/specs/17-persistence-and-storage.md` §17.17.1
//! SCP-CAPSEL-8001 and §17.17.3 SCP-CAPSEL-8013).
//!
//! `PkarrDhtClient` is the only shipped DID/DHT backend. §17.17.3 names the
//! exact failure this test forbids: an arm whose "publish reports success
//! while doing nothing" fails OPEN, because the SDK then tells the caller a key
//! rotation or revocation reached the DHT layer when no peer received it. So
//! the assertion is not merely that publishing errors — it is that publishing
//! against a DHT that does not answer produces `DhtError::DhtPublishFailed`
//! rather than `Ok(())`.
//!
//! The client is built with a one-millisecond DHT deadline, which no Mainline
//! round trip can meet, so the unreachable-DHT condition holds whether or not
//! the machine running the test has network access.

#![cfg(feature = "production-dht")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use scp_dht::{DhtClient, DhtError, PkarrDhtClient};

/// A deadline no DHT round trip can meet, so `put_mutable` cannot complete.
const UNMEETABLE_DEADLINE: Duration = Duration::from_millis(1);

#[tokio::test]
async fn publish_fails_closed_when_the_dht_does_not_answer() {
    let client = PkarrDhtClient::builder()
        .dht_timeout(UNMEETABLE_DEADLINE)
        .build()
        .expect("the production Pkarr client must build");

    let public_key = [0x11u8; 32];
    let signature = [0x22u8; 64];

    let result = client
        .publish(&public_key, &signature, b"did-document-bytes", 1)
        .await;

    match result {
        Err(DhtError::DhtPublishFailed(message)) => {
            assert!(
                !message.is_empty(),
                "the fail-closed DHT publish error must carry a diagnostic message"
            );
        }
        Err(other) => panic!("expected DhtError::DhtPublishFailed, got {other:?}"),
        Ok(()) => panic!(
            "publishing to a DHT that does not answer must fail closed with \
             DhtError::DhtPublishFailed; reporting success here tells the caller a rotation or \
             revocation reached the DHT layer when no peer received it (spec §17.17.3 \
             SCP-CAPSEL-8013)"
        ),
    }
}
