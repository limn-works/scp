//! `ScpClient`-specific test orchestration over the single-sourced relay mock.
//!
//! The faithful in-memory [`Relay`] model — subscription table, self-echo
//! deliver-to-publisher, `since:Some` backfill, `publish_log`, and the
//! `fail_publish_after` / `fail_send_until` / `external_publish` / `inject_blob`
//! knobs — lives ONCE in the dev-only `scp-relay-mock` crate and is re-exported
//! here. Only the `ScpClient`-specific bits stay in this module: the [`Party`]
//! (an `ScpClient` + its relay connection id) with its [`RelayParty`] impl, the
//! [`RelayExt`] party constructors, and the bootstrap helpers.

#![allow(dead_code)]
// not every integration test uses every helper
// Not every integration-test binary uses every re-export from `scp-relay-mock`
// (the `pub use` below); a test bin has no external consumers, so an unused
// re-export would warn like dead code.
#![allow(unused_imports)]
#![allow(clippy::expect_used)] // integration-test harness: `expect` makes failures legible

use std::sync::Arc;

use scp_client::{LocalSigner, MemoryStorage, ScpClient, Storage};
use scp_clock::{Clock, SystemClock, TestClock};
use scp_protocol::context::membership::ContextEvent;

pub use scp_relay_mock::{ConnId, PublishRecord, Relay, RelayParty};

/// A client plus its relay connection id.
pub struct Party {
    pub client: ScpClient,
    pub conn: ConnId,
}

impl RelayParty for Party {
    fn conn_id(&self) -> ConnId {
        self.conn
    }

    fn deliver(&mut self, frame: Vec<u8>) -> Result<(), String> {
        self.client
            .handle_relay_frame(&frame)
            .map_err(|e| format!("{e:?}"))
    }
}

/// `ScpClient`-specific party constructors over a shared [`Relay`]. Kept as an
/// extension trait (not inherent methods, which a foreign type cannot gain) so
/// call sites keep the `relay.new_party(..)` / `relay.party_with(..)` shape.
pub trait RelayExt {
    /// Builds a fresh [`Party`] connected to this relay, over a fixed clock seeded
    /// from real `now + offset` (so minted `KeyPackage` `Lifetime`s stay valid
    /// against openmls's un-injectable internal clock) and an in-memory store.
    fn new_party(&self, did: &str, offset: u64) -> Party;

    /// Builds a [`Party`] over CALLER-SUPPLIED deps (for restore/poison tests that
    /// share a storage handle or inject a failing store), connected to this relay.
    fn party_with(
        &self,
        signer: Arc<LocalSigner>,
        storage: Arc<dyn Storage>,
        clock: Arc<dyn Clock>,
    ) -> Party;
}

impl RelayExt for Relay {
    fn new_party(&self, did: &str, offset: u64) -> Party {
        let (conn, sink) = self.connect();
        let signer = Arc::new(LocalSigner::active_for_testing(did));
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let clock: Arc<dyn Clock> = Arc::new(TestClock::new(SystemClock.now_secs() + offset));
        let client = ScpClient::new(signer, storage, clock, sink).expect("construct client");
        Party { client, conn }
    }

    fn party_with(
        &self,
        signer: Arc<LocalSigner>,
        storage: Arc<dyn Storage>,
        clock: Arc<dyn Clock>,
    ) -> Party {
        let (conn, sink) = self.connect();
        let client = ScpClient::new(signer, storage, clock, sink).expect("construct client");
        Party { client, conn }
    }
}

/// The first `MessageReceived` payload in a drained event list, if any.
#[must_use]
pub fn first_received(events: &[ContextEvent]) -> Option<Vec<u8>> {
    events.iter().find_map(|e| match e {
        ContextEvent::MessageReceived { payload, .. } => Some(payload.clone()),
        _ => None,
    })
}

/// Delivers the in-tab §9.16 sender-key distributions to their targets (directly
/// via `receive_message`, the out-of-band model — not over the relay). Maps
/// `target_did` to the matching party.
#[allow(clippy::expect_used)]
pub fn deliver_distributions(
    ctx: &str,
    dists: &[scp_client::SenderKeyDistribution],
    parties: &mut [(&str, &mut ScpClient)],
) {
    for d in dists {
        for (did, client) in parties.iter_mut() {
            if *did == d.target_did {
                client
                    .receive_message(ctx, &d.ciphertext)
                    .expect("install sender-key distribution");
            }
        }
    }
}

/// Connects Alice (creator) + Bob (joiner) into a fully-wired 2-party context over
/// the realistic relay: MLS group shared, §9.16 sender keys exchanged both ways,
/// and — via the reciprocal-announce cascade pumped to quiescence — BOTH pseudonym
/// registries populated. Both parties' buffers are drained before return.
#[allow(clippy::expect_used)]
#[must_use]
pub fn connect_two(relay: &Relay, ctx: &str, alice_did: &str, bob_did: &str) -> (Party, Party) {
    let mut alice = relay.new_party(alice_did, 0);
    alice.client.create_context(ctx).expect("alice creates");

    let mut bob = relay.new_party(bob_did, 100);
    let bob_kp = bob
        .client
        .generate_key_package_for_join(ctx)
        .expect("bob key package");
    let add = alice
        .client
        .add_member(ctx, &bob_kp)
        .expect("alice adds bob");
    let bob_dists = bob
        .client
        .join_context_encrypted(ctx, &add.welcome, &add.event_log, &add.wrapping_keys)
        .expect("bob joins");

    // Exchange §9.16 sender keys out-of-band, THEN pump the announce cascade (Bob's
    // join-announce → Alice reciprocates → Bob reciprocates → quiescent).
    deliver_distributions(
        ctx,
        &add.sender_key_distributions,
        &mut [(alice_did, &mut alice.client), (bob_did, &mut bob.client)],
    );
    deliver_distributions(
        ctx,
        &bob_dists,
        &mut [(alice_did, &mut alice.client), (bob_did, &mut bob.client)],
    );
    relay.pump(&mut [&mut alice, &mut bob]);

    let _ = alice.client.drain_events(ctx);
    let _ = bob.client.drain_events(ctx);
    let _ = relay.drain_publish_log();
    (alice, bob)
}
