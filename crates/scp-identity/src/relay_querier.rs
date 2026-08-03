//! Generic multi-relay DID-document querier composer (§3.10.2, §3.10.4).
//!
//! [`RealMultiRelayQuerier`] is the production, transport-agnostic composer that
//! wires the relay layer into dual-layer resolution. It bridges the two relay
//! abstractions:
//!
//! - [`RelayQuerier`](crate::resolution::RelayQuerier) — the SINGLE-relay QUERY
//!   trait. Its production implementation lives in `scp-transport`
//!   ([`TransportRelayQuerier`]) because only that crate can talk to a relay
//!   (`scp-transport` depends on `scp-identity`, so a reverse dependency would
//!   be circular). A relay implementation performs `query_raw` + SCPR-decode
//!   (§9.10.12) and returns the decoded `(value, signature, seq)` triple as a
//!   [`RelayQueryRecord`](crate::resolution::RelayQueryRecord).
//! - [`MultiRelayQuerier`](crate::resolver::MultiRelayQuerier) — the MULTI-relay
//!   trait the [`DualLayerResolver`](crate::resolver::DualLayerResolver) composes.
//!   It takes a slice of relay URLs and returns the highest-seq valid record.
//!
//! Because [`RealMultiRelayQuerier`] needs only the `scp-identity`
//! `RelayQuerier` trait, [`did_routing_id`](crate::resolution::did_routing_id),
//! and the local BEP44 / self-cert helpers — all in this crate — the composer
//! itself does NOT depend on `scp-transport` (§3.10.12;
//! `resolution.rs` §3.10.4 establishes this abstraction).
//!
//! [`TransportRelayQuerier`]: https://docs.rs/scp-transport

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinSet;
use tracing::{debug, warn};

use crate::IdentityError;
use crate::dht::extract_public_key;
use crate::resolution::{RelayQuerier, did_routing_id, verify_relay_record};
use crate::resolver::{MultiRelayQuerier, RelayRecord};

/// The relay QUERY `limit` and the per-relay candidate-verification budget —
/// one canonical `N = 16` (§3.10.2).
///
/// This is the single source of truth for `N`, serving both roles the spec
/// pins to the same value so they cannot drift:
///
/// - **QUERY `limit: N`** (§3.10.2) — the production single-relay querier
///   (`TransportRelayQuerier` in `scp-transport`, which reuses this constant)
///   asks each relay for at most `N` candidates. `limit: N` dominates `limit: 1`
///   and defeats intra-relay shadowing on a non-validating relay.
/// - **Verification budget** — this composer verifies at most `N` candidates per
///   relay, bounding the Ed25519 cost against a malicious relay that returns a
///   huge candidate list. An honest relay stores O(1) co-located frames, so the
///   cap never constrains a realistic honest-relay workload.
///
/// Reused across the crate boundary (rather than re-declared in `scp-transport`)
/// so there is exactly one `N`, per SCP-RELAYRES-002 "reuse/converge, don't add
/// a third constant".
pub const MAX_CANDIDATES_PER_RELAY: usize = 16;

/// Per-relay wall-clock budget applied to each concurrent relay query.
///
/// With [`JoinSet`] concurrent fan-out each relay query races under this
/// independent deadline. Without it a single hung relay stalls the
/// `join_next()` loop until the resolver's outer `LAYER_TIMEOUT` (10 s)
/// fires and cancels the entire composer future — discarding any valid `best`
/// already collected from faster relays. At 5 s each task completes (or is
/// dropped) well before the outer backstop, preserving already-found results.
const PER_RELAY_TIMEOUT: Duration = Duration::from_secs(5);

/// The production [`MultiRelayQuerier`] composer over any single-relay
/// [`RelayQuerier`] (§3.10.2, §3.10.4 step 3a).
///
/// Queries the provided relay URLs concurrently (§3.10.8: "suppression by one
/// relay source does not prevent resolution"). For each relay it fetches the
/// returned candidates — up to [`MAX_CANDIDATES_PER_RELAY`] per relay (the `Vec`
/// [`RelayQuerier`] contract) — and selects the one with the highest BEP44
/// `seq` among those that pass `verify_relay_record`: BEP44 signature verifies
/// against the DID's Ed25519 key (§9.6.1) AND the embedded identity key
/// self-certifies against the DID suffix. Invalid candidates are logged at WARN
/// and skipped — WITHIN a relay's candidate list AND across relays. The overall
/// best across all relays is returned.
///
/// # Shadow-defeat (intra-relay suppression, §3.10.8)
///
/// Iterating the returned candidates at a routing ID — up to
/// [`MAX_CANDIDATES_PER_RELAY`] per relay, not just the first decodable one — is
/// load-bearing against two attacks that afflict **honest relays** with
/// co-located stale/junk frames:
///
/// 1. **Bad-signature shadow.** A decodable-but-bad-signature frame co-located
///    before the genuine record must not shadow it; since raw publish is
///    unauthenticated and the routing ID is DID-derivable, an attacker could
///    plant one well-framed bad-signature blob to permanently suppress relay
///    resolution on an honest relay.
///
/// 2. **Stale-valid shadow (version rollback).** Old DID documents are
///    legitimately signed by the DID key and their `(value, signature, seq)`
///    triples are public (previously published, cached by any resolver). An
///    attacker captures an old triple (seq=1, pre-rotation `#active` key) and
///    republishes it co-located before the current record (seq=5). Without
///    highest-seq selection, first-valid returns the stale record and the
///    resolver never sees the fresher one. Selecting highest-seq among the
///    verified candidates closes this attack: `seq` is inside the BEP44 signed
///    payload, so an attacker cannot forge a higher seq without the owner's
///    private key (§3.10.7).
///
/// # Threat-model boundary (the cap is a `DoS` budget, not a suppression control)
///
/// The [`MAX_CANDIDATES_PER_RELAY`] cap bounds the Ed25519 verification budget
/// per relay. Shadow-defeat therefore holds for **honest** relays: their
/// co-located junk/stale frames sit alongside O(1) genuine records, well within
/// the cap. It does NOT hold against a **malicious** relay that deliberately
/// returns ≥[`MAX_CANDIDATES_PER_RELAY`] junk frames before the genuine record —
/// such a relay can push the real record past the cap and suppress it. This is
/// not a new capability: a malicious relay can suppress resolution with zero
/// effort simply by returning an empty `Vec`. A relay actively trying to
/// suppress is already in the threat model (§3.10.8 "relay suppresses
/// document"), and cross-relay + DHT fan-out is the defense against it — not the
/// intra-relay candidate scan. The cap trades an unbounded-verification `DoS` for
/// a suppression vector that a malicious relay already possesses for free.
///
/// # Layering
///
/// This composer owns **intra-relay candidate selection** (highest-seq among
/// valid candidates at each relay's candidate list). The
/// [`DualLayerResolver`](crate::resolver::DualLayerResolver) owns
/// **cross-layer sequence arbitration** (relay result vs DHT result), rollback
/// rejection against the cached high-water mark, and caching (§3.10.4/§3.10.7).
/// The resolver independently re-verifies the returned record (defense in
/// depth) via the same shared [`verify_relay_record`] path.
pub struct RealMultiRelayQuerier<Q: RelayQuerier> {
    /// The single-relay querier (production: `TransportRelayQuerier`).
    inner: Arc<Q>,
}

impl<Q: RelayQuerier> RealMultiRelayQuerier<Q> {
    /// Creates a composer over the given single-relay querier.
    #[must_use]
    pub const fn new(inner: Arc<Q>) -> Self {
        Self { inner }
    }
}

// Trait uses RPITIT with an explicit `+ Send` bound; `async fn` in trait does
// not guarantee `Send` futures, so a manual `impl Future` is required.
#[allow(clippy::manual_async_fn)]
impl<Q: RelayQuerier + 'static> MultiRelayQuerier for RealMultiRelayQuerier<Q> {
    fn query(
        &self,
        did: &str,
        relay_urls: &[String],
    ) -> impl Future<Output = Result<Option<RelayRecord>, IdentityError>> + Send {
        let inner = Arc::clone(&self.inner);
        let did = did.to_owned();
        let relay_urls = relay_urls.to_vec();

        async move {
            // Compute the routing ID and extract the DID's Ed25519 key once.
            // A malformed DID string is a caller error, propagated as `Err`.
            let routing_id = did_routing_id(&did);
            let public_key = extract_public_key(&did)?;

            // Query all relays CONCURRENTLY, each guarded by PER_RELAY_TIMEOUT
            // (§3.10.8: "suppression by one relay source does not prevent
            // resolution"). Without per-relay timeout, a single hung relay would
            // stall the join_next() collection loop until the resolver's outer
            // LAYER_TIMEOUT fires, cancelling the entire composer future and
            // discarding any `best` already collected from faster relays. With
            // per-relay timeout each task completes within PER_RELAY_TIMEOUT
            // regardless of reachability, so the outer timeout is a backstop that
            // rarely fires. Accumulation order is unspecified (tasks complete as
            // they finish), but highest-seq selection is order-independent. On a
            // seq tie the first-received result is retained (strict `>`); this is
            // acceptable — two valid records at the same seq are byte-identical
            // (same signed `(value, signature, seq)` payload), only `relay_url`
            // provenance differs.
            //
            // `routing_id` is `[u8; 32]` (Copy); each task gets its own copy.
            let mut tasks: JoinSet<(String, Vec<_>)> = JoinSet::new();
            for relay_url in relay_urls {
                let inner = Arc::clone(&inner);
                tasks.spawn(async move {
                    let candidates = match tokio::time::timeout(
                        PER_RELAY_TIMEOUT,
                        inner.query(&relay_url, &routing_id),
                    )
                    .await
                    {
                        Ok(Ok(v)) => v,
                        Ok(Err(e)) => {
                            debug!(relay_url = %relay_url, error = %e, "relay query failed — skipping relay");
                            Vec::new()
                        }
                        Err(_elapsed) => {
                            debug!(relay_url = %relay_url, "relay query timed out — skipping relay");
                            Vec::new()
                        }
                    };
                    (relay_url, candidates)
                });
            }

            // Track the highest-seq valid record across all relays (§3.10.4 step 5
            // / §3.10.7: "the highest valid sequence number wins").
            let mut best: Option<RelayRecord> = None;

            while let Some(join_result) = tasks.join_next().await {
                // Transport errors and relay timeouts are already handled inside
                // the spawned task: they return an empty Vec and skip the relay
                // without aborting the sweep. A JoinError here is a task panic —
                // a bug, but still must not abort the sweep.
                let (relay_url, candidates) = match join_result {
                    Ok(task_output) => task_output,
                    Err(e) => {
                        warn!(error = %e, "relay query task panicked unexpectedly");
                        continue;
                    }
                };

                // Apply a defensive cap: an untrusted relay must not be able to
                // drive O(N) Ed25519 verifications per resolve (§3.10.8). This is
                // a `DoS` budget, not a suppression control — see the type doc.
                for record in candidates.into_iter().take(MAX_CANDIDATES_PER_RELAY) {
                    // Shared verify: BEP44 signature + UTF-8/JSON + self-cert.
                    // Cross-DID substitution is cryptographically impossible:
                    // the embedded identity key must match the DID suffix, and
                    // `seq` is inside the signed payload so an attacker cannot
                    // forge a higher seq without the owner's private key.
                    if let Err(e) = verify_relay_record(
                        &did,
                        &public_key,
                        &record.value,
                        &record.signature,
                        record.seq,
                    ) {
                        warn!(relay_url = %relay_url, did = %did, error = %e, "relay candidate failed verification — skipping");
                        continue;
                    }

                    // Highest-seq valid record wins (§3.10.4 step 5, §3.10.7).
                    if best.as_ref().is_none_or(|b| record.seq > b.seq) {
                        best = Some(RelayRecord {
                            value: record.value,
                            signature: record.signature,
                            seq: record.seq,
                            relay_url: relay_url.clone(),
                        });
                    }
                }
            }

            // The resolver re-verifies the returned record (defense in depth)
            // and owns cross-layer sequence arbitration + caching.
            Ok(best)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::resolution::{InMemoryRelayQuerier, RelayQueryRecord};
    use scp_dht::bep44_signable;
    use scp_did::DidDocument;

    fn make_ed25519_keypair() -> (ed25519_dalek::VerifyingKey, ed25519_dalek::SigningKey) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        (verifying_key, signing_key)
    }

    fn did_from_public_key(public_key: &ed25519_dalek::VerifyingKey) -> String {
        format!("did:dht:z{}", zbase32::encode(public_key.as_bytes()))
    }

    fn signed_record(
        did: &str,
        identity_key: &[u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
        seq: u64,
    ) -> RelayQueryRecord {
        let doc = DidDocument::new(did, identity_key, &[2u8; 32], &[3u8; 32]);
        let value = serde_json::to_vec(&doc).unwrap();
        let payload = bep44_signable(&value, seq);
        let signature: ed25519_dalek::Signature =
            ed25519_dalek::Signer::sign(signing_key, &payload);
        RelayQueryRecord {
            value,
            signature: signature.to_bytes(),
            seq,
        }
    }

    /// Returns the valid record from relay-b when relay-a has none.
    /// The `relay_url` field in the returned record matches the serving relay.
    #[tokio::test]
    async fn returns_valid_record_with_relay_url() {
        let (vk, sk) = make_ed25519_keypair();
        let did = did_from_public_key(&vk);
        let routing_id = did_routing_id(&did);
        let record = signed_record(&did, vk.as_bytes(), &sk, 7);

        let inner = InMemoryRelayQuerier::new();
        inner
            .insert("wss://relay-b.example.com/scp/v1", &routing_id, record)
            .await;

        let composer = RealMultiRelayQuerier::new(Arc::new(inner));
        let result = composer
            .query(
                &did,
                &[
                    "wss://relay-a.example.com/scp/v1".to_owned(),
                    "wss://relay-b.example.com/scp/v1".to_owned(),
                ],
            )
            .await
            .unwrap();

        let record = result.expect("relay-b has a valid record");
        assert_eq!(record.seq, 7);
        assert_eq!(record.relay_url, "wss://relay-b.example.com/scp/v1");
    }

    /// Shadow-defeat across relays: relay-a has a bad signature, relay-b has
    /// a valid record at the same routing ID — the composer returns relay-b's
    /// valid record instead of shadowing it with relay-a's bad one.
    #[tokio::test]
    async fn skips_invalid_signature_falls_through_to_next_candidate() {
        let (vk, sk) = make_ed25519_keypair();
        let did = did_from_public_key(&vk);
        let routing_id = did_routing_id(&did);

        let mut bad = signed_record(&did, vk.as_bytes(), &sk, 1);
        bad.signature[0] ^= 0xFF;
        let good = signed_record(&did, vk.as_bytes(), &sk, 1);

        let inner = InMemoryRelayQuerier::new();
        inner
            .insert("wss://relay-a.example.com/scp/v1", &routing_id, bad)
            .await;
        inner
            .insert("wss://relay-b.example.com/scp/v1", &routing_id, good)
            .await;

        let composer = RealMultiRelayQuerier::new(Arc::new(inner));
        let result = composer
            .query(
                &did,
                &[
                    "wss://relay-a.example.com/scp/v1".to_owned(),
                    "wss://relay-b.example.com/scp/v1".to_owned(),
                ],
            )
            .await
            .unwrap();

        assert_eq!(
            result.expect("relay-b valid").relay_url,
            "wss://relay-b.example.com/scp/v1"
        );
    }

    /// Intra-relay shadow-defeat — bad-signature (§3.10.8): a decodable but
    /// bad-signature frame co-located FIRST at the SAME `routing_id` on the
    /// SAME relay must NOT shadow the valid frame stored after it. The composer
    /// must iterate every candidate and still return the valid record —
    /// otherwise an attacker planting one well-framed bad-signature blob
    /// (raw publish is unauthenticated, the `routing_id` is DID-derivable)
    /// permanently suppresses relay resolution.
    #[tokio::test]
    async fn skips_bad_candidate_colocated_before_valid_at_same_relay() {
        let (vk, sk) = make_ed25519_keypair();
        let did = did_from_public_key(&vk);
        let routing_id = did_routing_id(&did);

        let mut bad = signed_record(&did, vk.as_bytes(), &sk, 3);
        bad.signature[0] ^= 0xFF; // decodes, but signature fails to verify
        let good = signed_record(&did, vk.as_bytes(), &sk, 3);

        let inner = InMemoryRelayQuerier::new();
        // Bad FIRST, valid SECOND — both at the SAME (relay_url, routing_id).
        inner
            .insert("wss://relay-a.example.com/scp/v1", &routing_id, bad)
            .await;
        inner
            .insert("wss://relay-a.example.com/scp/v1", &routing_id, good)
            .await;

        let composer = RealMultiRelayQuerier::new(Arc::new(inner));
        let result = composer
            .query(&did, &["wss://relay-a.example.com/scp/v1".to_owned()])
            .await
            .unwrap();

        let record = result.expect("valid co-located record must still resolve");
        assert_eq!(record.seq, 3);
        assert_eq!(record.relay_url, "wss://relay-a.example.com/scp/v1");
    }

    /// Intra-relay shadow-defeat — stale-valid (§3.10.7, §3.10.8): a
    /// validly-signed STALE record (seq=1) co-located BEFORE the current record
    /// (seq=5) at the SAME relay must NOT shadow the fresh record. The composer
    /// must return the HIGHEST-SEQ valid candidate, not the first. Old DID
    /// documents have good BEP44 signatures (the owner signed them once); an
    /// attacker with access to a captured old triple can replay it at the
    /// DID-derivable `routing_id` to roll back a key rotation.
    #[tokio::test]
    async fn highest_seq_wins_over_stale_colocated_at_same_relay() {
        let (vk, sk) = make_ed25519_keypair();
        let did = did_from_public_key(&vk);
        let routing_id = did_routing_id(&did);

        // Stale record (seq=1) inserted FIRST — this is the shadow-attack vector.
        let stale = signed_record(&did, vk.as_bytes(), &sk, 1);
        // Fresh record (seq=5) inserted SECOND — must win per §3.10.7.
        let fresh = signed_record(&did, vk.as_bytes(), &sk, 5);

        let inner = InMemoryRelayQuerier::new();
        inner
            .insert("wss://relay-a.example.com/scp/v1", &routing_id, stale)
            .await;
        inner
            .insert("wss://relay-a.example.com/scp/v1", &routing_id, fresh)
            .await;

        let composer = RealMultiRelayQuerier::new(Arc::new(inner));
        let result = composer
            .query(&did, &["wss://relay-a.example.com/scp/v1".to_owned()])
            .await
            .unwrap();

        let record = result.expect("at least one valid record must be found");
        assert_eq!(
            record.seq, 5,
            "fresh record (seq=5) must win over stale (seq=1) — first-valid would return 1"
        );
    }

    /// Combined intra-relay shadow-defeat (§3.10.4 step 5, §3.10.7, §3.10.8):
    /// the genuine HIGHEST-seq record is co-located with BOTH a stale-but-valid
    /// record AND a decodable-but-bad-signature record at the SAME relay, in the
    /// worst insertion order (junk first). The composer must still return the
    /// genuine highest-seq record — proving the #2226 first-valid selection is
    /// gone (first-valid would return the stale seq=2 or skip to whatever
    /// verifies first, never the seq=9 genuine record). This is the composer-side
    /// half of the raw-query "genuine blob not dropped on repeat/co-located
    /// query" acceptance criterion; the transport-side half (undecodable
    /// co-located blobs) lives in `scp-transport`'s `TransportRelayQuerier`
    /// integration tests, since undecodable blobs are dropped at frame-decode
    /// before the composer ever sees them.
    #[tokio::test]
    async fn highest_seq_wins_over_stale_and_bad_sig_colocated() {
        let (vk, sk) = make_ed25519_keypair();
        let did = did_from_public_key(&vk);
        let routing_id = did_routing_id(&did);

        // Bad-signature record FIRST (a planted shadow), then a stale-but-valid
        // record, then the genuine current record LAST — the worst order for a
        // first-valid selector.
        let mut bad = signed_record(&did, vk.as_bytes(), &sk, 5);
        bad.signature[0] ^= 0xFF;
        let stale = signed_record(&did, vk.as_bytes(), &sk, 2);
        let genuine = signed_record(&did, vk.as_bytes(), &sk, 9);

        let inner = InMemoryRelayQuerier::new();
        for rec in [bad, stale, genuine] {
            inner
                .insert("wss://relay-a.example.com/scp/v1", &routing_id, rec)
                .await;
        }

        let composer = RealMultiRelayQuerier::new(Arc::new(inner));
        let result = composer
            .query(&did, &["wss://relay-a.example.com/scp/v1".to_owned()])
            .await
            .unwrap();

        let record = result.expect("the genuine highest-seq record must resolve");
        assert_eq!(
            record.seq, 9,
            "genuine seq=9 must win over stale seq=2 and the bad-sig shadow — \
             first-valid selection would not return 9"
        );
    }

    /// Self-certification failure: a record signed with the correct key but
    /// containing a mismatched identity key in the document body is rejected.
    #[tokio::test]
    async fn skips_bad_self_certification() {
        let (vk, sk) = make_ed25519_keypair();
        let did = did_from_public_key(&vk);
        let routing_id = did_routing_id(&did);

        // Signed correctly, but the embedded identity key does not match the DID.
        let record = signed_record(&did, &[0xFFu8; 32], &sk, 1);

        let inner = InMemoryRelayQuerier::new();
        inner
            .insert("wss://relay-a.example.com/scp/v1", &routing_id, record)
            .await;

        let composer = RealMultiRelayQuerier::new(Arc::new(inner));
        let result = composer
            .query(&did, &["wss://relay-a.example.com/scp/v1".to_owned()])
            .await
            .unwrap();

        assert!(result.is_none(), "self-certification failure => no record");
    }

    /// Cross-relay shadow-defeat — stale-valid (§3.10.7): relay-a holds a
    /// validly-signed STALE record (seq=3) and relay-b holds the current record
    /// (seq=10). The composer must return relay-b's seq=10, not relay-a's seq=3.
    /// Without cross-relay highest-seq accumulation, an attacker controlling an
    /// earlier-priority relay (or a relay that serves a stale but genuine old
    /// triple captured from any public resolution) could downgrade resolution to
    /// the stale record and suppress a key rotation.
    #[tokio::test]
    async fn cross_relay_highest_seq_wins_over_stale_relay() {
        let (vk, sk) = make_ed25519_keypair();
        let did = did_from_public_key(&vk);
        let routing_id = did_routing_id(&did);

        // relay-a (higher priority, queried first) holds seq=3 — stale.
        let stale = signed_record(&did, vk.as_bytes(), &sk, 3);
        // relay-b (lower priority) holds seq=10 — current.
        let fresh = signed_record(&did, vk.as_bytes(), &sk, 10);

        let inner = InMemoryRelayQuerier::new();
        inner
            .insert("wss://relay-a.example.com/scp/v1", &routing_id, stale)
            .await;
        inner
            .insert("wss://relay-b.example.com/scp/v1", &routing_id, fresh)
            .await;

        let composer = RealMultiRelayQuerier::new(Arc::new(inner));
        let result = composer
            .query(
                &did,
                &[
                    "wss://relay-a.example.com/scp/v1".to_owned(),
                    "wss://relay-b.example.com/scp/v1".to_owned(),
                ],
            )
            .await
            .unwrap();

        let record = result.expect("at least one valid record must be found");
        assert_eq!(
            record.seq, 10,
            "cross-relay highest-seq (10) must beat lower-priority relay's stale seq (3)"
        );
        assert_eq!(
            record.relay_url, "wss://relay-b.example.com/scp/v1",
            "result must come from the relay that held the freshest record"
        );
    }

    /// An empty relay list returns `Ok(None)` immediately without querying.
    #[tokio::test]
    async fn empty_relay_list_returns_none() {
        let (vk, _sk) = make_ed25519_keypair();
        let did = did_from_public_key(&vk);
        let composer = RealMultiRelayQuerier::new(Arc::new(InMemoryRelayQuerier::new()));
        let result = composer.query(&did, &[]).await.unwrap();
        assert!(result.is_none());
    }

    /// A malformed DID string (not `did:dht:z...`) returns `Err` immediately.
    #[tokio::test]
    async fn invalid_did_is_error() {
        let composer = RealMultiRelayQuerier::new(Arc::new(InMemoryRelayQuerier::new()));
        let result = composer
            .query("not-a-did", &["wss://relay.example.com/scp/v1".to_owned()])
            .await;
        assert!(result.is_err());
    }
}
