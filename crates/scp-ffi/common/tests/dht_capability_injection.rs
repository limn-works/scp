//! DHT capability-injection tests (ADR-062 Slice 1, SCP-CAPINJECT-001).
//!
//! These lock in the E1 structural fix: the shipped DHT backend is the real
//! Mainline Pkarr client, construction fails closed, and the in-memory arm is a
//! test-harness double that is *not even nameable* in a shipped (non-`testing`)
//! build.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use scp_ffi_common::dht::{ClientDhtConfig, DhtInitError, FfiDhtClient};

// ---------------------------------------------------------------------------
// M3 — production DHT construction fails closed
// ---------------------------------------------------------------------------

/// An unsatisfiable production `ClientDhtConfig` (a malformed gateway URL)
/// yields `Err(DhtInitError)` — it NEVER falls back to an in-memory or no-op
/// client. This is the §17.17.3 fail-closed guarantee for the DHT backend.
#[test]
fn into_client_fails_closed_on_unsatisfiable_config() {
    let cfg = ClientDhtConfig {
        gateways: vec!["not-a-valid-url".to_owned()],
    };
    let result = cfg.into_client();
    assert!(
        matches!(result, Err(DhtInitError::InvalidGateway { .. })),
        "an unsatisfiable production DHT config must fail closed with DhtInitError, \
         never substitute an in-memory client"
    );
}

/// A well-formed gateway URL is accepted and builds a real Pkarr client (the
/// only shipped backend). This is the happy path for `into_client`.
#[test]
fn into_client_builds_pkarr_for_valid_config() {
    let cfg = ClientDhtConfig {
        gateways: vec!["https://dns.example.org".to_owned()],
    };
    let client = cfg
        .into_client()
        .expect("valid gateway config must build a Pkarr client");
    // In a shipped build the only inhabitable variant is Pkarr.
    match &client {
        FfiDhtClient::Pkarr(_) => {}
        #[cfg(feature = "testing")]
        FfiDhtClient::InMemory(_) => panic!("into_client must never construct the InMemory arm"),
    }
}

/// Gateway-normalization PARITY with the node/self-host `build_pkarr_client`:
/// each gateway is TRIMMED and empty entries are SKIPPED *before* validation, so
/// a whitespace-padded gateway is trimmed-then-accepted (not rejected as a
/// malformed raw URL) and a whitespace-only entry is silently skipped. Before the
/// fix this path validated the RAW string, so `"  https://dns.example.org  "` —
/// accepted by the node path — was rejected here, breaking the "identical
/// contract" the docs claim. Both paths now accept/reject exactly these inputs
/// (mirror: `scp_node::self_host::build_pkarr_client` and its
/// `build_pkarr_client_trims_and_accepts_whitespace_padded_gateway` test).
#[test]
fn into_client_trims_and_skips_gateways_like_the_node_path() {
    // A whitespace-padded VALID gateway is trimmed then accepted → Pkarr client.
    let padded = ClientDhtConfig {
        gateways: vec!["  https://dns.example.org  ".to_owned()],
    }
    .into_client()
    .expect("a whitespace-padded valid gateway must be trimmed-then-accepted (node-path parity)");
    match &padded {
        FfiDhtClient::Pkarr(_) => {}
        #[cfg(feature = "testing")]
        FfiDhtClient::InMemory(_) => panic!("into_client must never construct the InMemory arm"),
    }

    // A whitespace-only entry is skipped (not a validation error) — same as an
    // empty gateway list, so this builds the default direct-Mainline client.
    let whitespace_only = ClientDhtConfig {
        gateways: vec!["   ".to_owned(), String::new()],
    }
    .into_client()
    .expect("whitespace-only / empty gateways must be skipped, not rejected (node-path parity)");
    match &whitespace_only {
        FfiDhtClient::Pkarr(_) => {}
        #[cfg(feature = "testing")]
        FfiDhtClient::InMemory(_) => panic!("into_client must never construct the InMemory arm"),
    }

    // A padded but MALFORMED gateway still fails closed (trim does not rescue it).
    let malformed = ClientDhtConfig {
        gateways: vec!["  not-a-valid-url  ".to_owned()],
    }
    .into_client();
    assert!(
        matches!(malformed, Err(DhtInitError::InvalidGateway { .. })),
        "a malformed gateway must still fail closed after trimming"
    );
}

// ---------------------------------------------------------------------------
// Structural — FfiDhtClient is Pkarr-only in a shipped build
// ---------------------------------------------------------------------------

/// Compile-time assertion (a `match` with no `InMemory` arm) that in a shipped
/// (non-`testing`) build `FfiDhtClient` has exactly one variant, `Pkarr`, and
/// the in-memory §17.17.3 nullifier is not in scope. If a future change added an
/// ungated in-memory arm, this exhaustive match would fail to compile.
#[cfg(not(feature = "testing"))]
#[test]
fn ffi_dht_client_is_pkarr_only_in_shipped_build() {
    fn backend_label(client: &FfiDhtClient) -> &'static str {
        match client {
            FfiDhtClient::Pkarr(_) => "pkarr",
        }
    }
    let client = ClientDhtConfig::default()
        .into_client()
        .expect("default (no-gateway) config builds a direct-Mainline Pkarr client");
    assert_eq!(backend_label(&client), "pkarr");
}

// ---------------------------------------------------------------------------
// A2 — DhtMode::Disabled resolution is honest not-found, never fabricated
// ---------------------------------------------------------------------------

/// A `DhtMode::Disabled` node resolves via the `DualLayerResolver` with the DHT
/// arm off (`DisabledDhtClient`) and the production relay querier holding no
/// bound transport. An unknown DID therefore resolves to an honest absent
/// outcome that names the relay layer unavailable — never a typed error on
/// resolve, never a fabricated or in-memory document (ADR-062 §Decision 1, A2,
/// as amended 2026-08-17; spec §3.10.4). Runs in a shipped (non-`testing`) build
/// to prove the property without any test-harness DHT.
#[cfg(not(feature = "testing"))]
#[tokio::test]
async fn disabled_node_resolution_returns_ok_none_for_unknown_did() {
    use std::sync::Arc;

    use scp_dht::DisabledDhtClient;
    use scp_identity::resolver::{DidResolver, LayerStatus, ResolutionOutcome};
    use scp_identity::{BootstrapRelays, DidCache, DualLayerResolver, RealMultiRelayQuerier};
    use scp_transport::native::TransportRelayQuerier;

    // A well-formed-but-unpublished did:dht:z identifier.
    let did = {
        use ed25519_dalek::SigningKey;
        let mut rng = rand::thread_rng();
        let vk = SigningKey::generate(&mut rng).verifying_key();
        format!("did:dht:z{}", zbase32::encode(vk.as_bytes()))
    };

    let relay_querier = Arc::new(TransportRelayQuerier::new());
    let bootstrap: Arc<dyn BootstrapRelays> = relay_querier.clone();
    let resolver = DualLayerResolver::new(
        Arc::new(RealMultiRelayQuerier::new(relay_querier)),
        Arc::new(DisabledDhtClient),
        Arc::new(DidCache::new()),
        bootstrap,
    );

    let resolution = resolver
        .resolve(&did)
        .await
        .expect("Disabled resolution must not error — the DHT arm answers with Ok(None)");
    match resolution {
        ResolutionOutcome::Absent { layers } => {
            assert_eq!(
                layers.dht,
                LayerStatus::Answered,
                "the Disabled DHT arm answers that it holds nothing"
            );
            assert_eq!(
                layers.relay,
                LayerStatus::Unavailable,
                "no relay transport is bound, which the relay layer reports honestly \
                 instead of claiming the relays hold no such DID"
            );
        }
        ResolutionOutcome::Found(doc) => panic!(
            "a Disabled node must never fabricate or serve an in-memory document, got {doc:?}"
        ),
    }
}

// ---------------------------------------------------------------------------
// Rotation reflected through the shared resolver (test-harness only)
// ---------------------------------------------------------------------------

/// A key rotation is reflected by a subsequent resolve through a resolver that
/// shares the identity's DHT client and cache: after `rotate_active_key`
/// republishes the document and the stale cache entry is invalidated, the
/// resolved `#active` key differs from the pre-rotation one. Exercises the
/// in-memory test double (compiled only under `testing`).
#[cfg(feature = "testing")]
#[tokio::test]
async fn rotation_is_reflected_by_resolve_through_shared_resolver() {
    use std::sync::Arc;

    use scp_identity::resolver::DidResolver;
    use scp_identity::{
        BootstrapRelays, DidDht, DidMethod, DualLayerResolver, RealMultiRelayQuerier,
    };
    use scp_platform::testing::{InMemoryKeyCustody, InMemoryPreRotationCustody};
    use scp_transport::native::TransportRelayQuerier;

    let custody = Arc::new(InMemoryKeyCustody::new());
    let pre_rotation = InMemoryPreRotationCustody::new();
    let did_dht = DidDht::with_in_memory_custody(Arc::clone(&custody));

    let (identity, document, _pre_rotation_handle) = did_dht
        .create(custody.as_ref(), &pre_rotation)
        .await
        .expect("create identity");
    did_dht
        .publish(&identity, &document)
        .await
        .expect("publish initial document");

    // The resolver shares the DID method's DHT client and cache — the same
    // wiring the node uses (build_shared_cache_key_resolver).
    let relay_querier = Arc::new(TransportRelayQuerier::new());
    let bootstrap: Arc<dyn BootstrapRelays> = relay_querier.clone();
    let resolver = DualLayerResolver::new(
        Arc::new(RealMultiRelayQuerier::new(relay_querier)),
        Arc::clone(did_dht.dht_client()),
        Arc::clone(did_dht.cache()),
        bootstrap,
    );

    let before = resolver
        .resolve(&identity.did)
        .await
        .expect("resolve must not error")
        .into_found()
        .expect("the published identity must resolve");
    let active_before = active_key_multibase(&before.document);

    // Rotate the active key: republishes a higher-sequence document.
    let (rotated_identity, _rotated_doc) = did_dht
        .rotate_active_key(&identity, &document, custody.as_ref())
        .await
        .expect("rotate active key");
    // Invalidate the stale cache entry so the resolver re-reads the DHT.
    did_dht.cache().remove(&identity.did).await;

    let after = resolver
        .resolve(&rotated_identity.did)
        .await
        .expect("resolve must not error")
        .into_found()
        .expect("the rotated identity must resolve");
    let active_after = active_key_multibase(&after.document);

    assert_ne!(
        active_before, active_after,
        "the resolved #active key must reflect the rotation"
    );
}

/// Extracts the `#active` verification method's public-key multibase from a
/// resolved document, for equality comparison across a rotation.
#[cfg(feature = "testing")]
fn active_key_multibase(document: &scp_did::DidDocument) -> String {
    document
        .verification_method
        .iter()
        .find(|vm| vm.id.ends_with("#active"))
        .map(|vm| vm.public_key_multibase.clone())
        .expect("a resolved document must carry an #active verification method")
}

// ---------------------------------------------------------------------------
// Live Mainline roundtrip (ignored — requires network)
// ---------------------------------------------------------------------------

/// End-to-end publish/resolve roundtrip against the live `BitTorrent` Mainline
/// DHT via the real Pkarr client. `#[ignore]`d because it needs network access
/// and a live DHT; run manually with `cargo test -- --ignored`.
#[test]
#[ignore = "requires live Mainline DHT network access"]
fn live_mainline_pkarr_roundtrip() {
    use ed25519_dalek::{Signer, SigningKey};
    use scp_dht::DhtClient;

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let client = ClientDhtConfig::default()
            .into_client()
            .expect("build real Pkarr client");

        let mut rng = rand::thread_rng();
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();
        let value = b"live-roundtrip-did-document";
        let seq = 1u64;
        let payload = scp_dht::bep44_signable(value, seq);
        let sig = sk.sign(&payload).to_bytes();

        client
            .publish(vk.as_bytes(), &sig, value, seq)
            .await
            .expect("publish to live Mainline DHT");

        let record = client
            .resolve(vk.as_bytes())
            .await
            .expect("resolve from live Mainline DHT")
            .expect("the just-published record must be resolvable");
        assert_eq!(record.value, value);
        assert_eq!(record.seq, seq);
    });
}
