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
/// arm off (`DisabledDhtClient`) and the interim `NoOpRelayQuerier` relay arm.
/// An unknown DID therefore resolves to honest `Ok(None)` — never a typed error
/// on resolve, never a fabricated or in-memory document (ADR-062 §Decision 1,
/// A2). Runs in a shipped (non-`testing`) build to prove the property without
/// any test-harness DHT.
#[cfg(not(feature = "testing"))]
#[tokio::test]
async fn disabled_node_resolution_returns_ok_none_for_unknown_did() {
    use std::sync::Arc;

    use scp_dht::DisabledDhtClient;
    use scp_identity::resolver::{DidResolver, NoOpRelayQuerier};
    use scp_identity::{DidCache, DualLayerResolver};

    // A well-formed-but-unpublished did:dht:z identifier.
    let did = {
        use ed25519_dalek::SigningKey;
        let mut rng = rand::thread_rng();
        let vk = SigningKey::generate(&mut rng).verifying_key();
        format!("did:dht:z{}", zbase32::encode(vk.as_bytes()))
    };

    let resolver = DualLayerResolver::new(
        Arc::new(NoOpRelayQuerier),
        Arc::new(DisabledDhtClient),
        Arc::new(DidCache::new()),
        Vec::new(),
    );

    let resolution = resolver
        .resolve(&did)
        .await
        .expect("Disabled resolution must not error — the DHT arm contributes Ok(None)");
    assert!(
        resolution.is_none(),
        "a Disabled node must resolve an unknown DID to honest not-found Ok(None), \
         never a fabricated or in-memory document"
    );
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

    use scp_identity::resolver::{DidResolver, NoOpRelayQuerier};
    use scp_identity::{DidDht, DidMethod, DualLayerResolver};
    use scp_platform::testing::{InMemoryKeyCustody, InMemoryPreRotationCustody};

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
    let resolver = DualLayerResolver::new(
        Arc::new(NoOpRelayQuerier),
        did_dht.dht_client(),
        Arc::clone(did_dht.cache()),
        Vec::new(),
    );

    let before = resolver
        .resolve(&identity.did)
        .await
        .expect("resolve must not error")
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

// ---------------------------------------------------------------------------
// The dev-dependency edge that compiles the in-memory double above
// ---------------------------------------------------------------------------

/// `rotation_is_reflected_by_resolve_through_shared_resolver` calls
/// `DidDht::with_in_memory_custody`, which scp-identity compiles only under its
/// own `testing` feature (`crates/scp-identity/src/dht.rs`). This crate's `testing`
/// feature does not forward `scp-identity/testing`, on purpose: it reaches every
/// bridge test build, and the forward would compile scp-identity's in-memory
/// pre-rotation mint arm there. The edge that carries the feature is this crate's
/// own `[dev-dependencies]` entry for `scp-identity`, which only this crate's test
/// build activates.
///
/// A `cargo nextest run --workspace` also builds `scp-testing`'s dev-dependencies,
/// whose self-edge enables `scp-testing/helpers` and through it
/// `scp-identity/testing`, and cargo unifies that feature into this test binary.
/// So the test above compiles in every workspace lane whether or not this crate's
/// own entry exists, and only
/// `cargo nextest run -p scp-ffi-common --features testing --test dht_capability_injection`
/// exposes its loss. This test reads the manifest instead, so the loss turns red in
/// the workspace lanes too, and it runs under the default feature set as well.
#[test]
fn own_dev_dependency_on_scp_identity_enables_testing() {
    let manifest = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
    let doc: toml_edit::DocumentMut = manifest.parse().expect("scp-ffi-common Cargo.toml parses");
    let identity_manifest = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scp-identity/Cargo.toml"
    ));
    let identity: toml_edit::DocumentMut = identity_manifest
        .parse()
        .expect("scp-identity Cargo.toml parses");
    let activating = identity_features_implying_testing(&identity);

    let dev_features = doc["dev-dependencies"]["scp-identity"]["features"]
        .as_array()
        .expect("`[dev-dependencies] scp-identity` carries a `features` array");
    assert!(
        dev_features
            .iter()
            .filter_map(|feature| feature.as_str())
            .any(|feature| activating.contains(feature)),
        "`[dev-dependencies] scp-identity` must enable `testing`: without it, \
         `DidDht::with_in_memory_custody` does not exist on a standalone \
         `-p scp-ffi-common --features testing` build and the rotation test above \
         fails to compile"
    );

    let escaping = non_dev_activations_of_identity_testing(&doc, &activating);
    assert!(
        escaping.is_empty(),
        "only this manifest's `[dev-dependencies]` entry may activate \
         `scp-identity/testing`, because cargo builds a dev-dependency for this \
         crate's own test targets alone. These edges activate it from elsewhere and \
         reach every bridge test build, which compiles scp-identity's in-memory \
         pre-rotation mint arm there: {escaping:?}"
    );
}

// --- BEGIN shared manifest reader (byte-identical twin — see
// check_identity_manifest_readers_match in scripts/tests/ci-gate/ci_gate_selftest.py) ---
//
// CRITERION this reader enforces: in the manifest it reads, a `[dev-dependencies]`
// entry is the ONLY edge permitted to activate `scp-identity/testing`. Cargo builds
// a dev-dependency for that crate's own test targets alone, so that edge reaches no
// consumer. Every other spelling cargo accepts reaches a consumer's build, so the
// reader reports each one it finds.
//
// Indicators, not the criterion — the spellings a literal comparison against the
// string "scp-identity/testing" over the `testing` array walks past, which is what
// an earlier revision of these two tests compared:
//
//   - `"scp-identity?/testing"`, the weak spelling, which cargo accepts wherever the
//     dependency is optional, as it is in crates/scp-ffi/common/Cargo.toml;
//   - either spelling parked in a second feature that `testing` then names, which is
//     why this reads every feature the manifest declares;
//   - either spelling written against a rename, because `identity = { package =
//     "scp-identity" }` makes `"identity/testing"` the same activation;
//   - either spelling naming a different scp-identity feature that itself turns
//     `testing` on, which is why `identity_features_implying_testing` reads
//     scp-identity's own feature table instead of matching the word `testing`;
//   - a `[dependencies]` or `[build-dependencies]` entry on scp-identity whose
//     `features` list names `testing`, which reaches strictly more builds than a
//     feature forward does;
//   - any of those under `[target.<cfg>]`.
//
// This block is duplicated verbatim in crates/scp-runtime/tests/identity_config_cross_path.rs
// and crates/scp-ffi/common/tests/dht_capability_injection.rs. Each crate asserts the
// property about its own manifest and neither dev-depends on the other, so there is no
// crate in which to put one copy; check_identity_manifest_readers_match compares the two
// blocks byte for byte, so a fix applied to one and not the other fails the gate
// self-test.

use std::collections::BTreeSet;

/// Returns every scp-identity feature whose activation turns `testing` on,
/// `testing` itself included, by reading scp-identity's own `[features]` table.
fn identity_features_implying_testing(identity: &toml_edit::DocumentMut) -> BTreeSet<String> {
    let table = identity
        .get("features")
        .and_then(|item| item.as_table_like())
        .expect("scp-identity Cargo.toml declares a `[features]` table");
    let mut implying: BTreeSet<String> = BTreeSet::from(["testing".to_string()]);
    loop {
        let mut grew = false;
        for (feature, implies) in table.iter() {
            if implying.contains(feature) {
                continue;
            }
            let reaches = implies
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|entry| entry.as_str())
                .any(|entry| implying.contains(entry));
            if reaches {
                implying.insert(feature.to_string());
                grew = true;
            }
        }
        if !grew {
            return implying;
        }
    }
}

/// Returns every dependency table `manifest` declares, each paired with the
/// heading a reader would find it under, `[target.<cfg>]` tables included.
fn dependency_sections<'a>(
    manifest: &'a toml_edit::DocumentMut,
) -> Vec<(String, &'a dyn toml_edit::TableLike)> {
    const SECTIONS: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];
    let mut found: Vec<(String, &'a dyn toml_edit::TableLike)> = Vec::new();
    for section in SECTIONS {
        if let Some(table) = manifest.get(section).and_then(|item| item.as_table_like()) {
            found.push((format!("[{section}]"), table));
        }
    }
    let targets: Vec<_> = manifest
        .get("target")
        .and_then(|item| item.as_table_like())
        .map(|table| table.iter().collect())
        .unwrap_or_default();
    for (cfg, entry) in targets {
        for section in SECTIONS {
            if let Some(table) = entry
                .as_table_like()
                .and_then(|target| target.get(section))
                .and_then(|item| item.as_table_like())
            {
                found.push((format!("[target.{cfg}.{section}]"), table));
            }
        }
    }
    found
}

/// Returns every name a `[features]` value in `manifest` can use to address
/// scp-identity: each dependency-table key that names it, and each key that
/// renames it through a `package` field.
fn scp_identity_aliases(manifest: &toml_edit::DocumentMut) -> BTreeSet<String> {
    let mut aliases = BTreeSet::new();
    for (_, table) in dependency_sections(manifest) {
        for (key, spec) in table.iter() {
            let renamed = spec
                .as_table_like()
                .and_then(|entry| entry.get("package"))
                .and_then(|item| item.as_str());
            if renamed.unwrap_or(key) == "scp-identity" {
                aliases.insert(key.to_string());
            }
        }
    }
    aliases
}

/// Returns one sentence per edge in `manifest` that activates a scp-identity
/// feature in `activating` from anywhere other than a `[dev-dependencies]` table.
fn non_dev_activations_of_identity_testing(
    manifest: &toml_edit::DocumentMut,
    activating: &BTreeSet<String>,
) -> Vec<String> {
    let aliases = scp_identity_aliases(manifest);
    let mut found = Vec::new();
    for (section, table) in dependency_sections(manifest) {
        if section.ends_with("dev-dependencies]") {
            continue;
        }
        for (key, spec) in table.iter() {
            if !aliases.contains(key) {
                continue;
            }
            let features = spec
                .as_table_like()
                .and_then(|entry| entry.get("features"))
                .and_then(|item| item.as_array());
            for feature in features
                .into_iter()
                .flatten()
                .filter_map(|value| value.as_str())
            {
                if activating.contains(feature) {
                    found.push(format!(
                        "{section} `{key}` names `{feature}` in its `features` list"
                    ));
                }
            }
        }
    }
    let features: Vec<_> = manifest
        .get("features")
        .and_then(|item| item.as_table_like())
        .map(|table| table.iter().collect())
        .unwrap_or_default();
    for (feature, implies) in features {
        for entry in implies
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|value| value.as_str())
        {
            let Some((dependency, activated)) = entry.split_once('/') else {
                continue;
            };
            let dependency = dependency.strip_suffix('?').unwrap_or(dependency);
            if aliases.contains(dependency) && activating.contains(activated) {
                found.push(format!(
                    "`[features] {feature}` names \"{entry}\", which activates \
                     `scp-identity/testing`"
                ));
            }
        }
    }
    found
}

// --- END shared manifest reader ---
