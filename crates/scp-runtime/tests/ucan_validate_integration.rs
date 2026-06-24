//! Integration tests for UCAN validation pipeline.
//!
//! These tests exercise the full 11-step UCAN validation pipeline with real
//! minted and signed tokens. They require async operations (key generation,
//! UCAN minting) from scp-runtime, which is why they live here rather than
//! in scp-protocol.
//!
//! Originally located in `scp-protocol::crypto::ucan::validate` behind a
//! `_runtime_tests` feature gate. Moved here as proper integration tests
//! where scp-runtime is available.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::{KeyCustody, KeyType};
use scp_primitives::Clock;

use scp_protocol::crypto::ucan::capability::CapabilityUri;
use scp_protocol::crypto::ucan::nonce;
use scp_protocol::crypto::ucan::revoke::compute_revocation_cid;
use scp_protocol::crypto::ucan::validate::{
    CapabilityValidation, DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, InMemoryDidResolver,
    InMemoryNonceTracker, InMemoryProofResolver, InMemoryRevocationChecker, NonceTracker,
    ProofResolver, ValidationContext, evaluate_ucan, parse_ucan, validate_ucan,
};
use scp_protocol::crypto::ucan::{Attenuation, UcanError, UcanHeader, UcanPayload, UcanToken};

use scp_runtime::crypto::ucan::mint::{DelegateParams, MintParams, compute_cid, mint_ucan};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Create an `InMemoryKeyCustody`, generate an Ed25519 key, return the
/// custody, handle, DID string, and raw public key bytes.
async fn setup_identity() -> (
    InMemoryKeyCustody,
    scp_platform::traits::KeyHandle,
    String,
    [u8; 32],
) {
    let custody = InMemoryKeyCustody::new();
    let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let pubkey = custody.public_key(&handle).await.unwrap();
    let pk_bytes: [u8; 32] = pubkey.as_bytes().try_into().unwrap();
    let did = format!("did:dht:z{}", zbase32::encode(pubkey.as_bytes()));
    (custody, handle, did, pk_bytes)
}

/// Production system clock for tests that validate against real time.
static SYSTEM_CLOCK: scp_primitives::SystemClock = scp_primitives::SystemClock;

/// Build a [`ValidationContext`] with in-memory implementations.
fn build_context<'a, S: std::hash::BuildHasher>(
    did_resolver: &'a InMemoryDidResolver,
    nonce_tracker: &'a mut InMemoryNonceTracker,
    revocation_checker: &'a InMemoryRevocationChecker,
    proof_resolver: &'a InMemoryProofResolver,
    ceiling: &'a HashSet<String, S>,
    context_creator_did: &'a str,
    presenting_agent_did: &'a str,
) -> ValidationContext<
    'a,
    InMemoryDidResolver,
    InMemoryNonceTracker,
    InMemoryRevocationChecker,
    InMemoryProofResolver,
    S,
> {
    ValidationContext {
        did_resolver,
        nonce_tracker,
        revocation_checker,
        proof_resolver,
        ceiling,
        context_creator_did,
        presenting_agent_did,
        clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
        clock: &SYSTEM_CLOCK,
    }
}

fn default_ceiling() -> HashSet<String> {
    [
        "messages:read".to_owned(),
        "messages:write".to_owned(),
        "tool_invoke:assistant".to_owned(),
        "member:invite".to_owned(),
        "role:assign".to_owned(),
        "context:close".to_owned(),
    ]
    .into_iter()
    .collect()
}

// ---------------------------------------------------------------------------
// Step 1: Parse
// ---------------------------------------------------------------------------

#[test]
fn parse_ucan_rejects_too_few_segments() {
    let result = parse_ucan("only.two");
    assert!(matches!(result, Err(UcanError::MalformedToken(_))));
}

#[test]
fn parse_ucan_rejects_too_many_segments() {
    let result = parse_ucan("a.b.c.d");
    assert!(matches!(result, Err(UcanError::MalformedToken(_))));
}

#[test]
fn parse_ucan_rejects_invalid_base64() {
    let result = parse_ucan("!!!.@@@.###");
    assert!(matches!(result, Err(UcanError::MalformedToken(_))));
}

// ---------------------------------------------------------------------------
// Step 2: Signature verification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn validate_ucan_accepts_valid_token() {
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
    let caps = vec!["messages:write".to_owned()];

    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: "did:dht:z6MkMember",
        context_id: "ctx-test",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: None,
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let ceiling = default_ceiling();

    let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        "did:dht:z6MkMember",
    );

    let result = validate_ucan(&token, &required_cap, &mut ctx);
    assert!(result.is_ok(), "valid token must pass: {result:?}");
}

#[tokio::test]
async fn validate_ucan_rejects_tampered_signature() {
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
    let caps = vec!["messages:write".to_owned()];

    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: "did:dht:z6MkMember",
        context_id: "ctx-test",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: None,
    };

    let mut token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    // Tamper with the signature.
    token.signature[0] ^= 0xFF;
    // Also update the encoded string with the tampered sig.
    let parts: Vec<&str> = token.encoded.split('.').collect();
    let tampered_sig_b64 = URL_SAFE_NO_PAD.encode(&token.signature);
    token.encoded = format!("{}.{}.{}", parts[0], parts[1], tampered_sig_b64);

    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let ceiling = default_ceiling();

    let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        "did:dht:z6MkMember",
    );

    let result = validate_ucan(&token, &required_cap, &mut ctx);
    assert!(
        matches!(result, Err(UcanError::SignatureInvalid)),
        "tampered signature must be rejected: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Step 3: Delegation chain verification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn validate_ucan_accepts_delegated_token() {
    // Creator (root issuer)
    let (custody_creator, key_creator, creator_did, pk_creator) = setup_identity().await;
    // Delegator (receives from creator, delegates to agent)
    let (custody_delegator, key_delegator, delegator_did, pk_delegator) = setup_identity().await;
    // Agent (final audience)
    let (_custody_agent, _key_agent, agent_did, _pk_agent) = setup_identity().await;

    let caps = vec!["messages:write".to_owned(), "messages:read".to_owned()];

    // Creator mints root token to delegator.
    let root_token = mint_ucan(
        &MintParams {
            issuer_did: &creator_did,
            issuer_key: &key_creator,
            audience_did: &delegator_did,
            context_id: "ctx-chain",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        },
        &custody_creator,
        &scp_primitives::SystemClock,
    )
    .await
    .unwrap();

    let root_cid = compute_cid(&root_token);

    // Delegator delegates to agent (narrowing to just write).
    let delegated_token = scp_runtime::crypto::ucan::mint::delegate_ucan(
        &DelegateParams {
            parent_token: &root_token,
            delegator_did: &delegator_did,
            delegator_key: &key_delegator,
            delegatee_did: &agent_did,
            attenuated_capabilities: &[Attenuation {
                with: "scp:ctx:ctx-chain/messages:write".to_owned(),
                can: "write".to_owned(),
            }],
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        },
        &custody_delegator,
        &scp_primitives::SystemClock,
    )
    .await
    .unwrap();

    // Build resolver with both keys.
    let resolver = InMemoryDidResolver {
        keys: [
            (creator_did.clone(), pk_creator),
            (delegator_did.clone(), pk_delegator),
        ]
        .into_iter()
        .collect(),
        kid_keys: std::collections::HashMap::new(),
    };

    let proof_resolver = InMemoryProofResolver {
        proofs: std::collections::HashMap::from([(root_cid, root_token)]),
    };

    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let ceiling = default_ceiling();
    let required_cap = CapabilityUri::new("ctx-chain", "messages", "write");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &creator_did,
        &agent_did,
    );

    let result = validate_ucan(&delegated_token, &required_cap, &mut ctx);
    assert!(
        result.is_ok(),
        "delegated token must pass validation: {result:?}"
    );
}

#[tokio::test]
async fn validate_ucan_rejects_broken_chain_aud_iss_mismatch() {
    let (custody_creator, key_creator, creator_did, pk_creator) = setup_identity().await;
    let (_custody_a, _key_a, did_a, _pk_a) = setup_identity().await;
    let (custody_b, key_b, did_b, pk_b) = setup_identity().await;
    let (_custody_agent, _key_agent, agent_did, _pk_agent) = setup_identity().await;

    let caps = vec!["messages:write".to_owned()];

    // Root token: creator -> A.
    let root_token = mint_ucan(
        &MintParams {
            issuer_did: &creator_did,
            issuer_key: &key_creator,
            audience_did: &did_a,
            context_id: "ctx-chain",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        },
        &custody_creator,
        &scp_primitives::SystemClock,
    )
    .await
    .unwrap();

    let root_cid = compute_cid(&root_token);

    // B tries to delegate from root_token, but root_token.aud = A, not B.
    // Manually construct a bad token by minting with proofs.
    let bad_delegated = mint_ucan(
        &MintParams {
            issuer_did: &did_b,
            issuer_key: &key_b,
            audience_did: &agent_did,
            context_id: "ctx-chain",
            capabilities: &caps,
            lifetime_secs: 1800,
            not_before: None,
            proofs: vec![root_cid.clone()],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        },
        &custody_b,
        &scp_primitives::SystemClock,
    )
    .await
    .unwrap();

    let resolver = InMemoryDidResolver {
        keys: [(creator_did.clone(), pk_creator), (did_b.clone(), pk_b)]
            .into_iter()
            .collect(),
        kid_keys: std::collections::HashMap::new(),
    };

    let proof_resolver = InMemoryProofResolver {
        proofs: std::collections::HashMap::from([(root_cid, root_token)]),
    };

    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let ceiling = default_ceiling();
    let required_cap = CapabilityUri::new("ctx-chain", "messages", "write");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &creator_did,
        &agent_did,
    );

    let result = validate_ucan(&bad_delegated, &required_cap, &mut ctx);
    assert!(
        matches!(result, Err(UcanError::DelegationChainBroken(_))),
        "broken chain (aud/iss mismatch) must be rejected: {result:?}"
    );
}

#[tokio::test]
async fn validate_ucan_rejects_unresolvable_proof() {
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
    let caps = vec!["messages:write".to_owned()];

    // Mint a token with a non-existent proof CID.
    let token = mint_ucan(
        &MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-test",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec!["bafyrei-nonexistent".to_owned()],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        },
        &custody,
        &scp_primitives::SystemClock,
    )
    .await
    .unwrap();

    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };

    let proof_resolver = InMemoryProofResolver::new();

    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let ceiling = default_ceiling();
    let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        "did:dht:z6MkMember",
    );

    let result = validate_ucan(&token, &required_cap, &mut ctx);
    assert!(
        matches!(result, Err(UcanError::DelegationChainBroken(_))),
        "unresolvable proof CID must be rejected: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Step 4: Root issuer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn validate_ucan_rejects_wrong_issuer() {
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
    let caps = vec!["messages:write".to_owned()];

    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: "did:dht:z6MkMember",
        context_id: "ctx-test",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: None,
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let ceiling = default_ceiling();

    let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

    // Use a different context creator DID.
    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        "did:dht:z6MkWrongCreator",
        "did:dht:z6MkMember",
    );

    let result = validate_ucan(&token, &required_cap, &mut ctx);
    assert!(
        matches!(result, Err(UcanError::InvalidIssuer { .. })),
        "wrong issuer must be rejected: {result:?}"
    );
}

#[tokio::test]
async fn validate_ucan_rejects_wrong_root_issuer_in_chain() {
    // Non-creator mints the root. The context creator is different.
    let (custody_non_creator, key_non_creator, non_creator_did, pk_non_creator) =
        setup_identity().await;
    let (custody_delegator, key_delegator, delegator_did, pk_delegator) = setup_identity().await;
    let (_custody_agent, _key_agent, agent_did, _pk_agent) = setup_identity().await;

    let caps = vec!["messages:write".to_owned()];

    // Root token: non_creator -> delegator.
    let root_token = mint_ucan(
        &MintParams {
            issuer_did: &non_creator_did,
            issuer_key: &key_non_creator,
            audience_did: &delegator_did,
            context_id: "ctx-chain",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        },
        &custody_non_creator,
        &scp_primitives::SystemClock,
    )
    .await
    .unwrap();

    let root_cid = compute_cid(&root_token);

    // Delegator -> agent.
    let delegated_token = scp_runtime::crypto::ucan::mint::delegate_ucan(
        &DelegateParams {
            parent_token: &root_token,
            delegator_did: &delegator_did,
            delegator_key: &key_delegator,
            delegatee_did: &agent_did,
            attenuated_capabilities: &[Attenuation {
                with: "scp:ctx:ctx-chain/messages:write".to_owned(),
                can: "write".to_owned(),
            }],
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        },
        &custody_delegator,
        &scp_primitives::SystemClock,
    )
    .await
    .unwrap();

    let resolver = InMemoryDidResolver {
        keys: [
            (non_creator_did.clone(), pk_non_creator),
            (delegator_did.clone(), pk_delegator),
        ]
        .into_iter()
        .collect(),
        kid_keys: std::collections::HashMap::new(),
    };

    let proof_resolver = InMemoryProofResolver {
        proofs: std::collections::HashMap::from([(root_cid, root_token)]),
    };

    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let ceiling = default_ceiling();
    let required_cap = CapabilityUri::new("ctx-chain", "messages", "write");

    // The context creator is "did:dht:z6MkRealCreator" -- not non_creator.
    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        "did:dht:z6MkRealCreator",
        &agent_did,
    );

    let result = validate_ucan(&delegated_token, &required_cap, &mut ctx);
    assert!(
        matches!(result, Err(UcanError::InvalidIssuer { .. })),
        "wrong root issuer in chain must be rejected: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Step 5: Audience
// ---------------------------------------------------------------------------

#[tokio::test]
async fn validate_ucan_rejects_audience_mismatch() {
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
    let caps = vec!["messages:write".to_owned()];

    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: "did:dht:z6MkMember",
        context_id: "ctx-test",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: None,
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let ceiling = default_ceiling();

    let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

    // Use a different presenting agent DID.
    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        "did:dht:z6MkWrongAgent",
    );

    let result = validate_ucan(&token, &required_cap, &mut ctx);
    assert!(
        matches!(result, Err(UcanError::AudienceMismatch { .. })),
        "audience mismatch must be rejected: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Step 6: Capability match
// ---------------------------------------------------------------------------

#[tokio::test]
async fn validate_ucan_rejects_missing_capability() {
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
    let caps = vec!["messages:read".to_owned()];

    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: "did:dht:z6MkMember",
        context_id: "ctx-test",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: None,
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let ceiling = default_ceiling();

    // Request a capability the token does NOT grant.
    let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        "did:dht:z6MkMember",
    );

    let result = validate_ucan(&token, &required_cap, &mut ctx);
    assert!(
        matches!(result, Err(UcanError::CapabilityNotGranted(_))),
        "missing capability must be rejected: {result:?}"
    );
}

#[tokio::test]
async fn validate_ucan_accepts_wildcard_capability_grant() {
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;

    // Mint with wildcard context_id "*" to produce scp:ctx:*/messages:write.
    let caps = vec!["messages:write".to_owned()];
    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: "did:dht:z6MkMember",
        context_id: "*",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: None,
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    // Verify the attenuation uses wildcard context.
    assert_eq!(token.payload.att[0].with, "scp:ctx:*/messages:write");

    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let ceiling = default_ceiling();

    // Request specific context capability -- wildcard should match.
    let required_cap = CapabilityUri::new("ctx-specific", "messages", "write");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        "did:dht:z6MkMember",
    );

    let result = validate_ucan(&token, &required_cap, &mut ctx);
    assert!(
        result.is_ok(),
        "wildcard capability must match specific context: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Step 7: Attenuation verification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn validate_ucan_rejects_widened_capabilities_in_delegation() {
    // Creator grants read-only. Delegator tries to delegate write.
    let (custody_creator, key_creator, creator_did, pk_creator) = setup_identity().await;
    let (custody_delegator, key_delegator, delegator_did, pk_delegator) = setup_identity().await;
    let (_custody_agent, _key_agent, agent_did, _pk_agent) = setup_identity().await;

    let caps = vec!["messages:read".to_owned()]; // Only read.

    // Root token: creator -> delegator (read only).
    let root_token = mint_ucan(
        &MintParams {
            issuer_did: &creator_did,
            issuer_key: &key_creator,
            audience_did: &delegator_did,
            context_id: "ctx-att",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        },
        &custody_creator,
        &scp_primitives::SystemClock,
    )
    .await
    .unwrap();

    let root_cid = compute_cid(&root_token);

    // Manually construct a delegated token that WIDENS to write.
    // (delegate_ucan would reject this, so we mint directly with proofs.)
    let bad_token = mint_ucan(
        &MintParams {
            issuer_did: &delegator_did,
            issuer_key: &key_delegator,
            audience_did: &agent_did,
            context_id: "ctx-att",
            capabilities: &["messages:write".to_owned()], // Widened!
            lifetime_secs: 1800,
            not_before: None,
            proofs: vec![root_cid.clone()],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        },
        &custody_delegator,
        &scp_primitives::SystemClock,
    )
    .await
    .unwrap();

    let resolver = InMemoryDidResolver {
        keys: [
            (creator_did.clone(), pk_creator),
            (delegator_did.clone(), pk_delegator),
        ]
        .into_iter()
        .collect(),
        kid_keys: std::collections::HashMap::new(),
    };

    let proof_resolver = InMemoryProofResolver {
        proofs: std::collections::HashMap::from([(root_cid, root_token)]),
    };

    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let ceiling = default_ceiling();
    let required_cap = CapabilityUri::new("ctx-att", "messages", "write");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &creator_did,
        &agent_did,
    );

    let result = validate_ucan(&bad_token, &required_cap, &mut ctx);
    assert!(
        matches!(result, Err(UcanError::AttenuationViolation(_))),
        "widened delegation must be rejected: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Step 8: Ceiling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn validate_ucan_rejects_capability_outside_ceiling() {
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
    let caps = vec!["context:close".to_owned()];

    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: "did:dht:z6MkMember",
        context_id: "ctx-test",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: None,
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();

    // Ceiling does NOT include context:close.
    let ceiling: HashSet<String> = ["messages:read".to_owned(), "messages:write".to_owned()]
        .into_iter()
        .collect();

    let required_cap = CapabilityUri::new("ctx-test", "context", "close");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        "did:dht:z6MkMember",
    );

    let result = validate_ucan(&token, &required_cap, &mut ctx);
    assert!(
        matches!(result, Err(UcanError::CapabilityOutsideCeiling(_))),
        "capability outside ceiling must be rejected: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Step 9: Nonce
// ---------------------------------------------------------------------------

#[tokio::test]
async fn validate_ucan_rejects_nonce_replay() {
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
    let caps = vec!["messages:write".to_owned()];

    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: "did:dht:z6MkMember",
        context_id: "ctx-nonce",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: None,
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let ceiling = default_ceiling();
    let required_cap = CapabilityUri::new("ctx-nonce", "messages", "write");

    // First validation should succeed.
    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        "did:dht:z6MkMember",
    );
    let result = validate_ucan(&token, &required_cap, &mut ctx);
    assert!(result.is_ok(), "first validation must pass: {result:?}");

    // Second validation with same token should fail (nonce replay).
    let mut ctx2 = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        "did:dht:z6MkMember",
    );
    let result2 = validate_ucan(&token, &required_cap, &mut ctx2);
    assert!(
        matches!(result2, Err(UcanError::NonceReused(_))),
        "nonce replay must be rejected: {result2:?}"
    );
}

// ---------------------------------------------------------------------------
// Step 10: Revocation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn validate_ucan_rejects_revoked_token() {
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
    let caps = vec!["messages:write".to_owned()];

    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: "did:dht:z6MkMember",
        context_id: "ctx-test",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: None,
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();

    // Add the token's revocation CID (SHA-256 of raw encoded JWT) to the
    // revocation list.
    let mut revocation_checker = InMemoryRevocationChecker::new();
    revocation_checker
        .revoked
        .insert(compute_revocation_cid(&token.encoded));

    let proof_resolver = InMemoryProofResolver::new();
    let ceiling = default_ceiling();
    let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        "did:dht:z6MkMember",
    );

    let result = validate_ucan(&token, &required_cap, &mut ctx);
    assert!(
        matches!(result, Err(UcanError::TokenRevoked(_))),
        "revoked token must be rejected: {result:?}"
    );
}

#[tokio::test]
async fn validate_ucan_revocation_uses_content_hash_cid() {
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
    let caps = vec!["messages:write".to_owned()];

    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: "did:dht:z6MkMember",
        context_id: "ctx-cid",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: None,
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();
    let revocation_cid = compute_revocation_cid(&token.encoded);

    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();

    // Revoke using content-hash CID (SHA-256 of raw encoded JWT).
    let mut revocation_checker = InMemoryRevocationChecker::new();
    revocation_checker.revoked.insert(revocation_cid.clone());

    let proof_resolver = InMemoryProofResolver::new();
    let ceiling = default_ceiling();
    let required_cap = CapabilityUri::new("ctx-cid", "messages", "write");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        "did:dht:z6MkMember",
    );

    let result = validate_ucan(&token, &required_cap, &mut ctx);
    assert!(
        matches!(result, Err(UcanError::TokenRevoked(ref cid)) if cid == &revocation_cid),
        "token revoked by content-hash CID must be rejected: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Step 11: Expiry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn validate_ucan_rejects_expired_token() {
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
    let caps = vec!["messages:write".to_owned()];

    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: "did:dht:z6MkMember",
        context_id: "ctx-test",
        capabilities: &caps,
        lifetime_secs: 1, // Very short lifetime.
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: None,
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    // Wait for the token to expire.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let ceiling = default_ceiling();

    let required_cap = CapabilityUri::new("ctx-test", "messages", "write");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        "did:dht:z6MkMember",
    );
    // Use zero tolerance so the 2-second expiry is detected.
    ctx.clock_skew_tolerance_secs = 0;

    let result = validate_ucan(&token, &required_cap, &mut ctx);
    assert!(
        matches!(result, Err(UcanError::TokenExpired)),
        "expired token must be rejected: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Nonce tracker tests
// ---------------------------------------------------------------------------

#[test]
fn nonce_tracker_rejects_reused_nonce() {
    let mut tracker = InMemoryNonceTracker::new();
    let now_millis = scp_primitives::SystemClock.now_millis();

    let nonce = format!("{now_millis}-aabbccdd11223344aabbccdd11223344");
    let expiry = scp_primitives::SystemClock.now_secs() + 3600;

    assert!(tracker.check_and_record(&nonce, expiry).is_ok());
    let result = tracker.check_and_record(&nonce, expiry);
    assert!(
        matches!(result, Err(UcanError::NonceReused(_))),
        "reused nonce must be rejected: {result:?}"
    );
}

#[test]
fn nonce_tracker_rejects_malformed_nonce() {
    let mut tracker = InMemoryNonceTracker::new();
    let expiry = scp_primitives::SystemClock.now_secs() + 3600;

    // No separator.
    let result = tracker.check_and_record("nohyphen", expiry);
    assert!(matches!(result, Err(UcanError::NonceFormatInvalid(_))));

    // Non-numeric timestamp.
    let result = tracker.check_and_record("notanumber-aabbccdd11223344aabbccdd11223344", expiry);
    assert!(matches!(result, Err(UcanError::NonceFormatInvalid(_))));

    // Hex suffix too short.
    let now_millis = scp_primitives::SystemClock.now_millis();
    let result = tracker.check_and_record(&format!("{now_millis}-aabb"), expiry);
    assert!(matches!(result, Err(UcanError::NonceFormatInvalid(_))));
}

// ---------------------------------------------------------------------------
// Parse + validate roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn parse_and_validate_roundtrip() {
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
    let caps = vec!["messages:write".to_owned()];

    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: "did:dht:z6MkMember",
        context_id: "ctx-roundtrip",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: None,
    };

    let minted = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    // Parse the encoded token back.
    let parsed = parse_ucan(&minted.encoded).unwrap();
    assert_eq!(parsed.header, minted.header);
    assert_eq!(parsed.payload, minted.payload);
    assert_eq!(parsed.signature, minted.signature);

    // Validate the parsed token.
    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let ceiling = default_ceiling();

    let required_cap = CapabilityUri::new("ctx-roundtrip", "messages", "write");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        "did:dht:z6MkMember",
    );

    assert!(validate_ucan(&parsed, &required_cap, &mut ctx).is_ok());
}

// ---------------------------------------------------------------------------
// Full pipeline: mint -> delegate -> parse -> validate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_pipeline_mint_delegate_parse_validate() {
    let (custody_creator, key_creator, creator_did, pk_creator) = setup_identity().await;
    let (custody_delegator, key_delegator, delegator_did, pk_delegator) = setup_identity().await;

    let caps = vec![
        "messages:write".to_owned(),
        "messages:read".to_owned(),
        "tool_invoke:assistant".to_owned(),
    ];

    // Creator mints root.
    let root_token = mint_ucan(
        &MintParams {
            issuer_did: &creator_did,
            issuer_key: &key_creator,
            audience_did: &delegator_did,
            context_id: "ctx-full",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        },
        &custody_creator,
        &scp_primitives::SystemClock,
    )
    .await
    .unwrap();

    let root_cid = compute_cid(&root_token);

    // Delegator narrows to read + write.
    let delegated = scp_runtime::crypto::ucan::mint::delegate_ucan(
        &DelegateParams {
            parent_token: &root_token,
            delegator_did: &delegator_did,
            delegator_key: &key_delegator,
            delegatee_did: "did:dht:z6MkAgent",
            attenuated_capabilities: &[
                Attenuation {
                    with: "scp:ctx:ctx-full/messages:write".to_owned(),
                    can: "write".to_owned(),
                },
                Attenuation {
                    with: "scp:ctx:ctx-full/messages:read".to_owned(),
                    can: "read".to_owned(),
                },
            ],
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        },
        &custody_delegator,
        &scp_primitives::SystemClock,
    )
    .await
    .unwrap();

    // Parse from encoded form.
    let parsed = parse_ucan(&delegated.encoded).unwrap();
    assert_eq!(parsed.payload.iss, delegator_did);
    assert_eq!(parsed.payload.aud, "did:dht:z6MkAgent");
    assert_eq!(parsed.payload.att.len(), 2);

    // Validate.
    let resolver = InMemoryDidResolver {
        keys: [
            (creator_did.clone(), pk_creator),
            (delegator_did.clone(), pk_delegator),
        ]
        .into_iter()
        .collect(),
        kid_keys: std::collections::HashMap::new(),
    };

    let proof_resolver = InMemoryProofResolver {
        proofs: std::collections::HashMap::from([(root_cid, root_token)]),
    };

    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let ceiling = default_ceiling();
    let required_cap = CapabilityUri::new("ctx-full", "messages", "write");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &creator_did,
        "did:dht:z6MkAgent",
    );

    let result = validate_ucan(&parsed, &required_cap, &mut ctx);
    assert!(
        result.is_ok(),
        "full pipeline (mint -> delegate -> parse -> validate) must pass: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// InMemoryProofResolver tests
// ---------------------------------------------------------------------------

#[test]
fn in_memory_proof_resolver_rejects_missing_cid() {
    let resolver = InMemoryProofResolver::new();
    let result = resolver.resolve_proof("bafyrei-missing");
    assert!(matches!(result, Err(UcanError::DelegationChainBroken(_))));
}

#[test]
fn in_memory_proof_resolver_returns_stored_token() {
    let token = UcanToken {
        header: UcanHeader::new(),
        payload: UcanPayload {
            iss: "did:dht:z6MkCreator".into(),
            aud: "did:dht:z6MkMember".into(),
            exp: 1_700_000_000,
            nbf: None,
            nnc: "1234567890000-aabbccdd11223344aabbccdd11223344".to_owned(),
            att: vec![],
            prf: vec![],
            fct: None,
        },
        signature: vec![0u8; 64],
        encoded: "test.encoded.token".to_owned(),
    };

    let mut proof_resolver = InMemoryProofResolver::new();
    proof_resolver
        .proofs
        .insert("bafyrei-test".to_owned(), token.clone());

    let result = proof_resolver.resolve_proof("bafyrei-test").unwrap();
    assert_eq!(result, token);
}

// ---------------------------------------------------------------------------
// Step 5a: Self-delegation safety check (SCP-AB-013)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn validate_ucan_rejects_self_delegation_without_key_scope() {
    // iss == aud without scp_key_scope must be rejected at validation level.
    // mint_ucan now also rejects this at mint time, so we construct the
    // invalid token manually to verify the validation layer independently.
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;

    let now = scp_primitives::SystemClock.now_secs();
    let header = UcanHeader::new();
    let payload = UcanPayload {
        iss: issuer_did.clone(),
        aud: issuer_did.clone(),
        exp: now + 3600,
        nbf: None,
        nnc: nonce::generate_nonce(&scp_primitives::SystemClock),
        att: vec![Attenuation {
            with: "scp:ctx:ctx-self/messages:write".to_owned(),
            can: "write".to_owned(),
        }],
        prf: vec![],
        fct: None,
    };
    let header_json = serde_json::to_vec(&header).unwrap();
    let payload_json = serde_json::to_vec(&payload).unwrap();
    let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = custody
        .sign(&key_handle, signing_input.as_bytes())
        .await
        .unwrap();
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_bytes());
    let encoded = format!("{signing_input}.{sig_b64}");
    let token = UcanToken {
        header,
        payload,
        signature: sig.into_bytes(),
        encoded,
    };

    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let ceiling = default_ceiling();

    let required_cap = CapabilityUri::new("ctx-self", "messages", "write");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        &issuer_did, // presenting agent is the same DID
    );

    let result = validate_ucan(&token, &required_cap, &mut ctx);
    assert!(
        matches!(result, Err(UcanError::SelfDelegationWithoutKeyScope)),
        "iss == aud without key_scope must be rejected: {result:?}"
    );
}

#[tokio::test]
async fn validate_ucan_accepts_self_delegation_with_key_scope() {
    // iss == aud WITH scp_key_scope must be accepted.
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
    let caps = vec!["messages:write".to_owned()];

    // Mint a self-delegation token with key_scope.
    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: &issuer_did, // self-delegation
        context_id: "ctx-self",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: Some("#active".to_owned()),
        signing_key_id: None,
        ceiling: None,
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    // The default key IS the #active key, so register it under both
    // the default and the kid_keys paths.
    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::iter::once(((issuer_did.clone(), "#active".to_owned()), pk_bytes)).collect(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let ceiling = default_ceiling();

    let required_cap = CapabilityUri::new("ctx-self", "messages", "write");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        &issuer_did, // presenting agent is the same DID
    );

    let result = validate_ucan(&token, &required_cap, &mut ctx);
    assert!(
        result.is_ok(),
        "iss == aud with key_scope must be accepted: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Step 5b: Key scope verification (SCP-AB-013)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn validate_ucan_accepts_matching_key_scope() {
    // Token with key_scope="#agent", signed by #agent key -> accepted.
    let (custody, _key_active, issuer_did, pk_active) = setup_identity().await;

    // Generate a second key pair for the agent key.
    let agent_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let agent_pubkey = custody.public_key(&agent_key).await.unwrap();
    let pk_agent: [u8; 32] = agent_pubkey.as_bytes().try_into().unwrap();

    let caps = vec!["messages:write".to_owned()];

    // Mint a token with key_scope="#agent", signed by the agent key.
    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &agent_key,    // Signed by agent key
        audience_did: &issuer_did, // self-delegation
        context_id: "ctx-scope",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: Some("#agent".to_owned()),
        signing_key_id: None,
        ceiling: None,
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    // kid should be "#agent" in the header.
    assert_eq!(token.header.kid, Some("#agent".to_owned()));

    // Register the agent key under the kid_keys resolver.
    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_active)).collect(),
        kid_keys: std::iter::once(((issuer_did.clone(), "#agent".to_owned()), pk_agent)).collect(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let ceiling = default_ceiling();

    let required_cap = CapabilityUri::new("ctx-scope", "messages", "write");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        &issuer_did, // self-delegation
    );

    let result = validate_ucan(&token, &required_cap, &mut ctx);
    assert!(
        result.is_ok(),
        "matching key_scope (#agent signed by #agent) must pass: {result:?}"
    );
}

#[tokio::test]
async fn validate_ucan_rejects_mismatched_key_scope() {
    let (custody, key_active, issuer_did, pk_active) = setup_identity().await;

    // Generate a separate agent keypair.
    let agent_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let agent_pubkey = custody.public_key(&agent_key).await.unwrap();
    let pk_agent: [u8; 32] = agent_pubkey.as_bytes().try_into().unwrap();

    let caps = vec!["messages:write".to_owned()];

    // Mint with key_scope="#agent" but sign with the ACTIVE key.
    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_active, // WRONG key: signing with #active
        audience_did: &issuer_did,
        context_id: "ctx-scope",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: Some("#agent".to_owned()), // Says #agent
        signing_key_id: None,
        ceiling: None,
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    // Register both keys. The #agent key is different from #active.
    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_active)).collect(),
        kid_keys: std::iter::once((
            (issuer_did.clone(), "#agent".to_owned()),
            pk_agent, // Different from the key that actually signed
        ))
        .collect(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let ceiling = default_ceiling();

    let required_cap = CapabilityUri::new("ctx-scope", "messages", "write");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        &issuer_did,
    );

    let result = validate_ucan(&token, &required_cap, &mut ctx);
    assert!(
        matches!(result, Err(UcanError::SignatureInvalid)),
        "token signed by wrong key must fail signature verification: {result:?}"
    );
}

#[tokio::test]
async fn validate_ucan_skips_key_scope_check_when_absent() {
    // Token without scp_key_scope in facts: step 5b is skipped.
    // This is the backward-compatibility case.
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
    let caps = vec!["messages:write".to_owned()];

    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: "did:dht:z6MkMember",
        context_id: "ctx-compat",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None, // No key scope: legacy token
        signing_key_id: None,
        ceiling: None,
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let ceiling = default_ceiling();

    let required_cap = CapabilityUri::new("ctx-compat", "messages", "write");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        "did:dht:z6MkMember",
    );

    let result = validate_ucan(&token, &required_cap, &mut ctx);
    assert!(
        result.is_ok(),
        "token without key_scope must pass (backward compat): {result:?}"
    );
}

#[tokio::test]
async fn validate_ucan_scoped_ucan_cannot_be_exercised_by_wrong_key() {
    let (custody, key_handle, issuer_did, pk_active) = setup_identity().await;

    // Generate a different key that represents the "real" agent key.
    let real_agent_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let real_agent_pubkey = custody.public_key(&real_agent_key).await.unwrap();
    let pk_real_agent: [u8; 32] = real_agent_pubkey.as_bytes().try_into().unwrap();

    let caps = vec!["messages:write".to_owned()];

    // Mint with key_scope="#agent" signed by the active key (not the real agent key).
    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle, // #active key signing
        audience_did: &issuer_did,
        context_id: "ctx-wrong",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: Some("#agent".to_owned()),
        signing_key_id: None,
        ceiling: None,
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    // The resolver maps #agent to the REAL agent key (different from #active).
    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_active)).collect(),
        kid_keys: std::iter::once((
            (issuer_did.clone(), "#agent".to_owned()),
            pk_real_agent, // Different from the key that actually signed
        ))
        .collect(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let ceiling = default_ceiling();

    let required_cap = CapabilityUri::new("ctx-wrong", "messages", "write");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        &issuer_did,
    );

    let result = validate_ucan(&token, &required_cap, &mut ctx);
    assert!(
        matches!(result, Err(UcanError::SignatureInvalid)),
        "scoped UCAN exercised by wrong key must fail: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Step 8: All-attestation ceiling enforcement (spec §7.2.1 step 8)
//
// Step 8 enforces the ceiling over the token's ENTIRE attestation set, not
// only the invoked capability. A token whose invoked capability is in-ceiling
// but which smuggles an out-of-ceiling attestation must be rejected, and the
// rejection must happen BEFORE the nonce is recorded (step 9).
// ---------------------------------------------------------------------------

/// Mints a multi-attestation token whose invoked cap is in-ceiling but which
/// also carries an out-of-ceiling attestation, and asserts step 8 rejects it
/// with `CapabilityOutsideCeiling`.
#[tokio::test]
async fn validate_ucan_step8_rejects_smuggled_out_of_ceiling_attestation() {
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;

    // Token grants BOTH messages:write (invoked, in-ceiling) and role:assign
    // (smuggled). Mint-time ceiling includes both so the token is well-formed
    // and signed; the narrower validation ceiling below is what must reject it.
    let caps = vec!["messages:write".to_owned(), "role:assign".to_owned()];
    let mint_ceiling: HashSet<String> = ["messages:write".to_owned(), "role:assign".to_owned()]
        .into_iter()
        .collect();

    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: "did:dht:z6MkMember",
        context_id: "ctx-step8",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: Some(mint_ceiling),
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();

    // Validation ceiling allows messages:write but NOT role:assign.
    let ceiling: HashSet<String> = std::iter::once("messages:write".to_owned()).collect();
    let required_cap = CapabilityUri::new("ctx-step8", "messages", "write");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        "did:dht:z6MkMember",
    );

    let result = validate_ucan(&token, &required_cap, &mut ctx);
    assert!(
        matches!(result, Err(UcanError::CapabilityOutsideCeiling(ref c)) if c == "role:assign"),
        "smuggled out-of-ceiling attestation must be rejected by step 8: {result:?}"
    );
}

/// A multi-attestation token where every attestation is in-ceiling must pass.
#[tokio::test]
async fn validate_ucan_step8_accepts_multi_attestation_all_in_ceiling() {
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;

    let caps = vec![
        "messages:read".to_owned(),
        "messages:write".to_owned(),
        "tool_invoke:assistant".to_owned(),
    ];

    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: "did:dht:z6MkMember",
        context_id: "ctx-step8-ok",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: None,
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let ceiling = default_ceiling(); // contains all three caps
    let required_cap = CapabilityUri::new("ctx-step8-ok", "messages", "write");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        "did:dht:z6MkMember",
    );

    let result = validate_ucan(&token, &required_cap, &mut ctx);
    assert!(
        result.is_ok(),
        "multi-attestation token with all caps in-ceiling must pass: {result:?}"
    );
}

/// A ceiling-violating token (rejected at step 8) must NOT consume its nonce:
/// step 8 short-circuits before step 9 (`check_and_record`). Proven by
/// validating the token (which must fail with `CapabilityOutsideCeiling`), then
/// asserting the tracker's read-only `check_replay` still accepts that exact
/// nonce afterward — which it could only do if step 9 never recorded it.
#[tokio::test]
async fn validate_ucan_ceiling_violation_does_not_consume_nonce() {
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;

    let caps = vec!["messages:write".to_owned(), "role:assign".to_owned()];
    let mint_ceiling: HashSet<String> = ["messages:write".to_owned(), "role:assign".to_owned()]
        .into_iter()
        .collect();

    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: "did:dht:z6MkMember",
        context_id: "ctx-step8-nonce",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: Some(mint_ceiling),
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let ceiling: HashSet<String> = std::iter::once("messages:write".to_owned()).collect();
    let required_cap = CapabilityUri::new("ctx-step8-nonce", "messages", "write");

    // Validate: must fail at step 8 (ceiling), before step 9 records the nonce.
    {
        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
            &ceiling,
            &issuer_did,
            "did:dht:z6MkMember",
        );
        let result = validate_ucan(&token, &required_cap, &mut ctx);
        assert!(
            matches!(result, Err(UcanError::CapabilityOutsideCeiling(_))),
            "must be rejected by step 8: {result:?}"
        );
    }

    // The token's nonce must NOT have been recorded — a read-only replay probe
    // for that exact nonce still succeeds (would be NonceReused if step 9 had
    // run and recorded it).
    assert!(
        nonce_tracker
            .check_replay(&token.payload.nnc, token.payload.exp)
            .is_ok(),
        "ceiling-violating token must not have consumed its nonce (step 8 short-circuits before step 9)"
    );
}

// ---------------------------------------------------------------------------
// evaluate_ucan: structured, side-effect-free evaluation
// ---------------------------------------------------------------------------

/// `evaluate_ucan` called twice on the same token must report `nonce_valid:
/// true` BOTH times — proving it never records the nonce. As the regression
/// guard's enforcement half, `validate_ucan` on the same token must throw
/// `NonceReused` on the 2nd call — proving the gate DOES record.
#[tokio::test]
async fn evaluate_ucan_does_not_consume_nonce_but_validate_does() {
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
    let caps = vec!["messages:write".to_owned()];

    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: "did:dht:z6MkMember",
        context_id: "ctx-eval-nonce",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: None,
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let ceiling = default_ceiling();
    let required_cap = CapabilityUri::new("ctx-eval-nonce", "messages", "write");

    // evaluate_ucan twice — read-only, so nonce_valid must be true both times.
    {
        let ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
            &ceiling,
            &issuer_did,
            "did:dht:z6MkMember",
        );
        let first = evaluate_ucan(&token, &required_cap, &ctx);
        let second = evaluate_ucan(&token, &required_cap, &ctx);
        assert!(
            first.nonce_valid && second.nonce_valid,
            "evaluate_ucan must not consume the nonce: {first:?} {second:?}"
        );
        assert_eq!(
            first, second,
            "evaluate_ucan must be deterministic / side-effect-free"
        );
        assert!(
            first
                == CapabilityValidation {
                    tokens_valid: true,
                    signatures_valid: true,
                    within_ceiling: true,
                    nonce_valid: true,
                    not_revoked: true,
                    time_bounds_valid: true,
                },
            "fully valid token must evaluate all-true: {first:?}"
        );
    }

    // validate_ucan DOES record: 1st passes, 2nd is NonceReused.
    {
        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
            &ceiling,
            &issuer_did,
            "did:dht:z6MkMember",
        );
        let first = validate_ucan(&token, &required_cap, &mut ctx);
        assert!(first.is_ok(), "first validate_ucan must pass: {first:?}");
    }
    {
        let mut ctx = build_context(
            &resolver,
            &mut nonce_tracker,
            &revocation_checker,
            &proof_resolver,
            &ceiling,
            &issuer_did,
            "did:dht:z6MkMember",
        );
        let second = validate_ucan(&token, &required_cap, &mut ctx);
        assert!(
            matches!(second, Err(UcanError::NonceReused(_))),
            "second validate_ucan must reject the recorded nonce: {second:?}"
        );
    }
}

/// `evaluate_ucan` returns the correct per-field struct for a bad-signature
/// token: parse succeeds (`tokens_valid`), but signature fails so
/// `signatures_valid` and everything after are false.
#[tokio::test]
async fn evaluate_ucan_reports_bad_signature() {
    let (custody, key_handle, issuer_did, _pk_bytes) = setup_identity().await;
    let caps = vec!["messages:write".to_owned()];

    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: "did:dht:z6MkMember",
        context_id: "ctx-eval-sig",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: None,
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    // Resolver returns the WRONG public key for the issuer, so signature
    // verification (step 2) fails while parsing (step 1) succeeds.
    let wrong_pk = [0u8; 32];
    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), wrong_pk)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let ceiling = default_ceiling();
    let required_cap = CapabilityUri::new("ctx-eval-sig", "messages", "write");

    let ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        "did:dht:z6MkMember",
    );

    let result = evaluate_ucan(&token, &required_cap, &ctx);
    assert_eq!(
        result,
        CapabilityValidation {
            tokens_valid: true,
            signatures_valid: false,
            within_ceiling: false,
            nonce_valid: false,
            not_revoked: false,
            time_bounds_valid: false,
        },
        "bad signature must report tokens_valid=true, rest false: {result:?}"
    );
}

/// `evaluate_ucan` reports `within_ceiling: false` for a token carrying an
/// out-of-ceiling attestation (signatures pass, ceiling fails, rest false).
#[tokio::test]
async fn evaluate_ucan_reports_out_of_ceiling_attestation() {
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;

    let caps = vec!["messages:write".to_owned(), "role:assign".to_owned()];
    let mint_ceiling: HashSet<String> = ["messages:write".to_owned(), "role:assign".to_owned()]
        .into_iter()
        .collect();

    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: "did:dht:z6MkMember",
        context_id: "ctx-eval-ceiling",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: Some(mint_ceiling),
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let ceiling: HashSet<String> = std::iter::once("messages:write".to_owned()).collect();
    let required_cap = CapabilityUri::new("ctx-eval-ceiling", "messages", "write");

    let ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        "did:dht:z6MkMember",
    );

    let result = evaluate_ucan(&token, &required_cap, &ctx);
    assert_eq!(
        result,
        CapabilityValidation {
            tokens_valid: true,
            signatures_valid: true,
            within_ceiling: false,
            nonce_valid: false,
            not_revoked: false,
            time_bounds_valid: false,
        },
        "out-of-ceiling attestation must report within_ceiling=false: {result:?}"
    );
}

/// `evaluate_ucan` reports `not_revoked: false` for a token whose revocation
/// CID is on the context revocation list. Revocation is step 10; everything
/// before it (parse, signatures, ceiling, nonce) passes, and step 11 (expiry)
/// never runs after revocation short-circuits, so `time_bounds_valid` stays
/// false. This documents the actual short-circuit field mapping in
/// `evaluate_ucan`.
#[tokio::test]
async fn evaluate_ucan_reports_revoked_token() {
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
    let caps = vec!["messages:write".to_owned()];

    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: "did:dht:z6MkMember",
        context_id: "ctx-eval-revoke",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: None,
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    // Revoke the token by inserting its content-hash CID into the checker.
    let revocation_cid = compute_revocation_cid(&token.encoded);
    let mut revocation_checker = InMemoryRevocationChecker::new();
    revocation_checker.revoked.insert(revocation_cid);

    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let ceiling = default_ceiling();
    let required_cap = CapabilityUri::new("ctx-eval-revoke", "messages", "write");

    let ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        "did:dht:z6MkMember",
    );

    let result = evaluate_ucan(&token, &required_cap, &ctx);
    assert_eq!(
        result,
        CapabilityValidation {
            tokens_valid: true,
            signatures_valid: true,
            within_ceiling: true,
            nonce_valid: true,
            not_revoked: false,
            time_bounds_valid: false,
        },
        "revoked token must report not_revoked=false (and time_bounds_valid \
         stays false because expiry never runs after revocation): {result:?}"
    );
}

/// `evaluate_ucan` reports `time_bounds_valid: false` for an expired token.
/// Expiry is the last step (11); everything before it passes, including
/// `not_revoked: true`. This documents the actual field mapping in
/// `evaluate_ucan`.
#[tokio::test]
async fn evaluate_ucan_reports_expired_token() {
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
    let caps = vec!["messages:write".to_owned()];

    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: "did:dht:z6MkMember",
        context_id: "ctx-eval-expired",
        capabilities: &caps,
        lifetime_secs: 1, // Very short lifetime.
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: None,
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    // Wait for the token to expire.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let ceiling = default_ceiling();
    let required_cap = CapabilityUri::new("ctx-eval-expired", "messages", "write");

    let mut ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        "did:dht:z6MkMember",
    );
    // Use zero tolerance so the 2-second expiry is detected.
    ctx.clock_skew_tolerance_secs = 0;

    let result = evaluate_ucan(&token, &required_cap, &ctx);
    assert_eq!(
        result,
        CapabilityValidation {
            tokens_valid: true,
            signatures_valid: true,
            within_ceiling: true,
            nonce_valid: true,
            not_revoked: true,
            time_bounds_valid: false,
        },
        "expired token must report time_bounds_valid=false with all prior \
         stages true: {result:?}"
    );
}

/// Regression guard for the structured `ucan_evaluate` contract that the
/// cross-bridge parity op (`OP_UCAN_EVALUATE_STRUCTURED` in
/// `seed_operations.py`) drives end-to-end: a parseable, validly-signed root
/// token evaluated against a capability it does NOT grant returns a
/// PARTIAL-FALSE struct WITHOUT throwing, the field mapping short-circuits at
/// the failing stage, and repeated evaluation is byte-identical (read-only).
///
/// Concretely: mint a valid token granting `messages:read`, then evaluate it
/// requiring `messages:write`. The step-6 invoked-capability grant-match fails
/// (the token's `att` set has no `messages:write`), so the failure lands in the
/// `signatures_valid` stage: `tokens_valid: true` (parse ran and passed),
/// `signatures_valid: false` (grant-match failed), and every later field false
/// (those stages never ran). Evaluating twice yields the EXACT same struct,
/// proving the call records nothing.
///
/// This is the no-throw partial-struct counterpart to the malformed-token path
/// (which throws before the pipeline runs). The all-true read-only-nonce
/// invariant is pinned separately by
/// `evaluate_ucan_does_not_consume_nonce_but_validate_does`; this test pins the
/// determinism of a MID-PIPELINE failure.
#[tokio::test]
async fn evaluate_ucan_partial_struct_for_ungranted_capability_is_stable() {
    let (custody, key_handle, issuer_did, pk_bytes) = setup_identity().await;
    // Token grants ONLY messages:read.
    let caps = vec!["messages:read".to_owned()];

    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &key_handle,
        audience_did: "did:dht:z6MkMember",
        context_id: "ctx-eval-ungranted",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: None,
    };

    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    let resolver = InMemoryDidResolver {
        keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
        kid_keys: std::collections::HashMap::new(),
    };
    let mut nonce_tracker = InMemoryNonceTracker::new();
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    // Ceiling permits both caps so the divergence is purely the ungranted
    // INVOKED capability (grant-match), not the ceiling check — matching the
    // parity op's construction exactly.
    let ceiling: HashSet<String> = ["messages:read".to_owned(), "messages:write".to_owned()]
        .into_iter()
        .collect();
    // Evaluate requiring messages:write — a capability the token does NOT grant.
    let required_cap = CapabilityUri::new("ctx-eval-ungranted", "messages", "write");

    let ctx = build_context(
        &resolver,
        &mut nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        &ceiling,
        &issuer_did,
        "did:dht:z6MkMember",
    );

    let expected = CapabilityValidation {
        tokens_valid: true,
        signatures_valid: false,
        within_ceiling: false,
        nonce_valid: false,
        not_revoked: false,
        time_bounds_valid: false,
    };

    let first = evaluate_ucan(&token, &required_cap, &ctx);
    let second = evaluate_ucan(&token, &required_cap, &ctx);

    assert_eq!(
        first, expected,
        "ungranted invoked capability must report tokens_valid=true, \
         signatures_valid=false, rest false (no throw): {first:?}"
    );
    assert_eq!(
        first, second,
        "evaluate_ucan must be deterministic / side-effect-free across repeated \
         calls on a mid-pipeline failure: {first:?} {second:?}"
    );
}
