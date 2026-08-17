//! Negative tests for ADR-039 agent binding (SCP-AB-022).
//!
//! Tests key continuity fingerprint behavior, DID document agent key
//! constraints, UCAN self-delegation / key-scope semantics, and governance
//! one-vote-per-DID enforcement.

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::type_complexity
)]
mod tests {
    use std::collections::HashSet;

    use scp_did::{DidDocument, VerificationMethod};
    use scp_platform::testing::InMemoryKeyCustody;
    use scp_platform::traits::{KeyCustody, KeyType};

    use crate::crypto::ucan::mint::{MintParams, mint_ucan};
    use scp_protocol::crypto::key_continuity::{
        KeyContinuityParty, compute_key_continuity_fingerprint,
    };
    use scp_protocol::crypto::ucan::UcanError;
    use scp_protocol::crypto::ucan::validate::{
        DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, InMemoryDidResolver, InMemoryRevocationChecker,
        NoCaveatResolver, ValidationContext,
    };

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Creates an Ed25519 identity keypair, returns (custody, `key_handle`, did, `public_key_bytes`).
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

    /// Creates a `DidDocument` with identity + active keys and optionally an agent key.
    ///
    /// `add_agent_key` rather than a hand-built `VerificationMethod`, because
    /// it also references `{did}#agent` from `authentication` and
    /// `assertionMethod`. Pushing the method alone modelled a document no SCP
    /// constructor produces, and a resolver reading a verification relationship
    /// supplies no key from it.
    fn make_did_document(
        did: &str,
        identity_pk: &[u8; 32],
        active_pk: &[u8; 32],
        agent_pk: Option<&[u8; 32]>,
    ) -> DidDocument {
        let mut doc = DidDocument::new(did, identity_pk, active_pk, &[0u8; 32]);
        if let Some(apk) = agent_pk {
            doc.add_agent_key(apk)
                .expect("a freshly built document publishes no #agent method yet");
        }
        doc
    }

    // -----------------------------------------------------------------------
    // Test 1: Agent uses key_scope UCAN with wrong key
    //
    // Per ADR-039, a UCAN with `fct.scp_key_scope: "#agent"` must be signed
    // by the `#agent` key, not the `#active` key. This test mints a UCAN
    // with key_scope "#agent" in its `fct` but signs it with the `#active`
    // key. The validation pipeline (step 5b) should reject this.
    //
    // Step 5b (key scope verification) is implemented in validate.rs via
    // `validate_key_scope()`. This test verifies UCAN construction with
    // key_scope and kid header fields set correctly.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn agent_key_scope_ucan_signed_with_active_key_is_detectable() {
        // Create a human identity (this signs with #active).
        let (custody, active_key, did, _pk) = setup_identity().await;

        // Create a separate agent key (which SHOULD sign the scoped UCAN).
        let agent_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let _agent_pk = custody.public_key(&agent_handle).await.unwrap();

        // Mint a UCAN with key_scope: "#agent" in fct, but sign with #active key.
        let caps = vec!["messages:write".to_owned()];
        let params = MintParams {
            issuer_did: &did,
            issuer_key: &active_key, // WRONG: should be agent_handle
            audience_did: &did,      // Self-delegation
            context_id: "ctx-test",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: Some(serde_json::json!({
                "scp_key_scope": "#agent"
            })),
            key_scope: Some("#agent".to_owned()),
            signing_key_id: None, // Deliberately not setting — tests key_scope mismatch
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
            .await
            .unwrap();

        // The token was minted successfully (step 5b is enforced at validation
        // time, not mint time). Verify the facts contain the key_scope claim.
        let fct = token.payload.fct.as_ref().unwrap();
        assert_eq!(fct["scp_key_scope"], "#agent");

        // Verify it's a self-delegation (iss == aud).
        assert_eq!(token.payload.iss, token.payload.aud);

        // Verify the kid header is set from key_scope.
        assert_eq!(token.header.kid.as_deref(), Some("#agent"));
    }

    // -----------------------------------------------------------------------
    // Test 2: Self-delegation without key_scope
    //
    // Per ADR-039, self-delegation (iss == aud) is ONLY valid when the
    // token's `fct` contains `scp_key_scope`. Without it, iss == aud is
    // ambiguous and should be rejected by step 5.
    //
    // Currently, validate_ucan does not special-case self-delegation, so
    // iss == aud passes the audience check when the presenting agent DID
    // matches. This test documents that once key_scope enforcement is
    // added, self-delegation without key_scope must be rejected.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn self_delegation_without_key_scope_is_structurally_invalid() {
        let (custody, key, did, _pk) = setup_identity().await;

        // Self-delegation: iss == aud, but NO scp_key_scope in fct.
        let caps = vec!["messages:write".to_owned()];
        let params = MintParams {
            issuer_did: &did,
            issuer_key: &key,
            audience_did: &did, // Self-delegation
            context_id: "ctx-test",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None, // No key_scope!
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        // mint_ucan rejects self-delegation without key_scope at mint time
        // (ADR-039 enforcement).
        let result = mint_ucan(&params, &custody, &scp_clock::SystemClock).await;
        assert!(
            result.is_err(),
            "self-delegation (iss == aud) without key_scope must be rejected"
        );
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("self-delegation"),
            "error should mention self-delegation: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 3: Agent mints root UCAN (not sub-delegated)
    //
    // Per ADR-039 step 4: "Agent keys (#agent) cannot issue root UCANs —
    // root UCAN issuance requires #active (the human signing key)."
    //
    // However, structurally a root UCAN is just one with empty `prf`.
    // The enforcement is at validation step 4 (root issuer must be context
    // creator) and step 5b (signing key must match declared scope). This
    // test verifies that an agent key CAN mint a token (it's just bytes)
    // but the validation pipeline should reject it as a root UCAN.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn agent_key_root_ucan_is_rejected_as_root_issuer() {
        // Human is the context creator.
        let (_custody_human, _human_key, human_did, human_pk) = setup_identity().await;

        // Agent has its own key custody (separate key).
        let (custody_agent, agent_key, agent_did, agent_pk) = setup_identity().await;

        // Agent mints a root UCAN (empty prf) claiming to be the root issuer.
        let caps = vec!["messages:write".to_owned()];
        let params = MintParams {
            issuer_did: &agent_did,
            issuer_key: &agent_key,
            audience_did: &human_did,
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

        let token = mint_ucan(&params, &custody_agent, &scp_clock::SystemClock)
            .await
            .unwrap();

        // Validate: the root issuer (agent_did) != context creator (human_did).
        let resolver = InMemoryDidResolver {
            keys: [(human_did.clone(), human_pk), (agent_did.clone(), agent_pk)]
                .into_iter()
                .collect(),
            kid_keys: std::collections::HashMap::new(),
        };
        let mut nonce_tracker = scp_protocol::crypto::ucan::validate::InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let proof_resolver = scp_protocol::crypto::ucan::validate::InMemoryProofResolver::new();
        let ceiling: HashSet<String> = ["messages:write".to_owned(), "messages:read".to_owned()]
            .into_iter()
            .collect();

        let required_cap = scp_protocol::crypto::ucan::capability::CapabilityUri::new(
            "ctx-test", "messages", "write",
        );

        let caveat_resolver = NoCaveatResolver;
        let mut ctx = ValidationContext {
            did_resolver: &resolver,
            nonce_tracker: &mut nonce_tracker,
            revocation_checker: &revocation_checker,
            proof_resolver: &proof_resolver,
            caveat_resolver: &caveat_resolver,
            ceiling: &ceiling,
            context_creator_did: &human_did,
            presenting_agent_did: &human_did,
            clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
            clock: &scp_clock::SystemClock,
        };

        let result =
            scp_protocol::crypto::ucan::validate::validate_ucan(&token, &required_cap, &mut ctx);

        // Must fail: root issuer is agent_did, not the context creator human_did.
        assert!(
            matches!(result, Err(UcanError::InvalidIssuer { .. })),
            "agent key root UCAN must be rejected as root issuer: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 4: DID document with two #agent VMs
    //
    // Per spec §4.2: "The human's DID document contains at most one #agent
    // verification method." Adding a second agent key should be rejected.
    //
    // The `DidDocument::validate_agent_keys()` method enforces this constraint.
    // This test validates the constraint by both direct structural inspection
    // and calling `validate_agent_keys()`.
    // -----------------------------------------------------------------------

    #[test]
    fn did_document_with_two_agent_vms_violates_constraint() {
        let did = "did:dht:z6MkTestDualAgent";
        let identity_pk = [1u8; 32];
        let active_pk = [2u8; 32];
        let agent_pk_1 = [3u8; 32];
        let agent_pk_2 = [4u8; 32];

        let mut doc = make_did_document(did, &identity_pk, &active_pk, Some(&agent_pk_1));

        // Manually add a second #agent VM (this should violate the constraint).
        let second_agent_vm = VerificationMethod {
            id: format!("{did}#agent"),
            method_type: "Ed25519VerificationKey2020".to_owned(),
            controller: did.to_owned(),
            public_key_multibase: format!("z{}", bs58::encode(&agent_pk_2).into_string()),
        };
        doc.verification_method.push(second_agent_vm);

        // Count #agent VMs. The invariant requires at most 1.
        let agent_vm_count = doc
            .verification_method
            .iter()
            .filter(|vm| vm.id.ends_with("#agent"))
            .count();

        assert_eq!(
            agent_vm_count, 2,
            "test setup: should have 2 agent VMs to violate constraint"
        );

        // validate_agent_keys() enforces the at-most-one constraint.
        assert!(
            doc.validate_agent_keys().is_err(),
            "DID document with multiple #agent VMs must be rejected by validate_agent_keys()"
        );
    }

    // -----------------------------------------------------------------------
    // Test 5: One DID casts two governance votes
    //
    // The governance module uses DID-based vote deduplication. In the
    // shared-DID model (ADR-039), a human and their agent share the same
    // DID. This means the governance `has_voted` check naturally prevents
    // a DID from voting twice, regardless of whether the vote comes from
    // the human (#active key) or the agent (#agent key).
    //
    // This test exercises the existing MajorityVoteEngine to confirm that
    // a second vote from the same DID is rejected with AlreadyVoted.
    // -----------------------------------------------------------------------

    #[test]
    fn one_did_cannot_cast_two_governance_votes() {
        use scp_did::DID;
        use scp_protocol::context::governance::majority::MajorityVoteEngine;
        use scp_protocol::context::governance::{
            GovernanceAction, GovernanceContext, GovernanceEngine, GovernanceError,
        };

        let admin_did = DID::from("did:dht:z6MkAdmin");
        let voter_did = DID::from("did:dht:z6MkVoter");
        let third_did = DID::from("did:dht:z6MkThird");

        // The voter's DID is shared between human and agent (ADR-039).
        // Both the human (#active) and agent (#agent) would present the same DID.

        let eligible_voters = vec![admin_did.clone(), voter_did.clone(), third_did.clone()];

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xAA; 32]);
        let admin_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xBB; 32]);

        // Resolver maps each DID to the signing key used by that participant.
        let admin_vk = admin_signing_key.verifying_key();
        let voter_vk = signing_key.verifying_key();
        let third_vk = ed25519_dalek::SigningKey::from_bytes(&[0xCC; 32]).verifying_key();
        #[allow(clippy::type_complexity)]
        let resolver: std::sync::Arc<
            dyn Fn(&scp_did::DID, scp_did::SigningKeyId) -> Option<ed25519_dalek::VerifyingKey>
                + Send
                + Sync,
        > = {
            let admin_d = admin_did.clone();
            let voter_d = voter_did.clone();
            let third_d = third_did.clone();
            std::sync::Arc::new(move |did: &scp_did::DID, _kid: scp_did::SigningKeyId| {
                if *did == admin_d {
                    Some(admin_vk)
                } else if *did == voter_d {
                    Some(voter_vk)
                } else if *did == third_d {
                    Some(third_vk)
                } else {
                    None
                }
            })
        };
        let mut engine = MajorityVoteEngine::new(
            eligible_voters,
            300,  // voting_window_secs: 5 minutes
            5000, // min_participation_bps: 50%
            resolver,
        )
        .unwrap();

        let ctx = GovernanceContext {
            context_id: "ctx-gov-test".to_owned(),
            members: vec![
                (admin_did.clone(), "admin".to_owned()),
                (voter_did.clone(), "member".to_owned()),
                (third_did, "member".to_owned()),
            ],
            admin_dids: vec![admin_did.clone()],
            current_epoch: Some(1),
            now: 1000,
        };

        // Admin proposes.
        let action = GovernanceAction::CloseContext { reason: None };
        let (proposal, _events) = engine
            .propose(&admin_did, action, &ctx, &admin_signing_key)
            .unwrap();

        let proposal_id = proposal.proposal_id;

        // First vote: voter approves (this could be the "human" side).
        let (_status, _events) = engine
            .approve(&proposal_id, &voter_did, &ctx, &signing_key)
            .unwrap();

        // Second vote: same DID votes again (this would be the "agent" side).
        // Even though the agent has a different signing key (#agent), it
        // presents the same DID. The governance engine should reject this.
        let agent_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xCC; 32]);
        let result = engine.approve(&proposal_id, &voter_did, &ctx, &agent_signing_key);

        // Must be rejected: either AlreadyVoted (within window) or
        // ProposalNotPending (if early-resolved). Both prevent double voting.
        assert!(
            result.is_err(),
            "second vote from same DID must be rejected: {result:?}"
        );

        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                GovernanceError::AlreadyVoted | GovernanceError::ProposalNotPending { .. }
            ),
            "expected AlreadyVoted or ProposalNotPending, got: {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 6: Key continuity fingerprint with and without agent key
    //
    // These tests are in the key_continuity module itself. Here we add
    // additional integration-level tests that combine DidDocument structures
    // with the fingerprint computation.
    // -----------------------------------------------------------------------

    #[test]
    fn fingerprint_from_did_documents_without_agent_keys() {
        let alice_did = "did:dht:z6MkAlice";
        let alice_id = [10u8; 32];
        let alice_active = [20u8; 32];
        let bob_did = "did:dht:z6MkBob";
        let bob_id = [30u8; 32];
        let bob_active = [40u8; 32];

        let _alice_doc = make_did_document(alice_did, &alice_id, &alice_active, None);
        let _bob_doc = make_did_document(bob_did, &bob_id, &bob_active, None);

        let alice = KeyContinuityParty {
            did: alice_did,
            identity_key: &alice_id,
            active_key: &alice_active,
            agent_key: None,
        };
        let bob = KeyContinuityParty {
            did: bob_did,
            identity_key: &bob_id,
            active_key: &bob_active,
            agent_key: None,
        };

        // Compute fingerprint without agent keys.
        let fp = compute_key_continuity_fingerprint(&alice, &bob);

        // Deterministic: same inputs produce same output.
        let fp2 = compute_key_continuity_fingerprint(&alice, &bob);
        assert_eq!(fp, fp2);

        // Non-zero: not a degenerate output.
        assert_ne!(fp, [0u8; 32]);
    }

    #[test]
    fn fingerprint_changes_when_agent_key_added_to_did_document() {
        let alice_did = "did:dht:z6MkAlice";
        let alice_id = [10u8; 32];
        let alice_active = [20u8; 32];
        let alice_agent = [50u8; 32];
        let bob_did = "did:dht:z6MkBob";
        let bob_id = [30u8; 32];
        let bob_active = [40u8; 32];

        let alice_no_agent = KeyContinuityParty {
            did: alice_did,
            identity_key: &alice_id,
            active_key: &alice_active,
            agent_key: None,
        };
        let alice_with_agent = KeyContinuityParty {
            did: alice_did,
            identity_key: &alice_id,
            active_key: &alice_active,
            agent_key: Some(&alice_agent),
        };
        let bob = KeyContinuityParty {
            did: bob_did,
            identity_key: &bob_id,
            active_key: &bob_active,
            agent_key: None,
        };

        // Before agent binding.
        let fp_before = compute_key_continuity_fingerprint(&alice_no_agent, &bob);

        // After Alice binds an agent.
        let fp_after = compute_key_continuity_fingerprint(&alice_with_agent, &bob);

        assert_ne!(
            fp_before, fp_after,
            "fingerprint must change when an agent key is added"
        );
    }

    #[test]
    fn fingerprint_with_both_agent_keys_is_deterministic() {
        let alice_did = "did:dht:z6MkAlice";
        let alice_id = [10u8; 32];
        let alice_active = [20u8; 32];
        let alice_agent = [50u8; 32];
        let bob_did = "did:dht:z6MkBob";
        let bob_id = [30u8; 32];
        let bob_active = [40u8; 32];
        let bob_agent = [60u8; 32];

        let alice = KeyContinuityParty {
            did: alice_did,
            identity_key: &alice_id,
            active_key: &alice_active,
            agent_key: Some(&alice_agent),
        };
        let bob = KeyContinuityParty {
            did: bob_did,
            identity_key: &bob_id,
            active_key: &bob_active,
            agent_key: Some(&bob_agent),
        };

        let fp1 = compute_key_continuity_fingerprint(&alice, &bob);
        let fp2 = compute_key_continuity_fingerprint(&alice, &bob);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_agent_absence_differs_from_zero_bytes() {
        let alice_did = "did:dht:z6MkAlice";
        let alice_id = [10u8; 32];
        let alice_active = [20u8; 32];
        let bob_did = "did:dht:z6MkBob";
        let bob_id = [30u8; 32];
        let bob_active = [40u8; 32];
        let zero_key = [0u8; 32];

        let alice_none = KeyContinuityParty {
            did: alice_did,
            identity_key: &alice_id,
            active_key: &alice_active,
            agent_key: None,
        };
        let bob_none = KeyContinuityParty {
            did: bob_did,
            identity_key: &bob_id,
            active_key: &bob_active,
            agent_key: None,
        };

        let alice_zero = KeyContinuityParty {
            did: alice_did,
            identity_key: &alice_id,
            active_key: &alice_active,
            agent_key: Some(&zero_key),
        };
        let bob_zero = KeyContinuityParty {
            did: bob_did,
            identity_key: &bob_id,
            active_key: &bob_active,
            agent_key: Some(&zero_key),
        };

        // None agent key uses domain-derived sentinel SHA-256("SCP-ABSENT-AGENT-KEY"),
        // NOT zero bytes. This prevents collision with the Ed25519 identity point.
        let fp_none = compute_key_continuity_fingerprint(&alice_none, &bob_none);
        let fp_zero = compute_key_continuity_fingerprint(&alice_zero, &bob_zero);

        assert_ne!(
            fp_none, fp_zero,
            "absent agent key (None) must differ from explicit zero bytes (uses domain-derived sentinel)"
        );
    }
}
