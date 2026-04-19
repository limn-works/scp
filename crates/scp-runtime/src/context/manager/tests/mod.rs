use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
// AtomicUsize / AtomicU64 are referenced via fully-qualified paths inside
// the H5 mock event logs (`OrderedMockEventLog`, `FailingAppendEventLog`)
// to avoid widening the global `std::sync::atomic::*` import for the rest
// of this module.

use super::*;
use scp_protocol::context::params::MemoryScope;
use scp_protocol::context::{ContextMode, ContextState};
use scp_protocol::crypto::ucan::UcanToken;

mod broadcast;
mod commit_retry;
mod governance;
mod lifecycle;
mod messaging;
mod queries;
mod trust_recovery;

// -----------------------------------------------------------------------
// Key resolver helpers for tests
// -----------------------------------------------------------------------

/// No-op key resolver that always returns `None`. Suitable for tests
/// that don't exercise governance vote signature verification.
pub(super) fn noop_key_resolver() -> KeyResolver {
    Arc::new(|_| None)
}

/// Derives a deterministic Ed25519 seed from a DID string.
/// Used by both `mock_key_resolver` and `signing_key_for_did` to
/// ensure signing keys and resolved verifying keys match.
pub(super) fn did_to_seed(did: &DID) -> [u8; 32] {
    let mut s = [0u8; 32];
    let bytes = did.as_ref().as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        s[i % 32] ^= *b;
    }
    s
}

/// Mock key resolver that returns a deterministic verifying key derived
/// from the DID string. Suitable for governance proposal tests that
/// need actual key resolution for vote verification.
pub(super) fn mock_key_resolver() -> KeyResolver {
    Arc::new(|did| {
        let seed = did_to_seed(did);
        Some(ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key())
    })
}

/// Returns the signing key that corresponds to what `mock_key_resolver`
/// resolves for the given DID.
pub(super) fn signing_key_for_did(did: &DID) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&did_to_seed(did))
}

/// Creates an [`InMemoryKeyCustody`] and imports an Ed25519 signing key
/// from seed bytes, returning both the custody and the key handle.
///
/// Used by broadcast publish tests that need to pass custody + handle
/// to [`ContextManager::publish_broadcast`].
pub(super) async fn test_custody_from_seed(
    seed: &[u8; 32],
) -> (
    scp_platform::testing::InMemoryKeyCustody,
    scp_platform::KeyHandle,
) {
    let custody = scp_platform::testing::InMemoryKeyCustody::new();
    let handle = custody.import_ed25519_key(seed).await;
    (custody, handle)
}

// -----------------------------------------------------------------------
// Dummy UCAN for economy tests
// -----------------------------------------------------------------------

/// Returns a [`UcanToken`] with a generous default [`SpendingCapability`]
/// embedded in the `fct` field, suitable for tests that need a spending
/// UCAN to pass the AND-composition gate (spec §19.5, #1593).
///
/// This token is structurally valid but not cryptographically signed.
/// `check_spending_capability` extracts `SpendingCapability` from the `fct`
/// field and validates `action_cost <= max_per_action` and currency match.
/// The default capability grants up to `u64::MAX` per action in USD —
/// effectively unlimited, since most tests only care about the UCAN's
/// presence, not the spending limit.
///
/// For tests that need to exercise specific spending limits, use
/// [`dummy_spending_ucan_with_cap`].
///
/// C1/C1b (PR #1606) follow-up: spending UCANs are now cryptographically
/// validated end-to-end on the `send_message`, `join_context`, and
/// `invoke_tool_with_economy` paths. This zero-arg helper produces an
/// UNSIGNED token bound to the placeholder DID `did:key:test-spender` —
/// sufficient ONLY for tests that (a) use the direct free-function
/// `invoke_tool` helper (which does NOT run signature validation —
/// that's a caller-side escape hatch with no bridge exposure) or
/// (b) only assert that a paid action is rejected (the rejection now
/// happens at signature validation rather than at the previous
/// attestation/scope check, but the visible outcome is identical:
/// `Result::is_err()`).
///
/// Tests that exercise the `send_message` / `join_context` /
/// `ContextManager::invoke_tool_with_economy` HAPPY PATH with a paid
/// policy MUST use [`dummy_spending_ucan_for`] (which signs the token
/// with the deterministic test key matching `mock_key_resolver`).
/// Pairing the unsigned helper with a paid happy-path call will fail
/// signature validation — that is the correct fail-closed behavior
/// introduced by the C1/C1b fix.
pub(super) fn dummy_spending_ucan() -> UcanToken {
    // Unsigned token bound to a placeholder DID. Used by tests where
    // the spending UCAN does not need to pass signature verification
    // (tool invoke path, or assert-rejects tests).
    build_spending_ucan(
        &DID::from("did:key:test-spender"),
        u64::MAX,
        u64::MAX,
        false,
    )
}

/// Returns a fully-signed spending UCAN bound to the given actor DID.
///
/// The token is signed with the deterministic Ed25519 key produced by
/// [`signing_key_for_did`], which matches what [`mock_key_resolver`]
/// returns for the same DID. Tests using this helper with
/// `mock_key_resolver` get end-to-end cryptographic validation (closing
/// C1) without any per-test plumbing.
pub(super) fn dummy_spending_ucan_for(actor_did: &DID) -> UcanToken {
    build_spending_ucan(actor_did, u64::MAX, u64::MAX, true)
}

/// Returns a [`UcanToken`] with a real [`SpendingCapability`] embedded in
/// the `fct` field for tests that exercise paid actions.
///
/// The capability grants up to `max_per_action` per single action and
/// `max_total` within a 1-hour window, in USD. The token is signed with
/// the deterministic test key for `actor_did` so it passes the C1
/// signature validation pipeline.
#[allow(dead_code)] // Test utility — used by paid-action tests.
pub(super) fn dummy_spending_ucan_with_cap(
    actor_did: &DID,
    max_per_action: u64,
    max_total: u64,
) -> UcanToken {
    build_spending_ucan(actor_did, max_per_action, max_total, true)
}

/// Internal helper — builds a spending UCAN with the given cap, optionally
/// signing it with the deterministic test key for `actor_did`.
///
/// `signed = false` produces the legacy unsigned shape used by the
/// pre-C1 helpers. `signed = true` mints a real Ed25519 signature
/// bound to `actor_did` (matches `mock_key_resolver`).
fn build_spending_ucan(
    actor_did: &DID,
    max_per_action: u64,
    max_total: u64,
    signed: bool,
) -> UcanToken {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use scp_protocol::crypto::ucan::spending::{Amount, CurrencyCode, SpendingCapability};

    let cap = SpendingCapability {
        max_per_action: Amount(max_per_action),
        max_total: Amount(max_total),
        currency: CurrencyCode::from_code("USD").unwrap_or(CurrencyCode(*b"USD\0")),
        time_window: std::time::Duration::from_hours(1),
        allowed_adapters: vec![],
    };

    // Build the spending UCAN facts: capability + key scope. ADR-039 requires
    // self-delegation tokens (`iss == aud`) to carry `scp_key_scope` so the
    // validator can map `kid` to a verification method.
    let mut fct = serde_json::Map::new();
    fct.insert(
        "spending_capability".to_owned(),
        cap.to_fact_value().unwrap_or(serde_json::Value::Null),
    );
    fct.insert(
        "scp_key_scope".to_owned(),
        serde_json::Value::String("#agent".to_owned()),
    );

    // Spending attestation. Global scope (`scp:spending:*`) so the same
    // helper works for any test context — `validate_spending_ucan_signed`
    // delegates scope coverage to `validate_spending_ucan`, which accepts
    // global scope as covering any context ID.
    let spending_att = scp_protocol::crypto::ucan::Attenuation {
        with: "scp:spending:*".to_owned(),
        can: "spend".to_owned(),
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Use a unique nonce per call so back-to-back tests cannot collide on
    // the per-context nonce tracker. The standard helper uses unix-millis
    // plus 16 random bytes — sufficient even when tests share a manager.
    let nonce = scp_protocol::crypto::ucan::nonce::generate_nonce(&scp_primitives::SystemClock);

    let header = scp_protocol::crypto::ucan::UcanHeader::with_kid("#agent".to_owned());
    let payload = scp_protocol::crypto::ucan::UcanPayload {
        iss: actor_did.as_ref().to_owned(),
        aud: actor_did.as_ref().to_owned(),
        exp: now + 3600, // 1 hour — within the 24-hour spending UCAN ceiling.
        nbf: Some(now.saturating_sub(60)), // tolerate small clock skew in CI runners
        nnc: nonce,
        att: vec![spending_att],
        prf: vec![],
        fct: Some(serde_json::Value::Object(fct)),
    };

    if !signed {
        // Legacy unsigned shape — preserved so the zero-arg
        // `dummy_spending_ucan()` helper does not break tests that
        // (a) only exercise the tool-invoke path or (b) only assert
        // rejection. The token IS still rejected by the C1 signature
        // pipeline; that rejection is the test's expected outcome.
        return UcanToken {
            header,
            payload,
            signature: Vec::new(),
            encoded: "test.spending.ucan.unsigned".to_owned(),
        };
    }

    // JWT-encode header.payload, sign with the deterministic test signing
    // key for this DID. `mock_key_resolver` returns the matching verifying
    // key, so the validator's signature check will pass.
    let header_json = serde_json::to_vec(&header).expect("header serializes");
    let payload_json = serde_json::to_vec(&payload).expect("payload serializes");
    let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
    let signing_input = format!("{header_b64}.{payload_b64}");

    let signing_key = signing_key_for_did(actor_did);
    let signature = ed25519_dalek::Signer::sign(&signing_key, signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let encoded = format!("{signing_input}.{sig_b64}");

    UcanToken {
        header,
        payload,
        signature: signature.to_bytes().to_vec(),
        encoded,
    }
}

// -----------------------------------------------------------------------
// Reusable mock providers
// -----------------------------------------------------------------------

#[derive(Default)]
#[allow(
    clippy::disallowed_types,
    reason = "Test scaffolding for `std::sync::Mutex`-based test harnesses; migrated to `tokio::sync::Mutex` in commit 11 of ADR-049 (actor refactor), where all 8 submodule handlers complete their migration. See plan §Commit ladder."
)]
pub(super) struct MockCrypto {
    pub(super) fail_create_mls: AtomicBool,
    pub(super) fail_validate_key_package: AtomicBool,
    pub(super) fail_advance_epoch: AtomicBool,
    pub(super) fail_remove_member: AtomicBool,
    pub(super) fail_remove_member_sender_key: AtomicBool,
    pub(super) fail_rotate_sender_key: AtomicBool,
    /// H3: when set, `drain_pending_sender_key_messages` returns an error.
    /// Used to assert that `join_context` rolls back MLS + economy state
    /// when sender key drain fails catastrophically.
    pub(super) fail_drain_pending_sender_key_messages: AtomicBool,
    /// AC3 bug 2: when set, `export_crypto_state` returns an error so the
    /// `persist_context_snapshot` error branch is exercised and verified
    /// to mark the persisted snapshot with `needs_reconnect = true`.
    pub(super) fail_export_crypto_state: AtomicBool,
    pub(super) mls_created: std::sync::Mutex<Vec<[u8; 32]>>,
    pub(super) sender_keys_created: std::sync::Mutex<Vec<[u8; 32]>>,
    pub(super) broadcast_created: std::sync::Mutex<Vec<[u8; 32]>>,
    pub(super) mls_destroyed: std::sync::Mutex<Vec<[u8; 32]>>,
    pub(super) sender_keys_destroyed: std::sync::Mutex<Vec<[u8; 32]>>,
    pub(super) members_added: std::sync::Mutex<Vec<String>>,
    pub(super) members_removed: std::sync::Mutex<Vec<String>>,
    pub(super) sender_keys_distributed: std::sync::Mutex<Vec<String>>,
    pub(super) sender_keys_removed: std::sync::Mutex<Vec<String>>,
    pub(super) sender_keys_rotated: std::sync::Mutex<Vec<[u8; 32]>>,
    pub(super) messages_encrypted: std::sync::Mutex<Vec<Vec<u8>>>,
    pub(super) epochs_advanced: std::sync::Mutex<Vec<[u8; 32]>>,
    /// Shared handle for test code to observe `advance_epoch` calls after
    /// the mock has been moved into the `ContextManager`.
    pub(super) epochs_advanced_shared: Arc<std::sync::Mutex<Vec<[u8; 32]>>>,
    /// Shared ordered call log for verifying cross-method call ordering.
    /// Each entry is a (`method_name`, arg) tuple recorded in call order.
    /// Used by `sender_key_before_mls_removal_ordering` to verify that
    /// `remove_member_sender_key` is called before `remove_member`.
    pub(super) call_order: Arc<std::sync::Mutex<Vec<(String, String)>>>,
    /// Per-context per-sender epoch floors, keyed by `hex(context_id)`.
    /// Tests seed this to simulate pre-existing epoch state before import.
    pub(super) epoch_floors:
        std::sync::Mutex<std::collections::HashMap<String, Vec<(String, u64)>>>,
    /// Epoch floors to be installed by `restore_crypto_state` for the NEXT
    /// call. Tests pre-populate this to simulate incoming snapshot epochs.
    pub(super) pending_restore_epochs: std::sync::Mutex<Option<Vec<(String, u64)>>>,
}

impl ContextCryptoProvider for MockCrypto {
    fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn create_mls_group(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        if self.fail_create_mls.load(Ordering::Relaxed) {
            return Err(ContextCreationError::CryptoFailed("mock failure".into()));
        }
        self.mls_created.lock().unwrap().push(*id);
        Ok(())
    }

    fn generate_sender_key(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.sender_keys_created.lock().unwrap().push(*id);
        Ok(())
    }

    fn init_broadcast_key(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.broadcast_created.lock().unwrap().push(*id);
        Ok(())
    }

    fn destroy_mls_group(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.mls_destroyed.lock().unwrap().push(*id);
        Ok(())
    }

    fn destroy_sender_key(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.sender_keys_destroyed.lock().unwrap().push(*id);
        Ok(())
    }

    fn validate_key_package(
        &self,
        _owner_did: &str,
        _key_package_bytes: Option<&[u8]>,
    ) -> Result<(), ContextError> {
        if self.fail_validate_key_package.load(Ordering::Relaxed) {
            return Err(ContextError::InvalidKeyPackage("mock invalid".into()));
        }
        Ok(())
    }

    fn add_member(
        &self,
        _context_id: &[u8; 32],
        member_did: &str,
        _key_package_bytes: Option<&[u8]>,
    ) -> Result<scp_protocol::context::builder::AddMemberOutput, ContextError> {
        self.members_added
            .lock()
            .unwrap()
            .push(member_did.to_owned());
        Ok(scp_protocol::context::builder::AddMemberOutput::default())
    }

    fn remove_member(
        &self,
        _context_id: &[u8; 32],
        member_did: &str,
    ) -> Result<scp_protocol::context::builder::RemoveMemberOutput, ContextError> {
        if self.fail_remove_member.load(Ordering::Relaxed) {
            return Err(ContextError::MembershipFailed(
                "mock remove_member failure".into(),
            ));
        }
        self.members_removed
            .lock()
            .unwrap()
            .push(member_did.to_owned());
        self.call_order
            .lock()
            .unwrap()
            .push(("remove_member".to_owned(), member_did.to_owned()));
        // Return a non-empty stub commit so the broadcast retry path
        // (PR #1606 C6 helpers) is exercised by the manager. Production
        // MLS providers always return non-empty `commit_bytes` here.
        Ok(scp_protocol::context::builder::RemoveMemberOutput {
            commit_bytes: vec![0xC0, 0x6E, 0x57],
            group_info_bytes: Vec::new(),
        })
    }

    fn distribute_sender_key(
        &self,
        _context_id: &[u8; 32],
        member_did: &str,
    ) -> Result<(), ContextError> {
        self.sender_keys_distributed
            .lock()
            .unwrap()
            .push(member_did.to_owned());
        Ok(())
    }

    fn drain_pending_sender_key_messages(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<Vec<(String, Vec<u8>)>, ContextError> {
        if self
            .fail_drain_pending_sender_key_messages
            .load(Ordering::Relaxed)
        {
            return Err(ContextError::CryptoFailed(
                "mock drain_pending_sender_key_messages failure".into(),
            ));
        }
        // Default behavior: no pending distributions. Real distributions
        // are exercised at the provider level (welcome_delivery.rs).
        Ok(Vec::new())
    }

    fn remove_member_sender_key(
        &self,
        _context_id: &[u8; 32],
        member_did: &str,
    ) -> Result<(), ContextError> {
        if self.fail_remove_member_sender_key.load(Ordering::Relaxed) {
            return Err(ContextError::CryptoFailed(
                "mock remove_member_sender_key failure".into(),
            ));
        }
        self.sender_keys_removed
            .lock()
            .unwrap()
            .push(member_did.to_owned());
        self.call_order
            .lock()
            .unwrap()
            .push(("remove_member_sender_key".to_owned(), member_did.to_owned()));
        Ok(())
    }

    fn rotate_sender_key(&self, context_id: &[u8; 32]) -> Result<(), ContextError> {
        if self.fail_rotate_sender_key.load(Ordering::Relaxed) {
            return Err(ContextError::CryptoFailed(
                "mock rotate_sender_key failure".into(),
            ));
        }
        self.sender_keys_rotated.lock().unwrap().push(*context_id);
        self.call_order
            .lock()
            .unwrap()
            .push(("rotate_sender_key".to_owned(), hex::encode(context_id)));
        Ok(())
    }

    fn seal(
        &self,
        _context_id: &[u8; 32],
        inner: &scp_protocol::envelope::inner::InnerEnvelope,
        _routing_id: &[u8],
        _blob_ttl: u32,
    ) -> Result<Vec<u8>, ContextError> {
        self.messages_encrypted
            .lock()
            .unwrap()
            .push(inner.payload.clone());
        // Mock: serialize inner envelope directly (no encryption).
        rmp_serde::to_vec_named(inner)
            .map_err(|e| ContextError::CryptoFailed(format!("mock seal: {e}")))
    }

    fn open(
        &self,
        _context_id: &[u8; 32],
        outer_bytes: &[u8],
    ) -> Result<scp_protocol::context::builder::OpenResult, ContextError> {
        // Mock: deserialize directly as InnerEnvelope (no decryption).
        let inner: scp_protocol::envelope::inner::InnerEnvelope =
            rmp_serde::from_slice(outer_bytes)
                .map_err(|e| ContextError::CryptoFailed(format!("mock open: {e}")))?;
        let sender_did = inner.sender_did.clone();
        Ok(scp_protocol::context::builder::OpenResult::Application(
            Box::new(scp_protocol::context::builder::OpenedEnvelope { inner, sender_did }),
        ))
    }

    fn advance_epoch(
        &self,
        context_id: &[u8; 32],
    ) -> Result<scp_protocol::context::builder::AdvanceEpochOutput, ContextError> {
        if self.fail_advance_epoch.load(Ordering::Relaxed) {
            return Err(ContextError::CryptoFailed(
                "mock advance_epoch failure".into(),
            ));
        }
        self.epochs_advanced.lock().unwrap().push(*context_id);
        self.epochs_advanced_shared
            .lock()
            .unwrap()
            .push(*context_id);
        // Return a non-empty stub commit so the broadcast retry path
        // (PR #1606 C6 helpers) is exercised by the manager.
        Ok(scp_protocol::context::builder::AdvanceEpochOutput {
            commit_bytes: vec![0xEA, 0xC0, 0x06],
        })
    }

    fn export_sender_key_epochs(&self, context_id: &[u8; 32]) -> Vec<(String, u64)> {
        let ctx_key = hex::encode(context_id);
        self.epoch_floors
            .lock()
            .unwrap()
            .get(&ctx_key)
            .cloned()
            .unwrap_or_default()
    }

    fn restore_crypto_state(
        &self,
        context_id: &[u8; 32],
        _data: &[u8],
    ) -> Result<(), ContextError> {
        // If the test staged a set of incoming epoch floors, install them as
        // the restored state for this context (simulating what a real provider
        // does after deserializing an MLS crypto blob).
        let taken = self.pending_restore_epochs.lock().unwrap().take();
        if let Some(epochs) = taken {
            let ctx_key = hex::encode(context_id);
            self.epoch_floors.lock().unwrap().insert(ctx_key, epochs);
        }
        Ok(())
    }

    fn export_crypto_state(&self, _context_id: &[u8; 32]) -> Result<Vec<u8>, ContextError> {
        // AC3 bug 2: return a typed error when the test flag is set, so the
        // `persist_context_snapshot` error branch is exercised. Default path
        // returns an empty blob (matches the trait default).
        if self.fail_export_crypto_state.load(Ordering::Relaxed) {
            return Err(ContextError::CryptoFailed(
                "mock export_crypto_state failure".into(),
            ));
        }
        Ok(Vec::new())
    }

    fn validate_and_merge_epoch_floors(
        &self,
        context_id: &[u8; 32],
        local_floors: Vec<(String, u64)>,
        max_advance_per_sender: u64,
    ) -> Result<(), ContextError> {
        use scp_protocol::crypto::sender_keys::SenderKeyStore;

        if local_floors.is_empty() {
            return Ok(());
        }

        let ctx_id_hex = hex::encode(context_id);

        // Read the import floors installed by `restore_crypto_state`.
        let import_floors = self
            .epoch_floors
            .lock()
            .unwrap()
            .get(&ctx_id_hex)
            .cloned()
            .unwrap_or_default();

        // Validate: seed a temp store with local floors, merge in import floors.
        // Rejects if any import floor regresses below a local floor, or
        // exceeds local + max_advance (epoch-poisoning guard).
        let mut temp_store = SenderKeyStore::new();
        for (did, floor) in &local_floors {
            temp_store.restore_epoch_high_water(&ctx_id_hex, did, *floor);
        }
        temp_store
            .merge_incoming_epochs_with_atomic_reject(
                &ctx_id_hex,
                import_floors,
                max_advance_per_sender,
            )
            .map_err(|per_sender_deltas| ContextError::SnapshotFloorRegression {
                resource: "sender_key_epoch".to_owned(),
                per_sender_deltas,
            })?;

        // Apply merged result (max of local and import) back to the mock.
        let merged = temp_store.epochs_for_context(&ctx_id_hex);
        self.epoch_floors.lock().unwrap().insert(ctx_id_hex, merged);

        Ok(())
    }
}

#[allow(
    clippy::disallowed_types,
    reason = "Test scaffolding for `std::sync::Mutex`-based test harnesses; migrated to `tokio::sync::Mutex` in commit 11 of ADR-049 (actor refactor), where all 8 submodule handlers complete their migration. See plan §Commit ladder."
)]
pub(super) struct MockTransport {
    pub(super) connected: AtomicBool,
    pub(super) published: std::sync::Mutex<Vec<[u8; 32]>>,
    pub(super) deleted: std::sync::Mutex<Vec<[u8; 32]>>,
    pub(super) messages_sent: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    /// Routing IDs passed to `send_message`. Each entry corresponds 1:1
    /// with `messages_sent`.
    pub(super) routing_ids_sent: Arc<std::sync::Mutex<Vec<[u8; 32]>>>,
}

#[allow(
    clippy::disallowed_types,
    reason = "Test scaffolding for `std::sync::Mutex`-based test harnesses; migrated to `tokio::sync::Mutex` in commit 11 of ADR-049 (actor refactor), where all 8 submodule handlers complete their migration. See plan §Commit ladder."
)]
impl Default for MockTransport {
    fn default() -> Self {
        Self {
            connected: AtomicBool::new(false),
            published: std::sync::Mutex::new(Vec::new()),
            deleted: std::sync::Mutex::new(Vec::new()),
            messages_sent: Arc::new(std::sync::Mutex::new(Vec::new())),
            routing_ids_sent: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }
}

#[allow(
    clippy::disallowed_types,
    reason = "Test scaffolding for `std::sync::Mutex`-based test harnesses; migrated to `tokio::sync::Mutex` in commit 11 of ADR-049 (actor refactor), where all 8 submodule handlers complete their migration. See plan §Commit ladder."
)]
impl MockTransport {
    pub(super) fn connected() -> Self {
        let t = Self::default();
        t.connected.store(true, Ordering::Relaxed);
        t
    }

    /// Returns a shared handle to the sent-messages buffer.
    /// Clone before moving the transport into `ContextManager` to observe
    /// transport output from test code.
    pub(super) fn sent_messages_handle(&self) -> Arc<std::sync::Mutex<Vec<Vec<u8>>>> {
        Arc::clone(&self.messages_sent)
    }

    /// Returns a shared handle to the routing IDs buffer.
    pub(super) fn routing_ids_handle(&self) -> Arc<std::sync::Mutex<Vec<[u8; 32]>>> {
        Arc::clone(&self.routing_ids_sent)
    }
}

impl ContextTransportProvider for MockTransport {
    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    fn publish_context(
        &self,
        id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        self.published.lock().unwrap().push(*id);
        Ok(())
    }

    fn delete_published(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.deleted.lock().unwrap().push(*id);
        Ok(())
    }

    fn send_message(
        &self,
        context_id: &[u8; 32],
        encrypted_payload: &[u8],
    ) -> Result<(), ContextError> {
        self.routing_ids_sent.lock().unwrap().push(*context_id);
        self.messages_sent
            .lock()
            .unwrap()
            .push(encrypted_payload.to_vec());
        Ok(())
    }
}

#[derive(Default)]
#[allow(
    clippy::disallowed_types,
    reason = "Test scaffolding for `std::sync::Mutex`-based test harnesses; migrated to `tokio::sync::Mutex` in commit 11 of ADR-049 (actor refactor), where all 8 submodule handlers complete their migration. See plan §Commit ladder."
)]
pub(super) struct MockEventLog {
    pub(super) inited: std::sync::Mutex<Vec<[u8; 32]>>,
    pub(super) events: std::sync::Mutex<Vec<([u8; 32], String)>>,
    /// Full entries for `event_log_entries()` — supports `sync_merkle_tree`.
    full_entries: std::sync::Mutex<Vec<crate::context::providers::event_log::EventLogEntry>>,
    /// Context ID for the current `full_entries` log.
    full_entries_context: std::sync::Mutex<Option<[u8; 32]>>,
    pub(super) destroyed: std::sync::Mutex<Vec<[u8; 32]>>,
}

impl ContextEventLogProvider for MockEventLog {
    fn init_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.inited.lock().unwrap().push(*id);
        Ok(())
    }

    fn append_event(
        &self,
        id: &[u8; 32],
        event: &str,
        actor_did: &str,
        payload: Option<&serde_json::Value>,
    ) -> Result<(), ContextCreationError> {
        self.events.lock().unwrap().push((*id, event.to_owned()));
        // Build a proper EventLogEntry for sync_merkle_tree support.
        let mut full = self.full_entries.lock().unwrap();
        let mut ctx_id = self.full_entries_context.lock().unwrap();
        // Reset if context changes (simple single-context mock).
        if ctx_id.is_none_or(|c| c != *id) {
            full.clear();
            *ctx_id = Some(*id);
        }
        let prev_hash = full.last().map_or([0u8; 32], |e| e.hash);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let hash = crate::context::providers::event_log::entry_hash(
            event, actor_did, timestamp, &prev_hash, payload,
        );
        full.push(crate::context::providers::event_log::EventLogEntry {
            event: event.to_owned(),
            actor_did: actor_did.to_owned(),
            timestamp,
            prev_hash,
            hash,
            payload: payload.cloned(),
        });
        Ok(())
    }

    fn destroy_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.destroyed.lock().unwrap().push(*id);
        Ok(())
    }

    fn event_log_entries(
        &self,
        context_id: &[u8; 32],
    ) -> Result<
        Option<Vec<crate::context::providers::event_log::EventLogEntry>>,
        scp_protocol::context::ContextError,
    > {
        let full = self.full_entries.lock().unwrap();
        let ctx_id = self.full_entries_context.lock().unwrap();
        if ctx_id.is_some_and(|c| c == *context_id) && !full.is_empty() {
            Ok(Some(full.clone()))
        } else {
            Ok(None)
        }
    }
}

/// Extended event log mock that stores `actor_did` and supports
/// `event_log_entries()` reads. Used by tests that verify `actor_did`
/// attribution on event log entries (#1594).
#[derive(Default)]
#[allow(
    clippy::disallowed_types,
    reason = "Test scaffolding for `std::sync::Mutex`-based test harnesses; migrated to `tokio::sync::Mutex` in commit 11 of ADR-049 (actor refactor), where all 8 submodule handlers complete their migration. See plan §Commit ladder."
)]
pub(super) struct MockEventLogWithActorDid {
    pub(super) inited: std::sync::Mutex<Vec<[u8; 32]>>,
    /// Each entry: (`context_id`, `event_name`, `actor_did`, timestamp, payload).
    pub(super) entries:
        std::sync::Mutex<Vec<([u8; 32], String, String, u64, Option<serde_json::Value>)>>,
    pub(super) destroyed: std::sync::Mutex<Vec<[u8; 32]>>,
}

impl ContextEventLogProvider for MockEventLogWithActorDid {
    fn init_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.inited.lock().unwrap().push(*id);
        Ok(())
    }

    fn append_event(
        &self,
        id: &[u8; 32],
        event: &str,
        actor_did: &str,
        payload: Option<&serde_json::Value>,
    ) -> Result<(), ContextCreationError> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.entries.lock().unwrap().push((
            *id,
            event.to_owned(),
            actor_did.to_owned(),
            ts,
            payload.cloned(),
        ));
        Ok(())
    }

    fn destroy_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.destroyed.lock().unwrap().push(*id);
        Ok(())
    }

    fn event_log_entries(
        &self,
        context_id: &[u8; 32],
    ) -> Result<Option<Vec<crate::context::providers::event_log::EventLogEntry>>, ContextError>
    {
        let entries = self.entries.lock().unwrap();
        let result: Vec<_> = entries
            .iter()
            .filter(|(cid, _, _, _, _)| cid == context_id)
            .map(|(_, event, actor_did, ts, payload)| {
                crate::context::providers::event_log::EventLogEntry {
                    event: event.clone(),
                    actor_did: actor_did.clone(),
                    timestamp: *ts,
                    prev_hash: [0u8; 32],
                    hash: [0u8; 32],
                    payload: payload.clone(),
                }
            })
            .collect();
        if result.is_empty() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }
}

/// Thin wrapper that delegates `ContextEventLogProvider` to an
/// `Arc<MockEventLogWithActorDid>`, allowing tests to inspect the event log
/// entries after the `ContextManager` has been constructed.
pub(super) struct ArcEventLog(pub(super) std::sync::Arc<MockEventLogWithActorDid>);

impl ContextEventLogProvider for ArcEventLog {
    fn init_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.init_event_log(id)
    }

    fn append_event(
        &self,
        id: &[u8; 32],
        event: &str,
        actor_did: &str,
        payload: Option<&serde_json::Value>,
    ) -> Result<(), ContextCreationError> {
        self.0.append_event(id, event, actor_did, payload)
    }

    fn destroy_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.destroy_event_log(id)
    }

    fn event_log_entries(
        &self,
        context_id: &[u8; 32],
    ) -> Result<Option<Vec<crate::context::providers::event_log::EventLogEntry>>, ContextError>
    {
        self.0.event_log_entries(context_id)
    }
}

/// Records the relative call order of `append_event` and `event_log_entries`
/// so structural tests can assert that an append for a given event happened
/// BEFORE a subsequent read. Used by H5 to verify that
/// `deliver_incoming` appends `MessageReceived` to the durable event log
/// before invoking the receive-side consequence evaluation block (which
/// calls `event_log_entries_for_consequences`, which in turn calls
/// `event_log_entries`).
///
/// Each call records `(operation_kind, optional_event_name, monotonic_seq)`.
#[derive(Default)]
#[allow(
    clippy::disallowed_types,
    reason = "Test scaffolding for `std::sync::Mutex`-based test harnesses; migrated to `tokio::sync::Mutex` in commit 11 of ADR-049 (actor refactor), where all 8 submodule handlers complete their migration. See plan §Commit ladder."
)]
pub(super) struct OrderedMockEventLog {
    pub(super) inited: std::sync::Mutex<Vec<[u8; 32]>>,
    pub(super) entries:
        std::sync::Mutex<Vec<([u8; 32], String, String, u64, Option<serde_json::Value>)>>,
    pub(super) destroyed: std::sync::Mutex<Vec<[u8; 32]>>,
    /// Monotonic operation log: each tuple is (kind, `event_name_or_empty`, seq).
    /// `kind` is `"append"` or `"read"`. `seq` is a monotonic counter assigned
    /// from `next_seq` at the moment the operation completes.
    pub(super) op_log: std::sync::Mutex<Vec<(String, String, u64)>>,
    pub(super) next_seq: std::sync::atomic::AtomicU64,
}

impl OrderedMockEventLog {
    fn record(&self, kind: &str, event_name: &str) -> u64 {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        self.op_log
            .lock()
            .unwrap()
            .push((kind.to_owned(), event_name.to_owned(), seq));
        seq
    }
}

impl ContextEventLogProvider for OrderedMockEventLog {
    fn init_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.inited.lock().unwrap().push(*id);
        Ok(())
    }

    fn append_event(
        &self,
        id: &[u8; 32],
        event: &str,
        actor_did: &str,
        payload: Option<&serde_json::Value>,
    ) -> Result<(), ContextCreationError> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.entries.lock().unwrap().push((
            *id,
            event.to_owned(),
            actor_did.to_owned(),
            ts,
            payload.cloned(),
        ));
        self.record("append", event);
        Ok(())
    }

    fn destroy_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.destroyed.lock().unwrap().push(*id);
        Ok(())
    }

    fn event_log_entries(
        &self,
        context_id: &[u8; 32],
    ) -> Result<Option<Vec<crate::context::providers::event_log::EventLogEntry>>, ContextError>
    {
        let entries = self.entries.lock().unwrap();
        let result: Vec<_> = entries
            .iter()
            .filter(|(cid, _, _, _, _)| cid == context_id)
            .map(|(_, event, actor_did, ts, payload)| {
                crate::context::providers::event_log::EventLogEntry {
                    event: event.clone(),
                    actor_did: actor_did.clone(),
                    timestamp: *ts,
                    prev_hash: [0u8; 32],
                    hash: [0u8; 32],
                    payload: payload.clone(),
                }
            })
            .collect();
        drop(entries);
        self.record("read", "");
        if result.is_empty() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }
}

/// Thin wrapper that delegates `ContextEventLogProvider` to an
/// `Arc<OrderedMockEventLog>`, allowing the test to retain a handle on the
/// underlying mock and inspect the recorded operation log after
/// `ContextManager` has been constructed.
pub(super) struct ArcOrderedEventLog(pub(super) std::sync::Arc<OrderedMockEventLog>);

impl ContextEventLogProvider for ArcOrderedEventLog {
    fn init_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.init_event_log(id)
    }

    fn append_event(
        &self,
        id: &[u8; 32],
        event: &str,
        actor_did: &str,
        payload: Option<&serde_json::Value>,
    ) -> Result<(), ContextCreationError> {
        self.0.append_event(id, event, actor_did, payload)
    }

    fn destroy_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.destroy_event_log(id)
    }

    fn event_log_entries(
        &self,
        context_id: &[u8; 32],
    ) -> Result<Option<Vec<crate::context::providers::event_log::EventLogEntry>>, ContextError>
    {
        self.0.event_log_entries(context_id)
    }
}

/// Event log mock with clock-controlled timestamps. Identical to
/// [`MockEventLogWithActorDid`] except that `append_event` reads the
/// current time from a caller-supplied [`Clock`] instead of [`SystemTime`].
/// Used by H5 behavioural tests so the same [`TestClock`] instance can
/// drive both the manager (`now = clock.now_secs()` inside `deliver_incoming`)
/// and the event log entries it produces (timestamps written by
/// `append_event`). Without a shared clock the mock would stamp new entries
/// with wall-clock seconds, which the window filter inside
/// `evaluate_consequence_rules` would reject (`event.timestamp <= now`).
#[allow(
    clippy::disallowed_types,
    reason = "Test scaffolding for `std::sync::Mutex`-based test harnesses; migrated to `tokio::sync::Mutex` in commit 11 of ADR-049 (actor refactor), where all 8 submodule handlers complete their migration. See plan §Commit ladder."
)]
pub(super) struct ClockedMockEventLog {
    pub(super) inited: std::sync::Mutex<Vec<[u8; 32]>>,
    pub(super) entries:
        std::sync::Mutex<Vec<([u8; 32], String, String, u64, Option<serde_json::Value>)>>,
    pub(super) destroyed: std::sync::Mutex<Vec<[u8; 32]>>,
    pub(super) clock: Arc<dyn scp_primitives::Clock>,
}

#[allow(
    clippy::disallowed_types,
    reason = "Test scaffolding for `std::sync::Mutex`-based test harnesses; migrated to `tokio::sync::Mutex` in commit 11 of ADR-049 (actor refactor), where all 8 submodule handlers complete their migration. See plan §Commit ladder."
)]
impl ClockedMockEventLog {
    pub(super) fn new(clock: Arc<dyn scp_primitives::Clock>) -> Self {
        Self {
            inited: std::sync::Mutex::new(Vec::new()),
            entries: std::sync::Mutex::new(Vec::new()),
            destroyed: std::sync::Mutex::new(Vec::new()),
            clock,
        }
    }
}

impl ContextEventLogProvider for ClockedMockEventLog {
    fn init_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.inited.lock().unwrap().push(*id);
        Ok(())
    }

    fn append_event(
        &self,
        id: &[u8; 32],
        event: &str,
        actor_did: &str,
        payload: Option<&serde_json::Value>,
    ) -> Result<(), ContextCreationError> {
        let ts = self.clock.now_secs();
        self.entries.lock().unwrap().push((
            *id,
            event.to_owned(),
            actor_did.to_owned(),
            ts,
            payload.cloned(),
        ));
        Ok(())
    }

    fn destroy_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.destroyed.lock().unwrap().push(*id);
        Ok(())
    }

    fn event_log_entries(
        &self,
        context_id: &[u8; 32],
    ) -> Result<Option<Vec<crate::context::providers::event_log::EventLogEntry>>, ContextError>
    {
        let entries = self.entries.lock().unwrap();
        let result: Vec<_> = entries
            .iter()
            .filter(|(cid, _, _, _, _)| cid == context_id)
            .map(|(_, event, actor_did, ts, payload)| {
                crate::context::providers::event_log::EventLogEntry {
                    event: event.clone(),
                    actor_did: actor_did.clone(),
                    timestamp: *ts,
                    prev_hash: [0u8; 32],
                    hash: [0u8; 32],
                    payload: payload.clone(),
                }
            })
            .collect();
        if result.is_empty() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }
}

/// Thin Arc wrapper for [`ClockedMockEventLog`].
pub(super) struct ArcClockedEventLog(pub(super) std::sync::Arc<ClockedMockEventLog>);

impl ContextEventLogProvider for ArcClockedEventLog {
    fn init_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.init_event_log(id)
    }

    fn append_event(
        &self,
        id: &[u8; 32],
        event: &str,
        actor_did: &str,
        payload: Option<&serde_json::Value>,
    ) -> Result<(), ContextCreationError> {
        self.0.append_event(id, event, actor_did, payload)
    }

    fn destroy_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.destroy_event_log(id)
    }

    fn event_log_entries(
        &self,
        context_id: &[u8; 32],
    ) -> Result<Option<Vec<crate::context::providers::event_log::EventLogEntry>>, ContextError>
    {
        self.0.event_log_entries(context_id)
    }
}

/// Event log mock that succeeds on `init_event_log` but fails on every
/// `append_event` call whose event name matches `fail_event`. Used by H5 to
/// assert that `deliver_incoming` does NOT propagate event log append
/// failures (the receive buffer already holds the message).
#[allow(
    clippy::disallowed_types,
    reason = "Test scaffolding for `std::sync::Mutex`-based test harnesses; migrated to `tokio::sync::Mutex` in commit 11 of ADR-049 (actor refactor), where all 8 submodule handlers complete their migration. See plan §Commit ladder."
)]
pub(super) struct FailingAppendEventLog {
    pub(super) inited: std::sync::Mutex<Vec<[u8; 32]>>,
    /// Successful append entries (those whose event name does NOT match
    /// `fail_event`). Mirrors [`MockEventLog::events`] so the test can
    /// verify that other events still land.
    pub(super) events: std::sync::Mutex<Vec<([u8; 32], String)>>,
    pub(super) destroyed: std::sync::Mutex<Vec<[u8; 32]>>,
    pub(super) fail_event: String,
    pub(super) failed_attempts: std::sync::atomic::AtomicUsize,
}

#[allow(
    clippy::disallowed_types,
    reason = "Test scaffolding for `std::sync::Mutex`-based test harnesses; migrated to `tokio::sync::Mutex` in commit 11 of ADR-049 (actor refactor), where all 8 submodule handlers complete their migration. See plan §Commit ladder."
)]
impl FailingAppendEventLog {
    pub(super) fn new(fail_event: impl Into<String>) -> Self {
        Self {
            inited: std::sync::Mutex::new(Vec::new()),
            events: std::sync::Mutex::new(Vec::new()),
            destroyed: std::sync::Mutex::new(Vec::new()),
            fail_event: fail_event.into(),
            failed_attempts: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl ContextEventLogProvider for FailingAppendEventLog {
    fn init_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.inited.lock().unwrap().push(*id);
        Ok(())
    }

    fn append_event(
        &self,
        id: &[u8; 32],
        event: &str,
        _actor_did: &str,
        _payload: Option<&serde_json::Value>,
    ) -> Result<(), ContextCreationError> {
        if event == self.fail_event {
            self.failed_attempts.fetch_add(1, Ordering::SeqCst);
            return Err(ContextCreationError::EventLogFailed(format!(
                "FailingAppendEventLog: forced failure for event {event}"
            )));
        }
        self.events.lock().unwrap().push((*id, event.to_owned()));
        Ok(())
    }

    fn destroy_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.destroyed.lock().unwrap().push(*id);
        Ok(())
    }
}

/// Thin Arc wrapper for [`FailingAppendEventLog`] (mirrors [`ArcEventLog`]
/// pattern) so tests can keep a handle on the underlying mock.
pub(super) struct ArcFailingAppendEventLog(pub(super) std::sync::Arc<FailingAppendEventLog>);

impl ContextEventLogProvider for ArcFailingAppendEventLog {
    fn init_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.init_event_log(id)
    }

    fn append_event(
        &self,
        id: &[u8; 32],
        event: &str,
        actor_did: &str,
        payload: Option<&serde_json::Value>,
    ) -> Result<(), ContextCreationError> {
        self.0.append_event(id, event, actor_did, payload)
    }

    fn destroy_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.destroy_event_log(id)
    }
}

/// A transport mock that always fails on `send_message`.
/// Used to test that phantom `MessageSent` events are not emitted
/// when transport fails (#1420).
pub(super) struct FailingTransport;

impl ContextTransportProvider for FailingTransport {
    fn is_connected(&self) -> bool {
        true
    }

    fn publish_context(
        &self,
        _id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn delete_published(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn send_message(
        &self,
        _context_id: &[u8; 32],
        _encrypted_payload: &[u8],
    ) -> Result<(), ContextError> {
        Err(ContextError::TransportFailed(
            "mock transport failure".into(),
        ))
    }
}

/// Configurable transport mock used by PR #1606 C6 commit retry tests.
///
/// Each `send_message` call increments a counter and returns either an error
/// or `Ok` based on the remaining `fail_count`. Setting `fail_count = 0`
/// makes the transport always succeed; setting `fail_count = u32::MAX` makes
/// it always fail; any positive value fails that many times then succeeds.
#[allow(
    clippy::disallowed_types,
    reason = "Test scaffolding for `std::sync::Mutex`-based test harnesses; migrated to `tokio::sync::Mutex` in commit 11 of ADR-049 (actor refactor), where all 8 submodule handlers complete their migration. See plan §Commit ladder."
)]
pub(super) struct RetriableMockTransport {
    pub(super) fail_count: std::sync::atomic::AtomicU32,
    pub(super) total_calls: std::sync::atomic::AtomicU32,
    pub(super) last_payload: std::sync::Mutex<Vec<u8>>,
}

#[allow(
    clippy::disallowed_types,
    reason = "Test scaffolding for `std::sync::Mutex`-based test harnesses; migrated to `tokio::sync::Mutex` in commit 11 of ADR-049 (actor refactor), where all 8 submodule handlers complete their migration. See plan §Commit ladder."
)]
impl Default for RetriableMockTransport {
    fn default() -> Self {
        Self {
            fail_count: std::sync::atomic::AtomicU32::new(0),
            total_calls: std::sync::atomic::AtomicU32::new(0),
            last_payload: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl ContextTransportProvider for RetriableMockTransport {
    fn is_connected(&self) -> bool {
        true
    }

    fn publish_context(
        &self,
        _id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn delete_published(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn send_message(
        &self,
        _context_id: &[u8; 32],
        encrypted_payload: &[u8],
    ) -> Result<(), ContextError> {
        self.total_calls.fetch_add(1, Ordering::Relaxed);
        let remaining = self.fail_count.load(Ordering::Relaxed);
        if remaining > 0 {
            // Decrement only if not at sentinel u32::MAX (always-fail).
            if remaining != u32::MAX {
                self.fail_count.store(remaining - 1, Ordering::Relaxed);
            }
            return Err(ContextError::TransportFailed(format!(
                "retriable mock failure (remaining={remaining})"
            )));
        }
        *self.last_payload.lock().unwrap() = encrypted_payload.to_vec();
        Ok(())
    }
}

/// Wrapper that delegates to an `Arc<RetriableMockTransport>` so tests can
/// reach in and tweak `fail_count` after the manager has been constructed.
pub(super) struct ArcRetriableTransport(pub(super) std::sync::Arc<RetriableMockTransport>);

impl ContextTransportProvider for ArcRetriableTransport {
    fn is_connected(&self) -> bool {
        self.0.is_connected()
    }

    fn publish_context(
        &self,
        id: &[u8; 32],
        params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        self.0.publish_context(id, params)
    }

    fn delete_published(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.delete_published(id)
    }

    fn send_message(
        &self,
        context_id: &[u8; 32],
        encrypted_payload: &[u8],
    ) -> Result<(), ContextError> {
        self.0.send_message(context_id, encrypted_payload)
    }
}

// -----------------------------------------------------------------------
// FailingCapturePaymentAdapter — authorizes OK, always fails on capture.
// Used by H19 audit-trail tests.
// -----------------------------------------------------------------------

/// A payment adapter that authorizes successfully but always fails on
/// `capture`. Used to exercise the `PaymentCaptureFailed` audit trail path
/// without requiring a real payment backend (H19).
#[cfg(test)]
pub(super) struct FailingCapturePaymentAdapter;

#[cfg(test)]
impl crate::economy::adapter::PaymentAdapter for FailingCapturePaymentAdapter {
    fn adapter_id(&self) -> &'static str {
        "failing-capture"
    }

    fn capabilities(&self) -> crate::economy::adapter::AdapterCapabilities {
        crate::economy::adapter::AdapterCapabilities {
            supported_currencies: vec![scp_protocol::economy::types::CurrencyCode([85, 83, 68, 0])],
            supports_streaming: false,
            supports_batch_auth: false,
            supports_single_step: true,
            min_amount: None,
            max_amount: None,
            typical_settlement_ms: 0,
            requires_facilitator: false,
        }
    }

    async fn authorize(
        &self,
        payer: &scp_identity::DID,
        payee: &scp_identity::DID,
        amount: scp_protocol::economy::types::Amount,
        currency: scp_protocol::economy::types::CurrencyCode,
        _metadata: crate::economy::adapter::PaymentMetadata,
    ) -> Result<crate::economy::adapter::PaymentAuthorization, crate::economy::adapter::PaymentError>
    {
        Ok(crate::economy::adapter::PaymentAuthorization {
            auth_id: [0u8; 32],
            payer: payer.clone(),
            payee: payee.clone(),
            amount,
            currency,
            adapter_id: "failing-capture".to_owned(),
            created_at: 0,
            expires_at: u64::MAX,
            adapter_state: Vec::new(),
        })
    }

    async fn capture(
        &self,
        _auth: &crate::economy::adapter::PaymentAuthorization,
    ) -> Result<crate::economy::adapter::PaymentReceipt, crate::economy::adapter::PaymentError>
    {
        Err(crate::economy::adapter::PaymentError::AdapterError(
            "simulated capture failure".into(),
        ))
    }

    async fn void(
        &self,
        _auth: &crate::economy::adapter::PaymentAuthorization,
    ) -> Result<(), crate::economy::adapter::PaymentError> {
        Ok(())
    }

    async fn verify_authorization(
        &self,
        _auth: &crate::economy::adapter::PaymentAuthorization,
    ) -> Result<(), crate::economy::adapter::PaymentError> {
        Ok(())
    }

    async fn verify(
        &self,
        _receipt: &crate::economy::adapter::PaymentReceipt,
    ) -> Result<crate::economy::adapter::VerificationResult, crate::economy::adapter::PaymentError>
    {
        Ok(crate::economy::adapter::VerificationResult {
            valid: true,
            adapter_id: "failing-capture".to_owned(),
            verified_amount: scp_protocol::economy::types::Amount(0),
            verified_currency: scp_protocol::economy::types::CurrencyCode([85, 83, 68, 0]),
            verification_timestamp: 0,
        })
    }

    async fn refund(
        &self,
        _receipt: &crate::economy::adapter::PaymentReceipt,
        _amount: Option<scp_protocol::economy::types::Amount>,
    ) -> Result<crate::economy::adapter::RefundConfirmation, crate::economy::adapter::PaymentError>
    {
        Ok(crate::economy::adapter::RefundConfirmation {
            refund_id: [0u8; 32],
            original_receipt_id: [0u8; 32],
            refunded_amount: scp_protocol::economy::types::Amount(0),
            currency: scp_protocol::economy::types::CurrencyCode([85, 83, 68, 0]),
            adapter_proof: Vec::new(),
        })
    }
}

// -----------------------------------------------------------------------
// Helper: build a ContextManager with FailingCapturePaymentAdapter and a
// priced EconomicPolicy. Used by H19 audit-trail tests.
// -----------------------------------------------------------------------

/// Builds a [`ContextManager`] backed by the `FailingCapturePaymentAdapter`
/// and an event log that can be inspected post-run (H19 tests).
///
/// The returned `Arc<MockEventLogWithActorDid>` is the shared handle to the
/// event log; the handle to the newly created context is also returned.
///
/// The manager includes a `MessageSend` and `JoinContext` economic policy
/// with a cost of 1 USD so that `authorize_paid_action` → `capture` actually
/// runs (free contexts skip the capture path).
#[cfg(test)]
pub(super) async fn setup_failing_capture_manager_with_context(
    context_id: &str,
    creator_did: &str,
) -> (
    ContextManager,
    ContextHandle,
    std::sync::Arc<MockEventLogWithActorDid>,
) {
    use std::sync::Arc;

    let event_log = Arc::new(MockEventLogWithActorDid::default());

    // C1b: spending UCANs on the send_message path are cryptographically
    // validated. The mock_key_resolver resolves keys deterministically from
    // the DID, matching dummy_spending_ucan_for's signing key — required for
    // validate_spending_ucan_signed to pass the signature check.
    let manager = ContextManager::builder()
        .crypto(Box::new(MockCrypto::default()))
        .transport(Box::new(MockTransport::connected()))
        .event_log(Box::new(ArcEventLog(event_log.clone())))
        .payment_adapter(Arc::new(FailingCapturePaymentAdapter))
        .key_resolver(mock_key_resolver())
        .build()
        .unwrap();

    // Grant the creator enough budget for the operations under test.
    // We use a non-zero EconomicPolicy so the capture path actually runs.
    let policy = {
        use scp_protocol::economy::types::{Amount, CostSchedule, CurrencyCode, EconomicPolicy};
        EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: CurrencyCode([85, 83, 68, 0]),
                per_message: Some(Amount::new(1)),
                per_tool_invoke: None,
                per_join: Some(Amount::new(1)),
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec!["failing-capture".to_owned()],
            pricing_formula: None,
            payee: DID::from("did:key:payee"),
        }
    };

    let params = ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
            Capability::MemberBan,
        ],
        economic_policy: Some(policy),
        ..ContextParams::default()
    };

    let handle = manager
        .create_context(context_id.into(), params, creator_did.into(), None)
        .await
        .unwrap();

    // Grant a generous budget so economy enforcement passes.
    {
        let arc = manager.get_context_arc(context_id).unwrap();
        let mut g = arc.lock().await;
        let ctx = &mut *g;
        ctx.governance.budget_tracker.grant(
            &DID::from(creator_did),
            scp_protocol::economy::types::Amount::new(1_000_000),
        );
    }

    (manager, handle, event_log)
}

// -----------------------------------------------------------------------
// Helper: create a manager with default mocks and a registered context
// -----------------------------------------------------------------------

pub(super) async fn setup_active_context() -> (ContextManager, ContextHandle) {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let params = ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
            Capability::ToolRegister,
            Capability::ToolInterface,
            Capability::ChildContextCreate,
            Capability::MemberBan,
        ],
        ..ContextParams::default()
    };

    let handle = manager
        .create_context("test-ctx".into(), params, "did:key:creator".into(), None)
        .await
        .unwrap();

    (manager, handle)
}

/// Like `setup_active_context` but uses `mock_key_resolver()` so that
/// checkpoint signature verification succeeds in tests. Use with
/// `signing_key_for_did` to produce correctly-signed checkpoints.
pub(super) async fn setup_active_context_with_key_resolver() -> (ContextManager, ContextHandle) {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );

    let params = ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
            Capability::ToolRegister,
            Capability::ToolInterface,
            Capability::ChildContextCreate,
            Capability::MemberBan,
        ],
        ..ContextParams::default()
    };

    let handle = manager
        .create_context("test-ctx".into(), params, "did:key:creator".into(), None)
        .await
        .unwrap();

    (manager, handle)
}

/// Creates a properly signed [`ConsistencyCheckpoint`] for use in tests.
///
/// The checkpoint is signed using the `signing_key_for_did` helper so
/// that its signature passes `verify_checkpoint_signature` when the
/// manager uses `mock_key_resolver`.
pub(super) fn signed_checkpoint(
    context_id: &str,
    sender_did: &DID,
    event_count: u64,
    merkle_root: [u8; 32],
    epoch: Option<u64>,
    timestamp: u64,
) -> scp_event_log::checkpoint::ConsistencyCheckpoint {
    let sk = signing_key_for_did(sender_did);
    let canonical = scp_event_log::checkpoint::compute_checkpoint_canonical_hash(
        context_id,
        sender_did.as_ref(),
        event_count,
        &merkle_root,
        epoch,
        timestamp,
    );
    let sig = ed25519_dalek::Signer::sign(&sk, &canonical);
    scp_event_log::checkpoint::ConsistencyCheckpoint {
        context_id: context_id.to_owned(),
        sender_did: sender_did.clone(),
        event_count,
        merkle_root,
        epoch,
        timestamp,
        signature: sig.to_bytes().to_vec(),
    }
}

// -----------------------------------------------------------------------
// Shared helpers used across multiple test files
// -----------------------------------------------------------------------

/// Helper: creates an approved governance proposal for an arbitrary action
/// using `SingleAdminEngine`. The admin is `admin_did`.
pub(super) fn approved_governance_proposal(
    admin_did: &DID,
    context_id: &str,
    target_did: &DID,
    action: super::GovernanceAction,
) -> super::GovernanceProposal {
    use scp_protocol::context::governance::{
        GovernanceContext, GovernanceEngine, SingleAdminEngine,
    };

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let vk = signing_key.verifying_key();
    #[allow(clippy::type_complexity)]
    let resolver: std::sync::Arc<
        dyn Fn(&scp_identity::DID) -> Option<ed25519_dalek::VerifyingKey> + Send + Sync,
    > = std::sync::Arc::new(move |_| Some(vk));
    let mut engine = SingleAdminEngine::new(admin_did.clone(), resolver);
    let gov_ctx = GovernanceContext {
        context_id: context_id.to_owned(),
        members: vec![
            (admin_did.clone(), "admin".to_owned()),
            (target_did.clone(), "subscriber".to_owned()),
        ],
        admin_dids: vec![admin_did.clone()],
        current_epoch: None,
        now: 1000,
    };

    let (proposal, _events) = engine
        .propose(admin_did, action, &gov_ctx, &signing_key)
        .unwrap();
    assert!(matches!(proposal.status, super::ProposalStatus::Approved));
    proposal
}

/// Helper to create a broadcast context with two authors (alice + bob).
///
/// Both authors are registered in the `BroadcastContext` (for publish
/// capability) and in `MembershipState` (for sequence number tracking).
/// Both author DIDs are registered as locally controlled (#234).
pub(super) async fn setup_broadcast_context_two_authors() -> (ContextManager, ContextHandle, String)
{
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    // Register both author DIDs as locally controlled (#234).
    manager.register_local_did("did:key:alice".into()).await;
    manager.register_local_did("did:key:bob".into()).await;

    let params = ContextParams {
        mode: ContextMode::Broadcast,
        memory_scope: scp_protocol::context::MemoryScope::Full,
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
            Capability::MemberBan,
        ],
        ..ContextParams::default()
    };

    let handle = manager
        .create_context(
            "broadcast-2auth-ctx".into(),
            params,
            "did:key:alice".into(),
            None,
        )
        .await
        .unwrap();

    // Add bob as a second author: both in BroadcastContext and membership.
    {
        let arc = manager
            .contexts
            .get("broadcast-2auth-ctx")
            .unwrap()
            .value()
            .clone();
        let mut g = arc.lock().await;
        let ctx = &mut *g;
        let bc = ctx.broadcast_context.as_mut().unwrap();
        bc.add_author("did:key:bob").unwrap();
        // Also add to membership tracking so sequence numbers work.
        ctx.membership
            .add_member("did:key:bob".into(), "author".into(), vec![]);
    }

    let ctx_id = "broadcast-2auth-ctx".to_owned();
    (manager, handle, ctx_id)
}

/// Helper: creates a broadcast context with `MemberBan` in ceiling,
/// admin (alice) and subscriber (sub1).
pub(super) async fn setup_broadcast_with_member_ban() -> (ContextManager, String) {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    manager.register_local_did("did:key:alice".into()).await;

    let params = ContextParams {
        mode: ContextMode::Broadcast,
        memory_scope: scp_protocol::context::MemoryScope::Full,
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
            scp_protocol::context::params::Capability::new("member:ban"),
        ],
        ..ContextParams::default()
    };

    let _handle = manager
        .create_context(
            "broadcast-ban-ctx".into(),
            params,
            "did:key:alice".into(),
            None,
        )
        .await
        .unwrap();

    // Subscribe sub1 directly via BroadcastContext.
    {
        use scp_protocol::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                "broadcast-ban-ctx",
                &DID("did:key:sub1".into()),
                None,
                1000,
                None,
            )
            .await
            .unwrap();
    }

    let ctx_id = "broadcast-ban-ctx".to_owned();
    (manager, ctx_id)
}

/// Helper: creates an encrypted context with `MemberBan` in ceiling,
/// admin (alice) and member (bob).
pub(super) async fn setup_encrypted_with_member_ban() -> (ContextManager, String) {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    manager.register_local_did("did:key:alice".into()).await;
    manager.register_local_did("did:key:bob".into()).await;

    let params = ContextParams {
        mode: ContextMode::Encrypted,
        memory_scope: MemoryScope::Full,
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::RoleAssign,
            Capability::MemberBan,
        ],
        ..ContextParams::default()
    };

    let _handle = manager
        .create_context("enc-ban-ctx".into(), params, "did:key:alice".into(), None)
        .await
        .unwrap();

    // Add bob as a member.
    {
        let arc = manager.get_context_arc("enc-ban-ctx").unwrap();
        let mut g = arc.lock().await;
        let ctx = &mut *g;
        ctx.membership
            .add_member("did:key:bob".into(), "member".into(), vec![]);
    }

    (manager, "enc-ban-ctx".to_owned())
}

/// Helper: `ContextParams` with governance-compatible ceiling.
pub(super) fn governance_params() -> ContextParams {
    ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
            scp_protocol::context::params::Capability::new("governance:propose"),
            scp_protocol::context::params::Capability::new("governance:vote"),
            scp_protocol::context::params::Capability::new("member:ban"),
            scp_protocol::context::params::Capability::new("context:close"),
            Capability::ToolRegister,
        ],
        ..ContextParams::default()
    }
}

/// Helper: create a `ToolRegistration` fixture.
pub(super) fn test_tool_registration(id: &str) -> ToolRegistration {
    use scp_protocol::context::tools::registry::{TestVector, ToolSchema};
    ToolRegistration {
        tool_id: id.to_owned(),
        name: id.to_owned(),
        description: "test tool".to_owned(),
        schema: ToolSchema {
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
        },
        implementation_hash: [0u8; 32],
        test_vectors: vec![TestVector {
            input: serde_json::json!({}),
            expected_output: serde_json::json!({}),
            description: "noop".to_owned(),
        }],
        operator_did: "did:key:test-operator".into(),
        cost: None,
        registered_at: 0,
        signature: Vec::new(),
    }
}

/// Helper: creates a broadcast context with an author (author1),
/// registers `did:key:author1` as a local DID.
pub(super) async fn setup_broadcast_context() -> (ContextManager, ContextHandle, String) {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    // Register the author DID as locally controlled (#234).
    manager.register_local_did("did:key:author1".into()).await;

    let params = ContextParams {
        mode: ContextMode::Broadcast,
        memory_scope: scp_protocol::context::MemoryScope::Full,
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
        ],
        ..ContextParams::default()
    };

    let handle = manager
        .create_context(
            "broadcast-ctx".into(),
            params,
            "did:key:author1".into(),
            None,
        )
        .await
        .unwrap();

    (manager, handle, "broadcast-ctx".into())
}

/// Helper: creates an approved `Revoke` (write) governance proposal using
/// `SingleAdminEngine` (admin = `admin_did`). Returns the approved
/// proposal that can be passed to `execute_governance_action()`.
pub(super) fn approved_revoke_proposal(
    admin_did: &DID,
    context_id: &str,
    target_did: &DID,
) -> super::GovernanceProposal {
    use scp_protocol::context::governance::{
        AccessScope, GovernanceAction, GovernanceContext, GovernanceEngine, SingleAdminEngine,
    };

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let vk = signing_key.verifying_key();
    #[allow(clippy::type_complexity)]
    let resolver: std::sync::Arc<
        dyn Fn(&scp_identity::DID) -> Option<ed25519_dalek::VerifyingKey> + Send + Sync,
    > = std::sync::Arc::new(move |_| Some(vk));
    let mut engine = SingleAdminEngine::new(admin_did.clone(), resolver);
    let gov_ctx = GovernanceContext {
        context_id: context_id.to_owned(),
        members: vec![
            (admin_did.clone(), "admin".to_owned()),
            (target_did.clone(), "author".to_owned()),
        ],
        admin_dids: vec![admin_did.clone()],
        current_epoch: None,
        now: 1000,
    };

    let action = GovernanceAction::RevokeAccess {
        did: target_did.clone(),
        access: AccessScope::Write,
    };

    let (proposal, _events) = engine
        .propose(admin_did, action, &gov_ctx, &signing_key)
        .unwrap();
    assert!(matches!(proposal.status, super::ProposalStatus::Approved));
    proposal
}
