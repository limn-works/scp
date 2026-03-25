//! Shared key exchange for coordinating Welcome messages and sender keys
//! between separate `E2eCryptoProvider` instances.
//!
//! In production, Welcome messages travel over transport and sender keys are
//! exchanged via the HPKE pull protocol. In tests, the `KeyExchange` struct
//! acts as a side channel that bridges these materials between two independent
//! crypto providers without requiring transport wiring.

use std::collections::HashMap;

use openmls::prelude::MlsMessageOut;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use scp_core::crypto::access_keys::AccessKey;
use scp_core::crypto::sender_keys::SenderKey;

/// A Welcome message + the joiner's MLS signer and provider, captured when
/// `add_member` is called on the adder's side. The joiner retrieves this to
/// form their MLS group state via `join_group`.
pub struct PendingWelcome {
    /// The MLS Welcome message (HPKE-encrypted to the joiner's key package).
    pub welcome: MlsMessageOut,
    /// The joiner's MLS signature key pair (generated during `generate_key_package`).
    pub signer: SignatureKeyPair,
    /// The joiner's `OpenMLS` crypto+storage provider.
    pub provider: OpenMlsRustCrypto,
}

/// Shared key exchange between `E2eCryptoProvider` instances.
///
/// Thread-safe via external `std::sync::Mutex` wrapping. The exchange is
/// keyed by `(context_id_bytes, joiner_did)` for Welcomes and
/// `(context_id_hex, sender_did, target_did)` for sender keys.
pub struct KeyExchange {
    /// Pending Welcome messages: `(context_id, joiner_did) -> PendingWelcome`.
    welcomes: HashMap<([u8; 32], String), PendingWelcome>,
    /// Sender keys deposited for target members:
    /// `(context_id_hex, sender_did, target_did) -> SenderKey`.
    sender_keys: HashMap<(String, String, String), SenderKey>,
    /// Pending MLS commits for existing members to process.
    /// `(context_id, target_did) -> Vec<commit_bytes>`.
    /// When Alice adds Carol, she deposits the Commit for Bob to process
    /// so Bob's MLS group advances to the same epoch.
    pending_commits: HashMap<([u8; 32], String), Vec<Vec<u8>>>,
    /// Access keys deposited for joiners:
    /// `(context_id_str, target_joiner_did) -> Vec<(member_did, AccessKey)>`.
    /// When Alice adds Bob, she deposits ALL existing members' access keys
    /// (including Bob's and her own) here so Bob can retrieve them during
    /// `join_from_welcome`. Using a Vec allows multiple keys per joiner.
    access_keys: HashMap<(String, String), Vec<(String, AccessKey)>>,
}

impl KeyExchange {
    /// Creates an empty key exchange.
    #[must_use]
    pub fn new() -> Self {
        Self {
            welcomes: HashMap::new(),
            sender_keys: HashMap::new(),
            pending_commits: HashMap::new(),
            access_keys: HashMap::new(),
        }
    }

    /// Deposits a Welcome message for a joiner to retrieve later.
    pub fn deposit_welcome(
        &mut self,
        context_id: [u8; 32],
        joiner_did: &str,
        welcome: PendingWelcome,
    ) {
        self.welcomes
            .insert((context_id, joiner_did.to_owned()), welcome);
    }

    /// Takes (removes) the Welcome message for the given joiner.
    ///
    /// Returns `None` if no Welcome has been deposited for this
    /// `(context_id, joiner_did)` pair.
    pub fn take_welcome(
        &mut self,
        context_id: &[u8; 32],
        joiner_did: &str,
    ) -> Option<PendingWelcome> {
        self.welcomes.remove(&(*context_id, joiner_did.to_owned()))
    }

    /// Deposits a sender key for a target member to retrieve.
    pub fn deposit_sender_key(
        &mut self,
        context_id_hex: &str,
        sender_did: &str,
        target_did: &str,
        key: SenderKey,
    ) {
        self.sender_keys.insert(
            (
                context_id_hex.to_owned(),
                sender_did.to_owned(),
                target_did.to_owned(),
            ),
            key,
        );
    }

    /// Deposits a serialized MLS Commit for an existing group member to process.
    ///
    /// When a new member is added, the Commit must be distributed to all
    /// existing members so their MLS groups advance to the new epoch.
    pub fn deposit_commit(
        &mut self,
        context_id: [u8; 32],
        target_did: &str,
        commit_bytes: Vec<u8>,
    ) {
        self.pending_commits
            .entry((context_id, target_did.to_owned()))
            .or_default()
            .push(commit_bytes);
    }

    /// Takes all pending commits for the given member in a context.
    ///
    /// Returns the commit bytes in deposit order. The caller must process
    /// them sequentially to advance the MLS group epoch correctly.
    pub fn take_commits(&mut self, context_id: &[u8; 32], member_did: &str) -> Vec<Vec<u8>> {
        self.pending_commits
            .remove(&(*context_id, member_did.to_owned()))
            .unwrap_or_default()
    }

    /// Deposits an access key for a joiner to retrieve during `join_from_welcome`.
    ///
    /// The key is associated with `target_joiner_did` -- the DID of the member
    /// who will pick it up. `member_did` identifies WHOSE access key this is.
    /// Call once per existing member when adding a new joiner.
    pub fn deposit_access_key(
        &mut self,
        context_id: &str,
        target_joiner_did: &str,
        member_did: &str,
        key: AccessKey,
    ) {
        self.access_keys
            .entry((context_id.to_owned(), target_joiner_did.to_owned()))
            .or_default()
            .push((member_did.to_owned(), key));
    }

    /// Takes (removes) all access keys deposited for the given joiner.
    ///
    /// Returns `(member_did, AccessKey)` pairs. Returns an empty Vec if
    /// no keys have been deposited for this joiner.
    pub fn take_access_keys(
        &mut self,
        context_id: &str,
        joiner_did: &str,
    ) -> Vec<(String, AccessKey)> {
        self.access_keys
            .remove(&(context_id.to_owned(), joiner_did.to_owned()))
            .unwrap_or_default()
    }

    /// Takes all sender keys deposited for the given target in a context.
    ///
    /// Returns `(sender_did, SenderKey)` pairs.
    pub fn take_sender_keys(
        &mut self,
        context_id_hex: &str,
        target_did: &str,
    ) -> Vec<(String, SenderKey)> {
        let mut result = Vec::new();
        let keys_to_remove: Vec<_> = self
            .sender_keys
            .keys()
            .filter(|(ctx, _, target)| ctx == context_id_hex && target == target_did)
            .cloned()
            .collect();
        for key in keys_to_remove {
            if let Some(sk) = self.sender_keys.remove(&key) {
                result.push((key.1, sk));
            }
        }
        result
    }
}

impl Default for KeyExchange {
    fn default() -> Self {
        Self::new()
    }
}
