//! Serializable snapshot of an [`ScpMlsGroup`]'s in-memory state.
//!
//! The native runtime persists MLS crypto state by snapshotting the in-memory
//! `OpenMLS` provider out-of-band (§17.9.1); an in-browser client does the same,
//! backing the blob with `IndexedDB`/OPFS (ADR-057 component 3). Both need one
//! operation to serialize an `ScpMlsGroup` — the `OpenMLS` `MemoryStorage`
//! contents (group tree, epoch secrets, key schedule), the group id required to
//! reload it, and the Ed25519 MLS signer — into a single opaque blob, and one to
//! reconstruct a live group from it.
//!
//! This module owns exactly that primitive. It lives in `scp-mls` (not the
//! callers) because the `OpenMLS` provider internals — `provider().storage()`,
//! `MlsGroup::load`, [`ScpMlsGroup::from_parts`] — are this crate's concern; a
//! caller should serialize a group without reaching into openmls. The mechanics
//! mirror the proven native-runtime `export_crypto_state` / `restore_crypto_state`
//! path (`scp-runtime/src/crypto/mls/provider.rs`, §17.9.1) so both targets
//! round-trip identically.
//!
//! # Security — this blob contains raw private key material
//!
//! [`MlsGroupSnapshot`] carries the Ed25519 signer private key and the `OpenMLS`
//! `MemoryStorage` dump (which includes MLS epoch secrets and HPKE private
//! keys). It is NOT self-encrypting: the `Storage` backend that persists it MUST
//! provide encryption at rest (§17.5, and the ADR-057 tab-boundary consequence —
//! the browser tab is the plaintext/custody boundary). [`ScpMlsGroup::serialize_state`]
//! and [`ScpMlsGroup::deserialize_state`] zeroize the intermediate snapshot
//! struct's key-bearing fields after use to minimize the window where private
//! keys sit as structured, easily-extractable data in memory.

use openmls::prelude::{GroupId, MlsGroup};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::InMemoryMlsProvider;
use crate::error::MlsError;
use crate::group::ScpMlsGroup;

/// A serializable snapshot of an [`ScpMlsGroup`]'s in-memory state.
///
/// Round-trips through [`ScpMlsGroup::serialize_state`] /
/// [`ScpMlsGroup::deserialize_state`]. See the module docs for the security
/// contract (raw private key material; storage-layer encryption-at-rest is
/// required). Serialized with `MessagePack` (`rmp_serde`), the codebase's
/// name-tagged, width-/endianness-independent wire form (ADR-057), so a native
/// and a wasm32 build produce a byte-compatible encoding.
#[derive(Serialize, Deserialize)]
pub struct MlsGroupSnapshot {
    /// The raw key-value pairs from the `OpenMLS` `MemoryStorage` backing the
    /// group. Each pair is `(key_bytes, value_bytes)`. Includes MLS epoch
    /// secrets, HPKE private keys, and the key schedule.
    mls_storage_entries: Vec<(Vec<u8>, Vec<u8>)>,
    /// The MLS signer (`SignatureKeyPair`) serialized to bytes via serde.
    /// `SignatureKeyPair` does not derive `Clone` without the `clonable`
    /// feature, so it is serialized separately and stored here.
    signer_bytes: Vec<u8>,
    /// The MLS group id bytes. Required to call `MlsGroup::load` on restore.
    group_id: Vec<u8>,
}

// SECURITY: manual `Debug` redacts all key-bearing fields. `Clone` is
// intentionally NOT derived — the snapshot holds the Ed25519 signer private key
// and the MLS epoch/HPKE secrets in `mls_storage_entries`, and must not be
// freely duplicated.
impl std::fmt::Debug for MlsGroupSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlsGroupSnapshot")
            .field(
                "mls_storage_entries",
                &format_args!("[{} entries, REDACTED]", self.mls_storage_entries.len()),
            )
            .field("signer_bytes", &"[REDACTED]")
            .field("group_id", &format_args!("[{} bytes]", self.group_id.len()))
            .finish()
    }
}

impl MlsGroupSnapshot {
    /// Zeroizes every field that holds private key material.
    ///
    /// Called after serialization (export) and after reconstruction (restore) so
    /// the raw signer bytes and MLS storage secrets do not linger in the
    /// intermediate struct.
    fn zeroize_secrets(&mut self) {
        self.signer_bytes.zeroize();
        for (_, value) in &mut self.mls_storage_entries {
            value.zeroize();
        }
    }
}

impl ScpMlsGroup {
    /// Serializes this group's full in-memory state into an opaque `MessagePack`
    /// blob for out-of-band persistence (§17.9.1, ADR-057 component 3).
    ///
    /// Captures the `OpenMLS` provider storage, the group id, and the MLS signer —
    /// everything [`Self::deserialize_state`] needs to reconstruct a live group.
    /// The intermediate snapshot's key material is zeroized before returning.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::GroupDestroyed`] if the group or signer has already
    /// been destroyed, or [`MlsError::Snapshot`] if the provider-storage lock is
    /// poisoned or `MessagePack` serialization fails.
    pub fn serialize_state(&self) -> Result<Vec<u8>, MlsError> {
        let group_id = self.group_id()?.to_vec();
        let signer = self.signer_key_pair()?;

        let signer_bytes = rmp_serde::to_vec_named(signer)
            .map_err(|e| MlsError::Snapshot(format!("signer serialization: {e}")))?;

        let mls_storage_entries: Vec<(Vec<u8>, Vec<u8>)> = {
            let values =
                self.provider().storage().values.read().map_err(|e| {
                    MlsError::Snapshot(format!("provider storage lock poisoned: {e}"))
                })?;
            values.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };

        let mut snapshot = MlsGroupSnapshot {
            mls_storage_entries,
            signer_bytes,
            group_id,
        };

        let result = rmp_serde::to_vec_named(&snapshot)
            .map_err(|e| MlsError::Snapshot(format!("snapshot serialization: {e}")));

        // SECURITY: zeroize the intermediate key material regardless of outcome.
        snapshot.zeroize_secrets();

        result
    }

    /// Reconstructs a live [`ScpMlsGroup`] from a blob produced by
    /// [`Self::serialize_state`].
    ///
    /// Rebuilds a fresh in-memory provider, re-injects the persisted storage
    /// entries, restores the signer into the provider key store, reloads the
    /// group via `MlsGroup::load`, and reassembles via [`Self::from_parts`]. The
    /// intermediate snapshot's key material is zeroized before returning.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::Snapshot`] if the blob cannot be deserialized, the
    /// provider-storage lock is poisoned, the signer cannot be re-stored, or the
    /// group cannot be reloaded (`MlsGroup::load` errored or returned `None` —
    /// the blob does not contain a group under the recorded id).
    pub fn deserialize_state(blob: &[u8]) -> Result<Self, MlsError> {
        let mut snapshot: MlsGroupSnapshot = rmp_serde::from_slice(blob)
            .map_err(|e| MlsError::Snapshot(format!("snapshot deserialization: {e}")))?;

        let provider = InMemoryMlsProvider::default();
        {
            let mut values =
                provider.storage().values.write().map_err(|e| {
                    MlsError::Snapshot(format!("provider storage lock poisoned: {e}"))
                })?;
            // Drain so the snapshot no longer holds the MLS storage secrets.
            for (k, v) in snapshot.mls_storage_entries.drain(..) {
                values.insert(k, v);
            }
        }

        let signer: SignatureKeyPair = rmp_serde::from_slice(&snapshot.signer_bytes)
            .map_err(|e| MlsError::Snapshot(format!("signer deserialization: {e}")))?;
        snapshot.signer_bytes.zeroize();

        signer
            .store(provider.storage())
            .map_err(|e| MlsError::Snapshot(format!("signer store failed: {e}")))?;

        let group_id = GroupId::from_slice(&snapshot.group_id);
        let mls_group = MlsGroup::load(provider.storage(), &group_id)
            .map_err(|e| MlsError::Snapshot(format!("MlsGroup::load storage error: {e}")))?
            .ok_or_else(|| {
                MlsError::Snapshot(
                    "MlsGroup::load returned None — group not found in restored storage".to_owned(),
                )
            })?;

        // Belt-and-suspenders: any residual key bytes (should already be
        // drained/zeroized above) are cleared before the snapshot drops.
        snapshot.zeroize_secrets();

        Ok(Self::from_parts(mls_group, provider, signer))
    }
}

/// A serializable snapshot of unconsumed pending-join material.
///
/// Between generating a `KeyPackage` ([`crate::group::generate_key_package`]) and
/// processing the resulting Welcome, a prospective member must retain the private
/// half of that key package — the `OpenMLS` provider storage entries holding the
/// HPKE init/encryption private keys, plus the MLS signer. Unlike
/// [`MlsGroupSnapshot`] there is **no group yet**: this captures a bare
/// `(provider, signer)` pair so an in-browser driver can persist it across a tab
/// close and resume the join on reopen (ADR-057 T2, §17.9.1).
///
/// # Security — this blob contains raw private key material
///
/// Carries the Ed25519 signer private key and the `OpenMLS` `MemoryStorage` dump
/// (HPKE private keys). It is NOT self-encrypting: the `Storage` backend that
/// persists it MUST provide encryption at rest (§17.5, ADR-057 tab boundary).
/// [`serialize_pending_join`] / [`restore_pending_join`] zeroize the intermediate
/// snapshot's key-bearing fields after use.
#[derive(Serialize, Deserialize)]
pub struct PendingJoinSnapshot {
    /// The raw key-value pairs from the `OpenMLS` `MemoryStorage` backing the
    /// pending key package. Each pair is `(key_bytes, value_bytes)`. Includes the
    /// stored signer and the key package's HPKE private keys.
    mls_storage_entries: Vec<(Vec<u8>, Vec<u8>)>,
    /// The MLS signer (`SignatureKeyPair`) serialized to bytes via serde.
    signer_bytes: Vec<u8>,
}

// SECURITY: manual `Debug` redacts all key-bearing fields. `Clone` is
// intentionally NOT derived (holds the signer private key + HPKE secrets).
impl std::fmt::Debug for PendingJoinSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingJoinSnapshot")
            .field(
                "mls_storage_entries",
                &format_args!("[{} entries, REDACTED]", self.mls_storage_entries.len()),
            )
            .field("signer_bytes", &"[REDACTED]")
            .finish()
    }
}

impl PendingJoinSnapshot {
    /// Zeroizes every field that holds private key material.
    fn zeroize_secrets(&mut self) {
        self.signer_bytes.zeroize();
        for (_, value) in &mut self.mls_storage_entries {
            value.zeroize();
        }
    }
}

/// Serializes unconsumed pending-join material for out-of-band persistence.
///
/// Captures a bare `(provider, signer)` pair from
/// [`crate::group::generate_key_package`] into an opaque `MessagePack` blob
/// (§17.9.1, ADR-057 component 3). The inverse is [`restore_pending_join`]. The
/// intermediate snapshot's key material is zeroized before returning.
///
/// # Errors
///
/// Returns [`MlsError::Snapshot`] if the provider-storage lock is poisoned or
/// `MessagePack` serialization fails.
pub fn serialize_pending_join(
    provider: &InMemoryMlsProvider,
    signer: &SignatureKeyPair,
) -> Result<Vec<u8>, MlsError> {
    let signer_bytes = rmp_serde::to_vec_named(signer)
        .map_err(|e| MlsError::Snapshot(format!("pending signer serialization: {e}")))?;

    let mls_storage_entries: Vec<(Vec<u8>, Vec<u8>)> = {
        let values = provider
            .storage()
            .values
            .read()
            .map_err(|e| MlsError::Snapshot(format!("provider storage lock poisoned: {e}")))?;
        values.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    };

    let mut snapshot = PendingJoinSnapshot {
        mls_storage_entries,
        signer_bytes,
    };

    let result = rmp_serde::to_vec_named(&snapshot)
        .map_err(|e| MlsError::Snapshot(format!("pending snapshot serialization: {e}")));

    // SECURITY: zeroize the intermediate key material regardless of outcome.
    snapshot.zeroize_secrets();

    result
}

/// Reconstructs the `(provider, signer)` pair from a pending-join blob.
///
/// Produced by [`serialize_pending_join`]; the returned pair is ready to hand to
/// [`crate::group::join_group_from_bytes`] when the Welcome arrives.
/// Rebuilds a fresh in-memory provider and re-injects the persisted storage
/// entries (byte-identical to what `generate_key_package` produced), then
/// deserializes the signer. The intermediate snapshot's key material is zeroized
/// before returning.
///
/// # Errors
///
/// Returns [`MlsError::Snapshot`] if the blob cannot be deserialized, the
/// provider-storage lock is poisoned, or the signer cannot be reconstructed.
pub fn restore_pending_join(
    blob: &[u8],
) -> Result<(InMemoryMlsProvider, SignatureKeyPair), MlsError> {
    let mut snapshot: PendingJoinSnapshot = rmp_serde::from_slice(blob)
        .map_err(|e| MlsError::Snapshot(format!("pending snapshot deserialization: {e}")))?;

    let provider = InMemoryMlsProvider::default();
    {
        let mut values = provider
            .storage()
            .values
            .write()
            .map_err(|e| MlsError::Snapshot(format!("provider storage lock poisoned: {e}")))?;
        // Drain so the snapshot no longer holds the HPKE/signer secrets.
        for (k, v) in snapshot.mls_storage_entries.drain(..) {
            values.insert(k, v);
        }
    }

    let signer: SignatureKeyPair = rmp_serde::from_slice(&snapshot.signer_bytes)
        .map_err(|e| MlsError::Snapshot(format!("pending signer deserialization: {e}")))?;

    // Belt-and-suspenders: clear any residual key bytes before drop.
    snapshot.zeroize_secrets();

    Ok((provider, signer))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::similar_names)]
mod tests {
    use super::*;
    use crate::ScpCredential;
    use crate::group::{add_member, create_group, generate_key_package, join_group};
    use openmls::prelude::KeyPackageIn;
    use scp_did::SigningKeyId;
    use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

    const ALICE: &str = "did:key:z6MkAliceMlsSnapshotFixtureAAAAAAAAAAAAAAA";
    const BOB: &str = "did:key:z6MkBobMlsSnapshotFixtureBBBBBBBBBBBBBBBBBB";

    fn credential(did: &str) -> ScpCredential {
        ScpCredential::new(did.to_owned(), None, SigningKeyId::Active).unwrap()
    }

    #[test]
    fn round_trip_preserves_group_identity_and_epoch() {
        let group = create_group(&credential(ALICE)).unwrap();
        let original_epoch = group.epoch().unwrap();
        let original_group_id = group.group_id().unwrap().to_vec();

        let blob = group.serialize_state().unwrap();
        let restored = ScpMlsGroup::deserialize_state(&blob).unwrap();

        assert_eq!(
            restored.epoch().unwrap(),
            original_epoch,
            "restored group is on the same MLS epoch"
        );
        assert_eq!(
            restored.group_id().unwrap().to_vec(),
            original_group_id,
            "restored group id is byte-identical"
        );
    }

    #[test]
    fn restored_group_still_encrypts_and_decrypts() {
        use crate::encrypt::{decrypt_with_membership_changes, encrypt, serialize_ciphertext};

        // Alice creates a two-member group so the restored group can decrypt a
        // message a peer sent — proving the epoch secrets survived the snapshot.
        let mut alice = create_group(&credential(ALICE)).unwrap();
        let (bundle, bob_signer, bob_provider) = generate_key_package(&credential(BOB)).unwrap();
        let kp_in = KeyPackageIn::tls_deserialize(
            &mut &*bundle.key_package().tls_serialize_detached().unwrap(),
        )
        .unwrap();
        let add = add_member(&mut alice, kp_in).unwrap();
        let bob = join_group(&add.welcome, bob_provider, bob_signer).unwrap();

        // Snapshot Bob, then restore into a fresh group.
        let blob = bob.serialize_state().unwrap();
        let mut restored_bob = ScpMlsGroup::deserialize_state(&blob).unwrap();

        // Alice sends; the RESTORED Bob must decrypt it.
        let ct = serialize_ciphertext(&encrypt(&mut alice, b"after restore").unwrap()).unwrap();
        match decrypt_with_membership_changes(&mut restored_bob, &ct).unwrap() {
            crate::InboundChange::Application { plaintext, .. } => {
                assert_eq!(plaintext, b"after restore");
            }
            other => panic!("expected an application message, got {other:?}"),
        }

        // Bob (the pre-snapshot original) must NOT be advanced by the restore.
        assert_eq!(bob.epoch().unwrap(), restored_bob.epoch().unwrap());
    }

    #[test]
    fn deserialize_rejects_garbage() {
        let result = ScpMlsGroup::deserialize_state(b"not a messagepack snapshot");
        assert!(matches!(result, Err(MlsError::Snapshot(_))));
    }

    #[test]
    fn pending_join_round_trip_completes_a_welcome() {
        // Bob generates a key package (retaining its private provider + signer),
        // snapshots that pending material, then RESTORES it and uses the restored
        // pair to join a group Alice adds him to — proving the persisted pending
        // material carries the HPKE private keys the Welcome needs.
        let (bundle, bob_signer, bob_provider) = generate_key_package(&credential(BOB)).unwrap();

        // Persist and restore Bob's pending-join material.
        let blob = serialize_pending_join(&bob_provider, &bob_signer).unwrap();
        let (restored_provider, restored_signer) = restore_pending_join(&blob).unwrap();

        // Alice creates a group and adds Bob from his published key package.
        let mut alice = create_group(&credential(ALICE)).unwrap();
        let kp_in = KeyPackageIn::tls_deserialize(
            &mut &*bundle.key_package().tls_serialize_detached().unwrap(),
        )
        .unwrap();
        let add = add_member(&mut alice, kp_in).unwrap();

        // The RESTORED pending pair must process the Welcome into a live group.
        let bob = join_group(&add.welcome, restored_provider, restored_signer).unwrap();
        assert_eq!(
            bob.epoch().unwrap(),
            alice.epoch().unwrap(),
            "restored joiner lands on the committer's epoch"
        );
    }

    #[test]
    fn restore_pending_join_rejects_garbage() {
        let result = restore_pending_join(b"not a messagepack pending snapshot");
        assert!(matches!(result, Err(MlsError::Snapshot(_))));
    }
}
