//! Identity types and utilities for SCP — pure protocol types.
//!
//! Pure module re-exports. Async modules (blocking, recovery,
//! `custody_migration`, scpid) stay in scp-runtime.

pub mod attestation;
pub mod block_list;
pub mod private_state;
pub mod private_state_events;

// Re-export SigningKeyId from scp-primitives for convenience.
pub use scp_primitives::SigningKeyId;

/// Extracts the 32-byte Ed25519 public key from a `did:dht:z...` DID string.
///
/// The suffix after `did:dht:z` is z-base-32 encoded. This function decodes it
/// and returns the raw 32-byte public key. Returns an error if the prefix is
/// wrong, the z-base-32 decoding fails, or the result is not exactly 32 bytes.
///
/// This is a local re-implementation of `scp_identity::extract_public_key` to
/// avoid pulling in the full scp-identity crate (and its tokio dependency)
/// into scp-protocol.
///
/// # Errors
///
/// Returns an error string if the DID does not start with `did:dht:z`,
/// if z-base-32 decoding fails, or if the decoded key is not exactly 32 bytes.
pub fn extract_public_key_from_did(did_string: &str) -> Result<[u8; 32], String> {
    let encoded = did_string
        .strip_prefix("did:dht:z")
        .ok_or_else(|| format!("expected 'did:dht:z...' prefix, got: {did_string}"))?;

    let decoded = zbase32::decode(encoded).map_err(|e| format!("z-base-32 decode failed: {e}"))?;

    let key_bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|v: Vec<u8>| format!("expected 32-byte public key, got {} bytes", v.len()))?;

    Ok(key_bytes)
}
