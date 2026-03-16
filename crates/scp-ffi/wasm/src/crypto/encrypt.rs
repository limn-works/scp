//! Higher-level MLS encrypt/decrypt with TLS serialization.
//!
//! Wraps `WasmMlsGroup::encrypt`/`decrypt` with TLS codec pre-validation
//! and serialization for wire-ready ciphertext. The decrypt path performs
//! TLS deserialization *before* calling into `OpenMLS` `process_message`,
//! catching malformed wire data early.

use openmls::prelude::*;
use tls_codec::Deserialize as TlsDeserializeTrait;

use super::error::WasmCryptoError;
use super::group::WasmMlsGroup;

/// Encrypts plaintext using the MLS group and returns TLS-serialized bytes.
///
/// This is a convenience wrapper around `WasmMlsGroup::encrypt` that
/// handles serialization. The returned bytes can be sent over the wire.
///
/// # Errors
///
/// Returns an error if the group is destroyed or encryption fails.
pub fn mls_encrypt(group: &mut WasmMlsGroup, plaintext: &[u8]) -> Result<Vec<u8>, WasmCryptoError> {
    group.encrypt(plaintext)
}

/// Decrypts TLS-serialized MLS ciphertext and returns the plaintext.
///
/// Pre-validates the ciphertext by TLS-deserializing into `MlsMessageIn` and
/// verifying it is a protocol message *before* passing to `process_message`.
/// This catches obviously malformed wire data early (deserialization errors)
/// rather than deep inside `OpenMLS` where panics are possible.
///
/// # WASM trap risk
///
/// On `wasm32`, `std::panic::catch_unwind` is a no-op — panics abort the
/// WASM instance. `OpenMLS` 0.8 may panic on tampered AEAD ciphertext
/// (specifically inside `libcrux`/`RustCrypto` AES-GCM decryption), causing
/// a WASM trap that kills the browser tab.
///
/// **Mitigation:** The relay is untrusted by design (ADR-004); clients should
/// handle WASM trap errors at the JS layer (e.g., `try/catch` around the
/// `wasm-bindgen` call). The pre-validation here reduces (but cannot eliminate)
/// the attack surface — well-formed TLS framing with tampered AEAD payloads
/// will still reach `process_message`.
///
// SAFETY: On wasm32, catch_unwind is a no-op. OpenMLS 0.8 may panic on tampered
// AEAD ciphertext, causing a WASM trap. This is a known DoS vector against
// browser clients. Mitigation: the relay is untrusted by design; clients
// should handle WASM trap errors at the JS layer.
///
/// # Errors
///
/// Returns an error if the group is destroyed, TLS deserialization fails,
/// the message is not a protocol message, or decryption fails.
pub fn mls_decrypt(
    group: &mut WasmMlsGroup,
    ciphertext: &[u8],
) -> Result<Vec<u8>, WasmCryptoError> {
    // Pre-validate: TLS-deserialize the wire bytes into an MlsMessageIn.
    // This catches malformed framing before OpenMLS touches the AEAD payload.
    let mls_in = MlsMessageIn::tls_deserialize(&mut &*ciphertext)
        .map_err(|e| WasmCryptoError::DecryptionFailed(format!("TLS deserialization: {e}")))?;

    // Verify it is a protocol message (not a Welcome, GroupInfo, or KeyPackage).
    let protocol_msg = mls_in.try_into_protocol_message().map_err(|_| {
        WasmCryptoError::DecryptionFailed("message is not a protocol message".to_string())
    })?;

    // Delegate to the group for AEAD decryption and epoch processing.
    group.decrypt_protocol_message(protocol_msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::credential::{WasmScpCredential, WasmSigningKeyId};

    #[allow(clippy::unwrap_used)]
    fn test_credential(name: &str) -> WasmScpCredential {
        WasmScpCredential::new(
            format!("did:dht:z6Mk{name}"),
            None,
            WasmSigningKeyId::Active,
        )
        .unwrap()
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn mls_encrypt_decrypt_roundtrip() {
        let alice_cred = test_credential("alice");
        let mut alice_group = WasmMlsGroup::create_group(&alice_cred).unwrap();

        let bob_cred = test_credential("bob");
        let (bob_kp_bytes, bob_holder) = WasmMlsGroup::generate_key_package(&bob_cred).unwrap();

        let bob_kp_in = KeyPackageIn::tls_deserialize(&mut &*bob_kp_bytes).unwrap();
        let (_commit, welcome) = alice_group.add_member(bob_kp_in).unwrap();

        let mut bob_group = WasmMlsGroup::join_from_welcome(&welcome, bob_holder).unwrap();

        let plaintext = b"mls roundtrip test message";
        let ciphertext = mls_encrypt(&mut alice_group, plaintext).unwrap();
        let decrypted = mls_decrypt(&mut bob_group, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
