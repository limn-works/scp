//! The `ContextOperatorBinding`, and the chain entry and receipt its
//! `context_key` signs.
//!
//! Sources: `09-security-model.md` §9.5.2 **`ContextOperatorBinding`**,
//! **Context chain entry**, **Context receipt**; §9.7.1 log-anchored and
//! context-key rows; §9.18.2 separators; ADR-069; spec 25 §25.36 Vectors 92,
//! 94 and 95.
//!
//! The operator's `#active` key signs
//!
//! ```text
//! binding_hash = SHA-256("SCP-CONTEXT-OPERATOR-V1:" ‖ BE32(len(context_id)) ‖ context_id
//!                        ‖ operator (32) ‖ context_key (33) ‖ key_state_head (32))
//! ```
//!
//! `context_id` is the one variable-length field and carries its length, and
//! the three fields after it are fixed width, so no two field tuples share a
//! preimage. The node then signs under `context_key`
//!
//! ```text
//! SHA-256("SCP-CONTEXT-CHAIN-V1:"   ‖ binding_hash ‖ BE64(position) ‖ item_hash ‖ previous_hash)
//! SHA-256("SCP-CONTEXT-RECEIPT-V1:" ‖ binding_hash ‖ BE64(position) ‖ submission_hash)
//! ```
//!
//! whose fields are all fixed width. `binding_hash` stands in for
//! `context_id` in both, so an entry or receipt under one binding never
//! verifies under another.

use scp_crypto::p256::{
    COMPRESSED_POINT_LEN, P256Error, P256PublicKey, SIGNATURE_LEN, verify_prehash_strict,
};
use scp_did::Identifier;
use sha2::{Digest, Sha256};

use super::node_address::Reader;
use crate::crypto::canonical::{ABSENT_SENTINEL, CanonicalError, CanonicalField, canonical_hash};

/// The §9.18.2 separator of the binding preimage.
pub const CONTEXT_OPERATOR_SEPARATOR: &str = "SCP-CONTEXT-OPERATOR-V1:";
/// The §9.18.2 separator of the chain-entry preimage.
pub const CONTEXT_CHAIN_SEPARATOR: &str = "SCP-CONTEXT-CHAIN-V1:";
/// The §9.18.2 separator of the receipt preimage.
pub const CONTEXT_RECEIPT_SEPARATOR: &str = "SCP-CONTEXT-RECEIPT-V1:";

/// The `previous_hash` of the chain entry at the first position:
/// `SHA-256(0x00)` (§9.5.2 **Context chain entry** field 4).
pub const FIRST_PREVIOUS_HASH: [u8; 32] = ABSENT_SENTINEL;

/// The bytes of a binding after `context_id`: `operator` (32),
/// `context_key` (33), `key_state_head` (32) and the signature (64).
const BINDING_FIXED_TAIL_LEN: usize = 32 + COMPRESSED_POINT_LEN + 32 + SIGNATURE_LEN;

/// The `SHA-256` of the submission bytes as the node received them.
///
/// It is the `item_hash` of the chain entry and the `submission_hash` of the
/// receipt, which hash the same bytes (§9.5.2 **Context receipt** note).
#[must_use]
pub fn submission_hash(submission: &[u8]) -> [u8; 32] {
    Sha256::digest(submission).into()
}

/// Decodes 33 bytes as a compressed SEC1 point on P-256, refusing the
/// uncompressed tag `from_sec1` would accept at another length.
pub(crate) fn compressed_point(bytes: &[u8; COMPRESSED_POINT_LEN]) -> Option<P256PublicKey> {
    match bytes[0] {
        0x02 | 0x03 => P256PublicKey::from_sec1(bytes).ok(),
        _ => None,
    }
}

/// The binding of one context instantiation to its operator and its
/// `context_key` (§9.5.2 **`ContextOperatorBinding`**).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextOperatorBinding {
    /// The context the node instantiated.
    pub context_id: String,
    /// The operator's identifier, its 32 raw digest bytes.
    pub operator: Identifier,
    /// The compressed SEC1 P-256 key under which the node signs the
    /// context's chain entries, receipts and node addresses.
    pub context_key: [u8; COMPRESSED_POINT_LEN],
    /// The operator's key-state position when it signed (§9.7.1 log-anchored
    /// row).
    pub key_state_head: [u8; 32],
    /// The operator's `#active` signature over `binding_hash`.
    pub signature: [u8; SIGNATURE_LEN],
}

/// Why bytes are not a binding, or why a binding, chain entry or receipt is
/// refused.
///
/// No variant carries text or bytes from the input, so an error never echoes
/// what a peer sent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContextOperatorError {
    /// The bytes end before the signature.
    #[error("context operator binding bytes end early")]
    Truncated,
    /// Bytes follow the signature.
    #[error("context operator binding carries {0} bytes after its signature")]
    TrailingBytes(usize),
    /// `context_id` is not UTF-8.
    #[error("context operator binding context_id is not UTF-8")]
    ContextIdNotUtf8,
    /// `context_key` is not a compressed SEC1 point on P-256.
    #[error("context_key is not a compressed point on P-256")]
    ContextKey,
    /// The binding's hash is not the `binding_hash` the reader's invitation
    /// or group state holds, or an entry, receipt or address names another
    /// binding.
    #[error("binding_hash differs from the one the reader holds")]
    BindingMismatch,
    /// A signature does not verify strictly under its key.
    #[error("context signature: {0}")]
    Signature(P256Error),
    /// `context_id` could not be length-prefixed.
    #[error("context operator binding encoding: {0}")]
    Encoding(#[from] CanonicalError),
}

impl ContextOperatorBinding {
    /// `binding_hash` over the four fields.
    ///
    /// # Errors
    ///
    /// [`ContextOperatorError::Encoding`] when `context_id` exceeds a BE32
    /// length.
    pub fn signing_digest(
        context_id: &str,
        operator: &Identifier,
        context_key: &[u8; COMPRESSED_POINT_LEN],
        key_state_head: &[u8; 32],
    ) -> Result<[u8; 32], ContextOperatorError> {
        Ok(canonical_hash(
            CONTEXT_OPERATOR_SEPARATOR,
            &[
                CanonicalField::VarBytes(context_id.as_bytes()),
                CanonicalField::Fixed32(operator.as_bytes()),
                CanonicalField::RawBytes(context_key),
                CanonicalField::Fixed32(key_state_head),
            ],
        )?)
    }

    /// This binding's `binding_hash`.
    ///
    /// # Errors
    ///
    /// As [`Self::signing_digest`].
    pub fn binding_hash(&self) -> Result<[u8; 32], ContextOperatorError> {
        Self::signing_digest(
            &self.context_id,
            &self.operator,
            &self.context_key,
            &self.key_state_head,
        )
    }

    /// The §9.5.2 bytes: `BE32(len(context_id)) ‖ context_id ‖ operator ‖
    /// context_key ‖ key_state_head ‖ signature`.
    ///
    /// # Errors
    ///
    /// [`ContextOperatorError::Encoding`] when `context_id` exceeds a BE32
    /// length.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ContextOperatorError> {
        let len =
            u32::try_from(self.context_id.len()).map_err(|_| CanonicalError::FieldTooLarge {
                size: self.context_id.len(),
                max: u32::MAX as usize,
            })?;
        let mut out = Vec::with_capacity(4 + self.context_id.len() + BINDING_FIXED_TAIL_LEN);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(self.context_id.as_bytes());
        out.extend_from_slice(self.operator.as_bytes());
        out.extend_from_slice(&self.context_key);
        out.extend_from_slice(&self.key_state_head);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// Decodes exactly one binding.
    ///
    /// # Errors
    ///
    /// [`ContextOperatorError::Truncated`],
    /// [`ContextOperatorError::TrailingBytes`] or
    /// [`ContextOperatorError::ContextIdNotUtf8`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContextOperatorError> {
        let mut reader = Reader::new(bytes);
        let context_id = reader.var().ok_or(ContextOperatorError::Truncated)?;
        let context_id = std::str::from_utf8(context_id)
            .map_err(|_| ContextOperatorError::ContextIdNotUtf8)?
            .to_owned();
        let operator =
            Identifier::from_bytes(reader.array().ok_or(ContextOperatorError::Truncated)?);
        let context_key = reader.array().ok_or(ContextOperatorError::Truncated)?;
        let key_state_head = reader.array().ok_or(ContextOperatorError::Truncated)?;
        let signature = reader.array().ok_or(ContextOperatorError::Truncated)?;
        match reader.remaining() {
            0 => Ok(Self {
                context_id,
                operator,
                context_key,
                key_state_head,
                signature,
            }),
            n => Err(ContextOperatorError::TrailingBytes(n)),
        }
    }
}

/// A [`ContextOperatorBinding`] the reader accepted.
///
/// Its hash is the one the reader's invitation or group state holds, its
/// `context_key` is a point, and the operator's `#active` signature over it
/// verified.
///
/// [`Self::verify`] is the only constructor, and the type has no
/// `Deserialize`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedContextOperatorBinding {
    binding: ContextOperatorBinding,
    binding_hash: [u8; 32],
    context_key: P256PublicKey,
}

impl VerifiedContextOperatorBinding {
    /// The §9.5.2 verification.
    ///
    /// `expected_binding_hash` is the `binding_hash` of the invitation a
    /// joiner holds, or of the `0xFF02` extension a member's group state
    /// holds. `operator_active` is the operator's `#active` key that was
    /// `Current` at the binding's `key_state_head`; resolving it from the
    /// operator's key state is the caller's step of the §9.7.1 log-anchored
    /// class.
    ///
    /// # Errors
    ///
    /// [`ContextOperatorError::BindingMismatch`],
    /// [`ContextOperatorError::ContextKey`],
    /// [`ContextOperatorError::Signature`] (including a high-`s` signature)
    /// or [`ContextOperatorError::Encoding`].
    pub fn verify(
        binding: ContextOperatorBinding,
        expected_binding_hash: &[u8; 32],
        operator_active: &P256PublicKey,
    ) -> Result<Self, ContextOperatorError> {
        let binding_hash = binding.binding_hash()?;
        if binding_hash != *expected_binding_hash {
            return Err(ContextOperatorError::BindingMismatch);
        }
        let context_key =
            compressed_point(&binding.context_key).ok_or(ContextOperatorError::ContextKey)?;
        verify_prehash_strict(operator_active, &binding_hash, &binding.signature)
            .map_err(ContextOperatorError::Signature)?;
        Ok(Self {
            binding,
            binding_hash,
            context_key,
        })
    }

    /// The binding this value verified.
    #[must_use]
    pub const fn binding(&self) -> &ContextOperatorBinding {
        &self.binding
    }

    /// The binding's `binding_hash`.
    #[must_use]
    pub const fn binding_hash(&self) -> &[u8; 32] {
        &self.binding_hash
    }

    /// The decoded `context_key`.
    #[must_use]
    pub const fn context_key(&self) -> &P256PublicKey {
        &self.context_key
    }

    /// Checks `signature` strictly under `context_key` over a digest whose
    /// preimage carries `binding_hash`.
    fn verify_under_context_key(
        &self,
        binding_hash: &[u8; 32],
        digest: &[u8; 32],
        signature: &[u8; SIGNATURE_LEN],
    ) -> Result<(), ContextOperatorError> {
        if *binding_hash != self.binding_hash {
            return Err(ContextOperatorError::BindingMismatch);
        }
        verify_prehash_strict(&self.context_key, digest, signature)
            .map_err(ContextOperatorError::Signature)
    }
}

/// One entry of a context's chain, signed under `context_key`
/// (§9.5.2 **Context chain entry**).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextChainEntry {
    /// The binding whose `context_key` signed the entry.
    pub binding_hash: [u8; 32],
    /// The entry's position in the chain.
    pub position: u64,
    /// [`submission_hash`] of the item at `position`.
    pub item_hash: [u8; 32],
    /// The [`Self::digest`] of the entry at `position − 1`, or
    /// [`FIRST_PREVIOUS_HASH`] at the first position.
    pub previous_hash: [u8; 32],
    /// The `context_key` signature over [`Self::digest`].
    pub signature: [u8; SIGNATURE_LEN],
}

impl ContextChainEntry {
    /// The digest `context_key` signs, which is also the next entry's
    /// `previous_hash`.
    #[must_use]
    pub fn signing_digest(
        binding_hash: &[u8; 32],
        position: u64,
        item_hash: &[u8; 32],
        previous_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(CONTEXT_CHAIN_SEPARATOR.as_bytes());
        hasher.update(binding_hash);
        hasher.update(position.to_be_bytes());
        hasher.update(item_hash);
        hasher.update(previous_hash);
        hasher.finalize().into()
    }

    /// The digest over this entry's four fields.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        Self::signing_digest(
            &self.binding_hash,
            self.position,
            &self.item_hash,
            &self.previous_hash,
        )
    }
}

/// A [`ContextChainEntry`] whose signature verified under the `context_key`
/// of the binding it names. [`Self::verify`] is the only constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedContextChainEntry {
    entry: ContextChainEntry,
}

impl VerifiedContextChainEntry {
    /// Verifies `entry` strictly (low-`s`, no second hash) under `binding`'s
    /// `context_key`.
    ///
    /// # Errors
    ///
    /// [`ContextOperatorError::BindingMismatch`] when the entry names another
    /// binding, or [`ContextOperatorError::Signature`].
    pub fn verify(
        entry: ContextChainEntry,
        binding: &VerifiedContextOperatorBinding,
    ) -> Result<Self, ContextOperatorError> {
        binding.verify_under_context_key(&entry.binding_hash, &entry.digest(), &entry.signature)?;
        Ok(Self { entry })
    }

    /// The entry this value verified.
    #[must_use]
    pub const fn entry(&self) -> &ContextChainEntry {
        &self.entry
    }
}

/// The node's receipt for one submission, signed under `context_key`
/// (§9.5.2 **Context receipt**).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextReceipt {
    /// The binding whose `context_key` signed the receipt.
    pub binding_hash: [u8; 32],
    /// The position the node assigned to the submission.
    pub position: u64,
    /// [`submission_hash`] of the submission bytes as the node received them.
    pub submission_hash: [u8; 32],
    /// The `context_key` signature over [`Self::digest`].
    pub signature: [u8; SIGNATURE_LEN],
}

impl ContextReceipt {
    /// The digest `context_key` signs.
    #[must_use]
    pub fn signing_digest(
        binding_hash: &[u8; 32],
        position: u64,
        submission_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(CONTEXT_RECEIPT_SEPARATOR.as_bytes());
        hasher.update(binding_hash);
        hasher.update(position.to_be_bytes());
        hasher.update(submission_hash);
        hasher.finalize().into()
    }

    /// The digest over this receipt's three fields.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        Self::signing_digest(&self.binding_hash, self.position, &self.submission_hash)
    }
}

/// A [`ContextReceipt`] whose signature verified under the `context_key` of
/// the binding it names. [`Self::verify`] is the only constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedContextReceipt {
    receipt: ContextReceipt,
}

impl VerifiedContextReceipt {
    /// Verifies `receipt` strictly (low-`s`, no second hash) under
    /// `binding`'s `context_key`.
    ///
    /// # Errors
    ///
    /// [`ContextOperatorError::BindingMismatch`] when the receipt names
    /// another binding, or [`ContextOperatorError::Signature`].
    pub fn verify(
        receipt: ContextReceipt,
        binding: &VerifiedContextOperatorBinding,
    ) -> Result<Self, ContextOperatorError> {
        binding.verify_under_context_key(
            &receipt.binding_hash,
            &receipt.digest(),
            &receipt.signature,
        )?;
        Ok(Self { receipt })
    }

    /// The receipt this value verified.
    #[must_use]
    pub const fn receipt(&self) -> &ContextReceipt {
        &self.receipt
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use scp_crypto::p256::{P256SecretKey, SeedLabel, sign_prehash_rfc6979};

    use super::*;

    pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    pub fn key(seed: u8) -> P256SecretKey {
        P256SecretKey::from_seed(SeedLabel::TestVectorKey, &[seed; 32])
    }

    /// A binding signed by `key(1)` as the operator's `#active`, with
    /// `key(2)` as `context_key`.
    pub fn binding() -> TestResult<ContextOperatorBinding> {
        let context_id = "ctx-operator-test".to_owned();
        let operator = Identifier::from_bytes([0x11; 32]);
        let context_key = key(2).public_key().to_compressed();
        let key_state_head = [0x22; 32];
        let digest = ContextOperatorBinding::signing_digest(
            &context_id,
            &operator,
            &context_key,
            &key_state_head,
        )?;
        Ok(ContextOperatorBinding {
            context_id,
            operator,
            context_key,
            key_state_head,
            signature: sign_prehash_rfc6979(&key(1), &digest)?,
        })
    }

    pub fn verified_binding() -> TestResult<VerifiedContextOperatorBinding> {
        let binding = binding()?;
        let hash = binding.binding_hash()?;
        Ok(VerifiedContextOperatorBinding::verify(
            binding,
            &hash,
            &key(1).public_key(),
        )?)
    }

    fn check(
        binding: ContextOperatorBinding,
        expected: &[u8; 32],
    ) -> Result<(), ContextOperatorError> {
        VerifiedContextOperatorBinding::verify(binding, expected, &key(1).public_key()).map(|_| ())
    }

    /// The `s` of a 64-byte signature replaced by `n − s`.
    fn high_s(signature: &[u8; SIGNATURE_LEN]) -> [u8; SIGNATURE_LEN] {
        // n, the P-256 group order, big-endian.
        const N: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let mut out = *signature;
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = i16::from(N[i]) - i16::from(signature[32 + i]) - borrow;
            borrow = i16::from(d < 0);
            out[32 + i] = u8::try_from(d.rem_euclid(256)).unwrap_or(0);
        }
        out
    }

    #[test]
    fn a_signed_binding_verifies_and_round_trips() -> TestResult {
        let binding = binding()?;
        let bytes = binding.to_bytes()?;
        assert_eq!(bytes.len(), 165 + binding.context_id.len());
        let back = ContextOperatorBinding::from_bytes(&bytes)?;
        assert_eq!(back, binding);
        let verified = verified_binding()?;
        assert_eq!(verified.binding(), &binding);
        assert_eq!(verified.context_key(), &key(2).public_key());
        Ok(())
    }

    #[test]
    fn the_preimage_is_the_separator_and_the_four_fields() -> TestResult {
        let binding = binding()?;
        let mut preimage = CONTEXT_OPERATOR_SEPARATOR.as_bytes().to_vec();
        preimage.extend_from_slice(&u32::try_from(binding.context_id.len())?.to_be_bytes());
        preimage.extend_from_slice(binding.context_id.as_bytes());
        preimage.extend_from_slice(binding.operator.as_bytes());
        preimage.extend_from_slice(&binding.context_key);
        preimage.extend_from_slice(&binding.key_state_head);
        assert_eq!(
            binding.binding_hash()?,
            <[u8; 32]>::from(Sha256::digest(&preimage))
        );
        Ok(())
    }

    /// A change to any field moves `binding_hash`, so the reader's held hash
    /// refuses it, and a binding presented against its own new hash fails
    /// the signature.
    #[test]
    fn a_change_to_any_field_is_refused() -> TestResult {
        let good = binding()?;
        let held = good.binding_hash()?;
        let mut variants = Vec::new();
        let mut b = good.clone();
        b.context_id.push('x');
        variants.push(b);
        let mut b = good.clone();
        b.operator = Identifier::from_bytes([0x12; 32]);
        variants.push(b);
        let mut b = good.clone();
        b.context_key = key(3).public_key().to_compressed();
        variants.push(b);
        let mut b = good.clone();
        b.key_state_head[31] ^= 1;
        variants.push(b);
        for b in variants {
            assert_eq!(
                check(b.clone(), &held),
                Err(ContextOperatorError::BindingMismatch)
            );
            let own = b.binding_hash()?;
            assert_eq!(
                check(b, &own),
                Err(ContextOperatorError::Signature(
                    P256Error::VerificationFailed
                ))
            );
        }
        let mut b = good;
        b.signature[0] ^= 1;
        assert!(matches!(
            check(b, &held),
            Err(ContextOperatorError::Signature(_))
        ));
        Ok(())
    }

    #[test]
    fn a_binding_under_another_operator_key_is_refused() -> TestResult {
        let binding = binding()?;
        let held = binding.binding_hash()?;
        assert_eq!(
            VerifiedContextOperatorBinding::verify(binding, &held, &key(3).public_key()),
            Err(ContextOperatorError::Signature(
                P256Error::VerificationFailed
            ))
        );
        Ok(())
    }

    #[test]
    fn a_high_s_binding_signature_is_refused() -> TestResult {
        let mut binding = binding()?;
        let held = binding.binding_hash()?;
        binding.signature = high_s(&binding.signature);
        assert_eq!(
            check(binding, &held),
            Err(ContextOperatorError::Signature(P256Error::HighS))
        );
        Ok(())
    }

    /// A `context_key` off the curve, or in an encoding other than the
    /// compressed one, is refused even when the operator signed it.
    #[test]
    fn an_off_curve_context_key_is_refused() -> TestResult {
        let mut off_curve = [0u8; COMPRESSED_POINT_LEN];
        off_curve[0] = 0x02;
        off_curve[32] = 0x01; // x = 1: x³ − 3x + b is a non-residue mod p.
        let mut uncompressed_tag = key(2).public_key().to_compressed();
        uncompressed_tag[0] = 0x04;
        for context_key in [off_curve, uncompressed_tag] {
            assert!(compressed_point(&context_key).is_none());
            let mut b = binding()?;
            b.context_key = context_key;
            let digest = b.binding_hash()?;
            b.signature = sign_prehash_rfc6979(&key(1), &digest)?;
            assert_eq!(check(b, &digest), Err(ContextOperatorError::ContextKey));
        }
        Ok(())
    }

    #[test]
    fn decode_refuses_truncation_trailing_bytes_and_non_utf8() -> TestResult {
        let bytes = binding()?.to_bytes()?;
        assert_eq!(
            ContextOperatorBinding::from_bytes(&bytes[..bytes.len() - 1]),
            Err(ContextOperatorError::Truncated)
        );
        let mut long = bytes.clone();
        long.extend_from_slice(&[0, 0]);
        assert_eq!(
            ContextOperatorBinding::from_bytes(&long),
            Err(ContextOperatorError::TrailingBytes(2))
        );
        let mut bad = bytes;
        bad[4] = 0xff;
        assert_eq!(
            ContextOperatorBinding::from_bytes(&bad),
            Err(ContextOperatorError::ContextIdNotUtf8)
        );
        Ok(())
    }

    fn entry(
        binding: &VerifiedContextOperatorBinding,
        signer: u8,
    ) -> TestResult<ContextChainEntry> {
        let item_hash = submission_hash(b"submission");
        let digest = ContextChainEntry::signing_digest(
            binding.binding_hash(),
            1,
            &item_hash,
            &FIRST_PREVIOUS_HASH,
        );
        Ok(ContextChainEntry {
            binding_hash: *binding.binding_hash(),
            position: 1,
            item_hash,
            previous_hash: FIRST_PREVIOUS_HASH,
            signature: sign_prehash_rfc6979(&key(signer), &digest)?,
        })
    }

    fn receipt(binding: &VerifiedContextOperatorBinding, signer: u8) -> TestResult<ContextReceipt> {
        let submission_hash = submission_hash(b"submission");
        let digest = ContextReceipt::signing_digest(binding.binding_hash(), 1, &submission_hash);
        Ok(ContextReceipt {
            binding_hash: *binding.binding_hash(),
            position: 1,
            submission_hash,
            signature: sign_prehash_rfc6979(&key(signer), &digest)?,
        })
    }

    #[test]
    fn chain_entry_and_receipt_preimages_are_fixed_width() -> TestResult {
        let binding = verified_binding()?;
        let e = entry(&binding, 2)?;
        let mut preimage = CONTEXT_CHAIN_SEPARATOR.as_bytes().to_vec();
        preimage.extend_from_slice(&e.binding_hash);
        preimage.extend_from_slice(&e.position.to_be_bytes());
        preimage.extend_from_slice(&e.item_hash);
        preimage.extend_from_slice(&e.previous_hash);
        assert_eq!(preimage.len(), 21 + 32 + 8 + 32 + 32);
        assert_eq!(e.digest(), <[u8; 32]>::from(Sha256::digest(&preimage)));
        let r = receipt(&binding, 2)?;
        let mut preimage = CONTEXT_RECEIPT_SEPARATOR.as_bytes().to_vec();
        preimage.extend_from_slice(&r.binding_hash);
        preimage.extend_from_slice(&r.position.to_be_bytes());
        preimage.extend_from_slice(&r.submission_hash);
        assert_eq!(preimage.len(), 23 + 32 + 8 + 32);
        assert_eq!(r.digest(), <[u8; 32]>::from(Sha256::digest(&preimage)));
        // One submission's entry and receipt carry one hash.
        assert_eq!(e.item_hash, r.submission_hash);
        assert_eq!(FIRST_PREVIOUS_HASH, <[u8; 32]>::from(Sha256::digest([0u8])));
        Ok(())
    }

    #[test]
    fn chain_entries_and_receipts_verify_only_under_context_key() -> TestResult {
        let binding = verified_binding()?;
        let e = VerifiedContextChainEntry::verify(entry(&binding, 2)?, &binding)?;
        assert_eq!(e.entry().position, 1);
        let r = VerifiedContextReceipt::verify(receipt(&binding, 2)?, &binding)?;
        assert_eq!(r.receipt().position, 1);

        // Signed by the operator's #active instead of context_key.
        assert_eq!(
            VerifiedContextChainEntry::verify(entry(&binding, 1)?, &binding),
            Err(ContextOperatorError::Signature(
                P256Error::VerificationFailed
            ))
        );
        assert_eq!(
            VerifiedContextReceipt::verify(receipt(&binding, 1)?, &binding),
            Err(ContextOperatorError::Signature(
                P256Error::VerificationFailed
            ))
        );

        // Naming another binding.
        let mut e = entry(&binding, 2)?;
        e.binding_hash[0] ^= 1;
        assert_eq!(
            VerifiedContextChainEntry::verify(e, &binding),
            Err(ContextOperatorError::BindingMismatch)
        );
        let mut r = receipt(&binding, 2)?;
        r.binding_hash[0] ^= 1;
        assert_eq!(
            VerifiedContextReceipt::verify(r, &binding),
            Err(ContextOperatorError::BindingMismatch)
        );

        // A change to position or to a hash.
        let mut e = entry(&binding, 2)?;
        e.position = 2;
        assert!(VerifiedContextChainEntry::verify(e, &binding).is_err());
        let mut e = entry(&binding, 2)?;
        e.previous_hash[0] ^= 1;
        assert!(VerifiedContextChainEntry::verify(e, &binding).is_err());
        let mut r = receipt(&binding, 2)?;
        r.submission_hash[0] ^= 1;
        assert!(VerifiedContextReceipt::verify(r, &binding).is_err());

        // High s.
        let mut e = entry(&binding, 2)?;
        e.signature = high_s(&e.signature);
        assert_eq!(
            VerifiedContextChainEntry::verify(e, &binding),
            Err(ContextOperatorError::Signature(P256Error::HighS))
        );
        let mut r = receipt(&binding, 2)?;
        r.signature = high_s(&r.signature);
        assert_eq!(
            VerifiedContextReceipt::verify(r, &binding),
            Err(ContextOperatorError::Signature(P256Error::HighS))
        );
        Ok(())
    }
}
