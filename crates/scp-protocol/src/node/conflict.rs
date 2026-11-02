//! The witness conflict statement and the `WitnessConflictRecordV4` frame it
//! travels in at `scp:wcf:` (`09-security-model.md` §9.7.4.3 **The conflict
//! statement**, §9.10.12).
//!
//! A statement's fields, in preimage order: `witness` (32, a `NodeId`),
//! `subject` (32), `held_sequence` (8), `held_digest` (32),
//! `offered_sequence` (8), `offered_digest` (32), `observed_at` (8). The
//! witness's node key signs
//!
//! ```text
//! SHA-256("SCP-WITNESS-CONFLICT-V1:" ‖ the 152 field bytes)
//! ```
//!
//! and the statement is the 152 field bytes followed by the 64-byte
//! signature, 216 bytes on the wire. The frame is `0x04 ‖ subject ‖ value`,
//! where `value` is one or more statements; a decoder refuses a `value`
//! whose length is not a positive multiple of 216 (§9.10.12).

use scp_crypto::p256::{P256Error, P256PublicKey, SIGNATURE_LEN, verify_prehash_strict};
use scp_did::{Identifier, NodeId};
use sha2::{Digest, Sha256};

use super::frame::{FramePrefixError, MAX_RECORD_FRAME_VALUE_LEN, join_frame, split_frame};

/// The frame's version byte (§9.10.12).
pub const CONFLICT_FRAME_VERSION: u8 = 4;

/// `"SCP-WITNESS-CONFLICT-V1:"`, §9.18.2's separator for the statement.
pub const WITNESS_CONFLICT_SEPARATOR: &str = "SCP-WITNESS-CONFLICT-V1:";

/// The statement's field bytes, the signature excluded.
pub const CONFLICT_STATEMENT_FIELDS_LEN: usize = 152;

/// One statement on the wire: fields and signature.
pub const CONFLICT_STATEMENT_LEN: usize = CONFLICT_STATEMENT_FIELDS_LEN + SIGNATURE_LEN;

/// A witness's signed statement that it refused to cosign `offered` because
/// it held `held` for the same subject (§9.7.4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictStatement {
    /// The refusing witness's `NodeId`.
    pub witness: NodeId,
    /// The subject identity.
    pub subject: Identifier,
    /// The sequence of the head the witness held.
    pub held_sequence: u64,
    /// The digest of the head the witness held.
    pub held_digest: [u8; 32],
    /// The sequence of the head the witness was offered.
    pub offered_sequence: u64,
    /// The digest of the head the witness was offered.
    pub offered_digest: [u8; 32],
    /// When the witness observed the conflict, in seconds.
    pub observed_at: u64,
    /// The node key's signature over [`signing_digest`](Self::signing_digest).
    pub signature: [u8; SIGNATURE_LEN],
}

/// Why a conflict-statement frame, or one statement in it, is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConflictFrameError {
    /// A prefix rule.
    #[error(transparent)]
    Prefix(#[from] FramePrefixError),
    /// `value` is not a positive multiple of 216 bytes.
    #[error("conflict frame value is {0} bytes, not a positive multiple of 216")]
    NotWholeStatements(usize),
    /// A statement's signature does not verify under the key handed in.
    #[error("conflict statement signature: {0}")]
    Signature(P256Error),
}

impl ConflictStatement {
    /// The 152 field bytes in preimage order.
    #[must_use]
    pub fn fields(&self) -> [u8; CONFLICT_STATEMENT_FIELDS_LEN] {
        let mut out = [0u8; CONFLICT_STATEMENT_FIELDS_LEN];
        out[..32].copy_from_slice(self.witness.as_bytes());
        out[32..64].copy_from_slice(self.subject.as_bytes());
        out[64..72].copy_from_slice(&self.held_sequence.to_be_bytes());
        out[72..104].copy_from_slice(&self.held_digest);
        out[104..112].copy_from_slice(&self.offered_sequence.to_be_bytes());
        out[112..144].copy_from_slice(&self.offered_digest);
        out[144..].copy_from_slice(&self.observed_at.to_be_bytes());
        out
    }

    /// `SHA-256("SCP-WITNESS-CONFLICT-V1:" ‖ fields)`.
    #[must_use]
    pub fn signing_digest(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(WITNESS_CONFLICT_SEPARATOR.as_bytes())
            .chain_update(self.fields())
            .finalize()
            .into()
    }

    /// The 216 wire bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CONFLICT_STATEMENT_LEN] {
        let mut out = [0u8; CONFLICT_STATEMENT_LEN];
        out[..CONFLICT_STATEMENT_FIELDS_LEN].copy_from_slice(&self.fields());
        out[CONFLICT_STATEMENT_FIELDS_LEN..].copy_from_slice(&self.signature);
        out
    }

    /// Reads one statement from exactly 216 bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; CONFLICT_STATEMENT_LEN]) -> Self {
        let array32 = |at: usize| {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes[at..at + 32]);
            out
        };
        let be64 = |at: usize| {
            let mut out = [0u8; 8];
            out.copy_from_slice(&bytes[at..at + 8]);
            u64::from_be_bytes(out)
        };
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[CONFLICT_STATEMENT_FIELDS_LEN..]);
        Self {
            witness: NodeId::from_bytes(array32(0)),
            subject: Identifier::from_bytes(array32(32)),
            held_sequence: be64(64),
            held_digest: array32(72),
            offered_sequence: be64(104),
            offered_digest: array32(112),
            observed_at: be64(144),
            signature,
        }
    }

    /// Verifies the signature strictly under `node_key`, the key of a
    /// binding whose `NodeId` the caller matched against
    /// [`witness`](Self::witness).
    ///
    /// # Errors
    ///
    /// [`ConflictFrameError::Signature`] when it does not verify.
    pub fn verify(&self, node_key: &P256PublicKey) -> Result<(), ConflictFrameError> {
        verify_prehash_strict(node_key, &self.signing_digest(), &self.signature)
            .map_err(ConflictFrameError::Signature)
    }
}

/// Decodes a conflict-statement frame: the prefix rules, then a `value` of
/// one or more whole statements. Signatures are not checked.
///
/// # Errors
///
/// [`ConflictFrameError`] names the first rule the bytes break.
pub fn decode_conflict_frame(
    bytes: &[u8],
) -> Result<(Identifier, Vec<ConflictStatement>), ConflictFrameError> {
    let (subject, value) = split_frame(bytes, CONFLICT_FRAME_VERSION)?;
    if value.is_empty() || value.len() % CONFLICT_STATEMENT_LEN != 0 {
        return Err(ConflictFrameError::NotWholeStatements(value.len()));
    }
    let statements = value
        .as_chunks::<CONFLICT_STATEMENT_LEN>()
        .0
        .iter()
        .map(ConflictStatement::from_bytes)
        .collect();
    Ok((subject, statements))
}

/// Encodes a frame for `subject` carrying `statements`.
///
/// # Errors
///
/// [`ConflictFrameError::NotWholeStatements`] for no statement, or
/// [`FramePrefixError::ValueTooLarge`] past the `value` bound.
pub fn encode_conflict_frame(
    subject: &Identifier,
    statements: &[ConflictStatement],
) -> Result<Vec<u8>, ConflictFrameError> {
    if statements.is_empty() {
        return Err(ConflictFrameError::NotWholeStatements(0));
    }
    let value: Vec<u8> = statements
        .iter()
        .flat_map(ConflictStatement::to_bytes)
        .collect();
    if value.len() > MAX_RECORD_FRAME_VALUE_LEN {
        return Err(FramePrefixError::ValueTooLarge(value.len()).into());
    }
    Ok(join_frame(CONFLICT_FRAME_VERSION, subject, &value))
}

#[cfg(test)]
mod tests {
    use scp_crypto::p256::{P256SecretKey, SeedLabel, sign_prehash_rfc6979};

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn statement(key: &P256SecretKey) -> Result<ConflictStatement, P256Error> {
        let mut statement = ConflictStatement {
            witness: NodeId::from_bytes([1; 32]),
            subject: Identifier::from_bytes([2; 32]),
            held_sequence: 3,
            held_digest: [4; 32],
            offered_sequence: 3,
            offered_digest: [5; 32],
            observed_at: 1_700_000_000,
            signature: [0; SIGNATURE_LEN],
        };
        statement.signature = sign_prehash_rfc6979(key, &statement.signing_digest())?;
        Ok(statement)
    }

    #[test]
    fn a_statement_round_trips_and_verifies_only_under_its_key() -> TestResult {
        let key = P256SecretKey::from_seed(SeedLabel::TestVectorKey, &[9; 32]);
        let other = P256SecretKey::from_seed(SeedLabel::TestVectorKey, &[8; 32]);
        let statement = statement(&key)?;
        let frame = encode_conflict_frame(&statement.subject, std::slice::from_ref(&statement))?;
        let (subject, decoded) = decode_conflict_frame(&frame)?;
        assert_eq!(subject, statement.subject);
        assert_eq!(decoded, vec![statement.clone()]);
        statement.verify(&key.public_key())?;
        assert!(statement.verify(&other.public_key()).is_err());
        Ok(())
    }

    #[test]
    fn the_preimage_is_the_separator_and_152_field_bytes() -> TestResult {
        let key = P256SecretKey::from_seed(SeedLabel::TestVectorKey, &[9; 32]);
        let statement = statement(&key)?;
        let mut preimage = WITNESS_CONFLICT_SEPARATOR.as_bytes().to_vec();
        preimage.extend_from_slice(&statement.fields());
        assert_eq!(preimage.len(), 24 + 152);
        let expected: [u8; 32] = Sha256::digest(&preimage).into();
        assert_eq!(statement.signing_digest(), expected);
        assert_eq!(statement.to_bytes().len(), 216);
        Ok(())
    }

    #[test]
    fn a_value_that_is_not_whole_statements_is_refused() {
        for len in [0, 215, 217] {
            let frame = join_frame(CONFLICT_FRAME_VERSION, &Identifier::ZERO, &vec![0; len]);
            assert_eq!(
                decode_conflict_frame(&frame),
                Err(ConflictFrameError::NotWholeStatements(len))
            );
        }
    }
}
