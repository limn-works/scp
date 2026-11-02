//! Local checks on an identifier and its inception (`03-identity.md` §3.1;
//! `09-security-model.md` §9.7.4.2 R2 and R3). Neither makes a network call.

use scp_did::Identifier;
use scp_kel::{EntryVerdict, validate_entry};

use super::IdentityError;

/// Whether `inception_event`, one encoded event unit, is a valid inception
/// of `identifier` (`09-security-model.md` §9.7.4.2 R2 and R3).
///
/// The unit must recompute to `identifier`, as
/// `SHA-256("SCP-KEL-ID-V1:" ‖ signed preimage)`, and pass every step of
/// R3's check order for position zero, its signature included. A unit that
/// is discarded, recomputes to another identifier, or is not an inception
/// gives `false`.
#[must_use]
pub fn verify_did(identifier: &Identifier, inception_event: &[u8]) -> bool {
    let validation = validate_entry(identifier, &[inception_event]);
    matches!(validation.verdict, EntryVerdict::Valid { .. }) && validation.discarded.is_empty()
}

/// Parses the canonical text form of an identifier (`03-identity.md` §3.1).
///
/// # Errors
///
/// [`IdentityError::NonCanonicalIdentifier`] where `text` is not the
/// canonical form: uppercase, padded, `did:` prefixed, or of any other
/// shape. No input is lowercased, trimmed or unpadded first.
pub fn parse_identifier(text: &str) -> Result<Identifier, IdentityError> {
    Ok(text.parse::<Identifier>()?)
}

#[cfg(test)]
mod tests {
    use scp_crypto::p256::{P256SecretKey, sign_prehash_rfc6979};
    use scp_did::{
        CommitmentEntry, CustodyType, FixedCommitment, KeyAlgorithm, KeyCondition, KeyEntry,
        KeyRole,
    };
    use scp_kel::{
        Continuation, EventPreimage, InceptionFields, KeyStateSnapshot, SignatureForm, SignerGroup,
        encode_preimage, prerotation_commitment,
    };

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// `BE32(len) ‖ signed preimage ‖ signature field`.
    fn unit_of(
        signed: &[u8],
        signature_field: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut unit = u32::try_from(signed.len())?.to_be_bytes().to_vec();
        unit.extend_from_slice(signed);
        unit.extend_from_slice(signature_field);
        Ok(unit)
    }

    fn v51_unit() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        unit_of(
            &hex::decode(V51_INCEPTION_PREIMAGE)?,
            &hex::decode(V51_INCEPTION_SIGNATURE)?,
        )
    }

    fn v51_identifier() -> Result<Identifier, Box<dyn std::error::Error>> {
        let bytes: [u8; 32] = hex::decode(V51_IDENTIFIER)?
            .try_into()
            .map_err(|_| "identifier is 32 bytes")?;
        Ok(Identifier::from_bytes(bytes))
    }

    /// A signed one-member inception whose continuation is `continuation`,
    /// and the identifier it derives.
    fn signed_inception(
        continuation: Continuation,
    ) -> Result<(Identifier, Vec<u8>), Box<dyn std::error::Error>> {
        let root = P256SecretKey::from_scalar_bytes(&[7; 32])?;
        let active = P256SecretKey::from_scalar_bytes(&[9; 32])?;
        let entry = |key: &P256SecretKey, role| KeyEntry {
            key: key.public_key().to_compressed(),
            role,
            condition: KeyCondition::Current,
            compromised_from: 0,
            custody_type: CustodyType::Software,
            key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
        };
        let encoded = encode_preimage(&EventPreimage::inception(InceptionFields {
            root_group: SignerGroup {
                indices: vec![0],
                forms: vec![SignatureForm::Raw],
            },
            key_state: KeyStateSnapshot {
                root_threshold: 1,
                keys: vec![
                    entry(&root, KeyRole::RootMember),
                    entry(&active, KeyRole::Active),
                ],
                witnesses: vec![],
                witnessing_interval: scp_kel::constants::DEFAULT_WITNESSING_INTERVAL,
                service_key_role: KeyRole::Active,
                delegator: Identifier::ZERO,
            },
            continuation,
        }))?;
        let signed = encoded.signed_preimage();
        let signature = sign_prehash_rfc6979(&root, &encoded.event_digest())?;
        let identifier = scp_kel::derive_identifier(encoded.preimage())?;
        Ok((identifier, unit_of(&signed, &signature)?))
    }

    fn fixes_commitment() -> Result<Continuation, Box<dyn std::error::Error>> {
        let next = P256SecretKey::from_scalar_bytes(&[11; 32])?;
        Ok(Continuation::FixesCommitment(FixedCommitment {
            commitments: vec![CommitmentEntry {
                commitment: prerotation_commitment(&next.public_key().to_compressed()),
                custody_type: CustodyType::Passkey,
                key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
            }],
            next_threshold: 1,
        }))
    }

    #[test]
    fn vector_51_inception_verifies() -> TestResult {
        assert!(verify_did(&v51_identifier()?, &v51_unit()?));
        Ok(())
    }

    #[test]
    fn a_flipped_signature_byte_fails() -> TestResult {
        let mut unit = v51_unit()?;
        let last = unit.len() - 1;
        unit[last] ^= 0x01;
        assert!(!verify_did(&v51_identifier()?, &unit));
        Ok(())
    }

    #[test]
    fn another_identifier_fails() -> TestResult {
        let mut bytes = *v51_identifier()?.as_bytes();
        bytes[0] ^= 0x01;
        assert!(!verify_did(&Identifier::from_bytes(bytes), &v51_unit()?));
        Ok(())
    }

    #[test]
    fn a_composed_inception_that_fixes_a_commitment_verifies() -> TestResult {
        let (identifier, unit) = signed_inception(fixes_commitment()?)?;
        assert!(verify_did(&identifier, &unit));
        Ok(())
    }

    #[test]
    fn an_inception_that_abandons_fails() -> TestResult {
        let (identifier, unit) = signed_inception(Continuation::Abandons)?;
        assert!(!verify_did(&identifier, &unit));
        Ok(())
    }

    #[test]
    fn a_key_state_unit_fails() -> TestResult {
        let unit = unit_of(&hex::decode(V51_PREIMAGE)?, &hex::decode(V51_SIGNATURE)?)?;
        assert!(!verify_did(&v51_identifier()?, &unit));
        Ok(())
    }

    #[test]
    fn the_canonical_form_parses_and_round_trips() -> TestResult {
        let identifier = v51_identifier()?;
        assert_eq!(parse_identifier(&identifier.to_string())?, identifier);
        Ok(())
    }

    #[test]
    fn non_canonical_forms_give_1106() -> TestResult {
        let canonical = v51_identifier()?.to_string();
        let body = canonical.trim_start_matches("scp:");
        let inputs = [
            canonical.to_ascii_uppercase(),
            format!("scp:{}", body.to_ascii_uppercase()),
            format!("{canonical}===="),
            format!("did:dht:{body}"),
        ];
        for input in inputs {
            let error = parse_identifier(&input)
                .err()
                .ok_or("non-canonical input parsed")?;
            assert_eq!(error, IdentityError::NonCanonicalIdentifier, "{input}");
            assert_eq!(error.code(), "SCP-IDENT-1106");
        }
        Ok(())
    }

    // Spec 25 Vector 51, copied from scp-kel's fixtures.
    const V51_IDENTIFIER: &str = "ccf037a6ebea7cc7bbe5f45f1390916a32f6658db9ee918dae9782dae760fcba";
    const V51_INCEPTION_PREIMAGE: &str = concat!(
        "5343502d4b454c2d4556454e542d56313a010000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000100",
        "0000000101000000000000000802b86554ca49a9bb429e555454b0e81c69242d",
        "efbed440f7dde65e3fd8aabdf33d02f0c2c400b1a26dc597eba50c752ba083ee",
        "6f3add7cdbf8049e3024b6c3851e8702c3d4e2a5c319b9869bef14077411afe3",
        "4743396ee96376b9e07ce907eceb428b0278210550385ce3b0449d868909adf4",
        "11a9531e886d4909063453347d58c2f437028669c107174e5219e9a66b15c6d2",
        "805610135b853eafad7e0c6f513d4f4b02b703849d444571033da6292bc75f55",
        "61eeed6fc4ee8787400ac6ce9daed75620361403b8d687792d2f1ccbe5cca256",
        "09a949fa39ef2c3c2b50c48aeb0ee954c2b96635026656dfeb9ed86ebd1e0b27",
        "40d52e9a8f4d69fef61d4157f254dce2fbcd3d21440000000100000001000000",
        "0902b86554ca49a9bb429e555454b0e81c69242defbed440f7dde65e3fd8aabd",
        "f33d01010000000000000000010102f0c2c400b1a26dc597eba50c752ba083ee",
        "6f3add7cdbf8049e3024b6c3851e8701010000000000000000020102c3d4e2a5",
        "c319b9869bef14077411afe34743396ee96376b9e07ce907eceb428b01010000",
        "00000000000003010278210550385ce3b0449d868909adf411a9531e886d4909",
        "063453347d58c2f437010100000000000000000401028669c107174e5219e9a6",
        "6b15c6d2805610135b853eafad7e0c6f513d4f4b02b701010000000000000000",
        "050103849d444571033da6292bc75f5561eeed6fc4ee8787400ac6ce9daed756",
        "20361401010000000000000000060103b8d687792d2f1ccbe5cca25609a949fa",
        "39ef2c3c2b50c48aeb0ee954c2b96635010100000000000000000701026656df",
        "eb9ed86ebd1e0b2740d52e9a8f4d69fef61d4157f254dce2fbcd3d2144010100",
        "00000000000000080102db931079de36ba5f17d6450a9e26378b05fc89704c32",
        "e6f9bc2ea14597fee28202010000000000000000090100000001e77d53354271",
        "e4c1c3c319cf7b5cfcc23be431c2ec795d5b6ecf549355f1561000000e100200",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000001000000016644cc0e3ef3eae7dd1274d305e48fb593acce69ed4e4cef",
        "a9c63683174ed0ac010100000001",
    );
    const V51_INCEPTION_SIGNATURE: &str = concat!(
        "335b62a56c8a0b2c5da1e467bf074138cdf829115e7aeb50a0725fcb394a797b",
        "460d3e8a0d48d189c881befb4338e546459a8b89c7d0015b1967f62bbfbcb00f",
    );
    const V51_PREIMAGE: &str = concat!(
        "5343502d4b454c2d4556454e542d56313a02ccf037a6ebea7cc7bbe5f45f1390",
        "916a32f6658db9ee918dae9782dae760fcba00000000000000015d23919df0fa",
        "99fb5076951e9b98aba559d7fb0dcab48cb0bbc40fe5df4ff568000000000100",
        "00000001010000000000000000000000010000000902b86554ca49a9bb429e55",
        "5454b0e81c69242defbed440f7dde65e3fd8aabdf33d01010000000000000000",
        "010102f0c2c400b1a26dc597eba50c752ba083ee6f3add7cdbf8049e3024b6c3",
        "851e8701010000000000000000020102c3d4e2a5c319b9869bef14077411afe3",
        "4743396ee96376b9e07ce907eceb428b01010000000000000000030102782105",
        "50385ce3b0449d868909adf411a9531e886d4909063453347d58c2f437010100",
        "000000000000000401028669c107174e5219e9a66b15c6d2805610135b853eaf",
        "ad7e0c6f513d4f4b02b701010000000000000000050103849d444571033da629",
        "2bc75f5561eeed6fc4ee8787400ac6ce9daed756203614010100000000000000",
        "00060103b8d687792d2f1ccbe5cca25609a949fa39ef2c3c2b50c48aeb0ee954",
        "c2b96635010100000000000000000701026656dfeb9ed86ebd1e0b2740d52e9a",
        "8f4d69fef61d4157f254dce2fbcd3d214401010000000000000000080102db93",
        "1079de36ba5f17d6450a9e26378b05fc89704c32e6f9bc2ea14597fee2820201",
        "0000000000000000090100000001e77d53354271e4c1c3c319cf7b5cfcc23be4",
        "31c2ec795d5b6ecf549355f1561000001c200200000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000",
    );
    const V51_SIGNATURE: &str = concat!(
        "e06a292f1bb82840708833e72107fee5e97c7344feb53fd37e0a963351c87e9d",
        "7de07af8245b601ad02ef7543bb55769cb281609cc4d63270c7570535c1bb747",
    );
}
