//! Broadcast context subscription validation.
//!
//! Validates UCAN tokens presented by subscribers joining broadcast contexts.
//! Ensures the token grants `messages:read` for the target context and that the
//! token's audience (`aud`) matches the subscriber presenting it.

use crate::crypto::ucan::capability::{CapabilityUri, check_capability_match};
use crate::crypto::ucan::{UcanError, UcanToken};

/// Validates a UCAN token for broadcast subscription (messages:read).
///
/// Checks two things:
/// 1. The token's audience (`aud`) matches `subscriber_did` -- prevents a
///    subscriber from presenting a UCAN issued to someone else.
/// 2. The token grants `messages:read` for the given `context_id`.
///
/// Standard UCAN validation (signature, chain, revocation, nonce, expiry)
/// should be performed separately via
/// [`crate::crypto::ucan::validate::validate_ucan`].
///
/// # Arguments
///
/// * `token` -- The UCAN token presented by the subscriber.
/// * `context_id` -- The broadcast context being subscribed to.
/// * `subscriber_did` -- The DID of the agent presenting the token.
///
/// # Errors
///
/// Returns [`UcanError::AudienceMismatch`] if the token's audience does not
/// match the subscriber DID.
/// Returns [`UcanError::CapabilityNotGranted`] if the token lacks a
/// `messages:read` capability for the context.
pub fn validate_messages_read_ucan(
    token: &UcanToken,
    context_id: &str,
    subscriber_did: &str,
) -> Result<(), UcanError> {
    if token.payload.aud != subscriber_did {
        return Err(UcanError::AudienceMismatch {
            expected: subscriber_did.to_owned(),
            actual: token.payload.aud.clone(),
        });
    }

    let required = CapabilityUri::new(context_id, "messages", "read");
    let granted: Vec<CapabilityUri> = token
        .payload
        .att
        .iter()
        .filter_map(|att| att.with.parse().ok())
        .collect();
    check_capability_match(&granted, &required)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::crypto::ucan::{Attenuation, UcanHeader, UcanPayload};

    fn make_token(aud: &str, att: Vec<Attenuation>) -> UcanToken {
        UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkCreator".to_owned(),
                aud: aud.to_owned(),
                exp: 1_700_000_000,
                nbf: None,
                nnc: "1699999000000-aabbccdd11223344".to_owned(),
                att,
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: "header.payload.signature".to_owned(),
        }
    }

    #[test]
    fn accepts_valid_subscriber_ucan() {
        let token = make_token(
            "did:dht:z6MkSubscriber",
            vec![Attenuation {
                with: "scp:ctx:broadcast-ctx-1/messages:read".to_owned(),
                can: "read".to_owned(),
            }],
        );

        let result =
            validate_messages_read_ucan(&token, "broadcast-ctx-1", "did:dht:z6MkSubscriber");
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_audience_mismatch() {
        let token = make_token(
            "did:dht:z6MkOtherAgent",
            vec![Attenuation {
                with: "scp:ctx:broadcast-ctx-1/messages:read".to_owned(),
                can: "read".to_owned(),
            }],
        );

        let result =
            validate_messages_read_ucan(&token, "broadcast-ctx-1", "did:dht:z6MkSubscriber");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, UcanError::AudienceMismatch { ref expected, ref actual }
                if expected == "did:dht:z6MkSubscriber" && actual == "did:dht:z6MkOtherAgent")
        );
    }

    #[test]
    fn rejects_missing_messages_read_capability() {
        let token = make_token(
            "did:dht:z6MkSubscriber",
            vec![Attenuation {
                with: "scp:ctx:broadcast-ctx-1/messages:write".to_owned(),
                can: "write".to_owned(),
            }],
        );

        let result =
            validate_messages_read_ucan(&token, "broadcast-ctx-1", "did:dht:z6MkSubscriber");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            UcanError::CapabilityNotGranted(_)
        ));
    }

    #[test]
    fn rejects_wrong_context_id() {
        let token = make_token(
            "did:dht:z6MkSubscriber",
            vec![Attenuation {
                with: "scp:ctx:other-ctx/messages:read".to_owned(),
                can: "read".to_owned(),
            }],
        );

        let result =
            validate_messages_read_ucan(&token, "broadcast-ctx-1", "did:dht:z6MkSubscriber");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            UcanError::CapabilityNotGranted(_)
        ));
    }

    #[test]
    fn accepts_wildcard_context_capability() {
        let token = make_token(
            "did:dht:z6MkSubscriber",
            vec![Attenuation {
                with: "scp:ctx:*/messages:read".to_owned(),
                can: "read".to_owned(),
            }],
        );

        let result =
            validate_messages_read_ucan(&token, "broadcast-ctx-1", "did:dht:z6MkSubscriber");
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_empty_attestations() {
        let token = make_token("did:dht:z6MkSubscriber", vec![]);

        let result =
            validate_messages_read_ucan(&token, "broadcast-ctx-1", "did:dht:z6MkSubscriber");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            UcanError::CapabilityNotGranted(_)
        ));
    }

    #[test]
    fn audience_checked_before_capability() {
        let token = make_token("did:dht:z6MkWrongAud", vec![]);

        let result =
            validate_messages_read_ucan(&token, "broadcast-ctx-1", "did:dht:z6MkSubscriber");
        assert!(matches!(
            result.unwrap_err(),
            UcanError::AudienceMismatch { .. }
        ));
    }
}
