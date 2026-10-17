//! Canonical identifiers for challenge parties (spec 07 §7.3.4
//! "Identifiers").
//!
//! A did:dht identifier has sixteen z-base-32 spellings of one 32-byte key,
//! because the last character carries padding bits. Two parties compared by
//! string could then be one key under two names, which defeats the
//! `verifier ≠ subject` rule and the trusted-verifier list. Every challenge
//! step parses its identifiers into [`CanonicalIdentifier`] first; equality
//! compares the decoded key. Encoders never use it: a preimage signs the
//! identifier's text exactly as carried.

use std::hash::{Hash, Hasher};

use super::TrustError;

/// An identifier that decodes to a 32-byte key and is that key's only
/// accepted spelling.
///
/// `PartialEq` and `Hash` compare the key, never the text.
#[derive(Debug, Clone)]
pub struct CanonicalIdentifier {
    text: String,
    key: [u8; 32],
}

impl CanonicalIdentifier {
    /// Parses `identifier`.
    ///
    /// - `did:dht:z…` must decode under
    ///   [`scp_did::extract_public_key_from_did`], which refuses every padding
    ///   alias by re-encoding.
    /// - `did:key:<hex>` is a test fixture form, accepted only under
    ///   `cfg(test)` or the `testing` feature, and only as lowercase hex.
    /// - Every other form is refused.
    ///
    /// # Errors
    ///
    /// [`TrustError::NonCanonicalIdentifier`] naming the identifier and why.
    pub fn parse(identifier: &str) -> Result<Self, TrustError> {
        let refuse = |reason: String| TrustError::NonCanonicalIdentifier {
            identifier: identifier.to_owned(),
            reason,
        };
        if identifier.starts_with("did:dht:") {
            let key = scp_did::extract_public_key_from_did(identifier).map_err(refuse)?;
            return Ok(Self {
                text: identifier.to_owned(),
                key,
            });
        }
        #[cfg(any(test, feature = "testing"))]
        if let Some(hex_text) = identifier.strip_prefix("did:key:") {
            let key = scp_did::extract_public_key_from_did(identifier).map_err(refuse)?;
            if hex::encode(key) != hex_text {
                return Err(refuse("did:key hex is not lowercase canonical".to_owned()));
            }
            return Ok(Self {
                text: identifier.to_owned(),
                key,
            });
        }
        Err(refuse("only did:dht identifiers are accepted".to_owned()))
    }

    /// The identifier exactly as parsed.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The decoded 32-byte key.
    #[must_use]
    pub const fn key(&self) -> &[u8; 32] {
        &self.key
    }
}

impl PartialEq for CanonicalIdentifier {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for CanonicalIdentifier {}

impl Hash for CanonicalIdentifier {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The last of the 52 characters carries one key bit and four padding
    /// bits, so the 32 last characters spell two keys sixteen ways each.
    /// Exactly one spelling of each key parses.
    #[test]
    fn did_dht_padding_alias_is_refused() {
        let key = [7u8; 32];
        let canonical = scp_did::did_dht_from_public_key(&key).0;
        let parsed = CanonicalIdentifier::parse(&canonical).unwrap();
        assert_eq!(parsed.key(), &key);
        let alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769";
        let stem = &canonical[..canonical.len() - 1];
        let mut accepted = 0;
        for c in alphabet.chars() {
            let candidate = format!("{stem}{c}");
            match CanonicalIdentifier::parse(&candidate) {
                Ok(id) => {
                    // The canonical spelling of this key, or of the key
                    // whose final bit differs.
                    assert_eq!(id == parsed, candidate == canonical, "{candidate}");
                    assert_eq!(id.as_str(), scp_did::did_dht_from_public_key(id.key()).0);
                    accepted += 1;
                }
                Err(TrustError::NonCanonicalIdentifier { identifier, .. }) => {
                    assert_eq!(identifier, candidate);
                }
                Err(other) => panic!("unexpected error {other:?}"),
            }
        }
        assert_eq!(accepted, 2);
    }

    #[test]
    fn equality_compares_keys() {
        let key = [3u8; 32];
        let dht = CanonicalIdentifier::parse(&scp_did::did_dht_from_public_key(&key).0).unwrap();
        let fixture = CanonicalIdentifier::parse(&format!("did:key:{}", hex::encode(key))).unwrap();
        assert_eq!(dht, fixture);
        assert_ne!(dht.as_str(), fixture.as_str());
    }

    #[test]
    fn other_forms_are_refused() {
        for bad in [
            "",
            "did:dht:verifier",
            "scp:tfgiiao36zlseo2tzfoi32knfx6topped3qloxcsube5gdvfrqgq",
            &format!("did:key:{}", hex::encode_upper([0xabu8; 32])),
            "did:web:example.com",
        ] {
            assert!(
                matches!(
                    CanonicalIdentifier::parse(bad),
                    Err(TrustError::NonCanonicalIdentifier { .. })
                ),
                "{bad}"
            );
        }
    }
}
