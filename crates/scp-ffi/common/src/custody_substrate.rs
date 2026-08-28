//! The two facts a published custody value states, read off a platform
//! `KeyCustodyProvider` callback.
//!
//! §3.2.2 of the identity spec states that a DID document publishes
//! extractability and the unlock factor, and that
//! [`ScpKeyCustodyAttestation::derive`](scp_did::attestation::ScpKeyCustodyAttestation::derive)
//! reads both off the backend rather than taking them from a caller. A backend
//! answers both questions through
//! [`CustodySubstrate`](scp_did::attestation::CustodySubstrate).
//!
//! `FileKeyCustody`, `SqliteKeyCustody`, and `InMemoryKeyCustody` implement
//! that trait directly, because each one owns the store it describes. A
//! callback custody owns no store: the Apple Keychain adapter and the Android
//! Keystore adapter hold the key on the far side of the FFI boundary, so the
//! adapter is the only party that can answer either question. This module
//! carries the answers the adapter gave across that boundary and presents them
//! to `derive` as a `CustodySubstrate`.
//!
//! The three bridges share one type here so a Swift adapter, a Kotlin adapter,
//! a Python provider, and a JavaScript provider all report the two facts in the
//! same wire form, and one wire string carries one meaning on every bridge.

use scp_did::attestation::{CustodySubstrate, KeyCustodyModel, UnlockFactor};

/// The wire strings a `KeyCustodyProvider` returns from `unlock_factor`.
///
/// Each string names the [`UnlockFactor`] variant
/// [`parse_unlock_factor`] maps it to. An SDK adapter picks one of these five
/// strings; a bridge rejects nothing here, because
/// [`ReportedCustodySubstrate`] answers every other string with the variant
/// that publishes no custody value.
pub const UNLOCK_FACTOR_WIRE_VALUES: [&str; 5] = [
    "biometric",
    "pin",
    "passphrase",
    "caller_supplied_key",
    "unprotected",
];

/// Maps the wire string a `KeyCustodyProvider` returned onto an
/// [`UnlockFactor`].
///
/// A string [`UNLOCK_FACTOR_WIRE_VALUES`] does not list maps to
/// [`UnlockFactor::CallerSuppliedKey`], which publishes no custody value under
/// either extractability answer
/// ([`KeyCustodyModel::from_substrate`](scp_did::attestation::KeyCustodyModel::from_substrate)
/// returns `UnstatableCustody` for both pairs it forms). That variant's own
/// documentation states the position a bridge is in when a provider answers a
/// string this vocabulary does not spell: the backend "cannot name the factor a
/// holder presents". [`UnlockFactor::Unprotected`] would state instead that
/// nothing gates the key, which is a claim about the provider that the bridge
/// has no evidence for.
#[must_use]
pub fn parse_unlock_factor(reported: &str) -> UnlockFactor {
    match reported {
        "biometric" => UnlockFactor::Biometric,
        "pin" => UnlockFactor::Pin,
        "passphrase" => UnlockFactor::Passphrase,
        "unprotected" => UnlockFactor::Unprotected,
        _ => UnlockFactor::CallerSuppliedKey,
    }
}

/// The two facts one `KeyCustodyProvider` reported about one key.
///
/// A bridge builds this from the provider's answers and hands it to
/// [`ScpKeyCustodyAttestation::derive`](scp_did::attestation::ScpKeyCustodyAttestation::derive)
/// as a [`CustodySubstrate`]. The type holds the answers rather than a
/// reference to the provider, because the napi bridge cannot read a return
/// value out of a synchronous JavaScript callback dispatched from a tokio
/// worker thread, and `CustodySubstrate`'s two methods are synchronous. Each
/// bridge therefore reads both answers asynchronously, on the thread that may
/// call the provider, and stores them here.
///
/// One value describes one key, because
/// [`ScpKeyCustodyAttestation::derive`](scp_did::attestation::ScpKeyCustodyAttestation::derive)
/// takes one substrate for the `#active` key and another for the `#agent` key,
/// and a provider may hold the two keys under different unlock factors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportedCustodySubstrate {
    key_is_extractable: bool,
    unlock_factor: UnlockFactor,
}

impl ReportedCustodySubstrate {
    /// Records what a provider answered about one key.
    ///
    /// `reported_unlock_factor` is the raw string the provider returned;
    /// [`parse_unlock_factor`] maps it.
    #[must_use]
    pub fn new(key_is_extractable: bool, reported_unlock_factor: &str) -> Self {
        Self {
            key_is_extractable,
            unlock_factor: parse_unlock_factor(reported_unlock_factor),
        }
    }

    /// Copies the two facts out of a backend that answers them directly.
    ///
    /// `FileKeyCustody`, `SqliteKeyCustody`, and `InMemoryKeyCustody` each
    /// implement [`CustodySubstrate`] about themselves, so a bridge that holds
    /// one of them reads both answers here rather than crossing a callback
    /// boundary. A bridge's custody enum can then answer one question — what
    /// does the backend behind this key publish — for every variant it carries.
    #[must_use]
    pub fn from_substrate(substrate: &dyn CustodySubstrate) -> Self {
        Self {
            key_is_extractable: substrate.key_is_extractable(),
            unlock_factor: substrate.unlock_factor(),
        }
    }
}

/// Returns the wire form of the custody value a backend publishes, and `None`
/// when the backend reports a pair the published vocabulary states no value
/// for.
///
/// §3.2.2 of the identity spec states three published values and states that a
/// backend reporting any other pair "publishes no custody attestation at all".
/// ADR-039's Enforcement Stack layer 4 gives that absence a meaning, "Absence
/// of attestation is itself a signal", so `None` costs a reader one signal and
/// tells that reader nothing false.
///
/// The three strings are the ones `KeyCustodyModel`'s
/// `#[serde(rename_all = "kebab-case")]` produces, so a value this function
/// returns and a value a DID document carries are the same string.
#[must_use]
pub fn published_custody_wire_value(substrate: &dyn CustodySubstrate) -> Option<&'static str> {
    KeyCustodyModel::from_substrate(substrate)
        .ok()
        .map(|model| match model {
            KeyCustodyModel::NonExtractableBiometric => "non-extractable-biometric",
            KeyCustodyModel::NonExtractablePin => "non-extractable-pin",
            KeyCustodyModel::ExtractablePassphrase => "extractable-passphrase",
        })
}

impl CustodySubstrate for ReportedCustodySubstrate {
    /// Returns what the provider answered when the bridge asked whether the
    /// private key can leave the store the provider holds it in.
    fn key_is_extractable(&self) -> bool {
        self.key_is_extractable
    }

    /// Returns the [`UnlockFactor`] [`parse_unlock_factor`] read out of the
    /// string the provider returned.
    fn unlock_factor(&self) -> UnlockFactor {
        self.unlock_factor
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        ReportedCustodySubstrate, UNLOCK_FACTOR_WIRE_VALUES, parse_unlock_factor,
        published_custody_wire_value,
    };
    use scp_did::attestation::{CustodySubstrate, KeyCustodyModel, UnlockFactor};

    /// Every string `published_custody_wire_value` returns equals the string
    /// `KeyCustodyModel`'s own serde representation produces, so a bridge that
    /// reports the value and a DID document that carries it cannot drift.
    #[test]
    fn the_wire_values_match_the_serde_representation() {
        let cases = [(false, "biometric"), (false, "pin"), (true, "passphrase")];
        for (key_is_extractable, factor) in cases {
            let substrate = ReportedCustodySubstrate::new(key_is_extractable, factor);
            let ours = published_custody_wire_value(&substrate).expect("pair publishes a value");
            let model =
                KeyCustodyModel::from_substrate(&substrate).expect("pair publishes a value");
            let serde_form = serde_json::to_string(&model).expect("KeyCustodyModel serializes");
            assert_eq!(
                serde_form,
                format!("\"{ours}\""),
                "the shared wire value must equal the serde representation"
            );
        }
    }

    /// A pair the published vocabulary states no value for reports no string.
    #[test]
    fn an_unstatable_pair_reports_no_wire_value() {
        let substrate = ReportedCustodySubstrate::new(true, "biometric");
        assert_eq!(published_custody_wire_value(&substrate), None);
    }

    /// Each of the five wire strings maps to the variant it names.
    #[test]
    fn each_wire_string_maps_to_the_variant_it_names() {
        assert_eq!(parse_unlock_factor("biometric"), UnlockFactor::Biometric);
        assert_eq!(parse_unlock_factor("pin"), UnlockFactor::Pin);
        assert_eq!(parse_unlock_factor("passphrase"), UnlockFactor::Passphrase);
        assert_eq!(
            parse_unlock_factor("caller_supplied_key"),
            UnlockFactor::CallerSuppliedKey
        );
        assert_eq!(
            parse_unlock_factor("unprotected"),
            UnlockFactor::Unprotected
        );
    }

    /// The constant lists exactly the strings the parser reads, so an SDK
    /// adapter that copies the constant reaches every variant the parser
    /// names.
    #[test]
    fn the_constant_lists_every_string_the_parser_reads() {
        assert_eq!(UNLOCK_FACTOR_WIRE_VALUES.len(), 5);
        let mut distinct: Vec<UnlockFactor> = UNLOCK_FACTOR_WIRE_VALUES
            .iter()
            .map(|wire| parse_unlock_factor(wire))
            .collect();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            5,
            "two wire strings collapsed onto one UnlockFactor: {distinct:?}"
        );
    }

    /// A string the vocabulary does not spell publishes no custody value under
    /// either extractability answer.
    #[test]
    fn an_unrecognised_string_publishes_nothing() {
        for key_is_extractable in [true, false] {
            let substrate = ReportedCustodySubstrate::new(key_is_extractable, "yubikey_touch");
            assert_eq!(substrate.unlock_factor(), UnlockFactor::CallerSuppliedKey);
            let published = KeyCustodyModel::from_substrate(&substrate);
            assert!(
                published.is_err(),
                "an unrecognised unlock factor must publish no custody value, \
                 got: {published:?}"
            );
        }
    }

    /// The three publishable pairs reach the three published values.
    #[test]
    fn the_three_publishable_pairs_reach_their_published_values() {
        let cases = [
            (false, "biometric", KeyCustodyModel::NonExtractableBiometric),
            (false, "pin", KeyCustodyModel::NonExtractablePin),
            (true, "passphrase", KeyCustodyModel::ExtractablePassphrase),
        ];
        for (key_is_extractable, wire, expected) in cases {
            let substrate = ReportedCustodySubstrate::new(key_is_extractable, wire);
            assert_eq!(substrate.key_is_extractable(), key_is_extractable);
            assert_eq!(
                KeyCustodyModel::from_substrate(&substrate).expect("pair must publish a value"),
                expected
            );
        }
    }
}
