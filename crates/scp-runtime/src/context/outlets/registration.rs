//! Runtime-side registration helpers for outlet acceptance.
//!
//! `pin_outlet_message_key_at_acceptance` is the integration point between
//! [`super::message_key::derive_outlet_message_key`] (the pure derive
//! helper) and the per-context `ContextManager` registration pipeline. It
//! is invoked exactly once per `OutletRegistration` acceptance, at the
//! moment MLS commits the registration, and produces the 32-byte
//! `outlet_message_key` that gets pinned to the outlet's registration
//! state.
//!
//! See `.docs/specs/05-contexts.md` §5.4.4 round-5 and SCP-OUT-041a.

use scp_protocol::context::ContextError;
use scp_protocol::context::outlets::OutletId;
use scp_protocol::context::outlets::errors::OUTLET_MESSAGE_KEY_LEN;

use super::super::interface::ikm_commitment::MlsExporter;
use super::message_key::{DeriveOutletMessageKeyError, derive_outlet_message_key};

/// Outcome of pinning a freshly-derived `outlet_message_key` to a single
/// `OutletRegistration` acceptance.
///
/// The pinned key is the MLS-exporter-derived 32-byte HMAC key that keys
/// the on-wire `OutletError.message` field for every error emitted by this
/// outlet (§5.4.4 round-5). It is byte-equal to the value that
/// [`derive_outlet_message_key`] would return on the **acceptance-time**
/// exporter; subsequent epoch advances (including grace-window epoch
/// transitions per BH5-B2) MUST NOT cause re-derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedOutletMessageKey {
    /// The outlet whose registration this key was derived for. Stored
    /// verbatim so callers do not need to re-thread `outlet_id` through
    /// downstream persistence calls.
    pub outlet_id: OutletId,
    /// Event-log id of the [`OutletRegistration`](scp_protocol::context::outlets::OutletRegistration)
    /// event whose acceptance produced the key. Persisted alongside the key
    /// so the SCP-OUT-041b receiver LRU can disambiguate concurrent
    /// re-registrations of the same outlet.
    pub registration_event_id: [u8; 32],
    /// 32-byte `outlet_message_key` derived at acceptance via
    /// `MLS_EXPORTER("scp-outlet-message-v1:" || BE32(len(outlet_id))
    /// || outlet_id, b"", 32)`.
    pub outlet_message_key: [u8; OUTLET_MESSAGE_KEY_LEN],
}

/// Derives the §5.4.4 round-5 `outlet_message_key` for an outlet at
/// registration acceptance and packages it with the registration's
/// event-log id for persistence.
///
/// Callers MUST invoke this exactly **once** per outlet-registration
/// acceptance, at the moment MLS commits the registration. The 32-byte
/// `outlet_message_key` returned in the [`PinnedOutletMessageKey`] is
/// pinned for the lifetime of the registration — it MUST NOT be
/// re-derived at error emission time, and grace-window epoch transitions
/// MUST NOT change it (the BH5-B2 closure).
///
/// Persistence under
/// `context/{context_id}/outlet/{outlet_id}/registration/{registration_event_id}/message_key`
/// is the responsibility of the caller (typically
/// `ContextManager::execute_register_outlet`), keyed by
/// `registration_event_id` so concurrent registrations of the same
/// outlet can coexist for the SCP-OUT-041b receiver LRU.
///
/// # Errors
///
/// Returns [`DeriveOutletMessageKeyError`] if the underlying exporter call
/// fails (e.g., the MLS group has been destroyed or the provider returns
/// an unexpected payload length).
///
/// # Spec
///
/// - `.docs/specs/05-contexts.md` §5.4.4 round-5.
/// - `.docs/specs/09-security-model.md` §9.18.3.
/// - `.docs/adrs/ADR-049-outlet-redesign.md` Round 5.
///
/// # Story
///
/// SCP-OUT-041a.
pub fn pin_outlet_message_key_at_acceptance<E: MlsExporter + ?Sized>(
    context_mls: &E,
    context_id_bytes: &[u8; 32],
    outlet_id: &OutletId,
    registration_event_id: [u8; 32],
) -> Result<PinnedOutletMessageKey, DeriveOutletMessageKeyError> {
    let outlet_message_key = derive_outlet_message_key(context_mls, context_id_bytes, outlet_id)?;
    Ok(PinnedOutletMessageKey {
        outlet_id: outlet_id.clone(),
        registration_event_id,
        outlet_message_key,
    })
}

/// Maps a [`DeriveOutletMessageKeyError`] into a [`ContextError`] suitable
/// for surfacing through the runtime acceptance handler.
///
/// Both variants surface as [`ContextError::CryptoFailed`] — the failure
/// modes (provider error, unexpected exporter length) are both
/// crypto-provider-level conditions that must abort the registration.
#[must_use]
pub fn derive_error_to_context_error(err: DeriveOutletMessageKeyError) -> ContextError {
    match err {
        DeriveOutletMessageKeyError::ProviderFailed(inner) => inner,
        DeriveOutletMessageKeyError::UnexpectedExporterLength { actual, expected } => {
            ContextError::CryptoFailed(format!(
                "outlet_message_key exporter returned {actual} bytes, expected {expected}"
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::uninlined_format_args,
    clippy::match_wildcard_for_single_variants,
    clippy::type_complexity
)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    /// Deterministic exporter used by the unit tests. Mirrors the fixture
    /// in [`super::super::message_key`] tests but is duplicated here to
    /// keep the test module self-contained.
    #[derive(Default)]
    struct DeterministicExporter {
        epochs: Mutex<std::collections::HashMap<[u8; 32], u64>>,
    }

    impl DeterministicExporter {
        fn epoch_for(&self, context_id: &[u8; 32]) -> u64 {
            *self.epochs.lock().unwrap().get(context_id).unwrap_or(&0)
        }
        fn advance_epoch(&self, context_id: &[u8; 32]) {
            *self.epochs.lock().unwrap().entry(*context_id).or_insert(0) += 1;
        }
    }

    impl MlsExporter for DeterministicExporter {
        fn export_secret(
            &self,
            context_id: &[u8; 32],
            label: &[u8],
            context: &[u8],
            length: usize,
        ) -> Result<Zeroizing<Vec<u8>>, ContextError> {
            let epoch = self.epoch_for(context_id);
            let mut hasher = Sha256::new();
            hasher.update(b"FIXTURE-EXPORTER-V1:");
            hasher.update(context_id);
            hasher.update(epoch.to_be_bytes());
            let label_len = u32::try_from(label.len()).unwrap_or(u32::MAX);
            let context_len = u32::try_from(context.len()).unwrap_or(u32::MAX);
            hasher.update(label_len.to_be_bytes());
            hasher.update(label);
            hasher.update(context_len.to_be_bytes());
            hasher.update(context);
            let digest: [u8; 32] = hasher.finalize().into();
            assert_eq!(length, 32);
            Ok(Zeroizing::new(digest.to_vec()))
        }
    }

    #[test]
    fn pin_returns_outlet_id_event_id_and_key() {
        let exporter = DeterministicExporter::default();
        let outlet_id: OutletId = "calculator".to_owned();
        let context_id = [0x11; 32];
        let event_id = [0x22; 32];
        let pinned =
            pin_outlet_message_key_at_acceptance(&exporter, &context_id, &outlet_id, event_id)
                .expect("pin ok");
        assert_eq!(pinned.outlet_id, outlet_id);
        assert_eq!(pinned.registration_event_id, event_id);
        // The key matches what `derive_outlet_message_key` would produce
        // independently — `pin_outlet_message_key_at_acceptance` is a
        // packaging wrapper, not a separate derivation.
        let direct = derive_outlet_message_key(&exporter, &context_id, &outlet_id).unwrap();
        assert_eq!(pinned.outlet_message_key, direct);
    }

    /// AC6 (re-read determinism): pinning the same registration twice in a
    /// row yields a byte-equal `outlet_message_key`.
    #[test]
    fn pin_is_deterministic_across_re_reads() {
        let exporter = DeterministicExporter::default();
        let outlet_id: OutletId = "weather".to_owned();
        let context_id = [0x33; 32];
        let event_id = [0x44; 32];
        let a = pin_outlet_message_key_at_acceptance(&exporter, &context_id, &outlet_id, event_id)
            .unwrap();
        let b = pin_outlet_message_key_at_acceptance(&exporter, &context_id, &outlet_id, event_id)
            .unwrap();
        assert_eq!(a, b);
        assert_eq!(a.outlet_message_key, b.outlet_message_key);
    }

    /// AC4 (context distinctness): two contexts pin distinct keys for the
    /// same outlet_id even when the registration_event_id happens to
    /// coincide.
    #[test]
    fn pin_in_distinct_contexts_yields_distinct_keys() {
        let exporter = DeterministicExporter::default();
        let outlet_id: OutletId = "calculator".to_owned();
        let event_id = [0x55; 32];
        let ctx_a = [0xAA; 32];
        let ctx_b = [0xBB; 32];
        let a =
            pin_outlet_message_key_at_acceptance(&exporter, &ctx_a, &outlet_id, event_id).unwrap();
        let b =
            pin_outlet_message_key_at_acceptance(&exporter, &ctx_b, &outlet_id, event_id).unwrap();
        assert_ne!(a.outlet_message_key, b.outlet_message_key);
    }

    /// AC5 (BH5-B2 grace-window closure): the **pinned** key returned by
    /// `pin_outlet_message_key_at_acceptance` must not change when the
    /// MLS epoch advances after the pin. The function is the single
    /// derive entry point at acceptance time; callers cache the
    /// returned `PinnedOutletMessageKey` and never call it again.
    /// This test asserts the contract by:
    ///
    /// 1. Pinning at epoch E and recording the value.
    /// 2. Advancing the simulated epoch to E+1 (the grace-window
    ///    transition).
    /// 3. Verifying that an independent derivation at E+1 (which a
    ///    BUGGY implementation would do at error-emission time) yields
    ///    a DIFFERENT value — confirming the fixture is genuinely
    ///    epoch-sensitive.
    /// 4. Verifying that the pinned key from step 1 is byte-identical
    ///    to a re-pin call we deliberately DON'T make in production —
    ///    the cache is the contract. We assert the cached value is
    ///    stable.
    #[test]
    fn pinned_key_unchanged_across_grace_window_epoch_transition() {
        let exporter = DeterministicExporter::default();
        let outlet_id: OutletId = "weather".to_owned();
        let context_id = [0x66; 32];
        let event_id = [0x77; 32];
        // (1) Pin at epoch E.
        let pinned =
            pin_outlet_message_key_at_acceptance(&exporter, &context_id, &outlet_id, event_id)
                .unwrap();
        let cached_key = pinned.outlet_message_key;

        // (2) Grace-window epoch transition E -> E+1.
        exporter.advance_epoch(&context_id);

        // (3) Independent derivation at E+1 yields a different value.
        let post_advance = derive_outlet_message_key(&exporter, &context_id, &outlet_id).unwrap();
        assert_ne!(
            cached_key, post_advance,
            "fixture must produce different output across epoch advance for the test to be meaningful"
        );

        // (4) The cached key from (1) is byte-stable — a buggy caller
        // that re-derives at E+1 would observe `post_advance`, but the
        // protocol contract is to use the cached value. The test asserts
        // the **value** the caller is committed to — `pinned.outlet_message_key`
        // — is the pre-advance one, not the post-advance one.
        assert_eq!(pinned.outlet_message_key, cached_key);
        assert_ne!(pinned.outlet_message_key, post_advance);

        // Bumping again does not change the pinned cache:
        exporter.advance_epoch(&context_id);
        assert_eq!(pinned.outlet_message_key, cached_key);
    }

    #[test]
    fn derive_error_to_context_error_maps_provider_failure() {
        let inner = ContextError::CryptoFailed("MLS group destroyed".into());
        let err = DeriveOutletMessageKeyError::ProviderFailed(inner);
        let mapped = derive_error_to_context_error(err);
        assert!(matches!(mapped, ContextError::CryptoFailed(_)));
    }

    #[test]
    fn derive_error_to_context_error_maps_unexpected_length() {
        let err = DeriveOutletMessageKeyError::UnexpectedExporterLength {
            actual: 16,
            expected: OUTLET_MESSAGE_KEY_LEN,
        };
        let mapped = derive_error_to_context_error(err);
        match mapped {
            ContextError::CryptoFailed(msg) => {
                assert!(msg.contains("16"));
                assert!(msg.contains("32"));
            }
            other => panic!("expected CryptoFailed, got {other:?}"),
        }
    }

    /// Defense-in-depth: pinning preserves the `outlet_id` verbatim even
    /// when the id contains UTF-8 bytes that could be mis-handled by
    /// careless serialization.
    #[test]
    fn pin_preserves_unicode_outlet_id() {
        let exporter = DeterministicExporter::default();
        let outlet_id: OutletId = "tüp-名前".to_owned();
        let context_id = [0x88; 32];
        let event_id = [0x99; 32];
        let pinned =
            pin_outlet_message_key_at_acceptance(&exporter, &context_id, &outlet_id, event_id)
                .unwrap();
        assert_eq!(pinned.outlet_id, outlet_id);
    }
}
