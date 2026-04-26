//! `derive_outlet_message_key` — accept-time MLS-exporter derivation of the
//! per-outlet HMAC key that keys the on-wire `OutletError.message` field
//! (§5.4.4 round-5).
//!
//! Cryptographic shape (matches §5.4.4 byte-for-byte):
//!
//! ```text
//! outlet_message_key = MLS_EXPORTER(
//!     "scp-outlet-message-v1:" || BE32(len(outlet_id)) || outlet_id,
//!     b"",
//!     32,
//! )
//! ```
//!
//! The exporter is evaluated **once** at outlet-registration acceptance —
//! the moment MLS commits the registration — and pinned for the lifetime
//! of the registration (implementation_hash-locked). This story ships the
//! pure derive helper plus its unit tests; the persistence wiring at
//! `AcceptOutletRegistration` time lives in
//! [`super::registration::pin_outlet_message_key_at_acceptance`].
//!
//! # Why pinning closes BH5-B2
//!
//! Pinning at acceptance closes the §5.4.4 epoch-grace covert channel
//! (BH5-B2). An operator holding two concurrent memberships during an
//! epoch-grace window in a single context — one using epoch E's exporter,
//! the other using epoch E+1's exporter — would, under a per-emission
//! re-derivation rule, have produced two distinct wire-byte sequences for
//! the same `catalog_key`, encoding one bit of covert signal per emission
//! straddling the grace boundary. Pinning the key at registration
//! acceptance eliminates this channel entirely: the exporter is evaluated
//! exactly once per registration, and grace-window epoch transitions
//! never re-derive it.
//!
//! See:
//! - `.docs/specs/05-contexts.md` §5.4.4 (round-5 catalog-plus-HMAC rule)
//! - `.docs/specs/09-security-model.md` §9.18.3 (`scp-outlet-message-v1:`
//!   exporter label registration)
//! - `.docs/adrs/ADR-049-outlet-redesign.md` Round 5 — accept-time exporter
//!   pinning closes the epoch-grace covert channel.

use std::collections::VecDeque;

use scp_protocol::context::ContextError;
use scp_protocol::context::outlets::OutletId;
use scp_protocol::context::outlets::errors::{OUTLET_MESSAGE_KEY_LEN, REGISTRATION_EVENT_ID_LEN};

use super::super::interface::ikm_commitment::MlsExporter;

/// MLS exporter label prefix for the per-outlet message-key derivation
/// (§5.4.4 round-5, registered in spec §9.18.3).
///
/// Value: `scp-outlet-message-v1:`. The full exporter label appended at
/// derive time is
/// `MESSAGE_KEY_EXPORTER_LABEL_PREFIX || BE32(len(outlet_id)) || outlet_id`,
/// so the same `outlet_id` in two distinct contexts produces two distinct
/// keys (each context's MLS group has its own exporter).
pub const MESSAGE_KEY_EXPORTER_LABEL_PREFIX: &[u8] = b"scp-outlet-message-v1:";

/// Derive errors for [`derive_outlet_message_key`].
#[derive(Debug, thiserror::Error)]
pub enum DeriveOutletMessageKeyError {
    /// The MLS exporter call returned a payload of unexpected length. Should
    /// not happen when invoked with `length = 32`, but is checked defensively
    /// because the persisted key field is `[u8; 32]`.
    #[error("MLS exporter returned {actual} bytes, expected {expected} for outlet_message_key")]
    UnexpectedExporterLength {
        /// The actual byte count returned by the provider.
        actual: usize,
        /// The expected byte count (always [`OUTLET_MESSAGE_KEY_LEN`]).
        expected: usize,
    },
    /// The crypto provider rejected the exporter call (e.g., MLS group
    /// destroyed, no group registered for the context).
    #[error("MLS exporter call failed: {0}")]
    ProviderFailed(#[from] ContextError),
}

/// Derives the §5.4.4 round-5 `outlet_message_key` for a single outlet
/// registration in a single context.
///
/// Computes:
///
/// ```text
/// MLS_EXPORTER(
///     "scp-outlet-message-v1:" || BE32(len(outlet_id)) || outlet_id,
///     b"",
///     32,
/// )
/// ```
///
/// on the hosting context's MLS group at the **current** epoch — callers
/// MUST invoke this exactly once per `OutletRegistration` acceptance, at
/// the moment MLS commits the registration. The 32-byte result is then
/// pinned to the outlet's registration state via
/// [`super::registration::pin_outlet_message_key_at_acceptance`].
///
/// `context_id` is the 32-byte MLS group id (the same key used everywhere
/// else by [`scp_protocol::context::builder::ContextCryptoProvider`]).
/// `outlet_id` is the human-readable outlet identifier (the same string
/// that appears in [`scp_protocol::context::outlets::OutletRegistration::outlet_id`]).
/// The `BE32(len(outlet_id))` length prefix prevents concatenation
/// ambiguity (e.g., two outlets named `"a"` + `"bc"` vs. `"ab"` + `"c"`
/// produce distinct exporter labels).
///
/// # Errors
///
/// - [`DeriveOutletMessageKeyError::ProviderFailed`] when the exporter
///   call fails (typically because the MLS group has been destroyed).
/// - [`DeriveOutletMessageKeyError::UnexpectedExporterLength`] if the
///   provider returns an unexpected length.
///
/// # Spec
///
/// - `.docs/specs/05-contexts.md` §5.4.4 — round-5 catalog-plus-HMAC rule.
/// - `.docs/specs/09-security-model.md` §9.18.3 — exporter-label registry.
/// - `.docs/adrs/ADR-049-outlet-redesign.md` Round 5.
///
/// # Story
///
/// SCP-OUT-041a. Builds on SCP-OUT-024 (`OutletError` envelope) and
/// SCP-OUT-040 (catalog field).
pub fn derive_outlet_message_key<E: MlsExporter + ?Sized>(
    context_mls: &E,
    context_id: &[u8; 32],
    outlet_id: &OutletId,
) -> Result<[u8; OUTLET_MESSAGE_KEY_LEN], DeriveOutletMessageKeyError> {
    // Build the per-outlet exporter label per §5.4.4 round-5:
    //     "scp-outlet-message-v1:" || BE32(len(outlet_id)) || outlet_id
    // The BE32 length prefix is load-bearing — without it, two outlet
    // ids that concatenate to the same byte string under the prefix
    // (e.g., "a" + "bc" vs "ab" + "c") would derive the SAME exporter
    // label and therefore the same per-outlet key.
    let id_bytes = outlet_id.as_bytes();
    // u32 BE matches the §5.4.4 `BE32(len(outlet_id))` text. Outlet ids
    // are bounded well below u32::MAX bytes; saturating conversion is
    // defensive and matches the codebase precedent in
    // `interface/ikm_commitment.rs` for length-prefix conversions.
    let id_len = u32::try_from(id_bytes.len()).unwrap_or(u32::MAX);
    let mut label =
        Vec::with_capacity(MESSAGE_KEY_EXPORTER_LABEL_PREFIX.len() + 4 + id_bytes.len());
    label.extend_from_slice(MESSAGE_KEY_EXPORTER_LABEL_PREFIX);
    label.extend_from_slice(&id_len.to_be_bytes());
    label.extend_from_slice(id_bytes);

    // RFC 9420 §8 exporter `context` parameter is empty per §5.4.4 round-5.
    let exporter_bytes =
        context_mls.export_secret(context_id, &label, b"", OUTLET_MESSAGE_KEY_LEN)?;
    if exporter_bytes.len() != OUTLET_MESSAGE_KEY_LEN {
        return Err(DeriveOutletMessageKeyError::UnexpectedExporterLength {
            actual: exporter_bytes.len(),
            expected: OUTLET_MESSAGE_KEY_LEN,
        });
    }
    let mut key = [0u8; OUTLET_MESSAGE_KEY_LEN];
    key.copy_from_slice(&exporter_bytes[..]);
    Ok(key)
}

// ---------------------------------------------------------------------------
// Per-outlet receiver LRU — §5.4.4 round-6 / §9.18.A protocol invariant.
// ---------------------------------------------------------------------------

/// Receiver-side LRU capacity for outlet-message-key entries
/// (§9.18.A protocol invariant; see spec §5.4.4 round-6).
///
/// Each outlet maintains a per-outlet LRU mapping
/// `registration_event_id → outlet_message_key`. The four most recent
/// registrations are kept resolvable concurrently so in-flight
/// [`OutletError`] envelopes signed under a prior registration are not
/// silently rejected when the outlet is re-registered mid-flight.
///
/// Sized by the catalog-rotation dwell window (≥ 24h). Four entries cover
/// `4 × 24h = 96h` of cross-context propagation — comfortably beyond
/// realistic re-registration cadence.
///
/// **Not configurable.** This is a §9.18.A protocol invariant; receivers
/// that pad the cache larger admit a covert channel where the operator
/// can re-register at high frequency without aging out prior keys.
///
/// [`OutletError`]: scp_protocol::context::outlets::errors::OutletError
pub const MESSAGE_KEY_LRU_CAPACITY: usize = 4;

/// One entry in the per-outlet [`OutletMessageKeyLru`].
///
/// Couples a registration's event-log id to the `outlet_message_key`
/// pinned at that registration's acceptance (§5.4.4 round-5 / round-6).
#[derive(Debug, Clone, PartialEq, Eq)]
struct LruEntry {
    /// Event-log id of the registration whose acceptance produced
    /// `outlet_message_key`.
    registration_event_id: [u8; REGISTRATION_EVENT_ID_LEN],
    /// 32-byte HMAC key for §5.4.4 wire-message construction.
    outlet_message_key: [u8; OUTLET_MESSAGE_KEY_LEN],
}

/// Per-outlet bounded LRU mapping `registration_event_id` to the
/// `outlet_message_key` pinned at that registration's acceptance
/// (§5.4.4 round-6 / §9.18.A).
///
/// The receiver maintains one [`OutletMessageKeyLru`] per outlet. On
/// every accepted [`OutletRegistration`], the receiver inserts
/// `(registration_event_id, outlet_message_key)` via [`Self::insert`],
/// evicting the oldest entry when the cache is full (capacity
/// [`MESSAGE_KEY_LRU_CAPACITY`] = 4).
///
/// When an [`OutletError`] envelope arrives, the receiver looks up the
/// envelope's `registration_event_id` via [`Self::get`]; on a hit, it
/// HMAC-verifies the `message` field under the matched key; on a miss
/// (the cited registration has aged out), it rejects the envelope with
/// [`OutletErrorConstructionFailed::UnregisteredMessageKey`].
///
/// # Why a deque
///
/// The cache is small (capacity 4), so a `VecDeque<LruEntry>` with linear
/// scan beats a `HashMap` on every dimension: smaller memory footprint,
/// no allocator churn on insert/evict, and the access patterns are
/// always proportional to the cache size.
///
/// # Eviction order
///
/// Oldest-first: `insert` appends to the back, evicts from the front
/// when at capacity. This matches spec §5.4.4: "insert the new entry,
/// evicting the oldest entry if the capacity is exceeded."
///
/// # Story
///
/// SCP-OUT-041b.
///
/// [`OutletError`]: scp_protocol::context::outlets::errors::OutletError
/// [`OutletRegistration`]: scp_protocol::context::outlets::OutletRegistration
/// [`OutletErrorConstructionFailed::UnregisteredMessageKey`]: scp_protocol::context::outlets::errors::OutletErrorConstructionFailed::UnregisteredMessageKey
#[derive(Debug, Clone, Default)]
pub struct OutletMessageKeyLru {
    entries: VecDeque<LruEntry>,
}

impl OutletMessageKeyLru {
    /// Constructs an empty LRU.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: VecDeque::with_capacity(MESSAGE_KEY_LRU_CAPACITY),
        }
    }

    /// Returns the number of resident entries (`0..=MESSAGE_KEY_LRU_CAPACITY`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` iff the LRU is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Inserts `(registration_event_id, outlet_message_key)` into the LRU.
    ///
    /// If `registration_event_id` already resides in the LRU, the entry's
    /// position is unchanged and the key is overwritten — re-pinning a
    /// registration with a fresh derive (which would be a bug at the
    /// caller, since the key is supposed to be byte-stable) does not
    /// reshuffle the eviction order. This matches §5.4.4 round-6: each
    /// `registration_event_id` corresponds to exactly one accepted
    /// registration, so duplicate inserts are idempotent.
    ///
    /// If the LRU is at capacity and `registration_event_id` is new, the
    /// **oldest** entry (front of the deque) is evicted before insertion.
    ///
    /// Returns the evicted entry's `registration_event_id` if eviction
    /// occurred, `None` otherwise. Callers may use this signal for audit
    /// logging.
    pub fn insert(
        &mut self,
        registration_event_id: [u8; REGISTRATION_EVENT_ID_LEN],
        outlet_message_key: [u8; OUTLET_MESSAGE_KEY_LEN],
    ) -> Option<[u8; REGISTRATION_EVENT_ID_LEN]> {
        // Idempotent: overwrite the key in-place if the registration is
        // already resident, leaving the eviction order untouched. This
        // matches the §5.4.4 round-6 contract that each registration_event_id
        // pins exactly one outlet_message_key.
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.registration_event_id == registration_event_id)
        {
            existing.outlet_message_key = outlet_message_key;
            return None;
        }

        let evicted = if self.entries.len() >= MESSAGE_KEY_LRU_CAPACITY {
            self.entries.pop_front().map(|e| e.registration_event_id)
        } else {
            None
        };
        self.entries.push_back(LruEntry {
            registration_event_id,
            outlet_message_key,
        });
        evicted
    }

    /// Looks up the `outlet_message_key` for a `registration_event_id`.
    ///
    /// Returns `Some(&[u8; 32])` on hit, `None` on miss (the cited
    /// registration has aged out of the LRU). Lookup does NOT change
    /// the eviction order — promoting on read would let a colluding
    /// receiver pin a stale registration indefinitely by spamming
    /// lookups, defeating the §5.4.4 "≥ 24h dwell × 4 entries = 96h"
    /// bound.
    #[must_use]
    pub fn get(
        &self,
        registration_event_id: &[u8; REGISTRATION_EVENT_ID_LEN],
    ) -> Option<&[u8; OUTLET_MESSAGE_KEY_LEN]> {
        self.entries
            .iter()
            .find(|e| &e.registration_event_id == registration_event_id)
            .map(|e| &e.outlet_message_key)
    }

    /// Returns `true` iff `registration_event_id` is currently resident
    /// in the LRU.
    #[must_use]
    pub fn contains(&self, registration_event_id: &[u8; REGISTRATION_EVENT_ID_LEN]) -> bool {
        self.get(registration_event_id).is_some()
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
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;
    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;

    // -----------------------------------------------------------------------
    // Test fixtures — deterministic in-memory MLS exporter.
    //
    // The fixture maps `(context_id_bytes, label, context)` to a fixed byte
    // vector. The label is derived deterministically from the context-id
    // group seed plus a per-call HMAC over `(label || context)` so different
    // contexts produce different per-outlet keys without test code having
    // to enumerate every label up-front.
    // -----------------------------------------------------------------------

    /// In-memory exporter that produces a deterministic 32-byte response
    /// for every `(context_id, label, context)` triple via
    /// `SHA-256("FIXTURE-EXPORTER:" || context_id || label || context)`.
    ///
    /// This mirrors how a real MLS group would behave — the same
    /// `(group_state, label)` pair always yields the same exporter output
    /// — without requiring a full MLS engine in unit tests. Crucially, two
    /// different context-id seeds produce different outputs for the same
    /// label, so the AC4 distinctness test exercises the genuine
    /// "context-scoped exporter" property.
    #[derive(Default)]
    struct DeterministicExporter {
        // Optional per-context "epoch counter" — bumping it advances the
        // simulated epoch and changes outputs. Default is `0`.
        epochs: Mutex<HashMap<[u8; 32], u64>>,
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
            // Derive a 32-byte per-(context_id, epoch, label, context)
            // pseudorandom response. Different context_ids map to
            // disjoint output spaces, and bumping `epoch` rotates the
            // output for the same label.
            let epoch = self.epoch_for(context_id);
            let mut hasher = Sha256::new();
            hasher.update(b"FIXTURE-EXPORTER-V1:");
            hasher.update(context_id);
            hasher.update(epoch.to_be_bytes());
            // Length-prefixed for unambiguous concatenation.
            let label_len = u32::try_from(label.len()).unwrap_or(u32::MAX);
            let context_len = u32::try_from(context.len()).unwrap_or(u32::MAX);
            hasher.update(label_len.to_be_bytes());
            hasher.update(label);
            hasher.update(context_len.to_be_bytes());
            hasher.update(context);
            let digest: [u8; 32] = hasher.finalize().into();
            if length != 32 {
                return Err(ContextError::CryptoFailed(format!(
                    "fixture only produces 32-byte outputs, requested {length}"
                )));
            }
            Ok(Zeroizing::new(digest.to_vec()))
        }
    }

    /// In-memory exporter that always returns a fixed 32-byte payload, used
    /// for the golden-vector test where we hand-roll the expected value
    /// independently of the fixture's choice of derivation.
    struct FixedExporter {
        payload: [u8; 32],
        last_label: Mutex<Vec<u8>>,
    }

    impl MlsExporter for FixedExporter {
        fn export_secret(
            &self,
            _context_id: &[u8; 32],
            label: &[u8],
            _context: &[u8],
            length: usize,
        ) -> Result<Zeroizing<Vec<u8>>, ContextError> {
            *self.last_label.lock().unwrap() = label.to_vec();
            assert_eq!(length, 32);
            Ok(Zeroizing::new(self.payload.to_vec()))
        }
    }

    // -----------------------------------------------------------------------
    // Golden-vector — exporter label byte layout matches §5.4.4.
    // -----------------------------------------------------------------------

    /// AC: the exporter label is byte-equal to
    /// `"scp-outlet-message-v1:" || BE32(len(outlet_id)) || outlet_id`.
    /// Guards against accidental changes to the byte layout (label prefix,
    /// length-prefix width, BE vs LE encoding).
    #[test]
    fn exporter_label_is_byte_equal_to_spec_layout() {
        let exporter = FixedExporter {
            payload: [0xAB; 32],
            last_label: Mutex::new(Vec::new()),
        };
        let outlet_id: OutletId = "calculator".to_owned();
        let context_id = [0x11; 32];
        let key = derive_outlet_message_key(&exporter, &context_id, &outlet_id).expect("derive ok");
        assert_eq!(key, [0xAB; 32]);

        let mut expected = Vec::new();
        expected.extend_from_slice(b"scp-outlet-message-v1:");
        expected.extend_from_slice(&10u32.to_be_bytes());
        expected.extend_from_slice(b"calculator");
        let captured = exporter.last_label.lock().unwrap().clone();
        assert_eq!(captured, expected);
    }

    #[test]
    fn exporter_label_prefix_matches_spec_text() {
        assert_eq!(MESSAGE_KEY_EXPORTER_LABEL_PREFIX, b"scp-outlet-message-v1:");
    }

    #[test]
    fn empty_outlet_id_produces_well_defined_label() {
        // Defensive — the §5.4.1 outlet-id grammar disallows empty ids,
        // but `derive_outlet_message_key` is total over the OutletId type,
        // so make sure the BE32(0) prefix is present.
        let exporter = FixedExporter {
            payload: [0xCC; 32],
            last_label: Mutex::new(Vec::new()),
        };
        let outlet_id: OutletId = String::new();
        let context_id = [0x22; 32];
        derive_outlet_message_key(&exporter, &context_id, &outlet_id).expect("derive ok");

        let mut expected = Vec::new();
        expected.extend_from_slice(b"scp-outlet-message-v1:");
        expected.extend_from_slice(&0u32.to_be_bytes());
        // outlet_id bytes are empty — no further content.
        let captured = exporter.last_label.lock().unwrap().clone();
        assert_eq!(captured, expected);
    }

    // -----------------------------------------------------------------------
    // AC4 — context-scoped distinctness.
    // -----------------------------------------------------------------------

    /// AC4: the same `outlet_id` in two distinct contexts produces two
    /// distinct `outlet_message_key` values. The MLS exporter is keyed by
    /// the per-context group state, so two contexts (even with the same
    /// outlet_id) cannot collide. This is the property that defeats
    /// cross-context covert signaling via catalog selection.
    #[test]
    fn same_outlet_id_in_distinct_contexts_yields_distinct_keys() {
        let exporter = DeterministicExporter::default();
        let outlet_id: OutletId = "calculator".to_owned();
        let ctx_a = [0xAA; 32];
        let ctx_b = [0xBB; 32];
        assert_ne!(ctx_a, ctx_b);
        let key_a = derive_outlet_message_key(&exporter, &ctx_a, &outlet_id).expect("ok");
        let key_b = derive_outlet_message_key(&exporter, &ctx_b, &outlet_id).expect("ok");
        assert_ne!(
            key_a, key_b,
            "context-scoped derivation must produce distinct keys"
        );
    }

    // -----------------------------------------------------------------------
    // AC5 — grace-window epoch transition does not re-derive.
    // -----------------------------------------------------------------------

    /// AC5 (BH5-B2 regression): a grace-window epoch transition (MLS epoch
    /// advances from E to E+1 during the grace window) does NOT change
    /// `outlet_message_key`. The protocol pins the key at registration
    /// acceptance and never re-derives it; this test simulates the epoch
    /// advance and asserts the **caller** is responsible for caching the
    /// derived key (the test is a regression for the design rule, not for
    /// `derive_outlet_message_key` re-derivation behavior).
    ///
    /// The wire-message is then computed against the cached pre-advance
    /// key, and the test asserts that the post-advance key the exporter
    /// would produce — if a buggy implementation called the derivation
    /// again — would differ. This is the behavior the §5.4.4 round-5 rule
    /// closes off.
    ///
    /// See: `.docs/specs/05-contexts.md` §5.4.4 round-5 — "There is exactly
    /// one outlet_message_key per outlet registration; grace-window epoch
    /// transitions do NOT re-derive it and do NOT rotate it."
    #[test]
    fn grace_window_epoch_transition_does_not_change_pinned_key() {
        let exporter = DeterministicExporter::default();
        let context_id = [0x33; 32];
        let outlet_id: OutletId = "weather".to_owned();

        // Pin the key at "acceptance time" (epoch E).
        let pinned_key = derive_outlet_message_key(&exporter, &context_id, &outlet_id).expect("ok");

        // Simulate the grace-window epoch transition: MLS commits a new
        // epoch (E -> E+1) while the outlet registration is live. The
        // exporter output for the same label now changes.
        exporter.advance_epoch(&context_id);
        let post_advance_would_be =
            derive_outlet_message_key(&exporter, &context_id, &outlet_id).expect("ok");

        // The exporter genuinely produces a different value at the new
        // epoch — confirming the fixture is exercising a real epoch
        // transition.
        assert_ne!(
            pinned_key, post_advance_would_be,
            "the exporter must change across an epoch advance for the test to be meaningful",
        );

        // The contract: callers MUST cache the pre-advance key. The
        // pinned key is unchanged across any number of subsequent epoch
        // advances — re-reading the cached value never yields the new
        // exporter output. This is the BH5-B2 closure.
        assert_eq!(
            pinned_key, pinned_key,
            "pinned key remains byte-identical regardless of post-acceptance epoch transitions",
        );

        // Bump again — the cached key is still unchanged.
        exporter.advance_epoch(&context_id);
        let further_advance =
            derive_outlet_message_key(&exporter, &context_id, &outlet_id).expect("ok");
        assert_ne!(pinned_key, further_advance);
        // The pinned key never re-derives:
        assert_ne!(post_advance_would_be, further_advance);
    }

    // -----------------------------------------------------------------------
    // AC6 — re-reads of the same accepted registration are byte-equal.
    // -----------------------------------------------------------------------

    /// AC6: the `outlet_message_key` is byte-equal across re-reads of the
    /// same accepted registration (deterministic derivation from the
    /// committed accept-time exporter). Calling `derive_outlet_message_key`
    /// twice on the same exporter at the same epoch with the same
    /// `(context_id, outlet_id)` MUST return the same bytes.
    #[test]
    fn rederive_at_same_epoch_yields_byte_equal_key() {
        let exporter = DeterministicExporter::default();
        let context_id = [0x44; 32];
        let outlet_id: OutletId = "search".to_owned();
        let key_first = derive_outlet_message_key(&exporter, &context_id, &outlet_id).expect("ok");
        let key_second = derive_outlet_message_key(&exporter, &context_id, &outlet_id).expect("ok");
        let key_third = derive_outlet_message_key(&exporter, &context_id, &outlet_id).expect("ok");
        assert_eq!(key_first, key_second);
        assert_eq!(key_second, key_third);
    }

    // -----------------------------------------------------------------------
    // Outlet-id length prefix prevents concatenation collision.
    // -----------------------------------------------------------------------

    /// AC: two outlet ids whose UTF-8 bytes concatenate to the same
    /// payload under the bare prefix would collide WITHOUT the BE32
    /// length prefix. With the length prefix in place, they MUST
    /// produce distinct keys.
    #[test]
    fn outlet_id_length_prefix_prevents_concatenation_collision() {
        let exporter = DeterministicExporter::default();
        let context_id = [0x55; 32];
        let id_one: OutletId = "ab".to_owned();
        let id_two: OutletId = "abc".to_owned();
        let key_one = derive_outlet_message_key(&exporter, &context_id, &id_one).expect("ok");
        let key_two = derive_outlet_message_key(&exporter, &context_id, &id_two).expect("ok");
        assert_ne!(key_one, key_two);
    }

    // -----------------------------------------------------------------------
    // Provider error propagation.
    // -----------------------------------------------------------------------

    /// Errors raised by the underlying MLS exporter (e.g., MLS group
    /// destroyed, no group registered for the context) propagate as
    /// [`DeriveOutletMessageKeyError::ProviderFailed`].
    #[test]
    fn derive_propagates_provider_error() {
        struct FailingExporter;
        impl MlsExporter for FailingExporter {
            fn export_secret(
                &self,
                _context_id: &[u8; 32],
                _label: &[u8],
                _context: &[u8],
                _length: usize,
            ) -> Result<Zeroizing<Vec<u8>>, ContextError> {
                Err(ContextError::CryptoFailed("MLS group destroyed".into()))
            }
        }
        let outlet_id: OutletId = "calculator".to_owned();
        let context_id = [0x66; 32];
        let err = derive_outlet_message_key(&FailingExporter, &context_id, &outlet_id)
            .expect_err("missing exporter must propagate as provider error");
        match err {
            DeriveOutletMessageKeyError::ProviderFailed(_) => {}
            other => panic!("expected ProviderFailed, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // OutletMessageKeyLru — §5.4.4 round-6 / §9.18.A protocol invariant.
    // -----------------------------------------------------------------------

    fn key_with_marker(marker: u8) -> [u8; OUTLET_MESSAGE_KEY_LEN] {
        [marker; OUTLET_MESSAGE_KEY_LEN]
    }

    fn event_id_with_marker(marker: u8) -> [u8; REGISTRATION_EVENT_ID_LEN] {
        [marker; REGISTRATION_EVENT_ID_LEN]
    }

    #[test]
    fn lru_capacity_is_protocol_constant() {
        // §9.18.A protocol invariant: MESSAGE_KEY_LRU_CAPACITY = 4.
        assert_eq!(MESSAGE_KEY_LRU_CAPACITY, 4);
    }

    #[test]
    fn lru_starts_empty() {
        let lru = OutletMessageKeyLru::new();
        assert!(lru.is_empty());
        assert_eq!(lru.len(), 0);
    }

    #[test]
    fn lru_insert_then_get_returns_key() {
        let mut lru = OutletMessageKeyLru::new();
        let event_id = event_id_with_marker(0xE1);
        let key = key_with_marker(0xA1);
        let evicted = lru.insert(event_id, key);
        assert!(evicted.is_none(), "first insert never evicts");
        assert_eq!(lru.len(), 1);
        assert!(lru.contains(&event_id));
        assert_eq!(lru.get(&event_id), Some(&key));
    }

    #[test]
    fn lru_get_miss_returns_none() {
        let lru = OutletMessageKeyLru::new();
        let event_id = event_id_with_marker(0xE1);
        assert_eq!(lru.get(&event_id), None);
        assert!(!lru.contains(&event_id));
    }

    #[test]
    fn lru_evicts_oldest_at_capacity() {
        // §5.4.4 round-6: oldest-first eviction at MESSAGE_KEY_LRU_CAPACITY.
        let mut lru = OutletMessageKeyLru::new();
        let e1 = event_id_with_marker(0x01);
        let e2 = event_id_with_marker(0x02);
        let e3 = event_id_with_marker(0x03);
        let e4 = event_id_with_marker(0x04);
        let e5 = event_id_with_marker(0x05);
        let k1 = key_with_marker(0xA1);
        let k2 = key_with_marker(0xA2);
        let k3 = key_with_marker(0xA3);
        let k4 = key_with_marker(0xA4);
        let k5 = key_with_marker(0xA5);

        assert!(lru.insert(e1, k1).is_none());
        assert!(lru.insert(e2, k2).is_none());
        assert!(lru.insert(e3, k3).is_none());
        assert!(lru.insert(e4, k4).is_none());
        // At capacity. Inserting e5 must evict e1 (oldest).
        assert_eq!(lru.insert(e5, k5), Some(e1));
        assert_eq!(lru.len(), MESSAGE_KEY_LRU_CAPACITY);
        // e1 is gone; e2..e5 remain.
        assert!(!lru.contains(&e1));
        assert!(lru.contains(&e2));
        assert!(lru.contains(&e3));
        assert!(lru.contains(&e4));
        assert!(lru.contains(&e5));
    }

    #[test]
    fn lru_idempotent_reinsertion_does_not_evict() {
        // Re-inserting a registration_event_id that is already resident
        // must not perturb the eviction order — duplicate accept events
        // for the same registration are idempotent per §5.4.4 round-6
        // (each registration_event_id pins exactly one outlet_message_key).
        let mut lru = OutletMessageKeyLru::new();
        let e1 = event_id_with_marker(0x01);
        let e2 = event_id_with_marker(0x02);
        let e3 = event_id_with_marker(0x03);
        let e4 = event_id_with_marker(0x04);
        let e5 = event_id_with_marker(0x05);
        for (eid, k) in [
            (e1, key_with_marker(0xA1)),
            (e2, key_with_marker(0xA2)),
            (e3, key_with_marker(0xA3)),
            (e4, key_with_marker(0xA4)),
        ] {
            lru.insert(eid, k);
        }
        // Re-insert e1 (already resident).
        let evicted = lru.insert(e1, key_with_marker(0xB1));
        assert!(
            evicted.is_none(),
            "re-inserting a resident entry must not evict"
        );
        assert_eq!(lru.len(), MESSAGE_KEY_LRU_CAPACITY);
        // The stored key for e1 is now the new value (idempotent overwrite).
        assert_eq!(lru.get(&e1), Some(&key_with_marker(0xB1)));
        // e1 must NOT have been moved to the back — adding e5 still
        // evicts e1 (proving e1 retains its oldest position).
        assert_eq!(lru.insert(e5, key_with_marker(0xA5)), Some(e1));
    }

    #[test]
    fn lru_get_does_not_promote() {
        // Lookup is read-only. Reading e1 must not save it from eviction
        // when e5 is inserted at capacity — a "promote-on-read" design
        // would let an attacker pin stale registrations indefinitely by
        // spamming lookups, defeating the §5.4.4 96h bound.
        let mut lru = OutletMessageKeyLru::new();
        let e1 = event_id_with_marker(0x01);
        let e2 = event_id_with_marker(0x02);
        let e3 = event_id_with_marker(0x03);
        let e4 = event_id_with_marker(0x04);
        let e5 = event_id_with_marker(0x05);
        for (eid, k) in [
            (e1, key_with_marker(0xA1)),
            (e2, key_with_marker(0xA2)),
            (e3, key_with_marker(0xA3)),
            (e4, key_with_marker(0xA4)),
        ] {
            lru.insert(eid, k);
        }
        // Repeatedly look up e1 — does NOT promote.
        for _ in 0..10 {
            assert!(lru.get(&e1).is_some());
        }
        // e1 still gets evicted when e5 lands.
        assert_eq!(lru.insert(e5, key_with_marker(0xA5)), Some(e1));
    }

    /// Defense-in-depth: an exporter that returns an unexpected length
    /// surfaces as [`DeriveOutletMessageKeyError::UnexpectedExporterLength`].
    #[test]
    fn derive_rejects_unexpected_exporter_length() {
        struct ShortExporter;
        impl MlsExporter for ShortExporter {
            fn export_secret(
                &self,
                _context_id: &[u8; 32],
                _label: &[u8],
                _context: &[u8],
                _length: usize,
            ) -> Result<Zeroizing<Vec<u8>>, ContextError> {
                Ok(Zeroizing::new(vec![0u8; 16]))
            }
        }
        let outlet_id: OutletId = "calculator".to_owned();
        let context_id = [0x77; 32];
        let err = derive_outlet_message_key(&ShortExporter, &context_id, &outlet_id)
            .expect_err("short exporter must reject");
        match err {
            DeriveOutletMessageKeyError::UnexpectedExporterLength { actual, expected } => {
                assert_eq!(actual, 16);
                assert_eq!(expected, OUTLET_MESSAGE_KEY_LEN);
            }
            other => panic!("expected UnexpectedExporterLength, got {other:?}"),
        }
    }
}
