//! `CreationReceipt` — the public, A-authored plan-metadata for a
//! standing-pair-creation saga (spec §5.15.8).
//!
//! A standing pair is the `bilateral-persistent` context two identities
//! create on first contact (§5.12.6). The lower-DID party (**A**) runs
//! Prepare-A: it creates the MLS group locally (2-leaf init) plus a fresh
//! sender key and records which creation steps succeeded into a
//! `CreationReceipt`. The receipt is **A-authored only** — the booleans
//! (`mls_group_created` / `sender_key_created` / `event_log_created` /
//! `published`) are inherently A-local creation state; B, joining via
//! Welcome, creates no group or sender key and authors no independent
//! receipt (§5.15.8 "Prepare-B").
//!
//! # Not secret-bearing
//!
//! Every field is public plan-metadata: never an MLS secret, sender-key,
//! or ratchet (§5.15.8 "`CreationReceipt` canonical field set"). The
//! journal records only this public metadata — there is no §9.4.3 secret
//! commitment, because there is no bearer artifact (MLS secrets live only
//! in actor-local crypto-provider state). The receipt is therefore freely
//! `Serialize`/`Deserialize`/`Clone`/`Debug` — the opposite discipline
//! from a bearer envelope.
//!
//! # No `group_id`
//!
//! Post-spec-revision, the standing-pair saga carries **no** `group_id`
//! field. MLS group isolation keys off `derived_context_id`: the crypto
//! provider computes the MLS group id internally as
//! `SHA-256("standing-" ‖ hex(derived_context_id))` inside
//! `create_mls_group`'s `Entry::Vacant` collision guard. The receipt's
//! `context_id` field is the `"standing-"`-prefixed display id, NOT the
//! raw digest and NOT a group id (§5.15.8 "id-form discipline").
//!
//! # Canonical bytes (JCS)
//!
//! [`CreationReceipt::to_bytes`] emits the RFC 8785 canonical JSON (JCS)
//! of the field set via the codebase's canonical `scp_protocol::jcs`.
//! "Byte-reproducible across implementations" means a *single* party's
//! serializer is deterministic — NOT that A's and B's receipts are
//! byte-identical (B authors none). [`CreationReceipt::from_bytes`]
//! round-trips via `serde_json`.
//!
//! # Rollback
//!
//! [`CreationReceipt::rollback`] reclaims A's un-published creation state
//! when Prepare-B fails (`PreparingB → Aborting`, §5.15.8 "Prepare-B-
//! failure rollback"). It runs the creation steps in **reverse order**,
//! **best-effort** (a failing step is logged and does not abort the
//! rest): `delete_published` (a no-op while `!published`) →
//! `destroy_event_log` → `destroy_sender_key` → `destroy_mls_group`. A's
//! group was never published, so no relay or peer observed it — this is
//! purely local key/state destruction.
//!
//! # Foundation-only
//!
//! This module defines the canonical type, its JCS round-trip, and the
//! rollback sequencing (all exercised by the unit tests below). The
//! production callers — the Prepare-A staging path and the
//! `PreparingB → Aborting` handler that invokes `rollback` over the real
//! crypto-provider / transport / event-log backends — land with the saga
//! dispatch wiring in a follow-on PR. The `dead_code` allow covers the
//! interval between this types-only foundation and that wiring; the tests
//! keep every item live and verified now.
#![allow(dead_code)]

use scp_identity::DID;
use serde::{Deserialize, Serialize};

use scp_protocol::context::builder::ContextCreationError;

// ---------------------------------------------------------------------------
// Canonical field constants (spec §5.15.8)
// ---------------------------------------------------------------------------

/// The fixed `mode` value for a standing pair — always encrypted
/// (`bilateral-persistent` is an encrypted template).
pub(in crate::context) const STANDING_PAIR_MODE: &str = "encrypted";

/// The fixed `template_id` for a standing pair (§5.12.6).
pub(in crate::context) const STANDING_PAIR_TEMPLATE_ID: &str = "scp:template/bilateral-persistent";

// ---------------------------------------------------------------------------
// CreationReceipt
// ---------------------------------------------------------------------------

/// Public, A-authored creation metadata for a standing-pair saga
/// (spec §5.15.8 "`CreationReceipt` canonical field set").
///
/// Field order matches the spec's JCS object. JCS canonicalization sorts
/// keys, so the declaration order here is for readability only — it does
/// not affect [`Self::to_bytes`].
///
/// `clippy::struct_excessive_bools` is allowed: the four creation-state
/// booleans (`mls_group_created`, `sender_key_created`,
/// `event_log_created`, `published`) are a **normative wire shape** — they
/// are the exact JCS field set spec §5.15.8 "`CreationReceipt` canonical
/// field set" mandates, each a distinct serialized key. Collapsing them
/// into a bitflag or state enum would change the canonical JSON and break
/// cross-implementation byte-reproducibility, so the flat-bool shape is
/// required, not incidental.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub(in crate::context) struct CreationReceipt {
    /// The canonical standing context id: `"standing-"` + 64-hex of the
    /// SHA-256 derivation (§5.15.8 "Determinism precondition"). This is
    /// the prefixed **display** form, NOT the raw 32-byte
    /// `derived_context_id` digest, and NOT a group id — a reader MUST NOT
    /// conflate the two forms.
    pub context_id: String,
    /// Always [`STANDING_PAIR_MODE`] (`"encrypted"`).
    pub mode: String,
    /// Always [`STANDING_PAIR_TEMPLATE_ID`]
    /// (`"scp:template/bilateral-persistent"`).
    pub template_id: String,
    /// The creator (lower) DID — `did_lo`.
    pub creator_did: String,
    /// The peer (higher) DID — `did_hi`.
    pub peer_did: String,
    /// `true` once A has created the local 2-leaf MLS group.
    pub mls_group_created: bool,
    /// `true` once A has generated the fresh sender key.
    pub sender_key_created: bool,
    /// `true` once A has initialised the event log.
    pub event_log_created: bool,
    /// `true` once A has published the context (flipped at Commit, never
    /// at Prepare — Prepare-A defers publication).
    pub published: bool,
}

impl CreationReceipt {
    /// Construct a fresh receipt for the A-side of a standing-pair saga,
    /// with all creation-state booleans `false`. Handlers flip the
    /// booleans as each creation step succeeds (Prepare-A) and `published`
    /// at Commit.
    ///
    /// `context_id` is the `"standing-"`-prefixed display id; `creator_did`
    /// is `did_lo` and `peer_did` is `did_hi` (the spec's A/B ordering).
    #[must_use]
    pub(in crate::context) fn new_pending(
        context_id: String,
        creator_did: &DID,
        peer_did: &DID,
    ) -> Self {
        Self {
            context_id,
            mode: STANDING_PAIR_MODE.to_owned(),
            template_id: STANDING_PAIR_TEMPLATE_ID.to_owned(),
            creator_did: creator_did.0.clone(),
            peer_did: peer_did.0.clone(),
            mls_group_created: false,
            sender_key_created: false,
            event_log_created: false,
            published: false,
        }
    }

    /// Serialize to the RFC 8785 canonical JSON (JCS) bytes via the
    /// codebase's canonical `scp_protocol::jcs` (spec §5.15.8 "Canonical
    /// bytes"). Deterministic for a single serializer; the journal stores
    /// these bytes as public plan-metadata.
    ///
    /// # Errors
    ///
    /// Returns the JCS serialization error string if canonicalization
    /// fails — which cannot occur for a well-formed receipt (all fields
    /// are strings or bools, both JCS-canonicalizable).
    pub(in crate::context) fn to_bytes(&self) -> Result<Vec<u8>, String> {
        scp_protocol::jcs::to_vec(self)
    }

    /// Round-trip a receipt from its canonical JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns the `serde_json` error if `bytes` is not valid JSON for the
    /// receipt shape.
    pub(in crate::context) fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Reverse-order, best-effort rollback of A's un-published creation
    /// state (spec §5.15.8 "Prepare-B-failure rollback"). Each step is
    /// independent: a failing step is logged and does NOT abort the
    /// remaining steps — the goal is to reclaim as much state as possible.
    ///
    /// Order (reverse of creation): `delete_published` (no-op while
    /// `!published`) → `destroy_event_log` → `destroy_sender_key` →
    /// `destroy_mls_group`. Each step is gated on whether the
    /// corresponding creation boolean recorded success, so we never call a
    /// destroy for a step that never ran.
    ///
    /// `derived_context_id` is the raw 32-byte digest the providers key
    /// their per-context state by — NOT the `"standing-"`-prefixed
    /// `self.context_id` display string.
    pub(in crate::context) fn rollback(
        &self,
        derived_context_id: &[u8; 32],
        targets: &dyn CreationReceiptRollbackTargets,
    ) {
        // Step 1 (reverse): un-publish. A no-op while `!published`
        // (Prepare-A never publishes), but kept in the sequence for the
        // Commit-failure path where `published` may be `true`.
        if self.published {
            Self::log_step(
                "delete_published",
                targets.delete_published(derived_context_id),
            );
        }
        // Step 2 (reverse): destroy the event log.
        if self.event_log_created {
            Self::log_step(
                "destroy_event_log",
                targets.destroy_event_log(derived_context_id),
            );
        }
        // Step 3 (reverse): destroy the sender key.
        if self.sender_key_created {
            Self::log_step(
                "destroy_sender_key",
                targets.destroy_sender_key(derived_context_id),
            );
        }
        // Step 4 (reverse): destroy the MLS group.
        if self.mls_group_created {
            Self::log_step(
                "destroy_mls_group",
                targets.destroy_mls_group(derived_context_id),
            );
        }
    }

    /// Log a best-effort rollback step's outcome. A failing step is warned
    /// and otherwise ignored — the caller continues to the next step.
    fn log_step(step: &str, result: Result<(), ContextCreationError>) {
        if let Err(e) = result {
            tracing::warn!(
                step,
                error = %e,
                "standing-pair rollback step failed (best-effort, continuing)"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Rollback target abstraction
// ---------------------------------------------------------------------------

/// The four reverse-order destroy/delete operations
/// [`CreationReceipt::rollback`] invokes (spec §5.15.8). Abstracted as a
/// trait so the rollback sequencing is unit-testable without a live
/// crypto provider / transport / event-log backend, and so the PR that
/// wires the abort handler can supply a concrete adapter over the real
/// providers.
///
/// Every method is **best-effort**: the caller logs and continues on
/// error, so implementations should perform a single cleanup attempt and
/// return its result rather than retrying.
pub(in crate::context) trait CreationReceiptRollbackTargets {
    /// Best-effort deletion of any published context blobs. A no-op for an
    /// un-published Prepare-A group (the rollback only calls this when
    /// `published` is set).
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if deletion fails; the caller
    /// treats this as best-effort.
    fn delete_published(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError>;

    /// Best-effort destruction of the context's event log.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if destruction fails; the caller
    /// treats this as best-effort.
    fn destroy_event_log(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError>;

    /// Best-effort destruction of the context's sender key.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if destruction fails; the caller
    /// treats this as best-effort.
    fn destroy_sender_key(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError>;

    /// Best-effort destruction of the context's MLS group.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if destruction fails; the caller
    /// treats this as best-effort.
    fn destroy_mls_group(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn did_lo() -> DID {
        DID("did:dht:z6mkaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned())
    }
    fn did_hi() -> DID {
        DID("did:dht:z6mkzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_owned())
    }

    fn sample_context_id() -> String {
        format!("standing-{}", "ab".repeat(32))
    }

    #[test]
    fn new_pending_sets_canonical_constants_and_false_flags() {
        let r = CreationReceipt::new_pending(sample_context_id(), &did_lo(), &did_hi());
        assert_eq!(r.context_id, sample_context_id());
        assert_eq!(r.mode, "encrypted");
        assert_eq!(r.template_id, "scp:template/bilateral-persistent");
        assert_eq!(r.creator_did, did_lo().0);
        assert_eq!(r.peer_did, did_hi().0);
        assert!(!r.mls_group_created);
        assert!(!r.sender_key_created);
        assert!(!r.event_log_created);
        assert!(!r.published);
    }

    #[test]
    fn to_bytes_from_bytes_round_trips() {
        let mut r = CreationReceipt::new_pending(sample_context_id(), &did_lo(), &did_hi());
        r.mls_group_created = true;
        r.sender_key_created = true;
        let bytes = r.to_bytes().unwrap();
        let back = CreationReceipt::from_bytes(&bytes).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn to_bytes_is_byte_stable() {
        // Two independently-constructed identical receipts must serialize
        // to byte-identical JCS — the §5.15.8 single-serializer
        // determinism property.
        let a = CreationReceipt::new_pending(sample_context_id(), &did_lo(), &did_hi());
        let b = CreationReceipt::new_pending(sample_context_id(), &did_lo(), &did_hi());
        assert_eq!(a.to_bytes().unwrap(), b.to_bytes().unwrap());
    }

    #[test]
    fn to_bytes_emits_jcs_sorted_keys() {
        // JCS sorts object keys lexicographically. `context_id` sorts
        // before `mode`, which sorts before `template_id`, etc. Assert the
        // canonical bytes are valid UTF-8 JSON with sorted keys so a
        // divergent serializer is caught.
        let r = CreationReceipt::new_pending(sample_context_id(), &did_lo(), &did_hi());
        let json = String::from_utf8(r.to_bytes().unwrap()).unwrap();
        // JCS key order: context_id, creator_did, event_log_created,
        // mls_group_created, mode, peer_did, published, sender_key_created,
        // template_id.
        let pos = |k: &str| json.find(k).unwrap();
        assert!(pos("\"context_id\"") < pos("\"creator_did\""));
        assert!(pos("\"creator_did\"") < pos("\"event_log_created\""));
        assert!(pos("\"event_log_created\"") < pos("\"mls_group_created\""));
        assert!(pos("\"mls_group_created\"") < pos("\"mode\""));
        assert!(pos("\"mode\"") < pos("\"peer_did\""));
        assert!(pos("\"peer_did\"") < pos("\"published\""));
        assert!(pos("\"published\"") < pos("\"sender_key_created\""));
        assert!(pos("\"sender_key_created\"") < pos("\"template_id\""));
    }

    /// A mock that records the ORDER of rollback calls and can be
    /// configured to fail a specific step, so the test can assert
    /// reverse-order sequencing AND that a failing step does not abort the
    /// rest.
    struct RecordingTargets {
        calls: RefCell<Vec<&'static str>>,
        fail_step: Option<&'static str>,
    }

    impl RecordingTargets {
        fn new(fail_step: Option<&'static str>) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                fail_step,
            }
        }

        fn record(&self, step: &'static str) -> Result<(), ContextCreationError> {
            self.calls.borrow_mut().push(step);
            if self.fail_step == Some(step) {
                Err(ContextCreationError::CreationFailed(format!(
                    "injected failure in {step}"
                )))
            } else {
                Ok(())
            }
        }
    }

    impl CreationReceiptRollbackTargets for RecordingTargets {
        fn delete_published(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.record("delete_published")
        }
        fn destroy_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.record("destroy_event_log")
        }
        fn destroy_sender_key(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.record("destroy_sender_key")
        }
        fn destroy_mls_group(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.record("destroy_mls_group")
        }
    }

    fn fully_created_receipt() -> CreationReceipt {
        let mut r = CreationReceipt::new_pending(sample_context_id(), &did_lo(), &did_hi());
        r.mls_group_created = true;
        r.sender_key_created = true;
        r.event_log_created = true;
        r.published = true;
        r
    }

    #[test]
    fn rollback_runs_reverse_creation_order() {
        let r = fully_created_receipt();
        let targets = RecordingTargets::new(None);
        r.rollback(&[7u8; 32], &targets);
        assert_eq!(
            *targets.calls.borrow(),
            vec![
                "delete_published",
                "destroy_event_log",
                "destroy_sender_key",
                "destroy_mls_group",
            ]
        );
    }

    #[test]
    fn rollback_skips_steps_that_never_ran() {
        // Prepare-A state: group + sender key created, but NOT published
        // and NO event log. Rollback must skip delete_published and
        // destroy_event_log entirely.
        let mut r = CreationReceipt::new_pending(sample_context_id(), &did_lo(), &did_hi());
        r.mls_group_created = true;
        r.sender_key_created = true;
        let targets = RecordingTargets::new(None);
        r.rollback(&[7u8; 32], &targets);
        assert_eq!(
            *targets.calls.borrow(),
            vec!["destroy_sender_key", "destroy_mls_group"]
        );
    }

    #[test]
    fn rollback_continues_after_a_failing_step() {
        // Inject a failure in the SECOND step (destroy_event_log). The
        // remaining steps (destroy_sender_key, destroy_mls_group) MUST
        // still run — best-effort does not abort.
        let r = fully_created_receipt();
        let targets = RecordingTargets::new(Some("destroy_event_log"));
        r.rollback(&[7u8; 32], &targets);
        assert_eq!(
            *targets.calls.borrow(),
            vec![
                "delete_published",
                "destroy_event_log",
                "destroy_sender_key",
                "destroy_mls_group",
            ],
            "a failing step must not abort the remaining reverse-order steps"
        );
    }
}
