//! SCP-OUT-041c — `CatalogRotationTooFrequent` validator tests.
//!
//! Spec: `.docs/specs/05-contexts.md` §5.4.4 round-5 catalog-rotation
//! discipline. ADR: `.docs/adrs/ADR-049-outlet-redesign.md` Round 5.
//!
//! Coverage:
//!
//! - Pure validator semantics (catalog unchanged → silent; T0 + 23.99 h →
//!   reject; T0 + 24.01 h → accept; back-dated `registered_at` cannot
//!   bypass).
//! - End-to-end through `ContextManager::execute_register_outlet`: a
//!   re-registration with a changed `message_catalog` within 24 h is
//!   rejected with the typed `OutletError` envelope under
//!   `OutletErrorClass::Protocol` / `CODE_PROTOCOL_VIOLATION` / slug
//!   `protocol.catalog-rotation-too-frequent`. After 24 h the
//!   re-registration is accepted.
//! - Operator-clock-bypass regression: an attacker that back-dates
//!   `OutletRegistration::registered_at` to `T0 - 12 h` (so the
//!   `registered_at` delta superficially appears to exceed 24 h) is still
//!   rejected because the validator consults the event-log append time —
//!   a protocol-enforced clock the operator cannot forge.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::uninlined_format_args,
    clippy::match_wildcard_for_single_variants,
    clippy::type_complexity
)]

use std::sync::Arc;

use scp_primitives::{Clock, TestClock};
use scp_protocol::context::ContextError;
use scp_protocol::context::outlets::error_codes::{
    CODE_PROTOCOL_VIOLATION, SLUG_PROTOCOL_CATALOG_ROTATION_TOO_FREQUENT,
};
use scp_protocol::context::outlets::errors::OutletErrorClass;
use scp_protocol::context::outlets::{MessageTemplate, OutletRegistration};
use scp_protocol::context::params::Capability;
use scp_protocol::context::{ContextParams, params::Capability as ProtoCapability};

use crate::context::builder::ContextEventLogProvider;
use crate::context::manager::ContextManager;
use crate::context::manager::outlets::{
    CATALOG_ROTATION_DWELL_SECS, CatalogRotationDwellRejection,
    catalog_rotation_dwell_rejection_to_context, validate_catalog_rotation_dwell_time,
};
use crate::context::manager::tests::{MockCrypto, MockTransport, noop_key_resolver};
use crate::context::providers::event_log::EventLogEntry;

// -----------------------------------------------------------------------
// Test fixtures
// -----------------------------------------------------------------------

const T0: u64 = 1_700_000_000;

fn catalog_a() -> Vec<MessageTemplate> {
    vec![MessageTemplate {
        key: "authorization.denied".to_owned(),
        template: "denied: catalog A".to_owned(),
    }]
}

fn catalog_b() -> Vec<MessageTemplate> {
    vec![MessageTemplate {
        key: "authorization.denied".to_owned(),
        template: "denied: catalog B".to_owned(),
    }]
}

fn outlet_registration(catalog: Vec<MessageTemplate>, registered_at: u64) -> OutletRegistration {
    use scp_protocol::context::outlets::registry::{OutletSchema, OutletTestVector};
    OutletRegistration {
        outlet_id: "out-041c-target".to_owned(),
        kind: scp_protocol::context::outlets::OutletKind::Action,
        name: "out-041c-target".to_owned(),
        description: "out-041c rotation target".to_owned(),
        schema: OutletSchema {
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
        },
        implementation_hash: [0u8; 32],
        test_vectors: vec![OutletTestVector {
            input: serde_json::json!({}),
            expected_output: serde_json::json!({}),
            description: "noop".to_owned(),
        }],
        operator_did: "did:key:test-operator".into(),
        cost: None,
        message_catalog: catalog,
        registered_at,
        signature: Vec::new(),
    }
}

// -----------------------------------------------------------------------
// Pure-validator tests — no manager, no event log
// -----------------------------------------------------------------------

/// AC1 (validator semantics, catalog unchanged): when `message_catalog`
/// is identical the validator is silent regardless of dwell time. Re-
/// registration that does not edit the catalog is the expected mechanism
/// for advancing `outlet_message_key` past an MLS epoch boundary
/// (SCP-OUT-041a) and is intentionally not throttled by §5.4.4.
#[test]
fn validator_silent_when_catalog_unchanged() {
    // Even a pathologically-fast retry (1 second after the prior) is
    // permitted when the catalog is identical.
    let result = validate_catalog_rotation_dwell_time(&catalog_a(), &catalog_a(), T0, T0 + 1);
    assert!(result.is_ok(), "unchanged catalog must not be throttled");
}

/// AC1 (validator semantics, catalog changed within 24h): an update that
/// edits `message_catalog` and lands within 24 h of the prior is
/// rejected with the typed envelope under `Protocol` / `SCP-TOOL-6100` /
/// `protocol.catalog-rotation-too-frequent`.
#[test]
fn validator_rejects_catalog_edit_within_dwell_floor() {
    // T0 + 23.99 h ≈ 86_364 s elapsed — strictly less than 86_400.
    let new_ts = T0 + (23 * 3600 + 59 * 60 + 24);
    let err = validate_catalog_rotation_dwell_time(&catalog_a(), &catalog_b(), T0, new_ts)
        .expect_err("23.99h elapsed must be rejected");

    assert_eq!(err.envelope.code, CODE_PROTOCOL_VIOLATION);
    assert_eq!(
        err.envelope.slug,
        SLUG_PROTOCOL_CATALOG_ROTATION_TOO_FREQUENT
    );
    assert!(matches!(err.envelope.class, OutletErrorClass::Protocol));
    assert!(err.elapsed_secs < CATALOG_ROTATION_DWELL_SECS);
}

/// AC2 (T0 + 24.01 h accepted): an update that edits the catalog at any
/// time at-or-after 24 h is accepted by the validator. The 24-hour floor
/// is INCLUSIVE — exactly 86_400 s of elapsed time clears the rule.
#[test]
fn validator_accepts_catalog_edit_at_or_after_dwell_floor() {
    // Exactly at the floor: 24h * 3600 = 86_400.
    let exact = validate_catalog_rotation_dwell_time(
        &catalog_a(),
        &catalog_b(),
        T0,
        T0 + CATALOG_ROTATION_DWELL_SECS,
    );
    assert!(exact.is_ok(), "exact 24h must be accepted");

    // T0 + 24.01h.
    let after = T0 + (24 * 3600 + 36); // +24h00m36s
    let result = validate_catalog_rotation_dwell_time(&catalog_a(), &catalog_b(), T0, after);
    assert!(result.is_ok(), "24.01h elapsed must be accepted");
}

/// AC3 (back-dating regression — pure validator): the validator accepts
/// only the trusted clock pair (`prior_append_time_secs`,
/// `new_append_time_secs`). Operator-declared `registered_at` values are
/// not accepted as inputs anywhere on this path. The "back-dated" attack
/// is structurally impossible at the validator boundary because the
/// operator-declared timestamps are never threaded in. This test pins
/// that contract: feeding the validator the actual event-log times
/// (T0, T0 + 12 h) rejects regardless of any plausible operator
/// `registered_at` claim.
#[test]
fn validator_uses_event_log_clock_only() {
    // 12 h of actual event-log dwell — well under the 24 h floor.
    let new_ts = T0 + 12 * 3600;
    let rejection: Box<CatalogRotationDwellRejection> =
        validate_catalog_rotation_dwell_time(&catalog_a(), &catalog_b(), T0, new_ts)
            .expect_err("12h elapsed must be rejected on the event-log clock");
    assert!(rejection.elapsed_secs < CATALOG_ROTATION_DWELL_SECS);
    assert_eq!(rejection.envelope.code, CODE_PROTOCOL_VIOLATION);
    assert_eq!(
        rejection.envelope.slug,
        SLUG_PROTOCOL_CATALOG_ROTATION_TOO_FREQUENT
    );
}

/// The `catalog_rotation_dwell_rejection_to_context` helper wraps the
/// typed envelope as `ContextError::OutletInvocation` so callers receive
/// the canonical typed error surface (no `PermissionDenied` fallback).
#[test]
fn rejection_to_context_yields_outlet_invocation() {
    let rejection =
        validate_catalog_rotation_dwell_time(&catalog_a(), &catalog_b(), T0, T0 + 12 * 3600)
            .expect_err("must reject");
    let ctx_err = catalog_rotation_dwell_rejection_to_context(rejection);
    match ctx_err {
        ContextError::OutletInvocation(env) => {
            assert_eq!(env.code, CODE_PROTOCOL_VIOLATION);
            assert_eq!(env.slug, SLUG_PROTOCOL_CATALOG_ROTATION_TOO_FREQUENT);
            assert!(matches!(env.class, OutletErrorClass::Protocol));
        }
        other => panic!("expected OutletInvocation, got {other:?}"),
    }
}

// -----------------------------------------------------------------------
// Integration tests — `ContextManager::execute_register_outlet`
// -----------------------------------------------------------------------

/// Mock event log that lets tests pin the per-context append timestamp
/// for `OutletRegistered` events to a synthetic value, while preserving
/// the SHA-256 hash chaining real event-log readers expect.
///
/// Each appended event is stored with the timestamp produced by the
/// injected `Clock`, so a `TestClock` driven by the test drives both the
/// runtime's "now" and the event-log's append time deterministically.
struct ClockedEventLog {
    clock: Arc<dyn Clock>,
    inner: std::sync::Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    inited: Vec<[u8; 32]>,
    entries: Vec<([u8; 32], EventLogEntry)>,
    destroyed: Vec<[u8; 32]>,
}

impl ClockedEventLog {
    fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            inner: std::sync::Mutex::new(Inner::default()),
        }
    }

    #[allow(dead_code)]
    fn outlet_registered_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap()
            .entries
            .iter()
            .filter(|(_, e)| e.event == "OutletRegistered")
            .count()
    }
}

impl ContextEventLogProvider for ClockedEventLog {
    fn init_event_log(
        &self,
        id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        self.inner.lock().unwrap().inited.push(*id);
        Ok(())
    }

    fn append_event(
        &self,
        id: &[u8; 32],
        event: &str,
        actor_did: &str,
        payload: Option<&serde_json::Value>,
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        let timestamp = self.clock.now_secs();
        let mut inner = self.inner.lock().unwrap();
        let prev_hash = inner
            .entries
            .iter()
            .rev()
            .find(|(cid, _)| cid == id)
            .map_or([0u8; 32], |(_, e)| e.hash);
        let hash = crate::context::providers::event_log::entry_hash(
            event, actor_did, timestamp, &prev_hash, payload,
        );
        inner.entries.push((
            *id,
            EventLogEntry {
                event: event.to_owned(),
                actor_did: actor_did.to_owned(),
                timestamp,
                prev_hash,
                hash,
                payload: payload.cloned(),
            },
        ));
        Ok(())
    }

    fn destroy_event_log(
        &self,
        id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        self.inner.lock().unwrap().destroyed.push(*id);
        Ok(())
    }

    fn event_log_entries(
        &self,
        context_id: &[u8; 32],
    ) -> Result<Option<Vec<EventLogEntry>>, ContextError> {
        let inner = self.inner.lock().unwrap();
        let result: Vec<EventLogEntry> = inner
            .entries
            .iter()
            .filter(|(cid, _)| cid == context_id)
            .map(|(_, e)| e.clone())
            .collect();
        if result.is_empty() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }
}

fn ctx_params_with_outlet_register() -> ContextParams {
    ContextParams {
        ceiling: vec![
            ProtoCapability::new("messages:read").expect("known capability"),
            ProtoCapability::new("messages:write").expect("known capability"),
            ProtoCapability::new("role:assign").expect("known capability"),
            Capability::OutletRegister,
        ],
        ..ContextParams::default()
    }
}

#[allow(clippy::unused_async)]
async fn build_test_manager_at(start_secs: u64) -> (ContextManager, Arc<TestClock>) {
    let clock = Arc::new(TestClock::new(start_secs));
    let event_log = ClockedEventLog::new(Arc::clone(&clock) as Arc<dyn Clock>);
    let manager = ContextManager::builder()
        .crypto(Box::new(MockCrypto::default()))
        .transport(Box::new(MockTransport::connected()))
        .event_log(Box::new(event_log))
        .key_resolver(noop_key_resolver())
        .clock(Arc::clone(&clock) as Arc<dyn Clock>)
        .build()
        .expect("build context manager");
    (manager, clock)
}

/// AC2 (integration, T0 + 23.99 h rejected; T0 + 24.01 h accepted): an
/// outlet registered at event-log time T0 with catalog C0, then updated
/// to catalog C1 at T0 + 23.99 h is rejected via
/// `ContextError::OutletInvocation` carrying the typed envelope under
/// `OutletErrorClass::Protocol` / `CODE_PROTOCOL_VIOLATION` /
/// `protocol.catalog-rotation-too-frequent`. A subsequent re-attempt at
/// T0 + 24.01 h is accepted.
#[tokio::test]
async fn execute_register_outlet_enforces_24h_dwell_on_catalog_edit() {
    let (manager, clock) = build_test_manager_at(T0).await;
    let _handle = manager
        .create_context(
            "test-ctx".into(),
            ctx_params_with_outlet_register(),
            "did:key:creator".into(),
            None,
        )
        .await
        .expect("create context");

    let pid = [0u8; 32];

    // Initial registration at T0 with catalog C0.
    let reg_v0 = outlet_registration(catalog_a(), T0);
    manager
        .execute_register_outlet("test-ctx", &reg_v0, pid, "did:key:creator")
        .await
        .expect("initial registration must succeed");

    // Advance clock to T0 + 23.99 h. Update with catalog C1.
    let dwell_minus = 23 * 3600 + 59 * 60 + 24; // 23h 59m 24s ≈ 23.99h
    clock.advance(dwell_minus);
    let reg_v1_too_soon = outlet_registration(catalog_b(), T0 + dwell_minus);
    let err = manager
        .execute_register_outlet("test-ctx", &reg_v1_too_soon, pid, "did:key:creator")
        .await
        .expect_err("update within 24h must be rejected");

    match err {
        ContextError::OutletInvocation(env) => {
            assert_eq!(env.code, CODE_PROTOCOL_VIOLATION);
            assert_eq!(env.slug, SLUG_PROTOCOL_CATALOG_ROTATION_TOO_FREQUENT);
            assert!(matches!(env.class, OutletErrorClass::Protocol));
        }
        other => panic!("expected OutletInvocation envelope, got {other:?}"),
    }

    // Advance clock to just past 24h (cumulative T0 + 24.01h). Update
    // with catalog C1 must succeed.
    let after_dwell = (24 * 3600 + 36) - dwell_minus; // remainder to push past 24h
    clock.advance(after_dwell);
    let reg_v1_ok = outlet_registration(catalog_b(), clock.now_secs());
    manager
        .execute_register_outlet("test-ctx", &reg_v1_ok, pid, "did:key:creator")
        .await
        .expect("update at 24.01h must be accepted");
}

/// AC3 (operator-clock-bypass regression): an attacker that back-dates
/// `OutletRegistration::registered_at` to `T0 - 12 h` (so a naïve
/// `registered_at` delta would falsely report 36 h of "dwell") cannot
/// bypass the 24 h floor because the validator consults the event-log
/// append time — a protocol-enforced clock the operator cannot forge.
/// The actual event-log append happens at `T0 + 12 h`, so the validator
/// computes `12 h < 24 h` and rejects.
#[tokio::test]
async fn back_dated_registered_at_cannot_bypass_dwell_rule() {
    let (manager, clock) = build_test_manager_at(T0).await;
    let _handle = manager
        .create_context(
            "test-ctx".into(),
            ctx_params_with_outlet_register(),
            "did:key:creator".into(),
            None,
        )
        .await
        .expect("create context");

    let pid = [0u8; 32];

    // Initial registration at event-log time T0. Operator declares the
    // truthful `registered_at = T0`.
    let reg_v0 = outlet_registration(catalog_a(), T0);
    manager
        .execute_register_outlet("test-ctx", &reg_v0, pid, "did:key:creator")
        .await
        .expect("initial registration must succeed");

    // 12 h elapses on the event-log clock. The attacker now submits an
    // update with `registered_at = T0 - 12h` so a naïve dwell check
    // against `registered_at` deltas would compute `T0 - (T0 - 12h) = 36h`
    // (above the 24h floor) and incorrectly accept the update.
    clock.advance(12 * 3600);
    let back_dated_registered_at = T0.saturating_sub(12 * 3600);
    let reg_v1_back_dated = outlet_registration(catalog_b(), back_dated_registered_at);

    let err = manager
        .execute_register_outlet("test-ctx", &reg_v1_back_dated, pid, "did:key:creator")
        .await
        .expect_err("back-dated registered_at must NOT bypass the dwell floor");

    match err {
        ContextError::OutletInvocation(env) => {
            assert_eq!(env.code, CODE_PROTOCOL_VIOLATION);
            assert_eq!(env.slug, SLUG_PROTOCOL_CATALOG_ROTATION_TOO_FREQUENT);
            assert!(matches!(env.class, OutletErrorClass::Protocol));
        }
        other => panic!("expected OutletInvocation envelope, got {other:?}"),
    }
}

/// Re-registering the same outlet with the **same** catalog within the
/// dwell window is permitted: SCP-OUT-041a treats catalog-preserving
/// re-registration as the canonical mechanism for refreshing
/// `outlet_message_key` past an MLS epoch boundary.
#[tokio::test]
async fn re_registration_with_unchanged_catalog_is_not_throttled() {
    let (manager, clock) = build_test_manager_at(T0).await;
    let _handle = manager
        .create_context(
            "test-ctx".into(),
            ctx_params_with_outlet_register(),
            "did:key:creator".into(),
            None,
        )
        .await
        .expect("create context");

    let pid = [0u8; 32];

    let reg_v0 = outlet_registration(catalog_a(), T0);
    manager
        .execute_register_outlet("test-ctx", &reg_v0, pid, "did:key:creator")
        .await
        .expect("initial registration");

    // Advance clock by 1 second. Same catalog → must succeed regardless
    // of dwell time.
    clock.advance(1);
    let reg_v0_again = outlet_registration(catalog_a(), clock.now_secs());
    manager
        .execute_register_outlet("test-ctx", &reg_v0_again, pid, "did:key:creator")
        .await
        .expect("same-catalog re-registration must succeed");
}
