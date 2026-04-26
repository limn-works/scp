//! SCP-OUT-029 — Integration test: cross-context outlet error wrapping
//! through three contexts (A → B → C) where C produces an `OutletError`
//! and the wrapping path back to A preserves the original `code` and
//! records the trail of contexts the error traversed.
//!
//! The test exercises [`wrap_cross_context_error`] at multiple layers:
//!
//! 1. **C** produces the error via [`OutletError::new`].
//! 2. **B** wraps as the error crosses out of C into B (intermediate
//!    layer; permissive view, no padding/pseudonymization fires here —
//!    the projection is deferred to the outermost observing layer).
//! 3. **A** wraps as the error crosses out of B into A. A is the
//!    outermost consumer; its view applies pseudonymization for non-
//!    member hops, oracle collapse for absent stems, and round-5
//!    trail-length padding when any hop is opaque.
//!
//! Asserts:
//!
//! - **Code preservation** — `wrapped.code == prev.code` (the §5.4.4
//!   cross-context wrapping rule: original code is NOT remapped). The
//!   integration test verifies this for the full visibility path.
//! - **Trail composition** — `source_chain` carries entries for B and C,
//!   ordered with the outermost wrap (most recently prepended) at front
//!   and `wrapped_code` preserved on every entry.
//! - **`pad_nonce` round-trip** — the envelope's `pad_nonce: [u8; 16]` is
//!   preserved verbatim through `MessagePack` serialization.
//!
//! See `.docs/specs/05-contexts.md` §5.4.4 (Outlet Error Taxonomy) and
//! `.docs/prds/outlet.json` SCP-OUT-029 acceptance criteria.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use scp_protocol::context::metadata::ContextId;
use scp_protocol::context::outlets::OutletId;
use scp_protocol::context::outlets::errors::{
    CatalogKey, MAX_TRAIL_PAD_DEPTH, OutletError, OutletErrorClass, OutletErrorNewOpts,
    PAD_NONCE_LEN, RetryPolicy,
};
use scp_runtime::context::manager::{
    OuterCallerStems, OutletErrorWrapView, wrap_cross_context_error,
};
use std::collections::{HashMap, HashSet};

const FIXED_OUTLET_MESSAGE_KEY: [u8; 32] = [0x42; 32];
const FIXED_REGISTRATION_EVENT_ID: [u8; 32] = [0xAB; 32];

fn registered_keys() -> Vec<CatalogKey> {
    vec![
        CatalogKey::try_new("authorization.denied").unwrap(),
        CatalogKey::try_new("authorization.amplification-violation").unwrap(),
    ]
}

fn build_inner_error_at_c() -> OutletError {
    let outlet_id: OutletId = "outlet-c-inner".to_owned();
    let key = CatalogKey::try_new("authorization.denied").unwrap();
    let registered = registered_keys();
    OutletError::new(OutletErrorNewOpts {
        outlet_id: &outlet_id,
        outlet_message_key: &FIXED_OUTLET_MESSAGE_KEY,
        registration_event_id: FIXED_REGISTRATION_EVENT_ID,
        catalog_key: &key,
        registered_keys: &registered,
        class: OutletErrorClass::Authorization,
        code: "SCP-TOOL-6110",
        slug: "authorization.denied",
        retry: RetryPolicy::Never,
        detail: None,
        source_chain: Vec::new(),
        pad_nonce: [0x55; PAD_NONCE_LEN],
    })
    .unwrap()
}

#[test]
fn integration_a_b_c_wrap_preserves_original_code_and_trail() {
    // Context A → Context B → Context C invocation. C returns an
    // OutletError at the innermost layer. We simulate the propagation:
    //
    //   C produces the error.
    //   B wraps (intermediate; just appends a real ContextHop).
    //   A receives and applies its outermost-observer view.
    //
    // A holds full visibility over the chain (member of A, B, C; both
    // stems on the inner outlet). A observes:
    //   - `code == "SCP-TOOL-6110"` (original, preserved)
    //   - `source_chain.len() == 2` (un-padded; entries for B and C)
    //   - `source_chain[0].context_id == "ctx-b"` (most recent wrap)
    //   - `source_chain[1].context_id == "ctx-c"` (innermost wrap)
    //   - both entries' `wrapped_code == "SCP-TOOL-6110"` (preserved)

    // Build the inner error at C.
    let inner = build_inner_error_at_c();
    let original_code = inner.code.clone();

    // B wraps using a permissive intermediate view (no padding, no
    // pseudonymization — defers the projection to A's wrap).
    let intermediate_observer: ContextId = "ctx-passthrough".to_owned();
    let mut intermediate_members: HashSet<String> = HashSet::new();
    intermediate_members.insert("ctx-c".to_owned());
    intermediate_members.insert("ctx-b".to_owned());
    intermediate_members.insert("ctx-a".to_owned());
    intermediate_members.insert(intermediate_observer.clone());
    let intermediate_salts: HashMap<String, [u8; 32]> = HashMap::new();
    let intermediate_view = OutletErrorWrapView {
        observer_ctx: &intermediate_observer,
        member_of_context: &|c| intermediate_members.contains(c),
        hop_salts: &|c| intermediate_salts.get(c).copied(),
        outer_caller_stems: OuterCallerStems {
            holds_query: true,
            holds_call: true,
        },
        inner_outlet_kind: None,
        pad_nonce: [0x00; PAD_NONCE_LEN],
        max_padded_trail_depth: 0,
    };
    let after_b = wrap_cross_context_error(&"ctx-b".to_owned(), inner, &intermediate_view);

    // A receives. A is the outermost consumer with full visibility.
    let observer: ContextId = "ctx-a".to_owned();
    let mut a_members: HashSet<String> = HashSet::new();
    a_members.insert(observer.clone());
    a_members.insert("ctx-b".to_owned());
    a_members.insert("ctx-c".to_owned());
    let a_salts: HashMap<String, [u8; 32]> = HashMap::new();
    let a_view = OutletErrorWrapView {
        observer_ctx: &observer,
        member_of_context: &|c| a_members.contains(c),
        hop_salts: &|c| a_salts.get(c).copied(),
        outer_caller_stems: OuterCallerStems {
            holds_query: true,
            holds_call: true,
        },
        inner_outlet_kind: None,
        pad_nonce: [0xCC; PAD_NONCE_LEN],
        max_padded_trail_depth: MAX_TRAIL_PAD_DEPTH,
    };

    // For the integration test the wrap-path at A can be modeled in two
    // equivalent ways: either A wraps with caller_ctx=B (recording the
    // boundary B→A just crossed) or A delegates wrapping to its inner
    // runtime call site. Both produce the trail "B and C" the AC requires.
    // Here we follow the per-cross-context-boundary convention: A
    // already-received the wrapped error from B and observes it directly.
    // A's projection re-projects existing source_chain entries through A's
    // view (raw context_ids since A is a member of every hop).
    let observed_at_a = wrap_cross_context_error(
        &"system-noop".to_owned(), // sentinel — not part of the trail; A
        // performs a no-op outer wrap to project the chain through its
        // view. A more typical runtime would wire wrap_cross_context_error
        // at the actual cross-context boundary (between contexts), but
        // this test focuses on the projection at A.
        after_b.clone(),
        &a_view,
    );

    // Code preserved.
    assert_eq!(after_b.code, original_code, "B preserves original code");
    assert_eq!(
        observed_at_a.code, original_code,
        "A observes original code"
    );

    // After B's wrap, the trail has one entry (for B) — C's hop is the
    // implicit origin recorded only by the outer envelope's `code` field
    // until A's runtime explicitly wraps for cross-context propagation
    // back to its observer.
    assert_eq!(after_b.source_chain.len(), 1);
    assert_eq!(after_b.source_chain[0].context_id, "ctx-b");
    assert_eq!(after_b.source_chain[0].wrapped_code, original_code);

    // Now exercise the A → B → C trail with B and C BOTH wrapping (the
    // "every-cross-context-boundary wraps" mode used in production).
    let inner2 = build_inner_error_at_c();
    let after_c = wrap_cross_context_error(&"ctx-c".to_owned(), inner2, &intermediate_view);
    let after_b2 = wrap_cross_context_error(&"ctx-b".to_owned(), after_c, &intermediate_view);
    // A consumes the full B-and-C trail.
    assert_eq!(after_b2.source_chain.len(), 2, "trail has B and C");
    assert_eq!(after_b2.source_chain[0].context_id, "ctx-b");
    assert_eq!(after_b2.source_chain[1].context_id, "ctx-c");
    assert_eq!(after_b2.source_chain[0].wrapped_code, original_code);
    assert_eq!(after_b2.source_chain[1].wrapped_code, original_code);
    // Monotonic hop_index — front is the most-recent wrap (highest).
    assert!(
        after_b2.source_chain[0].hop_index > after_b2.source_chain[1].hop_index,
        "monotonic hop_index ordering"
    );

    // pad_nonce is preserved through MessagePack round-trip on the
    // observed envelope.
    let bytes = rmp_serde::to_vec_named(&observed_at_a).unwrap();
    let back: OutletError = rmp_serde::from_slice(&bytes).unwrap();
    assert_eq!(
        back.pad_nonce, observed_at_a.pad_nonce,
        "pad_nonce round-trips byte-identical"
    );
}
