#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! Capability URI parser fuzz target (Tier 2).
//!
//! Exercises two distinct `CapabilityUri` parsers from different protocol
//! layers with arbitrary byte inputs:
//! - `scp_protocol::trust::CapabilityUri` (trust layer)
//! - `scp_protocol::crypto::ucan::capability::CapabilityUri` (UCAN layer)
//!
//! Invariants verified:
//! - I1: Neither parser panics on any byte input.
//! - Display roundtrip: if a parser accepts a string, re-parsing its `Display`
//!   output must also succeed and produce the same `Display` representation.
//!   A parser that fails its own roundtrip has a broken `Display` impl.

use libfuzzer_sys::fuzz_target;
use scp_protocol::crypto::ucan::capability::CapabilityUri as UcanCapabilityUri;
use scp_protocol::trust::CapabilityUri as TrustCapabilityUri;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // Trust-layer parser: verify I1 (no panic) + Display roundtrip.
    if let Ok(trust_uri) = s.parse::<TrustCapabilityUri>() {
        let displayed = trust_uri.to_string();
        let reparsed = displayed.parse::<TrustCapabilityUri>();
        assert!(
            reparsed.is_ok(),
            "TrustCapabilityUri Display roundtrip failed: \
             parsed {s:?} → displayed {displayed:?} → reparse error: {:?}",
            reparsed.unwrap_err()
        );
        assert_eq!(
            reparsed.unwrap().to_string(),
            displayed,
            "TrustCapabilityUri Display is not idempotent for input {s:?}"
        );
    }

    // UCAN-layer parser: verify I1 (no panic) + Display roundtrip.
    if let Ok(ucan_uri) = s.parse::<UcanCapabilityUri>() {
        let displayed = ucan_uri.to_string();
        let reparsed = displayed.parse::<UcanCapabilityUri>();
        assert!(
            reparsed.is_ok(),
            "UcanCapabilityUri Display roundtrip failed: \
             parsed {s:?} → displayed {displayed:?} → reparse error: {:?}",
            reparsed.unwrap_err()
        );
        assert_eq!(
            reparsed.unwrap().to_string(),
            displayed,
            "UcanCapabilityUri Display is not idempotent for input {s:?}"
        );
    }
});
