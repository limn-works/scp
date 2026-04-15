#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use libfuzzer_sys::fuzz_target;
use scp_protocol::trust::CapabilityUri as TrustCapabilityUri;
use scp_protocol::crypto::ucan::capability::CapabilityUri as UcanCapabilityUri;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = s.parse::<TrustCapabilityUri>();
    let _ = s.parse::<UcanCapabilityUri>();
});
