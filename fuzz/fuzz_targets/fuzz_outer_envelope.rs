#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use libfuzzer_sys::fuzz_target;
use scp_protocol::envelope::OuterEnvelope;

fuzz_target!(|data: &[u8]| {
    let _ = OuterEnvelope::from_bytes(data);
});
