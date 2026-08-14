#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use libfuzzer_sys::fuzz_target;
use scp_relay_client::RelayMessage;

fuzz_target!(|data: &[u8]| {
    let _ = RelayMessage::from_bytes(data);
});
