#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use libfuzzer_sys::fuzz_target;
use scp_transport::native::protocol::ClientMessage;

fuzz_target!(|data: &[u8]| {
    let _ = ClientMessage::from_bytes(data);
});
