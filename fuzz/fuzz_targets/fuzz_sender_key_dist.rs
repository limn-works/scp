#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use libfuzzer_sys::fuzz_target;
use scp_protocol::crypto::sender_keys::SenderKeyDistributionMessage;

fuzz_target!(|data: &[u8]| {
    let _ = SenderKeyDistributionMessage::from_bytes(data);
});
