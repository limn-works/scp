#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use libfuzzer_sys::fuzz_target;
use scp_protocol::context::broadcast_content::deserialize_broadcast_content;

fuzz_target!(|data: &[u8]| {
    let _ = deserialize_broadcast_content(data);
});
