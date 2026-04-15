#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use libfuzzer_sys::fuzz_target;
use scp_protocol::envelope::chunk::ChunkEnvelope;

fuzz_target!(|data: &[u8]| {
    let _ = rmp_serde::from_slice::<ChunkEnvelope>(data);
});
