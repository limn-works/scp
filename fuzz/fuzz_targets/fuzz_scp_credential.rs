#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use libfuzzer_sys::fuzz_target;
use scp_runtime::crypto::mls::credential::ScpCredential;

fuzz_target!(|data: &[u8]| {
    let _ = ScpCredential::from_bytes(data);
});
