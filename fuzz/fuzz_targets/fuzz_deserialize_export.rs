#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use libfuzzer_sys::fuzz_target;
use scp_runtime::context::export_import::deserialize_export;

fuzz_target!(|data: &[u8]| {
    let _ = deserialize_export(data);
});
