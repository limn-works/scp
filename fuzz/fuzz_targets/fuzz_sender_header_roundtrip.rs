#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use libfuzzer_sys::fuzz_target;
use scp_protocol::crypto::sender_keys::encrypt::{build_sender_header, parse_sender_header};

fuzz_target!(|data: &[u8]| {
    let Ok((epoch, seq, ciphertext)) = parse_sender_header(data) else {
        return;
    };
    let rebuilt = build_sender_header(epoch, seq, ciphertext);
    let (e2, s2, c2) = parse_sender_header(&rebuilt)
        .expect("re-parsing a built header must succeed");
    assert_eq!(epoch, e2, "epoch must survive roundtrip");
    assert_eq!(seq, s2, "sequence must survive roundtrip");
    assert_eq!(ciphertext, c2, "ciphertext must survive roundtrip");
});
