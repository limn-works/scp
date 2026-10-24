#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! B1, relay wire protocol: the `token` of a WebPush `PushRegistration`, which
//! a relay decodes as a `WebPushSubscription` before it verifies the
//! registration's signature (`22-human-readable-addressing.md` §22.11.4
//! **WebPush token encoding**, ADR-004).
//!
//! I1: no input panics the decoder. A token that decodes is at most 2,133
//! bytes, re-encodes to exactly its input bytes (the encoding is canonical),
//! and holds an endpoint that starts with `https://`.

use libfuzzer_sys::fuzz_target;
use scp_protocol::discovery::push::{WEBPUSH_TOKEN_MAX_LEN, WebPushSubscription};

fuzz_target!(|data: &[u8]| {
    if let Ok(sub) = WebPushSubscription::decode(data) {
        assert!(data.len() <= WEBPUSH_TOKEN_MAX_LEN);
        assert_eq!(sub.encode(), data);
        assert!(sub.endpoint().starts_with("https://"));
    }
});
