#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use libfuzzer_sys::fuzz_target;
use scp_protocol::envelope::OuterEnvelope;

fuzz_target!(|data: &[u8]| {
    let Ok(env) = OuterEnvelope::from_bytes(data) else {
        return;
    };
    let Ok(reserialized) = env.to_bytes() else {
        return;
    };
    let Ok(env2) = OuterEnvelope::from_bytes(&reserialized) else {
        // If reserialize succeeds but re-parse fails, that is a bug.
        panic!("roundtrip failed: from_bytes(to_bytes()) returned error");
    };
    assert_eq!(
        env.routing_id, env2.routing_id,
        "routing_id must survive roundtrip"
    );
    assert_eq!(
        env.blob_ttl, env2.blob_ttl,
        "blob_ttl must survive roundtrip"
    );
    assert_eq!(
        env.encrypted_blob, env2.encrypted_blob,
        "encrypted_blob must survive roundtrip"
    );
    assert_eq!(
        env.recipient_hint, env2.recipient_hint,
        "recipient_hint must survive roundtrip"
    );
});
