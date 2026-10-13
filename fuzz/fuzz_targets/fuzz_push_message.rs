#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! B1, relay wire protocol: the blob of a PUBLISH to a relay's reserved push
//! routing ID, which a relay that offers push decodes as a `PushRegistration`
//! or a `PushDeregistration` (ADR-004, `10-infrastructure-and-self-hosting.md`
//! §10.7.1).
//!
//! I1: no input panics either decoder. A registration that decodes lists at
//! least one routing ID and builds its signature preimage, and re-encoding it
//! decodes to the same message.

use libfuzzer_sys::fuzz_target;
use scp_protocol::discovery::push::{
    PushDeregistration, PushRegistration, push_deregistration_signing_bytes,
    push_registration_signing_bytes,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(reg) = PushRegistration::from_msgpack(data) {
        assert!(!reg.routing_ids.is_empty());
        push_registration_signing_bytes(&reg, "wss://relay.example").unwrap();
        let again = PushRegistration::from_msgpack(&reg.to_msgpack().unwrap()).unwrap();
        assert_eq!(again, reg);
    }
    if let Ok(dereg) = PushDeregistration::from_msgpack(data) {
        push_deregistration_signing_bytes(&dereg, "wss://relay.example").unwrap();
        let again = PushDeregistration::from_msgpack(&dereg.to_msgpack().unwrap()).unwrap();
        assert_eq!(again, dereg);
    }
});
