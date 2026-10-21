#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! Key-event unit decode fuzz target (Tier 2, trust boundary B3).
//!
//! A key event log arrives from an untrusted relay as a run of §9.10.12
//! event units, and `scp_kel::decode_event` reads one unit at a time in the
//! check order of `09-security-model.md` §9.7.4.2. The target walks `data`
//! as such a run, from offset 0 to the first unit whose signature field
//! does not walk. The order of the stages needs no invariant: `EventUnit`'s
//! variants are the stages that can stop a unit, so a walk or a body exists
//! only on a unit whose header passed. Invariants:
//!
//! - I1: no input panics `decode_event`, `RawSignedPreimage::identifier`,
//!   `RawSignedPreimage::event_digest` or
//!   `RawSignedPreimage::inception_zero_checks`.
//! - I2: a unit whose walk passed reads back to the bytes it consumed: the
//!   length prefix, the received signed preimage, then each walked
//!   signature, equal `data[offset..offset + consumed]`, whether or not its
//!   body decodes.
//! - I3: a unit whose body decodes re-encodes to the received signed
//!   preimage.

use libfuzzer_sys::fuzz_target;
use scp_kel::{EventUnit, decode_event, encode_preimage};

fuzz_target!(|data: &[u8]| {
    let mut offset = 0;
    loop {
        let unit = decode_event(data, offset);
        if let Some(raw) = unit.raw() {
            let _ = raw.identifier();
            let _ = raw.event_digest();
            let _ = raw.inception_zero_checks();
        }
        let EventUnit::Read(read) = unit else {
            break;
        };
        let raw = read.raw().signed_preimage();

        if let Ok(preimage) = read.preimage() {
            let reencoded = encode_preimage(preimage).expect("a decoded preimage encodes");
            assert_eq!(reencoded.signed_preimage(), raw);
        }

        let Ok(field) = read.signature_field() else {
            break;
        };
        let consumed = field.consumed();
        let mut unit_bytes = u32::try_from(raw.len()).unwrap().to_be_bytes().to_vec();
        unit_bytes.extend_from_slice(&raw);
        for group in field.groups() {
            for signature in group.signatures() {
                unit_bytes.extend_from_slice(&signature.signature().to_bytes());
            }
        }
        assert_eq!(unit_bytes, data[offset..offset + consumed]);
        offset += consumed;
    }
});
