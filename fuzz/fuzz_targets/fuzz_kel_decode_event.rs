#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! Key-event unit decode fuzz target (Tier 2, trust boundary B3).
//!
//! A key event log arrives from an untrusted relay as a run of §9.10.12
//! event units, and `scp_kel::decode_event` reads one unit at a time in the
//! check order of `09-security-model.md` §9.7.4.2. The target walks `data`
//! as such a run, from offset 0 to the first unit that does not report
//! `consumed`. Invariants:
//!
//! - I1: no input panics `decode_event`, `raw_identifier` or
//!   `inception_header_zero_checks`.
//! - I2: the stages run in the check order: no header without the raw
//!   preimage, no walk and no body unless the header passed, and `consumed`
//!   only when the walk passed.
//! - I3: a unit whose stages all succeed re-encodes to the bytes it
//!   consumed: the length prefix, the re-encoded signed preimage, then each
//!   walked signature, equal `data[offset..offset + consumed]`.
//! - I4: the header agrees with the body it was read from.

use libfuzzer_sys::fuzz_target;
use scp_kel::{decode_event, encode_preimage, inception_header_zero_checks, raw_identifier};

fuzz_target!(|data: &[u8]| {
    let mut offset = 0;
    loop {
        let unit = decode_event(data, offset);
        let Some(raw) = unit.raw_signed_preimage() else {
            assert!(unit.header().is_none() && unit.consumed().is_none());
            break;
        };
        let _ = raw_identifier(raw);
        let _ = inception_header_zero_checks(raw);
        let header = unit.header().expect("a raw preimage has a header stage");
        let Ok(header) = header else {
            assert!(unit.signatures().is_none() && unit.body().is_none());
            assert!(unit.consumed().is_none());
            break;
        };
        let signatures = unit.signatures().expect("a passed header is walked");
        let body = unit.body().expect("a passed header has a body stage");
        let Ok(groups) = signatures else {
            assert!(unit.consumed().is_none());
            break;
        };
        let consumed = unit.consumed().expect("a passed walk reports consumed");
        assert!(consumed > 0);
        if let Ok(body) = body {
            let preimage = body.preimage();
            assert_eq!(body.signed_preimage(), raw);
            assert_eq!(header.kind(), preimage.kind);
            assert_eq!(header.identifier(), preimage.identifier);
            assert_eq!(header.sequence(), preimage.sequence);
            assert_eq!(header.predecessor_digest(), &preimage.predecessor_digest);
            assert_eq!(header.standing_root(), preimage.standing_root);
            assert_eq!(header.signer_groups(), preimage.signer_groups.as_slice());

            let reencoded = encode_preimage(preimage).expect("a decoded preimage encodes");
            let signed = reencoded.signed_preimage();
            let mut unit_bytes = u32::try_from(signed.len()).unwrap().to_be_bytes().to_vec();
            unit_bytes.extend_from_slice(signed);
            for group in groups {
                for signature in group.signatures() {
                    unit_bytes.extend_from_slice(&signature.to_bytes());
                }
            }
            assert_eq!(unit_bytes, data[offset..offset + consumed]);
        }
        offset += consumed;
    }
});
