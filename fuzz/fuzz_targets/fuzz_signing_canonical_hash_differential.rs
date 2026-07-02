#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! Sign-then-verify consistency fuzz target (Tier 3 — covers #1661).
//!
//! # Security property
//!
//! The bytes that `create_inner_envelope_raw` signs (via `compute_canonical_hash`)
//! and the bytes that `verify_inner_signature` verifies (also via
//! `compute_canonical_hash`) must be identical for the same `InnerEnvelopeParams`.
//! If they diverge, a second-preimage attack becomes possible: an adversary
//! could produce an envelope that passes signature verification with a different
//! canonical hash than what was actually signed.
//!
//! # Assertion
//!
//! For any fuzz-generated `InnerEnvelopeParams` that reaches the signing step:
//!
//! 1. `create_inner_envelope_raw(params, key)` succeeds (no OOM/truncation panic).
//! 2. `verify_inner_signature(&envelope, verifying_key_bytes)` returns `Ok(true)`.
//!
//! If step 2 returns `Ok(false)` or `Err(_)` for a freshly-signed envelope,
//! the signing-hash and verification-hash inputs have diverged — this is a
//! **P0 security bug**.
//!
//! # Strategy
//!
//! Uses `Arbitrary` because `create_inner_envelope_raw` requires a valid
//! `InnerEnvelopeParams` struct, not raw bytes. The fuzzer varies all fields
//! that enter the canonical hash: `version`, `context_id`, `sender_did`,
//! `epoch`, `generation`, `sequence`, `timestamp`, `message_type`,
//! `signing_key_id`. `payload` and `provenance` are held constant to keep the
//! hash computation path fast (payload is hashed before signing; varying it
//! would add SHA-256 cost per fuzz iteration without exercising new code paths).
//!
//! # Trust boundary
//!
//! B2: Post-MLS decryption. `verify_inner_signature` is called on every
//! received message. A bug here would allow forged messages to pass
//! verification.
//!
//! # Security invariants
//! - I1: Must never panic on any input.
//! - I3: Freshly-signed envelope always verifies (sign-then-verify consistency).

use libfuzzer_sys::fuzz_target;
use scp_fuzz::ArbCanonicalHashInput;
use scp_did::SigningKeyId;
use scp_protocol::envelope::inner::verify_inner_signature;
use scp_protocol::envelope::InnerEnvelopeParams;

use ed25519_dalek::SigningKey;
use scp_runtime::envelope::inner::sign::create_inner_envelope_raw;

// Fixed signing key for all fuzz runs (deterministic, non-secret).
const FUZZ_SEED: [u8; 32] = [
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x01, 0x23,
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x01, 0x23,
    0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98,
    0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98,
];

fuzz_target!(|input: ArbCanonicalHashInput| {
    // Use only the `a` half of the pair — we only need one set of params.
    let Ok(ctx) = std::str::from_utf8(&input.a.context_id) else {
        return;
    };
    let Ok(did) = std::str::from_utf8(&input.a.sender_did) else {
        return;
    };

    let signing_key = SigningKey::from_bytes(&FUZZ_SEED);
    let verifying_key_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();

    let msg_type: scp_protocol::envelope::MessageType = input.a.message_type.clone().into();

    // Build params with fuzz-controlled fields.
    let params = InnerEnvelopeParams {
        version: input.a.version,
        context_id: ctx,
        sender_did: did,
        epoch: input.a.epoch,
        generation: input.a.generation,
        sequence: input.a.sequence,
        timestamp: input.a.timestamp,
        message_type: msg_type,
        // Fixed payload so SHA-256(payload) is stable — we care about the
        // canonical hash input, not the hash of the payload itself.
        payload: b"fuzz-payload",
        provenance: None,
        signing_key_id: SigningKeyId::Active,
    };

    // Step 1: Sign.
    let envelope = match create_inner_envelope_raw(&params, &signing_key) {
        Ok(env) => env,
        // PayloadTooLarge or SerializationFailed → skip this input.
        Err(_) => return,
    };

    // Step 2: Verify with the same key.
    // I3: verify_inner_signature MUST return Ok(true) for a freshly-signed
    // envelope. Any other result indicates a signing-verification hash mismatch.
    let result = verify_inner_signature(&envelope, &verifying_key_bytes);
    assert!(
        matches!(result, Ok(true)),
        "security invariant I3 violated: freshly-signed envelope failed verification \
         (signing-hash and verification-hash inputs diverged).\n\
         Error: {result:?}\n\
         context_id: {ctx:?}, sender_did: {did:?}, \
         epoch: {}, generation: {}, sequence: {}, timestamp: {}, \
         message_type: {:?}",
        input.a.epoch,
        input.a.generation,
        input.a.sequence,
        input.a.timestamp,
        input.a.message_type,
    );
});
