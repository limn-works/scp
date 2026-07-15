//! Cross-target determinism known-answer tests (ADR-057 Prerequisite 5).
//!
//! ADR-057's core safety claim is that the shared `scp-protocol` / `scp-mls` /
//! `scp-event-log` code, compiled to **both** native and `wasm32`, produces
//! **byte-identical** output for the protocol's *deterministic* artifacts — the
//! convergent §9.9.3 event-log leaves and the target-independent wire encodings.
//! The ADR is explicit that this is *"an invariant only if tested"*: shared code
//! can still silently diverge across targets on `usize`/`as` width (wasm32 is
//! 32-bit), on `HashMap` iteration order feeding a hash, or on any hidden
//! platform dependency — and this codebase already has precedent (three
//! divergent "canonical" forms grown from shared intent). This file is that
//! guard.
//!
//! # The determinism boundary (what is golden-vectored vs. roundtrip-only)
//!
//! Per ADR-057 (Context §determinism, line 22), byte-identical output is a claim
//! about the **wire ENCODING of identical inputs** — NOT about two independent
//! *constructions*. MLS `KeyPackage` / Commit / Welcome generation, HPKE
//! encapsulation, and AES-GCM nonces all draw from the platform RNG and differ on
//! every run and every target *by design*, so building a Commit on each target and
//! comparing bytes would be wrong. But the TLS presentation codec is **canonical**
//! (one encoding per value), so *re-encoding a fixed blob* is deterministic and
//! cross-target-stable — and that is exactly the property Prerequisite 5 (i)/(iii)
//! names. This module therefore tests the MLS legs by ROUND-TRIP: it commits one
//! golden wire blob (captured once), and on both targets **deserializes then
//! re-serializes** it and asserts the bytes are byte-identical to the golden. A
//! `usize`/`as`-width divergence (wasm32 is 32-bit) or a length-prefix / ordering
//! bug in the codec would make the wasm re-serialization differ from the golden →
//! caught. No seeded provider and no MLS construction is needed for the assertion.
//!
//! So this module golden-vectors two disciplined families:
//!
//! **Deterministic artifacts given fixed inputs (hex pinned + asserted):**
//! 1. Event-log **leaf hashes + Merkle root** over a FIXED event sequence. Each
//!    leaf is `SHA-256(0x00 ‖ rmp_serde(event))` (RFC 6962 domain separation over
//!    the `MessagePack`-encoded `Event`); the root is the RFC 6962 Merkle root of
//!    those leaves. Deterministic across targets because `rmp_serde::to_vec` emits
//!    a **positional** `MessagePack` array with explicit integer widths (the `u64`
//!    sequence/timestamp as big-endian `MessagePack` uints, the `[u8; 32]`
//!    `prev_hash` as a fixed-length array) — so no native `usize` reaches the
//!    preimage, and there is no float and no map iteration to order. NOTE: because
//!    the encoding is positional (fields by index, not by name), a struct-field
//!    REORDER silently changes the preimage; that change is caught by the committed
//!    golden re-derivation this file forces. This is the load-bearing §9.9.3
//!    convergence leg: the root alone masks compensating leaf-level bugs, so EACH
//!    leaf hash is pinned too.
//! 2. The **convergent-timestamp AAD** (`scp_mls::encode_convergent_timestamp_aad`)
//!    over a fixed timestamp — the fixed 13-byte `SCPT ‖ version ‖ u64-BE` blob
//!    (ADR-057 T3). Pure big-endian layout, no `usize` — target-independent.
//! 3. The **credential encoding** (`ScpCredential::to_bytes`) from a fixed DID +
//!    fixed `SigningKeyId` — `rmp_serde::to_vec` emits a positional `MessagePack`
//!    array with explicit integer widths, deterministic and width-/endianness-
//!    independent; the credential carries no RNG-derived field (a struct-field
//!    reorder would change the preimage and is guarded by the golden below).
//! 4. **AEAD sender-layer roundtrip** for a FIXED key + message: assert
//!    `decrypt(k, encrypt(k, m, …), …) == m`. We assert the ROUNDTRIP, not the
//!    ciphertext bytes, precisely because the GCM nonce is random — the pipeline
//!    is stable even though the ciphertext is not.
//!
//! **MLS wire-encoding round-trips (ADR-057 Prerequisite 5 (i)/(iii)):** a fixed
//! golden **Commit** body, **Welcome** body, and **`KeyPackage`** blob (captured
//! once from a real add-member / key-package flow) is deserialized and
//! re-serialized through openmls's canonical TLS codec — `PrivateMessageIn` for the
//! Commit body, `Welcome` for the Welcome body, `KeyPackageIn` for the bare
//! `KeyPackage` — and the re-serialized bytes are asserted byte-identical to the
//! golden. The Commit / Welcome blobs are the MLS BODY extracted from the add's
//! `MlsMessage` envelope: the body carries all the length-prefixed, nested TLS
//! structure where a cross-target `usize`/width or ordering bug would surface (the
//! 4-byte `MlsMessage` header is two trivially-stable `u16`s). This is the
//! *encoding* determinism test, not a construction comparison: the same round-trip
//! runs on native and wasm32, so a codec that diverges across targets is caught
//! against the shared golden.
//!
//! **What each leg actually exercises (coverage honesty).** The **Commit** and
//! **Welcome** legs round-trip a `PrivateMessage` / `Welcome` — an ENCRYPTED
//! envelope — so they exercise only the OUTER framing codec (the length-prefixed
//! ciphertext blobs, sender-data, epoch/content-type fields). The inner Commit
//! body (proposal ordering, the `UpdatePath` nodes) rides ENCRYPTED inside that
//! `PrivateMessage` ciphertext, so its TLS encoding is opaque to this round-trip
//! and is NOT tested for cross-target determinism here (the `GroupContext` is not
//! on this wire at all — it is the implicit AEAD context, never serialized into the
//! frame). The **`KeyPackage`** leg is the one
//! that reaches the deep codec surface: it round-trips a CLEARTEXT `LeafNode` with
//! its nested TLS vectors (ciphersuite list, leaf/extension lists, the
//! capabilities' proposal/credential-type vectors), so it DOES exercise
//! nested-vector ordering and length-prefix determinism — exactly the `usize`/width
//! and iteration-order surface a cross-target bug would hit. So nobody should
//! over-read the Commit leg as proving Commit-BODY determinism; the `KeyPackage`
//! leg carries the nested-structure guarantee.
//!
//! # Cross-target execution (transitive golden agreement)
//!
//! Every golden-vector assertion lives in a helper called from BOTH a native
//! `#[test]` and a `#[wasm_bindgen_test]`, via the
//! `#[cfg_attr(target_arch = "wasm32", …)]` / `#[cfg_attr(not …, test)]` pattern.
//! Because both targets assert against the SAME committed hex constants,
//! agreement is transitive: `native == golden` AND `wasm == golden` implies
//! `native == wasm`. The native run proves determinism-vs-golden; the wasm run
//! (under `wasm-pack test --node`, ADR-057 Prerequisite 5 wasm-test-runner slice)
//! proves byte-equality across targets. No `usize` appears in any preimage
//! (wasm32 is 32-bit); every width-bearing field is encoded through the shared
//! library path (`rmp_serde` / `to_be_bytes`).

// KATs assert on fixed vectors; `expect`/`unwrap`/`panic` keep failures legible.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use openmls::prelude::{KeyPackageIn, PrivateMessageIn, Welcome};
use scp_did::{DID, SigningKeyId};
use scp_event_log::tree::{append_unsigned_event, event_count, leaf_hash, root};
use scp_event_log::{Event, EventLog, EventPayload, EventType};
use scp_mls::{ScpCredential, encode_convergent_timestamp_aad};
use scp_protocol::crypto::sender_keys::SenderKey;
use scp_protocol::crypto::sender_keys::encrypt::{decrypt_sender_layer, encrypt_sender_layer};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

// ---------------------------------------------------------------------------
// Fixed inputs (identical on every target and every run)
// ---------------------------------------------------------------------------

const KAT_CONTEXT_ID: &str = "ctx-adr057-determinism-kat";
// `did:dht:z*` is accepted by `ScpCredential::new` in EVERY build config (the
// test-only `did:key:` / `did:test:` acceptance is not needed here), so the
// credential vector is deterministic with no feature gate.
const KAT_DID_A: &str = "did:dht:z6MkDeterminismKatFixtureAAAAAAAAAAAAAAAAAAAAA";
const KAT_DID_B: &str = "did:dht:z6MkDeterminismKatFixtureBBBBBBBBBBBBBBBBBBBBB";

/// A fixed committer timestamp (Unix seconds) for the convergent-timestamp AAD
/// vector. Encoded big-endian, so its bytes are target-independent.
const KAT_TIMESTAMP: u64 = 1_700_000_000;

/// A fixed 32-byte sender key. `SenderKey::from_bytes` takes raw bytes with no
/// RNG, so the AEAD roundtrip is fully deterministic across targets.
const KAT_SENDER_KEY: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

// ---------------------------------------------------------------------------
// Golden constants (generated natively, asserted on BOTH targets)
// ---------------------------------------------------------------------------

/// GOLDEN: the three fixed leaf hashes, hex-encoded, in sequence order.
///
/// If a change to the leaf preimage (field order, length-prefix width, hashing)
/// or a cross-target width divergence moves ANY of these, this constant must be
/// re-derived — and that re-derivation is itself the review signal that a
/// convergence-affecting change happened.
const GOLDEN_LEAF_HASHES_HEX: [&str; 3] = [
    "9e764c99a8097d1dc40587ccdcf1cd002efdeb7d858e45492c93155b91ccd7b4",
    "b7d429600914383208acd69cd9fafc12751fb0d19e4bcd2865949e17e65b04da",
    "f08c6ac4d7b8fe71c7be6db1bd84dca8f12b14a9ff1a9f83800dbb81a8aca56a",
];

/// GOLDEN: the Merkle root over the fixed 3-event log, hex-encoded.
const GOLDEN_MERKLE_ROOT_HEX: &str =
    "04e2f5cf81a53441793f15eb477860aef98f8e826ccfff78c9b58c7248160b85";

/// GOLDEN: the convergent-timestamp AAD for `KAT_TIMESTAMP`, hex-encoded.
/// Layout: `b"SCPT" (4B) || version=1 (1B) || KAT_TIMESTAMP (u64 BE, 8B)` = 13 B.
/// `53 43 50 54` = `SCPT`, `01` = version, `00000000 6553f100` = `1_700_000_000` BE.
const GOLDEN_CONVERGENT_TIMESTAMP_AAD_HEX: &str = "5343505401000000006553f100";

/// GOLDEN: the `MessagePack` encoding of a fixed credential (fixed DID + Active
/// key, no UCAN), hex-encoded. `rmp_serde::to_vec` emits a positional array (the
/// leading `0x93` is a 3-element `MessagePack` fixarray, NOT a name-keyed map),
/// with explicit integer widths — target-independent.
const GOLDEN_CREDENTIAL_HEX: &str = "93d9366469643a6468743a7a364d6b44657465726d696e69736d4b617446697874757265414141414141414141414141414141414141414141c0a723616374697665";

// GOLDEN MLS wire blobs (captured once from a real add-member / key-package flow,
// ADR-057 Prerequisite 5 (i)/(iii)). These are NOT re-generated per run — the KAT
// only DESERIALIZES + RE-SERIALIZES them and asserts the re-encoding is
// byte-identical (the canonical-TLS-codec determinism test). Their init/HPKE keys
// and signatures are random-at-capture and never re-derived, so pinning the exact
// captured blob is correct here (unlike a fresh construction, which would differ).
// The Commit / Welcome blobs are the MLS BODY (`PrivateMessage` / `Welcome`)
// extracted from the add's MlsMessage envelope — the length-prefixed, nested TLS
// structure that carries all the codec surface a cross-target width/ordering bug
// would hit; the 4-byte MlsMessage header (two u16s) is trivially target-stable.

/// GOLDEN: the MLS **Commit** body — the `PrivateMessage` extracted from a
/// two-party add-member's Commit `MlsMessage`, hex-encoded. Round-trips via
/// `PrivateMessageIn`.
const GOLDEN_MLS_COMMIT_HEX: &str = "10a01421f30c03d1158b31ea99f3f776f80000000000000000030d5343505401000000006a57d8e51c0b941fa69492df01b663364a190b856d527f4a9a4f8630f494e8203143392b6fa74860d77c6688eafb6790673ea0bbdcf5de9c7bc01e1da1d95682e6bfd151c3b76a514f3f88dbb955e012c73fc77dad1a5f4e5d8584b2ef3449bb1721f22b3fcd43ee6b165d9ede08b8a29b8fcd530902b512950465fd243218becde489bea96d51bafe3c066329d6b229a763c8ef646633e0fe560871b45832e975f558acee2562bda111170e29802ce2a710cb74ddcc3af7bbd6555d710a4385c793bea6c0d8e970f29cf3d1c57ec11489652b9c61da3c8b4b20571901360ce677e084642658601e71ba85c73dfba9d7bf752f9b65eb4ce3465054044673154a39ce8c1ce93e58df4e7fd502b8dabed2839665b444e499301d53c07704985b3fcb03d3945fe2ac55e051800655986cfe94e07579cd60133470314687add68dd3b34e80888b0aaf195de70dbe646bdfc645f4854937302d9b68ee5ffeab19e53f3cc3933d93e8dbdbcee74aefeb8f00dd049d82564fec1e1c5db5195aabe981e2e90ee86d94e8a19204d8967767e0590d1b1c544c2d82bde9cbfb9aef1ad8427a489a9bbf128818a46da9c620ac89d59e94cb1b1ebdd1e5b3a8149d26694c13df7c8e431fe1f8938935772afccab4799c7f7857061536c45b2ed97dfe22d63ed1a1279cbfb0af15669551b5d16545812deec3bd2354cc33a7b4edd4c86fbf2f671e94619f3360c137f92c4402782574bbd8a1dd4d87f1563b2d53d89b0881ee08320855a39f984150d8971a32512ff72baeb1075e205cdd0f0e538460e65ffeb18094069edd91c8b4ed0de1268a7aa91f590a133a9a5ff19247eb3cead4ed9f5541fd0ed2b4fa9b9ca58afb126cf805cb8b3e54d5310d10f95643b4f43d8ba9719503c5935a099ccb2e74a9b207cf75296edf4c78e67fab6b7767184c1f24f8def9539f1bd965c4865effae04dd1c24de14d5b9c0e676beabb82d90d24e03670fea261fd9304f56e22c5dfd5e8578251e64531866f6a2b580f5ccb1c51aaab396128c0f11450e8d4cd6cd94c9e0ed71d86e9fe7c06bd6106f8eb729a12e289be4ead18be12dabc2c32f726b94164d7667fa83393e523f6c3799d8cb48dc28e1a874f4739431e5de5271085b3b84cc7781555e12a88dde55647b7dba4263939d6cbe32beb35de70603f313180a4da6185d131ea271119623f66bba89f1";

/// GOLDEN: the MLS **Welcome** body — the `Welcome` extracted from the same add's
/// Welcome `MlsMessage`, hex-encoded. Round-trips via `Welcome`.
const GOLDEN_MLS_WELCOME_HEX: &str = "00014098206355b0c46bf3322a064b18e11eb62005b9e6e2a4d9a4c7a9adb6850d380eab782008c7d4b431d618156a1e4e4ef617f67e60c2e635f46abf65b3e3988b4a78645e40544b7e3fa9f5f7f3319e23c92dbf23fbf3c37b9539ee56f02c622bc9e1d7a7e569067f11d00a03a655b2aff4384f9f56b9a3d122d43969962505f0abd3fe8c32c86d14541d07537cfa082602d1f895dab995c121aa433df406003bde54c0ad439829c9c3aa3e0b330ba2c353559efff6fe501679ac2320e2e9eec981ce5287a0a3fca8be2ea89b936cc388a64234df814d71d30d48cf28917f8e557d419c6b027bfa99dca8cfab457828e18ee824fc01f21ffae7f7b5e30cf42b350577b981b0247c09a95f18d730d3a132f0302e13134af1a20bc8bf85adf24f1b415984599589b90707b765ca58d533d5df50208da82b7679bc019baaaf95e389cc7a8f0116e1b0749e263b95e57a785f1ca48463d9cab7dc1dd26436f41b29b29cb0b599d524c9c2eaaffecabe72d5b13682f8ecebd4308383382006675167ce8390e80ed12e73348f4ca8f5fde84f473f13a8671b9439c6bb4f04726f9d25e54ab6eb507ba4b4978d4c22642a1591cb0f14cb24aa0993310162037ea356cd54cbefa4014d7a676bcfc2a11287fa8d5d785ba82524f35ec2856b3556764b48b8c060bd1389c2cb66c27838933be8a22531abebd63349f33c77974ef83474cdd2e466f9efba268c829f429e8ca2ddb7ceccb9a268a1b7fad81fbb8d3c82d897b372bfc71735f032d3b07d9456b33fac775b1018f391a3b39886caa4988fd2184a9904847c12f327d8e362d0549b2c9c39bf0a39f72a4c33858e948a1a8828628193878776d0e0d299b8a2e88475a63e9496b395c0710b148911712ef17d5f6b75bf5084d55bd82d48571df7e0a158b997f654733ed7e7fc068608ced8fb4b3dc9102c6d82427a4a4a87711d8a89f5eb54fab8fc3c596225af07e139d22d677b980656be6c2de9651b88fe1ad689aeba304ae66d6d3d33a29618fbc341a6030275971f223440291fed5f619d7768e68f35eb32be2b8a11f5df39073d1a8b1c2337a09fe449ec59ad0267b8a112ca57dad3be9579a7a711887139a76ddfd397279cdcc34eeb54591e37961b75b8c5681069e3ae70b1d029f77890233cb3969a6e1177cfae59782ab6fb872e349235dea354a153df8e5526b93e592e0368c4ab757ba96332c69e7d8bcb4ff706a573834c656fc982632644e0df541fff2ddb23288006a36e291bd7ef269e6b4384889f23ec62a9f00a669d19f107018e862a05c5db8b0b1183d0a9a8c8fc5452c2d6f6691dc5e3f6fb7fe4a7532f018eeaab00f567234fb0fd9abfdcf21abf22555c9b15c6beae5407ef52ab14ff";

/// GOLDEN: a serialized MLS **`KeyPackage`** (bare wire bytes) for the joiner,
/// hex-encoded. Round-trips directly via `KeyPackageIn`.
const GOLDEN_KEY_PACKAGE_HEX: &str = "0001000120628e627c3dc03946d45c062be0a8fdf7617d04cb71fb2150b08cc300f94dd95520771f9f0de022b08d756c166fe89616824debc7f47e9e32890448e174a6dbbf1a20e3e14431dd3a00609e5bbb7d79104b010bdb16b52dea23483f417dcfac9eaea50001404293d9366469643a6468743a7a364d6b44657465726d696e69736d4b617446697874757265424242424242424242424242424242424242424242c0a72361637469766502000108000100020003004d02ff010002000101000000006a57cb39000000006ac6974923ff0120caa87cb8b359ebe1c29d3133eb6d06c6b5486a0c7db5bbd51145c98751cb1a6f4040e6d3ad0288d13d5bfcc7a3074b433fa1164be4e30691ed37596ee553cb9895dddef90b6505ff6e12e5ee51f7ba9ea7e797a0453e7000cd47a763095637e95f0b00404033520c2aa9f9cc4280705a9ca8a68f9dd5ccf6214300a6c7acf25f3aab20517d9fb0b1ec6c24771cfe269f4d2e856e3d0ea26d60e240ebc6c49ea0d747f37e00";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Lowercase hex without external deps (the KAT must build for wasm32, where
/// pulling `hex` transitively is avoidable). Uses a nibble lookup so it is
/// allocation-light and target-independent.
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decodes a lowercase hex string into bytes (the inverse of [`to_hex`]), for
/// loading a committed golden wire blob. Target-independent; panics on malformed
/// input (a golden constant is always well-formed).
fn from_hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex string has an even length");
    let nibble = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("non-hex digit in golden constant"),
        }
    };
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < b.len() {
        out.push((nibble(b[i]) << 4) | nibble(b[i + 1]));
        i += 2;
    }
    out
}

/// Builds a FIXED event sequence with fully-specified bytes, sequence, and
/// `prev_hash` (no clock reads, no RNG, no map iteration) and appends it through
/// the shared chain-validating append. The resulting leaf hashes and Merkle root
/// are deterministic across targets.
///
/// This mirrors the exact leaves the participant driver appends
/// (`ContextCreated`, `MemberJoined`, `MessageSent`), with committer-assigned
/// timestamps pinned to constants so each preimage is byte-stable. Each preimage
/// is the `MessagePack` encoding of the `Event` — every width-bearing field
/// (`u64` sequence/timestamp, `[u8; 32]` `prev_hash`) is encoded by `rmp_serde`
/// with an explicit `MessagePack` width, so no native `usize` reaches the hash.
fn build_fixed_event_log() -> EventLog {
    let mut log = EventLog::new(KAT_CONTEXT_ID.to_owned());

    let specs: [(EventType, &str, u64, &[u8]); 3] = [
        (EventType::ContextCreated, KAT_DID_A, KAT_TIMESTAMP, b""),
        (EventType::MemberJoined, KAT_DID_A, KAT_TIMESTAMP + 100, b""),
        (
            EventType::MessageSent,
            KAT_DID_B,
            KAT_TIMESTAMP + 200,
            b"deterministic payload",
        ),
    ];

    for (index, (event_type, actor, timestamp, payload)) in specs.into_iter().enumerate() {
        let sequence = u64::try_from(index).expect("index fits u64");
        let prev_hash = log.leaves().last().copied().unwrap_or([0u8; 32]);
        let event = Event {
            event_type,
            actor_did: DID::from(actor.to_owned()),
            timestamp,
            sequence,
            payload: EventPayload {
                data: payload.to_vec(),
            },
            prev_hash,
            signature: vec![],
        };
        append_unsigned_event(&mut log, &event).expect("fixed event chains onto the log");
    }
    log
}

// ---------------------------------------------------------------------------
// The golden-vector assertion body (called from BOTH targets)
// ---------------------------------------------------------------------------

/// Runs every golden-vector assertion. Called from a native `#[test]` and a
/// wasm32 `#[wasm_bindgen_test]` so the SAME committed constants are checked on
/// both targets — native proves determinism-vs-golden, wasm proves byte-equality
/// across targets (agreement is transitive through the shared golden).
fn assert_deterministic_golden_vectors() {
    // (1) Event-log leaf hashes + Merkle root over the fixed sequence.
    let log = build_fixed_event_log();

    let leaves = log.leaves();
    assert_eq!(leaves.len(), 3, "fixed sequence has exactly three leaves");
    for (i, (leaf, golden)) in leaves.iter().zip(GOLDEN_LEAF_HASHES_HEX).enumerate() {
        assert_eq!(
            to_hex(leaf),
            golden,
            "leaf {i} hash diverged from the golden vector (cross-target or \
             preimage change)"
        );
    }

    // The per-event leaf-hash helper must agree with the stored leaves (proving
    // `leaf_hash` and the append path compute the identical preimage — the root
    // alone would mask a compensating pair of leaf bugs).
    let recomputed: Vec<[u8; 32]> = log
        .events()
        .iter()
        .map(|e| leaf_hash(e).expect("leaf hash"))
        .collect();
    assert_eq!(
        recomputed,
        leaves.to_vec(),
        "leaf_hash() must match the appended leaves"
    );

    let merkle_root = root(&log);
    assert_eq!(
        to_hex(&merkle_root),
        GOLDEN_MERKLE_ROOT_HEX,
        "Merkle root diverged from the golden vector"
    );
    assert_eq!(event_count(&log), 3, "fixed log has three events");

    // (2) Convergent-timestamp AAD over the fixed timestamp (ADR-057 T3).
    let aad = encode_convergent_timestamp_aad(KAT_TIMESTAMP);
    assert_eq!(aad.len(), 13, "the AAD blob is exactly 13 bytes");
    assert_eq!(
        to_hex(&aad),
        GOLDEN_CONVERGENT_TIMESTAMP_AAD_HEX,
        "convergent-timestamp AAD diverged from the golden vector"
    );

    // (3) Credential encoding from a fixed DID + fixed key.
    let credential = ScpCredential::new(KAT_DID_A.to_owned(), None, SigningKeyId::Active)
        .expect("fixed credential constructs");
    let credential_bytes = credential.to_bytes().expect("credential encodes");
    assert_eq!(
        to_hex(&credential_bytes),
        GOLDEN_CREDENTIAL_HEX,
        "credential encoding diverged from the golden vector"
    );
    // And it round-trips (decode → identical struct) — the encoding is stable
    // both directions.
    assert_eq!(
        ScpCredential::from_bytes(&credential_bytes).expect("decodes"),
        credential,
        "credential round-trips through its deterministic encoding"
    );

    // (4) AEAD sender-layer roundtrip for a FIXED key + message. The ciphertext
    // bytes are NOT pinned (the GCM nonce is random per the ADR determinism
    // boundary); the ROUNDTRIP is the deterministic property.
    let key = SenderKey::from_bytes(KAT_SENDER_KEY);
    let message = b"fixed message for the AEAD roundtrip KAT";
    let epoch = 1u64;
    let sequence = 7u64;
    let ciphertext =
        encrypt_sender_layer(&key, message, KAT_CONTEXT_ID, KAT_DID_A, epoch, sequence)
            .expect("AEAD encrypt");
    let recovered = decrypt_sender_layer(
        &key,
        &ciphertext,
        KAT_CONTEXT_ID,
        KAT_DID_A,
        epoch,
        sequence,
    )
    .expect("AEAD decrypt");
    assert_eq!(
        recovered.as_slice(),
        message,
        "AEAD roundtrip recovers the fixed message (pipeline is deterministic \
         even though the nonce/ciphertext are not)"
    );
    // Wrong AAD (different sequence) must fail — the binding is stable.
    assert!(
        decrypt_sender_layer(
            &key,
            &ciphertext,
            KAT_CONTEXT_ID,
            KAT_DID_A,
            epoch,
            sequence + 1
        )
        .is_err(),
        "AAD binding is deterministic: a wrong sequence fails the roundtrip"
    );
}

// ---------------------------------------------------------------------------
// Native + wasm entry points for the golden vectors
// ---------------------------------------------------------------------------

/// Golden-vector determinism KAT. Runs natively (proving determinism vs. the
/// committed vectors) and under `wasm-pack test --node` (proving byte-equality
/// across targets — ADR-057 Prerequisite 5).
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn deterministic_artifacts_match_golden_vectors() {
    assert_deterministic_golden_vectors();
}

// ---------------------------------------------------------------------------
// MLS wire-encoding round-trips (ADR-057 Prerequisite 5 (i)/(iii))
// ---------------------------------------------------------------------------

/// Asserts that deserializing then re-serializing each committed golden MLS wire
/// blob reproduces the golden bytes byte-for-byte, through openmls's canonical TLS
/// codec. Called from BOTH targets: because the codec is canonical (one encoding
/// per value), the re-serialization is deterministic, so `native == golden` and
/// `wasm == golden` together prove the encoder/decoder does not diverge across
/// targets on `usize` width or ordering (ADR-057 Prerequisite 5 (i)/(iii)).
///
/// This is an *encoding* determinism test, not a construction comparison: the
/// golden blobs were captured once from a real add-member / key-package flow; their
/// random init/HPKE keys and signatures are never re-derived here — only re-encoded.
fn assert_mls_wire_encoding_roundtrips() {
    // The Commit is the `PrivateMessage` MLS body extracted from the add-Commit
    // MlsMessage (the encrypted-commit content — the length-prefixed, nested TLS
    // structure where a cross-target `usize`-width or ordering bug would surface).
    // `PrivateMessageIn` derives both TLS directions, so it round-trips ungated.
    {
        let golden = from_hex(GOLDEN_MLS_COMMIT_HEX);
        let pm = PrivateMessageIn::tls_deserialize(&mut &golden[..])
            .unwrap_or_else(|e| panic!("Commit golden blob deserializes: {e}"));
        let reserialized = pm
            .tls_serialize_detached()
            .unwrap_or_else(|e| panic!("Commit re-serializes: {e}"));
        assert_eq!(
            to_hex(&reserialized),
            GOLDEN_MLS_COMMIT_HEX,
            "Commit (PrivateMessage) wire encoding is not target-deterministic \
             (openmls TLS codec diverged from the golden — a width/ordering bug)"
        );
    }

    // The Welcome is the `Welcome` MLS body extracted from the add's Welcome
    // MlsMessage. `Welcome` derives both TLS directions, so it round-trips ungated.
    {
        let golden = from_hex(GOLDEN_MLS_WELCOME_HEX);
        let welcome = Welcome::tls_deserialize(&mut &golden[..])
            .unwrap_or_else(|e| panic!("Welcome golden blob deserializes: {e}"));
        let reserialized = welcome
            .tls_serialize_detached()
            .unwrap_or_else(|e| panic!("Welcome re-serializes: {e}"));
        assert_eq!(
            to_hex(&reserialized),
            GOLDEN_MLS_WELCOME_HEX,
            "Welcome wire encoding is not target-deterministic (openmls TLS codec \
             diverged from the golden — a width/ordering bug)"
        );
    }

    // The KeyPackage is a bare `KeyPackage` wire blob; `KeyPackageIn` round-trips
    // it directly (both TLS directions).
    {
        let golden = from_hex(GOLDEN_KEY_PACKAGE_HEX);
        let kp_in = KeyPackageIn::tls_deserialize(&mut &golden[..])
            .unwrap_or_else(|e| panic!("KeyPackage golden blob deserializes: {e}"));
        let reserialized = kp_in
            .tls_serialize_detached()
            .unwrap_or_else(|e| panic!("KeyPackage re-serializes: {e}"));
        assert_eq!(
            to_hex(&reserialized),
            GOLDEN_KEY_PACKAGE_HEX,
            "KeyPackage wire encoding is not target-deterministic (openmls TLS \
             codec diverged from the golden — a width/ordering bug)"
        );
    }
}

/// MLS wire-encoding determinism KAT (Commit / Welcome / `KeyPackage`). Runs
/// natively and under `wasm-pack test --node`, both asserting the round-trip
/// re-encoding equals the SAME committed golden (ADR-057 Prerequisite 5 (i)/(iii)).
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn mls_wire_encoding_is_target_deterministic() {
    assert_mls_wire_encoding_roundtrips();
}
