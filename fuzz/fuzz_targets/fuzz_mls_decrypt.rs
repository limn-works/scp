#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! MLS decrypt-path panic-safety fuzz target (Tier 4 — ADR-057 §Prereq-4, #1444).
//!
//! # What this proves
//!
//! The in-browser SCP client (ADR-057) decrypts ciphertext delivered by an
//! **untrusted relay**. The untrusted-relay guarantee is that a tampered or
//! malformed ciphertext must surface a **typed** `MlsError::DecryptionFailed`
//! (→ browser `[SCP-CRYPTO-4010]`), never abort the tab.
//!
//! The only attacker-reachable panic on the openmls 0.8.1 decrypt path is a
//! `debug_assert!` (`"Ciphertext decryption failed"`,
//! `openmls-0.8.1/src/framing/private_message_in.rs`), which is **compiled out
//! of `--release` builds**. This target drives arbitrary and tampered-AEAD
//! ciphertext through the `scp-mls` decrypt entry points and asserts they never
//! panic. libFuzzer treats any panic/abort as a crash, so "no panic" is the
//! invariant (I1) — returning `Ok` or `Err` are both acceptable.
//!
//! # CRITICAL: run with `-O` (debug-assertions OFF)
//!
//! This target validates the SHIPPED RELEASE path. It MUST be built with
//! debug-assertions OFF, i.e. `cargo +nightly fuzz run fuzz_mls_decrypt -O …`.
//! Without `-O`, cargo-fuzz injects `-Cdebug-assertions`, openmls's
//! `debug_assert!` fires on every tampered input, and the target reports a
//! false crash on the very first tampered ciphertext. `[profile.release]
//! debug-assertions = false` in `fuzz/Cargo.toml` keeps the profile consistent;
//! `-O` is the operative switch. See `.github/workflows/fuzz.yml`
//! (`fuzz-mls-decrypt` job).
//!
//! # Strategy
//!
//! A real 2-member MLS group (Alice → Bob) is built once per fuzzer process
//! (thread-local; libFuzzer runs single-threaded, and a crash reproducer
//! rebuilds fresh — the panic property is independent of the specific group
//! secrets). Each fuzz input is fed to every decrypt entry point two ways:
//!   1. straight in as ciphertext bytes (garbage / malformed-framing path);
//!   2. XOR-ed over the tail of a genuinely valid ciphertext, so openmls parses
//!      the frame and reaches AEAD-tag verification (the tampered-AEAD path that
//!      trips the debug_assert in a debug build).
//!
//! Decrypting arbitrary or tampered bytes never advances Bob's ratchet
//! (`process_message` is atomic and rejects before merging), so reusing the
//! group across inputs is sound.

use libfuzzer_sys::fuzz_target;
use scp_clock::SystemClock;
use scp_did::SigningKeyId;
use scp_mls::ScpMlsGroup;
use scp_mls::credential::ScpCredential;
use scp_mls::encrypt::{
    decrypt, decrypt_with_membership_changes, decrypt_with_sender_did, encrypt,
    serialize_ciphertext,
};
use scp_mls::group::{add_member, create_group, generate_key_package, join_group};
use std::cell::RefCell;

/// Per-process fuzz state: the receiving group plus one valid ciphertext used as
/// the base for the tampered-AEAD path.
struct FuzzState {
    /// Bob's group — the receiver whose decrypt path is under test.
    receiver: ScpMlsGroup,
    /// A genuinely valid application ciphertext from Alice at the joined epoch.
    valid_ciphertext: Vec<u8>,
}

/// Builds a real Alice→Bob MLS group over the production `scp-mls` API and
/// captures one valid ciphertext. Uses production DIDs (`did:dht:z…`), the real
/// `SystemClock`, and no `testing` feature — this exercises the shipped path.
fn build_state() -> Option<FuzzState> {
    let alice_cred = ScpCredential::new(
        "did:dht:z6MkfuzzAlice".to_owned(),
        None,
        SigningKeyId::Active,
    )
    .ok()?;
    let mut alice = create_group(&alice_cred, &SystemClock).ok()?;

    let bob_cred =
        ScpCredential::new("did:dht:z6MkfuzzBob".to_owned(), None, SigningKeyId::Active).ok()?;
    let (bob_bundle, bob_signer, bob_provider) =
        generate_key_package(&bob_cred, &SystemClock).ok()?;

    // `.into()` infers `KeyPackageIn` from `add_member`'s signature — no direct
    // openmls dependency needed in the fuzz crate.
    let add = add_member(
        &mut alice,
        bob_bundle.key_package().clone().into(),
        &SystemClock,
    )
    .ok()?;
    let bob = join_group(&add.welcome, bob_provider, bob_signer).ok()?;

    // One valid application ciphertext at the joined epoch, to be tampered by the
    // fuzz body. We do NOT feed it unmutated to `bob` here.
    let ct_msg = encrypt(&mut alice, b"fuzz-valid-template").ok()?;
    let valid_ciphertext = serialize_ciphertext(&ct_msg).ok()?;

    Some(FuzzState {
        receiver: bob,
        valid_ciphertext,
    })
}

thread_local! {
    static STATE: RefCell<Option<FuzzState>> = const { RefCell::new(None) };
}

/// Feeds `ciphertext` to every attacker-reachable decrypt entry point. The
/// invariant is implicit: any panic/abort is a libFuzzer crash. `Ok`/`Err` are
/// both fine.
fn drive_decrypt(receiver: &mut ScpMlsGroup, ciphertext: &[u8]) {
    let _ = decrypt(receiver, ciphertext);
    let _ = decrypt_with_sender_did(receiver, ciphertext, &SystemClock);
    let _ = decrypt_with_membership_changes(receiver, ciphertext, &SystemClock);
}

fuzz_target!(|data: &[u8]| {
    STATE.with(|cell| {
        let mut guard = cell.borrow_mut();
        if guard.is_none() {
            *guard = build_state();
        }
        let Some(state) = guard.as_mut() else {
            // Group construction failed (e.g. transient RNG); nothing to fuzz.
            return;
        };

        // 1. Arbitrary bytes straight in as ciphertext — malformed-framing /
        //    deserialize-rejection robustness.
        drive_decrypt(&mut state.receiver, data);

        // 2. Tamper the TAIL of a valid ciphertext (AEAD tag + body), leaving the
        //    MLS frame header intact so openmls reaches AEAD verification — the
        //    path that trips the debug-only `debug_assert!`.
        let mut tampered = state.valid_ciphertext.clone();
        let n = data.len().min(tampered.len());
        let start = tampered.len() - n;
        for (b, m) in tampered[start..].iter_mut().zip(data.iter()) {
            *b ^= *m;
        }
        drive_decrypt(&mut state.receiver, &tampered);
    });
});
