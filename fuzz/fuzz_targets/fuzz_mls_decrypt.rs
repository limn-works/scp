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
//! No release-mode panic has been *found* on the openmls 0.8.1 decrypt path
//! (this target is that standing evidence, pinned to openmls 0.8.1; a version
//! bump could introduce one, caught by the nightly fuzz job). The one known
//! debug-build panic is an openmls `debug_assert!` (`"Ciphertext decryption
//! failed"`, `openmls-0.8.1/src/framing/private_message_in.rs`), **compiled out
//! of `--release` builds**. This target drives arbitrary and tampered-AEAD
//! ciphertext through the browser/relay-reachable `scp-mls` decrypt entry points
//! and asserts they never panic. libFuzzer treats any panic/abort as a crash,
//! so "no panic" is the invariant (I1) — returning `Ok` or `Err` are both
//! acceptable there.
//!
//! Scope is the **untrusted-relay** threat model: a relay cannot forge an
//! AEAD-passing frame, so the deeper StagedCommit / tree-KEM (HPKE path-secret)
//! panic surface — reachable only *after* outer AEAD succeeds, i.e. only by a
//! malicious authenticated **member** (insider) — is a distinct threat model,
//! out of scope here.
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
//! # Strategy — a FRESH generation-0 receiver per decrypt call
//!
//! A real 2-member MLS group (Alice → Bob) is built once per fuzzer process
//! (thread-local; libFuzzer runs single-threaded, and a crash reproducer rebuilds
//! fresh — the panic property is independent of the specific group secrets). Bob's
//! *pristine generation-0* group state is snapshotted once
//! (`ScpMlsGroup::serialize_state`); every decrypt call restores a FRESH gen-0
//! receiver from that snapshot (`ScpMlsGroup::deserialize_state`) before running.
//!
//! Fresh-receiver-per-call is load-bearing, not incidental. openmls 0.8.1 advances
//! Bob's secret-tree receive ratchet (consuming generation 0) DURING
//! `process_message`, BEFORE the content-AEAD open, on `&mut self` state, and does
//! NOT roll it back on AEAD failure (openmls 0.8.1 `group/mls_group/processing.rs`,
//! `framing/validation.rs`, `framing/private_message_in.rs`,
//! `tree/sender_ratchet.rs`). So a *shared* receiver would reach the content-AEAD
//! path (the openmls `debug_assert!` this target stresses) at most ONCE per
//! process: after the first genuinely-tampered ciphertext consumes gen-0, every
//! later one is rejected at `secret_for_decryption` with a secret-reuse error
//! BEFORE content-AEAD. Restoring a fresh gen-0 receiver per call makes the
//! content-AEAD open reachable on EVERY input. (Snapshot-restore is cheap — an
//! `rmp_serde` load of a small 2-member group dump — so this is viable for a real
//! campaign; a per-input full group REBUILD would not be.)
//!
//! Each fuzz input is fed to every browser/relay-reachable decrypt entry point two
//! ways, each call against its own fresh gen-0 receiver:
//!   1. straight in as ciphertext bytes (garbage / malformed-framing path);
//!   2. XOR-ed over the tail of a genuinely valid ciphertext (guaranteed to change
//!      at least one byte — an empty/all-zero `data` would otherwise leave a
//!      PRISTINE valid ciphertext that decrypts `Ok`; the guard flips the last byte
//!      when the XOR was a no-op). The tampered tail leaves the frame header — and
//!      thus sender-data, which samples only the first 32 bytes
//!      (`openmls-0.8.1/src/schedule/mod.rs`) — intact, so openmls passes
//!      sender-data and reaches the content-AEAD open, the path that trips the
//!      debug-only `debug_assert!`. Every tampered decrypt MUST return `Err`
//!      (asserted): that is the no-forgery invariant AND the proof the content-AEAD
//!      boundary is genuinely reached on every input (not short-circuited by
//!      secret-reuse or a pristine-replay `Ok`).

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

/// Per-process fuzz state: a pristine gen-0 snapshot of the receiver plus one
/// valid ciphertext used as the base for the guaranteed-tamper (Path-2) mutation.
struct FuzzState {
    /// Serialized pristine generation-0 state of Bob's group. Restored into a
    /// FRESH receiver before every decrypt call (openmls advances the receive
    /// ratchet before content-AEAD and does not roll back — see module docs).
    receiver_snapshot: Vec<u8>,
    /// A genuinely valid application ciphertext from Alice, decryptable by a fresh
    /// gen-0 receiver (the base for the guaranteed-tamper Path-2 mutation).
    valid_ciphertext: Vec<u8>,
}

/// Builds a real Alice→Bob MLS group over the production `scp-mls` API, snapshots
/// Bob's pristine gen-0 state, and captures one valid ciphertext. Uses production
/// DIDs (`did:dht:z…`), the real `SystemClock`, and no `testing` feature — this
/// exercises the shipped path.
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

    // Snapshot Bob BEFORE he decrypts anything — this is the pristine generation-0
    // state restored fresh before every decrypt call.
    let receiver_snapshot = bob.serialize_state().ok()?;

    // One valid application ciphertext a fresh gen-0 Bob can decrypt, to be
    // tampered by the fuzz body.
    let ct_msg = encrypt(&mut alice, b"fuzz-valid-template").ok()?;
    let valid_ciphertext = serialize_ciphertext(&ct_msg).ok()?;

    // Positive control (runs ONCE): a fresh gen-0 receiver must decrypt the
    // UNtampered valid ciphertext successfully. This proves the snapshot restores a
    // working gen-0 receiver that reaches AND passes the content-AEAD open — i.e.
    // the content-AEAD path the tampered inputs exercise is genuinely reachable. A
    // failure here means the harness is broken (not a crypto finding), so fail
    // loudly rather than silently fuzzing a vacuous target.
    let mut control = ScpMlsGroup::deserialize_state(&receiver_snapshot).ok()?;
    assert!(
        decrypt(&mut control, &valid_ciphertext).is_ok(),
        "fuzz harness broken: a fresh gen-0 receiver failed to decrypt the untampered \
         valid ciphertext — the content-AEAD path would be unreachable"
    );

    Some(FuzzState {
        receiver_snapshot,
        valid_ciphertext,
    })
}

thread_local! {
    static STATE: RefCell<Option<FuzzState>> = const { RefCell::new(None) };
}

/// Restores a FRESH generation-0 receiver from the pristine snapshot. `None` only
/// if the snapshot fails to deserialize (never expected — it round-tripped in
/// `build_state`'s positive control).
fn fresh_receiver(snapshot: &[u8]) -> Option<ScpMlsGroup> {
    ScpMlsGroup::deserialize_state(snapshot).ok()
}

fuzz_target!(|data: &[u8]| {
    STATE.with(|cell| {
        let mut guard = cell.borrow_mut();
        if guard.is_none() {
            *guard = build_state();
        }
        let Some(state) = guard.as_ref() else {
            // Group construction failed (e.g. transient RNG); nothing to fuzz.
            return;
        };
        let snap = &state.receiver_snapshot;

        // --- Path 1: arbitrary bytes straight in as ciphertext ---
        // Malformed-framing / deserialize-rejection robustness. Every
        // browser/relay-reachable entry point, each on its own fresh gen-0
        // receiver. `Ok`/`Err` both fine (a random `data` that happens to be a
        // valid frame may decrypt Ok); the invariant is only "no panic".
        //
        // The fourth decrypt entry point, `encrypt::decrypt_with_sender_key`, is a
        // NATIVE-path fn (driven by `scp-runtime`, not the browser/relay surface),
        // so it is deliberately out of this target's threat model. It shares the
        // identical `process_message` + `catch_unwind` panic surface as the three
        // below, so the panic-free property is evidenced for it transitively.
        if let Some(mut g) = fresh_receiver(snap) {
            let _ = decrypt(&mut g, data);
        }
        if let Some(mut g) = fresh_receiver(snap) {
            let _ = decrypt_with_sender_did(&mut g, data, &SystemClock);
        }
        if let Some(mut g) = fresh_receiver(snap) {
            let _ = decrypt_with_membership_changes(&mut g, data, &SystemClock);
        }

        // --- Path 2: tamper the TAIL of a valid ciphertext ---
        // Leaves the frame header (and thus sender-data) intact so openmls reaches
        // the content-AEAD open. Guaranteed to change ≥1 byte.
        let mut tampered = state.valid_ciphertext.clone();
        let n = data.len().min(tampered.len());
        let start = tampered.len() - n;
        for (b, m) in tampered[start..].iter_mut().zip(data.iter()) {
            *b ^= *m;
        }
        // An empty / all-zero `data` XORs to a no-op, leaving a PRISTINE valid
        // ciphertext that would decrypt Ok. If the XOR changed nothing, flip the
        // last byte. An MLS PrivateMessage is never empty, so `last_mut()` is
        // always `Some`.
        if tampered == state.valid_ciphertext {
            if let Some(last) = tampered.last_mut() {
                *last ^= 0xff;
            }
        }

        // Every tampered decrypt MUST reject — this is the no-forgery invariant
        // AND the proof the content-AEAD boundary is reached on every input (a
        // fresh gen-0 receiver each time, so never short-circuited by secret-reuse;
        // a genuine tamper, so never a pristine-replay `Ok`). An `Ok` here would be
        // a real cryptographic finding (AEAD forgery), surfaced as a crash.
        if let Some(mut g) = fresh_receiver(snap) {
            assert!(
                decrypt(&mut g, &tampered).is_err(),
                "tampered ciphertext decrypted Ok via decrypt (AEAD forgery?)"
            );
        }
        if let Some(mut g) = fresh_receiver(snap) {
            assert!(
                decrypt_with_sender_did(&mut g, &tampered, &SystemClock).is_err(),
                "tampered ciphertext decrypted Ok via decrypt_with_sender_did (AEAD forgery?)"
            );
        }
        if let Some(mut g) = fresh_receiver(snap) {
            assert!(
                decrypt_with_membership_changes(&mut g, &tampered, &SystemClock).is_err(),
                "tampered ciphertext decrypted Ok via decrypt_with_membership_changes (AEAD forgery?)"
            );
        }
    });
});
