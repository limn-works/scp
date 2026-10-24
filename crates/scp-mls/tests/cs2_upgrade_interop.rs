//! Group state and messages that an earlier `openmls` build persisted and sent
//! on ciphersuite 2 (`MLS_128_DHKEMP256_AES128GCM_SHA256_P256`, 09 §9.5) still
//! work under the current build.
//!
//! `tests/fixtures/cs2_upgrade/` holds what `capture_cs2_upgrade_fixtures`
//! wrote on `openmls` 0.9.0 with `RustCrypto` 0.13:
//!
//! - `a_state.bin`, `b_state.bin`: A's and B's `ScpMlsGroup::serialize_state`
//!   blobs, A having created the group and added B and then C, and B having
//!   merged the Commit that adds C;
//! - `c_pending.bin`: C's `serialize_pending_join` blob from before the
//!   Welcome;
//! - `welcome_c.bin`, `commit_c.bin`: the Welcome and the Commit that add C;
//! - `from_a.bin`: an application message A sent after adding C, which no
//!   member processed before the capture;
//! - `capture_secs.txt`: the Unix time of the capture.
//!
//! B's state is captured after B merged `commit_c.bin`. A member processing
//! that Commit runs openmls's own `Lifetime::validate` on C's `KeyPackage`
//! against the wall clock (`lifetime.rs`, the receive side), and that
//! `KeyPackage` expires 84 days after the capture, so a test that merged it
//! would start failing on a date and not on a code change. The test instead
//! decodes the Commit and checks that it re-encodes to the same bytes.
//! C's Welcome join checks only C's own leaf against the clock the caller
//! injects, so the test passes the capture time there.

use std::path::PathBuf;

use openmls::prelude::{Ciphersuite, KeyPackageIn};
use scp_clock::{Clock as _, SystemClock, TestClock};
use scp_crypto::p256::testing::uncompressed_point_for;
use scp_did::SigningKeyId;
use scp_mls::encrypt::{decrypt, decrypt_with_sender_did, encrypt, serialize_ciphertext};
use scp_mls::group::join_group_from_bytes;
use scp_mls::ratchet::{propose_update, serialize_mls_message};
use scp_mls::wire::parse_mls_message_in;
use scp_mls::{
    DecryptedContent, ScpCredential, ScpMlsGroup, add_member, create_group, generate_key_package,
    join_group, restore_pending_join, serialize_pending_join,
};
use tls_codec::Serialize as _;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const A: &str = "did:dht:zCs2UpgradeAliceAAAAAAAAAAAAAAAAAAAAAAA";
const B: &str = "did:dht:zCs2UpgradeBobBBBBBBBBBBBBBBBBBBBBBBBBB";
const C: &str = "did:dht:zCs2UpgradeCarolCCCCCCCCCCCCCCCCCCCCCCC";
const D: &str = "did:dht:zCs2UpgradeDaveDDDDDDDDDDDDDDDDDDDDDDDD";
const C_CONTEXT: &str = "ctx-cs2-upgrade";
const FROM_A: &[u8] = b"from A, sent on openmls 0.9.0";

const A_STATE: &[u8] = include_bytes!("fixtures/cs2_upgrade/a_state.bin");
const B_STATE: &[u8] = include_bytes!("fixtures/cs2_upgrade/b_state.bin");
const C_PENDING: &[u8] = include_bytes!("fixtures/cs2_upgrade/c_pending.bin");
const WELCOME_C: &[u8] = include_bytes!("fixtures/cs2_upgrade/welcome_c.bin");
const COMMIT_C: &[u8] = include_bytes!("fixtures/cs2_upgrade/commit_c.bin");
const FROM_A_CT: &[u8] = include_bytes!("fixtures/cs2_upgrade/from_a.bin");
const CAPTURE_SECS: &str = include_str!("fixtures/cs2_upgrade/capture_secs.txt");

fn credential(did: &str) -> TestResult<ScpCredential> {
    Ok(ScpCredential::new(
        did.to_owned(),
        None,
        SigningKeyId::Active,
    )?)
}

fn key_package(
    did: &str,
) -> TestResult<(
    KeyPackageIn,
    scp_mls::SignatureKeyPair,
    scp_mls::InMemoryMlsProvider,
)> {
    let (bundle, signer, provider) = generate_key_package(
        &credential(did)?,
        &uncompressed_point_for(did),
        &SystemClock,
    )?;
    Ok((bundle.key_package().clone().into(), signer, provider))
}

fn merge_commit(group: &mut ScpMlsGroup, commit_bytes: &[u8]) -> TestResult {
    match decrypt_with_sender_did(group, commit_bytes)? {
        DecryptedContent::Commit { .. } => Ok(()),
        other => Err(format!("expected a Commit, got {other:?}").into()),
    }
}

fn send(group: &mut ScpMlsGroup, text: &[u8]) -> TestResult<Vec<u8>> {
    Ok(serialize_ciphertext(&encrypt(group, text)?)?)
}

/// Sends one message from each group and checks that every other group
/// decrypts it.
fn exchange(groups: &mut [&mut ScpMlsGroup], round: &str) -> TestResult {
    for sender in 0..groups.len() {
        let text = format!("{round}: from member {sender}").into_bytes();
        let ciphertext = send(groups[sender], &text)?;
        for (receiver, group) in groups.iter_mut().enumerate() {
            if receiver != sender {
                assert_eq!(
                    decrypt(group, &ciphertext)?,
                    text,
                    "{round}: {sender} -> {receiver}"
                );
            }
        }
    }
    Ok(())
}

/// Each group in turn commits a self-Update, and every other group merges it.
fn self_update_each(groups: &mut [&mut ScpMlsGroup]) -> TestResult {
    for committer in 0..groups.len() {
        let update = propose_update(groups[committer], &SystemClock)?;
        for (receiver, group) in groups.iter_mut().enumerate() {
            if receiver != committer {
                merge_commit(group, &update.commit_bytes)?;
            }
        }
    }
    let epoch = groups[0].epoch()?;
    for group in groups.iter() {
        assert_eq!(group.epoch()?, epoch, "every member is on the same epoch");
    }
    Ok(())
}

fn assert_cs2(group: &ScpMlsGroup) -> TestResult {
    assert_eq!(
        group.inner()?.ciphersuite(),
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
    );
    Ok(())
}

#[test]
fn cs2_state_and_messages_from_openmls_0_9_0_interoperate() -> TestResult {
    let capture_secs: u64 = CAPTURE_SECS.trim().parse()?;

    let mut a = ScpMlsGroup::deserialize_state(A_STATE)?;
    let mut b = ScpMlsGroup::deserialize_state(B_STATE)?;
    assert_eq!(a.epoch()?, b.epoch()?, "A and B were captured on one epoch");

    // B decrypts the message A sent before the capture.
    assert_eq!(decrypt(&mut b, FROM_A_CT)?, FROM_A);

    // C restores its pending join and joins from the captured Welcome. Only
    // C's own leaf is checked against a clock, the one passed here.
    let (c_provider, c_signer, owner, context) = restore_pending_join(C_PENDING)?;
    assert_eq!((owner.as_str(), context.as_str()), (C, C_CONTEXT));
    let mut c = join_group_from_bytes(
        WELCOME_C,
        c_provider,
        c_signer,
        &TestClock::new(capture_secs),
    )?;
    assert_eq!(c.epoch()?, a.epoch()?, "C joins on A's epoch");
    assert_eq!(decrypt(&mut c, FROM_A_CT)?, FROM_A);

    // The Commit that added C decodes and re-encodes to the captured bytes.
    let commit = parse_mls_message_in(COMMIT_C)?;
    assert_eq!(commit.tls_serialize_detached()?, COMMIT_C);

    for group in [&a, &b, &c] {
        assert_cs2(group)?;
        assert_eq!(group.members()?.len(), 3);
    }

    exchange(&mut [&mut a, &mut b, &mut c], "restored")?;
    self_update_each(&mut [&mut a, &mut b, &mut c])?;
    exchange(&mut [&mut a, &mut b, &mut c], "after self-updates")?;

    // Restored A adds a KeyPackage built by the current build.
    let (d_kp, d_signer, d_provider) = key_package(D)?;
    let add_d = add_member(&mut a, d_kp, &SystemClock)?;
    let commit_d = serialize_mls_message(&add_d.commit)?;
    merge_commit(&mut b, &commit_d)?;
    merge_commit(&mut c, &commit_d)?;
    let mut d = join_group(&add_d.welcome, d_provider, d_signer, &SystemClock)?;
    assert_eq!(d.members()?.len(), 4);
    exchange(&mut [&mut a, &mut b, &mut c, &mut d], "after adding D")?;
    Ok(())
}

/// Writes the fixtures `cs2_state_and_messages_from_openmls_0_9_0_interoperate`
/// reads. They were captured once, on `openmls` 0.9.0; running this on a
/// later build would replace the old build's output with the new build's, and
/// the test would then prove nothing about an upgrade. Run it only to capture
/// from the oldest build the fixtures must keep supporting:
/// `cargo test -p scp-mls --test cs2_upgrade_interop -- --ignored capture`.
#[test]
#[ignore = "writes the committed fixtures; run by hand on the build being captured"]
fn capture_cs2_upgrade_fixtures() -> TestResult {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cs2_upgrade");
    std::fs::create_dir_all(&dir)?;
    let capture_secs = SystemClock.now_secs();

    let mut a = create_group(&credential(A)?, &uncompressed_point_for(A), &SystemClock)?;
    let (b_kp, b_signer, b_provider) = key_package(B)?;
    let add_b = add_member(&mut a, b_kp, &SystemClock)?;
    let mut b = join_group(&add_b.welcome, b_provider, b_signer, &SystemClock)?;

    let (c_kp, c_signer, c_provider) = key_package(C)?;
    let c_pending = serialize_pending_join(&c_provider, &c_signer, C, C_CONTEXT)?;
    let add_c = add_member(&mut a, c_kp, &SystemClock)?;
    let commit_c = serialize_mls_message(&add_c.commit)?;
    let welcome_c = serialize_mls_message(&add_c.welcome)?;
    merge_commit(&mut b, &commit_c)?;

    let from_a = send(&mut a, FROM_A)?;
    let capture_time = format!("{capture_secs}\n");

    let files: [(&str, &[u8]); 7] = [
        ("a_state.bin", &a.serialize_state()?),
        ("b_state.bin", &b.serialize_state()?),
        ("c_pending.bin", &c_pending),
        ("welcome_c.bin", &welcome_c),
        ("commit_c.bin", &commit_c),
        ("from_a.bin", &from_a),
        ("capture_secs.txt", capture_time.as_bytes()),
    ];
    for (name, bytes) in files {
        std::fs::write(dir.join(name), bytes)?;
    }
    Ok(())
}
