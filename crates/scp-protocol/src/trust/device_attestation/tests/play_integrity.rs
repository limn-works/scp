//! Play Integrity checks 1 through 6 and the `PlayIntegrityVerifier` entry
//! parser (`09-security-model.md` §9.3.1), against spec 25 §25.35 Vector 87.
//!
//! Every failure runs through [`rejection_case`], which first reads the
//! unmutated fixture as `Verified`, then asserts the mutation's outcome and
//! the check that stopped the run, then reruns without that check and asserts
//! the outcome is gone. [`rejection_cases!`] generates each case's test and
//! the list the meta-test reads, so a case cannot be counted without
//! existing.
//!
//! The verifiers' key states come from key-event logs these tests sign under
//! §25.2's seed-to-scalar rule, resolved through `scp_kel::classify`, the only
//! constructor of a `ResolvedState`.

use std::time::{Duration, SystemTime};

use scp_crypto::p256::{P256SecretKey, SeedLabel, sign_prehash_rfc6979};
use scp_did::{
    CommitmentEntry, CustodyType, FixedCommitment, Identifier, KeyAlgorithm, KeyCondition,
    KeyEntry, KeyRole,
};
use scp_kel::{
    Continuation, EncodedPreimage, EventPreimage, InceptionFields, KeyStateFields,
    KeyStateSnapshot, OperatorProof, ResolutionInput, ResolutionVerdict, ResolvedState,
    SignatureForm, SignerGroup, SourceExhaustion, SourceRead, classify, encode_preimage,
    prerotation_commitment,
};
use sha2::{Digest, Sha256};

use super::{
    CheckFn, PLAY_INTEGRITY_CHECKS, PREIMAGE_LEN, PlayIntegrityCheck, PlayIntegrityFailure,
    PlayIntegrityRead, PreimageFields, Run, Stop, VERDICT_LEN, Verdict, VerifierEntryFault,
    parse_play_integrity_verifier_entry, read_play_integrity, run, verify_under_current_active,
};
use crate::trust::device_attestation::test_ca::{BoxResult, DAY, T0, TestResult};
use crate::trust::device_attestation::{
    DeviceAttestationPlatform, DeviceAttestationRejection as R, DeviceAttestationUnverifiable as U,
    device_attestation_binding_digest,
};
use crate::trust::sybil::{AcceptedAndroidPackage, ContextSybilPolicy};

// ── Spec 25 §25.35 Vector 87 ────────────────────────────────────────────────

/// Vector 87's integrity token.
const V87_TOKEN: &[u8] = b"SCP test vector integrity token";
/// Vector 87: SHA-256(token).
const V87_TOKEN_DIGEST: &str = "f3eedcddd35d370d042a0eb4e19b4b57a918a421aee1d96845c08c1fbdb9fe03";
/// Vector 87: SHA-256("com.example.scp").
const V87_PACKAGE_HASH: &str = "ee760b2de75a5f5a5e7eaa046eca0df481765a163b7088338eb7c54dee70daae";
/// Vector 86's `signing_cert_sha256`, which Vector 87 takes as `cert_digest`.
const V87_CERT_DIGEST: &str = "83599d12bbbeff09725d9d6ea2222acadb684c092b9f534dbaf10f973f6f5bd0";
/// Vector 84a's `D`.
const V84A_BINDING: &str = "66318c86819e17ad71427eabe4cf46590f16adb2bed9e43c9c7dc18ea060bbd3";
const V87_TOKEN_ISSUED_AT: u64 = 1_767_225_600;
const V87_CHECKED_AT: u64 = 1_767_225_660;
/// Vector 87's 238-byte preimage.
const V87_PREIMAGE: &str = concat!(
    "5343502d504c41592d494e544547524954592d564552444943542d56313aaca2",
    "c93825d53244c823000db9dec0a02498bdb3ed96aa2ce038425b4c65001e54c1",
    "1378109c934f30fab4b6757e7d5325560950f8fa485a4c05ba346c9b7f266631",
    "8c86819e17ad71427eabe4cf46590f16adb2bed9e43c9c7dc18ea060bbd3f3ee",
    "dcddd35d370d042a0eb4e19b4b57a918a421aee1d96845c08c1fbdb9fe03ee76",
    "0b2de75a5f5a5e7eaa046eca0df481765a163b7088338eb7c54dee70daae8359",
    "9d12bbbeff09725d9d6ea2222acadb684c092b9f534dbaf10f973f6f5bd00000",
    "00006955b900000000006955b93c",
);
/// Vector 87's preimage digest.
const V87_PREIMAGE_DIGEST: &str =
    "4098e91f88231da38665691770a1b026e60a8d184efae9bb2f11a3107fbe6e79";
/// Vector 87's raw `r ‖ s` signature.
const V87_SIGNATURE: &str = concat!(
    "feef9523a7bcd5ef7cadbd0886ad374057003f9964c6ded0716617b22841a230",
    "456fb375ccf6b28573637ee2084719cf04b9a2502d37baf66a2dd475e6358eb1",
);
/// Vector 87's 176-byte verdict.
const V87_VERDICT: &str = concat!(
    "aca2c93825d53244c823000db9dec0a02498bdb3ed96aa2ce038425b4c65001e",
    "ee760b2de75a5f5a5e7eaa046eca0df481765a163b7088338eb7c54dee70daae",
    "83599d12bbbeff09725d9d6ea2222acadb684c092b9f534dbaf10f973f6f5bd0",
    "000000006955b900000000006955b93cfeef9523a7bcd5ef7cadbd0886ad3740",
    "57003f9964c6ded0716617b22841a230456fb375ccf6b28573637ee2084719cf",
    "04b9a2502d37baf66a2dd475e6358eb1",
);
/// §25.2's reference seed, whose key signs Vector 87.
const REFERENCE_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

fn bytes32(hex_text: &str) -> BoxResult<[u8; 32]> {
    hex::decode(hex_text)?
        .try_into()
        .map_err(|_| "32 bytes".into())
}

/// `SHA-256(label)` as an identifier, as §25.35 derives its fixtures.
fn fixture_identifier(label: &str) -> Identifier {
    Identifier::from_bytes(Sha256::digest(label).into())
}

/// The P-256 group order n, big-endian.
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// Replaces `s` with `n − s`: the same ECDSA signature in its high-`s` form.
fn negate_s(signature: &mut [u8; 64]) {
    let mut borrow = 0u16;
    for index in (0..32).rev() {
        let minuend = u16::from(ORDER[index]);
        let subtrahend = u16::from(signature[32 + index]) + borrow;
        let (difference, next) = if minuend >= subtrahend {
            (minuend - subtrahend, 0)
        } else {
            (minuend + 0x100 - subtrahend, 1)
        };
        signature[32 + index] = difference.to_be_bytes()[1];
        borrow = next;
    }
}

// ── Key-event logs and resolution ───────────────────────────────────────────

fn key(seed: [u8; 32]) -> P256SecretKey {
    P256SecretKey::from_seed(SeedLabel::TestVectorKey, &seed)
}

fn point(seed: [u8; 32]) -> [u8; 33] {
    key(seed).public_key().to_compressed()
}

const fn entry(key: [u8; 33], role: KeyRole, condition: KeyCondition) -> KeyEntry {
    KeyEntry {
        key,
        role,
        condition,
        compromised_from: 0,
        custody_type: CustodyType::Software,
        key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
    }
}

fn root_group() -> SignerGroup {
    SignerGroup {
        indices: vec![0],
        forms: vec![SignatureForm::Raw],
    }
}

/// `BE32(len) ‖ signed preimage ‖ the root key's raw signature`.
fn unit(encoded: &EncodedPreimage, root: &P256SecretKey) -> BoxResult<Vec<u8>> {
    let signed = encoded.signed_preimage();
    let signature = sign_prehash_rfc6979(root, &Sha256::digest(&signed).into())?;
    let mut unit = u32::try_from(signed.len())?.to_be_bytes().to_vec();
    unit.extend_from_slice(&signed);
    unit.extend_from_slice(&signature);
    Ok(unit)
}

/// A verifier identity: its root key, its `#active` key and its log.
struct Identity {
    root: P256SecretKey,
    active: P256SecretKey,
    identifier: Identifier,
    units: Vec<Vec<u8>>,
    head: [u8; 32],
    snapshot: KeyStateSnapshot,
}

impl Identity {
    /// An inception with one root member at threshold 1, one `#active` key
    /// and a commitment to one next key.
    fn incept(root_seed: [u8; 32], active_seed: [u8; 32]) -> BoxResult<Self> {
        let root = key(root_seed);
        let snapshot = KeyStateSnapshot {
            root_threshold: 1,
            keys: vec![
                entry(point(root_seed), KeyRole::RootMember, KeyCondition::Current),
                entry(point(active_seed), KeyRole::Active, KeyCondition::Current),
            ],
            witnesses: vec![Identifier::from_bytes([0x77; 32])],
            witnessing_interval: 3600,
            service_key_role: KeyRole::Active,
            delegator: Identifier::ZERO,
        };
        let encoded = encode_preimage(&EventPreimage::inception(InceptionFields {
            root_group: root_group(),
            key_state: snapshot.clone(),
            continuation: Continuation::FixesCommitment(FixedCommitment {
                commitments: vec![CommitmentEntry {
                    commitment: prerotation_commitment(&point([0xee; 32])),
                    custody_type: CustodyType::Software,
                    key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
                }],
                next_threshold: 1,
            }),
        }))?;
        let identifier = encoded
            .inception_identifier()
            .ok_or("an inception derives its identifier")?;
        Ok(Self {
            units: vec![unit(&encoded, &root)?],
            head: encoded.event_digest(),
            root,
            active: key(active_seed),
            identifier,
            snapshot,
        })
    }

    /// The log extended by a `KeyState` its root signs, which installs
    /// `active_seed`'s key and drops the earlier `#active` key `Superseded`.
    fn rotate(mut self, active_seed: [u8; 32]) -> BoxResult<Self> {
        let (dropped, kept): (Vec<KeyEntry>, Vec<KeyEntry>) = self
            .snapshot
            .keys
            .iter()
            .copied()
            .partition(|entry| entry.role == KeyRole::Active);
        let mut snapshot = self.snapshot.clone();
        snapshot.keys = kept;
        snapshot.keys.push(entry(
            point(active_seed),
            KeyRole::Active,
            KeyCondition::Current,
        ));
        snapshot
            .keys
            .extend(dropped.into_iter().map(|entry| KeyEntry {
                condition: KeyCondition::Superseded,
                ..entry
            }));
        let encoded = encode_preimage(&EventPreimage::key_state(KeyStateFields {
            identifier: self.identifier,
            sequence: u64::try_from(self.units.len())?,
            predecessor_digest: self.head,
            root_group: root_group(),
            key_state: snapshot.clone(),
            seals: Vec::new(),
        }))?;
        self.units.push(unit(&encoded, &self.root)?);
        self.head = encoded.event_digest();
        self.snapshot = snapshot;
        self.active = key(active_seed);
        Ok(self)
    }

    /// The key state a first-contact resolution at `resolved_at_secs`
    /// accepts: two sources, read to the end under two distinct proven
    /// operator keys, serve the log (R11's floor).
    fn resolved(&self, resolved_at_secs: u64) -> BoxResult<ResolvedState> {
        let source = |name: &str, operator: u8| SourceRead {
            name: name.to_owned(),
            units: self.units.clone(),
            exhaustion: SourceExhaustion::Exhausted,
            proof: OperatorProof::Verified {
                operator_key: [operator; 33],
            },
        };
        let reads = [source("relay-a", 0x02), source("relay-b", 0x03)];
        let classification = classify(ResolutionInput {
            identifier: self.identifier,
            held: None,
            reads: &reads,
            now: SystemTime::UNIX_EPOCH + Duration::from_secs(resolved_at_secs),
        })?;
        match classification.verdict {
            ResolutionVerdict::Adopted { .. } | ResolutionVerdict::Confirmed => {}
            other => return Err(format!("expected Adopted, got {other:?}").into()),
        }
        classification
            .key_state
            .ok_or_else(|| "an Adopted verdict carries a key state".into())
    }
}

fn verifier_a() -> BoxResult<Identity> {
    Identity::incept([0x31; 32], [0x32; 32])
}

fn verifier_b() -> BoxResult<Identity> {
    Identity::incept([0x41; 32], [0x42; 32])
}

// ── Fixture ─────────────────────────────────────────────────────────────────

/// The reader's time.
const NOW: u64 = T0;
const MAX_AGE_SECS: u64 = 30 * DAY;
const PACKAGE: &str = "com.example.scp";
const OTHER_PACKAGE: &str = "com.example.other";
const CERT: [u8; 32] = [0x83; 32];
const CONTEXT: &str = "ctx-1";
const CHALLENGE: [u8; 32] = [0x11; 32];
const TOKEN: &[u8] = b"integrity token A";

/// What the verdict's signature covers, where a case signs over values other
/// than the ones the reader reads.
#[derive(Clone)]
struct SignedOver {
    /// The preimage's `subject`.
    subject: Identifier,
    /// The identifier the signed `D` covers.
    binding_subject: Identifier,
    /// The context the signed `D` covers.
    context_id: String,
    /// The token whose digest the preimage carries.
    token: Vec<u8>,
}

struct Fixture {
    policy: ContextSybilPolicy,
    /// The identifier being read.
    subject: Identifier,
    context_id: String,
    /// The token the entry carries.
    token: Vec<u8>,
    verifier: Identifier,
    package_hash: [u8; 32],
    cert_digest: [u8; 32],
    token_issued_at: u64,
    checked_at: u64,
    signer: P256SecretKey,
    signed: SignedOver,
    signature_hook: fn(&mut [u8; 64]),
    verdict_hook: fn(&mut Vec<u8>),
    key_states: Vec<ResolvedState>,
}

fn package(name: &str, verifier: Identifier) -> AcceptedAndroidPackage {
    AcceptedAndroidPackage {
        package_name: name.to_owned(),
        signing_cert_sha256: CERT,
        verifier_identifier: verifier,
    }
}

impl Fixture {
    /// An entry every check passes: verifier A signs for the subject, the
    /// context, the token and the one accepted package, and the caller
    /// supplies A's key state resolved ten seconds ago.
    fn valid() -> BoxResult<Self> {
        let a = verifier_a()?;
        let subject = fixture_identifier("SCP test vector identifier subject");
        let mut policy = ContextSybilPolicy::standard();
        policy.device_attestation_challenge = CHALLENGE;
        policy.device_attestation_max_age_secs = MAX_AGE_SECS;
        policy.accepted_android_packages = vec![package(PACKAGE, a.identifier)];
        Ok(Self {
            policy,
            subject,
            context_id: CONTEXT.to_owned(),
            token: TOKEN.to_vec(),
            verifier: a.identifier,
            package_hash: Sha256::digest(PACKAGE).into(),
            cert_digest: CERT,
            token_issued_at: NOW - 120,
            checked_at: NOW - 60,
            signer: a.active.clone(),
            signed: SignedOver {
                subject,
                binding_subject: subject,
                context_id: CONTEXT.to_owned(),
                token: TOKEN.to_vec(),
            },
            signature_hook: |_| {},
            verdict_hook: |_| {},
            key_states: vec![a.resolved(NOW - 10)?],
        })
    }

    /// Makes `identity` the verdict's verifier and signer.
    fn signed_by(&mut self, identity: &Identity) {
        self.verifier = identity.identifier;
        self.signer = identity.active.clone();
    }

    /// The verdict field: the signed fields, the signature over what
    /// [`SignedOver`] names, then each hook.
    fn verdict(&self) -> BoxResult<Vec<u8>> {
        let signed_binding = device_attestation_binding_digest(
            &self.signed.binding_subject,
            &self.signed.context_id,
            &CHALLENGE,
        )?;
        let fields = PreimageFields {
            verifier: *self.verifier.as_bytes(),
            subject: *self.signed.subject.as_bytes(),
            binding: *signed_binding.as_bytes(),
            token_digest: Sha256::digest(&self.signed.token).into(),
            package_hash: self.package_hash,
            cert_digest: self.cert_digest,
            token_issued_at: self.token_issued_at,
            checked_at: self.checked_at,
        };
        let mut signature = sign_prehash_rfc6979(&self.signer, &fields.digest())?;
        (self.signature_hook)(&mut signature);
        let mut verdict = Vec::with_capacity(VERDICT_LEN);
        verdict.extend_from_slice(self.verifier.as_bytes());
        verdict.extend_from_slice(&self.package_hash);
        verdict.extend_from_slice(&self.cert_digest);
        verdict.extend_from_slice(&self.token_issued_at.to_be_bytes());
        verdict.extend_from_slice(&self.checked_at.to_be_bytes());
        verdict.extend_from_slice(&signature);
        (self.verdict_hook)(&mut verdict);
        Ok(verdict)
    }

    fn run(&self, checks: &[(PlayIntegrityCheck, CheckFn)]) -> BoxResult<Run> {
        let policy = self.policy.validated()?;
        let binding = device_attestation_binding_digest(
            &self.subject,
            &self.context_id,
            &self.policy.device_attestation_challenge,
        )?;
        let verdict = self.verdict()?;
        let verifiers: Vec<&ResolvedState> = self.key_states.iter().collect();
        let read = PlayIntegrityRead {
            token: &self.token,
            verdict: &verdict,
            binding: &binding,
            policy,
            verifiers: &verifiers,
            now_secs: NOW,
            entry_id: "entry-0",
        };
        let full = run(&read, checks);
        if checks.len() == PLAY_INTEGRITY_CHECKS.len() {
            // The production entry point returns what the full array does.
            let entry_point = read_play_integrity(&read);
            let expected = full.result.clone().map_err(|stop| match stop {
                Stop::Fail(failure) => failure,
                Stop::Prerequisite(check) => check.prerequisite_failure(),
            });
            assert_eq!(
                entry_point, expected,
                "read_play_integrity runs every check"
            );
        }
        Ok(full)
    }

    fn run_all(&self) -> BoxResult<Run> {
        self.run(&PLAY_INTEGRITY_CHECKS)
    }
}

// ── Harness ─────────────────────────────────────────────────────────────────

type Mutation = fn(&mut Fixture) -> TestResult;

/// Every check except `check`.
fn without(check: PlayIntegrityCheck) -> Vec<(PlayIntegrityCheck, CheckFn)> {
    PLAY_INTEGRITY_CHECKS
        .iter()
        .filter(|(id, _)| *id != check)
        .copied()
        .collect()
}

fn require_verified(run: &Run, what: &str) -> TestResult {
    match &run.result {
        Ok(_) => Ok(()),
        Err(stop) => Err(format!(
            "{what}: expected Verified, got {stop:?} after {:?}",
            run.ran
        )
        .into()),
    }
}

/// The four steps of every failure test.
fn rejection_case(
    mutate: Mutation,
    check: PlayIntegrityCheck,
    failure: PlayIntegrityFailure,
) -> TestResult {
    let mut fixture = Fixture::valid()?;
    require_verified(&fixture.run_all()?, "unmutated fixture")?;
    mutate(&mut fixture)?;
    let full = fixture.run_all()?;
    assert_eq!(full.result, Err(Stop::Fail(failure)), "ran {:?}", full.ran);
    assert_eq!(
        full.ran.last(),
        Some(&check),
        "the named check stopped the run"
    );
    let rerun = fixture.run(&without(check))?;
    assert_ne!(
        rerun.result,
        Err(Stop::Fail(failure)),
        "without {check:?} the outcome must be gone; ran {:?}",
        rerun.ran
    );
    Ok(())
}

/// A must-pass case: the mutated fixture still reads `Verified`.
fn passes(mutate: Mutation) -> TestResult {
    let mut fixture = Fixture::valid()?;
    mutate(&mut fixture)?;
    require_verified(&fixture.run_all()?, "must-pass case")
}

macro_rules! rejection_cases {
    ($($name:ident: $check:ident => $kind:ident($cause:expr), $mutate:expr;)+) => {
        $(
            #[test]
            fn $name() -> TestResult {
                rejection_case(
                    $mutate,
                    PlayIntegrityCheck::$check,
                    PlayIntegrityFailure::$kind($cause),
                )
            }
        )+
        /// The check each generated case names, one entry per case.
        const COVERED_CHECKS: &[PlayIntegrityCheck] = &[$(PlayIntegrityCheck::$check),+];
    };
}

#[test]
fn every_check_has_a_rejection_case() {
    for check in PlayIntegrityCheck::ALL {
        assert!(
            COVERED_CHECKS.contains(&check),
            "{check:?} has no rejection case"
        );
    }
    let listed: Vec<PlayIntegrityCheck> = PLAY_INTEGRITY_CHECKS.iter().map(|(id, _)| *id).collect();
    assert_eq!(
        listed,
        PlayIntegrityCheck::ALL,
        "the array runs every check once, in order"
    );
}

// ── Mutations ───────────────────────────────────────────────────────────────

fn flip_r_bit(signature: &mut [u8; 64]) {
    signature[5] ^= 0x01;
}

rejection_cases! {
    // AC32.
    empty_packages_no_verifier_named: VerifierNamed => Unverifiable(U::NoVerifierNamed), |f| {
        f.policy.accepted_android_packages.clear();
        Ok(())
    };
    // AC33.
    verdict_zero_bytes_absent: VerdictPresent => Unverifiable(U::VerdictAbsent), |f| {
        f.verdict_hook = |verdict| verdict.fill(0);
        Ok(())
    };
    verdict_175_bytes_malformed: VerdictLength => Rejected(R::MalformedEntry), |f| {
        f.verdict_hook = |verdict| {
            verdict.pop();
        };
        Ok(())
    };
    verdict_177_bytes_malformed: VerdictLength => Rejected(R::MalformedEntry), |f| {
        f.verdict_hook = |verdict| verdict.push(0);
        Ok(())
    };
    token_issued_after_checked_malformed: TimestampOrder => Rejected(R::MalformedEntry), |f| {
        f.token_issued_at = f.checked_at + 1;
        Ok(())
    };
    // AC34.
    package_hash_unmatched: Package => Rejected(R::PackageNotAccepted), |f| {
        f.package_hash = Sha256::digest(OTHER_PACKAGE).into();
        Ok(())
    };
    cert_digest_unmatched: Package => Rejected(R::PackageNotAccepted), |f| {
        f.cert_digest = [0x99; 32];
        Ok(())
    };
    package_unnamed_verifier: Verifier => Unverifiable(U::VerdictFromUnnamedVerifier), |f| {
        let b = verifier_b()?;
        f.policy.accepted_android_packages = vec![package(PACKAGE, b.identifier)];
        f.key_states.push(b.resolved(NOW - 10)?);
        Ok(())
    };
    // AC36, binding B4 part one: the verdict for this package is signed by
    // the verifier another accepted package names.
    verdict_signed_by_other_packages_verifier:
        Verifier => Unverifiable(U::VerdictFromUnnamedVerifier), |f| {
        let b = verifier_b()?;
        f.policy
            .accepted_android_packages
            .push(package(OTHER_PACKAGE, b.identifier));
        f.signed_by(&b);
        f.key_states.push(b.resolved(NOW - 10)?);
        Ok(())
    };
    // AC35.
    checked_at_301_past_now_not_yet_valid: NotYetValid => Rejected(R::NotYetValid), |f| {
        f.checked_at = NOW + 301;
        Ok(())
    };
    issued_past_max_age_expired: MaxAge => Rejected(R::Expired), |f| {
        f.token_issued_at = NOW - MAX_AGE_SECS - 1;
        Ok(())
    };
    // AC37.
    verifier_absent_from_list: VerifierKeyState => Unverifiable(U::VerifierKeyStateUnresolved), |f| {
        f.key_states.clear();
        Ok(())
    };
    // Binding B4 part two: the only supplied key state is another identity's.
    verifier_key_state_of_other_identity:
        VerifierKeyState => Unverifiable(U::VerifierKeyStateUnresolved), |f| {
        f.key_states = vec![verifier_b()?.resolved(NOW - 10)?];
        Ok(())
    };
    // Binding B9: resolved exactly MAX_ATTESTATION_KEY_RESOLUTION_STALENESS ago.
    stale_verifier_key_state_unresolved:
        VerifierKeyState => Unverifiable(U::VerifierKeyStateUnresolved), |f| {
        f.key_states = vec![verifier_a()?.resolved(NOW - 300)?];
        Ok(())
    };
    // AC38.
    subject_not_reader_identifier: Signature => Rejected(R::VerdictSignatureInvalid), |f| {
        f.signed.subject = fixture_identifier("the reader's own identifier");
        Ok(())
    };
    // AC39.
    verdict_signature_flipped_bit: Signature => Rejected(R::VerdictSignatureInvalid), |f| {
        f.signature_hook = flip_r_bit;
        Ok(())
    };
    verdict_high_s_rejected: Signature => Rejected(R::VerdictSignatureInvalid), |f| {
        f.signature_hook = negate_s;
        Ok(())
    };
    signed_by_previous_active_after_rotation:
        Signature => Rejected(R::VerdictSignatureInvalid), |f| {
        let rotated = verifier_a()?.rotate([0x33; 32])?;
        f.key_states = vec![rotated.resolved(NOW - 10)?];
        // The signer stays A's old `#active` key, which the rotated state
        // lists `Superseded`.
        Ok(())
    };
    // Binding B5: the tag is this context's, the verdict covers another's `D`.
    verdict_for_other_context_under_this_tag:
        Signature => Rejected(R::VerdictSignatureInvalid), |f| {
        f.signed.context_id = "ctx-2".to_owned();
        Ok(())
    };
    // Binding B8: the entry carries token B beside a verdict over token A.
    token_b_with_verdict_over_token_a: Signature => Rejected(R::VerdictSignatureInvalid), |f| {
        f.token = b"integrity token B".to_vec();
        Ok(())
    };
}

// ── Must-pass cases ─────────────────────────────────────────────────────────

/// AC35: `checked_at` exactly the skew past the reader's time.
#[test]
fn checked_at_300_past_now_passes() -> TestResult {
    passes(|f| {
        f.checked_at = NOW + 300;
        Ok(())
    })
}

/// AC35: the reader's time exactly `token_issued_at` plus the maximum age.
#[test]
fn issued_exactly_max_age_ago_passes() -> TestResult {
    passes(|f| {
        f.token_issued_at = NOW - MAX_AGE_SECS;
        Ok(())
    })
}

/// Check 5: a key state resolved one second inside the bound.
#[test]
fn key_state_resolved_299_seconds_ago_passes() -> TestResult {
    passes(|f| {
        f.key_states = vec![verifier_a()?.resolved(NOW - 299)?];
        Ok(())
    })
}

/// AC34: two elements name one package and certificate with two verifiers,
/// and a verdict from either passes.
#[test]
fn package_two_verifiers_accepts_either() -> TestResult {
    passes(|f| {
        let b = verifier_b()?;
        f.policy
            .accepted_android_packages
            .push(package(PACKAGE, b.identifier));
        f.key_states.push(b.resolved(NOW - 10)?);
        Ok(())
    })?;
    passes(|f| {
        let b = verifier_b()?;
        f.policy
            .accepted_android_packages
            .push(package(PACKAGE, b.identifier));
        f.signed_by(&b);
        f.key_states.push(b.resolved(NOW - 10)?);
        Ok(())
    })
}

/// AC39: after a rotation, a verdict under the new Current `#active` key
/// passes, which makes the rotation case fail on the key alone.
#[test]
fn signed_by_current_active_after_rotation_passes() -> TestResult {
    passes(|f| {
        let rotated = verifier_a()?.rotate([0x33; 32])?;
        f.signer = rotated.active.clone();
        f.key_states = vec![rotated.resolved(NOW - 10)?];
        Ok(())
    })
}

/// AC38: the preimage's `subject` is the identifier being read. The reader
/// takes no identifier of its own, so a reader whose identifier differs from
/// the subject reads a verdict over the subject as `Verified`; the case
/// `subject_not_reader_identifier` shows a verdict over the reader's own
/// identifier fails.
#[test]
fn subject_differs_from_reader_identifier_passes() -> TestResult {
    let fixture = Fixture::valid()?;
    assert_ne!(
        fixture.subject,
        fixture_identifier("the reader's own identifier")
    );
    assert_eq!(fixture.signed.subject, fixture.subject);
    require_verified(&fixture.run_all()?, "verdict over the subject")
}

/// A `Verified` read carries the platform, the entry id, `SHA-256(token)` and
/// `token_issued_at` (§9.3.1).
#[test]
fn verified_fields() -> TestResult {
    let fixture = Fixture::valid()?;
    let verified = fixture
        .run_all()?
        .result
        .map_err(|stop| format!("{stop:?}"))?;
    assert_eq!(
        verified.platform(),
        DeviceAttestationPlatform::PlayIntegrity
    );
    assert_eq!(verified.entry_id(), "entry-0");
    assert_eq!(
        verified.credential(),
        &<[u8; 32]>::from(Sha256::digest(TOKEN))
    );
    assert_eq!(verified.minted_at(), NOW - 120);
    Ok(())
}

/// A check needing a part whose admitting check did not run fails closed in
/// production with that check's own outcome.
#[test]
fn prerequisite_fails_closed() {
    assert_eq!(
        PlayIntegrityCheck::VerdictLength.prerequisite_failure(),
        PlayIntegrityFailure::Rejected(R::MalformedEntry)
    );
    assert_eq!(
        PlayIntegrityCheck::VerifierKeyState.prerequisite_failure(),
        PlayIntegrityFailure::Unverifiable(U::VerifierKeyStateUnresolved)
    );
}

// ── Spec 25 §25.35 Vector 87 ────────────────────────────────────────────────

/// AC33: the verdict splits into Vector 87's fields, and check 6's preimage,
/// recomputed from that verdict, the reader's `D` and the token, is Vector
/// 87's 238 bytes and digest.
#[test]
fn verdict_preimage_238_bytes_matches_generator() -> TestResult {
    let verdict_bytes = hex::decode(V87_VERDICT)?;
    assert_eq!(verdict_bytes.len(), VERDICT_LEN);
    let verdict = Verdict::parse(&verdict_bytes).ok_or("176 bytes parse")?;
    let verifier = fixture_identifier("SCP test vector identifier verifier");
    let subject = fixture_identifier("SCP test vector identifier subject");
    assert_eq!(verdict.verifier, verifier);
    assert_eq!(verdict.package_hash, bytes32(V87_PACKAGE_HASH)?);
    assert_eq!(
        verdict.package_hash,
        <[u8; 32]>::from(Sha256::digest(PACKAGE))
    );
    assert_eq!(verdict.cert_digest, bytes32(V87_CERT_DIGEST)?);
    assert_eq!(verdict.token_issued_at, V87_TOKEN_ISSUED_AT);
    assert_eq!(verdict.checked_at, V87_CHECKED_AT);
    assert_eq!(verdict.signature.as_slice(), hex::decode(V87_SIGNATURE)?);

    let mut challenge = [0u8; 32];
    for (byte, value) in challenge.iter_mut().zip(0x20u8..) {
        *byte = value;
    }
    let binding = device_attestation_binding_digest(&subject, "ctx-1", &challenge)?;
    assert_eq!(binding.as_bytes(), &bytes32(V84A_BINDING)?);
    let fields = PreimageFields::of(&verdict, &binding, V87_TOKEN);
    assert_eq!(fields.token_digest, bytes32(V87_TOKEN_DIGEST)?);
    let preimage = fields.preimage();
    assert_eq!(preimage.len(), PREIMAGE_LEN);
    assert_eq!(hex::encode(&preimage), V87_PREIMAGE);
    assert_eq!(fields.digest(), bytes32(V87_PREIMAGE_DIGEST)?);

    assert_eq!(Verdict::parse(&verdict_bytes[..175]), None);
    let mut long = verdict_bytes;
    long.push(0);
    assert_eq!(Verdict::parse(&long), None);
    Ok(())
}

/// AC39: Vector 87's signature verifies through check 6's verification under
/// a key state whose Current `#active` key is §25.2's reference key, and fails
/// in its high-`s` form and under a rotated-away key.
#[test]
fn generator_verdict_signature_verifies() -> TestResult {
    let reference = bytes32(REFERENCE_SEED)?;
    let identity = Identity::incept([0x51; 32], reference)?;
    let resolved = identity.resolved(NOW)?;
    let digest = bytes32(V87_PREIMAGE_DIGEST)?;
    let signature: [u8; 64] = hex::decode(V87_SIGNATURE)?
        .try_into()
        .map_err(|_| "64 bytes")?;
    assert!(verify_under_current_active(&resolved, &digest, &signature));

    let mut high_s = signature;
    negate_s(&mut high_s);
    assert_ne!(high_s, signature);
    assert!(!verify_under_current_active(&resolved, &digest, &high_s));

    let rotated = identity.rotate([0x52; 32])?.resolved(NOW)?;
    assert!(!verify_under_current_active(&rotated, &digest, &signature));
    Ok(())
}

// ── The `PlayIntegrityVerifier` entry ───────────────────────────────────────

const ENDPOINT: &str = "com.example.scp 123456789012 https://verifier.example/verdict";

/// The canonical `id` and `serviceEndpoint` parse; an `id` of another
/// identifier or with a non-canonical index does not.
#[test]
fn play_integrity_verifier_entry_parse() -> TestResult {
    let verifier = fixture_identifier("SCP test vector identifier verifier");
    let id = format!("{verifier}#play-integrity-verifier-0");
    let parsed = parse_play_integrity_verifier_entry(&verifier, &id, ENDPOINT)?;
    assert_eq!(parsed.index, 0);
    assert_eq!(parsed.package_name, PACKAGE);
    assert_eq!(parsed.cloud_project_number, 123_456_789_012);
    assert_eq!(parsed.verdict_url, "https://verifier.example/verdict");

    let other_index = format!("{verifier}#play-integrity-verifier-12");
    assert_eq!(
        parse_play_integrity_verifier_entry(&verifier, &other_index, "p 1 https://h")
            .map(|entry| entry.index),
        Ok(12)
    );

    let must_fail = [
        (
            "another identifier's id",
            format!(
                "{}#play-integrity-verifier-0",
                fixture_identifier("another")
            ),
            VerifierEntryFault::IdNotOfVerifier,
        ),
        (
            "another fragment",
            format!("{verifier}#play-integrity-verifier0"),
            VerifierEntryFault::IdNotOfVerifier,
        ),
        (
            "an index with a leading zero",
            format!("{verifier}#play-integrity-verifier-01"),
            VerifierEntryFault::IndexNotCanonical,
        ),
        (
            "an empty index",
            format!("{verifier}#play-integrity-verifier-"),
            VerifierEntryFault::IndexNotCanonical,
        ),
    ];
    for (what, id, fault) in must_fail {
        assert_eq!(
            parse_play_integrity_verifier_entry(&verifier, &id, ENDPOINT),
            Err(fault),
            "{what}"
        );
    }
    Ok(())
}

/// Each `serviceEndpoint` that departs from the one canonical form fails
/// with its own fault.
#[test]
fn play_integrity_verifier_endpoint_must_fail() {
    let verifier = fixture_identifier("SCP test vector identifier verifier");
    let id = format!("{verifier}#play-integrity-verifier-0");
    let must_fail = [
        (
            "a project number with a leading zero",
            "com.example.scp 0123456789012 https://verifier.example/verdict",
            VerifierEntryFault::ProjectNumberNotCanonical,
        ),
        (
            "a signed project number",
            "com.example.scp +123456789012 https://verifier.example/verdict",
            VerifierEntryFault::ProjectNumberNotCanonical,
        ),
        (
            "a project number past u64",
            "com.example.scp 18446744073709551616 https://verifier.example/verdict",
            VerifierEntryFault::ProjectNumberNotCanonical,
        ),
        (
            "two spaces between fields",
            "com.example.scp  123456789012 https://verifier.example/verdict",
            VerifierEntryFault::FieldsNotThree,
        ),
        (
            "four fields",
            "com.example.scp 123456789012 https://verifier.example/verdict extra",
            VerifierEntryFault::FieldsNotThree,
        ),
        (
            "a trailing space",
            "com.example.scp 123456789012 https://verifier.example/verdict ",
            VerifierEntryFault::FieldsNotThree,
        ),
        (
            "an empty package name",
            " 123456789012 https://verifier.example/verdict",
            VerifierEntryFault::FieldsNotThree,
        ),
        (
            "an http:// URL",
            "com.example.scp 123456789012 http://verifier.example/verdict",
            VerifierEntryFault::UrlNotHttps,
        ),
        (
            "an uppercase scheme",
            "com.example.scp 123456789012 HTTPS://verifier.example/verdict",
            VerifierEntryFault::UrlNotHttps,
        ),
        (
            "a URL with no authority",
            "com.example.scp 123456789012 https:///verdict",
            VerifierEntryFault::UrlNotHttps,
        ),
        (
            "a bare scheme",
            "com.example.scp 123456789012 https://",
            VerifierEntryFault::UrlNotHttps,
        ),
    ];
    for (what, endpoint, fault) in must_fail {
        assert_eq!(
            parse_play_integrity_verifier_entry(&verifier, &id, endpoint),
            Err(fault),
            "{what}"
        );
    }
}
