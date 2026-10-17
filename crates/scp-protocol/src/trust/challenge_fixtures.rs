//! Test fixtures shared by the challenge, admission and aggregate tests:
//! three did:dht parties with real keys, a resolver over them, a
//! definition source, and genuine records built through the production
//! issue, respond, authenticate, grade and record steps.

use std::collections::{BTreeMap, HashMap};

use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

use scp_clock::TestClock;
use scp_did::DID;
use scp_event_log::Ed25519Signature;

use super::TrustError;
use super::attestation::ActiveKeyResolver;
use super::capability_definition::{
    CapabilityDefinition, CapabilityDefinitionSource, DefinitionError, ProtocolOnlyDefinitions,
};
use super::capability_registry::MinCases;
use super::capability_uri::CapabilityUri;
use super::challenge::{
    AnswerKey, ChallengePolicy, ChallengeRequest, ChallengeResponse, ChallengeSigner,
    ChallengeVerification, ExpectedOutput, NewChallenge, PolicyPick, TestCase, TestOutput,
    authenticate_challenge_response, challenge_response_unsigned, challenge_verification_unsigned,
    grade, issue_challenge,
};

/// The context every fixture challenge is administered in.
pub const CONTEXT: &str = "ctx-1";
/// The fixture clock's start.
pub const NOW: u64 = 1_700_000_000;
/// The spec 25 fixture URI: identifier-scoped, so only
/// [`FixtureDefinitions`] defines it.
pub const FIXTURE_URI: &str =
    "scp:tfgiiao36zlseo2tzfoi32knfx6topped3qloxcsube5gdvfrqgq:capability:schema-validation/v1";
/// A protocol row: `Total(20)`, 9500, 2 retries, cooldown 300.
pub const PROTOCOL_URI: &str = "scp:capability:schema-validation/v1";

/// The spec 25 Vector 63 definition.
pub fn fixture_definition() -> CapabilityDefinition {
    CapabilityDefinition {
        capability_uri: FIXTURE_URI.to_owned(),
        min_cases: MinCases::Total(1),
        pass_threshold_bps: 8000,
        max_retries: 2,
        cooldown_secs: 3600,
        description: "Fixture definition for spec 25 vectors 59-62.".to_owned(),
    }
}

/// The protocol rows plus the fixture definition, and optionally a
/// replacement definition for `FIXTURE_URI`.
#[derive(Debug, Clone, Default)]
pub struct FixtureDefinitions {
    /// Replaces the fixture definition when set.
    pub fixture_override: Option<CapabilityDefinition>,
}

impl CapabilityDefinitionSource for FixtureDefinitions {
    fn definition(&self, uri: &CapabilityUri) -> Result<CapabilityDefinition, DefinitionError> {
        if uri.to_string() == FIXTURE_URI {
            return Ok(self
                .fixture_override
                .clone()
                .unwrap_or_else(fixture_definition));
        }
        ProtocolOnlyDefinitions.definition(uri)
    }
}

/// One party: a signing key and its did:dht identifier.
pub struct Party {
    /// The canonical did:dht identifier.
    pub did: DID,
    /// The signing key.
    pub key: SigningKey,
}

impl Party {
    /// A deterministic party from `seed`.
    pub fn new(seed: u8) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let did = scp_did::did_dht_from_public_key(&key.verifying_key().to_bytes());
        Self { did, key }
    }

    /// The 32-byte public key.
    pub fn public(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// A different spelling of this party's key: a padding alias of the
    /// did:dht encoding, which [`super::identifier::CanonicalIdentifier`]
    /// refuses.
    pub fn padding_alias(&self) -> String {
        // The last of 52 characters carries the key's final bit (value bit
        // 4) and four padding bits; setting a padding bit keeps the key.
        let alphabet = b"ybndrfg8ejkmcpqxot1uwisza345h769";
        let text = self.did.0.as_str();
        let (stem, last) = text.split_at(text.len() - 1);
        let index = alphabet
            .iter()
            .position(|c| last.as_bytes() == [*c])
            .unwrap_or_default();
        let alias = alphabet[(index & 0x10) | 1];
        format!("{stem}{}", char::from(alias))
    }
}

impl ChallengeSigner for Party {
    fn sign(&self, digest: &[u8; 32]) -> Result<Ed25519Signature, TrustError> {
        Ok(self.key.sign(digest).to_bytes().to_vec())
    }
}

/// Resolves identifiers to keys from a fixed map.
pub struct MapResolver {
    keys: HashMap<String, Vec<u8>>,
}

impl MapResolver {
    /// Adds `did` with `key`.
    pub fn insert(&mut self, did: &str, key: [u8; 32]) {
        self.keys.insert(did.to_owned(), key.to_vec());
    }
}

impl ActiveKeyResolver for MapResolver {
    fn resolve_active_key(&self, did: &str) -> Result<Vec<u8>, TrustError> {
        self.keys
            .get(did)
            .cloned()
            .ok_or_else(|| TrustError::KeyResolutionUnavailable {
                did: did.to_owned(),
                reason: "not in the fixture resolver".to_owned(),
            })
    }
}

/// Verifier, subject and a third party, with a resolver over all three.
pub struct Fixture {
    /// The challenger.
    pub verifier: Party,
    /// The subject.
    pub subject: Party,
    /// A third party.
    pub other: Party,
    /// Resolves all three.
    pub resolver: MapResolver,
    /// Starts at [`NOW`].
    pub clock: TestClock,
    /// Protocol rows plus the fixture definition.
    pub definitions: FixtureDefinitions,
}

/// The standard fixture.
pub fn fixture() -> Fixture {
    let verifier = Party::new(1);
    let subject = Party::new(2);
    let other = Party::new(3);
    let mut resolver = MapResolver {
        keys: HashMap::new(),
    };
    for party in [&verifier, &subject, &other] {
        resolver.insert(&party.did, party.public());
    }
    Fixture {
        verifier,
        subject,
        other,
        resolver,
        clock: TestClock::new(NOW),
        definitions: FixtureDefinitions::default(),
    }
}

/// An `ExactMatch` case whose answer is `"ok"`.
pub fn case(test_id: &str, category: &str, weight: u32) -> TestCase {
    TestCase {
        test_id: test_id.to_owned(),
        input: json!({"prompt": test_id}),
        expected: ExpectedOutput::ExactMatch { value: json!("ok") },
        category: category.to_owned(),
        weight,
    }
}

/// `n` cases per `(category, n)` pair, weights summing to 10000.
pub fn cases_in(categories: &[(&str, u32)]) -> Vec<TestCase> {
    let total: u32 = categories.iter().map(|(_, n)| n).sum();
    let each = 10_000 / total;
    let mut out = Vec::new();
    for (category, n) in categories {
        for i in 0..*n {
            out.push(case(&format!("{category}-{i}"), category, each));
        }
    }
    if let Some(last) = out.last_mut() {
        last.weight += 10_000 - each * total;
    }
    out
}

/// `n` cases in one category.
pub fn cases(n: u32) -> Vec<TestCase> {
    cases_in(&[("general", n)])
}

impl Fixture {
    /// A [`NewChallenge`] from verifier to subject at the clock's time,
    /// with a one-hour window.
    pub fn new_challenge(
        &self,
        uri: &str,
        test_cases: Vec<TestCase>,
        pick: PolicyPick,
    ) -> Result<NewChallenge, TrustError> {
        Ok(NewChallenge {
            verifier: self.verifier.did.clone(),
            subject: self.subject.did.clone(),
            test_cases,
            created_at: scp_clock::Clock::now_secs(&self.clock),
            window_secs: 3600,
            context_id: CONTEXT.to_owned(),
            policy: ChallengePolicy::resolve(&self.definitions, uri, pick)?,
        })
    }

    /// A signed request for `uri` with `test_cases`.
    pub fn issue(
        &self,
        uri: &str,
        test_cases: Vec<TestCase>,
    ) -> Result<(ChallengeRequest, AnswerKey), TrustError> {
        issue_challenge(
            self.new_challenge(uri, test_cases, PolicyPick::default())?,
            &self.verifier,
        )
    }

    /// The subject's signed response for `attempt`.
    pub fn respond(
        &self,
        request: &ChallengeRequest,
        attempt: u32,
        outputs: Vec<TestOutput>,
    ) -> Result<ChallengeResponse, TrustError> {
        let unsigned = challenge_response_unsigned(
            request,
            &self.subject.did,
            attempt,
            outputs,
            &self.resolver,
            &self.clock,
        )?;
        let signature = self.subject.sign(&unsigned.signing_digest())?;
        Ok(unsigned.with_subject_signature(signature))
    }

    /// A genuine signed record: issue at the clock's time, respond with every
    /// answer correct (`ExactMatch` cases only), authenticate, grade and sign
    /// one second later, the first instant strictly inside the window
    /// (RULING 5).
    pub fn genuine_record(
        &self,
        uri: &str,
        test_cases: Vec<TestCase>,
    ) -> Result<ChallengeVerification, TrustError> {
        let (request, key) = self.issue(uri, test_cases)?;
        let outputs = request
            .test_cases
            .iter()
            .map(|c| TestOutput {
                test_id: c.test_id.clone(),
                output: json!("ok"),
            })
            .collect();
        let response = self.respond(&request, 1, outputs)?;
        let auth = authenticate_challenge_response(
            request.clone(),
            response,
            &self.verifier.did,
            &self.resolver,
        )?;
        let outcome = grade(&auth, &key, &BTreeMap::new(), &BTreeMap::new());
        let unsigned =
            challenge_verification_unsigned(&auth, &outcome, request.created_at.saturating_add(1))?;
        let signature = self.verifier.sign(&unsigned.signing_digest())?;
        Ok(unsigned.with_verifier_signature(signature))
    }

    /// Re-signs `record` with the verifier's key after a test edited it.
    pub fn resign(&self, record: &mut ChallengeVerification) -> Result<(), TrustError> {
        let digest = super::challenge::challenge_verification_signing_digest(record)?;
        record.verifier_signature = self.verifier.sign(&digest)?;
        Ok(())
    }
}
