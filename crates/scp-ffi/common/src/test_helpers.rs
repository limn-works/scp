//! Shared test fixtures for FFI bridge tests.
//!
//! Gated behind the `testing` feature so these helpers are available to all
//! bridge crates (`scp-ffi`, `scp-ffi-napi`, `scp-ffi-uniffi`) via
//! `[dev-dependencies] scp-ffi-common = { ..., features = ["testing"] }`.

use scp_core::context::governance::{
    GovernanceAction, GovernanceProposal, ProposalStatus, SignedVote, VoteType,
};
use scp_did::DID;

/// Build a [`GovernanceProposal`] in `Approved` status with a single approval
/// vote.  Used across bridge test suites to drive governance execution without
/// a full voting round-trip.
#[must_use]
pub fn approved_proposal(
    pid: [u8; 32],
    context_id: &str,
    action: GovernanceAction,
    approver_did: &str,
) -> GovernanceProposal {
    GovernanceProposal {
        proposal_id: pid,
        context_id: context_id.into(),
        proposer_did: DID(approver_did.to_owned()),
        action,
        status: ProposalStatus::Approved,
        created_at: 1000,
        voting_deadline: 2000,
        approvals: vec![SignedVote {
            voter_did: DID(approver_did.to_owned()),
            vote: VoteType::Approve,
            timestamp: 1000,
            signature: vec![0u8; 64],
        }],
        rejections: Vec::new(),
        created_at_epoch: None,
    }
}

/// The `bridgeTarget` the fixture's accepted bridge entry carries.
pub const FIXTURE_BRIDGE_TARGET: [u8; 32] = [0x42; 32];

/// The `serviceEndpoint`s of the entries [`document_with_rejected_services`]
/// keeps, in record order.
pub const FIXTURE_ACCEPTED_ENDPOINTS: [&str; 2] = [
    "wss://bridge.example.com/scp/v1",
    "wss://relay.example.com/scp/v1",
];

/// A DID document deserialized from a record mixing entries §18.2.1 accepts
/// and rejects.
///
/// The record holds a tier 3 bridge `SCPRelay` entry carrying
/// [`FIXTURE_BRIDGE_TARGET`], an `SCPRelay` entry whose URL carries a query,
/// a non-relay entry that carries `bridgeTarget`, and a plain `SCPRelay`
/// entry (`18-addressability-and-deployment.md` §18.2.1). Deserializing
/// drops the two rejected entries, so bridge projections must show only the
/// two accepted ones.
///
/// # Panics
///
/// Panics if the record does not serialize or deserialize.
#[must_use]
#[allow(clippy::expect_used)] // test fixture over a fixed record
pub fn document_with_rejected_services() -> scp_did::DidDocument {
    let did = "did:dht:zFixtureRejectedServices";
    let entry = |n: &str, ty: &str, endpoint: &str, bridge_target| scp_did::Service {
        id: format!("{did}#{n}"),
        service_type: ty.to_owned(),
        service_endpoint: endpoint.to_owned(),
        bridge_target,
    };
    let record = scp_did::DidDocument {
        context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
        id: did.to_owned(),
        verification_method: Vec::new(),
        authentication: Vec::new(),
        assertion_method: Vec::new(),
        also_known_as: Vec::new(),
        service: vec![
            entry(
                "scp-relay-1",
                "SCPRelay",
                FIXTURE_ACCEPTED_ENDPOINTS[0],
                Some(FIXTURE_BRIDGE_TARGET),
            ),
            entry(
                "scp-relay-2",
                "SCPRelay",
                "wss://query.example.com/scp/v1?bridge_target=00",
                None,
            ),
            entry(
                "pre-rotation",
                "PreRotationCommitment",
                "sha256:00",
                Some(FIXTURE_BRIDGE_TARGET),
            ),
            entry(
                "scp-relay-3",
                "SCPRelay",
                FIXTURE_ACCEPTED_ENDPOINTS[1],
                None,
            ),
        ],
    };
    assert_eq!(record.service.len(), 4);
    let json = record.to_json().expect("the record serializes");
    scp_did::DidDocument::from_json(&json).expect("the record deserializes")
}

/// One row of the custody error table each bridge's error test runs: a
/// custody failure kind, the error class and code every bridge reports for
/// it, and the bare `PlatformError`s whose kind it is.
///
/// The codes are the ones `.docs/standards/sdk-common.md` registers (ADR-006
/// 2026-09-29, 2026-10-11 and 2026-10-12 amendments), written as constants
/// here rather than read from `custody_failure_code`, so a wrong production
/// mapping fails the table.
#[derive(Debug)]
pub struct CustodyCodeRow {
    /// The custody failure kind.
    pub kind: scp_crypto::CustodyFailureKind,
    /// The error class the bridge reports.
    pub class: crate::error_codes::CustodyFailureClass,
    /// The code the bridge reports.
    pub code: &'static str,
    /// The bare `PlatformError`s whose kind is `kind`. Empty for
    /// [`TimedOut`](scp_crypto::CustodyFailureKind::TimedOut): a custody sign
    /// past the ADR-049 Decision 7a budget is never a `PlatformError` (ADR-006
    /// 2026-10-11 amendment), so it reaches a bridge only as a `CustodyFailure`.
    pub platform_errors: Vec<scp_platform::PlatformError>,
}

/// The custody error table: one row per [`CustodyFailureKind`](scp_crypto::CustodyFailureKind).
///
/// Key-not-found is `SCP-CRYPTO-4006`, a rejected host pseudonym
/// `SCP-IDENT-1055`, a custody sign past its budget `SCP-CRYPTO-4062`, a
/// closed or still-locked store `SCP-STORAGE-8006` or `SCP-STORAGE-8005`, a
/// device attestation failure `SCP-ATTEST-9001`, an unsupported operation
/// `SCP-CRYPTO-4061`, each push failure its own code from `SCP-TRANS-5080` to
/// `SCP-TRANS-5084`, and every other custody failure `SCP-CRYPTO-4060`.
#[must_use]
pub fn custody_code_rows() -> Vec<CustodyCodeRow> {
    use scp_crypto::CustodyFailureKind as K;
    // Expands one list of kinds into the array the table iterates and into a
    // match over the same list with no wildcard arm, so a `CustodyFailureKind`
    // variant missing from the list fails to compile (E0004) and a listed
    // duplicate is an unreachable pattern: the table covers every kind once.
    macro_rules! every_kind {
        ($($kind:ident),+ $(,)?) => {{
            const _: fn(K) = |kind| match kind {
                $(K::$kind)|+ => {}
            };
            [$(K::$kind),+]
        }};
    }
    every_kind![
        KeyNotFound,
        PseudonymRejected,
        TimedOut,
        Failed,
        StorageClosed,
        StorageLockHeld,
        AttestationFailed,
        Unsupported,
        PushWakePayloadInvalid,
        PushRegistrationRejected,
        PushVerifierUnavailable,
        PushPlatformUnavailable,
        PushProviderFailed,
    ]
    .into_iter()
    .map(|kind| {
        let (class, code, platform_errors) = custody_code_row(kind);
        CustodyCodeRow {
            kind,
            class,
            code,
            platform_errors,
        }
    })
    .collect()
}

/// The class, code and bare `PlatformError`s of one custody failure kind. A
/// kind added to `CustodyFailureKind` fails to compile here until it has an
/// arm, and in [`custody_code_rows`] until its list names it.
fn custody_code_row(
    kind: scp_crypto::CustodyFailureKind,
) -> (
    crate::error_codes::CustodyFailureClass,
    &'static str,
    Vec<scp_platform::PlatformError>,
) {
    use crate::error_codes::{self as codes, CustodyFailureClass as Class};
    use scp_crypto::CustodyFailureKind as K;
    use scp_platform::{PlatformError as P, PushFailureKind as Push};
    fn push(kind: Push) -> P {
        P::PushError {
            kind,
            detail: "push detail".to_owned(),
        }
    }
    match kind {
        K::KeyNotFound => (Class::Crypto, codes::CRYPTO_4006, vec![P::KeyNotFound]),
        K::PseudonymRejected => (
            Class::Identity,
            codes::IDENT_1055,
            vec![P::PseudonymRejected("pseudonym detail".to_owned())],
        ),
        K::TimedOut => (Class::Crypto, codes::CRYPTO_4062, Vec::new()),
        K::Failed => (
            Class::Crypto,
            codes::CRYPTO_4060,
            vec![
                P::WrongKeyType {
                    expected: scp_platform::traits::KeyType::P256Signing,
                    actual: scp_platform::traits::KeyType::HpkeP256,
                },
                P::NotIdentityKey,
                P::StorageError("storage detail".to_owned()),
                P::CustodyError("custody detail".to_owned()),
            ],
        ),
        K::StorageClosed => (
            Class::Validation,
            codes::STORAGE_8006,
            vec![P::StorageClosed],
        ),
        K::StorageLockHeld => (
            Class::Validation,
            codes::STORAGE_8005,
            vec![P::StorageLockHeld {
                dir: "/tmp/scp".to_owned(),
                lock_path: "/tmp/scp/scp.db.lock".to_owned(),
            }],
        ),
        K::AttestationFailed => (
            Class::Identity,
            codes::ATTEST_9001,
            vec![P::AttestationError("attestation detail".to_owned())],
        ),
        K::Unsupported => (
            Class::Crypto,
            codes::CRYPTO_4061,
            vec![P::Unsupported("unsupported detail")],
        ),
        K::PushWakePayloadInvalid => (
            Class::Transport,
            codes::TRANS_5080,
            vec![push(Push::WakePayloadInvalid)],
        ),
        K::PushRegistrationRejected => (
            Class::Transport,
            codes::TRANS_5081,
            vec![push(Push::RegistrationRejected)],
        ),
        K::PushVerifierUnavailable => (
            Class::Transport,
            codes::TRANS_5082,
            vec![push(Push::VerifierUnavailable)],
        ),
        K::PushPlatformUnavailable => (
            Class::Transport,
            codes::TRANS_5083,
            vec![push(Push::PlatformUnavailable)],
        ),
        K::PushProviderFailed => (
            Class::Transport,
            codes::TRANS_5084,
            vec![push(Push::ProviderFailed)],
        ),
    }
}

/// A [`CustodyFailure`](scp_crypto::CustodyFailure) of `kind`.
#[must_use]
pub fn custody_failure(kind: scp_crypto::CustodyFailureKind) -> scp_crypto::CustodyFailure {
    scp_crypto::CustodyFailure {
        kind,
        detail: "custody detail".to_owned(),
    }
}

/// The canonical URL [`node_binding_json_for`] binds.
#[cfg(feature = "server")]
pub const FIXTURE_NODE_URL: &str = "wss://node.example.org/scp/v1";

/// Runs `09-security-model.md` §9.6.3 steps 1 to 3 against an instance's
/// storage and returns the binding's canonical JSON for
/// [`FIXTURE_NODE_URL`].
///
/// It does what an operator does before it starts a bound node: draws the
/// node key a start would draw, has the node sign `possession_sig` as its
/// local `sign-binding` command does, and signs `operator_sig` with a fixed
/// operator key.
///
/// # Errors
///
/// The step that failed, as text.
#[cfg(feature = "server")]
pub async fn node_binding_json_for(
    storage: &crate::server::InstanceStorage,
) -> Result<String, String> {
    use crate::server::InstanceStorage;
    match storage {
        InstanceStorage::InMemoryEncrypted(s) => binding_json_on(std::sync::Arc::clone(s)).await,
        InstanceStorage::Sqlite(s) => binding_json_on(std::sync::Arc::clone(s)).await,
    }
}

#[cfg(feature = "server")]
async fn binding_json_on<S: scp_platform::EncryptedStorage>(storage: S) -> Result<String, String> {
    use scp_crypto::p256::{P256SecretKey, sign_prehash_rfc6979};
    use scp_node::node_key;

    let repository = scp_core::store::ProtocolRepository::new(storage);
    node_key::load_or_generate(&repository)
        .await
        .map_err(|e| format!("draw the node key: {e}"))?;
    let operator = scp_did::Identifier::from_bytes([0x0a; 32]);
    let key_state_head = [0x0b; 32];
    let url = scp_did::NodeUrl::new(FIXTURE_NODE_URL).map_err(|e| e.to_string())?;
    let grant = node_key::sign_possession(&repository, &operator, &url, &key_state_head)
        .await
        .map_err(|e| format!("sign possession: {e}"))?;
    let mut binding = scp_protocol::node::NodeBinding {
        operator,
        node_key: grant.node_key,
        url_hash: grant.url_hash,
        key_state_head,
        operator_sig: [0; 64],
        possession_sig: grant.possession_sig,
    };
    let operator_key = P256SecretKey::from_scalar_bytes(&[0x0c; 32]).map_err(|e| e.to_string())?;
    binding.operator_sig =
        sign_prehash_rfc6979(&operator_key, &binding.digest()).map_err(|e| e.to_string())?;
    let json = binding.to_canonical_json().map_err(|e| e.to_string())?;
    String::from_utf8(json).map_err(|e| e.to_string())
}
