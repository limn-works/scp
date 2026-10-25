//! Centralized SCP error code constants for all FFI bridges.
//!
//! Each error code follows the format `SCP-{CATEGORY}-{NUMBER}` where:
//! - `CATEGORY` identifies the subsystem (IDENT, CTX, PERM, CRYPTO, etc.)
//! - `NUMBER` falls within the allocated range for that category
//!
//! Canonical ranges (from `.docs/standards/sdk-common.md`):
//!
//! | Prefix        | Range       |
//! |---------------|-------------|
//! | `SCP-IDENT-`  | 1000--1999  |
//! | `SCP-CTX-`    | 2000--2999  |
//! | `SCP-PERM-`   | 3000--3999  |
//! | `SCP-CRYPTO-` | 4000--4999  |
//! | `SCP-TRANS-`  | 5000--5999  |
//! | `SCP-OUTLET-`   | 6000--6999  |
//! | `SCP-VALID-`  | 7000--7999  |
//! | `SCP-STORAGE-`| 8000--8999  |
//! | `SCP-ATTEST-` | 9000--9999  |
//! | `SCP-MCP-`    | 10000--10999|
//! | `SCP-GOV-`    | 11000--11999|
//! | `SCP-ECON-`   | 12000--12999|
//!
//! All FFI bridges (`PyO3`, napi-rs, `UniFFI`) import these constants
//! instead of defining error code strings locally. This eliminates
//! cross-bridge divergence and makes error code auditing trivial.
//!
//! # Uniqueness rule
//!
//! Every code number has exactly ONE meaning, defined by exactly ONE
//! constant in this file, and the doc-comment on that constant is
//! normative. Never re-label an existing constant's doc-comment to a new
//! purpose and never emit an existing code for a different purpose from
//! any layer (bridge or SDK wrapper) — codes already in this registry are
//! taken even if no Rust code currently emits them (they may be emitted
//! from SDK wrappers, e.g. Swift). New purposes get NEW numbers from the
//! next free run in the band. `scripts/check-error-codes.sh` enforces
//! that no code literal is defined twice in this file; cross-layer
//! purpose drift must be caught in review against these doc-comments.

// -------------------------------------------------------------------------
// Identity (SCP-IDENT- 1000--1999)
// -------------------------------------------------------------------------

/// Generic identity error.
pub const IDENT_1000: &str = "SCP-IDENT-1000";
/// Identity operation failed (generic identity error category).
///
/// Also the code surfaced when an identity is not registered / has no retained
/// state on the bridge instance: the registry-miss path that the NAPI and
/// `PyO3` bridges take in `with_identity` / `with_identity_mut` when the DID was
/// never created on this bridge. For registry-based key resolution this is where
/// missing signing custody manifests, in contrast to the handle-borne
/// `IDENT_1017` (see sdk-common.md).
pub const IDENT_1001: &str = "SCP-IDENT-1001";
/// Identity not found.
pub const IDENT_1002: &str = "SCP-IDENT-1002";
/// `"os_keystore"` custody requested with no `KeyCustodyProvider` (spec 03
/// §3.2.2).
///
/// The `PyO3`, NAPI and `UniFFI` bridges return this code only for
/// `"os_keystore"` with no provider, through
/// [`crate::custody_request::parse_custody_request`]; the caller passes the
/// provider through `identity_create_with_custody`. A `testing_seed` passed
/// with the request is reported first, as [`VALID_7009`].
pub const IDENT_1003: &str = "SCP-IDENT-1003";
/// Identity key generation failed.
pub const IDENT_1004: &str = "SCP-IDENT-1004";
/// Identity resolution failed.
pub const IDENT_1005: &str = "SCP-IDENT-1005";
/// Identity rotation failed.
pub const IDENT_1006: &str = "SCP-IDENT-1006";
/// Identity migration failed.
pub const IDENT_1007: &str = "SCP-IDENT-1007";
/// Identity load failed.
pub const IDENT_1008: &str = "SCP-IDENT-1008";
/// Identity storage error.
pub const IDENT_1009: &str = "SCP-IDENT-1009";
/// `UniFFI` identity create error.
pub const IDENT_1010: &str = "SCP-IDENT-1010";
/// `UniFFI` identity load error.
pub const IDENT_1011: &str = "SCP-IDENT-1011";
/// `UniFFI` identity resolve error.
pub const IDENT_1012: &str = "SCP-IDENT-1012";
/// DID method or format invalid.
///
/// Distinct from `IDENT_1004` (key generation failure) which is a
/// runtime / cryptographic error category. `IDENT_1014` is for
/// input-validation failures: unsupported DID method prefix, invalid
/// `z`-base-32 payload, non-canonical multibase encoding, payload
/// length wrong for the declared key type, or decoded bytes that fail
/// curve-point validation.
pub const IDENT_1014: &str = "SCP-IDENT-1014";
/// Device attestation unavailable — no production backend wired yet.
///
/// Surfaced by the shipped (no-`testing`) device-attestation *attest* surface
/// on every bridge — the `PyO3` `identity_attest_device` method, the NAPI
/// `identity_attest_device` method, the `UniFFI` `identity_attest_device_impl`
/// (dispatched from `Scp::identity_attest_device`), and the Python SDK shim.
/// Each resolves the identity against its instance registry, then fails closed:
/// no production device-attestation backend is wired yet. Apple App Attest /
/// Google Play Integrity are hardware/platform-backed and are intentionally
/// deferred (with hardware keychain custody) until an e2e-driven integration
/// lands. Per spec §9:187 device attestation is an optional trust signal whose
/// absence is expected and non-penalizing, so this is an honest-absent error,
/// not a silently-valid attestation. See ADR-025 and #2171.
pub const IDENT_1015: &str = "SCP-IDENT-1015";
/// Device attestation verification unavailable — no production backend wired yet.
///
/// Surfaced by the shipped (no-`testing`) device-attestation *verify* surface
/// on every bridge — the `PyO3` `identity_verify_device_attestation` free
/// `#[pyfunction]`, the NAPI `identity_verify_device_attestation` method, the
/// `UniFFI` `identity_verify_device_attestation_impl` (dispatched from the
/// `identity_verify_device_attestation` free fn), and the Python SDK shim.
/// Each fails closed: no production device-attestation backend is wired yet
/// (App Attest / Play Integrity are hardware/platform-backed and intentionally
/// deferred with hardware keychain custody). Returns this honest-absent error
/// rather than a silently-valid result (spec §9:187). See ADR-025 and #2171.
pub const IDENT_1016: &str = "SCP-IDENT-1016";
/// Operation requires retained signing custody, which this identity/handle
/// lacks.
///
/// Surfaced by operations that must sign with a creator/identity key (UCAN
/// mint, event-log checkpoint, broadcast publish) when an identity was loaded
/// externally with no retained custody, or when a custody/handle is sign-only
/// without needed key material. Distinct from `IDENT_1001` (identity not
/// registered). UCAN delegate surfaces `IDENT_1001` on every bridge, because
/// `PyO3`, NAPI, and `UniFFI` all read a delegator's key from their identity
/// registry — see sdk-common.md.
pub const IDENT_1017: &str = "SCP-IDENT-1017";
/// Recovery ownership rejection.
///
/// `identity_execute_recovery` was called for a DID that is not owned by this
/// SCP instance (absent from the bridge's identity/custody registry). Recovery
/// is restricted to identities registered on this instance (ADR-048 §7).
/// Distinct from `IDENT_1021` — a well-formed request whose compromise tier is
/// unrecognized.
pub const IDENT_1020: &str = "SCP-IDENT-1020";
/// Invalid compromise tier.
///
/// `identity_execute_recovery` was called with a tier string that is not one of
/// `agent`, `active_signing`, or `identity_key`. A caller-input error, kept
/// distinct from `IDENT_1020` (a valid tier for a DID this instance does not
/// own) so callers can tell "wrong instance" from "bad tier".
pub const IDENT_1021: &str = "SCP-IDENT-1021";
/// Recovery fail-closed (no configured backend).
///
/// `identity_execute_recovery` has no configured backend (the §9.12 WIRE is
/// #2240 Part B), so — after passing the ownership/tier gates — it returns this
/// typed error rather than fabricating a success. Recovery never silently
/// succeeds.
pub const IDENT_1022: &str = "SCP-IDENT-1022";
/// Identity agent key validation.
pub const IDENT_1023: &str = "SCP-IDENT-1023";
/// Custody-migration rejection.
///
/// `identity_execute_custody_migration` was rejected because either the DID is
/// not owned by this SCP instance (ownership check, ADR-048 §7) or the
/// requested migration target was not one of `platform_managed`, `hardware`,
/// `software`, or `in_memory`.
pub const IDENT_1024: &str = "SCP-IDENT-1024";
/// Identity custody error.
pub const IDENT_1025: &str = "SCP-IDENT-1025";
/// Identity DID method error.
pub const IDENT_1026: &str = "SCP-IDENT-1026";
/// Identity DHT publish error.
pub const IDENT_1027: &str = "SCP-IDENT-1027";
/// Identity key handle error.
pub const IDENT_1028: &str = "SCP-IDENT-1028";
/// SCPID challenge expired.
pub const IDENT_1030: &str = "SCP-IDENT-1030";
/// SCPID audience mismatch.
pub const IDENT_1031: &str = "SCP-IDENT-1031";
/// SCPID timestamp invalid.
pub const IDENT_1032: &str = "SCP-IDENT-1032";
/// SCPID DID resolution failed.
pub const IDENT_1033: &str = "SCP-IDENT-1033";
/// SCPID key not authorized.
pub const IDENT_1034: &str = "SCP-IDENT-1034";
/// SCPID signature invalid.
pub const IDENT_1035: &str = "SCP-IDENT-1035";
/// SCPID DID document stale.
pub const IDENT_1036: &str = "SCP-IDENT-1036";
/// SCPID signing failed.
pub const IDENT_1037: &str = "SCP-IDENT-1037";
/// SCPID invalid input.
pub const IDENT_1038: &str = "SCP-IDENT-1038";
/// Identity attestation create.
pub const IDENT_1040: &str = "SCP-IDENT-1040";
/// Identity attestation verify.
pub const IDENT_1041: &str = "SCP-IDENT-1041";
/// Identity attestation revoke.
pub const IDENT_1042: &str = "SCP-IDENT-1042";
/// Identity attestation status.
pub const IDENT_1043: &str = "SCP-IDENT-1043";
/// Identity attestation query.
pub const IDENT_1044: &str = "SCP-IDENT-1044";
/// Identity attestation list.
pub const IDENT_1045: &str = "SCP-IDENT-1045";
/// SCPID unbound closure invoked directly.
///
/// Construct an SCP-backed closure via `SCP.scpidSign` /
/// `SCP.scpidChallenge` / `SCP.scpidVerify`. Only surfaced by the Swift
/// SDK's `ScpId.unboundSign` / `unboundChallenge` / `unboundVerify`
/// stubs when a caller invokes them directly instead of passing an
/// `SCP`-bound closure.
pub const IDENT_1046: &str = "SCP-IDENT-1046";

// -----------------------------------------------------------------------
// Pre-rotation custody errors (one code per PreRotationCustodyError variant)
//
// Surfaced when `IdentityError::PreRotation(_)` crosses the FFI boundary.
// SDK consumers can match on `.code` to distinguish a missing handle from
// a substrate-unavailable backend, a user-declined biometric, an internal
// storage error, a callback malformation, or a commitment-integrity
// failure — without string-matching the message body.
// -----------------------------------------------------------------------

/// Pre-rotation custody handle not found in the backing store.
pub const IDENT_1047: &str = "SCP-IDENT-1047";
/// Pre-rotation custody substrate temporarily unavailable
/// (hardware not connected, network unreachable, etc.).
pub const IDENT_1048: &str = "SCP-IDENT-1048";
/// Pre-rotation custody operation declined by user (biometric refusal,
/// passkey cancellation, etc.).
pub const IDENT_1049: &str = "SCP-IDENT-1049";
/// Pre-rotation custody internal storage error.
pub const IDENT_1050: &str = "SCP-IDENT-1050";
/// Pre-rotation custody callback returned an invalid response
/// (malformed handle, length mismatch, schema violation, etc.).
pub const IDENT_1051: &str = "SCP-IDENT-1051";
/// Pre-rotation custody commitment-integrity failure: revealed public key
/// did not match the stored commitment. Indicates a substrate-level
/// tampering or corruption event.
pub const IDENT_1052: &str = "SCP-IDENT-1052";

/// `DidDht::migrate_identity` partial-publish failure.
///
/// Surfaced when one of `migrate_identity`'s two DHT publishes (step 7
/// publish-new or step 8 republish-old-with-alsoKnownAs) fails AFTER the
/// irreversible cold-custody mutation in step 5
/// (`PreRotationCustody::destroy_after_migration`). The caller cannot
/// recover by re-invoking `migrate_identity` — the OLD pre-rotation
/// handle is gone. The Rust core returns
/// `IdentityError::MigrationPublishFailed` carrying a typed
/// `MigrationPartialState` recovery handle; the structured FFI surface
/// for that handle is added in subsequent PRs (per ADR-048 §7 per-SDK
/// idiom). Phase-1 surface is JUST this code + the error message body.
pub const IDENT_1053: &str = "SCP-IDENT-1053";

// -----------------------------------------------------------------------
// Per-context pseudonym derivation errors (§9.10.4).
//
// Surfaced by all native bridges (PyO3, napi-rs, UniFFI) on the
// context_create / context_join / context_import lifecycle entry points
// when deriving the caller's per-member routing pseudonym from custody-held
// identity key material. Encrypted / pseudonymous contexts hard-fail on
// derivation error; broadcast contexts (spec §5.14) skip derivation entirely.
// A custody failure during derivation is not a pseudonym error: it carries
// the code `custody_failure_code` assigns.
// -----------------------------------------------------------------------

/// Pseudonym derivation: identity missing core key material.
pub const IDENT_1054: &str = "SCP-IDENT-1054";
/// A host-derived pseudonym the bridge rejects.
///
/// The bridge rejects a malformed key id or point, a `get_public_key(key_id)`
/// that fails with any code or returns a different point, or a key id already
/// bound to another point (ADR-021 2026-09-27 amendment). Custody failures of
/// the derive call itself carry the code [`custody_failure_code`] assigns.
pub const IDENT_1055: &str = "SCP-IDENT-1055";
/// Pseudonym derivation: no custody provider available.
pub const IDENT_1056: &str = "SCP-IDENT-1056";

/// Production DHT client initialization failed.
///
/// Surfaced by all native bridges (`PyO3`, napi-rs, `UniFFI`) when the shipped
/// Mainline Pkarr DHT client cannot be built — a malformed gateway URL or a
/// Pkarr build failure (`DhtInitError` from
/// [`crate::dht::build_ffi_dht_client`]). This is the fail-closed DHT
/// path (ADR-062 §Decision 1 / spec §17.17.3): construction NEVER substitutes an
/// in-memory or no-op client. Distinct from `IDENT_1001` (the generic /
/// registry-miss code) so SDK consumers can tell a DHT-init failure apart from
/// an identity that was never registered on this bridge.
pub const IDENT_1058: &str = "SCP-IDENT-1058";

/// No production pre-rotation custody backend is available (FAIL CLOSED).
///
/// Surfaced by all native bridges (`PyO3`, napi-rs, `UniFFI`) and `scp-node`
/// when a production identity-creation path is invoked on a shipped (no-`testing`)
/// build. Every identity commits a pre-rotation commitment at creation (spec
/// §9.7.4.1 item 5(a)), which requires a `PreRotationCustody` backend; the
/// only implementation that exists today is the in-memory test nullifier
/// (`InMemoryPreRotationCustody`), now gated to the test harness only (ADR-062
/// §Decision 6). Rather than silently mint the nullifier (which would ship a
/// false durability guarantee — AGENTS.md builder tenet "No dev/test-only
/// stand-ins in production"), creation fails closed with this typed code. Maps
/// from [`scp_identity::IdentityError::NoPreRotationBackend`]. A real, persistent
/// pre-rotation backend is tracked by #1729 / RFC #2130; non-committing creation
/// (Option A) is out of scope (Discussion #1553).
pub const IDENT_1059: &str = "SCP-IDENT-1059";

/// Identity-link attestation verification could not resolve an issuer's DID
/// document, or ran on a surface that reaches no DID resolver (FAIL CLOSED).
///
/// Surfaced by all native bridges (`PyO3`, napi-rs, `UniFFI`). Spec §3.5.4
/// step 1 makes resolution of an issuer's DID document a precondition of every
/// later step, so a bridge that cannot resolve cannot decide whether an
/// attestation is genuine. Reporting `false` would say "forged" about an
/// attestation nobody checked, so a bridge raises this code instead. Two
/// callers meet it:
///
/// 1. A per-instance `verify_link_attestation` whose resolver returned no
///    document, or reported a network fault, for an issuer's DID.
/// 2. A module-level `identity_verify_link_attestation` free function, which
///    reaches no bridge instance and therefore no DID resolver at all (phase D,
///    pull request #1695, deleted every process-wide default bridge instance).
///    Every caller of that free function moves to a per-instance
///    `verify_link_attestation` method on `SCP`.
///
/// Distinct from `IDENT_1006` (a DID resolution failure a caller asked for
/// directly) so an SDK consumer can tell an attestation-verification
/// precondition failure apart from a plain resolve call that failed.
pub const IDENT_1060: &str = "SCP-IDENT-1060";

/// Identity-link attestation verification found an issuer publishing an
/// attestation revocation list that no bridge reads (FAIL CLOSED).
///
/// Spec §3.5.2 states: "Verifiers check revocation by resolving the issuer's
/// DID document and looking for an `AttestationRevocations` service endpoint
/// (§18.2.2). The endpoint returns a list of revoked attestation IDs." Spec
/// §3.5.2 further states that the endpoint check "is ALWAYS required regardless
/// of `revocation_status` value", because a holder who keeps an
/// `Active`-signed copy replays it after an issuer revokes it. No bridge
/// fetches that endpoint, so a bridge that resolves a document publishing one
/// cannot conclude an attestation is unrevoked and raises this code instead of
/// answering `true`.
///
/// A caller that meets this code fetches that endpoint itself, checks whether
/// it lists this attestation's `id`, and decides. A caller cannot suppress this
/// code by supplying different arguments, because an issuer's own DID document
/// decides whether it applies.
///
/// Distinct from [`IDENT_1060`] (an issuer's document could not be resolved at
/// all) so an SDK consumer can tell "no document" apart from "a document whose
/// revocation list this bridge does not read".
pub const IDENT_1061: &str = "SCP-IDENT-1061";

/// Identity-link attestation verification reached a class 2 (Reference)
/// attestation whose external proof resource nobody fetched (FAIL CLOSED).
///
/// Spec §3.5.4 Class 2 step 2 has a verifier fetch a `signed_post` URL or query
/// a `dns_record` TXT record and confirm an issuer's DID appears in it. No
/// bridge performs that fetch, so each bridge's verify method takes a
/// `reference_proof` argument naming what a caller did about it. This code
/// reports the `"not_fetched"` case: spec §3.5.4 Class 2 step 3 states the
/// attestation "is unverified. Treat as if the attestation does not exist for
/// trust evaluation. Do not cache a negative result." Answering `false` would
/// hand a caller exactly that negative result, and a caller reads `false` on
/// this surface as "this attestation is forged", so a bridge raises this code
/// instead.
///
/// A caller that meets this code performs that fetch itself — HTTP GET for
/// `signed_post`, DNS TXT lookup of `_scp-verify.<domain>` for `dns_record` —
/// confirms an issuer's DID appears in what it fetched, and calls again with
/// `reference_proof` reading `"confirmed"`, which yields a verdict. A caller
/// whose fetch failed or found nothing keeps `"not_fetched"` and treats this
/// code as "not yet verified" rather than caching a rejection.
///
/// Distinct from [`IDENT_1060`] and [`IDENT_1061`]: a signature already
/// verified under a key an issuer's DID document publishes, so what remains
/// unchecked is an external resource rather than an issuer's document.
pub const IDENT_1062: &str = "SCP-IDENT-1062";

/// The operator identity is not available to a starting node.
///
/// The identity a node start config names is not registered on this `SCP`
/// instance, or the core node's identity operation failed (sdk-common.md
/// §"Node start error codes").
pub const IDENT_1063: &str = "SCP-IDENT-1063";

/// An identity-creating SDK entry received no custody argument (FAIL CLOSED).
///
/// Raised by the Python and TypeScript SDK wrappers, never by a bridge, before
/// any bridge call: `identity_create` / `identityCreate`,
/// `identity_create_with_agent_key` / `identityCreateWithAgentKey`, and
/// `identity_create_with_custody` / `identityCreateWithCustody` raise it when an
/// untyped caller passes nothing, `None`, `null`, or `undefined` where the
/// custody belongs. Which key store holds an identity's private key decides who
/// can reach that key, so no SDK picks one for the caller (SCP-294). Typed
/// callers meet the omission as a type-checker error instead.
///
/// Sits in the `SCP-IDENT-1100`..`1199` sub-block (`sdk-common.md` §Error code
/// format), at the number the key-event-log workstream allocated for it.
pub const IDENT_1116: &str = "SCP-IDENT-1116";

// -------------------------------------------------------------------------
// Context (SCP-CTX- 2000--2999)
// -------------------------------------------------------------------------

/// Generic context error.
pub const CTX_2000: &str = "SCP-CTX-2000";
/// Context operation failed.
pub const CTX_2001: &str = "SCP-CTX-2001";
/// Context not found.
pub const CTX_2002: &str = "SCP-CTX-2002";
/// Context already exists.
pub const CTX_2003: &str = "SCP-CTX-2003";
/// Context creation failed.
pub const CTX_2004: &str = "SCP-CTX-2004";
/// Context join failed.
pub const CTX_2005: &str = "SCP-CTX-2005";
/// Context leave failed.
pub const CTX_2006: &str = "SCP-CTX-2006";
/// Context send failed.
pub const CTX_2007: &str = "SCP-CTX-2007";
/// Context receive failed.
pub const CTX_2008: &str = "SCP-CTX-2008";
/// Context mode error.
pub const CTX_2011: &str = "SCP-CTX-2011";
/// Context manager error.
pub const CTX_2012: &str = "SCP-CTX-2012";
/// Context member error.
pub const CTX_2013: &str = "SCP-CTX-2013";
/// Context governance error.
pub const CTX_2014: &str = "SCP-CTX-2014";
/// Context TTL error.
pub const CTX_2015: &str = "SCP-CTX-2015";
/// Context TTL extension error.
pub const CTX_2016: &str = "SCP-CTX-2016";
/// Context broadcast error.
pub const CTX_2017: &str = "SCP-CTX-2017";
/// Context broadcast subscribe error.
pub const CTX_2018: &str = "SCP-CTX-2018";
/// Context broadcast publish error.
pub const CTX_2019: &str = "SCP-CTX-2019";
/// Context broadcast block error.
pub const CTX_2020: &str = "SCP-CTX-2020";
/// Context query error.
pub const CTX_2021: &str = "SCP-CTX-2021";
/// Context drain events error.
pub const CTX_2022: &str = "SCP-CTX-2022";
/// Context broadcast key request error.
pub const CTX_2023: &str = "SCP-CTX-2023";
/// Context governance action error.
pub const CTX_2024: &str = "SCP-CTX-2024";
/// Context broadcast unsubscribe error.
pub const CTX_2025: &str = "SCP-CTX-2025";
/// Context broadcast admission error.
pub const CTX_2026: &str = "SCP-CTX-2026";
/// Context broadcast subscriber count error.
pub const CTX_2027: &str = "SCP-CTX-2027";
/// Context broadcast subscriber check error.
pub const CTX_2028: &str = "SCP-CTX-2028";
/// Context member count.
pub const CTX_2030: &str = "SCP-CTX-2030";
/// Context member check.
pub const CTX_2031: &str = "SCP-CTX-2031";
/// Context member DIDs.
pub const CTX_2032: &str = "SCP-CTX-2032";
/// Context member role.
pub const CTX_2033: &str = "SCP-CTX-2033";
/// Context member role operation.
pub const CTX_2034: &str = "SCP-CTX-2034";
/// Context TTL reset error.
pub const CTX_2035: &str = "SCP-CTX-2035";
/// Context TTL propose error.
pub const CTX_2036: &str = "SCP-CTX-2036";
/// Context TTL handle error.
pub const CTX_2037: &str = "SCP-CTX-2037";
/// Context handle TTL expiry error.
pub const CTX_2038: &str = "SCP-CTX-2038";
/// Context handle governance timeout.
pub const CTX_2039: &str = "SCP-CTX-2039";
/// Context operation error.
pub const CTX_2040: &str = "SCP-CTX-2040";
/// Context governance error.
pub const CTX_2041: &str = "SCP-CTX-2041";
/// Context TTL error.
pub const CTX_2042: &str = "SCP-CTX-2042";
/// Context broadcast error.
pub const CTX_2043: &str = "SCP-CTX-2043";
/// Context member error.
pub const CTX_2044: &str = "SCP-CTX-2044";
/// Context drain error.
pub const CTX_2045: &str = "SCP-CTX-2045";
/// Context query error.
pub const CTX_2046: &str = "SCP-CTX-2046";
/// `UniFFI` context operation error.
pub const CTX_2050: &str = "SCP-CTX-2050";
/// `UniFFI` context create error.
pub const CTX_2051: &str = "SCP-CTX-2051";
/// `UniFFI` context join error.
pub const CTX_2052: &str = "SCP-CTX-2052";
/// `UniFFI` context close error.
pub const CTX_2053: &str = "SCP-CTX-2053";
/// `UniFFI` context leave error.
pub const CTX_2054: &str = "SCP-CTX-2054";
/// `UniFFI` context send error.
pub const CTX_2055: &str = "SCP-CTX-2055";
/// `UniFFI` relay connection error.
pub const CTX_2060: &str = "SCP-CTX-2060";
/// `UniFFI` context export error.
pub const CTX_2061: &str = "SCP-CTX-2061";
/// `UniFFI` context import error.
pub const CTX_2062: &str = "SCP-CTX-2062";
/// `UniFFI` context receive error.
pub const CTX_2063: &str = "SCP-CTX-2063";
/// `UniFFI` context governance error.
pub const CTX_2064: &str = "SCP-CTX-2064";
/// `UniFFI` context TTL error.
pub const CTX_2065: &str = "SCP-CTX-2065";
/// `UniFFI` context broadcast error.
pub const CTX_2066: &str = "SCP-CTX-2066";
/// `UniFFI` context query error.
pub const CTX_2070: &str = "SCP-CTX-2070";
/// `UniFFI` context member count error.
pub const CTX_2071: &str = "SCP-CTX-2071";
/// `UniFFI` context member check error.
pub const CTX_2072: &str = "SCP-CTX-2072";
/// `UniFFI` context member DIDs error.
pub const CTX_2073: &str = "SCP-CTX-2073";
/// `UniFFI` context member role error.
pub const CTX_2074: &str = "SCP-CTX-2074";
/// `UniFFI` context drain events error.
pub const CTX_2075: &str = "SCP-CTX-2075";
/// No recorded participation facts (spec §7.3.2).
///
/// The context event log is empty, so there is nothing to summarize for the
/// subject. A normal, branchable outcome — NOT a failure — so callers can
/// distinguish "no facts yet" from genuine errors (`NotInitialized`, provider
/// failures, the generic `CTX_2000` catch-all) without string-matching the
/// message. Maps from `ContextError::NoParticipationFacts`.
pub const CTX_2076: &str = "SCP-CTX-2076";
/// Snapshot import rejected: monotonic floor regression (spec §23.17).
///
/// A per-sender monotonic floor (sender-key epoch, spending nonce, etc.) would
/// regress on import. Maps from `ContextError::SnapshotFloorRegression`.
pub const CTX_2091: &str = "SCP-CTX-2091";
/// Context import rejected: structural or semantic violation.
///
/// Tampered consequence rules, forged approved-proposal entries, out-of-range
/// cooldown indices, etc. Maps from `ContextError::ImportRejected`.
pub const CTX_2092: &str = "SCP-CTX-2092";
/// Context export snapshot signature verification failed (spec §23.16.8).
///
/// A present-but-forged signature. Maps from
/// `ContextError::SnapshotSignatureInvalid`. Distinct from `CTX_2094` (the
/// format-version gate).
pub const CTX_2093: &str = "SCP-CTX-2093";
/// Context export format version unsupported (predates signed-export format).
///
/// The version gate fires before any signature is checked, so this is distinct
/// from `CTX_2093` (signature failure) — a caller can tell "old/unsupported
/// format" apart from "forged signature" (spec §23.16.8, §17.5; ADR-050). Maps
/// from `ContextError::ExportVersionUnsupported`.
pub const CTX_2094: &str = "SCP-CTX-2094";
/// Pseudonym registry empty — peers have not announced routing IDs (§9.10.4).
///
/// Maps from `ContextError::PseudonymRegistryEmpty`.
pub const CTX_2095: &str = "SCP-CTX-2095";
/// Per-member pseudonym requested for a non-pseudonymous (broadcast) context (§5.14).
///
/// Maps from `ContextError::NotPseudonymousContext`.
pub const CTX_2096: &str = "SCP-CTX-2096";
/// Actor busy (ADR-049 §10).
///
/// Maps from `ContextError::ActorBusy` in each bridge's error translator; that
/// variant's doc states its producers and retry behaviour.
pub const CTX_2130: &str = "SCP-CTX-2130";
/// Context poisoned: its actor exceeded the respawn budget (ADR-049 §10).
///
/// No longer respawned; the context is dormant until an operator clears the
/// poison (triggering a fresh respawn) or the process restarts.
///
/// Maps from `ContextError::ContextPoisoned`.
pub const CTX_2134: &str = "SCP-CTX-2134";
/// Context actor crashed and could not be respawned (ADR-049 §10).
///
/// Typically a lost or corrupt persisted snapshot. Distinct from `CTX_2134`:
/// the crash budget was not necessarily exhausted; the respawn itself was
/// impossible.
///
/// Maps from `ContextError::ActorCrashed`.
pub const CTX_2135: &str = "SCP-CTX-2135";
/// Key package single-use replay rejected by the crypto-layer consumed-init-key
/// backstop (ADR-049 §9 two-anchor single-use model).
///
/// Distinct from the generic `CTX_2001` catch-all and from `InvalidState`: a
/// caller can detect a security-relevant single-use replay (a Welcome addressed
/// to an already-consumed `KeyPackage` init key) rather than a transient state
/// mismatch.
///
/// Maps from `ContextError::KeyPackageReplay`.
pub const CTX_2136: &str = "SCP-CTX-2136";
/// Nothing to restore: a `RestoreAccess` governance action requested capabilities
/// that are not actually suspended for the member, and the member is not
/// read-excluded with read requested (§5.9).
///
/// Distinct from the generic `CTX_2001` catch-all so a caller can detect that a
/// restore was a no-op (the member already held the requested access) rather
/// than a generic context error. Mirrors native `execute_restore_access`, which
/// rejects before mutating when there is nothing to restore.
///
/// Maps from `ContextError::NothingToRestore`.
pub const CTX_2137: &str = "SCP-CTX-2137";
/// Supervisor shutting down.
///
/// The Supervisor that owns the context set its closed flag in
/// `shutdown_all_contexts`, or has dropped, so it refused to start the
/// operation (ADR-049 Decision 16, supervisor task drain). Nothing the
/// refused operation would have done has happened.
///
/// Distinct from the generic `CTX_2001` catch-all so a caller can tell an
/// operation refused by shutdown apart from a failure of the operation
/// itself. Construct a new `SCP` instance to continue.
///
/// Maps from `ContextError::SupervisorShutDown` and
/// `SagaError::SupervisorShutDown`.
pub const CTX_2138: &str = "SCP-CTX-2138";
/// Stream or streaming saga dropped unregistered by bridge shutdown.
///
/// A bridge returns this code, built by
/// [`late_registration_refusal`](crate::bridge_instance::late_registration_refusal),
/// when bridge shutdown began after the Supervisor opened an outlet stream or
/// started a streaming saga and before the bridge registered it. The operation
/// started before the refusal: its outlet handler may have run, and its pump
/// may append the stream's `OutletInvokedEvent` and settle its escrow. The
/// bridge holds no handle to the stream after the refusal.
///
/// Distinct from `CTX_2138`, whose refused operation has done nothing, so a
/// caller does not treat a started operation as one that never ran.
pub const CTX_2139: &str = "SCP-CTX-2139";
/// Sender-key distribution pending.
///
/// An encrypt under the local sender-key epoch was refused because a
/// distribution of that epoch to a current member has no accepted publish
/// (spec 09 §9.16.9 "A distribution whose publish fails", step 5). The
/// distribution stays queued, and the governance timer and a full
/// reconnection retry it; the send succeeds once a relay accepts it.
///
/// Distinct from the generic `CTX_2001` catch-all so a caller can tell a
/// send that waits on a key distribution apart from a failed send.
///
/// Maps from `ContextError::SenderKeyDistributionPending`.
pub const CTX_2140: &str = "SCP-CTX-2140";
/// Sender-key rotation pending.
///
/// An encrypt was refused because a rotation of the local sender key that a
/// membership or access change owes has not landed (spec 09 §9.16.9 "A
/// rotation that fails"). The governance timer retries the rotation; the
/// send succeeds once it lands.
///
/// Distinct from `CTX_2140`, whose rotation landed and whose distribution
/// waits on a relay.
///
/// Maps from `ContextError::SenderKeyRotationPending`.
pub const CTX_2141: &str = "SCP-CTX-2141";
/// Media context error.
pub const CTX_2500: &str = "SCP-CTX-2500";
/// Media context key export error.
pub const CTX_2501: &str = "SCP-CTX-2501";

// -------------------------------------------------------------------------
// Permission (SCP-PERM- 3000--3999)
// -------------------------------------------------------------------------

/// Generic permission error.
pub const PERM_3000: &str = "SCP-PERM-3000";
/// Permission denied.
pub const PERM_3001: &str = "SCP-PERM-3001";
/// Insufficient capabilities.
pub const PERM_3002: &str = "SCP-PERM-3002";
/// Capability delegation error.
pub const PERM_3003: &str = "SCP-PERM-3003";
/// Capability ceiling exceeded.
///
/// Reserved; no active producer. The bridge sites that emitted it for the
/// missing-signing-custody condition now use `IDENT_1017`. The semantic name is
/// retained for the capability-ceiling-exceeded condition should producers be
/// reintroduced.
pub const PERM_3004: &str = "SCP-PERM-3004";
/// Role assignment error.
pub const PERM_3005: &str = "SCP-PERM-3005";
/// UCAN token invalid.
pub const PERM_3006: &str = "SCP-PERM-3006";
/// UCAN token expired.
pub const PERM_3007: &str = "SCP-PERM-3007";
/// UCAN token revoked.
pub const PERM_3008: &str = "SCP-PERM-3008";
/// Provenance permission: signer not context member.
pub const PERM_3010: &str = "SCP-PERM-3010";
/// Provenance permission: signer role insufficient.
pub const PERM_3011: &str = "SCP-PERM-3011";
/// Provenance permission: capability check failed.
pub const PERM_3012: &str = "SCP-PERM-3012";
/// UCAN permission: issuer not authorized.
///
/// Reserved; no active producer. The bridge sites that emitted it for the
/// missing-signing-custody condition now use `IDENT_1017`. The semantic name is
/// retained for the issuer-not-authorized condition should producers be
/// reintroduced.
pub const PERM_3020: &str = "SCP-PERM-3020";
/// UCAN permission: audience mismatch.
///
/// Reserved; no active producer. UCAN audience-mismatch
/// (`UcanError::AudienceMismatch`) is currently classified as `PERM_3001` by
/// `ucan_errors::ucan_error_code`. The semantic name is retained for the
/// audience-mismatch condition should producers be reintroduced.
pub const PERM_3021: &str = "SCP-PERM-3021";
/// UCAN permission: delegation chain invalid.
///
/// Reserved; no active producer. The bridge sites that emitted it for the
/// missing-signing-custody condition now use `IDENT_1017`. UCAN
/// delegation-chain failures (`UcanError::DelegationChainBroken`) are currently
/// classified as `PERM_3001` by `ucan_errors::ucan_error_code`. The semantic
/// name is retained for the delegation-chain-invalid condition should producers
/// be reintroduced.
pub const PERM_3022: &str = "SCP-PERM-3022";
/// Reserved; no active producer.
///
/// Formerly overloaded by the NAPI bridge for the missing-signing-custody
/// condition (now `IDENT_1017`). Genuine UCAN nonce replay
/// (`UcanError::NonceReused`) is classified as `PERM_3001` by
/// `ucan_errors::ucan_error_code`.
pub const PERM_3023: &str = "SCP-PERM-3023";
/// Handle affinity violation — handle from a different SCP instance.
pub const PERM_3030: &str = "SCP-PERM-3030";

// -------------------------------------------------------------------------
// Crypto (SCP-CRYPTO- 4000--4999)
// -------------------------------------------------------------------------

/// Generic crypto error.
pub const CRYPTO_4001: &str = "SCP-CRYPTO-4001";
/// MLS group error.
pub const CRYPTO_4002: &str = "SCP-CRYPTO-4002";
/// Encryption failed.
pub const CRYPTO_4003: &str = "SCP-CRYPTO-4003";
/// Decryption failed.
pub const CRYPTO_4004: &str = "SCP-CRYPTO-4004";
/// Key not found: the key handle is unknown or its key was destroyed.
///
/// Every native bridge reports `PlatformError::KeyNotFound` with this code,
/// and a host custody callback signals key-not-found by failing with it; the
/// bridge maps a host failure with any other code to a custody error
/// ([`CRYPTO_4060`]). A pseudonym whose identity was destroyed fails with this
/// code (`09-security-model.md` §9.10.4.A).
pub const CRYPTO_4006: &str = "SCP-CRYPTO-4006";
/// MLS group create error.
pub const CRYPTO_4010: &str = "SCP-CRYPTO-4010";
/// MLS proposal error.
pub const CRYPTO_4011: &str = "SCP-CRYPTO-4011";
/// MLS commit error.
pub const CRYPTO_4012: &str = "SCP-CRYPTO-4012";
/// `UniFFI` MLS group error.
pub const CRYPTO_4050: &str = "SCP-CRYPTO-4050";
/// `UniFFI` MLS encrypt error.
pub const CRYPTO_4051: &str = "SCP-CRYPTO-4051";
/// `UniFFI` MLS decrypt error.
pub const CRYPTO_4052: &str = "SCP-CRYPTO-4052";
/// `UniFFI` MLS key export error.
pub const CRYPTO_4053: &str = "SCP-CRYPTO-4053";
/// `UniFFI` sender key error.
pub const CRYPTO_4054: &str = "SCP-CRYPTO-4054";
/// `UniFFI` key generation error.
pub const CRYPTO_4055: &str = "SCP-CRYPTO-4055";
/// `UniFFI` key import error.
pub const CRYPTO_4056: &str = "SCP-CRYPTO-4056";
/// `UniFFI` key export error.
pub const CRYPTO_4057: &str = "SCP-CRYPTO-4057";
/// `UniFFI` key package error.
pub const CRYPTO_4058: &str = "SCP-CRYPTO-4058";
/// `UniFFI` HPKE error.
pub const CRYPTO_4059: &str = "SCP-CRYPTO-4059";
/// Key custody error: a key custody provider, or a host's custody callback,
/// failed for a reason that has no more specific code.
///
/// [`custody_failure_code`] decides which custody failures carry this code.
pub const CRYPTO_4060: &str = "SCP-CRYPTO-4060";
/// Unsupported platform operation.
///
/// The backend does not support an optional operation
/// (`PlatformError::Unsupported`), such as an HSM-backed custody
/// asked for an extractable Ed25519 seed or a signature it cannot make.
pub const CRYPTO_4061: &str = "SCP-CRYPTO-4061";
/// Key custody timeout: a custody sign did not answer within the ADR-049
/// Decision 7a signing budget ([`CustodyFailureKind::TimedOut`](scp_crypto::CustodyFailureKind::TimedOut)).
///
/// Not a transport timeout: an unanswered biometric prompt or host callback is
/// not a retryable network fault.
pub const CRYPTO_4062: &str = "SCP-CRYPTO-4062";
/// No key custody is registered for the identity's wrapping key (spec 09
/// §9.16.1), so the invitation cannot be opened and no `KeyPackage` can carry
/// the key.
///
/// Maps from `ContextError::WrappingKeyCustodyUnavailable`.
pub const CRYPTO_4063: &str = "SCP-CRYPTO-4063";
/// The stored wrapping key handle is not held by the identity's custody, or
/// the custody's public key differs from the recorded one (spec 09 §9.16.1).
///
/// Maps from `ContextError::WrappingKeyHandleInvalid`.
pub const CRYPTO_4064: &str = "SCP-CRYPTO-4064";
/// The `KeyPackage` owner's `#active` key does not resolve, so a `KeyPackage`
/// attestation (spec 09 §9.7.1) can be neither signed nor checked.
///
/// Maps from `ContextError::AttestationSignerActiveKeyUnresolved`.
pub const CRYPTO_4065: &str = "SCP-CRYPTO-4065";
/// The handle offered to sign a `KeyPackage` attestation is not the owner's
/// resolved `#active` key (spec 09 §9.7.1); nothing was minted.
///
/// Maps from `ContextError::AttestationSignerNotActiveKey`.
pub const CRYPTO_4066: &str = "SCP-CRYPTO-4066";
/// A `KeyPackage` the inviter checks (spec 09 §9.7.1) is rejected.
///
/// It does not validate, its credential names another identity, it carries no
/// `0xFF01` or no `0xFF03`, its `0xFF01` is not a P-256 point, or its
/// attestation does not verify against the owner's resolved `#active` key
/// (including an attestation naming another role). A joiner's own reserved
/// `KeyPackage` that fails at join reports this code too.
///
/// Maps from `ContextError::InvalidKeyPackage`.
pub const CRYPTO_4067: &str = "SCP-CRYPTO-4067";

// -------------------------------------------------------------------------
// Transport (SCP-TRANS- 5000--5999)
// -------------------------------------------------------------------------

/// Generic transport error.
pub const TRANS_5001: &str = "SCP-TRANS-5001";
/// Transport connection failed.
pub const TRANS_5002: &str = "SCP-TRANS-5002";
/// Transport send failed.
pub const TRANS_5003: &str = "SCP-TRANS-5003";
/// Transport receive failed.
pub const TRANS_5004: &str = "SCP-TRANS-5004";
/// Transport subscription error.
pub const TRANS_5010: &str = "SCP-TRANS-5010";
/// Transport subscription already active.
pub const TRANS_5011: &str = "SCP-TRANS-5011";
/// Transport relay connect error.
pub const TRANS_5012: &str = "SCP-TRANS-5012";
/// Transport relay disconnect error.
pub const TRANS_5013: &str = "SCP-TRANS-5013";
/// Transport relay status error.
pub const TRANS_5014: &str = "SCP-TRANS-5014";
/// Transport cover traffic error.
pub const TRANS_5015: &str = "SCP-TRANS-5015";
/// Transport heartbeat error.
pub const TRANS_5016: &str = "SCP-TRANS-5016";
/// Transport checkpoint error.
pub const TRANS_5018: &str = "SCP-TRANS-5018";
/// Transport proof error.
pub const TRANS_5019: &str = "SCP-TRANS-5019";
/// MCP client `tools/list`: no client is registered under the handle.
pub const TRANS_5020: &str = "SCP-TRANS-5020";
/// MCP client `tools/list`: the handle was disconnected while the call
/// waited for the client's lock, so the call sent no request.
pub const TRANS_5021: &str = "SCP-TRANS-5021";
/// MCP client `tools/list`: the request failed on the transport, the server
/// answered with an error, or the call itself failed.
///
/// On NAPI and `UniFFI` the task running the call failed; on `PyO3` an
/// earlier call panicked while holding the client's lock, which fails every
/// later call on the handle this way until the host disconnects it.
pub const TRANS_5022: &str = "SCP-TRANS-5022";
/// MCP client `tools/call`: no client is registered under the handle.
pub const TRANS_5023: &str = "SCP-TRANS-5023";
/// MCP client `tools/call`: the handle was disconnected while the call
/// waited for the client's lock, so the call sent no request.
pub const TRANS_5024: &str = "SCP-TRANS-5024";
/// MCP client `tools/call`: the request failed on the transport, the server
/// answered with an error, or the call itself failed.
///
/// On NAPI and `UniFFI` the task running the call failed; on `PyO3` an
/// earlier call panicked while holding the client's lock, which fails every
/// later call on the handle this way until the host disconnects it.
pub const TRANS_5025: &str = "SCP-TRANS-5025";
/// Transport relay configured error.
pub const TRANS_5030: &str = "SCP-TRANS-5030";
/// `UniFFI` transport server error.
pub const TRANS_5050: &str = "SCP-TRANS-5050";
/// `UniFFI` transport bind error.
pub const TRANS_5051: &str = "SCP-TRANS-5051";
/// `UniFFI` transport TLS error.
pub const TRANS_5052: &str = "SCP-TRANS-5052";
/// `UniFFI` transport node error.
pub const TRANS_5054: &str = "SCP-TRANS-5054";
/// Node start: a dev-pair constructor (`node_start_in_memory`,
/// `node_start_local`) was called on a bridge built without its `testing`
/// feature (sdk-common.md §"Node start error codes").
pub const TRANS_5055: &str = "SCP-TRANS-5055";
/// Node start: the bridge could not wire the `SCP` instance's `Supervisor`
/// to the node it started (sdk-common.md §"Node start error codes").
pub const TRANS_5056: &str = "SCP-TRANS-5056";
/// `UniFFI` transport relay connect error.
pub const TRANS_5060: &str = "SCP-TRANS-5060";
/// `UniFFI` transport relay send error.
pub const TRANS_5061: &str = "SCP-TRANS-5061";
/// `UniFFI` transport relay receive error.
pub const TRANS_5062: &str = "SCP-TRANS-5062";
/// `UniFFI` transport relay status error.
pub const TRANS_5063: &str = "SCP-TRANS-5063";
/// `UniFFI` transport broadcast error.
pub const TRANS_5070: &str = "SCP-TRANS-5070";

// Push (ADR-006 2026-10-12 amendment): one code per
// `PlatformError::PushError` kind, assigned by [`custody_failure_code`].

/// Push wake payload invalid: a received push payload is not the platform's
/// wake signal (`PushFailureKind::WakePayloadInvalid`).
pub const TRANS_5080: &str = "SCP-TRANS-5080";
/// Push registration rejected: the relay found the registration's signature,
/// key state or encoding invalid (`PushFailureKind::RegistrationRejected`).
pub const TRANS_5081: &str = "SCP-TRANS-5081";
/// Push verifier unavailable: the relay cannot verify a registration's
/// signature yet (`PushFailureKind::VerifierUnavailable`).
pub const TRANS_5082: &str = "SCP-TRANS-5082";
/// Push platform unavailable: the relay has no push sender for the
/// registration's platform (`PushFailureKind::PlatformUnavailable`).
pub const TRANS_5083: &str = "SCP-TRANS-5083";
/// Push provider failure: the device's push provider (APNs, FCM) failed, such
/// as a failed token registration (`PushFailureKind::ProviderFailed`).
pub const TRANS_5084: &str = "SCP-TRANS-5084";

// Push wake (ADR-029 §2 push-wake pull mode step 7): one code per
// `push::WakeFailure` variant, assigned by `WakeFailure::code`.

/// Push wake failed: the instance is shut down (`WakeFailure::ShutDown`).
pub const TRANS_5085: &str = "SCP-TRANS-5085";
/// Push wake failed: the instance holds no supervisor
/// (`WakeFailure::NoSupervisor`).
pub const TRANS_5086: &str = "SCP-TRANS-5086";
/// Push wake failed: the instance holds no local member DID
/// (`WakeFailure::NoLocalIdentity`).
pub const TRANS_5087: &str = "SCP-TRANS-5087";
/// Push wake failed: restoring or reading the persisted contexts failed
/// (`WakeFailure::Restore`).
pub const TRANS_5089: &str = "SCP-TRANS-5089";
/// Push wake failed: a persisted Active context is not resident after the
/// restore (`WakeFailure::Unrestored`).
pub const TRANS_5090: &str = "SCP-TRANS-5090";
/// Push wake failed: listing the Active contexts' relays and routing IDs
/// failed (`WakeFailure::Targets`).
pub const TRANS_5091: &str = "SCP-TRANS-5091";
/// Push wake failed: a suspend or shutdown cancelled the relay dial
/// (`WakeFailure::DialCancelled`).
pub const TRANS_5092: &str = "SCP-TRANS-5092";
/// Push wake failed: one or more contexts' pulls failed (`WakeFailure::Pull`).
pub const TRANS_5093: &str = "SCP-TRANS-5093";
/// Push wake failed: the 25-second wake deadline expired with nothing
/// delivered (`WakeFailure::DeadlineExpired`).
pub const TRANS_5094: &str = "SCP-TRANS-5094";
/// Push wake context failed: the context's persisted relay set is empty
/// (`reconnect::WakePullError::NoRelays`).
pub const TRANS_5096: &str = "SCP-TRANS-5096";
/// Push wake context failed: a relay in the context's relay set was not
/// dialed (`reconnect::WakePullError::RelayUnavailable`).
pub const TRANS_5097: &str = "SCP-TRANS-5097";
/// Push wake context failed: reading the context's stored
/// `last_relay_contact` failed (`reconnect::WakePullError::ContactRead`).
pub const TRANS_5098: &str = "SCP-TRANS-5098";
/// Push wake context failed: the Phase 1 query on a relay of the context's
/// relay set failed (`reconnect::WakePullError::Query`).
pub const TRANS_5099: &str = "SCP-TRANS-5099";
/// Push wake context failed: writing the context's `last_relay_contact`
/// failed (`reconnect::WakePullError::ContactWrite`).
pub const TRANS_5100: &str = "SCP-TRANS-5100";
/// Push wake context failed: the actor reached no verdict on a blob of the
/// context's buffer (`reconnect::WakePullError::Undelivered`).
pub const TRANS_5101: &str = "SCP-TRANS-5101";
/// Reconnect context failed: no `last_relay_contact` is stored.
///
/// No tier was classified for the context and `needs_reconnect` stays set;
/// the other contexts reconnect (`reconnect::ContextReconnectResult::failure_code`).
pub const TRANS_5102: &str = "SCP-TRANS-5102";
/// Reconnect context failed: reading the stored `last_relay_contact` failed.
///
/// No tier was classified for the context and `needs_reconnect` stays set;
/// the other contexts reconnect (`reconnect::ContextReconnectResult::failure_code`).
pub const TRANS_5103: &str = "SCP-TRANS-5103";
/// Push registration unavailable: the device has no P-256 `#active` key.
///
/// `push_enable` or `push_disable` returned before it touched the provider
/// or the token (`push::PushRegistrationError::SigningKeyUnavailable`).
/// Retired once story PUSH-037 builds the registrar; never reused.
pub const TRANS_5104: &str = "SCP-TRANS-5104";
/// Push not enabled: the instance has no enabled push platform.
///
/// Returned by `push_handle_wake` on every bridge
/// (`push::WakeError::NotEnabled`).
pub const TRANS_5105: &str = "SCP-TRANS-5105";

// -------------------------------------------------------------------------
// Outlet (SCP-OUTLET- 6000--6999)
// -------------------------------------------------------------------------

/// Generic outlet error.
pub const OUTLET_6001: &str = "SCP-OUTLET-6001";
/// Outlet not found.
pub const OUTLET_6002: &str = "SCP-OUTLET-6002";
/// Outlet registration error.
pub const OUTLET_6003: &str = "SCP-OUTLET-6003";
/// Outlet invocation error.
pub const OUTLET_6004: &str = "SCP-OUTLET-6004";
/// Outlet verification error.
pub const OUTLET_6005: &str = "SCP-OUTLET-6005";
/// Outlet capability error.
pub const OUTLET_6006: &str = "SCP-OUTLET-6006";
/// Outlet interface error.
pub const OUTLET_6007: &str = "SCP-OUTLET-6007";
/// Outlet schema error.
pub const OUTLET_6008: &str = "SCP-OUTLET-6008";
/// Outlet handler error.
pub const OUTLET_6009: &str = "SCP-OUTLET-6009";
/// Outlet interface establish error.
pub const OUTLET_6010: &str = "SCP-OUTLET-6010";
/// Outlet interface query error.
pub const OUTLET_6011: &str = "SCP-OUTLET-6011";
/// Outlet interface list error.
pub const OUTLET_6012: &str = "SCP-OUTLET-6012";
/// Outlet signer error.
pub const OUTLET_6013: &str = "SCP-OUTLET-6013";
/// Outlet register error.
pub const OUTLET_6014: &str = "SCP-OUTLET-6014";
/// Outlet deregister error.
pub const OUTLET_6015: &str = "SCP-OUTLET-6015";
/// Outlet invoke capability error.
pub const OUTLET_6017: &str = "SCP-OUTLET-6017";
/// Outlet invoke schema validation error.
pub const OUTLET_6018: &str = "SCP-OUTLET-6018";
/// Outlet invoke result error.
pub const OUTLET_6019: &str = "SCP-OUTLET-6019";
/// Outlet invoke handler error.
pub const OUTLET_6020: &str = "SCP-OUTLET-6020";
/// Outlet invoke timeout error.
pub const OUTLET_6021: &str = "SCP-OUTLET-6021";
/// Outlet verify register error.
pub const OUTLET_6030: &str = "SCP-OUTLET-6030";
/// Outlet verify not found error.
pub const OUTLET_6031: &str = "SCP-OUTLET-6031";
/// Outlet verify invoke schema error.
pub const OUTLET_6032: &str = "SCP-OUTLET-6032";
/// Outlet verify invoke not found error.
pub const OUTLET_6033: &str = "SCP-OUTLET-6033";
/// Outlet verify output schema error.
pub const OUTLET_6035: &str = "SCP-OUTLET-6035";

// -------------------------------------------------------------------------
// Validation (SCP-VALID- 7000--7999)
// -------------------------------------------------------------------------

/// Generic validation error.
pub const VALID_7000: &str = "SCP-VALID-7000";
/// Input validation failed.
pub const VALID_7001: &str = "SCP-VALID-7001";
/// JSON parse error.
pub const VALID_7002: &str = "SCP-VALID-7002";
/// JSON schema validation error.
pub const VALID_7003: &str = "SCP-VALID-7003";
/// Missing required field.
pub const VALID_7004: &str = "SCP-VALID-7004";
/// Invalid field value.
pub const VALID_7005: &str = "SCP-VALID-7005";
/// Validation type error.
pub const VALID_7006: &str = "SCP-VALID-7006";
/// Validation format error.
///
/// Used for malformed or wrong-shape byte input at the FFI boundary —
/// e.g. a parity-harness `testing_seed` that is not exactly 32 bytes,
/// or a `signed_at_override` `BigInt` that cannot be represented
/// losslessly as a `u64`. Enum-like string mismatches (unknown custody
/// type, unknown transport mode) use `VALID_7005` (invalid field
/// value) instead.
pub const VALID_7007: &str = "SCP-VALID-7007";
/// Testing-only feature requires the `testing` feature flag.
///
/// Returned by `scpid_sign` when a caller supplies `signed_at_override`, an
/// ADR-046 cross-bridge parity-harness input rather than a production API,
/// in a build that was NOT compiled with the `testing` feature enabled.
///
/// A `testing_seed` on `identity_create` does not use this code: spec 03
/// §3.2.2 answers a seed with `"in_memory"` on such a build with
/// [`IDENT_1008`], through [`crate::custody_request::parse_custody_request`].
pub const VALID_7008: &str = "SCP-VALID-7008";
/// Seed requires `InMemoryKeyCustody`.
///
/// Returned when a caller passes a deterministic parity-harness `seed`
/// together with a custody type other than `"in_memory"`. Seeded
/// determinism is only meaningful for the in-process `InMemoryKeyCustody`
/// backend — `encrypted_file` and `os_keystore` custody produce keys outside the
/// seeded RNG, so accepting a seed with them would silently lie about
/// reproducibility.
pub const VALID_7009: &str = "SCP-VALID-7009";
/// UCAN token validation error.
pub const VALID_7010: &str = "SCP-VALID-7010";
/// UCAN mint validation error.
pub const VALID_7011: &str = "SCP-VALID-7011";
/// UCAN revoke validation error.
pub const VALID_7012: &str = "SCP-VALID-7012";
/// UCAN delegation validation error.
pub const VALID_7013: &str = "SCP-VALID-7013";
/// UCAN capability validation error.
pub const VALID_7014: &str = "SCP-VALID-7014";
/// UCAN nonce validation error.
pub const VALID_7015: &str = "SCP-VALID-7015";
/// UCAN audience validation error.
pub const VALID_7016: &str = "SCP-VALID-7016";
/// UCAN issuer validation error.
pub const VALID_7017: &str = "SCP-VALID-7017";
/// Event log validation error.
pub const VALID_7020: &str = "SCP-VALID-7020";
/// Event log query validation error.
pub const VALID_7021: &str = "SCP-VALID-7021";
/// Event log verify validation error.
pub const VALID_7022: &str = "SCP-VALID-7022";
/// SDK-wrapper local guard: the in-tab client is not initialized.
///
/// The caller must `await initScp()` — or use `ScpBrowserClient.connect`, which
/// awaits it — before constructing a client. Thrown TS-side by the
/// `@limn-works/scp-ts-wasm` wrapper, never minted by an FFI bridge.
pub const VALID_7025: &str = "SCP-VALID-7025";
/// SDK-wrapper local guard: a managed transport was passed to `create()`.
///
/// A `WebSocketRelaySocket` (the managed transport for `connect()`) was passed to
/// `create()`, leaving it unattached. Thrown TS-side by the
/// `@limn-works/scp-ts-wasm` wrapper, never minted by an FFI bridge.
pub const VALID_7026: &str = "SCP-VALID-7026";
/// Governance action validation error.
pub const VALID_7027: &str = "SCP-VALID-7027";
/// SDK-wrapper local guard: a second live `BrowserInvokerStreamSession`.
///
/// A second session was constructed on a `(client, contextId)` that already has
/// one (a session drains the client's whole per-context buffer, so it requires a
/// dedicated client/context). Thrown TS-side by `@limn-works/scp-ts-wasm`, never
/// by a bridge.
pub const VALID_7028: &str = "SCP-VALID-7028";
/// SDK-wrapper local guard: a stream drain was iterated re-entrantly.
///
/// A `BrowserInvokerStreamSession` drain was entered from two async contexts
/// concurrently — caller misuse, distinct from the lifecycle-closed
/// `SCP-OUTLET-6100`. Thrown TS-side by `@limn-works/scp-ts-wasm`, never by a bridge.
pub const VALID_7029: &str = "SCP-VALID-7029";
/// MCP validation error.
pub const VALID_7030: &str = "SCP-VALID-7030";
/// MCP transport validation error.
pub const VALID_7031: &str = "SCP-VALID-7031";
/// MCP handle validation error.
pub const VALID_7032: &str = "SCP-VALID-7032";
/// MCP context validation error.
pub const VALID_7033: &str = "SCP-VALID-7033";
/// MCP outlet validation error.
pub const VALID_7034: &str = "SCP-VALID-7034";
/// Outlet register input validation error.
pub const VALID_7035: &str = "SCP-VALID-7035";
/// Outlet register schema validation error.
pub const VALID_7036: &str = "SCP-VALID-7036";
/// Outlet invoke input validation error.
pub const VALID_7037: &str = "SCP-VALID-7037";
/// Outlet verify input validation error.
pub const VALID_7038: &str = "SCP-VALID-7038";
/// A challenge for a protocol capability URI carries fewer test cases than its
/// standard's minimum (spec 07 §7.3.4.3).
pub const VALID_7039: &str = "SCP-VALID-7039";
/// Event log input validation error.
pub const VALID_7040: &str = "SCP-VALID-7040";
/// Outlet verify register output validation.
pub const VALID_7041: &str = "SCP-VALID-7041";
/// Outlet verify output validation error.
pub const VALID_7042: &str = "SCP-VALID-7042";
/// Transport connect validation error.
pub const VALID_7043: &str = "SCP-VALID-7043";
/// Transport disconnect validation error.
pub const VALID_7044: &str = "SCP-VALID-7044";
/// Transport status validation error.
pub const VALID_7045: &str = "SCP-VALID-7045";
/// Transport cover traffic validation error.
pub const VALID_7046: &str = "SCP-VALID-7046";
/// Transport heartbeat validation error.
pub const VALID_7047: &str = "SCP-VALID-7047";
/// Transport checkpoint validation error.
pub const VALID_7048: &str = "SCP-VALID-7048";
/// Transport proof validation error.
pub const VALID_7049: &str = "SCP-VALID-7049";
/// DID validation error.
pub const VALID_7050: &str = "SCP-VALID-7050";
/// Context ID validation error.
pub const VALID_7051: &str = "SCP-VALID-7051";
/// Payload validation error.
pub const VALID_7052: &str = "SCP-VALID-7052";
/// Admission validation error.
pub const VALID_7053: &str = "SCP-VALID-7053";
/// Key validation error.
pub const VALID_7054: &str = "SCP-VALID-7054";
/// Participation record validation error (§7.3.2).
pub const VALID_7059: &str = "SCP-VALID-7059";
/// Discovery validation error.
pub const VALID_7060: &str = "SCP-VALID-7060";
/// Discovery member validation error.
pub const VALID_7061: &str = "SCP-VALID-7061";
/// Discovery context validation error.
pub const VALID_7062: &str = "SCP-VALID-7062";
/// Discovery register validation error.
pub const VALID_7063: &str = "SCP-VALID-7063";
/// Discovery unregister validation error.
pub const VALID_7064: &str = "SCP-VALID-7064";
/// Discovery query validation error.
pub const VALID_7065: &str = "SCP-VALID-7065";
/// Discovery probe validation error.
pub const VALID_7066: &str = "SCP-VALID-7066";
/// `check_capability_requirements`: malformed capability-requirements JSON.
pub const VALID_7073: &str = "SCP-VALID-7073";
/// `check_capability_requirements`: malformed agent-capabilities JSON.
pub const VALID_7074: &str = "SCP-VALID-7074";
/// `check_capability_requirements`: malformed challenge-verifications JSON.
pub const VALID_7075: &str = "SCP-VALID-7075";
/// `check_capability_requirements`: admission requirement unmet (missing
/// capability or challenge verification required).
pub const VALID_7076: &str = "SCP-VALID-7076";
/// `check_capability_requirements`: empty subject DID.
pub const VALID_7077: &str = "SCP-VALID-7077";
/// Attestation validation error.
pub const VALID_7080: &str = "SCP-VALID-7080";
/// SDK-wrapper local guard: no native bridge is installed.
///
/// An SDK's native loader raises it when the native bridge for the platform is
/// absent; the ts-native SDK throws it when no napi addon package resolves for
/// the platform (`src/internal/native.ts`), and the Python SDK raises it when no
/// `scp_sdk._scp_core` extension file is present (`scp_sdk/_extension.py`). It
/// is the only native-load failure a test skip guard may treat as absence. The
/// code has one meaning in every SDK that loads a native bridge, and no FFI
/// bridge mints it.
pub const VALID_7081: &str = "SCP-VALID-7081";
/// SDK-wrapper local guard: a native bridge is installed and failed to load.
///
/// The native bridge is present, and loading it failed (a `dlopen` error, an ABI
/// or architecture mismatch, a missing shared library), or it loaded without an
/// export the SDK calls. The ts-native SDK throws it from `src/internal/native.ts`
/// and `src/scp.ts`; the Python SDK raises it from `scp_sdk/__init__.py`,
/// `scp_sdk/_extension.py`, and `scp_sdk/scp.py`. The code has one meaning in
/// every SDK that loads a native bridge, and no FFI bridge mints it. A test skip
/// guard must fail on it.
pub const VALID_7082: &str = "SCP-VALID-7082";
/// Discovery announce validation error.
pub const VALID_7090: &str = "SCP-VALID-7090";
/// Discovery search validation error.
pub const VALID_7091: &str = "SCP-VALID-7091";
/// Discovery result validation error.
pub const VALID_7092: &str = "SCP-VALID-7092";
/// Trust aggregation result-parse error (Swift-SDK-emitted: the typed
/// `aggregateTrustInput` wrapper could not parse the bridge's result JSON).
pub const VALID_7093: &str = "SCP-VALID-7093";
/// Trust-admission input encoding error (Swift-SDK-emitted: the shared
/// trust-admission encoder failed to produce UTF-8 JSON).
pub const VALID_7094: &str = "SCP-VALID-7094";
/// `ParticipationProfile` byte-length validation error (Swift-SDK-emitted:
/// `eventLogRoot`/`signerPublicKey` must be 32 bytes, `signature` 64 bytes).
pub const VALID_7095: &str = "SCP-VALID-7095";
/// `ChallengeVerification` byte-length validation error (Swift-SDK-emitted:
/// `verifierSignature` must be 64 bytes).
pub const VALID_7096: &str = "SCP-VALID-7096";
/// Aggregate-trust-input byte-length validation error (Swift-SDK-emitted:
/// `EventLogEntry.prevHash` and the Merkle root must be 32 bytes,
/// `EventLogEntry.signature` 64 bytes).
pub const VALID_7097: &str = "SCP-VALID-7097";
/// Challenge verify-input byte-length validation error (Swift-SDK-emitted:
/// `ChallengeRequest`/`ChallengeResponse` `signature` must be 64 bytes).
pub const VALID_7098: &str = "SCP-VALID-7098";
/// A challenger's ledger already holds its bound of open challenges
/// ([`TrustError::ChallengeNotOpen`](scp_protocol::trust::TrustError::ChallengeNotOpen)).
pub const VALID_7099: &str = "SCP-VALID-7099";
// 7100 and 7101 are emitted by the TypeScript discovery module.
/// A challenge was answered or graded outside its signed window
/// ([`TrustError::ChallengeExpired`](scp_protocol::trust::TrustError::ChallengeExpired)).
pub const VALID_7102: &str = "SCP-VALID-7102";
/// A response's attempt number is not the next one
/// ([`TrustError::AttemptOutOfOrder`](scp_protocol::trust::TrustError::AttemptOutOfOrder)).
pub const VALID_7103: &str = "SCP-VALID-7103";
/// A response's attempt number exceeds `1 + max_retries`
/// ([`TrustError::RetriesExhausted`](scp_protocol::trust::TrustError::RetriesExhausted)).
pub const VALID_7104: &str = "SCP-VALID-7104";
/// A response arrived inside the cooldown after the previous attempt
/// ([`TrustError::CooldownActive`](scp_protocol::trust::TrustError::CooldownActive)).
pub const VALID_7105: &str = "SCP-VALID-7105";
/// The challenge is closed: passed or out of attempts.
///
/// The attempt check returns this code at begin and at commit (spec 07 §7.3.4)
/// ([`TrustError::ChallengeClosed`](scp_protocol::trust::TrustError::ChallengeClosed)).
pub const VALID_7106: &str = "SCP-VALID-7106";
/// No challenge the challenger holds answers this lookup.
///
/// No live challenge has this id, digest and subject, or a closed one graded
/// no response with this `D_r` (spec 07 §7.3.4)
/// ([`TrustError::UnknownChallenge`](scp_protocol::trust::TrustError::UnknownChallenge)).
pub const VALID_7107: &str = "SCP-VALID-7107";
/// A response does not answer its request: another challenge or digest, or
/// not one output per case in order
/// ([`TrustError::OutputsMismatch`](scp_protocol::trust::TrustError::OutputsMismatch)).
pub const VALID_7108: &str = "SCP-VALID-7108";
/// A custom evaluator outlet could not be run.
///
/// It is unregistered, has no handler, the challenger lacks call permission,
/// or the invocation failed before the handler ran
/// ([`TrustError::EvaluatorUnavailable`](scp_protocol::trust::TrustError::EvaluatorUnavailable)).
pub const VALID_7109: &str = "SCP-VALID-7109";
/// Handle/petname DID validation error.
pub const VALID_7110: &str = "SCP-VALID-7110";
/// Handle/petname alias validation error.
pub const VALID_7111: &str = "SCP-VALID-7111";
/// Handle/petname context validation error.
pub const VALID_7112: &str = "SCP-VALID-7112";
/// Handle/petname target validation error.
pub const VALID_7113: &str = "SCP-VALID-7113";
/// Handle/petname address validation error.
pub const VALID_7114: &str = "SCP-VALID-7114";
/// Petname event JSON deserialization error (malformed `PetnameEvent`).
pub const VALID_7115: &str = "SCP-VALID-7115";
/// Petname count exceeds `u32::MAX` and cannot be represented at the FFI boundary.
pub const VALID_7116: &str = "SCP-VALID-7116";
// 7117 (`evaluator_failed`) and 7118 (`budget_exceeded`) are reserved for the
// challenge case-fail reasons of those names; no error carries them, because
// at grade time each is a per-case result, not a failure of the call.
/// Handle registry lock error.
pub const VALID_7120: &str = "SCP-VALID-7120";
/// A required capability has no passing record from a trusted challenger.
///
/// The only passing record comes from a challenger the requirement does not
/// trust ([`AdmissionError::UntrustedVerifier`](scp_protocol::trust::AdmissionError::UntrustedVerifier)).
pub const VALID_7121: &str = "SCP-VALID-7121";
/// Handle registry operation error.
pub const VALID_7122: &str = "SCP-VALID-7122";
/// Handle registry query error.
pub const VALID_7123: &str = "SCP-VALID-7123";
/// Handle registry resolve error.
pub const VALID_7124: &str = "SCP-VALID-7124";
/// Handle registry list error.
pub const VALID_7125: &str = "SCP-VALID-7125";
/// Handle registry batch error.
pub const VALID_7126: &str = "SCP-VALID-7126";
/// A challenge or record names one key as both challenger and subject.
pub const VALID_7127: &str = "SCP-VALID-7127";
/// The capability's standard is not gradable by challenge
/// ([`TrustError::StandardNotGradable`](scp_protocol::trust::TrustError::StandardNotGradable)).
pub const VALID_7128: &str = "SCP-VALID-7128";
/// The capability definition a challenge cites could not be obtained
/// ([`TrustError::CapabilityDefinitionUnavailable`](scp_protocol::trust::TrustError::CapabilityDefinitionUnavailable)).
pub const VALID_7129: &str = "SCP-VALID-7129";
/// Address resolution validation error.
pub const VALID_7130: &str = "SCP-VALID-7130";
/// Address resolution parse error.
pub const VALID_7131: &str = "SCP-VALID-7131";
/// Address resolution format error.
pub const VALID_7132: &str = "SCP-VALID-7132";
/// Address resolution lookup error.
pub const VALID_7133: &str = "SCP-VALID-7133";
/// Address resolution result error.
pub const VALID_7134: &str = "SCP-VALID-7134";
/// Address resolution ambiguous error.
pub const VALID_7135: &str = "SCP-VALID-7135";
/// Address resolution reached no binding, and nobody read at least one
/// layer's data.
///
/// The criterion, per §22.8.2a of
/// `.docs/specs/22-human-readable-addressing.md`: resolution held no binding,
/// and for at least one layer no read happened at all. `VALID_7091` reports
/// the other case, where every consulted layer was read and none held a
/// binding, so a caller reads `VALID_7136` as "capability absent" and
/// `VALID_7091` as "binding absent". A caller retries `VALID_7136` against a
/// deployment holding the missing capability; retrying `VALID_7091` anywhere
/// returns the same answer.
///
/// Layers that go unread on these bridges, as evidence of what the criterion
/// admits rather than as the criterion itself: attestation reverse-lookup
/// (§22.5.1), because no bridge invokes an `attestation_lookup` outlet;
/// `.well-known/scp` domain handles (§22.6.1), because no bridge performs that
/// fetch and no bridge configures a domain; and a context handle registry this
/// bridge instance does not hold.
pub const VALID_7136: &str = "SCP-VALID-7136";
/// A signed challenge policy value lies outside a limit: outside its
/// capability definition, or looser than a requirement's retry cap.
pub const VALID_7137: &str = "SCP-VALID-7137";
/// A schema-match case's expected output was refused at challenge creation
/// ([`TrustError::SchemaRejected`](scp_protocol::trust::TrustError::SchemaRejected)).
pub const VALID_7138: &str = "SCP-VALID-7138";
/// Another grading of the same challenge holds a live lease
/// ([`TrustError::GradingInProgress`](scp_protocol::trust::TrustError::GradingInProgress)).
pub const VALID_7139: &str = "SCP-VALID-7139";
/// Recovery or custody-migration concurrency cap reached.
///
/// The NAPI bridge bounds concurrent `block_on` invocations to prevent libuv
/// worker-pool exhaustion (RED-PR5-002 / BLACK-PR5-002). Caller should back
/// off and retry.
pub const VALID_7140: &str = "SCP-VALID-7140";
/// A challenge request or response exceeds its size bound
/// ([`TrustError::ResponseTooLarge`](scp_protocol::trust::TrustError::ResponseTooLarge)).
pub const VALID_7143: &str = "SCP-VALID-7143";
/// Two capability definitions with one URI disagree
/// ([`TrustError::DefinitionEquivocation`](scp_protocol::trust::TrustError::DefinitionEquivocation)).
pub const VALID_7144: &str = "SCP-VALID-7144";
/// The challenger cannot grade now; the attempt is not used.
///
/// Every grading permit is held, or an evaluator's reserve refused the call
/// for its rate limit or budget. Resubmit the attempt
/// ([`TrustError::GradingCapacityExhausted`](scp_protocol::trust::TrustError::GradingCapacityExhausted)).
pub const VALID_7146: &str = "SCP-VALID-7146";
/// An identifier is not the canonical spelling of its key.
pub const VALID_7147: &str = "SCP-VALID-7147";
/// A context names too many capability requirements.
///
/// The limit is `MAX_CAPABILITY_REQUIREMENTS_PER_CONTEXT`
/// ([`AdmissionError::TooManyCapabilityRequirements`](scp_protocol::trust::AdmissionError::TooManyCapabilityRequirements)).
pub const VALID_7148: &str = "SCP-VALID-7148";
/// A grading's lease expired or was replaced before its commit; nothing was
/// written
/// ([`TrustError::GradingLeaseLost`](scp_protocol::trust::TrustError::GradingLeaseLost)).
pub const VALID_7149: &str = "SCP-VALID-7149";
/// A capability requirement breaks a shape rule of spec 07 §7.3.4.4
/// ([`AdmissionError::InvalidRequirement`](scp_protocol::trust::AdmissionError::InvalidRequirement)).
pub const VALID_7150: &str = "SCP-VALID-7150";
/// A challenge to this subject for this capability is inside its window.
///
/// Retry at that challenge's `expires_at`
/// ([`TrustError::ChallengeWindowOpen`](scp_protocol::trust::TrustError::ChallengeWindowOpen)).
pub const VALID_7151: &str = "SCP-VALID-7151";
/// An attempt was graded at or before its challenge's `created_at`.
///
/// Resubmit it at `created_at + 1`
/// ([`TrustError::ChallengeNotYetGradable`](scp_protocol::trust::TrustError::ChallengeNotYetGradable)).
pub const VALID_7153: &str = "SCP-VALID-7153";
/// Governance vote validation error.
pub const VALID_7216: &str = "SCP-VALID-7216";
/// Media validation error.
pub const VALID_7300: &str = "SCP-VALID-7300";
/// Media DID validation error.
pub const VALID_7301: &str = "SCP-VALID-7301";
/// Media context ID validation error.
pub const VALID_7302: &str = "SCP-VALID-7302";
/// Media configuration validation error.
pub const VALID_7303: &str = "SCP-VALID-7303";
/// Transport configure validation error.
pub const VALID_7400: &str = "SCP-VALID-7400";
/// Transport configure relay URL validation error.
pub const VALID_7401: &str = "SCP-VALID-7401";
/// Transport configure bearer token validation error.
pub const VALID_7402: &str = "SCP-VALID-7402";
/// Transport configure relay connection error.
pub const VALID_7403: &str = "SCP-VALID-7403";

// -------------------------------------------------------------------------
// Storage (SCP-STORAGE- 8000--8999)
// -------------------------------------------------------------------------

/// Storage selection required / no storage configured.
///
/// Returned when an `SCP` instance is constructed without an explicit
/// storage choice. Storage selection is mandatory and fail-closed (spec
/// §17.6): there is no default backend. The two valid selections are
/// `{"type": "in_memory"}` (development) and
/// `{"type": "sqlite", "path": ..., "key" | "passphrase": ...}`
/// (production). Bridges that can require storage at compile time (the
/// typed `UniFFI` constructor, the required Swift / Kotlin / TypeScript
/// constructor argument) do so; the dynamically-typed bridges (the `PyO3`
/// dict, the NAPI JSON-string factory) reject a missing selection at
/// runtime with this code. No bridge silently defaults to in-memory.
pub const STORAGE_8000: &str = "SCP-STORAGE-8000";

/// The selected durable storage backend failed to open.
///
/// Returned when `SqliteStorage::new` or `SqliteStorage::with_passphrase`
/// rejects the caller's selection: a wrong key or passphrase on an existing
/// `SQLCipher` database, a directory the process cannot write, a corrupt
/// file, or a salt-sidecar fail-closed condition. A directory whose advisory
/// lock another store holds is [`STORAGE_8005`] instead.
/// Spec §17.6 makes this terminal — no bridge downgrades to in-memory
/// storage after it. All three bridges report this one code, so a caller
/// reading a code learns the same thing whichever binding raised it.
///
/// The number is `8004`, not `8001`, because the `scp-kt-android`
/// `AndroidStorage` backend already owns `8001`--`8003`
/// (`.docs/standards/sdk-common.md` §Registered SCP-STORAGE- codes). An
/// Android app links `AndroidStorage` and this bridge into one process, so
/// reusing `8001` would make one code string mean both "storage key not
/// found" and "durable backend failed to open" inside that app.
pub const STORAGE_8004: &str = "SCP-STORAGE-8004";

/// The durable storage directory's advisory lock is still held.
///
/// Returned when `SqliteStorage::new` or `SqliteStorage::with_passphrase`
/// finds `{dir}/scp.db.lock` held by another store, in this process or
/// another (`scp_platform::PlatformError::StorageLockHeld`). Spec §17.6 "One
/// Opener per Durable Directory" makes the open fail at once: it does not
/// wait for the lock and does not fall back to another backend.
///
/// Also returned by an SDK `shutdown` that left the instance's own store
/// holding its lock: the Supervisor drain did not finish
/// (`ShutdownOutcome::TimedOut` with `durable_store_open`), the store refused
/// to close (`ShutdownError::DurableStoreClose`), or an earlier shutdown had
/// not closed it (`ShutdownError::AlreadyShutDown` with
/// `durable_store_open`). A reopen of the
/// directory then fails with this code until the store is released.
pub const STORAGE_8005: &str = "SCP-STORAGE-8005";

/// The store has released its database connection.
///
/// Each bridge's `From<scp_platform::PlatformError>` translation maps
/// `scp_platform::PlatformError::StorageClosed` to this code.
pub const STORAGE_8006: &str = "SCP-STORAGE-8006";

/// The node start configuration is invalid.
///
/// A required field is missing, a field value is invalid, or
/// `scp_node::validate_reach_and_tls` rejected the reach and TLS pair.
/// `node_start` returns it before it creates any directory or file
/// (sdk-common.md §"Node start error codes").
pub const STORAGE_8007: &str = "SCP-STORAGE-8007";

/// Node start's blob storage backend failed to open, or its directory could not
/// be created (sdk-common.md §"Node start error codes").
pub const STORAGE_8008: &str = "SCP-STORAGE-8008";

/// The core node returned a storage error during node start
/// (`NodeError::Storage`; sdk-common.md §"Node start error codes").
pub const STORAGE_8009: &str = "SCP-STORAGE-8009";

/// A `suspend` did not suspend because a context snapshot did not persist.
///
/// `CoreFields::suspend` flushes every context to the persistence provider
/// before it clears transport (ADR-049 Decision 9). When a flush fails,
/// misses the caller's deadline, or is interrupted, `suspend` leaves the
/// instance running with its transport connected and returns
/// `SuspendError::FlushFailed`, `SuspendError::DeadlineElapsed` or
/// `SuspendError::Interrupted`, which each bridge reports with this code. The
/// unflushed actors stay dirty, so a retried `suspend` flushes them again.
pub const STORAGE_8014: &str = "SCP-STORAGE-8014";

/// A `shutdown` completed, but a context snapshot did not persist.
///
/// `CoreFields::shutdown_core_async` flushes every context inside the
/// caller's deadline before it drains the Supervisor (ADR-049 Decision 9). A
/// flush that failed or did not finish in time is reported in
/// `ShutdownOutcome::flush` (`ShutdownFlush::Failed` or
/// `ShutdownFlush::TimedOut`), and each SDK `shutdown` raises this code when
/// the durable store was released. The instance is shut down either way; the
/// unflushed contexts restore from their last persisted snapshot. A shutdown
/// that also left the store holding its lock raises `SCP-STORAGE-8005`
/// instead, naming the flush failure in its message.
pub const STORAGE_8015: &str = "SCP-STORAGE-8015";

// -------------------------------------------------------------------------
// Attestation (SCP-ATTEST- 9000--9999)
// -------------------------------------------------------------------------

/// Device attestation provider call failed.
///
/// The Android adapter throws it when a Play Integrity token request fails,
/// and the Apple adapter throws it when Apple's App Attest service answers
/// with an error that no narrower `SCP-ATTEST-` code names, or when the
/// caller's task is cancelled while its App Attest call is queued or waiting
/// for Apple's answer. Every native bridge reports
/// `PlatformError::AttestationError` with it ([`custody_failure_code`]).
pub const ATTEST_9001: &str = "SCP-ATTEST-9001";

/// Attestation signature verification requires raw JSON, which is absent.
pub const ATTEST_9006: &str = "SCP-ATTEST-9006";

/// Identity link attestation create bridge function not yet exported.
pub const ATTEST_9010: &str = "SCP-ATTEST-9010";

/// Identity link attestation list bridge function not yet exported.
pub const ATTEST_9011: &str = "SCP-ATTEST-9011";

/// Identity link attestation remove bridge function not yet exported.
pub const ATTEST_9012: &str = "SCP-ATTEST-9012";

/// Identity link attestation renew bridge function not yet exported.
pub const ATTEST_9013: &str = "SCP-ATTEST-9013";

/// Identity link attestation verify bridge function not yet exported.
pub const ATTEST_9014: &str = "SCP-ATTEST-9014";

/// Attestation JSON bytes are not valid UTF-8.
pub const ATTEST_9015: &str = "SCP-ATTEST-9015";

/// Attestation list JSON bytes are not valid UTF-8.
pub const ATTEST_9016: &str = "SCP-ATTEST-9016";

/// Failed to re-serialize attestation to UTF-8 JSON.
pub const ATTEST_9017: &str = "SCP-ATTEST-9017";

/// Cryptographic-class verification method not verifiable via browser fetch.
pub const ATTEST_9018: &str = "SCP-ATTEST-9018";

// Codes the Swift `AppleDeviceAttestation` adapter throws as `ScpError`
// from its UniFFI `DeviceAttestationProvider` callback methods
// (`AttestationError.scpError`). Each of these nine codes belongs to one of
// the ten `AttestationError` cases; the tenth case, `serviceError`, reuses
// `ATTEST_9001`.

/// Apple App Attest is unsupported on this device.
///
/// `DCAppAttestService.isSupported` is `false`, or an App Attest call answered
/// with `DCError.featureUnsupported`.
pub const ATTEST_9019: &str = "SCP-ATTEST-9019";
/// No App Attest key ID is stored, so no assertion is possible.
pub const ATTEST_9020: &str = "SCP-ATTEST-9020";
/// Apple already attested this App Attest key.
///
/// `attestKey` answered `DCError.invalidKey` and the key probe's assertion
/// with that key succeeded. For the stored key, the Apple adapter keeps the
/// key and records it as attested; for a replacement key, it discards the
/// replacement key ID and keeps the stored key.
pub const ATTEST_9021: &str = "SCP-ATTEST-9021";
/// Apple refused an `assertRequest` assertion with a stored App Attest key that
/// carries no attestation record.
///
/// `assertRequest`'s `generateAssertion` answered `DCError.invalidKey` for a
/// key that carries no attestation record, which names either an unattested
/// key or a rejected key whose record was never written; the Apple adapter
/// keeps the key.
pub const ATTEST_9022: &str = "SCP-ATTEST-9022";
/// Apple's App Attest service rejected this device's key.
///
/// `generateAssertion` answered `DCError.invalidKey` for a key that carries
/// an attestation record, or `attestKey` and the key probe's assertion both
/// answered `DCError.invalidKey`. For the stored key, the Apple adapter
/// discards the key ID and record; for a replacement key, it discards the
/// replacement key ID and keeps the stored key and its record.
pub const ATTEST_9023: &str = "SCP-ATTEST-9023";
/// App Attest `attestKey` or `generateAssertion` answered
/// `DCError.serverUnavailable`.
///
/// The Apple adapter keeps the key for a retry. A `generateKey` answer of
/// `DCError.serverUnavailable` gives `SCP-ATTEST-9001`.
pub const ATTEST_9024: &str = "SCP-ATTEST-9024";
/// The App Attest adapter reached a state no caller input produces.
///
/// Apple's service answered a completion handler with neither a value nor an
/// error.
pub const ATTEST_9025: &str = "SCP-ATTEST-9025";
/// The attestation challenge or the assertion request hash is not 32 bytes.
///
/// ADR-025 acceptance criterion 3 has the Rust core pass the 32-byte binding
/// digest `D` of `09-security-model.md` §9.3.1 as `challenge` and the 32-byte
/// assertion digest `A` as `request_hash`, and the Apple adapter hands each to
/// App Attest as `clientDataHash` unchanged. On a device that supports App
/// Attest, the Apple adapter throws this code for either input when it is not
/// 32 bytes, before it generates a key or calls App Attest; on a device that
/// does not, it throws `SCP-ATTEST-9019` first.
pub const ATTEST_9026: &str = "SCP-ATTEST-9026";
/// Apple App Attest did not answer one serialized call within 25 seconds.
///
/// ADR-025 acceptance criterion 3 bounds each call the Apple adapter's call
/// serializer runs, the whole of one `attest` or one `assert_request`, at 25
/// seconds from the call's start, below the runtime's 30-second actor
/// `HANDLER_TIMEOUT`. Time the call spends queued behind earlier calls counts
/// against no bound, so a queued caller's whole wait can pass 30 seconds.
/// When the bound expires, the waiting
/// `attest` or `assert_request` throws this code, the serializer starts the
/// next queued call, and an answer Apple gives later is discarded: it stores
/// no key ID, writes no attestation record, discards no key ID, and reaches
/// no caller. `SCP-ATTEST-9025` names a completion
/// handler that answered with neither a value nor an error, a different
/// condition.
pub const ATTEST_9027: &str = "SCP-ATTEST-9027";

// -------------------------------------------------------------------------
// Governance (SCP-GOV- 11000--11999)
// -------------------------------------------------------------------------

/// A bridge reported a governance name the SDK reading it does not enumerate.
///
/// Every bridge names a governance outcome, a proposal status, and a rejection
/// reason through the exhaustive functions in
/// [`crate::governance_result`]. Each SDK parses those names into typed enums,
/// and an SDK older than its bridge reads a name its enum lacks. The SDK
/// raises this code instead of substituting a known name: governance decides
/// authorization, and a substituted name reports an action or status the
/// engine never reported. Each SDK's member-role parser raises it too, for a
/// role name that is neither one of the names `RESERVED_ROLE_NAMES` reserves
/// nor a name `validate_role_name` admits for a custom role. SDK-side only; no
/// bridge emits it.
/// `crates/scp-testing/tests/governance_outcome_parity.rs` holds each SDK's
/// name set equal to the Rust set.
pub const GOV_11040: &str = "SCP-GOV-11040";

// -------------------------------------------------------------------------
// Economy (SCP-ECON- 12000--12999)
// -------------------------------------------------------------------------

/// Economy insufficient balance.
pub const ECON_12061: &str = "SCP-ECON-12061";
/// Economy amount-display formatting: unknown currency, no decimals override.
///
/// Raised by the SDK `format`/`formatAmount` display helpers when a currency
/// is not in the SDK's known-currency decimals table and no explicit
/// `decimals` override was supplied (ADR-060 SDK display surface). SDK-side
/// only — the protocol does not store per-currency decimals.
pub const ECON_12070: &str = "SCP-ECON-12070";
/// Economy governance action spending error.
pub const ECON_12090: &str = "SCP-ECON-12090";
/// Economy context operation spending error.
pub const ECON_12091: &str = "SCP-ECON-12091";
/// Economy rate limit error.
pub const ECON_12095: &str = "SCP-ECON-12095";
/// Economy budget exceeded error.
pub const ECON_12096: &str = "SCP-ECON-12096";

// -------------------------------------------------------------------------
// Cross-context outlet-invocation saga (SCP-SAGA- 13000--13999)
// -------------------------------------------------------------------------
//
// The §6.2.4 / ADR-049 §3a saga terminal codes the FFI saga surface maps the
// typed `SagaError` onto. All registered in `.docs/standards/sdk-common.md`;
// band-validated by `scripts/check-error-codes.sh` (13000--13999). The
// `Aborted` arm's specific sub-code (e.g. 13050/13062/13067) is formatted
// inline from the producer's numeric `code` discriminant — these named
// constants pin the two FIXED terminal codes (`NeedsRepair`, `Busy`) plus the
// caller-axis authorization code the bridge's channel-auth binding reuses.

/// Saga caller-axis authorize-before-reserve rejection.
///
/// The initiator is not authorized to act over the named caller context. The
/// bridge reuses this for its channel-auth binding (`caller_did` not hosted by
/// this bridge instance, or not a member of `caller_context_id`) ⇒ a
/// `Rejected`-flavored `SagaAborted`.
pub const SAGA_13050: &str = "SCP-SAGA-13050";
/// Saga `NeedsRepair` terminal — Commit-retry exhausted; the saga diverged and
/// requires operator repair (carries the durable `saga_id`).
pub const SAGA_13065: &str = "SCP-SAGA-13065";
/// Saga `Busy` terminal — the participant context set overlapped an in-flight
/// saga (per-participant-context-set gating, §5.15.4).
pub const SAGA_13066: &str = "SCP-SAGA-13066";

/// The bridge error code for a runtime [`CustodyFailure`](scp_crypto::CustodyFailure).
///
/// One mapping for the `PyO3`, napi-rs and `UniFFI` bridges: key-not-found is
/// [`CRYPTO_4006`], a rejected host pseudonym is [`IDENT_1055`], a closed
/// custody store is [`STORAGE_8006`], a custody store whose directory lock is
/// still held is [`STORAGE_8005`], a custody sign past the ADR-049 Decision 7a
/// budget is [`CRYPTO_4062`], a device attestation failure is
/// [`ATTEST_9001`], an unsupported operation is [`CRYPTO_4061`], each push
/// failure kind has its own code from [`TRANS_5080`] to [`TRANS_5084`], and
/// any other custody failure is [`CRYPTO_4060`].
#[must_use]
pub const fn custody_failure_code(e: &scp_crypto::CustodyFailure) -> &'static str {
    use scp_crypto::CustodyFailureKind as Kind;
    match e.kind {
        Kind::KeyNotFound => CRYPTO_4006,
        Kind::PseudonymRejected => IDENT_1055,
        Kind::StorageClosed => STORAGE_8006,
        Kind::StorageLockHeld => STORAGE_8005,
        Kind::TimedOut => CRYPTO_4062,
        Kind::AttestationFailed => ATTEST_9001,
        Kind::Unsupported => CRYPTO_4061,
        Kind::PushWakePayloadInvalid => TRANS_5080,
        Kind::PushRegistrationRejected => TRANS_5081,
        Kind::PushVerifierUnavailable => TRANS_5082,
        Kind::PushPlatformUnavailable => TRANS_5083,
        Kind::PushProviderFailed => TRANS_5084,
        Kind::Failed => CRYPTO_4060,
    }
}

/// The bridge error class a [`CustodyFailure`](scp_crypto::CustodyFailure)
/// reaches the caller as; each bridge maps it to its own error variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyFailureClass {
    /// An identity error: a rejected host pseudonym or a device attestation
    /// failure.
    Identity,
    /// A validation error: a closed or still-locked store (spec §17.6).
    Validation,
    /// A crypto error: key-not-found, a custody sign past its budget, an
    /// unsupported operation, or any other key custody failure.
    Crypto,
    /// A transport error: a push failure (ADR-006 2026-10-12 amendment).
    Transport,
}

/// The error class for a custody failure kind, one mapping for the `PyO3`,
/// napi-rs and `UniFFI` bridges.
#[must_use]
pub const fn custody_failure_class(kind: scp_crypto::CustodyFailureKind) -> CustodyFailureClass {
    use scp_crypto::CustodyFailureKind as Kind;
    match kind {
        Kind::PseudonymRejected | Kind::AttestationFailed => CustodyFailureClass::Identity,
        Kind::StorageClosed | Kind::StorageLockHeld => CustodyFailureClass::Validation,
        Kind::KeyNotFound | Kind::TimedOut | Kind::Unsupported | Kind::Failed => {
            CustodyFailureClass::Crypto
        }
        Kind::PushWakePayloadInvalid
        | Kind::PushRegistrationRejected
        | Kind::PushVerifierUnavailable
        | Kind::PushPlatformUnavailable
        | Kind::PushProviderFailed => CustodyFailureClass::Transport,
    }
}

/// Whether a bare `PlatformError` of this kind is a key custody failure.
///
/// Only then does the bridge's message point the caller at the key custody
/// configuration. A storage, attestation or push failure is not, and its
/// message is the error's own text.
#[must_use]
pub const fn is_key_custody_failure(kind: scp_crypto::CustodyFailureKind) -> bool {
    use scp_crypto::CustodyFailureKind as Kind;
    match kind {
        Kind::KeyNotFound
        | Kind::PseudonymRejected
        | Kind::TimedOut
        | Kind::Unsupported
        | Kind::Failed => true,
        Kind::StorageClosed
        | Kind::StorageLockHeld
        | Kind::AttestationFailed
        | Kind::PushWakePayloadInvalid
        | Kind::PushRegistrationRejected
        | Kind::PushVerifierUnavailable
        | Kind::PushPlatformUnavailable
        | Kind::PushProviderFailed => false,
    }
}

/// The bridge error class a trust or admission failure reaches the caller as;
/// each bridge maps it to its own error variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustFailureClass {
    /// A validation error: the input or a record is refused.
    Validation,
    /// An identity error: a key or definition needed for the check could not
    /// be obtained, so the decision is unknown.
    Identity,
    /// A context error: the runtime could not run the operation, such as a
    /// blocking task that panicked or was cancelled.
    Context,
}

/// The key of the machine-readable retry time a trust error message ends
/// with: `(retry_after=<unix seconds>)`. Every SDK's `retryAfter` reads it.
pub const RETRY_AFTER_KEY: &str = "retry_after=";

/// The first Unix second at which a refused call may succeed.
///
/// Three refusals name one: a cooldown ([`VALID_7105`]), a challenge window
/// still open to this subject ([`VALID_7151`]), and an attempt graded at its
/// challenge's `created_at` ([`VALID_7153`]).
#[must_use]
pub const fn trust_error_retry_after(e: &scp_protocol::trust::TrustError) -> Option<u64> {
    use scp_protocol::trust::TrustError as E;
    match e {
        E::CooldownActive { retry_after, .. } => Some(*retry_after),
        E::ChallengeWindowOpen { expires_at, .. } => Some(*expires_at),
        E::ChallengeNotYetGradable { retry_at, .. } => Some(*retry_at),
        _ => None,
    }
}

/// The message a bridge reports for a [`TrustError`](scp_protocol::trust::TrustError).
///
/// The `PyO3`, napi-rs and `UniFFI` bridges share this wording. A refusal
/// with a retry time ends with `(retry_after=<unix seconds>)`
/// ([`RETRY_AFTER_KEY`]).
#[must_use]
pub fn trust_error_message(e: &scp_protocol::trust::TrustError) -> String {
    let message = if trust_error_code(e) == VALID_7039 {
        format!("{e} — supply at least the standard's minimum test cases")
    } else {
        format!("trust evaluation failed: {e}")
    };
    match trust_error_retry_after(e) {
        Some(at) => format!("{message} ({RETRY_AFTER_KEY}{at})"),
        None => message,
    }
}

/// The bridge error code for a [`TrustError`](scp_protocol::trust::TrustError),
/// one mapping for the `PyO3`, napi-rs and `UniFFI` bridges.
///
/// The match is exhaustive, so a new variant does not compile until it has a
/// code. Every challenge-flow error has its own code; the remaining trust
/// errors keep [`VALID_7003`], and a suite below its standard's minimum keeps
/// [`VALID_7039`].
#[must_use]
pub const fn trust_error_code(e: &scp_protocol::trust::TrustError) -> &'static str {
    use scp_protocol::trust::TrustError as E;
    match e {
        E::ChallengeSuiteBelowMinimum { .. } => VALID_7039,
        E::ChallengeNotOpen { .. } => VALID_7099,
        E::ChallengeExpired { .. } => VALID_7102,
        E::AttemptOutOfOrder { .. } => VALID_7103,
        E::RetriesExhausted { .. } => VALID_7104,
        E::CooldownActive { .. } => VALID_7105,
        E::ChallengeClosed { .. } => VALID_7106,
        E::UnknownChallenge { .. } => VALID_7107,
        E::OutputsMismatch { .. } => VALID_7108,
        E::EvaluatorUnavailable { .. } => VALID_7109,
        E::SelfChallenge { .. } => VALID_7127,
        E::StandardNotGradable { .. } => VALID_7128,
        E::CapabilityDefinitionUnavailable { .. } => VALID_7129,
        E::PolicyOutsideDefinition { .. } => VALID_7137,
        E::SchemaRejected { .. } => VALID_7138,
        E::GradingInProgress { .. } => VALID_7139,
        E::ResponseTooLarge { .. } => VALID_7143,
        E::DefinitionEquivocation { .. } => VALID_7144,
        E::GradingCapacityExhausted { .. } => VALID_7146,
        E::NonCanonicalIdentifier { .. } => VALID_7147,
        E::GradingLeaseLost { .. } => VALID_7149,
        E::ChallengeWindowOpen { .. } => VALID_7151,
        E::ChallengeNotYetGradable { .. } => VALID_7153,
        E::NoEventsForSubject { .. }
        | E::EmptyEventLog
        | E::InvalidEventData { .. }
        | E::AttestationSignatureInvalid { .. }
        | E::AttestationExpired { .. }
        | E::AttestationRevoked { .. }
        | E::AttestationRevocationInvalid { .. }
        | E::AttestationEvidenceInvalid { .. }
        | E::ChallengeResponderMismatch { .. }
        | E::ChallengeSignatureInvalid { .. }
        | E::ChallengeSigningFailed { .. }
        | E::CanonicalizationFailed { .. }
        | E::UnknownChallengeCapability { .. }
        | E::InvalidChallengeSuite { .. }
        | E::ChallengeVerifierMismatch { .. }
        | E::ChallengeVerificationIdMismatch { .. }
        | E::ChallengeVerificationValidityTooLong { .. }
        | E::ChallengeVerificationFromFuture { .. }
        | E::KeyResolutionUnavailable { .. }
        | E::ChallengeRequestSignatureInvalid { .. }
        | E::ChallengeVerificationSignatureInvalid { .. }
        | E::ChallengeVerificationExpired { .. }
        | E::ChallengeContextMismatch { .. }
        | E::ChallengeSubjectMismatch { .. }
        | E::ChallengeWindowInvalid { .. }
        | E::ChallengeVerificationOutsideWindow { .. }
        | E::ChallengeVerificationInconsistent { .. }
        | E::NotAMember { .. }
        | E::NotOptedIn { .. }
        | E::StoreError { .. } => VALID_7003,
    }
}

/// The bridge error code and class for an
/// [`AdmissionError`](scp_protocol::trust::AdmissionError), one mapping for
/// the `PyO3`, napi-rs and `UniFFI` bridges.
///
/// A record check that could not run ([`IDENT_1033`]) is an identity error;
/// every other admission failure is a validation error.
#[must_use]
pub const fn admission_error_code(
    e: &scp_protocol::trust::AdmissionError,
) -> (&'static str, TrustFailureClass) {
    use scp_protocol::trust::AdmissionError as E;
    let code = match e {
        E::MissingCapability { .. } | E::VerificationRequired { .. } => VALID_7076,
        E::EmptySubjectDid => VALID_7077,
        E::UntrustedVerifier { .. } => VALID_7121,
        E::SelfChallenge { .. } => VALID_7127,
        E::RetryCapExceeded { .. } => VALID_7137,
        E::InvalidRequirement { .. } => VALID_7150,
        E::NonCanonicalIdentifier { .. } => VALID_7147,
        E::TooManyCapabilityRequirements { .. } => VALID_7148,
        E::VerificationUnavailable { .. } => {
            return (IDENT_1033, TrustFailureClass::Identity);
        }
    };
    (code, TrustFailureClass::Validation)
}

/// The bridge error code for a [`ServerError`](crate::server::ServerError).
///
/// One mapping for the `PyO3`, napi-rs and `UniFFI` bridges, following
/// [`custody_failure_code`]; sdk-common.md §"Node start error codes" lists
/// every row.
#[cfg(feature = "server")]
#[must_use]
pub const fn server_error_code(e: &crate::server::ServerError) -> &'static str {
    use crate::server::ServerError as E;
    use scp_node::NodeError as N;
    match e {
        E::InvalidConfig(_) | E::Node(N::MissingField(_) | N::InvalidConfig(_)) => STORAGE_8007,
        E::Storage(_) | E::Io(_) => STORAGE_8008,
        E::Node(N::Storage(_)) => STORAGE_8009,
        E::OperatorIdentityUnavailable | E::Node(N::Identity(_)) => IDENT_1063,
        E::Node(N::Relay(_)) => TRANS_5051,
        E::Node(N::Tls(_)) => TRANS_5052,
        E::Node(N::Serve(_) | N::Nat(_)) => TRANS_5054,
        E::Relay(_) => TRANS_5050,
        E::DevStartUnavailable => TRANS_5055,
        E::SupervisorWiring(_) => TRANS_5056,
        E::DhtInit(_) => IDENT_1001,
        E::MissingPassphrase => VALID_7004,
        E::Platform(_) => CTX_2053,
    }
}

/// The bridge error class a [`ServerError`](crate::server::ServerError)
/// reaches the caller as; each bridge maps it to its own error variant.
#[cfg(feature = "server")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerErrorClass {
    /// A validation error: an invalid config, a missing passphrase, or a
    /// storage selection the bridge could not honour (`SCP-STORAGE-*`, as for
    /// the selection layer's `SCP-STORAGE-8004`).
    Validation,
    /// An identity error: the operator identity is unavailable, or the DHT
    /// client could not be built.
    Identity,
    /// A transport error: the relay, TLS, HTTP server or NAT traversal failed,
    /// the bridge could not wire its `Supervisor` to a started node, or a
    /// dev-pair start reached a bridge built without `testing`.
    Transport,
    /// A context error: a dev-pair `PlatformError`.
    Context,
}

/// The error class for a [`ServerError`](crate::server::ServerError), one
/// mapping for the `PyO3`, napi-rs and `UniFFI` bridges.
#[cfg(feature = "server")]
#[must_use]
pub const fn server_error_class(e: &crate::server::ServerError) -> ServerErrorClass {
    use crate::server::ServerError as E;
    use scp_node::NodeError as N;
    match e {
        E::InvalidConfig(_)
        | E::Node(N::MissingField(_) | N::InvalidConfig(_) | N::Storage(_))
        | E::Storage(_)
        | E::Io(_)
        | E::MissingPassphrase => ServerErrorClass::Validation,
        E::OperatorIdentityUnavailable | E::Node(N::Identity(_)) | E::DhtInit(_) => {
            ServerErrorClass::Identity
        }
        E::Node(N::Relay(_) | N::Tls(_) | N::Serve(_) | N::Nat(_))
        | E::Relay(_)
        | E::DevStartUnavailable
        | E::SupervisorWiring(_) => ServerErrorClass::Transport,
        E::Platform(_) => ServerErrorClass::Context,
    }
}

#[cfg(all(test, feature = "server"))]
mod server_error_tests {
    use super::*;
    use crate::server::ServerError as E;
    use scp_node::NodeError as N;

    /// One error per sdk-common.md §"Node start error codes" row, paired with
    /// its code and class.
    fn rows() -> Vec<(E, &'static str, ServerErrorClass)> {
        use crate::server::SupervisorWiringError as W;
        use ServerErrorClass::{Context, Identity, Transport, Validation};
        let io = || std::io::Error::other("x");
        vec![
            (E::InvalidConfig("x".into()), STORAGE_8007, Validation),
            (E::Node(N::MissingField("reach")), STORAGE_8007, Validation),
            (
                E::Node(N::InvalidConfig("x".into())),
                STORAGE_8007,
                Validation,
            ),
            (
                E::Storage(scp_transport::native::storage::StorageError::Internal(
                    "x".into(),
                )),
                STORAGE_8008,
                Validation,
            ),
            (E::Io(io()), STORAGE_8008, Validation),
            (E::Node(N::Storage("x".into())), STORAGE_8009, Validation),
            (E::OperatorIdentityUnavailable, IDENT_1063, Identity),
            (
                E::Node(N::Identity(scp_identity::IdentityError::Platform(
                    scp_platform::error::PlatformError::StorageClosed,
                ))),
                IDENT_1063,
                Identity,
            ),
            (
                E::Node(N::Relay(
                    scp_transport::native::server::RelayError::BindFailed("x".into()),
                )),
                TRANS_5051,
                Transport,
            ),
            (
                E::Node(N::Tls(scp_node::tls::TlsError::Acme("x".into()))),
                TRANS_5052,
                Transport,
            ),
            (E::Node(N::Serve("x".into())), TRANS_5054, Transport),
            (E::Node(N::Nat("x".into())), TRANS_5054, Transport),
            (
                E::Relay(scp_transport::native::server::RelayError::BindFailed(
                    "x".into(),
                )),
                TRANS_5050,
                Transport,
            ),
            (E::DevStartUnavailable, TRANS_5055, Transport),
            (
                E::SupervisorWiring(W::NodeAlreadyBound),
                TRANS_5056,
                Transport,
            ),
            (
                E::SupervisorWiring(W::RelayConnect(
                    scp_transport::TransportError::ConnectionFailed("x".into()),
                )),
                TRANS_5056,
                Transport,
            ),
            (
                E::SupervisorWiring(W::SupervisorUnavailable),
                TRANS_5056,
                Transport,
            ),
            (
                E::SupervisorWiring(W::TransportInstall(
                    crate::bridge_instance::TransportLockError::Poisoned,
                )),
                TRANS_5056,
                Transport,
            ),
            (
                E::DhtInit(crate::dht::DhtInitError::InvalidGateway {
                    url: "x".into(),
                    reason: "x".into(),
                }),
                IDENT_1001,
                Identity,
            ),
            (E::MissingPassphrase, VALID_7004, Validation),
            (
                E::Platform(scp_platform::error::PlatformError::StorageError("x".into())),
                CTX_2053,
                Context,
            ),
        ]
    }

    #[test]
    fn server_error_code_and_class_match_every_sdk_common_row() {
        for (err, code, class) in rows() {
            assert_eq!(server_error_code(&err), code, "{err:?}");
            assert_eq!(server_error_class(&err), class, "{err:?}");
        }
    }
}
