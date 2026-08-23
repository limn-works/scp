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
/// Identity already exists.
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
/// `UniFFI` identity passphrase error.
pub const IDENT_1013: &str = "SCP-IDENT-1013";
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
/// Surfaced by operations that must sign with the creator/identity key (UCAN
/// mint, UCAN delegate, event-log checkpoint, broadcast publish) when the
/// identity was loaded externally with no retained custody, or the
/// custody/handle is sign-only without the needed key material. Distinct from
/// `IDENT_1001` (identity not registered). (UCAN delegate surfaces this on
/// `UniFFI` only; the registry-based NAPI/PyO3 delegate paths surface
/// `IDENT_1001` instead — see sdk-common.md.)
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
// -----------------------------------------------------------------------

/// Pseudonym derivation: identity missing core key material.
pub const IDENT_1054: &str = "SCP-IDENT-1054";
/// Pseudonym derivation failed (custody/KDF error).
pub const IDENT_1055: &str = "SCP-IDENT-1055";
/// Pseudonym derivation: no custody provider available.
pub const IDENT_1056: &str = "SCP-IDENT-1056";
/// Pseudonym derivation: derived public key was not 32 bytes.
pub const IDENT_1057: &str = "SCP-IDENT-1057";

/// Production DHT client initialization failed.
///
/// Surfaced by all native bridges (`PyO3`, napi-rs, `UniFFI`) when the shipped
/// Mainline Pkarr DHT client cannot be built — a malformed gateway URL or a
/// Pkarr build failure (`DhtInitError` from
/// [`scp_ffi_common::dht::build_ffi_dht_client`]). This is the fail-closed DHT
/// path (ADR-062 §Decision 1 / spec §17.17.3): construction NEVER substitutes an
/// in-memory or no-op client. Distinct from `IDENT_1001` (the generic /
/// registry-miss code) so SDK consumers can tell a DHT-init failure apart from
/// an identity that was never registered on this bridge.
pub const IDENT_1058: &str = "SCP-IDENT-1058";

/// No production pre-rotation custody backend is available (FAIL CLOSED).
///
/// Reached on a shipped (no-`testing`) build wherever a bridge gets as far as the
/// pre-rotation step. `PyO3` reaches it from `identity_create` (it accepts
/// `"file"` custody); napi and `UniFFI` reject their three custody strings first
/// (`SCP-IDENT-1008` / `SCP-IDENT-1003`) and reach it only through callback
/// custody. All three surface it from `identity_migrate`. napi and `UniFFI` also
/// surface it from `rotate_key`, `add_agent_key`, `rotate_agent_key`, and
/// `remove_agent_key`; none of `PyO3`'s four — `rotate_key`, `add_agent_key`,
/// `rotate_agent_key`, `remove_agent_key` — carries a fail-closed arm at all, so
/// they return a registry-miss code instead. That divergence is a cross-bridge parity gap,
/// not a documentation one.
///
/// NOT surfaced by `scp-node`, which does not depend on this crate: its
/// node-start paths return the typed `IdentityError::NoPreRotationBackend` with
/// no code string. `PyO3` and napi then map that to "node startup failed" with no
/// code; `UniFFI` maps it to `ScpError::Identity` with `SCP-TRANS-5051`. Every identity commits a pre-rotation commitment at creation (spec
/// §9.7.4.1 §3 — mandatory), which requires a `PreRotationCustody` backend; the
/// only implementation that exists today is the in-memory test nullifier
/// (`InMemoryPreRotationCustody`), now gated to the test harness only (ADR-062
/// §Decision 6). Rather than silently mint the nullifier (which would ship a
/// false durability guarantee — CLAUDE.md builder tenet "No dev/test-only
/// stand-ins in production"), creation fails closed with this typed code. Maps
/// from [`scp_identity::IdentityError::NoPreRotationBackend`]. A real, persistent
/// pre-rotation backend is tracked by #1729 / RFC #2130; non-committing creation
/// (Option A) is out of scope (Discussion #1553).
pub const IDENT_1059: &str = "SCP-IDENT-1059";

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
/// Context close failed.
pub const CTX_2009: &str = "SCP-CTX-2009";
/// Context export/import failed.
pub const CTX_2010: &str = "SCP-CTX-2010";
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
/// Bridge connector context creation error.
pub const CTX_2100: &str = "SCP-CTX-2100";
/// Bridge connector context join error.
pub const CTX_2101: &str = "SCP-CTX-2101";
/// Bridge connector context send error.
pub const CTX_2102: &str = "SCP-CTX-2102";
/// Bridge connector context leave error.
pub const CTX_2103: &str = "SCP-CTX-2103";
/// Bridge connector context close error.
pub const CTX_2104: &str = "SCP-CTX-2104";
/// Bridge connector broadcast subscribe error.
pub const CTX_2105: &str = "SCP-CTX-2105";
/// Bridge connector broadcast unsubscribe error.
pub const CTX_2106: &str = "SCP-CTX-2106";
/// Bridge connector broadcast publish error.
pub const CTX_2107: &str = "SCP-CTX-2107";
/// Bridge connector broadcast block error.
pub const CTX_2108: &str = "SCP-CTX-2108";
/// Bridge connector broadcast key request error.
pub const CTX_2109: &str = "SCP-CTX-2109";
/// Bridge connector broadcast admission error.
pub const CTX_2110: &str = "SCP-CTX-2110";
/// Bridge connector governance action error.
pub const CTX_2111: &str = "SCP-CTX-2111";
/// Bridge connector TTL expiry error.
pub const CTX_2112: &str = "SCP-CTX-2112";
/// Bridge connector TTL extension error.
pub const CTX_2113: &str = "SCP-CTX-2113";
/// Bridge connector context import error.
pub const CTX_2114: &str = "SCP-CTX-2114";
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
/// `UniFFI` key custody error.
pub const CRYPTO_4060: &str = "SCP-CRYPTO-4060";

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
/// Transport webhook error.
pub const TRANS_5020: &str = "SCP-TRANS-5020";
/// Transport webhook register error.
pub const TRANS_5021: &str = "SCP-TRANS-5021";
/// Transport webhook unregister error.
pub const TRANS_5022: &str = "SCP-TRANS-5022";
/// Transport webhook list error.
pub const TRANS_5023: &str = "SCP-TRANS-5023";
/// Transport webhook fire error.
pub const TRANS_5024: &str = "SCP-TRANS-5024";
/// Transport webhook test error.
pub const TRANS_5025: &str = "SCP-TRANS-5025";
/// Transport relay configured error.
pub const TRANS_5030: &str = "SCP-TRANS-5030";
/// `UniFFI` transport server error.
pub const TRANS_5050: &str = "SCP-TRANS-5050";
/// `UniFFI` transport bind error.
pub const TRANS_5051: &str = "SCP-TRANS-5051";
/// `UniFFI` transport TLS error.
pub const TRANS_5052: &str = "SCP-TRANS-5052";
/// `UniFFI` transport storage error.
pub const TRANS_5053: &str = "SCP-TRANS-5053";
/// `UniFFI` transport node error.
pub const TRANS_5054: &str = "SCP-TRANS-5054";
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
/// Returned by FFI entry points when a caller supplies a parity-harness
/// affordance (`testing_seed` on `identity_create`, `signed_at_override`
/// on `scpid_sign`) in a build that was NOT compiled with the `testing`
/// feature enabled. These are ADR-046 cross-bridge parity-harness
/// inputs, not production APIs — production bundles reject them with
/// this code.
pub const VALID_7008: &str = "SCP-VALID-7008";
/// Seed requires `InMemoryKeyCustody`.
///
/// Returned when a caller passes a deterministic parity-harness `seed`
/// together with a custody type other than `"in_memory"`. Seeded
/// determinism is only meaningful for the in-process `InMemoryKeyCustody`
/// backend — platform/software/file custody all produce keys outside the
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
/// Bridge connector DID validation error.
pub const VALID_7050: &str = "SCP-VALID-7050";
/// Bridge connector context ID validation error.
pub const VALID_7051: &str = "SCP-VALID-7051";
/// Bridge connector payload validation error.
pub const VALID_7052: &str = "SCP-VALID-7052";
/// Bridge connector admission validation error.
pub const VALID_7053: &str = "SCP-VALID-7053";
/// Bridge connector key validation error.
pub const VALID_7054: &str = "SCP-VALID-7054";
/// Bridge connector broadcast key validation error.
pub const VALID_7055: &str = "SCP-VALID-7055";
/// Bridge connector epoch validation error.
pub const VALID_7056: &str = "SCP-VALID-7056";
/// Bridge connector governance validation error.
pub const VALID_7057: &str = "SCP-VALID-7057";
/// Bridge connector import validation error.
pub const VALID_7058: &str = "SCP-VALID-7058";
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
/// Webhook validation error.
pub const VALID_7070: &str = "SCP-VALID-7070";
/// Webhook register validation error.
pub const VALID_7071: &str = "SCP-VALID-7071";
/// Webhook operation validation error.
pub const VALID_7072: &str = "SCP-VALID-7072";
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
/// Handle registry lock error.
pub const VALID_7120: &str = "SCP-VALID-7120";
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
/// Recovery or custody-migration concurrency cap reached.
///
/// The NAPI bridge bounds concurrent `block_on` invocations to prevent libuv
/// worker-pool exhaustion (RED-PR5-002 / BLACK-PR5-002). Caller should back
/// off and retry.
pub const VALID_7140: &str = "SCP-VALID-7140";
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

// -------------------------------------------------------------------------
// Attestation (SCP-ATTEST- 9000--9999)
// -------------------------------------------------------------------------

/// Device attestation provider call failed (Play Integrity API error).
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
