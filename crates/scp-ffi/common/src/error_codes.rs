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
//! | `SCP-TOOL-`   | 6000--6999  |
//! | `SCP-VALID-`  | 7000--7999  |
//! | `SCP-STORAGE-`| 8000--8999  |
//! | `SCP-ATTEST-` | 9000--9999  |
//! | `SCP-MCP-`    | 10000--10999|
//! | `SCP-GOV-`    | 11000--11999|
//! | `SCP-ECON-`   | 12000--12999|
//!
//! All bridges (`PyO3`, napi-rs, `UniFFI`, WASM) import these constants
//! instead of defining error code strings locally. This eliminates
//! cross-bridge divergence and makes error code auditing trivial.

// -------------------------------------------------------------------------
// Identity (SCP-IDENT- 1000--1999)
// -------------------------------------------------------------------------

/// Generic identity error.
pub const IDENT_1000: &str = "SCP-IDENT-1000";
/// Identity operation failed.
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
/// Device attestation feature unavailable.
///
/// Surfaced by the Python SDK shim when the `PyO3` extension was built
/// without the `allow_in_memory_custody` feature: the `identity_attest_device`
/// method is not exposed on the native bridge.
pub const IDENT_1015: &str = "SCP-IDENT-1015";
/// Device attestation verification feature unavailable.
///
/// Surfaced by the Python SDK shim when the `PyO3` extension was built
/// without the `allow_in_memory_custody` feature: the
/// `identity_verify_device_attestation` method is not exposed on the
/// native bridge.
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
/// Identity agent key creation.
pub const IDENT_1020: &str = "SCP-IDENT-1020";
/// Identity DID document error.
pub const IDENT_1022: &str = "SCP-IDENT-1022";
/// Identity agent key validation.
pub const IDENT_1023: &str = "SCP-IDENT-1023";
/// Identity agent key operation error.
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
/// WASM context operation error.
pub const CTX_2040: &str = "SCP-CTX-2040";
/// WASM context governance error.
pub const CTX_2041: &str = "SCP-CTX-2041";
/// WASM context TTL error.
pub const CTX_2042: &str = "SCP-CTX-2042";
/// WASM context broadcast error.
pub const CTX_2043: &str = "SCP-CTX-2043";
/// WASM context member error.
pub const CTX_2044: &str = "SCP-CTX-2044";
/// WASM context drain error.
pub const CTX_2045: &str = "SCP-CTX-2045";
/// WASM context query error.
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
/// WASM MLS group create error.
pub const CRYPTO_4020: &str = "SCP-CRYPTO-4020";
/// WASM MLS proposal error.
pub const CRYPTO_4021: &str = "SCP-CRYPTO-4021";
/// WASM MLS commit error.
pub const CRYPTO_4022: &str = "SCP-CRYPTO-4022";
/// WASM sender key error.
pub const CRYPTO_4023: &str = "SCP-CRYPTO-4023";
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
// Tool (SCP-TOOL- 6000--6999)
// -------------------------------------------------------------------------

/// Generic tool error.
pub const TOOL_6001: &str = "SCP-TOOL-6001";
/// Tool not found.
pub const TOOL_6002: &str = "SCP-TOOL-6002";
/// Tool registration error.
pub const TOOL_6003: &str = "SCP-TOOL-6003";
/// Tool invocation error.
pub const TOOL_6004: &str = "SCP-TOOL-6004";
/// Tool verification error.
pub const TOOL_6005: &str = "SCP-TOOL-6005";
/// Tool capability error.
pub const TOOL_6006: &str = "SCP-TOOL-6006";
/// Tool interface error.
pub const TOOL_6007: &str = "SCP-TOOL-6007";
/// Tool schema error.
pub const TOOL_6008: &str = "SCP-TOOL-6008";
/// Tool handler error.
pub const TOOL_6009: &str = "SCP-TOOL-6009";
/// Tool interface establish error.
pub const TOOL_6010: &str = "SCP-TOOL-6010";
/// Tool interface query error.
pub const TOOL_6011: &str = "SCP-TOOL-6011";
/// Tool interface list error.
pub const TOOL_6012: &str = "SCP-TOOL-6012";
/// Tool signer error.
pub const TOOL_6013: &str = "SCP-TOOL-6013";
/// Tool register error.
pub const TOOL_6014: &str = "SCP-TOOL-6014";
/// Tool deregister error.
pub const TOOL_6015: &str = "SCP-TOOL-6015";
/// Tool invoke capability error.
pub const TOOL_6017: &str = "SCP-TOOL-6017";
/// Tool invoke schema validation error.
pub const TOOL_6018: &str = "SCP-TOOL-6018";
/// Tool invoke result error.
pub const TOOL_6019: &str = "SCP-TOOL-6019";
/// Tool invoke handler error.
pub const TOOL_6020: &str = "SCP-TOOL-6020";
/// Tool invoke timeout error.
pub const TOOL_6021: &str = "SCP-TOOL-6021";
/// Tool verify register error.
pub const TOOL_6030: &str = "SCP-TOOL-6030";
/// Tool verify not found error.
pub const TOOL_6031: &str = "SCP-TOOL-6031";
/// Tool verify invoke schema error.
pub const TOOL_6032: &str = "SCP-TOOL-6032";
/// Tool verify invoke not found error.
pub const TOOL_6033: &str = "SCP-TOOL-6033";
/// Tool verify output schema error.
pub const TOOL_6035: &str = "SCP-TOOL-6035";

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
/// Governance action validation error.
pub const VALID_7027: &str = "SCP-VALID-7027";
/// MCP validation error.
pub const VALID_7030: &str = "SCP-VALID-7030";
/// MCP transport validation error.
pub const VALID_7031: &str = "SCP-VALID-7031";
/// MCP handle validation error.
pub const VALID_7032: &str = "SCP-VALID-7032";
/// MCP context validation error.
pub const VALID_7033: &str = "SCP-VALID-7033";
/// MCP tool validation error.
pub const VALID_7034: &str = "SCP-VALID-7034";
/// Tool register input validation error.
pub const VALID_7035: &str = "SCP-VALID-7035";
/// Tool register schema validation error.
pub const VALID_7036: &str = "SCP-VALID-7036";
/// Tool invoke input validation error.
pub const VALID_7037: &str = "SCP-VALID-7037";
/// Tool verify input validation error.
pub const VALID_7038: &str = "SCP-VALID-7038";
/// Event log input validation error.
pub const VALID_7040: &str = "SCP-VALID-7040";
/// Tool verify register output validation.
pub const VALID_7041: &str = "SCP-VALID-7041";
/// Tool verify output validation error.
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
/// Attestation validation error.
pub const VALID_7080: &str = "SCP-VALID-7080";
/// Discovery announce validation error.
pub const VALID_7090: &str = "SCP-VALID-7090";
/// Discovery search validation error.
pub const VALID_7091: &str = "SCP-VALID-7091";
/// Discovery result validation error.
pub const VALID_7092: &str = "SCP-VALID-7092";
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
/// Economy governance action spending error.
pub const ECON_12090: &str = "SCP-ECON-12090";
/// Economy context operation spending error.
pub const ECON_12091: &str = "SCP-ECON-12091";
/// Economy rate limit error.
pub const ECON_12095: &str = "SCP-ECON-12095";
/// Economy budget exceeded error.
pub const ECON_12096: &str = "SCP-ECON-12096";
