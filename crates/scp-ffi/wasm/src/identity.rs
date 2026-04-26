//! `wasm-bindgen` bridge for identity operations.
//!
//! Exposes `WasmIdentity` and `WasmDIDDocument` as opaque JS objects with
//! getter properties, plus three bridge functions for identity lifecycle:
//!
//! - `identity_create` — Creates a new DID identity (returns `Promise<WasmIdentity>`).
//! - `identity_load` — Loads an existing identity by DID string.
//! - `identity_resolve` — Resolves a DID to its document.
//!
//! All async operations use [`wasm_bindgen_futures::future_to_promise`] to
//! return JS `Promise` objects. No Tokio runtime is used — the browser event
//! loop drives all async execution.
//!
//! # WASM constraints and scp-core dependency
//!
//! `scp-core` depends on `tokio = { features = ["full"] }`, which includes the
//! multi-thread runtime. The `wasm32-unknown-unknown` target cannot compile
//! tokio's multi-thread runtime. Therefore, this bridge does NOT directly call
//! `scp-core` identity functions. Instead, it:
//!
//! 1. Provides the correct opaque types (`WasmIdentity`, `WasmDIDDocument`)
//!    that the TypeScript SDK wrapper consumes.
//! 2. Returns typed errors signalling which operations require JS-side
//!    implementation (`WebCrypto` for key ops, DHT HTTP gateway for resolution).
//! 3. Acts as the stable ABI boundary — the TypeScript wrapper implements the
//!    actual protocol operations and stores results in these opaque handles.
//!
//! When a future story adds WASM-compatible scp-core feature flags (e.g.,
//! `tokio/single-thread`), these stubs will be connected to scp-core directly.
//!
//! # Opaque types
//!
//! `WasmIdentity` stores the DID string and custody type — NOT raw key
//! material. Key operations are delegated to the JS-injected `JsKeyCustody`
//! (see `custody.rs`), backed by `SubtleCrypto`.
//!
//! `WasmDIDDocument` exposes all document fields as JSON strings for
//! ergonomic TypeScript consumption.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md` for the full specification.

use scp_ffi_common::error_codes as codes;
use std::cell::RefCell;
use std::collections::HashMap;

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::ScpWasmError;

// ---------------------------------------------------------------------------
// Canonical hash helpers (matching scp-core::crypto::canonical)
// ---------------------------------------------------------------------------

/// Absent sentinel: `SHA-256(0x00)` — matches scp-core's `ABSENT_SENTINEL`.
const ABSENT_SENTINEL: [u8; 32] = [
    0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98, 0x9c, 0xa5, 0x44, 0xe6, 0xbb, 0x78, 0x0a, 0x2c,
    0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76, 0x85, 0x11, 0xa3, 0x06, 0x17, 0xaf, 0xa0, 0x1d,
];

/// Local structs mirroring scp-core's `AttestationClaim` field declaration order.
///
/// `rmp_serde::to_vec_named` serializes fields in struct declaration order for
/// named structs, but in alphabetical (`BTreeMap`) order for `serde_json::Value`.
/// To produce byte-identical msgpack output, we deserialize the JSON values into
/// these local structs before serializing to msgpack.
mod canonical_attestation {
    use serde::{Deserialize, Serialize};

    /// Mirrors `scp_core::identity::attestation::AttestationClaim` field order:
    /// `platform`, `platform_handle`, `platform_id`, `link_type`.
    #[derive(Serialize, Deserialize)]
    pub(super) struct Claim {
        pub platform: String,
        pub platform_handle: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub platform_id: Option<String>,
        pub link_type: String,
    }

    /// Mirrors `scp_core::identity::attestation::AttestationEvidence` field order:
    /// `method`, `proof`, `verified_at`, `verifier_did`.
    ///
    /// The `proof` field is an opaque string per §3.5.2 — verifiers MUST use
    /// this string as-is in signature scope, do not parse and re-serialize.
    #[derive(Serialize, Deserialize)]
    pub(super) struct Evidence {
        pub method: String,
        pub proof: String,
        pub verified_at: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verifier_did: Option<String>,
    }

    /// **Deprecated**: Typed proof data (§3.5.2). Retained for reference only.
    ///
    /// The wire format uses an opaque `String` for the `proof` field in
    /// [`Evidence`]. This enum is kept for informational purposes and
    /// internal validation tooling.
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    #[allow(clippy::enum_variant_names, dead_code)]
    pub(super) enum Proof {
        OauthVerified {
            provider: String,
            subject_id: String,
            verified_at: u64,
        },
        SignedPostVerified {
            post_url: String,
            nonce: String,
            posted_at: u64,
        },
        DnsRecordVerified {
            domain: String,
            record_name: String,
        },
        ChallengeResponseVerified {
            challenge: String,
            response_signature: String,
        },
    }

    // RevocationStatus imported from scp-protocol — canonical implementation.
    // Used instead of `serde_json::Value` for `revocation_status` serialization to
    // produce byte-identical msgpack output matching scp-core.
}

// ---------------------------------------------------------------------------
// WASM-local identity registry
// ---------------------------------------------------------------------------

/// Per-identity state stored in the WASM-local registry.
///
/// Two variants enforce the spec §3.2.1 two-key invariant at the type level:
///
/// * [`IdentityRecord::Local`] — A locally-created identity holding both the
///   `#0` identity key and the distinct `#active` signing key, plus an
///   optional `#agent` key. Produced by [`identity_create`],
///   [`identity_create_with_agent_key`], and [`identity_migrate`].
///   [`identity_rotate_key`] mutates an existing `Local` record in place,
///   replacing only `#active`. Can sign.
/// * [`IdentityRecord::Resolved`] — A DID-resolution-only handle carrying
///   just the `#0` public key and custody-type metadata. Produced when the
///   bridge knows a DID exists (e.g. after a future JS-driven DID resolve
///   path inserts one) but has no retained private key material. Cannot
///   sign — [`sign_with_identity`] returns [`codes::IDENT_1028`] on these.
///
/// Private key fields are wrapped in [`zeroize::Zeroizing`] and the enum
/// implements [`ZeroizeOnDrop`] so that key material is overwritten with zeros
/// when the entry is removed from the registry or replaced. `Clone` is
/// intentionally NOT derived — cloning would scatter unprotected copies of
/// private keys through WASM linear memory.
#[derive(Zeroize, ZeroizeOnDrop)]
enum IdentityRecord {
    /// Locally-created identity with retained key material for `#0` and
    /// `#active`, and an optional `#agent` key.
    ///
    /// `active_signing_key_bytes` is NOT `Option` — spec §3.2.1 mandates a
    /// distinct `#active` key, and the type system now enforces it. The
    /// scp-core bridges generate both keys as two separate Ed25519
    /// keypairs during `DidDht::create` (see `scp-identity/src/dht.rs`).
    /// Under `InMemoryKeyCustody::from_seed_bytes`, they consume the
    /// deterministic seed stream in sequence: `seed[0..32]` → identity
    /// key, `seed[32..64]` → active signing key. This bridge mirrors
    /// that sequence in both production (`OsRng`) and testing (seeded
    /// `StdRng`) builds — see ADR-046 for cross-bridge parity.
    Local {
        /// Ed25519 signing key bytes (32 bytes) for the DID-deriving
        /// identity key (`#0`). Used to sign device attestations
        /// (signed by `#0` per spec). NEVER used for day-to-day
        /// `#active` signatures, identity link attestations
        /// (signed by `#active` or `#agent` per spec §3.5/§3.5.2),
        /// or other operational signatures — those go through
        /// `active_signing_key_bytes`.
        ///
        /// Wrapped in `Zeroizing` for defense-in-depth: WASM linear
        /// memory is readable by same-origin JS, so key material must be
        /// zeroed on drop.
        signing_key_bytes: zeroize::Zeroizing<[u8; 32]>,
        /// Distinct `#active` signing key (spec §3.2.1). Used by
        /// [`sign_with_identity`] for `"#active"` signatures and
        /// published under the `#active` VM in
        /// [`resolve_did_document_fields`].
        ///
        /// Wrapped in `Zeroizing` (same rationale as
        /// `signing_key_bytes`).
        active_signing_key_bytes: zeroize::Zeroizing<[u8; 32]>,
        /// Pre-rotation Ed25519 signing key (spec §3.7, ADR-003 §4b).
        /// Reserved for the next identity-key migration: when
        /// `identity_migrate` runs, this private key becomes the new
        /// `#0` and a `PreRotationProof` is built showing
        /// `SHA-256(public(this))` matches the commitment published in
        /// the old DID document's `#pre-rotation` service endpoint.
        ///
        /// Mirrors the native bridges' `ScpIdentity::pre_rotation_commitment`
        /// (which stores the hash; we store the private key and recompute
        /// the hash on demand because WASM has no separate `KeyCustody`
        /// store). Generated by `identity_create` /
        /// `identity_create_with_agent_key` /  `identity_migrate` and
        /// preserved by `identity_rotate_key` (Layer-1 rotation does
        /// not consume the commitment).
        ///
        /// Wrapped in `Zeroizing` (same rationale as
        /// `signing_key_bytes`).
        pre_rotation_signing_key_bytes: zeroize::Zeroizing<[u8; 32]>,
        /// Ed25519 public key bytes (32 bytes) — the `#0` VM's public
        /// key, i.e. the DID-deriving identity key's public half.
        public_key_bytes: [u8; 32],
        /// Custody type string. Retained for future use when custody
        /// operations are wired (e.g., signing, key rotation).
        #[allow(dead_code)]
        custody_type: String,
        /// Agent signing key bytes (32 bytes), if an agent key has been
        /// bound. Used by [`sign_with_identity`] for `"#agent"`
        /// signatures.
        ///
        /// Wrapped in `Zeroizing` (same rationale as
        /// `signing_key_bytes`).
        agent_signing_key_bytes: Option<zeroize::Zeroizing<[u8; 32]>>,
    },
    /// Resolved-by-DID handle: carries only the `#0` public key and
    /// custody-type metadata. No local signing capability — attempts to
    /// sign return [`codes::IDENT_1028`]. The JS side is responsible for
    /// performing DHT resolution and presenting the full DID document;
    /// this variant exists so the bridge can expose public-key-only
    /// reads (`resolve_did_document_fields`) without pretending to have
    /// sign capability.
    ///
    /// No public bridge function constructs a `Resolved` record today
    /// — all current constructors (`identity_create`,
    /// `identity_create_with_agent_key`, `identity_migrate`) produce
    /// `Local`. `Resolved` exists as a
    /// type-level capacity for future resolution paths (e.g. the JS
    /// side passing a DHT-resolved DID document back across the
    /// boundary) and as a structural guard against the silent-fallback
    /// bug the `Option`-based model permitted (review round 12
    /// MINOR-4). The dead-code attribute is kept local to this variant
    /// so that the rest of the enum still surfaces unused fields.
    #[allow(dead_code)]
    Resolved {
        /// Ed25519 public key bytes (32 bytes) — the `#0` VM's public
        /// key, i.e. the DID-deriving identity key's public half.
        public_key_bytes: [u8; 32],
        /// Custody type string. Retained for future use when custody
        /// operations are wired.
        #[allow(dead_code)]
        custody_type: String,
    },
}

impl IdentityRecord {
    /// Returns the `#0` identity public key bytes for both variants.
    fn public_key_bytes(&self) -> [u8; 32] {
        match self {
            Self::Local {
                public_key_bytes, ..
            }
            | Self::Resolved {
                public_key_bytes, ..
            } => *public_key_bytes,
        }
    }

    /// Returns the custody type string for both variants.
    #[cfg(test)]
    fn custody_type(&self) -> &str {
        match self {
            Self::Local { custody_type, .. } | Self::Resolved { custody_type, .. } => {
                custody_type.as_str()
            }
        }
    }
}

/// Computes the pre-rotation commitment for a public key.
///
/// Per spec §3.7 / ADR-003 §4b: `commitment = SHA-256(pre_rotation_public_key)`.
/// Published as the `#pre-rotation` service endpoint in the DID document
/// in the `sha256:<hex>` format. On `identity_migrate`, the new `#0`
/// public key is revealed; verifiers check `SHA-256(revealed) == commitment`.
fn compute_pre_rotation_commitment(public_key_bytes: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(public_key_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

impl std::fmt::Debug for IdentityRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local {
                public_key_bytes,
                custody_type,
                agent_signing_key_bytes,
                ..
            } => {
                let mut ds = f.debug_struct("IdentityRecord::Local");
                ds.field("signing_key_bytes", &"[REDACTED]")
                    .field("active_signing_key_bytes", &"[REDACTED]")
                    .field("pre_rotation_signing_key_bytes", &"[REDACTED]")
                    .field("public_key_bytes", public_key_bytes)
                    .field("custody_type", custody_type)
                    .field(
                        "agent_signing_key_bytes",
                        &if agent_signing_key_bytes.is_some() {
                            "[REDACTED]"
                        } else {
                            "[None]"
                        },
                    );
                ds.finish()
            }
            Self::Resolved {
                public_key_bytes,
                custody_type,
            } => {
                let mut ds = f.debug_struct("IdentityRecord::Resolved");
                ds.field("public_key_bytes", public_key_bytes)
                    .field("custody_type", custody_type);
                ds.finish()
            }
        }
    }
}

/// Maximum number of identities in the WASM-local identity registry.
const WASM_IDENTITY_REGISTRY_CAP: usize = 10_000;

/// Checks that a `HashMap` has capacity for a new key. Returns `Err(JsValue)` if
/// the map is at `cap` and the key is not already present.
fn check_registry_capacity<K: std::hash::Hash + Eq, V>(
    map: &HashMap<K, V>,
    key: &K,
    cap: usize,
    registry_name: &str,
    error_code: &str,
) -> Result<(), JsValue> {
    if !map.contains_key(key) && map.len() >= cap {
        return Err(ScpWasmError::Validation {
            message: format!(
                "{registry_name} has reached capacity ({cap}) \
                 — cannot store additional entries"
            ),
            code: error_code.to_owned(),
        }
        .into_js()
        .into());
    }
    Ok(())
}

/// Maximum number of migration links stored in the WASM-local registry.
const WASM_MIGRATION_LINKS_CAP: usize = 10_000;

/// Maximum number of identity link attestation entries (DID keys) in the
/// WASM-local attestation registry.
const WASM_LINK_ATTESTATIONS_CAP: usize = 1_000;

use scp_ffi_common::validate::MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID;

thread_local! {
    /// Maps DID strings to identity state. WASM is single-threaded, so
    /// `RefCell` is sufficient. Capped at [`WASM_IDENTITY_REGISTRY_CAP`].
    static IDENTITY_REGISTRY: RefCell<HashMap<String, IdentityRecord>> =
        RefCell::new(HashMap::new());

    /// Maps new DID → old DID for migration links. Used by `identity_resolve`
    /// to populate `alsoKnownAs` fields. Capped at [`WASM_MIGRATION_LINKS_CAP`].
    static MIGRATION_LINKS: RefCell<HashMap<String, String>> =
        RefCell::new(HashMap::new());

    /// Identity link attestations stored per DID (§3.5.1).
    static LINK_ATTESTATIONS: RefCell<HashMap<String, Vec<serde_json::Value>>> =
        RefCell::new(HashMap::new());
}

// ---------------------------------------------------------------------------
// HMAC helpers (pub(crate) — used by manager.rs for export/import integrity)
// ---------------------------------------------------------------------------

/// Domain separation label for context export HMAC key derivation.
///
/// The creator's Ed25519 signing key is NOT used directly as the HMAC key.
/// Instead, we derive a purpose-specific key via HKDF-SHA256 with this info
/// string, so that the HMAC key is domain-separated from any signing use.
const EXPORT_HMAC_DOMAIN: &[u8] = b"scp-context-export-integrity-v1";

/// Computes HMAC-SHA256 over `data` using a key derived from the signing key
/// of the identity identified by `did`.
///
/// Returns the hex-encoded HMAC tag, or an error if the DID is not in the
/// identity registry.
///
/// The HMAC key is derived via `HKDF-SHA256(ikm=signing_key, salt=[], info=EXPORT_HMAC_DOMAIN)`
/// to ensure domain separation from the signing key's primary use (Ed25519
/// signatures).
pub(crate) fn compute_export_hmac(did: &str, data: &[u8]) -> Result<String, ScpWasmError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let hmac_key = derive_export_hmac_key(did)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(hmac_key.as_ref()).map_err(|e| ScpWasmError::Identity {
            message: format!("HMAC key init failed: {e}"),
            code: codes::CTX_2020.to_owned(),
        })?;
    mac.update(data);
    let result = mac.finalize();
    Ok(hex::encode(result.into_bytes()))
}

/// Resolves a specific verification method key by `kid` fragment identifier
/// for the given DID from the WASM-local identity registry (ADR-039).
///
/// - `#active` — returns the identity/active public key bytes.
/// - `#agent` — returns the agent public key bytes (derived from the stored
///   agent signing key). Returns an error if no agent key is bound.
/// - Any other `kid` value is rejected fail-closed.
///
/// Returns `Err` if the DID is not in the registry or the kid is invalid.
/// Used by [`crate::ucan::resolve_public_key_by_kid`] for kid-aware signature
/// verification.
pub(crate) fn resolve_verification_method_key(did: &str, kid: &str) -> Result<[u8; 32], String> {
    IDENTITY_REGISTRY.with(|reg| {
        let map = reg.borrow();
        let entry = map
            .get(did)
            .ok_or_else(|| format!("DID '{did}' not found in identity registry"))?;

        match (entry, kid) {
            // `#active` must mirror `sign_with_identity`'s key-selection
            // logic. Per spec §3.2.1, the active signing key is distinct
            // from the identity key for every SCP identity. The
            // `IdentityRecord::Local` variant carries the real active
            // signing key and its verifying key is derived here.
            (
                IdentityRecord::Local {
                    active_signing_key_bytes,
                    ..
                },
                "#active",
            ) => {
                let sk = ed25519_dalek::SigningKey::from_bytes(active_signing_key_bytes);
                Ok(sk.verifying_key().to_bytes())
            }
            (
                IdentityRecord::Local {
                    agent_signing_key_bytes,
                    ..
                },
                "#agent",
            ) => {
                let agent_sk_bytes = agent_signing_key_bytes.as_ref().ok_or_else(|| {
                    format!("no agent key bound for DID '{did}' — cannot verify kid '#agent'")
                })?;
                let sk = ed25519_dalek::SigningKey::from_bytes(agent_sk_bytes);
                Ok(sk.verifying_key().to_bytes())
            }
            // Resolved-by-DID handles carry only the `#0` public key —
            // the `#active` and `#agent` verifying keys would need to
            // come from a DHT resolution, which this bridge does not
            // perform. Fail closed rather than silently returning `#0`
            // under `#active` (which would violate spec §3.2.1 two-key
            // parity).
            (IdentityRecord::Resolved { .. }, "#active" | "#agent") => Err(format!(
                "DID '{did}' was resolved from a DID string without local key material — \
                 cannot verify kid '{kid}'; create a local identity via identity_create or \
                 perform DHT resolution on the JS side"
            )),
            (_, other) => Err(format!(
                "unrecognized verification method '{other}' on DID '{did}' \
                 (expected '#active' or '#agent')"
            )),
        }
    })
}

/// Verifies an HMAC-SHA256 tag over `data` using a key derived from the
/// signing key of the identity identified by `did`.
///
/// Returns `Ok(())` if the tag is valid, or an error if the DID is not found
/// or the tag does not match.
pub(crate) fn verify_export_hmac(
    did: &str,
    data: &[u8],
    expected_hex: &str,
) -> Result<(), ScpWasmError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let expected_bytes = hex::decode(expected_hex).map_err(|e| ScpWasmError::Context {
        message: format!("integrity_mac is not valid hex: {e}"),
        code: codes::CTX_2020.to_owned(),
    })?;

    let hmac_key = derive_export_hmac_key(did)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(hmac_key.as_ref()).map_err(|e| ScpWasmError::Identity {
            message: format!("HMAC key init failed: {e}"),
            code: codes::CTX_2020.to_owned(),
        })?;
    mac.update(data);
    mac.verify_slice(&expected_bytes)
        .map_err(|_| ScpWasmError::Context {
            message: "export integrity check failed — HMAC does not match".to_owned(),
            code: codes::CTX_2020.to_owned(),
        })
}

/// Derives a 32-byte HMAC key from the identity's Ed25519 signing key via
/// HKDF-SHA256 with domain separation.
///
/// The derived key is wrapped in `Zeroizing` to ensure it is zeroed on drop.
fn derive_export_hmac_key(did: &str) -> Result<zeroize::Zeroizing<[u8; 32]>, ScpWasmError> {
    IDENTITY_REGISTRY.with(|reg| {
        let map = reg.borrow();
        let entry = map.get(did).ok_or_else(|| ScpWasmError::Identity {
            message: format!("identity '{did}' not found in registry — cannot compute export HMAC"),
            code: codes::CTX_2020.to_owned(),
        })?;

        // Export HMAC requires the identity's signing key (IKM). Only a
        // `Local` record carries key material; a `Resolved` record is a
        // DID-resolution-only handle that cannot derive an HMAC key.
        let signing_key_bytes = match entry {
            IdentityRecord::Local {
                signing_key_bytes, ..
            } => signing_key_bytes,
            IdentityRecord::Resolved { .. } => {
                return Err(ScpWasmError::Identity {
                    message: format!(
                        "identity '{did}' was resolved from a DID string without local \
                         key material — cannot compute export HMAC"
                    ),
                    code: codes::IDENT_1028.to_owned(),
                });
            }
        };

        // HKDF-SHA256: extract(salt=[], ikm=signing_key) then
        // expand(info=EXPORT_HMAC_DOMAIN, len=32).
        let prk = hkdf_extract_sha256(&[], signing_key_bytes.as_ref()).map_err(|e| {
            ScpWasmError::Identity {
                message: format!("HKDF extract failed: {e}"),
                code: codes::CTX_2020.to_owned(),
            }
        })?;
        let okm = hkdf_expand_sha256(&prk, EXPORT_HMAC_DOMAIN, 32).map_err(|e| {
            ScpWasmError::Identity {
                message: format!("HKDF expand failed: {e}"),
                code: codes::CTX_2020.to_owned(),
            }
        })?;
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&okm);
        Ok(key)
    })
}

/// HKDF-Extract (RFC 5869) using HMAC-SHA256.
///
/// Returns the PRK wrapped in `Zeroizing` to ensure it is cleared from memory
/// on drop.
///
/// # Errors
///
/// Returns an error string if HMAC initialization fails (should not happen
/// since HMAC-SHA256 accepts any key length, but we avoid `expect`/`unwrap`).
fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let effective_salt: &[u8] = if salt.is_empty() { &[0u8; 32] } else { salt };
    let mut mac =
        Hmac::<Sha256>::new_from_slice(effective_salt).map_err(|e| format!("HMAC init: {e}"))?;
    mac.update(ikm);
    Ok(zeroize::Zeroizing::new(mac.finalize().into_bytes().into()))
}

/// HKDF-Expand (RFC 5869) using HMAC-SHA256.
///
/// `length` must be <= 255 * 32 = 8160 bytes.
///
/// All intermediates (`t` blocks, output buffer) are wrapped in `Zeroizing`
/// to ensure they are cleared from memory on drop.
///
/// # Errors
///
/// Returns an error string if HMAC initialization fails.
fn hkdf_expand_sha256(
    prk: &zeroize::Zeroizing<[u8; 32]>,
    info: &[u8],
    length: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let hash_len = 32;
    let n = length.div_ceil(hash_len);
    let mut okm = zeroize::Zeroizing::new(Vec::with_capacity(n * hash_len));
    let mut t = zeroize::Zeroizing::new(Vec::<u8>::new());

    for i in 1..=n {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(prk.as_ref()).map_err(|e| format!("HMAC init: {e}"))?;
        mac.update(&t);
        mac.update(info);
        #[allow(clippy::cast_possible_truncation)]
        mac.update(&[i as u8]);
        *t = mac.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&t);
    }

    okm.truncate(length);
    Ok(okm)
}

// ---------------------------------------------------------------------------
// z-base-32 encoding (mirrors ucan.rs zbase32_encode)
// ---------------------------------------------------------------------------

/// Minimal z-base-32 encoder for did:dht DID derivation.
///
/// z-base-32 uses the alphabet `ybndrfg8ejkmcpqxot1uwisza345h769`.
///
/// `pub(crate)` so other WASM bridge modules can reuse if needed.
pub(crate) fn zbase32_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

    let mut bits: u64 = 0;
    let mut bit_count: u32 = 0;
    let mut output = String::new();

    for &byte in input {
        bits = (bits << 8) | u64::from(byte);
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            #[allow(clippy::cast_possible_truncation)]
            let idx = ((bits >> bit_count) & 0x1f) as usize;
            output.push(ALPHABET[idx] as char);
            bits &= (1u64 << bit_count) - 1;
        }
    }

    // Encode remaining bits (padded to 5 bits).
    if bit_count > 0 {
        #[allow(clippy::cast_possible_truncation)]
        let idx = ((bits << (5 - bit_count)) & 0x1f) as usize;
        output.push(ALPHABET[idx] as char);
    }

    output
}

// ---------------------------------------------------------------------------
// WasmIdentity — opaque JS object for SCP identity
// ---------------------------------------------------------------------------

/// An SCP identity handle exposed to JavaScript.
///
/// Stores the DID string and custody type as safe, cloneable metadata.
/// Internal key material is NOT stored here — it remains within the
/// [`JsKeyCustody`](crate::custody::JsKeyCustody) boundary on the JS side,
/// managed by the browser's `SubtleCrypto` API.
///
/// # JS usage
///
/// ```js
/// const identity = await identity_create("js_custody");
/// console.log(identity.did);          // "did:dht:z..."
/// console.log(identity.custodyType);  // "js_custody"
/// ```
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmIdentity {
    /// The DID string (e.g., `"did:dht:z6Mk..."`).
    did: String,
    /// The custody type used at identity creation (`"js_custody"`).
    custody_type: String,
    /// Whether this identity has an `#agent` verification method.
    ///
    /// Managed locally (no scp-core dependency, per ADR-034).
    /// Set via `addAgentKey()` / `removeAgentKey()` / `rotateAgentKey()`.
    has_agent_key: bool,
    /// The agent key's public key as a multibase-encoded string, if present.
    ///
    /// Stored as metadata for JS-side consumption. Actual key material is
    /// managed by the JS `SubtleCrypto` API via `JsKeyCustody`.
    agent_public_key_multibase: Option<String>,
    /// Hex-encoded Ed25519 verifying-key bytes for the **identity key**
    /// (VM `#0`, the DID-deriving key). 64 hex chars = 32 raw bytes.
    /// `None` for identities constructed via `fromDid` without retained
    /// key material.
    ///
    /// Exposed as `#0` (not `#active`) for cross-bridge parity per
    /// ADR-046: every bridge's `identity_create` under a deterministic
    /// seed produces byte-identical `#0` public keys, and the NAPI bridge
    /// (`crates/scp-ffi/napi/src/identity.rs:281-290`) is the canonical
    /// definition of this field. `identity_rotate_key` rotates `#active`
    /// only — `#0` (and therefore this snapshot) is invariant across
    /// rotation.
    verifying_key_hex: Option<String>,
}

#[wasm_bindgen]
impl WasmIdentity {
    /// Returns the DID string for this identity.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn did(&self) -> String {
        self.did.clone()
    }

    /// Returns the custody type string for this identity.
    ///
    /// Always `"js_custody"` for browser targets.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "custodyType")]
    pub fn custody_type(&self) -> String {
        self.custody_type.clone()
    }

    /// Returns the hex-encoded Ed25519 verifying-key bytes for the `#0`
    /// identity key. See the `verifying_key_hex` field doc for the full
    /// contract (cross-bridge parity, rotation invariance, `null` for
    /// `from_did` handles).
    #[must_use]
    #[wasm_bindgen(getter, js_name = "verifyingKey")]
    pub fn verifying_key(&self) -> Option<String> {
        self.verifying_key_hex.clone()
    }

    /// Constructs a `WasmIdentity` from a DID string.
    ///
    /// Called by the TypeScript SDK after performing identity creation
    /// operations via `WebCrypto`. The SDK is responsible for:
    /// 1. Generating the Ed25519 keypairs via `SubtleCrypto.generateKey`.
    /// 2. Computing the `did:dht` string from the identity key public bytes.
    /// 3. Publishing the DID document to the DHT via HTTP gateway.
    /// 4. Calling `WasmIdentity.fromDid(did)` to obtain this handle.
    ///
    /// # Errors
    ///
    /// Returns `[SCP-IDENT-1000]` if the DID prefix is not `did:dht:`.
    #[wasm_bindgen(js_name = "fromDid")]
    pub fn from_did(did: String) -> Result<Self, JsError> {
        if !did.starts_with("did:dht:") {
            return Err(ScpWasmError::Identity {
                message: format!("unsupported DID method in {did:?} — only did:dht is supported"),
                code: codes::IDENT_1004.to_owned(),
            }
            .into_js());
        }
        Ok(Self {
            did,
            custody_type: "js_custody".to_owned(),
            has_agent_key: false,
            agent_public_key_multibase: None,
            // `fromDid` builds a handle from a bare DID string without
            // retained key material, so the verifying_key parity field is
            // unpopulated. Callers that need byte-exact parity must go
            // through `identity_create(custody, seed)`.
            verifying_key_hex: None,
        })
    }

    /// Returns whether this identity has an agent signing key (`#agent` VM).
    ///
    /// See ADR-039 acceptance criterion 4.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "hasAgentKey")]
    pub fn has_agent_key(&self) -> bool {
        self.has_agent_key
    }

    /// Returns the agent key's public key as a multibase string, or `null`.
    ///
    /// See ADR-039 acceptance criterion 4.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "agentPublicKey")]
    pub fn agent_public_key(&self) -> Option<String> {
        self.agent_public_key_multibase.clone()
    }

    /// Adds an agent signing key to this identity (ADR-039).
    ///
    /// # Contract
    ///
    /// The caller (TypeScript SDK) **MUST** have already updated the DID
    /// document on the DHT to include the `#agent` verification method
    /// **BEFORE** calling this method. Local state is **NOT** automatically
    /// synced with the DHT — this method only updates the in-memory
    /// `WasmIdentity`. Calling this method without completing the DHT update
    /// first will result in inconsistent state between the local
    /// `WasmIdentity` and the published DID document.
    ///
    /// ## Required steps (in order)
    ///
    /// 1. Generate the Ed25519 agent keypair via `SubtleCrypto.generateKey`.
    /// 2. Encode the public key as multibase.
    /// 3. Update the DID document on the DHT to include the `#agent` VM.
    /// 4. Call this method with the multibase public key to record state.
    ///
    /// # Errors
    ///
    /// Returns `[SCP-IDENT-1009]` if the identity already has an agent key.
    /// Returns `[SCP-IDENT-1010]` if the public key is empty.
    #[wasm_bindgen(js_name = "addAgentKey")]
    pub fn add_agent_key(&mut self, public_key_multibase: String) -> Result<(), JsError> {
        if self.has_agent_key {
            return Err(ScpWasmError::Identity {
                message: "identity already has an agent key — remove it first or use \
                          rotateAgentKey"
                    .to_owned(),
                code: codes::IDENT_1009.to_owned(),
            }
            .into_js());
        }
        if public_key_multibase.is_empty() {
            return Err(ScpWasmError::Identity {
                message: "agent public key multibase string must not be empty".to_owned(),
                code: codes::IDENT_1010.to_owned(),
            }
            .into_js());
        }
        self.has_agent_key = true;
        self.agent_public_key_multibase = Some(public_key_multibase);
        Ok(())
    }

    /// Removes the agent signing key from this identity (ADR-039).
    ///
    /// # Contract
    ///
    /// The caller (TypeScript SDK) **MUST** have already updated the DID
    /// document on the DHT to remove the `#agent` verification method
    /// **BEFORE** calling this method. Local state is **NOT** automatically
    /// synced with the DHT — this method only updates the in-memory
    /// `WasmIdentity`. Calling this method without completing the DHT update
    /// first will result in inconsistent state between the local
    /// `WasmIdentity` and the published DID document.
    ///
    /// ## Required steps (in order)
    ///
    /// 1. Remove the `#agent` VM from the DID document on the DHT.
    /// 2. Call this method to update local state.
    ///
    /// # Errors
    ///
    /// Returns `[SCP-IDENT-1011]` if the identity has no agent key.
    #[wasm_bindgen(js_name = "removeAgentKey")]
    pub fn remove_agent_key(&mut self) -> Result<(), JsError> {
        if !self.has_agent_key {
            return Err(ScpWasmError::Identity {
                message: "identity has no agent key to remove".to_owned(),
                code: codes::IDENT_1011.to_owned(),
            }
            .into_js());
        }
        self.has_agent_key = false;
        self.agent_public_key_multibase = None;
        Ok(())
    }

    /// Rotates the agent signing key for this identity (ADR-039).
    ///
    /// # Contract
    ///
    /// The caller (TypeScript SDK) **MUST** have already updated the DID
    /// document on the DHT to retire the old `#agent` verification method
    /// and install the new one **BEFORE** calling this method. Local state
    /// is **NOT** automatically synced with the DHT — this method only
    /// updates the in-memory `WasmIdentity`. Calling this method without
    /// completing the DHT update first will result in inconsistent state
    /// between the local `WasmIdentity` and the published DID document.
    ///
    /// ## Required steps (in order)
    ///
    /// 1. Generate the new Ed25519 agent keypair via `SubtleCrypto.generateKey`.
    /// 2. Encode the new public key as multibase.
    /// 3. Update the DID document on the DHT (retiring old `#agent`,
    ///    installing new).
    /// 4. Call this method with the new multibase public key to update state.
    ///
    /// # Errors
    ///
    /// Returns `[SCP-IDENT-1011]` if the identity has no agent key to rotate.
    /// Returns `[SCP-IDENT-1010]` if the new public key is empty.
    #[wasm_bindgen(js_name = "rotateAgentKey")]
    pub fn rotate_agent_key(&mut self, new_public_key_multibase: String) -> Result<(), JsError> {
        if !self.has_agent_key {
            return Err(ScpWasmError::Identity {
                message: "identity has no agent key to rotate — use addAgentKey first".to_owned(),
                code: codes::IDENT_1011.to_owned(),
            }
            .into_js());
        }
        if new_public_key_multibase.is_empty() {
            return Err(ScpWasmError::Identity {
                message: "new agent public key multibase string must not be empty".to_owned(),
                code: codes::IDENT_1010.to_owned(),
            }
            .into_js());
        }
        self.agent_public_key_multibase = Some(new_public_key_multibase);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WasmDIDDocument — opaque JS object for DID documents
// ---------------------------------------------------------------------------

/// A DID Document exposed to JavaScript.
///
/// Exposes the document's public fields via getter properties. All structured
/// fields (verification methods, services) are returned as JSON strings for
/// ergonomic TypeScript consumption — the TS wrapper parses them with
/// `JSON.parse()`.
///
/// # JS usage
///
/// ```js
/// const doc = await identity_resolve("did:dht:z...");
/// const vms = JSON.parse(doc.verificationMethodsJson);
/// console.log(doc.id); // "did:dht:z..."
/// ```
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmDIDDocument {
    /// The DID string this document describes.
    id: String,
    /// Verification methods serialized as JSON (array of objects with
    /// `id`, `type`, `controller`, `publicKeyMultibase`).
    verification_methods_json: String,
    /// Service entries serialized as JSON (array of objects with
    /// `id`, `type`, `serviceEndpoint`).
    services_json: String,
    /// `alsoKnownAs` entries serialized as JSON (array of strings).
    also_known_as_json: String,
    /// Authentication method references serialized as JSON (array of strings).
    authentication_json: String,
    /// Assertion method references serialized as JSON (array of strings).
    assertion_methods_json: String,
}

#[wasm_bindgen]
impl WasmDIDDocument {
    /// Returns the DID string this document describes.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    /// Returns the verification methods as a JSON string.
    ///
    /// Each object has `id`, `type`, `controller`, and `publicKeyMultibase`.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "verificationMethodsJson")]
    pub fn verification_methods_json(&self) -> String {
        self.verification_methods_json.clone()
    }

    /// Returns the service entries as a JSON string.
    ///
    /// Each object has `id`, `type`, and `serviceEndpoint`.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "servicesJson")]
    pub fn services_json(&self) -> String {
        self.services_json.clone()
    }

    /// Returns the `alsoKnownAs` entries as a JSON string.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "alsoKnownAsJson")]
    pub fn also_known_as_json(&self) -> String {
        self.also_known_as_json.clone()
    }

    /// Returns the authentication method references as a JSON string.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "authenticationJson")]
    pub fn authentication_json(&self) -> String {
        self.authentication_json.clone()
    }

    /// Returns the assertion method references as a JSON string.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "assertionMethodsJson")]
    pub fn assertion_methods_json(&self) -> String {
        self.assertion_methods_json.clone()
    }

    /// Constructs a `WasmDIDDocument` from JSON-encoded fields.
    ///
    /// Called by the TypeScript SDK after resolving a DID via the DHT HTTP
    /// gateway. The TypeScript layer performs the resolution and passes the
    /// parsed document fields back into the WASM boundary as JSON strings.
    ///
    /// All parameters must be valid JSON strings. Validation is performed by
    /// the TypeScript SDK before calling this constructor.
    #[must_use]
    // wasm-bindgen JS constructor must accept all fields individually.
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = "fromFields")]
    pub fn from_fields(
        id: String,
        verification_methods_json: String,
        services_json: String,
        also_known_as_json: String,
        authentication_json: String,
        assertion_methods_json: String,
    ) -> Self {
        Self {
            id,
            verification_methods_json,
            services_json,
            also_known_as_json,
            authentication_json,
            assertion_methods_json,
        }
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Narrows a caller-supplied `testing_seed` byte vector to a
/// zeroize-wrapped `[u8; 32]` and zeroizes the source `Vec<u8>`
/// before it drops.
///
/// The caller-supplied `testing_seed` parameter is a parity-harness
/// affordance (ADR-046), not a production API — mirrors how the
/// other three bridges gate `signed_at_override` behind `testing`.
/// Production WASM bundles reject any non-None seed with
/// `SCP-VALID-7008`; the testing build consumes the 32 bytes to drive
/// `StdRng::from_seed` in `identity_create`. A length mismatch
/// surfaces as `SCP-VALID-7007`.
///
/// Wrapping the narrowed array in `Zeroizing` ensures the seed bytes
/// are wiped when dropped — they feed `StdRng::from_seed` below and
/// produce the Ed25519 `#0`/`#active` private keys.
///
/// The function takes ownership of the source `Vec<u8>` and zeroes
/// its heap buffer before it drops. Leaving the source un-zeroed
/// means the original 32 seed bytes linger in the allocator's
/// freelist until overwritten, and — because WASM linear memory is
/// same-origin-readable from JS — any same-origin script can recover
/// them until the memory is reused (bug-catcher + security round 2).
/// JS callers are separately responsible for zeroing their own
/// `Uint8Array` after calling, but this bridge should not amplify
/// their exposure.
fn narrow_testing_seed(
    testing_seed: Option<Vec<u8>>,
) -> Result<Option<zeroize::Zeroizing<[u8; 32]>>, JsValue> {
    use zeroize::Zeroize;

    let Some(mut source) = testing_seed else {
        return Ok(None);
    };

    #[cfg(feature = "testing")]
    {
        let narrowed = scp_ffi_common::validate::expect_fixed_bytes::<32>(&source, "testing_seed")
            .map_err(|message| {
                ScpWasmError::Validation {
                    message,
                    code: codes::VALID_7007.to_owned(),
                }
                .into_js()
            })?;
        source.zeroize();
        Ok(Some(zeroize::Zeroizing::new(narrowed)))
    }

    #[cfg(not(feature = "testing"))]
    {
        // Wipe the source even on the rejection path — the caller
        // supplied bytes, we must not let them linger regardless of
        // whether we accept them.
        source.zeroize();
        Err(ScpWasmError::Validation {
            message: "`testing_seed` parameter requires the `testing` feature — not available \
                      in production WASM builds"
                .to_owned(),
            code: codes::VALID_7008.to_owned(),
        }
        .into_js()
        .into())
    }
}

/// Creates a new SCP identity.
///
/// Generates an Ed25519 keypair using the browser's cryptographic random
/// number generator (`crypto.getRandomValues` via `getrandom/js`), derives
/// a `did:dht` DID string from the public key, and returns a
/// [`WasmIdentity`] handle.
///
/// # Arguments
///
/// * `custody` — The custody type string. Must be `"js_custody"` or
///   `"in_memory"` for browser targets.
/// * `testing_seed` — Parity-harness affordance (ADR-046). Consumed and
///   zeroed inside the bridge. **JS caller responsibility:** WASM
///   linear memory is same-origin-readable from JS, so the caller's
///   source `Uint8Array` must also be zeroed after this call returns
///   — the bridge cannot reach through the `wasm-bindgen` boundary
///   to wipe the JS-side buffer.
///
/// # Returns
///
/// `Promise<WasmIdentity>` — resolves to the newly created identity handle.
///
/// # Errors
///
/// - Rejects with `[SCP-IDENT-1000]` if key generation fails.
/// - Rejects with `[SCP-IDENT-1004]` if the custody type is not supported.
///
/// See ADR-022 acceptance criterion 1.
///
/// Module-private alias for the three keys [`identity_create`] mints in a
/// single batch: the `#0` `SigningKey` (whose `to_bytes()` is consumed
/// directly when storing) plus the `#active` and pre-rotation private
/// bytes already wrapped in `Zeroizing` for lifetime-scoped wiping.
type ThreeKeyTuple = (
    ed25519_dalek::SigningKey,
    zeroize::Zeroizing<[u8; 32]>,
    zeroize::Zeroizing<[u8; 32]>,
);

#[wasm_bindgen]
pub fn identity_create(custody: String, testing_seed: Option<Vec<u8>>) -> Promise {
    future_to_promise(async move {
        if custody != "js_custody" && custody != "in_memory" {
            return Err(ScpWasmError::Identity {
                message: format!(
                    "unsupported custody type {custody:?} — only \"js_custody\" and \"in_memory\" \
                     are supported in the browser WASM bridge"
                ),
                code: codes::IDENT_1004.to_owned(),
            }
            .into_js()
            .into());
        }

        // Narrow + zeroize-wrap `testing_seed` — gated by the `testing`
        // feature. `narrow_testing_seed` takes ownership of the source
        // `Vec<u8>` and zeroes its heap buffer before it drops, since
        // WASM linear memory is same-origin-readable by JS and freed
        // bytes stay observable until the allocator reuses them.
        let testing_seed_bytes: Option<zeroize::Zeroizing<[u8; 32]>> =
            narrow_testing_seed(testing_seed)?;

        // Per spec §3.2.1 + §3.7, every SCP identity carries three
        // distinct Ed25519 keys: `#0` (the identity key, DID-deriving,
        // never rotates), `#active` (the rotatable active signing key),
        // and a pre-rotation key whose hash is published as the
        // `#pre-rotation` service commitment for the next identity-key
        // migration. scp-core's `DidDht::create` and
        // `create_with_agent_key` generate them via consecutive
        // `generate_keypair` calls on `InMemoryKeyCustody`; under
        // `from_seed_bytes` they consume `seed[0..32]`, `seed[32..64]`,
        // `seed[64..96]` (and `seed[96..128]` for the agent key).
        //
        // This bridge matches that sequence on both paths:
        //
        // * No-seed path — three independent `OsRng`-sourced keys
        //   (same behaviour as scp-core's default `generate_keypair`).
        // * Seed path — `StdRng::from_seed(seed)` consumed three times
        //   for 32 bytes each, byte-identical to the other bridges
        //   under a shared seed (ADR-046 cross-bridge parity harness).
        let random_three_key = || -> ThreeKeyTuple {
            let identity_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
            let active_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
            let pre_rotation_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
            (
                identity_key,
                zeroize::Zeroizing::new(active_key.to_bytes()),
                zeroize::Zeroizing::new(pre_rotation_key.to_bytes()),
            )
        };
        #[cfg(feature = "testing")]
        let (signing_key, active_signing_key_bytes, pre_rotation_signing_key_bytes): ThreeKeyTuple =
            testing_seed_bytes
                .as_ref()
                .map_or_else(random_three_key, |s| {
                    use rand::{RngCore, SeedableRng};
                    // Deref through `Zeroizing<[u8; 32]>` — one unavoidable
                    // by-value Copy goes into `StdRng::from_seed`, which
                    // discards it after consuming the seed. The outer
                    // wrapper is wiped at end-of-scope.
                    let mut rng = rand::rngs::StdRng::from_seed(**s);
                    let mut identity_key_bytes = zeroize::Zeroizing::new([0u8; 32]);
                    rng.fill_bytes(identity_key_bytes.as_mut());
                    let identity_key = ed25519_dalek::SigningKey::from_bytes(&identity_key_bytes);
                    // Consume the next 32 bytes for the distinct #active key.
                    let mut active_bytes = zeroize::Zeroizing::new([0u8; 32]);
                    rng.fill_bytes(active_bytes.as_mut());
                    // Consume the next 32 bytes for the pre-rotation key
                    // (matches scp-core's create_new_identity_keys order).
                    let mut pre_rotation_bytes = zeroize::Zeroizing::new([0u8; 32]);
                    rng.fill_bytes(pre_rotation_bytes.as_mut());
                    (identity_key, active_bytes, pre_rotation_bytes)
                });
        #[cfg(not(feature = "testing"))]
        let (signing_key, active_signing_key_bytes, pre_rotation_signing_key_bytes): ThreeKeyTuple = {
            // `testing_seed_bytes` is guaranteed `None` here — the
            // testing-gate match above returns early for any `Some(_)` on
            // non-testing builds. Silence the unused binding without
            // disturbing the shared control flow.
            let _ = testing_seed_bytes;
            random_three_key()
        };
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();

        // Derive did:dht DID from the public key using z-base-32 encoding.
        let did = format!("did:dht:z{}", zbase32_encode(&pub_bytes));
        let verifying_key_hex = hex::encode(pub_bytes);

        // Store the signing key in the WASM-local identity registry so that
        // identity_resolve can return the public key from the DID document
        // and identity_attest_device can produce real Ed25519 signatures.
        IDENTITY_REGISTRY.with(|reg| {
            let mut map = reg.borrow_mut();
            check_registry_capacity(
                &*map,
                &did,
                WASM_IDENTITY_REGISTRY_CAP,
                "identity registry",
                codes::VALID_7400,
            )?;
            map.insert(
                did.clone(),
                IdentityRecord::Local {
                    signing_key_bytes: zeroize::Zeroizing::new(signing_key.to_bytes()),
                    active_signing_key_bytes,
                    pre_rotation_signing_key_bytes,
                    public_key_bytes: pub_bytes,
                    custody_type: custody.clone(),
                    agent_signing_key_bytes: None,
                },
            );
            Ok::<(), JsValue>(())
        })?;

        Ok(JsValue::from(WasmIdentity {
            did,
            custody_type: custody,
            has_agent_key: false,
            agent_public_key_multibase: None,
            verifying_key_hex: Some(verifying_key_hex),
        }))
    })
}

/// Resolved DID document fields returned by [`resolve_did_document_fields`].
///
/// Each field is a JSON-serialized string matching the shape consumed by
/// [`WasmDIDDocument::from_fields`]. The `_json` suffix mirrors
/// [`WasmDIDDocument`]'s field naming convention.
#[allow(clippy::struct_field_names)]
struct ResolvedDocumentFields {
    verification_methods_json: String,
    services_json: String,
    also_known_as_json: String,
    authentication_json: String,
    assertion_methods_json: String,
}

/// Public-key bundle a registry record contributes to the DID document.
/// `Local` populates `active` and `pre_rotation_commitment`, plus
/// optionally `agent`; `Resolved` populates only the identity key.
///
/// All `_pub_bytes` fields are raw Ed25519 public keys for a distinct
/// VM (`#0`, `#active`, `#agent`); the shared suffix is the most precise
/// name, so the lint exemption is intentional and local.
#[allow(clippy::struct_field_names)]
struct ResolvedKeyInfo {
    identity_pub_bytes: [u8; 32],
    active_pub_bytes: Option<[u8; 32]>,
    agent_pub_bytes: Option<[u8; 32]>,
    /// SHA-256 hash of the next identity key's public bytes (spec §3.7).
    /// `Some` for `Local` records (we have the pre-rotation private key
    /// locally and can derive the public key + commitment); `None` for
    /// `Resolved` records — those carry no key material to commit.
    pre_rotation_commitment: Option<[u8; 32]>,
}

/// Looks up `did` in `IDENTITY_REGISTRY` and projects the record into
/// the public-key bundle the DID-document builder consumes. Returns
/// `None` for unknown DIDs.
fn read_resolved_key_info(did: &str) -> Option<ResolvedKeyInfo> {
    IDENTITY_REGISTRY.with(|reg| {
        let map = reg.borrow();
        map.get(did).map(|entry| match entry {
            IdentityRecord::Local {
                public_key_bytes,
                active_signing_key_bytes,
                pre_rotation_signing_key_bytes,
                agent_signing_key_bytes,
                ..
            } => {
                let agent_pub_bytes = agent_signing_key_bytes.as_ref().map(|sk_bytes| {
                    let sk = ed25519_dalek::SigningKey::from_bytes(sk_bytes);
                    sk.verifying_key().to_bytes()
                });
                let active_sk = ed25519_dalek::SigningKey::from_bytes(active_signing_key_bytes);
                let pre_rotation_pub =
                    ed25519_dalek::SigningKey::from_bytes(pre_rotation_signing_key_bytes)
                        .verifying_key()
                        .to_bytes();
                ResolvedKeyInfo {
                    identity_pub_bytes: *public_key_bytes,
                    active_pub_bytes: Some(active_sk.verifying_key().to_bytes()),
                    agent_pub_bytes,
                    pre_rotation_commitment: Some(compute_pre_rotation_commitment(
                        &pre_rotation_pub,
                    )),
                }
            }
            IdentityRecord::Resolved {
                public_key_bytes, ..
            } => ResolvedKeyInfo {
                identity_pub_bytes: *public_key_bytes,
                active_pub_bytes: None,
                agent_pub_bytes: None,
                pre_rotation_commitment: None,
            },
        })
    })
}

/// Renders the four DID-document JSON arrays from the resolved key
/// bundle: `(verification_methods, authentication, assertion_methods,
/// services)`. `Local` records produce `#0` + `#active` (+ optional
/// `#agent`) verification methods plus a `#pre-rotation` service;
/// `Resolved` records produce only `#0`.
fn build_did_document_arrays(
    did: &str,
    info: &ResolvedKeyInfo,
) -> (String, String, String, String) {
    let identity_multibase = format!("z{}", zbase32_encode(&info.identity_pub_bytes));

    // #0 — Identity Key (DID-deriving key, never rotates).
    let mut vms = vec![serde_json::json!({
        "id": format!("{did}#0"),
        "type": "Ed25519VerificationKey2020",
        "controller": did,
        "publicKeyMultibase": identity_multibase,
    })];

    let mut auth: Vec<serde_json::Value> = Vec::new();
    let mut assertion: Vec<serde_json::Value> = Vec::new();

    // #active — Active Signing Key. Per spec §3.2.1 a distinct key from
    // #0; emitted only when the bridge has the real material (`Local`).
    // `Resolved` records omit `#active` — JS supplies it via DHT.
    if let Some(active_bytes) = info.active_pub_bytes {
        let active_multibase = format!("z{}", zbase32_encode(&active_bytes));
        vms.push(serde_json::json!({
            "id": format!("{did}#active"),
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyMultibase": active_multibase,
        }));
        auth.push(serde_json::json!(format!("{did}#active")));
        assertion.push(serde_json::json!(format!("{did}#active")));
    }

    // #agent — Agent Signing Key (ADR-039), included when present.
    if let Some(agent_bytes) = info.agent_pub_bytes {
        let agent_multibase = format!("z{}", zbase32_encode(&agent_bytes));
        vms.push(serde_json::json!({
            "id": format!("{did}#agent"),
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyMultibase": agent_multibase,
        }));
        auth.push(serde_json::json!(format!("{did}#agent")));
        assertion.push(serde_json::json!(format!("{did}#agent")));
    }

    // #pre-rotation — commitment service entry (spec §3.7,
    // ADR-003 §4b). `Local` only; `Resolved` handles emit no services.
    let services = info
        .pre_rotation_commitment
        .map_or_else(Vec::new, |commitment| {
            vec![serde_json::json!({
                "id": format!("{did}#pre-rotation"),
                "type": "PreRotationCommitment",
                "serviceEndpoint": format!("sha256:{}", hex::encode(commitment)),
            })]
        });

    let vm_json = serde_json::Value::Array(vms);
    let auth_json = serde_json::Value::Array(auth);
    let assertion_json = serde_json::Value::Array(assertion);
    let services_json = serde_json::Value::Array(services);
    (
        serde_json::to_string(&vm_json).unwrap_or_else(|_| "[]".to_owned()),
        serde_json::to_string(&auth_json).unwrap_or_else(|_| "[]".to_owned()),
        serde_json::to_string(&assertion_json).unwrap_or_else(|_| "[]".to_owned()),
        serde_json::to_string(&services_json).unwrap_or_else(|_| "[]".to_owned()),
    )
}

/// Builds the DID document fields for a locally-known identity.
///
/// Pure logic extracted from [`identity_resolve`] so it can be tested without
/// `wasm_bindgen` / `Promise` / `JsValue` dependencies.
///
/// Reads from `IDENTITY_REGISTRY` and `MIGRATION_LINKS` thread-local state.
fn resolve_did_document_fields(did: &str) -> ResolvedDocumentFields {
    let (verification_methods_json, authentication_json, assertion_methods_json, services_json) =
        read_resolved_key_info(did).map_or_else(
            || {
                (
                    "[]".to_owned(),
                    "[]".to_owned(),
                    "[]".to_owned(),
                    "[]".to_owned(),
                )
            },
            |info| build_did_document_arrays(did, &info),
        );

    // Populate alsoKnownAs from MIGRATION_LINKS — after identity_migrate,
    // the new DID maps to the old DID (#540). `identity_rotate_key`
    // preserves the DID and therefore never writes to MIGRATION_LINKS.
    let also_known_as_json = MIGRATION_LINKS.with(|links| {
        let map = links.borrow();
        map.get(did).map_or_else(
            || "[]".to_owned(),
            |old_did| {
                let arr = serde_json::Value::Array(vec![serde_json::json!(old_did)]);
                serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_owned())
            },
        )
    });

    ResolvedDocumentFields {
        verification_methods_json,
        services_json,
        also_known_as_json,
        authentication_json,
        assertion_methods_json,
    }
}

/// Resolves a DID to its DID Document.
///
/// For locally-created identities, returns a DID document with the Ed25519
/// public key from the WASM-local identity registry. For unknown DIDs,
/// returns a minimal document with just the DID ID (the TypeScript SDK
/// performs full DHT resolution for remote DIDs).
///
/// # Arguments
///
/// * `did` — The DID string to resolve (e.g., `"did:dht:z6Mk..."`).
///
/// # Returns
///
/// `Promise<WasmDIDDocument>` — resolves to the DID document.
///
/// # Errors
///
/// Rejects with `[SCP-IDENT-1004]` if the DID method is not supported.
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn identity_resolve(did: String) -> Promise {
    future_to_promise(async move {
        if !did.starts_with("did:dht:") {
            return Err(ScpWasmError::Identity {
                message: format!("unsupported DID method in {did:?} — only did:dht is supported"),
                code: codes::IDENT_1004.to_owned(),
            }
            .into_js()
            .into());
        }

        let fields = resolve_did_document_fields(&did);

        Ok(JsValue::from(WasmDIDDocument::from_fields(
            did,
            fields.verification_methods_json,
            fields.services_json,
            fields.also_known_as_json,
            fields.authentication_json,
            fields.assertion_methods_json,
        )))
    })
}

/// Creates a new SCP identity with an agent signing key (ADR-039).
///
/// Generates two Ed25519 keypairs: one for the identity key and one for the
/// `#agent` verification method. Returns a `WasmIdentity` with
/// `has_agent_key = true`.
#[wasm_bindgen]
pub fn identity_create_with_agent_key(custody: String) -> Promise {
    future_to_promise(async move {
        if custody != "js_custody" && custody != "in_memory" {
            return Err(ScpWasmError::Identity {
                message: format!(
                    "unsupported custody type {custody:?} — only \"js_custody\" and \"in_memory\" \
                     are supported in the browser WASM bridge"
                ),
                code: codes::IDENT_1004.to_owned(),
            }
            .into_js()
            .into());
        }

        // Per spec §3.2.1 + §3.7 + ADR-039, an identity created via this
        // entry-point carries four distinct Ed25519 keys: `#0` (identity,
        // DID-deriving), `#active` (rotatable), pre-rotation (commitment
        // for next migration), and `#agent`. Generate all four
        // independently from `OsRng` in the order
        // `DidDht::create_with_agent_key` uses, so cross-bridge seeded
        // parity (ADR-046) holds when seeding paths are added later.
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();
        let did = format!("did:dht:z{}", zbase32_encode(&pub_bytes));

        // Distinct `#active` signing key (spec §3.2.1).
        let active_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let active_signing_key_bytes = zeroize::Zeroizing::new(active_key.to_bytes());

        // Pre-rotation key (spec §3.7) — its public-key hash is published
        // as the `#pre-rotation` service commitment by
        // `resolve_did_document_fields`.
        let pre_rotation_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let pre_rotation_signing_key_bytes = zeroize::Zeroizing::new(pre_rotation_key.to_bytes());

        // Generate agent Ed25519 keypair.
        let agent_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let agent_pub = agent_key.verifying_key();
        let agent_multibase = format!("z{}", zbase32_encode(&agent_pub.to_bytes()));

        IDENTITY_REGISTRY.with(|reg| {
            let mut map = reg.borrow_mut();
            check_registry_capacity(
                &*map,
                &did,
                WASM_IDENTITY_REGISTRY_CAP,
                "identity registry",
                codes::VALID_7400,
            )?;
            map.insert(
                did.clone(),
                IdentityRecord::Local {
                    signing_key_bytes: zeroize::Zeroizing::new(signing_key.to_bytes()),
                    active_signing_key_bytes,
                    pre_rotation_signing_key_bytes,
                    public_key_bytes: pub_bytes,
                    custody_type: custody.clone(),
                    agent_signing_key_bytes: Some(zeroize::Zeroizing::new(agent_key.to_bytes())),
                },
            );
            Ok::<(), JsValue>(())
        })?;

        Ok(JsValue::from(WasmIdentity {
            did,
            custody_type: custody,
            has_agent_key: true,
            agent_public_key_multibase: Some(agent_multibase),
            verifying_key_hex: Some(hex::encode(pub_bytes)),
        }))
    })
}

/// Adds an agent signing key to an existing identity (ADR-039).
///
/// Generates a new Ed25519 agent keypair, stores it in the identity registry,
/// and returns an updated identity.
///
/// # Errors
///
/// - `[SCP-IDENT-1002]` — the input DID is not in the local identity
///   registry.
/// - `[SCP-IDENT-1009]` — the identity already has an agent key.
/// - `[SCP-IDENT-1028]` — the registry entry is a `Resolved` handle
///   without retained key material.
#[wasm_bindgen]
pub fn identity_add_agent_key(identity: &WasmIdentity) -> Result<WasmIdentity, JsError> {
    if identity.has_agent_key {
        return Err(ScpWasmError::Identity {
            message: "identity already has an agent key".to_owned(),
            code: codes::IDENT_1009.to_owned(),
        }
        .into_js());
    }
    let agent_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let agent_pub = agent_key.verifying_key();
    let agent_multibase = format!("z{}", zbase32_encode(&agent_pub.to_bytes()));

    // Store the agent signing key in the identity registry. Only a
    // `Local` record can carry an agent key; `Resolved` handles do not
    // have retained key material and cannot host an agent key.
    let did = identity.did.clone();
    let status = IDENTITY_REGISTRY.with(|reg| {
        let mut map = reg.borrow_mut();
        match map.get_mut(&did) {
            Some(IdentityRecord::Local {
                agent_signing_key_bytes,
                ..
            }) => {
                *agent_signing_key_bytes = Some(zeroize::Zeroizing::new(agent_key.to_bytes()));
                AgentKeyMutationStatus::Updated
            }
            Some(IdentityRecord::Resolved { .. }) => AgentKeyMutationStatus::NotLocal,
            None => AgentKeyMutationStatus::NotFound,
        }
    });
    match status {
        AgentKeyMutationStatus::Updated => {}
        AgentKeyMutationStatus::NotFound => {
            return Err(ScpWasmError::Identity {
                message: format!("identity not found in registry: {did}"),
                code: codes::IDENT_1002.to_owned(),
            }
            .into_js());
        }
        AgentKeyMutationStatus::NotLocal => {
            return Err(ScpWasmError::Identity {
                message: format!(
                    "identity '{did}' was resolved from a DID string without local \
                     key material — cannot add an agent key"
                ),
                code: codes::IDENT_1028.to_owned(),
            }
            .into_js());
        }
    }

    Ok(WasmIdentity {
        did,
        custody_type: identity.custody_type.clone(),
        has_agent_key: true,
        agent_public_key_multibase: Some(agent_multibase),
        // The identity key does not change when an agent key is added, so
        // the original `verifying_key` carries through.
        verifying_key_hex: identity.verifying_key_hex.clone(),
    })
}

/// Outcome of a registry mutation that writes to the agent-key slot.
/// Exists so callers can distinguish "DID not in registry" from
/// "DID in registry but the record is a `Resolved` handle that cannot
/// host key material."
enum AgentKeyMutationStatus {
    Updated,
    NotFound,
    NotLocal,
}

/// Rotates the agent signing key for an identity (ADR-039).
///
/// Generates a new Ed25519 agent keypair, stores it in the identity registry,
/// and returns an updated identity.
///
/// # Errors
///
/// - `[SCP-IDENT-1002]` — the input DID is not in the local identity
///   registry.
/// - `[SCP-IDENT-1010]` — the new public key is empty.
/// - `[SCP-IDENT-1011]` — the identity has no agent key to rotate.
/// - `[SCP-IDENT-1028]` — the registry entry is a `Resolved` handle
///   without retained key material.
#[wasm_bindgen]
pub fn identity_rotate_agent_key(identity: &WasmIdentity) -> Result<WasmIdentity, JsError> {
    if !identity.has_agent_key {
        return Err(ScpWasmError::Identity {
            message: "identity has no agent key to rotate".to_owned(),
            code: codes::IDENT_1011.to_owned(),
        }
        .into_js());
    }
    let agent_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let agent_pub = agent_key.verifying_key();
    let agent_multibase = format!("z{}", zbase32_encode(&agent_pub.to_bytes()));

    // Store the new agent signing key in the identity registry. Only a
    // `Local` record can host an agent key.
    let did = identity.did.clone();
    let status = IDENTITY_REGISTRY.with(|reg| {
        let mut map = reg.borrow_mut();
        match map.get_mut(&did) {
            Some(IdentityRecord::Local {
                agent_signing_key_bytes,
                ..
            }) => {
                *agent_signing_key_bytes = Some(zeroize::Zeroizing::new(agent_key.to_bytes()));
                AgentKeyMutationStatus::Updated
            }
            Some(IdentityRecord::Resolved { .. }) => AgentKeyMutationStatus::NotLocal,
            None => AgentKeyMutationStatus::NotFound,
        }
    });
    match status {
        AgentKeyMutationStatus::Updated => {}
        AgentKeyMutationStatus::NotFound => {
            return Err(ScpWasmError::Identity {
                message: format!("identity not found in registry: {did}"),
                code: codes::IDENT_1002.to_owned(),
            }
            .into_js());
        }
        AgentKeyMutationStatus::NotLocal => {
            return Err(ScpWasmError::Identity {
                message: format!(
                    "identity '{did}' was resolved from a DID string without local \
                     key material — cannot rotate an agent key"
                ),
                code: codes::IDENT_1028.to_owned(),
            }
            .into_js());
        }
    }

    Ok(WasmIdentity {
        did,
        custody_type: identity.custody_type.clone(),
        has_agent_key: true,
        agent_public_key_multibase: Some(agent_multibase),
        // The identity key (and thus DID) does not change when only the
        // agent key rotates.
        verifying_key_hex: identity.verifying_key_hex.clone(),
    })
}

/// Rotates the `#active` signing key for an identity (spec §3.2.1, ADR-003 §4a).
///
/// This is **active-key-only rotation** — the same Layer-1 operation
/// implemented by `DidDht::rotate_active_key` on the native bridges
/// (`PyO3` / NAPI / `UniFFI`). The DID and `#0` identity key are preserved;
/// only the `#active` signing key is replaced. After rotation, every
/// future `#active` signature uses the new key, while signatures over `#0`
/// (device attestations, identity link attestations) remain unaffected.
///
/// Behavioral parity with native:
/// - DID string unchanged (derived from `#0`).
/// - `#0` identity key unchanged.
/// - `#agent` signing key unchanged (preserved across rotation).
/// - `#active` verifying method in the resolved DID document reflects the new
///   public key on the next `identity_resolve` call.
///
/// Identity-key migration (which produces a *new* DID and stores the old DID
/// in `alsoKnownAs`) is a distinct operation; use [`identity_migrate`] for
/// that.
///
/// # Caller responsibilities
///
/// Mirrors the native bridges' contract — the FFI rotation only replaces
/// the local `#active` material. After this call, the caller MUST:
///
/// - Issue MLS Update proposals in every active context so peers pick up
///   the new credential before the old `#active` expires from their
///   resolved DID document (spec §3.2.1 step 3b).
/// - Revoke and reissue UCAN tokens that were signed by the old
///   `#active` key (spec §3.2.1 step 3c).
/// - Re-sign and republish identity link attestations (§3.5) whose
///   envelope `signingKeyId` was `#active`; signatures made with the old
///   key will no longer verify against the resolved DID document
///   (spec §3.2.1 step 4a, §3.5.2).
///
/// The bridge itself does not perform DHT / relay republication — JS-
/// side publication is the SDK wrapper's responsibility (ADR-022,
/// ADR-034). Until publication runs, off-host verifiers will continue to
/// see the old `#active` in the resolved DID document.
///
/// # Pre-rotation commitment
///
/// Spec §3.7 defines a forward-secure rotation chain via
/// `pre_rotation_commitment`. Native `ScpIdentity` carries that field
/// across rotation; the WASM `IdentityRecord::Local` does not model it.
/// Layer-1 (`#active`) rotation is unaffected: the commitment binds
/// Layer-2 (`#0`) migration, not active-key rotation.
///
/// # Errors
///
/// - `[SCP-IDENT-1002]` — the input DID is not in the local identity
///   registry. Only identities created via [`identity_create`] /
///   [`identity_create_with_agent_key`] can be rotated; bare DIDs constructed
///   via [`WasmIdentity::from_did`] carry no retained key material.
/// - `[SCP-IDENT-1028]` — the registry entry is a `Resolved` handle without
///   retained signing-key material; rotation requires a `Local` record.
#[wasm_bindgen]
pub fn identity_rotate_key(identity: &WasmIdentity) -> Result<WasmIdentity, JsError> {
    rotate_active_key_inner(identity).map_err(ScpWasmError::into_js)
}

/// Inner implementation of [`identity_rotate_key`] that surfaces
/// [`ScpWasmError`] directly. Splitting the function this way lets the
/// non-wasm `#[test]` build inspect typed error variants — the
/// `wasm-bindgen` wrapper above can only return `JsError`, which cannot
/// be unwrapped outside a real wasm runtime.
fn rotate_active_key_inner(identity: &WasmIdentity) -> Result<WasmIdentity, ScpWasmError> {
    // Generate the new `#active` Ed25519 keypair before touching the
    // registry, so a key-generation failure (none today, but defensive)
    // never leaves the registry in a half-rotated state.
    let new_active = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let new_active_bytes = zeroize::Zeroizing::new(new_active.to_bytes());

    let did = identity.did.clone();
    let status = IDENTITY_REGISTRY.with(|reg| {
        let mut map = reg.borrow_mut();
        match map.get_mut(&did) {
            Some(IdentityRecord::Local {
                active_signing_key_bytes,
                ..
            }) => {
                // In-place replacement: the old `Zeroizing<[u8; 32]>` is
                // dropped and zeroed when the new value is assigned, so no
                // unprotected copy of the previous active key persists.
                *active_signing_key_bytes = new_active_bytes;
                AgentKeyMutationStatus::Updated
            }
            Some(IdentityRecord::Resolved { .. }) => AgentKeyMutationStatus::NotLocal,
            None => AgentKeyMutationStatus::NotFound,
        }
    });
    match status {
        AgentKeyMutationStatus::Updated => {}
        AgentKeyMutationStatus::NotFound => {
            return Err(ScpWasmError::Identity {
                message: format!("identity not found in registry: {did}"),
                code: codes::IDENT_1002.to_owned(),
            });
        }
        AgentKeyMutationStatus::NotLocal => {
            return Err(ScpWasmError::Identity {
                message: format!(
                    "identity '{did}' was resolved from a DID string without local \
                     key material — cannot rotate the active signing key"
                ),
                code: codes::IDENT_1028.to_owned(),
            });
        }
    }

    Ok(WasmIdentity {
        did,
        custody_type: identity.custody_type.clone(),
        // The agent-key state is preserved by the in-place mutation above
        // (we only touched `active_signing_key_bytes`), so the input
        // handle's flags carry through unchanged.
        has_agent_key: identity.has_agent_key,
        agent_public_key_multibase: identity.agent_public_key_multibase.clone(),
        // The `#0` identity key (and thus the DID and the
        // `verifying_key_hex` snapshot of `#0`) is unchanged — the input
        // handle's value carries through.
        verifying_key_hex: identity.verifying_key_hex.clone(),
    })
}

/// Removes the agent signing key from an identity (ADR-039).
///
/// # Errors
///
/// - `[SCP-IDENT-1002]` — the input DID is not in the local identity
///   registry.
/// - `[SCP-IDENT-1011]` — the identity has no agent key to remove.
/// - `[SCP-IDENT-1028]` — the registry entry is a `Resolved` handle
///   without retained key material.
#[wasm_bindgen]
pub fn identity_remove_agent_key(identity: &WasmIdentity) -> Result<WasmIdentity, JsError> {
    if !identity.has_agent_key {
        return Err(ScpWasmError::Identity {
            message: "identity has no agent key to remove".to_owned(),
            code: codes::IDENT_1011.to_owned(),
        }
        .into_js());
    }

    // Clear the agent signing key from the identity registry to prevent
    // the key material from lingering in WASM linear memory. Only
    // `Local` records host an agent key; for `Resolved` there is no key
    // to clear, so fail-closed with a distinct error.
    let did = identity.did.clone();
    let status = IDENTITY_REGISTRY.with(|reg| {
        let mut map = reg.borrow_mut();
        match map.get_mut(&did) {
            Some(IdentityRecord::Local {
                agent_signing_key_bytes,
                ..
            }) => {
                *agent_signing_key_bytes = None;
                AgentKeyMutationStatus::Updated
            }
            Some(IdentityRecord::Resolved { .. }) => AgentKeyMutationStatus::NotLocal,
            None => AgentKeyMutationStatus::NotFound,
        }
    });
    match status {
        AgentKeyMutationStatus::Updated => {}
        AgentKeyMutationStatus::NotFound => {
            return Err(ScpWasmError::Identity {
                message: format!("identity not found in registry: {did}"),
                code: codes::IDENT_1002.to_owned(),
            }
            .into_js());
        }
        AgentKeyMutationStatus::NotLocal => {
            return Err(ScpWasmError::Identity {
                message: format!(
                    "identity '{did}' was resolved from a DID string without local \
                     key material — cannot remove an agent key"
                ),
                code: codes::IDENT_1028.to_owned(),
            }
            .into_js());
        }
    }

    Ok(WasmIdentity {
        did,
        custody_type: identity.custody_type.clone(),
        has_agent_key: false,
        agent_public_key_multibase: None,
        // Removing an agent key does not change the identity key.
        verifying_key_hex: identity.verifying_key_hex.clone(),
    })
}

/// Result of [`identity_migrate`]: the new identity handle and the
/// `DidRotationEvent` JSON that the SDK distributes to context members.
///
/// The event JSON shape mirrors `scp_identity::DidRotationEvent` (spec
/// §3.7, ADR-003 §4b/§4c):
///
/// ```json
/// {
///   "old_did": "did:dht:z...",
///   "new_did": "did:dht:z...",
///   "migration_proof": {
///     "signature": "<128-hex>",
///     "old_public_key": "<64-hex>"
///   },
///   "pre_rotation_proof": {
///     "commitment": "<64-hex>",
///     "revealed_key": "<64-hex>"
///   },
///   "rotated_at": <unix-seconds>
/// }
/// ```
///
/// `pre_rotation_proof` is always present because the WASM bridge always
/// publishes a `#pre-rotation` commitment for `Local` identities; verifiers
/// can therefore demand STRONG-assurance migration.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmIdentityMigrationResult {
    identity: WasmIdentity,
    rotation_event_json: String,
}

#[wasm_bindgen]
impl WasmIdentityMigrationResult {
    /// Returns the migrated identity (the new DID).
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn identity(&self) -> WasmIdentity {
        self.identity.clone()
    }

    /// Returns the JSON-serialized `DidRotationEvent`.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "rotationEventJson")]
    pub fn rotation_event_json(&self) -> String {
        self.rotation_event_json.clone()
    }
}

/// Domain separator for migration proofs (spec §3.7, ADR-003 §4c).
const DOMAIN_MIGRATION_V1: &[u8] = b"SCP-MIGRATION-V1:";

/// Migrates an identity to a new DID (Layer-2 rotation, spec §3.7).
///
/// The pre-rotation key retained at identity creation becomes the new
/// `#0` identity key, fulfilling the commitment published in the old
/// DID document's `#pre-rotation` service. A fresh `#active` and a
/// fresh pre-rotation key are minted for the new DID. The function
/// returns a [`WasmIdentityMigrationResult`] containing the new
/// `WasmIdentity` and a `DidRotationEvent` JSON that the SDK MUST
/// distribute to all active contexts (spec §3.2.1 step 4b).
///
/// `MigrationProof` is the old `#0`'s signature over
/// `SHA-256("SCP-MIGRATION-V1:" || u32(len(old_did)) || old_did
///         || u32(len(new_did)) || new_did || u64(rotated_at))`.
/// `PreRotationProof` reveals the new `#0` public key against the old
/// document's `#pre-rotation` commitment so verifiers can check
/// `SHA-256(revealed_key) == commitment` (STRONG assurance).
///
/// If the source identity has an agent key, a new agent key is generated
/// for the migrated identity (preserving the `has_agent_key` state).
/// Link attestations are ported to the new DID, and a `MIGRATION_LINKS`
/// entry is recorded so `identity_resolve` can surface `alsoKnownAs`.
///
/// # Errors
///
/// - `[SCP-IDENT-1002]` — the input DID is not in the local identity
///   registry; the bridge has no retained pre-rotation key, so a
///   spec-conformant migration is impossible.
/// - `[SCP-IDENT-1028]` — the registry entry is a `Resolved` handle
///   without retained signing-key material.
/// - `[SCP-VALID-7400]` — the WASM identity registry has reached its
///   capacity limit and cannot accept the new DID.
/// - `[SCP-VALID-7401]` — the migration-links registry has reached its
///   capacity limit and cannot record the new→old DID mapping.
#[wasm_bindgen]
pub fn identity_migrate(identity: &WasmIdentity) -> Promise {
    let identity_clone = identity.clone();
    future_to_promise(async move {
        let rotated_at = crate::time::now_secs();
        migrate_inner(&identity_clone, rotated_at)
            .map(JsValue::from)
            .map_err(|e| -> JsValue { e.into_js().into() })
    })
}

/// Snapshot of the source-identity private key material that
/// [`migrate_inner`] needs before mutating the registry. Held in
/// `Zeroizing` wrappers so the temporary copies wipe at end-of-scope
/// (the WASM linear memory is readable by same-origin JS).
struct MigrationSourceKeys {
    signing: zeroize::Zeroizing<[u8; 32]>,
    pre_rotation: zeroize::Zeroizing<[u8; 32]>,
    public_bytes: [u8; 32],
}

/// Outcome of `IDENTITY_REGISTRY` lookup during migration. Distinguishes
/// "not present" (`SCP-IDENT-1002`) from "present but lacking key
/// material" (`SCP-IDENT-1028`).
enum MigrationLookupOutcome {
    Found(MigrationSourceKeys),
    NotLocal,
    NotFound,
}

/// Looks up the source identity for [`migrate_inner`] and returns its
/// retained key material (or a typed error: `SCP-IDENT-1002` for "DID
/// not found" / `SCP-IDENT-1028` for `Resolved` records).
fn lookup_migration_source(did: &str) -> Result<MigrationSourceKeys, ScpWasmError> {
    let lookup = IDENTITY_REGISTRY.with(|reg| {
        let map = reg.borrow();
        match map.get(did) {
            Some(IdentityRecord::Local {
                signing_key_bytes,
                pre_rotation_signing_key_bytes,
                public_key_bytes,
                ..
            }) => MigrationLookupOutcome::Found(MigrationSourceKeys {
                signing: zeroize::Zeroizing::new(**signing_key_bytes),
                pre_rotation: zeroize::Zeroizing::new(**pre_rotation_signing_key_bytes),
                public_bytes: *public_key_bytes,
            }),
            Some(IdentityRecord::Resolved { .. }) => MigrationLookupOutcome::NotLocal,
            None => MigrationLookupOutcome::NotFound,
        }
    });
    match lookup {
        MigrationLookupOutcome::Found(k) => Ok(k),
        MigrationLookupOutcome::NotFound => Err(ScpWasmError::Identity {
            message: format!("identity not found in registry: {did}"),
            code: codes::IDENT_1002.to_owned(),
        }),
        MigrationLookupOutcome::NotLocal => Err(ScpWasmError::Identity {
            message: format!(
                "identity '{did}' was resolved from a DID string without local \
                 key material — cannot migrate without the retained pre-rotation key"
            ),
            code: codes::IDENT_1028.to_owned(),
        }),
    }
}

/// Removes the source identity, capacity-checks, and installs the
/// migrated `Local` record. Also ports `LINK_ATTESTATIONS` to the new
/// DID and records the `MIGRATION_LINKS` mapping for `alsoKnownAs`.
fn install_migrated_identity(
    old_did: &str,
    new_did: &str,
    record: IdentityRecord,
) -> Result<(), ScpWasmError> {
    IDENTITY_REGISTRY.with(|reg| -> Result<(), ScpWasmError> {
        let mut map = reg.borrow_mut();
        map.remove(old_did);
        if !map.contains_key(new_did) && map.len() >= WASM_IDENTITY_REGISTRY_CAP {
            return Err(ScpWasmError::Validation {
                message: format!(
                    "identity registry has reached capacity ({WASM_IDENTITY_REGISTRY_CAP}) \
                     — cannot store additional entries"
                ),
                code: codes::VALID_7400.to_owned(),
            });
        }
        map.insert(new_did.to_owned(), record);
        Ok(())
    })?;

    LINK_ATTESTATIONS.with(|reg| {
        let mut map = reg.borrow_mut();
        if let Some(attestations) = map.remove(old_did) {
            map.insert(new_did.to_owned(), attestations);
        }
    });

    MIGRATION_LINKS.with(|links| -> Result<(), ScpWasmError> {
        let mut map = links.borrow_mut();
        if !map.contains_key(new_did) && map.len() >= WASM_MIGRATION_LINKS_CAP {
            return Err(ScpWasmError::Validation {
                message: format!(
                    "migration links registry has reached capacity ({WASM_MIGRATION_LINKS_CAP}) \
                     — cannot store additional entries"
                ),
                code: codes::VALID_7401.to_owned(),
            });
        }
        map.insert(new_did.to_owned(), old_did.to_owned());
        Ok(())
    })?;

    Ok(())
}

/// Builds the migration-proof Ed25519 signature over
/// `SHA-256("SCP-MIGRATION-V1:" || u32(len(old_did)) || old_did
///         || u32(len(new_did)) || new_did || u64(rotated_at))` using
/// the source `#0` private key. Byte-identical construction to native's
/// `build_migration_proof` in `crates/scp-identity/src/dht.rs`.
fn build_migration_signature(
    old_did: &str,
    new_did: &str,
    rotated_at: u64,
    source_signing_key: &zeroize::Zeroizing<[u8; 32]>,
) -> Result<[u8; 64], ScpWasmError> {
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};

    let old_len: u32 = old_did
        .len()
        .try_into()
        .map_err(|_| ScpWasmError::Identity {
            message: "old DID exceeds u32 length prefix".to_owned(),
            code: codes::IDENT_1004.to_owned(),
        })?;
    let new_len: u32 = new_did
        .len()
        .try_into()
        .map_err(|_| ScpWasmError::Identity {
            message: "new DID exceeds u32 length prefix".to_owned(),
            code: codes::IDENT_1004.to_owned(),
        })?;

    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_MIGRATION_V1);
    hasher.update(old_len.to_be_bytes());
    hasher.update(old_did.as_bytes());
    hasher.update(new_len.to_be_bytes());
    hasher.update(new_did.as_bytes());
    hasher.update(rotated_at.to_be_bytes());
    let digest = hasher.finalize();

    let signing_key = ed25519_dalek::SigningKey::from_bytes(source_signing_key);
    Ok(signing_key.sign(&digest).to_bytes())
}

/// Encodes the rotation event JSON for a successful migration. The
/// shape mirrors `scp_identity::DidRotationEvent` so JS-side verifiers
/// using the native verification helpers parse identically.
fn encode_rotation_event_json(
    old_did: &str,
    new_did: &str,
    rotated_at: u64,
    migration_signature_bytes: &[u8; 64],
    source_public_key: &[u8; 32],
    pre_rotation_commitment: &[u8; 32],
    revealed_new_identity_pub: &[u8; 32],
) -> Result<String, ScpWasmError> {
    let rotation_event = serde_json::json!({
        "old_did": old_did,
        "new_did": new_did,
        "migration_proof": {
            "signature": hex::encode(migration_signature_bytes),
            "old_public_key": hex::encode(source_public_key),
        },
        "pre_rotation_proof": {
            "commitment": hex::encode(pre_rotation_commitment),
            "revealed_key": hex::encode(revealed_new_identity_pub),
        },
        "rotated_at": rotated_at,
    });
    serde_json::to_string(&rotation_event).map_err(|e| ScpWasmError::Identity {
        message: format!("failed to serialize rotation event: {e}"),
        code: codes::IDENT_1004.to_owned(),
    })
}

/// Inner implementation of [`identity_migrate`] that surfaces
/// [`ScpWasmError`] directly and takes an explicit timestamp.
/// Splitting the function this way lets the non-wasm `#[test]` build
/// inspect typed error variants and drive the migration synchronously
/// without depending on `crate::time::now_secs()` (which routes through
/// `wasm-bindgen` `Date.now` and panics off-wasm). The `wasm-bindgen`
/// `Promise` wrapper above passes the live time source.
fn migrate_inner(
    identity: &WasmIdentity,
    rotated_at: u64,
) -> Result<WasmIdentityMigrationResult, ScpWasmError> {
    let old_did = identity.did.clone();
    let custody = identity.custody_type.clone();
    let had_agent_key = identity.has_agent_key;

    // Phase 1: extract source key material; refuses missing/Resolved.
    let source_keys = lookup_migration_source(&old_did)?;

    // Phase 2: the retained pre-rotation key BECOMES the new `#0`.
    let new_signing_key = ed25519_dalek::SigningKey::from_bytes(&source_keys.pre_rotation);
    let new_pub_bytes = new_signing_key.verifying_key().to_bytes();
    let new_did = format!("did:dht:z{}", zbase32_encode(&new_pub_bytes));

    // Fresh `#active` and fresh pre-rotation key for the new identity
    // (matches `DidDht::create_new_identity_keys` ordering).
    let new_active_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let new_active_signing_key_bytes = zeroize::Zeroizing::new(new_active_key.to_bytes());
    let new_pre_rotation_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let new_pre_rotation_signing_key_bytes =
        zeroize::Zeroizing::new(new_pre_rotation_key.to_bytes());

    // If the source identity had an agent key, mint a fresh one for
    // the migrated identity.
    let (new_agent_signing_key_bytes, new_agent_public_key_multibase) = if had_agent_key {
        let agent_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let agent_pub = agent_key.verifying_key();
        let multibase = format!("z{}", zbase32_encode(&agent_pub.to_bytes()));
        (
            Some(zeroize::Zeroizing::new(agent_key.to_bytes())),
            Some(multibase),
        )
    } else {
        (None, None)
    };

    // Phases 3-5: build proofs and rotation event JSON.
    let migration_signature_bytes =
        build_migration_signature(&old_did, &new_did, rotated_at, &source_keys.signing)?;
    // The commitment is `SHA-256(source_pre_rotation_pub)`, which the
    // old DID document published, and the revealed_key is the new `#0`.
    // By construction these are equal — no separate derivation needed.
    let pre_rotation_commitment = compute_pre_rotation_commitment(&new_pub_bytes);
    let rotation_event_json = encode_rotation_event_json(
        &old_did,
        &new_did,
        rotated_at,
        &migration_signature_bytes,
        &source_keys.public_bytes,
        &pre_rotation_commitment,
        &new_pub_bytes,
    )?;

    // Phase 6: install the new identity, port LINK_ATTESTATIONS,
    // record MIGRATION_LINKS for `alsoKnownAs`.
    install_migrated_identity(
        &old_did,
        &new_did,
        IdentityRecord::Local {
            signing_key_bytes: zeroize::Zeroizing::new(new_signing_key.to_bytes()),
            active_signing_key_bytes: new_active_signing_key_bytes,
            pre_rotation_signing_key_bytes: new_pre_rotation_signing_key_bytes,
            public_key_bytes: new_pub_bytes,
            custody_type: custody.clone(),
            agent_signing_key_bytes: new_agent_signing_key_bytes,
        },
    )?;

    Ok(WasmIdentityMigrationResult {
        identity: WasmIdentity {
            did: new_did,
            custody_type: custody,
            has_agent_key: had_agent_key,
            agent_public_key_multibase: new_agent_public_key_multibase,
            verifying_key_hex: Some(hex::encode(new_pub_bytes)),
        },
        rotation_event_json,
    })
}

/// Domain separator for device attestation payloads.
const DEVICE_ATTESTATION_DOMAIN: &[u8] = b"SCP-DEVICE-ATTESTATION-V1:";

/// Constructs the canonical device attestation payload bytes.
///
/// Format: `domain_separator || len(did) as u32 BE || did_bytes || timestamp as u64 BE`
///
/// Uses length-prefixed fields to match the canonical hash construction pattern
/// used by all other SCP signed payloads (§9.5.1).
fn device_attestation_payload(did: &str, timestamp_secs: u64) -> Vec<u8> {
    let did_bytes = did.as_bytes();
    let mut payload = Vec::with_capacity(DEVICE_ATTESTATION_DOMAIN.len() + 4 + did_bytes.len() + 8);
    payload.extend_from_slice(DEVICE_ATTESTATION_DOMAIN);
    #[allow(clippy::cast_possible_truncation)]
    payload.extend_from_slice(&(did_bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(did_bytes);
    payload.extend_from_slice(&timestamp_secs.to_be_bytes());
    payload
}

/// Generates a device attestation token for an identity.
///
/// Signs a timestamped challenge with the identity's Ed25519 signing key.
/// Returns the attestation token as a base64-encoded JSON string containing
/// the DID, timestamp, and a real Ed25519 signature over the attestation
/// payload.
#[wasm_bindgen]
pub fn identity_attest_device(did: String) -> Promise {
    use base64::Engine;
    use ed25519_dalek::Signer;

    future_to_promise(async move {
        // Create attestation payload using domain-separated canonical construction
        // matching other SCP signed payloads. Format: domain separator + length-prefixed
        // DID + u64 timestamp.
        let timestamp_secs = crate::time::now_secs();
        let payload = device_attestation_payload(&did, timestamp_secs);

        // Produce a real Ed25519 signature over the attestation payload.
        // Signing is performed inside the registry closure so that private
        // key material is never cloned out of the registry into unprotected
        // WASM linear memory.
        let signature_bytes = IDENTITY_REGISTRY.with(|reg| {
            let map = reg.borrow();
            let entry = map.get(&did).ok_or_else(|| -> JsValue {
                ScpWasmError::Identity {
                    message: format!("identity {did:?} not found in registry"),
                    code: codes::IDENT_1000.to_owned(),
                }
                .into_js()
                .into()
            })?;

            // Device attestation signs with the DID-deriving `#0`
            // identity key. Only `Local` records carry that key
            // material; `Resolved` handles are public-key-only and
            // cannot produce attestation signatures.
            let signing_key_bytes = match entry {
                IdentityRecord::Local {
                    signing_key_bytes, ..
                } => signing_key_bytes,
                IdentityRecord::Resolved { .. } => {
                    return Err::<[u8; 64], JsValue>(
                        ScpWasmError::Identity {
                            message: format!(
                                "identity '{did}' was resolved from a DID string \
                                 without local key material — cannot attest device"
                            ),
                            code: codes::IDENT_1028.to_owned(),
                        }
                        .into_js()
                        .into(),
                    );
                }
            };
            let signing_key = ed25519_dalek::SigningKey::from_bytes(signing_key_bytes);
            let signature = signing_key.sign(&payload);
            Ok::<[u8; 64], JsValue>(signature.to_bytes())
        })?;

        let token = serde_json::json!({
            "did": did,
            "timestamp": timestamp_secs,
            "signature": hex::encode(signature_bytes),
        });

        // Base64-encode the token JSON.
        let token_json = serde_json::to_string(&token).map_err(|e| -> JsValue {
            ScpWasmError::Identity {
                message: format!("failed to serialize attestation token: {e}"),
                code: codes::IDENT_1012.to_owned(),
            }
            .into_js()
            .into()
        })?;

        let encoded = base64::engine::general_purpose::STANDARD.encode(token_json.as_bytes());
        Ok(JsValue::from_str(&encoded))
    })
}

/// Parsed attestation token fields extracted from JSON.
///
/// Used internally by [`identity_verify_device_attestation`] and exposed
/// via [`parse_attestation_token`] for testability.
#[derive(Debug)]
struct AttestationTokenFields {
    did: String,
    timestamp: u64,
    signature_hex: String,
}

/// Decodes a base64 attestation token and extracts the required fields.
///
/// Returns `Err(ScpWasmError)` if:
/// - The base64 encoding is invalid (`SCP-IDENT-1013`).
/// - The JSON structure is invalid (`SCP-IDENT-1013`).
/// - The `did` field is missing or not a string (`SCP-VALID-7020`).
/// - The `timestamp` field is missing or not a u64 (`SCP-VALID-7021`).
/// - The `signature` field is missing or not a string (`SCP-VALID-7022`).
fn parse_attestation_token(token_base64: &str) -> Result<AttestationTokenFields, ScpWasmError> {
    use base64::Engine;

    let token_bytes = base64::engine::general_purpose::STANDARD
        .decode(token_base64.as_bytes())
        .map_err(|e| ScpWasmError::Identity {
            message: format!("invalid base64 in attestation token: {e}"),
            code: codes::IDENT_1013.to_owned(),
        })?;

    let token: serde_json::Value =
        serde_json::from_slice(&token_bytes).map_err(|e| ScpWasmError::Identity {
            message: format!("invalid JSON in attestation token: {e}"),
            code: codes::IDENT_1013.to_owned(),
        })?;

    let did = token["did"]
        .as_str()
        .ok_or_else(|| ScpWasmError::Validation {
            message: "attestation token missing required 'did' field (string)".to_owned(),
            code: codes::VALID_7020.to_owned(),
        })?
        .to_owned();

    let timestamp = token["timestamp"]
        .as_u64()
        .ok_or_else(|| ScpWasmError::Validation {
            message: "attestation token missing required 'timestamp' field (u64)".to_owned(),
            code: codes::VALID_7021.to_owned(),
        })?;

    let signature_hex = token["signature"]
        .as_str()
        .ok_or_else(|| ScpWasmError::Validation {
            message: "attestation token missing required 'signature' field (string)".to_owned(),
            code: codes::VALID_7022.to_owned(),
        })?
        .to_owned();

    Ok(AttestationTokenFields {
        did,
        timestamp,
        signature_hex,
    })
}

/// Verifies a device attestation token.
///
/// Decodes the base64 token, extracts the DID, timestamp, and Ed25519
/// signature, then verifies the signature against the identity's public
/// key in the registry.
///
/// # Errors
///
/// Rejects with validation errors if required token fields are missing:
/// - `[SCP-VALID-7020]` — missing `did` field
/// - `[SCP-VALID-7021]` — missing `timestamp` field
/// - `[SCP-VALID-7022]` — missing `signature` field
/// - `[SCP-IDENT-1013]` — invalid base64 or JSON encoding
#[wasm_bindgen]
pub fn identity_verify_device_attestation(did: String, token_base64: String) -> Promise {
    future_to_promise(async move {
        let fields = parse_attestation_token(&token_base64)
            .map_err(|e| -> JsValue { e.into_js().into() })?;

        if fields.did != did {
            return Ok(JsValue::from_bool(false));
        }

        // Freshness check: reject attestations older than 5 minutes (300s).
        // Prevents replay of captured attestation tokens.
        let now_secs = crate::time::now_secs();
        if now_secs.saturating_sub(fields.timestamp) > 300 {
            return Ok(JsValue::from_bool(false));
        }
        // Reject future-dated attestations (clock skew tolerance: 60s).
        if fields.timestamp > now_secs.saturating_add(60) {
            return Ok(JsValue::from_bool(false));
        }

        // Look up only the public key bytes from the registry — never
        // clone private key material out. Both variants expose the `#0`
        // public key via `IdentityRecord::public_key_bytes`.
        let pub_key_bytes = IDENTITY_REGISTRY.with(|reg| {
            let map = reg.borrow();
            map.get(&did).map(IdentityRecord::public_key_bytes)
        });

        let Some(pub_bytes) = pub_key_bytes else {
            return Ok(JsValue::from_bool(false));
        };

        // Decode the signature from hex.
        let Ok(sig_bytes) = hex::decode(&fields.signature_hex) else {
            return Ok(JsValue::from_bool(false));
        };
        let sig_array: [u8; 64] = match sig_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return Ok(JsValue::from_bool(false)),
        };

        // Verify the Ed25519 signature against the public key.
        let payload = device_attestation_payload(&did, fields.timestamp);
        let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&pub_bytes) else {
            return Ok(JsValue::from_bool(false));
        };
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
        let verified = verifying_key.verify_strict(&payload, &signature).is_ok();

        Ok(JsValue::from_bool(verified))
    })
}

/// Loads an existing identity from a DID string.
///
/// Validates the DID format and returns an identity handle. Storage loading
/// from wa-sqlite/IndexedDB is performed by the TypeScript SDK wrapper, which
/// then calls [`WasmIdentity::from_did`] to obtain this handle.
///
/// # Arguments
///
/// * `did` — The DID string (e.g., `"did:dht:z6Mk..."`).
///
/// # Returns
///
/// `Promise<WasmIdentity>` — resolves to the identity handle.
///
/// # Errors
///
/// Rejects with `[SCP-IDENT-1000]` if the DID method is not supported (only
/// `did:dht:` is accepted).
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn identity_load(did: String) -> Promise {
    future_to_promise(async move {
        if !did.starts_with("did:dht:") {
            return Err(ScpWasmError::Identity {
                message: format!("unsupported DID method in {did:?} — only did:dht is supported"),
                code: codes::IDENT_1004.to_owned(),
            }
            .into_js()
            .into());
        }

        // Check the registry for existing identity state (agent key, custody type).
        let (custody_type, has_agent_key, agent_pub_multibase, verifying_key_hex) =
            IDENTITY_REGISTRY.with(|reg| {
                let map = reg.borrow();
                match map.get(&did) {
                    Some(IdentityRecord::Local {
                        public_key_bytes,
                        custody_type,
                        agent_signing_key_bytes,
                        ..
                    }) => {
                        let agent_pub = agent_signing_key_bytes.as_ref().map(|sk_bytes| {
                            // Derive public key from agent signing key
                            // for the multibase field.
                            let sk = ed25519_dalek::SigningKey::from_bytes(sk_bytes);
                            let pk = ed25519_dalek::VerifyingKey::from(&sk);
                            format!("z{}", zbase32_encode(&pk.to_bytes()))
                        });
                        (
                            custody_type.clone(),
                            agent_pub.is_some(),
                            agent_pub,
                            Some(hex::encode(*public_key_bytes)),
                        )
                    }
                    Some(IdentityRecord::Resolved {
                        public_key_bytes,
                        custody_type,
                    }) => (
                        custody_type.clone(),
                        // `Resolved` handles never carry an agent key —
                        // they have no retained key material at all.
                        false,
                        None,
                        Some(hex::encode(*public_key_bytes)),
                    ),
                    None => ("js_custody".to_owned(), false, None, None),
                }
            });

        Ok(JsValue::from(WasmIdentity {
            did,
            custody_type,
            has_agent_key,
            agent_public_key_multibase: agent_pub_multibase,
            verifying_key_hex,
        }))
    })
}

// ---------------------------------------------------------------------------
// Compromise recovery — WASM local implementation (#632)
// ---------------------------------------------------------------------------

/// Executes the compromise recovery protocol for the given DID.
///
/// WASM cannot depend on scp-core (tokio multi-thread), and no real
/// recovery backend is available at the bridge layer. This function
/// validates the tier parameter and returns an error indicating that a
/// real backend must be provided via the SDK layer.
///
/// # Errors
///
/// Returns `SCP-IDENT-1020` if `tier` is not a recognized value.
/// Returns `SCP-IDENT-1022` because no recovery backend is configured.
///
/// See spec §9.12.
#[wasm_bindgen]
pub fn identity_execute_recovery(
    did: String,
    tier: String,
    context_ids: Vec<String>,
) -> Result<String, JsValue> {
    // Suppress unused-variable warnings — parameters are validated but the
    // operation cannot proceed without a real backend.
    let _ = &context_ids;

    // Validate DID before proceeding.
    if let Err(e) = scp_ffi_common::validate::validate_did(&did) {
        return Err(ScpWasmError::from(e).into_js().into());
    }

    // Validate tier parameter to give a clear error for invalid inputs.
    match tier.as_str() {
        "agent" | "active_signing" | "identity_key" => {}
        other => {
            return Err(ScpWasmError::Identity {
                message: format!(
                    "invalid compromise tier: {other}; expected 'agent', 'active_signing', or 'identity_key'"
                ),
                code: codes::IDENT_1020.to_owned(),
            }
            .into_js()
            .into());
        }
    }

    Err(ScpWasmError::Identity {
        message: "recovery backend not configured — provide a real backend via SDK layer"
            .to_owned(),
        code: codes::IDENT_1022.to_owned(),
    }
    .into_js()
    .into())
}

// ---------------------------------------------------------------------------
// SCPID signing helper (used by crate::scpid)
// ---------------------------------------------------------------------------

/// Signs arbitrary data with a registered identity's Ed25519 key.
///
/// Looks up the identity by DID and returns the 64-byte Ed25519 signature.
/// `signing_key_id` must be `"#active"` or `"#agent"`.
///
/// This is `pub(crate)` so the `scpid` module can reuse identity key lookup
/// without exposing the `IdentityRecord` enum or `IDENTITY_REGISTRY`.
///
/// Signing is a privilege of [`IdentityRecord::Local`]; a
/// [`IdentityRecord::Resolved`] handle carries no private key material and
/// any signing attempt returns [`codes::IDENT_1028`] (identity key handle
/// error) — a structural refusal that the `Option`-based fallback model
/// could only express as a silent fallback to `#0`.
pub(crate) fn sign_with_identity(
    did: &str,
    signing_key_id: &str,
    data: &[u8],
) -> Result<[u8; 64], crate::error::ScpWasmError> {
    use ed25519_dalek::Signer;

    IDENTITY_REGISTRY.with(|reg| {
        let registry = reg.borrow();
        let entry = registry
            .get(did)
            .ok_or_else(|| crate::error::ScpWasmError::Identity {
                message: format!(
                    "identity '{did}' not found in registry — \
                 was it created with identity_create?"
                ),
                // Spec: identity-not-found in the local registry is an
                // identity-domain error, not a DID-document resolution
                // failure (IDENT_1010 is reserved for DID document issues).
                // PyO3 canonical: crates/scp-ffi/src/runtime.rs::with_identity.
                code: codes::IDENT_1001.to_owned(),
            })?;

        // Only `Local` records carry signing keys. A `Resolved` handle
        // was produced from a bare DID string (e.g. a future DHT
        // resolution path) and has no private key material — refuse
        // structurally rather than falling back to `#0` (spec §3.2.1
        // two-key invariant).
        let (signing_key_bytes, active_signing_key_bytes, agent_signing_key_bytes) = match entry {
            IdentityRecord::Local {
                signing_key_bytes,
                active_signing_key_bytes,
                agent_signing_key_bytes,
                ..
            } => (
                signing_key_bytes,
                active_signing_key_bytes,
                agent_signing_key_bytes,
            ),
            IdentityRecord::Resolved { .. } => {
                return Err(crate::error::ScpWasmError::Identity {
                    message: format!(
                        "identity '{did}' was resolved from a DID string without local \
                         signing keys — use a local identity created via identity_create \
                         instead"
                    ),
                    code: codes::IDENT_1028.to_owned(),
                });
            }
        };

        let key_bytes: &[u8; 32] = match signing_key_id {
            // Per spec §3.2.1, `#active` is a distinct signing key from
            // `#0`. The `Local` variant always carries the real active
            // key — no silent fallback to `signing_key_bytes`.
            "#active" => active_signing_key_bytes,
            // Suppress the unused binding for `#agent`-only branches.
            "#agent" => agent_signing_key_bytes.as_deref().ok_or_else(|| {
                crate::error::ScpWasmError::Identity {
                    message: format!(
                        "identity '{did}' has no agent signing key — \
                         add one with identity_add_agent_key first"
                    ),
                    code: codes::IDENT_1034.to_owned(),
                }
            })?,
            _ => {
                return Err(crate::error::ScpWasmError::Validation {
                    message: format!(
                        "invalid signing_key_id '{signing_key_id}': expected '#active' or '#agent'"
                    ),
                    code: codes::IDENT_1034.to_owned(),
                });
            }
        };

        // `signing_key_bytes` is intentionally unused under `#active` /
        // `#agent`; it is kept in the pattern destructuring so that
        // future `#0` signing paths can adopt it without widening the
        // match. Silence the unused warning without suppressing the
        // binding.
        let _ = signing_key_bytes;

        let signing_key = ed25519_dalek::SigningKey::from_bytes(key_bytes);
        let signature = signing_key.sign(data);
        Ok(signature.to_bytes())
    })
}

// ---------------------------------------------------------------------------
// Custody migration — WASM local implementation (#632)
// ---------------------------------------------------------------------------

/// Executes the custody migration protocol for the given DID.
///
/// WASM cannot depend on scp-core (tokio multi-thread), and no real
/// custody migration backend is available at the bridge layer. This
/// function validates the target parameter and returns an error indicating
/// that a real backend must be provided via the SDK layer.
///
/// # Errors
///
/// Returns `SCP-IDENT-1024` if `target` is not a recognized value.
/// Returns `SCP-IDENT-1025` because no custody migration backend is configured.
///
/// See spec §3.2.1.
#[wasm_bindgen]
pub fn identity_execute_custody_migration(
    did: String,
    target: String,
    context_ids: Vec<String>,
) -> Result<String, JsValue> {
    // Suppress unused-variable warnings — parameters are validated but the
    // operation cannot proceed without a real backend.
    let _ = &context_ids;

    // Validate DID before proceeding.
    if let Err(e) = scp_ffi_common::validate::validate_did(&did) {
        return Err(ScpWasmError::from(e).into_js().into());
    }

    // Validate target parameter to give a clear error for invalid inputs.
    match target.as_str() {
        "platform_managed" | "hardware" | "software" | "in_memory" => {}
        other => {
            return Err(ScpWasmError::Identity {
                message: format!(
                    "invalid custody migration target: {other}; expected 'platform_managed', 'hardware', 'software', or 'in_memory'"
                ),
                code: codes::IDENT_1024.to_owned(),
            }
            .into_js()
            .into());
        }
    }

    Err(ScpWasmError::Identity {
        message: "custody migration backend not configured — provide a real backend via SDK layer"
            .to_owned(),
        code: codes::IDENT_1025.to_owned(),
    }
    .into_js()
    .into())
}

// ---------------------------------------------------------------------------
// Identity link attestation bridge (§3.5.1, §3.5.2)
//
// WASM re-implements locally per ADR-034: no scp-core dep.
// Attestations are stored as JSON values in a thread-local registry.
// Signing uses ed25519-dalek from the WASM-local identity registry.
// ---------------------------------------------------------------------------

/// Creates an identity link attestation for an external platform identity.
///
/// Returns a JSON string of the created attestation with a real Ed25519
/// signature.
///
/// See spec §3.5.1, §3.5.2.
#[wasm_bindgen]
#[allow(clippy::too_many_lines, clippy::cast_possible_truncation)]
pub fn identity_create_link_attestation(
    did: String,
    platform: String,
    handle: String,
    proof: String,
    verification_method: String,
    platform_id: Option<String>,
) -> Promise {
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};

    future_to_promise(async move {
        // Validate DID format.
        if let Err(e) = scp_ffi_common::validate::validate_did(&did) {
            return Err(ScpWasmError::Validation {
                message: format!("invalid DID: {e}"),
                code: codes::VALID_7033.to_owned(),
            }
            .into_js()
            .into());
        }

        // Validate attestation input field sizes.
        if let Err(e) =
            scp_ffi_common::validate::validate_attestation_fields(&platform, &handle, &proof)
        {
            return Err(ScpWasmError::Validation {
                message: format!("attestation field validation failed: {e}"),
                code: codes::VALID_7037.to_owned(),
            }
            .into_js()
            .into());
        }

        // Validate verification method.
        let method_str = match verification_method.as_str() {
            "oauth" | "signed_post" | "dns_record" | "challenge_response" => {
                verification_method.as_str().to_owned()
            }
            other => {
                return Err(ScpWasmError::Identity {
                    message: format!(
                        "invalid verification method: {other}; expected 'oauth', \
                         'signed_post', 'dns_record', or 'challenge_response'"
                    ),
                    code: codes::IDENT_1040.to_owned(),
                }
                .into_js()
                .into());
            }
        };

        let now_secs = crate::time::now_secs();

        // Compute deterministic attestation ID.
        let issuer_bytes = did.as_bytes();
        let mut hasher = Sha256::new();
        hasher.update(b"SCP-ATTESTATION-ID-V1:");
        hasher.update((issuer_bytes.len() as u32).to_be_bytes());
        hasher.update(issuer_bytes);
        hasher.update((platform.len() as u32).to_be_bytes());
        hasher.update(platform.as_bytes());
        hasher.update((handle.len() as u32).to_be_bytes());
        hasher.update(handle.as_bytes());
        hasher.update(now_secs.to_be_bytes());
        let id = hex::encode(hasher.finalize());

        // Proof is an opaque string per §3.5.2 — pass through as-is.
        // Do not parse and re-serialize. Verifiers MUST use this string
        // as-is in signature scope.

        // Build the attestation JSON.
        let mut attestation = serde_json::json!({
            "id": id,
            "type": "identity_link",
            "issuer": did,
            "subject": did,
            "issued_at": now_secs,
            "claim": {
                "platform": platform,
                "platform_handle": handle,
                "link_type": "self_attestation",
            },
            "evidence": {
                "method": method_str,
                "proof": proof,
                "verified_at": now_secs,
            },
            "revocation_status": "Active",
            "signature": [],
        });

        if let Some(pid) = &platform_id {
            attestation["claim"]["platform_id"] = serde_json::json!(pid);
        }

        // Structural validation before signing (mirrors scp-core's
        // validate_structure). WASM cannot call scp-core directly per ADR-034,
        // so we implement equivalent checks locally.
        {
            let mut errors: Vec<String> = Vec::new();
            if attestation["type"].as_str() != Some("identity_link") {
                errors.push("type must be \"identity_link\"".to_owned());
            }
            if attestation["issuer"].as_str() != attestation["subject"].as_str() {
                errors.push("issuer must equal subject for self-attestations".to_owned());
            }
            if attestation["claim"]["link_type"].as_str() != Some("self_attestation") {
                errors.push("claim.link_type must be \"self_attestation\"".to_owned());
            }
            // ID recomputation check (SHA-256 of issuer+platform+handle+issued_at).
            if attestation["id"].as_str() != Some(id.as_str()) {
                errors.push(format!(
                    "id mismatch: expected {id}, got {:?}",
                    attestation["id"].as_str().unwrap_or("<missing>"),
                ));
            }
            // revoked_by == issuer check (when Revoked).
            if let Some(revoked_obj) = attestation
                .get("revocation_status")
                .and_then(|s| s.as_object())
                .and_then(|obj| obj.get("Revoked"))
            {
                let revoked_by = revoked_obj
                    .get("revoked_by")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let issuer_str = attestation["issuer"].as_str().unwrap_or("");
                if !revoked_by.is_empty() && revoked_by != issuer_str {
                    errors.push(format!(
                        "revoked_by {revoked_by} does not match issuer {issuer_str}",
                    ));
                }
            }
            // Note: proof is an opaque string per §3.5.2 — no structural
            // validation of proof contents at the wire-format level.
            if !errors.is_empty() {
                return Err(ScpWasmError::Validation {
                    message: format!(
                        "attestation structure validation failed: {}",
                        errors.join("; ")
                    ),
                    code: codes::VALID_7034.to_owned(),
                }
                .into_js()
                .into());
            }
        }

        // Compute canonical signing bytes via the shared function (§9.5.1).
        let canonical = compute_attestation_canonical_bytes(&attestation)?;

        // Sign with the issuer's #active key per spec §3.5 ("signed by
        // the issuer's #active or #agent key") and §3.5.2 wire format
        // ("using issuer's #active or #agent key"). Only `Local` records
        // carry it; `Resolved` handles refuse structurally.
        let signature_bytes = IDENTITY_REGISTRY.with(|reg| {
            let map = reg.borrow();
            let entry = map.get(&did).ok_or_else(|| -> JsValue {
                ScpWasmError::Identity {
                    message: format!("identity {did:?} not found in registry"),
                    code: codes::IDENT_1000.to_owned(),
                }
                .into_js()
                .into()
            })?;

            let active_signing_key_bytes = match entry {
                IdentityRecord::Local {
                    active_signing_key_bytes,
                    ..
                } => active_signing_key_bytes,
                IdentityRecord::Resolved { .. } => {
                    return Err::<[u8; 64], JsValue>(
                        ScpWasmError::Identity {
                            message: format!(
                                "identity '{did}' was resolved from a DID string \
                                 without local key material — cannot sign a link \
                                 attestation"
                            ),
                            code: codes::IDENT_1028.to_owned(),
                        }
                        .into_js()
                        .into(),
                    );
                }
            };
            let signing_key = ed25519_dalek::SigningKey::from_bytes(active_signing_key_bytes);
            let signature = signing_key.sign(&canonical);
            Ok::<[u8; 64], JsValue>(signature.to_bytes())
        })?;

        attestation["signature"] = serde_json::json!(
            signature_bytes
                .iter()
                .map(|b| serde_json::Value::Number(serde_json::Number::from(*b)))
                .collect::<Vec<_>>()
        );

        // Store the attestation (with capacity checks).
        LINK_ATTESTATIONS.with(|reg| {
            let mut map = reg.borrow_mut();
            check_registry_capacity(
                &*map,
                &did,
                WASM_LINK_ATTESTATIONS_CAP,
                "link attestation registry",
                codes::VALID_7402,
            )?;
            let entry = map.entry(did).or_default();
            if entry.len() >= MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID {
                return Err(JsValue::from(
                    ScpWasmError::Validation {
                        message: format!(
                            "DID has reached the per-identity attestation limit \
                             ({MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID}) — cannot store additional attestations"
                        ),
                        code: codes::VALID_7403.to_owned(),
                    }
                    .into_js(),
                ));
            }
            entry.push(attestation.clone());
            Ok(())
        })?;

        let json = serde_json::to_string(&attestation).map_err(|e| -> JsValue {
            ScpWasmError::Identity {
                message: format!("failed to serialize attestation: {e}"),
                code: codes::IDENT_1042.to_owned(),
            }
            .into_js()
            .into()
        })?;
        Ok(JsValue::from_str(&json))
    })
}

/// Lists all identity link attestations for an identity.
///
/// Returns a JSON array string.
///
/// # Errors
///
/// Returns `JsError` if serialization fails.
///
/// See spec §3.5.1.
#[wasm_bindgen]
pub fn identity_link_attestations(did: String) -> Result<String, JsError> {
    let attestations = LINK_ATTESTATIONS.with(|reg| {
        let map = reg.borrow();
        map.get(&did).cloned().unwrap_or_default()
    });
    serde_json::to_string(&attestations)
        .map_err(|e| JsError::new(&format!("failed to serialize attestations: {e}")))
}

/// Removes an identity link attestation by its ID.
///
/// Returns `true` if found and removed, `false` if the DID is not in the
/// identity registry or the attestation was not found.
///
/// See spec §3.5.1.
#[must_use]
#[wasm_bindgen]
pub fn identity_remove_link_attestation(did: String, attestation_id: String) -> bool {
    // Verify the caller owns the DID by checking the identity registry.
    let owns_did = IDENTITY_REGISTRY.with(|reg| reg.borrow().contains_key(&did));
    if !owns_did {
        return false;
    }

    LINK_ATTESTATIONS.with(|reg| {
        let mut map = reg.borrow_mut();
        map.get_mut(&did).is_some_and(|list| {
            let before = list.len();
            list.retain(|a| a.get("id").and_then(|v| v.as_str()) != Some(&attestation_id));
            list.len() < before
        })
    })
}

/// Extracts a required string field from an attestation JSON value, returning
/// an identity error if the field is missing or not a string.
fn attestation_required_str<'a>(
    attestation: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, JsValue> {
    attestation[field]
        .as_str()
        .ok_or_else(|| attestation_err(format!("attestation missing required field '{field}'")))
}

/// Shorthand for `SCP-IDENT-1044` attestation errors used across
/// `compute_attestation_canonical_bytes` and its helpers.
fn attestation_err(message: String) -> JsValue {
    ScpWasmError::Identity {
        message,
        code: codes::IDENT_1044.to_owned(),
    }
    .into_js()
    .into()
}

/// Computes the canonical signing bytes for an attestation JSON value.
///
/// Replicates scp-core's `canonical_hash` construction (§9.5.1): domain
/// separator, length-prefixed `VarBytes`, `U64` timestamps, `Absent` sentinel
/// for missing `expires_at`, and `rmp_serde` for sub-struct serialization
/// using typed structs that match scp-core field declaration order.
#[allow(clippy::cast_possible_truncation)]
fn compute_attestation_canonical_bytes(
    attestation: &serde_json::Value,
) -> Result<Vec<u8>, JsValue> {
    use sha2::{Digest, Sha256};

    let id = attestation_required_str(attestation, "id")?;
    let atype = attestation_required_str(attestation, "type")?;
    let issuer = attestation_required_str(attestation, "issuer")?;
    let subject = attestation_required_str(attestation, "subject")?;
    let issued_at = attestation["issued_at"]
        .as_u64()
        .ok_or_else(|| attestation_err("attestation missing required field 'issued_at'".into()))?;

    // Deserialize sub-structs into local types that mirror scp-core's
    // field declaration order, ensuring byte-identical msgpack output.
    let claim: canonical_attestation::Claim = serde_json::from_value(attestation["claim"].clone())
        .map_err(|e| attestation_err(format!("claim deserialization failed: {e}")))?;
    let evidence: canonical_attestation::Evidence =
        serde_json::from_value(attestation["evidence"].clone())
            .map_err(|e| attestation_err(format!("evidence deserialization failed: {e}")))?;

    let claim_msgpack = rmp_serde::to_vec_named(&claim)
        .map_err(|e| attestation_err(format!("claim serialization failed: {e}")))?;
    let evidence_msgpack = rmp_serde::to_vec_named(&evidence)
        .map_err(|e| attestation_err(format!("evidence serialization failed: {e}")))?;
    // Deserialize revocation_status into the typed mirror enum to produce
    // byte-identical msgpack matching scp-core's RevocationStatus.
    let revocation_status_value =
        attestation
            .get("revocation_status")
            .cloned()
            .ok_or_else(|| {
                attestation_err("attestation missing required field 'revocation_status'".into())
            })?;
    let revocation_status: scp_protocol::trust::attestation::RevocationStatus =
        serde_json::from_value(revocation_status_value).map_err(|e| {
            attestation_err(format!("revocation_status deserialization failed: {e}"))
        })?;
    let revocation_status_msgpack = rmp_serde::to_vec_named(&revocation_status)
        .map_err(|e| attestation_err(format!("revocation_status serialization failed: {e}")))?;

    let mut h = Sha256::new();
    h.update(b"SCP-IDENTITY-LINK-ATTESTATION-V1:");
    for field in &[
        id.as_bytes().to_vec(),
        atype.as_bytes().to_vec(),
        issuer.as_bytes().to_vec(),
        subject.as_bytes().to_vec(),
    ] {
        h.update((field.len() as u32).to_be_bytes());
        h.update(field);
    }
    h.update(issued_at.to_be_bytes());
    // expires_at handling: Absent sentinel = SHA-256(0x00), matching scp-core.
    match attestation
        .get("expires_at")
        .and_then(serde_json::Value::as_u64)
    {
        Some(exp) => h.update(exp.to_be_bytes()),
        None => h.update(ABSENT_SENTINEL),
    }
    for field in &[claim_msgpack, evidence_msgpack, revocation_status_msgpack] {
        h.update((field.len() as u32).to_be_bytes());
        h.update(field);
    }
    Ok(h.finalize().to_vec())
}

/// Decodes a hex-encoded Ed25519 public key for attestation verification.
///
/// The issuer's public key cannot be reliably extracted from the DID string
/// because attestations are signed with `#active` or `#agent` keys
/// (spec §3.5.2), not the `#0` identity key embedded in the DID.
fn decode_attestation_public_key(issuer_public_key_hex: &str) -> Result<Option<[u8; 32]>, JsValue> {
    let decoded = hex::decode(issuer_public_key_hex).map_err(|e| -> JsValue {
        ScpWasmError::Validation {
            message: format!("invalid issuer_public_key_hex: {e}"),
            code: codes::VALID_7032.to_owned(),
        }
        .into_js()
        .into()
    })?;
    if decoded.len() != 32 {
        return Ok(None);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&decoded);
    Ok(Some(arr))
}

/// Verifies the Ed25519 signature on an identity link attestation JSON.
///
/// Re-implements signature verification locally per ADR-034.
///
/// # Arguments
///
/// * `attestation_json` — JSON string of the attestation.
/// * `issuer_public_key_hex` — Hex-encoded Ed25519 public key of the issuer.
///   The issuer's public key cannot be reliably extracted from the DID string
///   because attestations are signed with `#active` or `#agent` keys
///   (spec §3.5.2), not the `#0` identity key embedded in the DID.
///
/// See spec §3.5.1.
#[wasm_bindgen]
pub fn identity_verify_link_attestation_signature(
    attestation_json: String,
    issuer_public_key_hex: String,
) -> Promise {
    future_to_promise(async move {
        let attestation: serde_json::Value =
            serde_json::from_str(&attestation_json).map_err(|e| -> JsValue {
                ScpWasmError::Identity {
                    message: format!("failed to parse attestation JSON: {e}"),
                    code: codes::IDENT_1044.to_owned(),
                }
                .into_js()
                .into()
            })?;

        let issuer = attestation["issuer"]
            .as_str()
            .ok_or_else(|| -> JsValue {
                ScpWasmError::Validation {
                    message: "attestation missing 'issuer' field".to_owned(),
                    code: codes::VALID_7030.to_owned(),
                }
                .into_js()
                .into()
            })?
            .to_owned();

        // Validate DID format: must be did:{method}:{id}.
        if let Err(e) = scp_ffi_common::validate::validate_did(&issuer) {
            return Err(ScpWasmError::Validation {
                message: format!("invalid issuer DID: {e}"),
                code: codes::VALID_7033.to_owned(),
            }
            .into_js()
            .into());
        }

        let sig_array: Vec<u8> = attestation["signature"]
            .as_array()
            .ok_or_else(|| -> JsValue {
                ScpWasmError::Validation {
                    message: "attestation missing 'signature' field".to_owned(),
                    code: codes::VALID_7031.to_owned(),
                }
                .into_js()
                .into()
            })?
            .iter()
            .map(|v| {
                v.as_u64()
                    .and_then(|n| u8::try_from(n).ok())
                    .ok_or("invalid signature byte")
            })
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|e| -> JsValue {
                ScpWasmError::Identity {
                    message: format!("signature contains invalid bytes: {e}"),
                    code: codes::IDENT_1045.to_owned(),
                }
                .into_js()
                .into()
            })?;

        if sig_array.len() != 64 {
            return Ok(JsValue::from_bool(false));
        }
        let sig_bytes: [u8; 64] = sig_array.try_into().map_err(|_| -> JsValue {
            ScpWasmError::Identity {
                message: "signature must be exactly 64 bytes".to_owned(),
                code: codes::IDENT_1045.to_owned(),
            }
            .into_js()
            .into()
        })?;

        let canonical = compute_attestation_canonical_bytes(&attestation)?;

        let Some(pub_bytes) = decode_attestation_public_key(&issuer_public_key_hex)? else {
            return Ok(JsValue::from_bool(false));
        };

        let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&pub_bytes) else {
            return Ok(JsValue::from_bool(false));
        };
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let verified = verifying_key.verify_strict(&canonical, &signature).is_ok();
        Ok(JsValue::from_bool(verified))
    })
}

// ---------------------------------------------------------------------------
// Test helpers (pub(crate) for cross-module integration tests)
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;

    /// Register an Ed25519 identity with a separate agent key in
    /// `IDENTITY_REGISTRY`. Returns `(did, identity_signing_key, agent_signing_key)`
    /// so callers can produce real Ed25519 signatures under the identity VM
    /// (`kid: "#0"`) or agent VM (`kid: "#agent"`).
    ///
    /// Used by `ucan::tests` for E2E integration tests that exercise the full
    /// `validate_ucan_full` pipeline with real cryptography (issue #1012).
    ///
    /// The spec §3.2.1 two-key invariant is now type-enforced via
    /// [`IdentityRecord::Local`], so this helper generates a distinct
    /// `#active` key alongside `#0` and `#agent`. Returns the four-tuple
    /// `(did, identity_key, active_key, agent_key)` — tests that need
    /// to sign as `#active` must use `active_key`, not `identity_key`,
    /// because the registered record carries a distinct active key that
    /// `sign_with_identity("#active", …)` and `verify_token_signature`
    /// both resolve through.
    pub fn register_identity_with_agent_key() -> (
        String,
        ed25519_dalek::SigningKey,
        ed25519_dalek::SigningKey,
        ed25519_dalek::SigningKey,
    ) {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let did = format!("did:dht:z{}", zbase32_encode(&pub_bytes));

        let active_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let pre_rotation_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let agent_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

        IDENTITY_REGISTRY.with(|reg| {
            reg.borrow_mut().insert(
                did.clone(),
                IdentityRecord::Local {
                    signing_key_bytes: zeroize::Zeroizing::new(signing_key.to_bytes()),
                    active_signing_key_bytes: zeroize::Zeroizing::new(active_key.to_bytes()),
                    pre_rotation_signing_key_bytes: zeroize::Zeroizing::new(
                        pre_rotation_key.to_bytes(),
                    ),
                    public_key_bytes: pub_bytes,
                    custody_type: "in_memory".to_owned(),
                    agent_signing_key_bytes: Some(zeroize::Zeroizing::new(agent_key.to_bytes())),
                },
            );
        });
        (did, signing_key, active_key, agent_key)
    }

    /// Clean up the identity registry (prevents cross-test pollution from
    /// thread-local state persisting across tests in the same thread).
    pub fn cleanup_identity_registry() {
        IDENTITY_REGISTRY.with(|reg| reg.borrow_mut().clear());
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Helper: generate an Ed25519 identity key plus a distinct `#active`
    /// signing key (spec §3.2.1) and a pre-rotation key (spec §3.7), and
    /// register them in `IDENTITY_REGISTRY`. Returns
    /// `(did, identity_pub_bytes, active_pub_bytes)`.
    fn register_identity() -> (String, [u8; 32], [u8; 32]) {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let did = format!("did:dht:z{}", zbase32_encode(&pub_bytes));

        let active_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let active_pub_bytes = active_key.verifying_key().to_bytes();
        let pre_rotation_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

        IDENTITY_REGISTRY.with(|reg| {
            reg.borrow_mut().insert(
                did.clone(),
                IdentityRecord::Local {
                    signing_key_bytes: zeroize::Zeroizing::new(signing_key.to_bytes()),
                    active_signing_key_bytes: zeroize::Zeroizing::new(active_key.to_bytes()),
                    pre_rotation_signing_key_bytes: zeroize::Zeroizing::new(
                        pre_rotation_key.to_bytes(),
                    ),
                    public_key_bytes: pub_bytes,
                    custody_type: "in_memory".to_owned(),
                    agent_signing_key_bytes: None,
                },
            );
        });
        (did, pub_bytes, active_pub_bytes)
    }

    /// Helper: generate an Ed25519 identity key plus a distinct `#active`
    /// signing key, a pre-rotation key, and an agent key, and register
    /// them in `IDENTITY_REGISTRY`. Returns
    /// `(did, identity_pub_bytes, active_pub_bytes, agent_pub_bytes)`.
    fn register_identity_with_agent() -> (String, [u8; 32], [u8; 32], [u8; 32]) {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let did = format!("did:dht:z{}", zbase32_encode(&pub_bytes));

        let active_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let active_pub_bytes = active_key.verifying_key().to_bytes();
        let pre_rotation_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let agent_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let agent_pub_bytes = agent_key.verifying_key().to_bytes();

        IDENTITY_REGISTRY.with(|reg| {
            reg.borrow_mut().insert(
                did.clone(),
                IdentityRecord::Local {
                    signing_key_bytes: zeroize::Zeroizing::new(signing_key.to_bytes()),
                    active_signing_key_bytes: zeroize::Zeroizing::new(active_key.to_bytes()),
                    pre_rotation_signing_key_bytes: zeroize::Zeroizing::new(
                        pre_rotation_key.to_bytes(),
                    ),
                    public_key_bytes: pub_bytes,
                    custody_type: "in_memory".to_owned(),
                    agent_signing_key_bytes: Some(zeroize::Zeroizing::new(agent_key.to_bytes())),
                },
            );
        });
        (did, pub_bytes, active_pub_bytes, agent_pub_bytes)
    }

    /// Helper: clean up thread-local state after each test to avoid cross-test
    /// pollution (thread-local state persists across tests in the same thread).
    fn cleanup_registries() {
        IDENTITY_REGISTRY.with(|reg| reg.borrow_mut().clear());
        MIGRATION_LINKS.with(|links| links.borrow_mut().clear());
        LINK_ATTESTATIONS.with(|reg| reg.borrow_mut().clear());
    }

    #[test]
    fn test_resolve_unknown_did() {
        cleanup_registries();

        let fields = resolve_did_document_fields("did:dht:zunknown");

        // Unknown DID: no keys in registry, so all arrays should be empty.
        let vms: Vec<serde_json::Value> =
            serde_json::from_str(&fields.verification_methods_json).unwrap();
        let auth: Vec<serde_json::Value> =
            serde_json::from_str(&fields.authentication_json).unwrap();
        let assertion: Vec<serde_json::Value> =
            serde_json::from_str(&fields.assertion_methods_json).unwrap();
        let aka: Vec<serde_json::Value> = serde_json::from_str(&fields.also_known_as_json).unwrap();

        assert!(vms.is_empty(), "unknown DID should have no VMs");
        assert!(auth.is_empty(), "unknown DID should have no authentication");
        assert!(
            assertion.is_empty(),
            "unknown DID should have no assertionMethod"
        );
        assert!(
            aka.is_empty(),
            "unknown DID should have no alsoKnownAs entries"
        );
        assert_eq!(fields.services_json, "[]");

        cleanup_registries();
    }

    #[test]
    fn test_resolve_known_did_basic() {
        cleanup_registries();

        let (did, pub_bytes, active_pub_bytes) = register_identity();
        let identity_multibase = format!("z{}", zbase32_encode(&pub_bytes));
        let active_multibase = format!("z{}", zbase32_encode(&active_pub_bytes));

        let fields = resolve_did_document_fields(&did);

        // Verification methods: #0 (identity) and #active (signing).
        let vms: Vec<serde_json::Value> =
            serde_json::from_str(&fields.verification_methods_json).unwrap();
        assert_eq!(vms.len(), 2, "should have #0 and #active VMs");

        // #0 — Identity Key
        assert_eq!(vms[0]["id"], format!("{did}#0"));
        assert_eq!(vms[0]["type"], "Ed25519VerificationKey2020");
        assert_eq!(vms[0]["controller"], did);
        assert_eq!(vms[0]["publicKeyMultibase"], identity_multibase);

        // #active — Active Signing Key. Per spec §3.2.1 the two keys
        // must differ, so the `IdentityRecord::Local` variant always
        // emits a distinct `#active` multibase.
        assert_eq!(vms[1]["id"], format!("{did}#active"));
        assert_eq!(vms[1]["type"], "Ed25519VerificationKey2020");
        assert_eq!(vms[1]["controller"], did);
        assert_eq!(vms[1]["publicKeyMultibase"], active_multibase);
        assert_ne!(
            identity_multibase, active_multibase,
            "spec §3.2.1 requires #0 and #active to be distinct keys"
        );

        // Authentication and assertionMethod reference #active.
        let auth: Vec<serde_json::Value> =
            serde_json::from_str(&fields.authentication_json).unwrap();
        assert_eq!(auth.len(), 1);
        assert_eq!(auth[0], format!("{did}#active"));

        let assertion: Vec<serde_json::Value> =
            serde_json::from_str(&fields.assertion_methods_json).unwrap();
        assert_eq!(assertion.len(), 1);
        assert_eq!(assertion[0], format!("{did}#active"));

        // No migration link → empty alsoKnownAs.
        let aka: Vec<serde_json::Value> = serde_json::from_str(&fields.also_known_as_json).unwrap();
        assert!(aka.is_empty());

        // The pre-rotation commitment is always published for `Local`
        // identities (spec §3.7) — verify the service endpoint shape.
        let services: Vec<serde_json::Value> = serde_json::from_str(&fields.services_json).unwrap();
        assert_eq!(
            services.len(),
            1,
            "Local identities expose one #pre-rotation service"
        );
        assert_eq!(services[0]["id"], format!("{did}#pre-rotation"));
        assert_eq!(services[0]["type"], "PreRotationCommitment");
        let endpoint = services[0]["serviceEndpoint"]
            .as_str()
            .expect("serviceEndpoint must be a string");
        let hex_part = endpoint
            .strip_prefix("sha256:")
            .expect("endpoint MUST be `sha256:<hex>`");
        assert_eq!(hex_part.len(), 64, "32-byte SHA-256 = 64 hex chars");

        cleanup_registries();
    }

    #[test]
    fn test_resolve_with_agent_key() {
        cleanup_registries();

        let (did, pub_bytes, active_pub_bytes, agent_pub_bytes) = register_identity_with_agent();
        let identity_multibase = format!("z{}", zbase32_encode(&pub_bytes));
        let active_multibase = format!("z{}", zbase32_encode(&active_pub_bytes));
        let agent_multibase = format!("z{}", zbase32_encode(&agent_pub_bytes));

        let fields = resolve_did_document_fields(&did);

        // Verification methods: #0, #active, and #agent.
        let vms: Vec<serde_json::Value> =
            serde_json::from_str(&fields.verification_methods_json).unwrap();
        assert_eq!(vms.len(), 3, "should have #0, #active, and #agent VMs");

        // #0 — Identity Key
        assert_eq!(vms[0]["id"], format!("{did}#0"));
        assert_eq!(vms[0]["publicKeyMultibase"], identity_multibase);

        // #active — Active Signing Key (distinct from #0 per spec §3.2.1).
        assert_eq!(vms[1]["id"], format!("{did}#active"));
        assert_eq!(vms[1]["publicKeyMultibase"], active_multibase);
        assert_ne!(
            identity_multibase, active_multibase,
            "spec §3.2.1 requires #0 and #active to be distinct keys"
        );

        // #agent — Agent Signing Key (ADR-039)
        assert_eq!(vms[2]["id"], format!("{did}#agent"));
        assert_eq!(vms[2]["type"], "Ed25519VerificationKey2020");
        assert_eq!(vms[2]["controller"], did);
        assert_eq!(vms[2]["publicKeyMultibase"], agent_multibase);

        // Authentication references both #active and #agent.
        let auth: Vec<serde_json::Value> =
            serde_json::from_str(&fields.authentication_json).unwrap();
        assert_eq!(auth.len(), 2);
        assert_eq!(auth[0], format!("{did}#active"));
        assert_eq!(auth[1], format!("{did}#agent"));

        // assertionMethod references both #active and #agent.
        let assertion: Vec<serde_json::Value> =
            serde_json::from_str(&fields.assertion_methods_json).unwrap();
        assert_eq!(assertion.len(), 2);
        assert_eq!(assertion[0], format!("{did}#active"));
        assert_eq!(assertion[1], format!("{did}#agent"));

        cleanup_registries();
    }

    #[test]
    fn test_resolve_with_migration_link() {
        cleanup_registries();

        let (did, _pub_bytes, _active_pub_bytes) = register_identity();
        let old_did = "did:dht:zOldDid12345";

        // Simulate a migration: new DID maps to old DID.
        MIGRATION_LINKS.with(|links| {
            links.borrow_mut().insert(did.clone(), old_did.to_owned());
        });

        let fields = resolve_did_document_fields(&did);

        // alsoKnownAs should contain the old DID.
        let aka: Vec<serde_json::Value> = serde_json::from_str(&fields.also_known_as_json).unwrap();
        assert_eq!(aka.len(), 1, "should have exactly one alsoKnownAs entry");
        assert_eq!(aka[0], old_did);

        // VMs should still be populated (identity exists in registry).
        let vms: Vec<serde_json::Value> =
            serde_json::from_str(&fields.verification_methods_json).unwrap();
        assert_eq!(vms.len(), 2, "should have #0 and #active VMs");

        cleanup_registries();
    }

    // -----------------------------------------------------------------------
    // Attestation token parsing tests (#511)
    // -----------------------------------------------------------------------

    /// Helper: base64-encode a JSON value for use as an attestation token.
    fn encode_token(value: &serde_json::Value) -> String {
        use base64::Engine;
        let json = serde_json::to_string(value).unwrap();
        base64::engine::general_purpose::STANDARD.encode(json.as_bytes())
    }

    #[test]
    fn test_parse_attestation_token_valid() {
        let token = serde_json::json!({
            "did": "did:dht:zTest123",
            "timestamp": 1_700_000_000_u64,
            "signature": "abcdef0123456789",
        });
        let encoded = encode_token(&token);
        let result = parse_attestation_token(&encoded).unwrap();
        assert_eq!(result.did, "did:dht:zTest123");
        assert_eq!(result.timestamp, 1_700_000_000);
        assert_eq!(result.signature_hex, "abcdef0123456789");
    }

    #[test]
    fn test_parse_attestation_token_missing_did() {
        let token = serde_json::json!({
            "timestamp": 1_700_000_000_u64,
            "signature": "abcdef",
        });
        let encoded = encode_token(&token);
        let err = parse_attestation_token(&encoded).unwrap_err();
        match err {
            ScpWasmError::Validation {
                ref code,
                ref message,
            } => {
                assert_eq!(code, codes::VALID_7020);
                assert!(
                    message.contains("did"),
                    "message should mention 'did': {message}"
                );
            }
            other => panic!("expected Validation error, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_attestation_token_did_wrong_type() {
        // did is a number, not a string
        let token = serde_json::json!({
            "did": 42,
            "timestamp": 1_700_000_000_u64,
            "signature": "abcdef",
        });
        let encoded = encode_token(&token);
        let err = parse_attestation_token(&encoded).unwrap_err();
        match err {
            ScpWasmError::Validation { ref code, .. } => {
                assert_eq!(code, codes::VALID_7020);
            }
            other => panic!("expected Validation error, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_attestation_token_missing_timestamp() {
        let token = serde_json::json!({
            "did": "did:dht:zTest123",
            "signature": "abcdef",
        });
        let encoded = encode_token(&token);
        let err = parse_attestation_token(&encoded).unwrap_err();
        match err {
            ScpWasmError::Validation {
                ref code,
                ref message,
            } => {
                assert_eq!(code, codes::VALID_7021);
                assert!(
                    message.contains("timestamp"),
                    "message should mention 'timestamp': {message}"
                );
            }
            other => panic!("expected Validation error, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_attestation_token_timestamp_wrong_type() {
        // timestamp is a string, not a u64
        let token = serde_json::json!({
            "did": "did:dht:zTest123",
            "timestamp": "not-a-number",
            "signature": "abcdef",
        });
        let encoded = encode_token(&token);
        let err = parse_attestation_token(&encoded).unwrap_err();
        match err {
            ScpWasmError::Validation { ref code, .. } => {
                assert_eq!(code, codes::VALID_7021);
            }
            other => panic!("expected Validation error, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_attestation_token_missing_signature() {
        let token = serde_json::json!({
            "did": "did:dht:zTest123",
            "timestamp": 1_700_000_000_u64,
        });
        let encoded = encode_token(&token);
        let err = parse_attestation_token(&encoded).unwrap_err();
        match err {
            ScpWasmError::Validation {
                ref code,
                ref message,
            } => {
                assert_eq!(code, codes::VALID_7022);
                assert!(
                    message.contains("signature"),
                    "message should mention 'signature': {message}"
                );
            }
            other => panic!("expected Validation error, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_attestation_token_empty_object() {
        // All three fields missing — should fail on the first one (did).
        let token = serde_json::json!({});
        let encoded = encode_token(&token);
        let err = parse_attestation_token(&encoded).unwrap_err();
        match err {
            ScpWasmError::Validation { ref code, .. } => {
                assert_eq!(
                    code,
                    codes::VALID_7020,
                    "first missing field should be 'did'"
                );
            }
            other => panic!("expected Validation error, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_attestation_token_invalid_base64() {
        let err = parse_attestation_token("not-valid-base64!!!").unwrap_err();
        match err {
            ScpWasmError::Identity { ref code, .. } => {
                assert_eq!(code, codes::IDENT_1013);
            }
            other => panic!("expected Identity error, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_attestation_token_invalid_json() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"this is not json");
        let err = parse_attestation_token(&encoded).unwrap_err();
        match err {
            ScpWasmError::Identity { ref code, .. } => {
                assert_eq!(code, codes::IDENT_1013);
            }
            other => panic!("expected Identity error, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_attestation_token_null_fields() {
        // Fields present but null — should fail validation.
        let token = serde_json::json!({
            "did": null,
            "timestamp": null,
            "signature": null,
        });
        let encoded = encode_token(&token);
        let err = parse_attestation_token(&encoded).unwrap_err();
        match err {
            ScpWasmError::Validation { ref code, .. } => {
                assert_eq!(code, codes::VALID_7020, "null 'did' should fail validation");
            }
            other => panic!("expected Validation error, got: {other:?}"),
        }
    }

    /// Regression test: per spec §3.2.1, a seeded identity has a
    /// distinct `#active` signing key (seed[32..64]) that is NOT the
    /// identity key. `resolve_verification_method_key("#active")` must
    /// return the verifying key derived from the active signing key so
    /// that `sign_with_identity("#active", ...)` signatures verify.
    ///
    /// Prior bug: `resolve_verification_method_key` returned
    /// `entry.public_key_bytes` unconditionally, causing signatures
    /// produced with the active signing key to fail verification under
    /// the parity-harness seed path (ADR-046).
    ///
    /// Gated on `testing` because the seeded `StdRng` construction
    /// depends on the `rand` crate, which is `optional = true` and only
    /// pulled in under the `testing` feature.
    #[cfg(feature = "testing")]
    #[test]
    fn test_sign_verify_active_roundtrip_seeded() {
        use ed25519_dalek::{Signature, Verifier};
        use rand::{RngCore, SeedableRng};

        cleanup_registries();

        // Register a seeded identity mirroring the seed path in
        // `identity_create`: identity_key from seed[0..32], active from
        // seed[32..64], pre-rotation from seed[64..96], via
        // `StdRng::from_seed`.
        let seed = [0x42u8; 32];
        let mut rng = rand::rngs::StdRng::from_seed(seed);
        let mut identity_key_bytes = [0u8; 32];
        rng.fill_bytes(&mut identity_key_bytes);
        let identity_key = ed25519_dalek::SigningKey::from_bytes(&identity_key_bytes);
        let identity_pub_bytes = identity_key.verifying_key().to_bytes();
        let mut active_bytes = [0u8; 32];
        rng.fill_bytes(&mut active_bytes);
        let mut pre_rotation_bytes = [0u8; 32];
        rng.fill_bytes(&mut pre_rotation_bytes);

        let did = format!("did:dht:z{}", zbase32_encode(&identity_pub_bytes));
        IDENTITY_REGISTRY.with(|reg| {
            reg.borrow_mut().insert(
                did.clone(),
                IdentityRecord::Local {
                    signing_key_bytes: zeroize::Zeroizing::new(identity_key.to_bytes()),
                    active_signing_key_bytes: zeroize::Zeroizing::new(active_bytes),
                    pre_rotation_signing_key_bytes: zeroize::Zeroizing::new(pre_rotation_bytes),
                    public_key_bytes: identity_pub_bytes,
                    custody_type: "in_memory".to_owned(),
                    agent_signing_key_bytes: None,
                },
            );
        });

        // Sanity: the active signing key is distinct from the identity
        // key (otherwise the bug this test guards against could not
        // manifest).
        let active_key = ed25519_dalek::SigningKey::from_bytes(&active_bytes);
        let active_pub_bytes = active_key.verifying_key().to_bytes();
        assert_ne!(
            active_pub_bytes, identity_pub_bytes,
            "seeded testing path must produce a distinct #active key"
        );

        // Sign with #active.
        let message = b"scp-parity-harness-roundtrip";
        let sig_bytes = sign_with_identity(&did, "#active", message)
            .expect("sign_with_identity(#active) should succeed");
        let signature = Signature::from_bytes(&sig_bytes);

        // Resolve the verifying key via the sibling path.
        let resolved_pub_bytes = resolve_verification_method_key(&did, "#active")
            .expect("resolve_verification_method_key(#active) should succeed");

        // The resolver must return the ACTIVE signing key's verifying
        // key, not the identity key's. Without the fix, this assertion
        // fails.
        assert_eq!(
            resolved_pub_bytes, active_pub_bytes,
            "resolver must return the active signing key's verifying key under testing seed"
        );
        assert_ne!(
            resolved_pub_bytes, identity_pub_bytes,
            "resolver must NOT return the identity key's verifying key for #active"
        );

        // Round-trip: signature produced by sign_with_identity(#active)
        // MUST verify under resolve_verification_method_key(#active).
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&resolved_pub_bytes)
            .expect("resolved public key bytes should decode to a valid Ed25519 verifying key");
        verifying_key
            .verify(message, &signature)
            .expect("sign/verify round-trip must succeed under testing seed");

        cleanup_registries();
    }

    /// Sign/verify round-trip exercising the production (non-seeded)
    /// path on an `IdentityRecord::Local` record. With the two-key
    /// invariant now type-enforced, every `Local` record carries a
    /// distinct `#active` key — there is no legacy fallback to
    /// regress. This test proves that `sign_with_identity(#active)`
    /// and `resolve_verification_method_key(#active)` stay paired on
    /// the no-seed code path.
    #[test]
    fn test_sign_verify_active_roundtrip_production() {
        use ed25519_dalek::{Signature, Verifier};

        cleanup_registries();

        let (did, identity_pub_bytes, active_pub_bytes) = register_identity();

        let message = b"scp-production-roundtrip";
        let sig_bytes = sign_with_identity(&did, "#active", message)
            .expect("sign_with_identity(#active) should succeed");
        let signature = Signature::from_bytes(&sig_bytes);

        let resolved_pub_bytes = resolve_verification_method_key(&did, "#active")
            .expect("resolve_verification_method_key(#active) should succeed");

        // The resolver must return the active signing key's verifying
        // key, NOT the identity key's — the two are distinct by spec
        // §3.2.1 and the type system forbids the former fallback.
        assert_eq!(
            resolved_pub_bytes, active_pub_bytes,
            "resolver must return the active signing key's verifying key"
        );
        assert_ne!(
            resolved_pub_bytes, identity_pub_bytes,
            "resolver must NOT return the identity key's verifying key for #active"
        );

        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&resolved_pub_bytes)
            .expect("resolved public key bytes should decode to a valid Ed25519 verifying key");
        verifying_key
            .verify(message, &signature)
            .expect("sign/verify round-trip must succeed");

        cleanup_registries();
    }

    /// Adversarial-review round 12 MINOR-4 regression test: a
    /// [`IdentityRecord::Resolved`] handle has no retained key
    /// material and MUST NOT sign. The old `Option`-based model
    /// silently fell back to `signing_key_bytes` (the `#0` identity
    /// key) when `active_signing_key_bytes` was `None`, violating the
    /// spec §3.2.1 two-key invariant whenever a future call site
    /// constructed such a handle. The enum split makes that impossible
    /// at the type level: this test exercises the explicit refusal
    /// path on both `#active` and `#agent` to prove the structural
    /// guarantee and pins the error code.
    #[test]
    fn resolved_handle_cannot_sign_active() {
        cleanup_registries();

        // Fabricate a `Resolved` record directly in the registry —
        // there is no public bridge function that constructs one
        // today, but the type split means any future caller who does
        // insert a `Resolved` handle cannot accidentally produce a
        // signature against it.
        let pub_bytes = [0xAAu8; 32];
        let did = format!("did:dht:z{}", zbase32_encode(&pub_bytes));
        IDENTITY_REGISTRY.with(|reg| {
            reg.borrow_mut().insert(
                did.clone(),
                IdentityRecord::Resolved {
                    public_key_bytes: pub_bytes,
                    custody_type: "js_custody".to_owned(),
                },
            );
        });

        // Sanity: the accessor helpers work on both variants.
        IDENTITY_REGISTRY.with(|reg| {
            let map = reg.borrow();
            let entry = map.get(&did).expect("record must be present");
            assert_eq!(entry.public_key_bytes(), pub_bytes);
            assert_eq!(entry.custody_type(), "js_custody");
        });

        // `#active` must refuse structurally with IDENT_1028.
        let err_active = sign_with_identity(&did, "#active", b"payload")
            .expect_err("Resolved handle must refuse to sign #active");
        match err_active {
            ScpWasmError::Identity {
                ref code,
                ref message,
            } => {
                assert_eq!(
                    code,
                    codes::IDENT_1028,
                    "Resolved #active refusal must use IDENT_1028; got {code}"
                );
                assert!(
                    message.contains("resolved from a DID string"),
                    "refusal message should explain the cause: {message}"
                );
            }
            other => panic!("expected Identity error, got: {other:?}"),
        }

        // `#agent` must refuse with the same structural error — the
        // refusal predates the kid-specific match arms.
        let err_agent = sign_with_identity(&did, "#agent", b"payload")
            .expect_err("Resolved handle must refuse to sign #agent");
        match err_agent {
            ScpWasmError::Identity { ref code, .. } => {
                assert_eq!(
                    code,
                    codes::IDENT_1028,
                    "Resolved #agent refusal must use IDENT_1028; got {code}"
                );
            }
            other => panic!("expected Identity error, got: {other:?}"),
        }

        // Verifying-key resolution also refuses rather than silently
        // returning `#0` under `#active`.
        let resolver_err = resolve_verification_method_key(&did, "#active")
            .expect_err("resolver must refuse Resolved #active");
        assert!(
            resolver_err.contains("resolved from a DID string"),
            "resolver refusal message should explain the cause: {resolver_err}"
        );

        // `identity_verify_device_attestation`-style public-key reads
        // continue to work on a `Resolved` record — `public_key_bytes`
        // is available on both variants.
        let resolved_pub = IDENTITY_REGISTRY
            .with(|reg| reg.borrow().get(&did).map(IdentityRecord::public_key_bytes));
        assert_eq!(resolved_pub, Some(pub_bytes));

        cleanup_registries();
    }

    // -------------------------------------------------------------------
    // identity_rotate_key — active-key-only rotation parity tests
    // -------------------------------------------------------------------

    /// Reads the current `#active` private-key bytes for `did` out of the
    /// registry. Test-only — production code never copies private key
    /// material out of the registry.
    fn snapshot_active_signing_key(did: &str) -> [u8; 32] {
        IDENTITY_REGISTRY.with(|reg| match reg.borrow().get(did) {
            Some(IdentityRecord::Local {
                active_signing_key_bytes,
                ..
            }) => **active_signing_key_bytes,
            other => panic!("expected Local record for {did}, got {other:?}"),
        })
    }

    fn handle_for(did: &str, identity_pub_bytes: [u8; 32]) -> WasmIdentity {
        WasmIdentity {
            did: did.to_owned(),
            custody_type: "in_memory".to_owned(),
            has_agent_key: false,
            agent_public_key_multibase: None,
            verifying_key_hex: Some(hex::encode(identity_pub_bytes)),
        }
    }

    #[test]
    fn rotate_key_preserves_did_and_identity_key() {
        cleanup_registries();
        let (did, identity_pub_bytes, _) = register_identity();
        let handle = handle_for(&did, identity_pub_bytes);

        let rotated = identity_rotate_key(&handle).expect("rotate_key should succeed");

        assert_eq!(
            rotated.did, did,
            "rotate_key MUST preserve the DID — active-key-only rotation"
        );
        assert_eq!(
            rotated.verifying_key_hex,
            Some(hex::encode(identity_pub_bytes)),
            "rotate_key MUST preserve the #0 verifying-key snapshot"
        );
        let registry_pub = IDENTITY_REGISTRY.with(|reg| {
            reg.borrow().get(&did).map_or_else(
                || panic!("expected entry for {did}"),
                IdentityRecord::public_key_bytes,
            )
        });
        assert_eq!(
            registry_pub, identity_pub_bytes,
            "rotate_key MUST NOT mutate the #0 identity key in the registry"
        );

        cleanup_registries();
    }

    #[test]
    fn rotate_key_changes_active_signing_key() {
        cleanup_registries();
        let (did, identity_pub_bytes, _) = register_identity();
        let handle = handle_for(&did, identity_pub_bytes);
        let pre_rotation_active = snapshot_active_signing_key(&did);

        identity_rotate_key(&handle).expect("rotate_key should succeed");

        let post_rotation_active = snapshot_active_signing_key(&did);
        assert_ne!(
            pre_rotation_active, post_rotation_active,
            "rotate_key MUST replace the #active signing key bytes"
        );

        cleanup_registries();
    }

    #[test]
    fn rotate_key_preserves_agent_key_bytes() {
        cleanup_registries();
        let (did, identity_pub_bytes, _, agent_pub_bytes) = register_identity_with_agent();
        let mut handle = handle_for(&did, identity_pub_bytes);
        handle.has_agent_key = true;
        handle.agent_public_key_multibase = Some(format!("z{}", zbase32_encode(&agent_pub_bytes)));

        let rotated = identity_rotate_key(&handle).expect("rotate_key should succeed");

        // Returned handle reflects the input agent-key state.
        assert!(
            rotated.has_agent_key,
            "rotate_key MUST preserve has_agent_key=true across rotation"
        );
        assert_eq!(
            rotated.agent_public_key_multibase,
            Some(format!("z{}", zbase32_encode(&agent_pub_bytes))),
            "rotate_key MUST preserve the agent public-key multibase"
        );

        // Registry's agent signing key is bit-for-bit unchanged: rotation
        // touches `#active` only.
        let post_rotation_agent = IDENTITY_REGISTRY.with(|reg| match reg.borrow().get(&did) {
            Some(IdentityRecord::Local {
                agent_signing_key_bytes: Some(bytes),
                ..
            }) => **bytes,
            other => panic!("expected Local with agent key, got {other:?}"),
        });
        let expected_agent = ed25519_dalek::VerifyingKey::from(
            &ed25519_dalek::SigningKey::from_bytes(&post_rotation_agent),
        )
        .to_bytes();
        assert_eq!(
            expected_agent, agent_pub_bytes,
            "rotate_key MUST NOT touch the agent signing key"
        );

        cleanup_registries();
    }

    #[test]
    fn rotate_key_does_not_record_migration_link() {
        cleanup_registries();
        let (did, identity_pub_bytes, _) = register_identity();
        let handle = handle_for(&did, identity_pub_bytes);

        identity_rotate_key(&handle).expect("rotate_key should succeed");

        // No DID change, so no entry should land in MIGRATION_LINKS.
        let migration_link_count = MIGRATION_LINKS.with(|links| links.borrow().len());
        assert_eq!(
            migration_link_count, 0,
            "rotate_key MUST NOT write to MIGRATION_LINKS — that is identity_migrate's contract"
        );

        cleanup_registries();
    }

    #[test]
    fn rotate_key_keeps_link_attestations_under_same_did() {
        cleanup_registries();
        let (did, identity_pub_bytes, _) = register_identity();
        let handle = handle_for(&did, identity_pub_bytes);

        // Attach a single attestation to the original DID.
        LINK_ATTESTATIONS.with(|reg| {
            reg.borrow_mut().insert(
                did.clone(),
                vec![serde_json::json!({"id": "test-attestation"})],
            );
        });

        identity_rotate_key(&handle).expect("rotate_key should succeed");

        let attested =
            LINK_ATTESTATIONS.with(|reg| reg.borrow().get(&did).map(Vec::len).unwrap_or_default());
        assert_eq!(
            attested, 1,
            "rotate_key MUST leave LINK_ATTESTATIONS entries on the original DID — \
             the DID itself does not change"
        );

        cleanup_registries();
    }

    #[test]
    fn rotate_key_unknown_did_errors() {
        cleanup_registries();
        let handle = WasmIdentity {
            did: "did:dht:znothinghere".to_owned(),
            custody_type: "in_memory".to_owned(),
            has_agent_key: false,
            agent_public_key_multibase: None,
            verifying_key_hex: None,
        };

        // Inspect the typed error via the inner function — `JsError`
        // cannot be unwrapped on non-wasm targets.
        let err =
            rotate_active_key_inner(&handle).expect_err("rotate_key on unknown DID must fail");
        match err {
            ScpWasmError::Identity { ref code, .. } => {
                assert_eq!(
                    code,
                    codes::IDENT_1002,
                    "unknown-DID refusal must use IDENT_1002 (\"Identity not found\"); got {code}"
                );
            }
            other => panic!("expected Identity error, got: {other:?}"),
        }

        cleanup_registries();
    }

    #[test]
    fn rotate_key_resolved_record_refused() {
        cleanup_registries();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let did = format!("did:dht:z{}", zbase32_encode(&pub_bytes));

        IDENTITY_REGISTRY.with(|reg| {
            reg.borrow_mut().insert(
                did.clone(),
                IdentityRecord::Resolved {
                    public_key_bytes: pub_bytes,
                    custody_type: "js_custody".to_owned(),
                },
            );
        });

        let handle = handle_for(&did, pub_bytes);
        let err = rotate_active_key_inner(&handle).expect_err("rotate_key on Resolved must refuse");
        match err {
            ScpWasmError::Identity { ref code, .. } => {
                assert_eq!(
                    code,
                    codes::IDENT_1028,
                    "Resolved refusal must use IDENT_1028; got {code}"
                );
            }
            other => panic!("expected Identity error, got: {other:?}"),
        }

        cleanup_registries();
    }

    #[test]
    fn rotate_key_updates_resolved_active_verification_method() {
        cleanup_registries();
        let (did, identity_pub_bytes, pre_active_pub) = register_identity();
        let handle = handle_for(&did, identity_pub_bytes);

        identity_rotate_key(&handle).expect("rotate_key should succeed");

        // After rotation, identity_resolve must surface the NEW #active VM.
        let fields = resolve_did_document_fields(&did);
        let vms: Vec<serde_json::Value> =
            serde_json::from_str(&fields.verification_methods_json).unwrap();
        let active_vm = vms
            .iter()
            .find(|vm| vm.get("id").and_then(|v| v.as_str()) == Some(&format!("{did}#active")))
            .expect("resolved DID document must expose #active after rotation");
        let active_multibase = active_vm
            .get("publicKeyMultibase")
            .and_then(|v| v.as_str())
            .expect("#active VM must expose publicKeyMultibase");
        let pre_multibase = format!("z{}", zbase32_encode(&pre_active_pub));
        assert_ne!(
            active_multibase, pre_multibase,
            "rotate_key MUST publish a new #active verifying key in the resolved DID document"
        );

        cleanup_registries();
    }

    #[test]
    fn rotate_key_twice_produces_three_distinct_active_keys() {
        cleanup_registries();
        let (did, identity_pub_bytes, _) = register_identity();
        let handle = handle_for(&did, identity_pub_bytes);
        let active_0 = snapshot_active_signing_key(&did);

        identity_rotate_key(&handle).expect("first rotate_key should succeed");
        let active_1 = snapshot_active_signing_key(&did);

        identity_rotate_key(&handle).expect("second rotate_key should succeed");
        let active_2 = snapshot_active_signing_key(&did);

        assert_ne!(active_0, active_1, "first rotation must replace #active");
        assert_ne!(
            active_1, active_2,
            "second rotation must replace #active again"
        );
        assert_ne!(
            active_0, active_2,
            "back-to-back rotations must not collide"
        );

        cleanup_registries();
    }

    #[test]
    fn rotate_key_then_sign_active_uses_new_key() {
        use ed25519_dalek::{Signature, Verifier};

        cleanup_registries();
        let (did, identity_pub_bytes, _) = register_identity();
        let handle = handle_for(&did, identity_pub_bytes);

        identity_rotate_key(&handle).expect("rotate_key should succeed");

        // sign_with_identity(#active) must use the NEW key, and the
        // verifying key surfaced by resolve_verification_method_key(#active)
        // must verify the signature.
        let message = b"post-rotation-active-signature";
        let sig_bytes = sign_with_identity(&did, "#active", message)
            .expect("sign_with_identity(#active) should succeed after rotation");
        let signature = Signature::from_bytes(&sig_bytes);
        let resolved_pub = resolve_verification_method_key(&did, "#active")
            .expect("resolve_verification_method_key(#active) should succeed after rotation");
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&resolved_pub)
            .expect("resolved #active bytes must decode");
        verifying_key
            .verify(message, &signature)
            .expect("post-rotation signature must verify under the resolved #active key");

        cleanup_registries();
    }

    // ----------------------------------------------------------------
    // Pre-rotation commitment lifecycle (spec §3.7)
    // ----------------------------------------------------------------

    /// Reads the pre-rotation private bytes out of the registry. Test-only.
    fn snapshot_pre_rotation_key(did: &str) -> [u8; 32] {
        IDENTITY_REGISTRY.with(|reg| match reg.borrow().get(did) {
            Some(IdentityRecord::Local {
                pre_rotation_signing_key_bytes,
                ..
            }) => **pre_rotation_signing_key_bytes,
            other => panic!("expected Local record for {did}, got {other:?}"),
        })
    }

    fn pre_rotation_service_commitment_hex(did: &str) -> String {
        let fields = resolve_did_document_fields(did);
        let services: Vec<serde_json::Value> = serde_json::from_str(&fields.services_json).unwrap();
        let pre_rotation = services
            .iter()
            .find(|s| s["id"].as_str() == Some(&format!("{did}#pre-rotation")))
            .expect("Local identities MUST publish a #pre-rotation service");
        let endpoint = pre_rotation["serviceEndpoint"]
            .as_str()
            .expect("serviceEndpoint must be a string");
        endpoint
            .strip_prefix("sha256:")
            .expect("endpoint must be `sha256:<hex>`")
            .to_owned()
    }

    #[test]
    fn create_publishes_pre_rotation_commitment() {
        cleanup_registries();
        let (did, _, _) = register_identity();

        // Local pre-rotation private bytes derive a public key whose
        // SHA-256 must equal the published commitment.
        let pre_rotation_priv = snapshot_pre_rotation_key(&did);
        let pre_rotation_pub = ed25519_dalek::SigningKey::from_bytes(&pre_rotation_priv)
            .verifying_key()
            .to_bytes();
        let expected_commitment_hex =
            hex::encode(compute_pre_rotation_commitment(&pre_rotation_pub));
        let published_commitment_hex = pre_rotation_service_commitment_hex(&did);
        assert_eq!(
            published_commitment_hex, expected_commitment_hex,
            "#pre-rotation service endpoint MUST match SHA-256 of the local pre-rotation public key"
        );

        cleanup_registries();
    }

    #[test]
    fn rotate_key_preserves_pre_rotation_commitment() {
        cleanup_registries();
        let (did, identity_pub_bytes, _) = register_identity();
        let handle = handle_for(&did, identity_pub_bytes);
        let pre_rotation_before = snapshot_pre_rotation_key(&did);

        identity_rotate_key(&handle).expect("rotate_key should succeed");

        let pre_rotation_after = snapshot_pre_rotation_key(&did);
        assert_eq!(
            pre_rotation_before, pre_rotation_after,
            "Layer-1 rotation MUST preserve the pre-rotation key (spec §3.7) so the \
             commitment chain remains valid for the next migration"
        );

        cleanup_registries();
    }

    #[test]
    fn migrate_consumes_pre_rotation_key_as_new_identity() {
        use ed25519_dalek::Verifier;
        use sha2::{Digest, Sha256};

        cleanup_registries();
        let (old_did, identity_pub_bytes, _) = register_identity();
        let handle = handle_for(&old_did, identity_pub_bytes);

        // The OLD pre-rotation public key MUST become the new #0 — that
        // is the entire point of pre-rotation forward-secure chaining.
        let expected_new_identity_pub =
            ed25519_dalek::SigningKey::from_bytes(&snapshot_pre_rotation_key(&old_did))
                .verifying_key()
                .to_bytes();
        let expected_new_did = format!("did:dht:z{}", zbase32_encode(&expected_new_identity_pub));

        let result = migrate_inner(&handle, 1_700_000_000).expect("migrate should succeed");

        assert_eq!(
            result.identity.did, expected_new_did,
            "migrate MUST derive the new DID from the previously-committed pre-rotation key"
        );
        assert_eq!(
            result.identity.verifying_key_hex,
            Some(hex::encode(expected_new_identity_pub)),
            "the new #0 MUST be the OLD pre-rotation key (revealed)"
        );

        // Registry is updated: new DID is present, old DID is not.
        let new_present =
            IDENTITY_REGISTRY.with(|reg| reg.borrow().contains_key(&expected_new_did));
        let old_present = IDENTITY_REGISTRY.with(|reg| reg.borrow().contains_key(&old_did));
        assert!(new_present, "new DID MUST be installed");
        assert!(!old_present, "old DID MUST be removed");

        // Verify the rotation-event JSON shape: pre-rotation proof's
        // revealed_key MUST hash to the commitment.
        let event: serde_json::Value = serde_json::from_str(&result.rotation_event_json).unwrap();
        assert_eq!(event["old_did"], old_did);
        assert_eq!(event["new_did"], expected_new_did);
        let revealed_hex = event["pre_rotation_proof"]["revealed_key"]
            .as_str()
            .unwrap();
        let commitment_hex = event["pre_rotation_proof"]["commitment"].as_str().unwrap();
        let revealed_bytes: [u8; 32] = hex::decode(revealed_hex).unwrap().try_into().unwrap();
        let recomputed_commitment_hex =
            hex::encode(compute_pre_rotation_commitment(&revealed_bytes));
        assert_eq!(
            recomputed_commitment_hex, commitment_hex,
            "PreRotationProof MUST satisfy SHA-256(revealed_key) == commitment"
        );

        // Migration proof signature MUST verify under the OLD #0 public key.
        let sig_hex = event["migration_proof"]["signature"].as_str().unwrap();
        let old_pub_hex = event["migration_proof"]["old_public_key"].as_str().unwrap();
        assert_eq!(
            old_pub_hex,
            hex::encode(identity_pub_bytes),
            "MigrationProof.old_public_key MUST equal the old DID's #0"
        );
        let sig_bytes: [u8; 64] = hex::decode(sig_hex).unwrap().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let old_pub_bytes: [u8; 32] = hex::decode(old_pub_hex).unwrap().try_into().unwrap();
        let old_verifying = ed25519_dalek::VerifyingKey::from_bytes(&old_pub_bytes).unwrap();
        // Recompute the digest the way migrate_inner did.
        let rotated_at = event["rotated_at"].as_u64().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_MIGRATION_V1);
        hasher.update(u32::try_from(old_did.len()).unwrap().to_be_bytes());
        hasher.update(old_did.as_bytes());
        hasher.update(u32::try_from(expected_new_did.len()).unwrap().to_be_bytes());
        hasher.update(expected_new_did.as_bytes());
        hasher.update(rotated_at.to_be_bytes());
        let digest = hasher.finalize();
        old_verifying
            .verify(&digest, &signature)
            .expect("MigrationProof signature MUST verify under the old #0 public key");

        // The new identity's pre-rotation key is FRESH (not re-using
        // the new #0). Verify it publishes a new commitment.
        let new_pre_rotation_priv = snapshot_pre_rotation_key(&expected_new_did);
        let new_pre_rotation_pub = ed25519_dalek::SigningKey::from_bytes(&new_pre_rotation_priv)
            .verifying_key()
            .to_bytes();
        assert_ne!(
            new_pre_rotation_pub, expected_new_identity_pub,
            "migration MUST mint a fresh pre-rotation key for the next chain link"
        );
        let new_commitment_hex = pre_rotation_service_commitment_hex(&expected_new_did);
        assert_eq!(
            new_commitment_hex,
            hex::encode(compute_pre_rotation_commitment(&new_pre_rotation_pub)),
            "migrated identity MUST publish the fresh pre-rotation commitment"
        );

        // Migration link records new -> old.
        let aka = MIGRATION_LINKS.with(|links| links.borrow().get(&expected_new_did).cloned());
        assert_eq!(aka, Some(old_did));

        cleanup_registries();
    }

    #[test]
    fn migrate_unknown_did_errors_with_ident_1002() {
        cleanup_registries();
        let handle = WasmIdentity {
            did: "did:dht:zabsentvictim".to_owned(),
            custody_type: "in_memory".to_owned(),
            has_agent_key: false,
            agent_public_key_multibase: None,
            verifying_key_hex: None,
        };

        let err = migrate_inner(&handle, 1_700_000_000).expect_err("unknown DID must refuse");
        match err {
            ScpWasmError::Identity { ref code, .. } => {
                assert_eq!(
                    code,
                    codes::IDENT_1002,
                    "unknown-DID migrate refusal must use IDENT_1002; got {code}"
                );
            }
            other => panic!("expected Identity error, got: {other:?}"),
        }

        cleanup_registries();
    }

    #[test]
    fn migrate_resolved_record_refused_with_ident_1028() {
        cleanup_registries();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let did = format!("did:dht:z{}", zbase32_encode(&pub_bytes));
        IDENTITY_REGISTRY.with(|reg| {
            reg.borrow_mut().insert(
                did.clone(),
                IdentityRecord::Resolved {
                    public_key_bytes: pub_bytes,
                    custody_type: "js_custody".to_owned(),
                },
            );
        });
        let handle = handle_for(&did, pub_bytes);

        let err = migrate_inner(&handle, 1_700_000_000).expect_err("Resolved migrate must refuse");
        match err {
            ScpWasmError::Identity { ref code, .. } => {
                assert_eq!(
                    code,
                    codes::IDENT_1028,
                    "Resolved migrate refusal must use IDENT_1028; got {code}"
                );
            }
            other => panic!("expected Identity error, got: {other:?}"),
        }

        cleanup_registries();
    }
}
