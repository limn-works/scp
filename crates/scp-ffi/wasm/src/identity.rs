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
/// Private key fields are wrapped in [`zeroize::Zeroizing`] and the struct
/// implements [`ZeroizeOnDrop`] so that key material is overwritten with zeros
/// when the entry is removed from the registry or replaced. `Clone` is
/// intentionally NOT derived — cloning would scatter unprotected copies of
/// private keys through WASM linear memory.
#[derive(Zeroize, ZeroizeOnDrop)]
struct IdentityEntry {
    /// Ed25519 signing key bytes (32 bytes). Stored to produce real Ed25519
    /// signatures for device attestation and other identity operations.
    ///
    /// Wrapped in `Zeroizing` for defense-in-depth: WASM linear memory is
    /// readable by same-origin JS, so key material must be zeroed on drop.
    signing_key_bytes: zeroize::Zeroizing<[u8; 32]>,
    /// Ed25519 public key bytes (32 bytes).
    public_key_bytes: [u8; 32],
    /// Custody type string. Retained for future use when custody operations
    /// are wired (e.g., signing, key rotation).
    #[allow(dead_code)]
    custody_type: String,
    /// Agent signing key bytes (32 bytes), if an agent key has been bound.
    ///
    /// Wrapped in `Zeroizing` for defense-in-depth (same rationale as
    /// `signing_key_bytes`).
    agent_signing_key_bytes: Option<zeroize::Zeroizing<[u8; 32]>>,
}

impl std::fmt::Debug for IdentityEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityEntry")
            .field("signing_key_bytes", &"[REDACTED]")
            .field("public_key_bytes", &self.public_key_bytes)
            .field("custody_type", &self.custody_type)
            .field(
                "agent_signing_key_bytes",
                &if self.agent_signing_key_bytes.is_some() {
                    "[REDACTED]"
                } else {
                    "[None]"
                },
            )
            .finish()
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
    static IDENTITY_REGISTRY: RefCell<HashMap<String, IdentityEntry>> =
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

        match kid {
            "#active" => Ok(entry.public_key_bytes),
            "#agent" => {
                let agent_sk_bytes = entry.agent_signing_key_bytes.as_ref().ok_or_else(|| {
                    format!("no agent key bound for DID '{did}' — cannot verify kid '#agent'")
                })?;
                let sk = ed25519_dalek::SigningKey::from_bytes(agent_sk_bytes);
                Ok(sk.verifying_key().to_bytes())
            }
            _ => Err(format!(
                "unrecognized verification method '{kid}' on DID '{did}' \
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

        // HKDF-SHA256: extract(salt=[], ikm=signing_key) then
        // expand(info=EXPORT_HMAC_DOMAIN, len=32).
        let prk = hkdf_extract_sha256(&[], entry.signing_key_bytes.as_ref()).map_err(|e| {
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
    /// Hex-encoded Ed25519 verifying-key bytes for the `#active` signing
    /// key (64 hex chars = 32 raw bytes). `None` for identities constructed
    /// via `fromDid` (no retained key material).
    ///
    /// Exposed for cross-bridge parity testing (ADR-046): with a
    /// deterministic seed, every bridge's `identity_create` must produce
    /// byte-identical verifying keys.
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

    /// Returns the hex-encoded Ed25519 verifying-key bytes for the `#active`
    /// signing key, or `null` if this handle was constructed from a bare DID
    /// string without live key material.
    ///
    /// Under a deterministic `seed`, this value is byte-identical across
    /// every bridge (ADR-046 / FOLLOWUP.md §1).
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
#[wasm_bindgen]
pub fn identity_create(custody: String, seed: Option<Vec<u8>>) -> Promise {
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

        // Validate the optional 32-byte seed at the FFI boundary. A seed
        // is only meaningful when the `testing` feature is enabled
        // (cross-bridge parity harness, ADR-046).
        let seed_bytes: Option<[u8; 32]> = match seed.as_deref() {
            None => None,
            #[cfg(feature = "testing")]
            Some(bytes) => Some(<[u8; 32]>::try_from(bytes).map_err(|_| {
                ScpWasmError::Validation {
                    message: format!("seed must be exactly 32 bytes, got {}", bytes.len()),
                    code: codes::VALID_7007.to_owned(),
                }
                .into_js()
            })?),
            #[cfg(not(feature = "testing"))]
            Some(_) => {
                return Err(ScpWasmError::Validation {
                    message: "`seed` parameter requires the `testing` feature — not available \
                              in production WASM builds"
                        .to_owned(),
                    code: codes::VALID_7007.to_owned(),
                }
                .into_js()
                .into());
            }
        };

        // Generate the identity-key Ed25519 keypair. Under the seeded
        // path (only reachable when the `testing` feature is enabled) we
        // derive the key from `rand::rngs::StdRng::from_seed(seed)` —
        // the same KDF used by `InMemoryKeyCustody::from_seed_bytes` on
        // the scp-core bridges, so the first generated key is byte-equal
        // across all four bridges (ADR-046). The `rand` crate is pulled
        // in only by the `testing` feature so production WASM bundles
        // don't ship the extra code.
        #[cfg(feature = "testing")]
        let signing_key = if let Some(s) = seed_bytes {
            use rand::{RngCore, SeedableRng};
            let mut rng = rand::rngs::StdRng::from_seed(s);
            let mut key_bytes = zeroize::Zeroizing::new([0u8; 32]);
            rng.fill_bytes(key_bytes.as_mut());
            ed25519_dalek::SigningKey::from_bytes(&key_bytes)
        } else {
            ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng)
        };
        #[cfg(not(feature = "testing"))]
        let signing_key = {
            // When `testing` is off, the seed-validation path above has
            // already returned an error for non-None seeds, so
            // `seed_bytes` is guaranteed to be None here.
            let _ = seed_bytes;
            ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng)
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
                IdentityEntry {
                    signing_key_bytes: zeroize::Zeroizing::new(signing_key.to_bytes()),
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

/// Builds the DID document fields for a locally-known identity.
///
/// Pure logic extracted from [`identity_resolve`] so it can be tested without
/// `wasm_bindgen` / `Promise` / `JsValue` dependencies.
///
/// Reads from `IDENTITY_REGISTRY` and `MIGRATION_LINKS` thread-local state.
fn resolve_did_document_fields(did: &str) -> ResolvedDocumentFields {
    // Look up public key bytes from the local identity registry.
    // Only extract public keys — never clone private key material
    // out of the registry. Derive agent public key inside the closure.
    let key_info = IDENTITY_REGISTRY.with(|reg| {
        let map = reg.borrow();
        map.get(did).map(|entry| {
            let agent_pub_bytes = entry.agent_signing_key_bytes.as_ref().map(|sk_bytes| {
                let sk = ed25519_dalek::SigningKey::from_bytes(sk_bytes);
                sk.verifying_key().to_bytes()
            });
            (entry.public_key_bytes, agent_pub_bytes)
        })
    });

    let (verification_methods_json, authentication_json, assertion_methods_json) = key_info
        .map_or_else(
            || ("[]".to_owned(), "[]".to_owned(), "[]".to_owned()),
            |(pub_bytes, agent_pub_bytes)| {
                // Build verification methods for ALL keys in the identity
                // per ADR-039: #0 (Identity Key), #active (Active Signing
                // Key), and optionally #agent (Agent Signing Key).
                let identity_multibase = format!("z{}", zbase32_encode(&pub_bytes));

                // #0 — Identity Key (DID-deriving key, never rotates).
                let mut vms = vec![serde_json::json!({
                    "id": format!("{did}#0"),
                    "type": "Ed25519VerificationKey2020",
                    "controller": did,
                    "publicKeyMultibase": identity_multibase,
                })];

                // #active — Active Signing Key (Human Signing Key). In the
                // WASM bridge's simplified key model, the active signing key
                // uses the same keypair as the identity key. Authentication
                // and assertionMethod reference #active (not #0), matching
                // the scp-core DidDocument pattern.
                vms.push(serde_json::json!({
                    "id": format!("{did}#active"),
                    "type": "Ed25519VerificationKey2020",
                    "controller": did,
                    "publicKeyMultibase": identity_multibase,
                }));

                let mut auth = vec![serde_json::json!(format!("{did}#active"))];
                let mut assertion = vec![serde_json::json!(format!("{did}#active"))];

                // #agent — Agent Signing Key (ADR-039), included when present.
                if let Some(agent_bytes) = agent_pub_bytes {
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

                let vm_json = serde_json::Value::Array(vms);
                let auth_json = serde_json::Value::Array(auth);
                let assertion_json = serde_json::Value::Array(assertion);
                (
                    serde_json::to_string(&vm_json).unwrap_or_else(|_| "[]".to_owned()),
                    serde_json::to_string(&auth_json).unwrap_or_else(|_| "[]".to_owned()),
                    serde_json::to_string(&assertion_json).unwrap_or_else(|_| "[]".to_owned()),
                )
            },
        );

    // Populate alsoKnownAs from MIGRATION_LINKS — after identity_migrate
    // or identity_rotate_key, the new DID maps to the old DID (#540).
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
        services_json: "[]".to_owned(),
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

        // Generate identity Ed25519 keypair.
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();
        let did = format!("did:dht:z{}", zbase32_encode(&pub_bytes));

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
                IdentityEntry {
                    signing_key_bytes: zeroize::Zeroizing::new(signing_key.to_bytes()),
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
/// Returns `[SCP-IDENT-1009]` if the identity already has an agent key.
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

    // Store the agent signing key in the identity registry.
    let did = identity.did.clone();
    let found = IDENTITY_REGISTRY.with(|reg| {
        let mut map = reg.borrow_mut();
        if let Some(entry) = map.get_mut(&did) {
            entry.agent_signing_key_bytes = Some(zeroize::Zeroizing::new(agent_key.to_bytes()));
            true
        } else {
            false
        }
    });
    if !found {
        return Err(ScpWasmError::Identity {
            message: format!("identity not found in registry: {did}"),
            code: codes::IDENT_1009.to_owned(),
        }
        .into_js());
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

/// Rotates the agent signing key for an identity (ADR-039).
///
/// Generates a new Ed25519 agent keypair, stores it in the identity registry,
/// and returns an updated identity.
///
/// # Errors
///
/// Returns `[SCP-IDENT-1011]` if the identity has no agent key to rotate.
/// Returns `[SCP-IDENT-1010]` if the new public key is empty.
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

    // Store the new agent signing key in the identity registry.
    let did = identity.did.clone();
    let found = IDENTITY_REGISTRY.with(|reg| {
        let mut map = reg.borrow_mut();
        if let Some(entry) = map.get_mut(&did) {
            entry.agent_signing_key_bytes = Some(zeroize::Zeroizing::new(agent_key.to_bytes()));
            true
        } else {
            false
        }
    });
    if !found {
        return Err(ScpWasmError::Identity {
            message: format!("identity not found in registry: {did}"),
            code: codes::IDENT_1011.to_owned(),
        }
        .into_js());
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

/// Rotates the main signing key for an identity.
///
/// Generates a new Ed25519 keypair, derives a new `did:dht` DID from the
/// new public key, updates the identity registry, and returns a new
/// `WasmIdentity`. The old DID is stored in the migration links so
/// `identity_resolve` can include it in `alsoKnownAs`.
///
/// # Errors
///
/// Returns `[SCP-IDENT-1010]` if key generation fails.
#[wasm_bindgen]
pub fn identity_rotate_key(identity: &WasmIdentity) -> Result<WasmIdentity, JsError> {
    let old_did = identity.did.clone();
    let custody = identity.custody_type.clone();

    // Generate a new Ed25519 signing key.
    let new_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let new_pub = new_key.verifying_key();
    let pub_bytes = new_pub.to_bytes();
    let new_did = format!("did:dht:z{}", zbase32_encode(&pub_bytes));

    // Remove old entry and re-insert new entry in a single closure so the
    // agent key bytes are moved, not cloned.
    IDENTITY_REGISTRY
        .with(|reg| {
            let mut map = reg.borrow_mut();

            // Take the agent key bytes from the old entry before removing it.
            // `take()` moves the inner value out without cloning; the remaining
            // entry is zeroized on drop via `remove()`.
            let agent_key_bytes = map
                .get_mut(&old_did)
                .and_then(|entry| entry.agent_signing_key_bytes.take());
            map.remove(&old_did);

            check_registry_capacity(
                &*map,
                &new_did,
                WASM_IDENTITY_REGISTRY_CAP,
                "identity registry",
                codes::VALID_7400,
            )?;

            map.insert(
                new_did.clone(),
                IdentityEntry {
                    signing_key_bytes: zeroize::Zeroizing::new(new_key.to_bytes()),
                    public_key_bytes: pub_bytes,
                    custody_type: custody.clone(),
                    agent_signing_key_bytes: agent_key_bytes,
                },
            );

            Ok::<(), JsValue>(())
        })
        .map_err(|e| JsError::new(&format!("{e:?}")))?;

    // Migrate any link attestations from the old DID to the new DID so they
    // remain discoverable after rotation.
    LINK_ATTESTATIONS.with(|reg| {
        let mut map = reg.borrow_mut();
        if let Some(attestations) = map.remove(&old_did) {
            map.insert(new_did.clone(), attestations);
        }
    });

    // Record the migration link (with capacity check).
    MIGRATION_LINKS
        .with(|links| {
            let mut map = links.borrow_mut();
            check_registry_capacity(
                &*map,
                &new_did,
                WASM_MIGRATION_LINKS_CAP,
                "migration links registry",
                codes::VALID_7401,
            )?;
            map.insert(new_did.clone(), old_did);
            Ok::<(), JsValue>(())
        })
        .map_err(|e| JsError::new(&format!("{e:?}")))?;

    // Derive agent key state from the registry entry (authoritative) rather
    // than copying from the input handle, which may be stale.
    let (has_agent, agent_multibase) = IDENTITY_REGISTRY.with(|reg| {
        let map = reg.borrow();
        map.get(&new_did).map_or((false, None), |entry| {
            entry
                .agent_signing_key_bytes
                .as_ref()
                .map_or((false, None), |sk_bytes| {
                    let sk = ed25519_dalek::SigningKey::from_bytes(sk_bytes);
                    let pub_bytes = sk.verifying_key().to_bytes();
                    (true, Some(format!("z{}", zbase32_encode(&pub_bytes))))
                })
        })
    });

    Ok(WasmIdentity {
        did: new_did,
        custody_type: custody,
        has_agent_key: has_agent,
        agent_public_key_multibase: agent_multibase,
        // Key rotation produces a new identity key, hence a new
        // verifying_key + new DID.
        verifying_key_hex: Some(hex::encode(pub_bytes)),
    })
}

/// Removes the agent signing key from an identity (ADR-039).
///
/// # Errors
///
/// Returns `[SCP-IDENT-1011]` if the identity has no agent key to remove.
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
    // the key material from lingering in WASM linear memory.
    let did = identity.did.clone();
    let found = IDENTITY_REGISTRY.with(|reg| {
        let mut map = reg.borrow_mut();
        if let Some(entry) = map.get_mut(&did) {
            entry.agent_signing_key_bytes = None;
            true
        } else {
            false
        }
    });
    if !found {
        return Err(ScpWasmError::Identity {
            message: format!("identity not found in registry: {did}"),
            code: codes::IDENT_1011.to_owned(),
        }
        .into_js());
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

/// Migrates an identity to a new DID (Layer 2 rotation).
///
/// Generates a new Ed25519 keypair, derives a new `did:dht` DID, and returns
/// a new `WasmIdentity`. The old DID is stored in the `alsoKnownAs` field
/// of the new identity's DID document (handled by `identity_resolve`).
///
/// If the source identity has an agent key, a new agent key is generated
/// for the migrated identity (preserving the `has_agent_key` state).
#[wasm_bindgen]
pub fn identity_migrate(identity: &WasmIdentity) -> Promise {
    let old_did = identity.did.clone();
    let custody = identity.custody_type.clone();
    let had_agent_key = identity.has_agent_key;
    future_to_promise(async move {
        // Generate new Ed25519 keypair for the new DID.
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();
        let new_did = format!("did:dht:z{}", zbase32_encode(&pub_bytes));

        // If the source identity had an agent key, generate a new one.
        let (agent_signing_key_bytes, agent_public_key_multibase) = if had_agent_key {
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

        IDENTITY_REGISTRY.with(|reg| {
            let mut map = reg.borrow_mut();
            // Remove the old identity's key material from the registry.
            // `ZeroizeOnDrop` ensures the old signing keys are zeroed.
            map.remove(&old_did);
            // After removing old_did, the net count stays the same or decreases,
            // so we only need to check if the new_did is truly a new entry.
            check_registry_capacity(
                &*map,
                &new_did,
                WASM_IDENTITY_REGISTRY_CAP,
                "identity registry",
                codes::VALID_7400,
            )?;
            map.insert(
                new_did.clone(),
                IdentityEntry {
                    signing_key_bytes: zeroize::Zeroizing::new(signing_key.to_bytes()),
                    public_key_bytes: pub_bytes,
                    custody_type: custody.clone(),
                    agent_signing_key_bytes,
                },
            );
            Ok::<(), JsValue>(())
        })?;

        // Migrate any link attestations from the old DID to the new DID so
        // they remain discoverable after migration.
        LINK_ATTESTATIONS.with(|reg| {
            let mut map = reg.borrow_mut();
            if let Some(attestations) = map.remove(&old_did) {
                map.insert(new_did.clone(), attestations);
            }
        });

        // Store the migration link so identity_resolve can populate alsoKnownAs.
        MIGRATION_LINKS.with(|links| {
            let mut map = links.borrow_mut();
            check_registry_capacity(
                &*map,
                &new_did,
                WASM_MIGRATION_LINKS_CAP,
                "migration links registry",
                codes::VALID_7401,
            )?;
            map.insert(new_did.clone(), old_did);
            Ok::<(), JsValue>(())
        })?;

        Ok(JsValue::from(WasmIdentity {
            did: new_did,
            custody_type: custody,
            has_agent_key: had_agent_key,
            agent_public_key_multibase,
            // Migration generates a fresh identity key, so the new DID and
            // verifying_key match `pub_bytes` above.
            verifying_key_hex: Some(hex::encode(pub_bytes)),
        }))
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

            let signing_key = ed25519_dalek::SigningKey::from_bytes(&entry.signing_key_bytes);
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
        // clone private key material out.
        let pub_key_bytes = IDENTITY_REGISTRY.with(|reg| {
            let map = reg.borrow();
            map.get(&did).map(|entry| entry.public_key_bytes)
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
                map.get(&did).map_or_else(
                    || ("js_custody".to_owned(), false, None, None),
                    |entry| {
                        let has_agent = entry.agent_signing_key_bytes.is_some();
                        let agent_pub = if has_agent {
                            // Derive public key from agent signing key for the multibase field.
                            entry.agent_signing_key_bytes.as_ref().map(|sk_bytes| {
                                let sk = ed25519_dalek::SigningKey::from_bytes(sk_bytes);
                                let pk = ed25519_dalek::VerifyingKey::from(&sk);
                                format!("z{}", zbase32_encode(&pk.to_bytes()))
                            })
                        } else {
                            None
                        };
                        (
                            entry.custody_type.clone(),
                            has_agent,
                            agent_pub,
                            Some(hex::encode(entry.public_key_bytes)),
                        )
                    },
                )
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
/// without exposing the `IdentityEntry` struct or `IDENTITY_REGISTRY`.
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

        let key_bytes: &[u8; 32] = match signing_key_id {
            "#active" => &entry.signing_key_bytes,
            "#agent" => entry.agent_signing_key_bytes.as_deref().ok_or_else(|| {
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

        // Sign inside the registry closure.
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

            let signing_key = ed25519_dalek::SigningKey::from_bytes(&entry.signing_key_bytes);
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
    pub fn register_identity_with_agent_key()
    -> (String, ed25519_dalek::SigningKey, ed25519_dalek::SigningKey) {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let did = format!("did:dht:z{}", zbase32_encode(&pub_bytes));

        let agent_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

        IDENTITY_REGISTRY.with(|reg| {
            reg.borrow_mut().insert(
                did.clone(),
                IdentityEntry {
                    signing_key_bytes: zeroize::Zeroizing::new(signing_key.to_bytes()),
                    public_key_bytes: pub_bytes,
                    custody_type: "in_memory".to_owned(),
                    agent_signing_key_bytes: Some(zeroize::Zeroizing::new(agent_key.to_bytes())),
                },
            );
        });
        (did, signing_key, agent_key)
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
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// Helper: generate an Ed25519 keypair and register it in `IDENTITY_REGISTRY`.
    /// Returns `(did, public_key_bytes)`.
    fn register_identity() -> (String, [u8; 32]) {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let did = format!("did:dht:z{}", zbase32_encode(&pub_bytes));
        IDENTITY_REGISTRY.with(|reg| {
            reg.borrow_mut().insert(
                did.clone(),
                IdentityEntry {
                    signing_key_bytes: zeroize::Zeroizing::new(signing_key.to_bytes()),
                    public_key_bytes: pub_bytes,
                    custody_type: "in_memory".to_owned(),
                    agent_signing_key_bytes: None,
                },
            );
        });
        (did, pub_bytes)
    }

    /// Helper: generate an Ed25519 keypair and register it with an agent key
    /// in `IDENTITY_REGISTRY`. Returns `(did, identity_pub_bytes, agent_pub_bytes)`.
    fn register_identity_with_agent() -> (String, [u8; 32], [u8; 32]) {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let did = format!("did:dht:z{}", zbase32_encode(&pub_bytes));

        let agent_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let agent_pub_bytes = agent_key.verifying_key().to_bytes();

        IDENTITY_REGISTRY.with(|reg| {
            reg.borrow_mut().insert(
                did.clone(),
                IdentityEntry {
                    signing_key_bytes: zeroize::Zeroizing::new(signing_key.to_bytes()),
                    public_key_bytes: pub_bytes,
                    custody_type: "in_memory".to_owned(),
                    agent_signing_key_bytes: Some(zeroize::Zeroizing::new(agent_key.to_bytes())),
                },
            );
        });
        (did, pub_bytes, agent_pub_bytes)
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

        let (did, pub_bytes) = register_identity();
        let expected_multibase = format!("z{}", zbase32_encode(&pub_bytes));

        let fields = resolve_did_document_fields(&did);

        // Verification methods: #0 (identity) and #active (signing).
        let vms: Vec<serde_json::Value> =
            serde_json::from_str(&fields.verification_methods_json).unwrap();
        assert_eq!(vms.len(), 2, "should have #0 and #active VMs");

        // #0 — Identity Key
        assert_eq!(vms[0]["id"], format!("{did}#0"));
        assert_eq!(vms[0]["type"], "Ed25519VerificationKey2020");
        assert_eq!(vms[0]["controller"], did);
        assert_eq!(vms[0]["publicKeyMultibase"], expected_multibase);

        // #active — Active Signing Key (same key material in simplified model)
        assert_eq!(vms[1]["id"], format!("{did}#active"));
        assert_eq!(vms[1]["type"], "Ed25519VerificationKey2020");
        assert_eq!(vms[1]["controller"], did);
        assert_eq!(vms[1]["publicKeyMultibase"], expected_multibase);

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

        // Services always empty for locally-created identities.
        assert_eq!(fields.services_json, "[]");

        cleanup_registries();
    }

    #[test]
    fn test_resolve_with_agent_key() {
        cleanup_registries();

        let (did, pub_bytes, agent_pub_bytes) = register_identity_with_agent();
        let identity_multibase = format!("z{}", zbase32_encode(&pub_bytes));
        let agent_multibase = format!("z{}", zbase32_encode(&agent_pub_bytes));

        let fields = resolve_did_document_fields(&did);

        // Verification methods: #0, #active, and #agent.
        let vms: Vec<serde_json::Value> =
            serde_json::from_str(&fields.verification_methods_json).unwrap();
        assert_eq!(vms.len(), 3, "should have #0, #active, and #agent VMs");

        // #0 — Identity Key
        assert_eq!(vms[0]["id"], format!("{did}#0"));
        assert_eq!(vms[0]["publicKeyMultibase"], identity_multibase);

        // #active — Active Signing Key
        assert_eq!(vms[1]["id"], format!("{did}#active"));
        assert_eq!(vms[1]["publicKeyMultibase"], identity_multibase);

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

        let (did, _pub_bytes) = register_identity();
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
}
