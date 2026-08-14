//! `#[napi] Scp` class — the caller-owned SCP instance exposed to TypeScript.
//!
//! `SCP` (exposed to TS as `SCP`) is the top-level SDK-facing handle that
//! owns a `NapiBridgeInstance` — which in turn owns the `Supervisor`,
//! transport, and bridge-specific registries.
//!
//! Phase 4 PR 4 (#1549, ADR-048) completed the migration: the
//! free-function façade and the process-wide default bridge that
//! backed it were deleted. Every entry point now flows through a
//! caller-owned `Scp` whose handles are stamped with its
//! `instance_id`, and cross-instance handle misuse is rejected by the
//! inline `CoreFields::check_handle` call.
//!
//! See #1549 Phase 4 remainder plan and ADR-048.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use napi::Env;
use napi::Error as NapiError;
use napi_derive::napi;
use scp_ffi_common::bridge_instance::BridgeInstanceCore as _;
use scp_ffi_common::error_codes as codes;
use scp_identity::DidMethod as _;

// `Buffer` is used unconditionally by the §5.4.5 streaming-outlet pure-wrapper
// methods (`outletStreamVerifyChunkSignature` /
// `outletStreamComputeCaveatsBinding` / `outletStreamPollNext`) as well as the
// in-memory-custody-gated full-stack test methods; production `identity_create`
// uses the fully-qualified path for its `testing_seed` arg.
use napi::bindgen_prelude::Buffer;

use crate::context::{
    NapiAssetEntry, NapiBatchPublishResult, NapiContextHandle, NapiEvaluationResult,
    NapiInviteMemberOutcome, NapiKeyPackageReservation, NapiMessage, NapiPublishResult,
    NapiSealedInvitation,
};
use crate::error::{ScpNapiError, validate_custody_type};
use crate::event_log::{NapiCheckpoint, NapiEvent, NapiProof};
use crate::identity::NapiIdentity;
use crate::mcp::{
    NapiAllowlistState, NapiMcpClientHandle, NapiMcpInvokeResult, NapiMcpServerConfig,
    NapiMcpServerHandle, NapiMcpToolInfo,
};
use crate::outlets::{NapiOutletDefinition, NapiOutletVerificationResult};
use crate::runtime::{NapiBridgeInstance, SqliteKeyMaterial, StorageConfig};
#[cfg(feature = "server")]
use crate::server::{NapiNodeHandle, NapiRelayHandle};
use crate::sync::NapiSyncPolicy;
#[cfg(feature = "testing")]
use crate::testing::NapiFullStackNode;
use crate::transport::{NapiReliabilityScore, NapiTransportManager, NapiTransportStatus};
use crate::trust::{NapiAttestationVerificationResult, NapiChallengeResult, NapiTrustScoreResult};
use crate::ucan::NapiUcanToken;

/// The SCP instance — a caller-owned handle that wraps a
/// `NapiBridgeInstance`.
///
/// # JS usage
///
/// ```js
/// import { SCP } from '@limn-works/scp-ts-napi';
///
/// // Storage selection is required — there is no default (spec §17.6).
/// const scp = new SCP('{"type":"in_memory"}'); // explicit dev/test storage
/// await scp.shutdown(5n);                       // async graceful shutdown
/// ```
///
/// Phase 4 PR 4 (#1549, ADR-048) removed `SCP.default()` along with the
/// process-wide default-instance fallback; every caller must construct
/// an `SCP` explicitly and route handles through it.
//
// CodeQL note (rust/access-invalid-pointer, alert #425 — false positive):
// The `#[napi]` macro generates `FromNapiRef`/`FromNapiMutRef` impls that call
// `napi_unwrap` to recover the boxed Rust value from a JS object, then
// dereference the resulting `*mut c_void` as `*const Scp` / `*mut Scp`.
// CodeQL flags this as an invalid-pointer deref. It is safe by construction:
// `ToNapiValue` boxes the `Scp` via `Box::into_raw` and registers a
// finalizer (`ObjectFinalize`) with N-API. The pointer is non-null,
// well-aligned, and live for as long as the JS object is reachable —
// standard napi-rs class plumbing. The identical pattern is used by 10
// other `#[napi]` structs in this crate (NapiContextHandle, NapiIdentity,
// NapiMcpServerHandle, NapiMcpClientHandle, NapiTransportManager,
// NapiUcanToken, NapiRelayHandle, NapiNodeHandle, NapiFullStackNode, Scp)
// and has been repeatedly dismissed as a false positive (prior alerts
// #99, #100, #101, #102, #103, #104, #263, #264, #265, #266).
#[napi(js_name = "SCP")]
pub struct Scp {
    /// The underlying per-bridge concrete instance.
    pub(crate) inner: Arc<NapiBridgeInstance>,
}

#[napi]
impl Scp {
    /// Constructs a fresh `SCP` instance from a JSON storage-config string.
    ///
    /// Storage selection is MANDATORY and fail-closed (spec §17.6): the
    /// `config_json` argument is required (TypeScript / Bun callers must
    /// pass it), and there is no default backend. This routes to the same
    /// fail-closed parser as [`Self::with_storage`]; passing a config whose
    /// `type` is missing or unrecognised is a `ValidationError`
    /// (`SCP-STORAGE-8000` for the missing-selection case).
    ///
    /// Accepted shapes (see [`Self::with_storage`] for the full contract):
    /// - `{"type":"in_memory"}` — encrypted in-memory storage (dev/test only).
    /// - `{"type":"sqlite","path":...,"key"|"passphrase":...}` —
    ///   SQLCipher-encrypted storage (production).
    #[napi(constructor)]
    pub fn new(config_json: String) -> napi::Result<Self> {
        Self::with_storage(config_json)
    }

    /// Constructs an `SCP` instance with a storage configuration.
    ///
    /// Accepted shapes:
    /// - `{"type":"in_memory"}` — encrypted in-memory storage (ephemeral).
    /// - `{"type":"sqlite","path":"/dir","key":"<hex>"|[..]}` —
    ///   SQLCipher-encrypted storage at `{path}/scp.db` keyed by raw
    ///   encryption key material (`key` as a hex string or a JSON byte array).
    /// - `{"type":"sqlite","path":"/dir","passphrase":"..."}` —
    ///   SQLCipher-encrypted storage whose key is derived from a passphrase via
    ///   Argon2id (spec §17.6).
    ///
    /// For the `sqlite` type, exactly ONE of `key` or `passphrase` must be
    /// supplied — providing both, or neither, is a `ValidationError`
    /// (`SCP-VALID-7005`).
    ///
    /// Accepts a JSON-encoded string so the API remains stable while the
    /// `StorageConfig` surface evolves (napi-rs has no stable derive for
    /// untyped JSON values). Unknown variants are rejected with
    /// `SCP-VALID-7005`. A failed `SQLCipher` open (bad key/passphrase,
    /// permission denied, corrupt file, salt-sidecar fail-closed) also raises
    /// `ValidationError` — the factory FAILS CLOSED (spec §17.6) and never
    /// silently degrades to in-memory.
    #[napi(factory, js_name = "withStorage")]
    pub fn with_storage(config_json: String) -> napi::Result<Self> {
        let config: serde_json::Value = serde_json::from_str(&config_json).map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!("storage config is not valid JSON: {e}"),
                code: codes::VALID_7005.to_owned(),
            })
        })?;
        let config_obj = config.as_object().ok_or_else(|| {
            napi::Error::from(ScpNapiError::Validation {
                message: "storage config must be a JSON object".to_owned(),
                code: codes::VALID_7005.to_owned(),
            })
        })?;
        // Storage selection is MANDATORY (spec §17.6): a missing `type` is
        // not a silent in-memory default — it is `SCP-STORAGE-8000`.
        let ty = config_obj
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                napi::Error::from(ScpNapiError::Validation {
                    message: "storage selection is required: missing 'type' — expected \
                              {\"type\":\"in_memory\"} (development) or \
                              {\"type\":\"sqlite\",\"path\":...,\"key\"|\"passphrase\":...} \
                              (production). There is no default storage."
                        .to_owned(),
                    code: codes::STORAGE_8000.to_owned(),
                })
            })?;
        let storage = match ty {
            "in_memory" => StorageConfig::InMemory,
            "sqlite" => {
                let path_str = config_obj
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        napi::Error::from(ScpNapiError::Validation {
                            message:
                                "withStorage(sqlite): missing required field 'path' (directory for scp.db)"
                                    .to_owned(),
                            code: codes::VALID_7005.to_owned(),
                        })
                    })?
                    .to_owned();
                // Defense-in-depth: validate path string at FFI boundary
                // (matches the project pattern for every other caller-supplied
                // string). #1543 PR-C security review.
                scp_ffi_common::validate::validate_storage_path(&path_str).map_err(|e| {
                    napi::Error::from(ScpNapiError::Validation {
                        message: format!("withStorage(sqlite): invalid 'path' — {}", e.message),
                        code: codes::VALID_7005.to_owned(),
                    })
                })?;
                // Exactly one of `key` (raw bytes: hex string OR byte array)
                // or `passphrase` (string) must be supplied — the
                // SqliteKeyMaterial sum type enforces mutual exclusion at the
                // type level; here we enforce it at the JSON boundary (spec
                // §17.6). The passphrase is moved into Zeroizing immediately so
                // it never lingers in an un-wiped String.
                let key_item = config_obj.get("key");
                let passphrase_item = config_obj.get("passphrase");
                let key_material = match (key_item, passphrase_item) {
                    (Some(_), Some(_)) => {
                        return Err(napi::Error::from(ScpNapiError::Validation {
                            message: "withStorage(sqlite): supply exactly one of 'key' or 'passphrase', not both".to_owned(),
                            code: codes::VALID_7005.to_owned(),
                        }));
                    }
                    (None, None) => {
                        return Err(napi::Error::from(ScpNapiError::Validation {
                            message: "withStorage(sqlite): missing key material — supply either 'key' (hex string or byte array) or 'passphrase' (string)".to_owned(),
                            code: codes::VALID_7005.to_owned(),
                        }));
                    }
                    (Some(key_val), None) => {
                        // `key` is accepted either as a hex-encoded string (most
                        // common from JS/TS where JSON has no native bytes type)
                        // or as a JSON array of byte values.
                        let key_bytes: Vec<u8> = match key_val {
                            serde_json::Value::String(hex_str) => hex::decode(hex_str)
                                .map_err(|e| {
                                    napi::Error::from(ScpNapiError::Validation {
                                        message: format!(
                                            "withStorage(sqlite): 'key' is not valid hex: {e}"
                                        ),
                                        code: codes::VALID_7005.to_owned(),
                                    })
                                })?,
                            serde_json::Value::Array(arr) => arr
                                .iter()
                                .map(|v| {
                                    v.as_u64().and_then(|n| u8::try_from(n).ok()).ok_or_else(|| {
                                        napi::Error::from(ScpNapiError::Validation {
                                            message: "withStorage(sqlite): 'key' array must contain byte values (0-255)".to_owned(),
                                            code: codes::VALID_7005.to_owned(),
                                        })
                                    })
                                })
                                .collect::<Result<Vec<u8>, _>>()?,
                            _ => {
                                return Err(napi::Error::from(ScpNapiError::Validation {
                                    message: "withStorage(sqlite): wrongly-typed 'key' (expected hex string or byte array)".to_owned(),
                                    code: codes::VALID_7005.to_owned(),
                                }));
                            }
                        };
                        SqliteKeyMaterial::Raw(zeroize::Zeroizing::new(key_bytes))
                    }
                    (None, Some(pass_val)) => {
                        let passphrase = pass_val.as_str().ok_or_else(|| {
                            napi::Error::from(ScpNapiError::Validation {
                                message: "withStorage(sqlite): 'passphrase' must be a string"
                                    .to_owned(),
                                code: codes::VALID_7005.to_owned(),
                            })
                        })?;
                        SqliteKeyMaterial::Passphrase(zeroize::Zeroizing::new(
                            passphrase.to_owned(),
                        ))
                    }
                };
                StorageConfig::Sqlite {
                    path: std::path::PathBuf::from(path_str),
                    key: key_material,
                }
            }
            other => {
                // An unknown `type` value is a STORAGE-SELECTION error, not a
                // within-variant field validation — surface the same selection
                // code as a missing `type` (spec §17.6, `SCP-STORAGE-8000`).
                return Err(napi::Error::from(ScpNapiError::Validation {
                    message: format!(
                        "unknown storage selection: type {other:?} is not a valid backend — pass type \"in_memory\" (development) or \"sqlite\" (production). There is no default storage."
                    ),
                    code: codes::STORAGE_8000.to_owned(),
                }));
            }
        };
        // FAIL CLOSED (spec §17.6): a failed durable-backend open surfaces as a
        // JS-thrown ValidationError rather than a silent in-memory fallback.
        let bi = NapiBridgeInstance::with_storage_napi(storage).map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: e.to_string(),
                code: codes::VALID_7005.to_owned(),
            })
        })?;
        Ok(Self {
            inner: Arc::new(bi),
        })
    }

    /// Suspends this bridge instance (mobile backgrounding).
    ///
    /// Disconnects transport and flushes context snapshots. Transport-
    /// dependent operations fail until `resume()` is called.
    #[napi]
    pub fn suspend(&self) -> napi::Result<()> {
        self.inner.core.suspend().map_err(|e| {
            napi::Error::from(ScpNapiError::Transport {
                message: format!("suspend failed: {e}"),
                code: codes::TRANS_5001.to_owned(),
            })
        })
    }

    /// Resumes a suspended bridge instance.
    ///
    /// Clears the suspended flag, then runs the async work in the
    /// `BridgeInstanceCore::resume` default body (transport reconnect
    /// from pending relay URLs, persisted-context restoration).
    #[napi]
    pub async fn resume(&self) -> napi::Result<()> {
        use scp_ffi_common::bridge_instance::BridgeInstanceCore as _;
        self.inner.resume().await.map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("resume failed: {e}"),
                code: codes::CTX_2000.to_owned(),
            })
        })
    }

    /// Shuts down this bridge instance with a graceful deadline.
    ///
    /// Awaits in-flight tasks up to `timeout_millis` **milliseconds**,
    /// aborts any remaining tasks, then clears registries and runs
    /// shutdown hooks. Permanent — a shut-down instance cannot be reused.
    ///
    /// The unit is **milliseconds** — unified across all Rust bridges.
    /// The width is `u64` so the NAPI / `UniFFI` / `PyO3` bridges share
    /// a single canonical shutdown-timeout surface (#1692). NAPI
    /// exposes `u64` as JS `BigInt` on the wire — TypeScript callers
    /// must pass a `bigint` (`shutdown(5000n)`). Negative /
    /// out-of-range values saturate at `u64::MAX` per `BigInt::get_u64`
    /// semantics (last tuple element flags lossless conversion, which
    /// we intentionally ignore — any bigint beyond `u64::MAX` is
    /// clamped to "effectively unbounded").
    #[napi]
    pub async fn shutdown(
        &self,
        timeout_millis: napi::bindgen_prelude::BigInt,
    ) -> napi::Result<()> {
        let (_sign, value, _lossless) = timeout_millis.get_u64();
        let timeout = Duration::from_millis(value);
        match self.inner.shutdown(timeout).await {
            Ok(_) => Ok(()),
            // `AlreadyShutDown` is treated as a harmless lifecycle
            // observation — double-shutdown is idempotent at the SDK
            // surface.
            Err(_already) => Ok(()),
        }
    }

    /// Returns the instance id as a base-10 string.
    ///
    /// u64 is serialized as a string so it survives crossing the
    /// JavaScript number boundary (which only exposes f64's 53-bit
    /// mantissa). The id is monotonic and unique per instance within a
    /// single process.
    #[napi(getter, js_name = "instanceId")]
    #[must_use]
    pub fn instance_id(&self) -> String {
        self.inner.instance_id().to_string()
    }

    // ====================================================================
    // #1549 Phase 4 PR 4 — sub-slice B: identity operations on SCP.
    //
    // Hosts the `identity_*` instance methods on [`Scp`] routed through
    // `&*self.inner`. The free-function façade that these methods
    // superseded was deleted in the Phase 4 PR 4 demolition slice along
    // with the process-wide default bridge it operated on (ADR-048).
    // ====================================================================

    /// Per-instance equivalent of the free-function `identity_create`.
    ///
    /// Creates a new DID identity under this SCP instance, routing through
    /// `&*self.inner`. Key material, registry writes, and the DID
    /// resolver are all scoped to this `SCP`.
    ///
    /// When `testing_seed` is supplied (32 bytes), the in-memory custody
    /// is backed by a deterministic RNG so subsequent `generate_keypair`
    /// calls produce byte-identical Ed25519 keys across bridges — the
    /// basis of the cross-bridge parity test (ADR-046). `testing_seed` is
    /// only valid for `"in_memory"` custody; other custody types reject
    /// it with `SCP-VALID-7009`.
    #[napi(js_name = "identityCreate")]
    // napi-rs requires `async` for the Promise return type. Without the
    // in-memory-custody backend the only `.await` (the `"in_memory"` arm) is
    // compiled out, so the bare build sees an await-free async fn.
    #[cfg_attr(not(feature = "testing"), allow(clippy::unused_async))]
    pub async fn identity_create(
        &self,
        custody: String,
        testing_seed: Option<napi::bindgen_prelude::Buffer>,
    ) -> napi::Result<crate::identity::NapiIdentity> {
        #[cfg(feature = "testing")]
        use crate::identity::NapiIdentityInner;
        use crate::identity::ensure_did_resolver_initialized_on;

        validate_custody_type(&custody).map_err(NapiError::from)?;

        // Validate the optional 32-byte `testing_seed` at the FFI boundary
        // so we fail early rather than panicking in
        // `InMemoryKeyCustody::from_seed_bytes`. A length mismatch is
        // `SCP-VALID-7007`; a seed paired with a non-InMemory custody
        // surfaces later as `SCP-VALID-7009`. The seed bytes feed
        // `Ed25519 SigningKey::from_bytes` inside the custody's RNG, so
        // we wrap the narrowed `[u8; 32]` in `Zeroizing` immediately to
        // wipe them when dropped rather than leaving them on the stack.
        //
        // The `Buffer` argument is backed by a V8 `ArrayBuffer` owned by
        // the JS side — its memory is not ours to mutate and is held by
        // the JS GC until the caller drops their reference. To keep the
        // Rust side clean we copy to an owned `Vec<u8>`, narrow, then
        // `zeroize` the owned copy before it drops (bug-catcher +
        // security round 2). JS callers are responsible for zeroing
        // their own `Uint8Array` after calling — the SDK wrapper
        // documents this requirement.
        let testing_seed_bytes: Option<zeroize::Zeroizing<[u8; 32]>> = match testing_seed {
            None => None,
            Some(buf) => {
                let mut owned: Vec<u8> = buf.as_ref().to_vec();
                let narrowed =
                    scp_ffi_common::validate::expect_fixed_bytes::<32>(&owned, "testing_seed")
                        .map_err(|message| {
                            NapiError::from(ScpNapiError::Validation {
                                message,
                                code: codes::VALID_7007.to_owned(),
                            })
                        })?;
                use zeroize::Zeroize;
                owned.zeroize();
                Some(zeroize::Zeroizing::new(narrowed))
            }
        };

        let bi = &*self.inner;
        ensure_did_resolver_initialized_on(bi).map_err(NapiError::from)?;

        match custody.as_str() {
            #[cfg(feature = "testing")]
            "in_memory" => {
                use scp_platform::testing::InMemoryKeyCustody;

                // Deref through `Zeroizing<[u8; 32]>` so the wrapper
                // drops (and wipes) at the end of this scope. The inner
                // `[u8; 32]` is consumed by value by `from_seed_bytes`
                // (one unavoidable Copy) and then discarded inside
                // `StdRng::from_seed`.
                let in_memory = testing_seed_bytes
                    .as_ref()
                    .map_or_else(InMemoryKeyCustody::new, |seed| {
                        InMemoryKeyCustody::from_seed_bytes(**seed)
                    });
                let key_custody = Arc::new(crate::custody::NapiKeyCustody::InMemory(
                    crate::identity::OpaqueInMemoryKeyCustody(in_memory),
                ));
                let pre_rotation_custody =
                    Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
                let dht = crate::identity::shared_did_method()?;
                let (scp_identity, document, pre_rotation_handle) = dht
                    .create(&*key_custody, pre_rotation_custody.as_ref())
                    .await
                    .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

                let verifying_key_hex = crate::identity::identity_verifying_key_hex(
                    &key_custody,
                    &scp_identity.identity_key,
                )
                .await;

                crate::runtime::register_identity(
                    bi,
                    &scp_identity.did,
                    crate::runtime::NapiIdentityEntry {
                        identity: scp_identity.clone(),
                        custody: Arc::clone(&key_custody),
                        document: document.clone(),
                        identity_link_attestations: Vec::new(),
                        pre_rotation_handle,
                        pre_rotation_custody,
                    },
                );

                crate::identity::publish_to_shared_dht_for(&scp_identity, &document, &key_custody)
                    .await;

                let handle = crate::identity::NapiIdentity {
                    inner: Arc::new(NapiIdentityInner {
                        did: scp_identity.did.clone(),
                        custody_type: "in_memory".to_owned(),
                        scp_identity: Some(scp_identity),
                        in_memory_custody: Some(key_custody),
                        document: Some(document),
                        bi: Arc::clone(&self.inner),
                        verifying_key_hex,
                        instance_id: bi.instance_id(),
                        rotation_event_json: None,
                    }),
                };
                crate::increment_handle_count();
                Ok(handle)
            }
            #[cfg(not(feature = "testing"))]
            "in_memory" => {
                // Mirrors PyO3 `parse_custody_with_seed`
                // (cfg(not(testing))): a `testing_seed` is
                // a parity-harness affordance gated on the
                // `testing` feature, so surface it as
                // SCP-VALID-7008 ("testing-only feature requires feature
                // flag") ahead of the generic custody-unavailable error.
                if testing_seed_bytes.is_some() {
                    return Err(NapiError::from(ScpNapiError::Validation {
                        message: "`testing_seed` parameter requires the testing feature".to_owned(),
                        code: codes::VALID_7008.to_owned(),
                    }));
                }
                Err(ScpNapiError::Identity {
                    message: "in_memory custody is not available in this build -- use \
                              \"software\" or \"platform\" custody for production key storage"
                        .to_owned(),
                    code: codes::IDENT_1008.to_owned(),
                }
                .into())
            }
            "platform" | "software" => {
                if testing_seed_bytes.is_some() {
                    return Err(NapiError::from(ScpNapiError::Validation {
                        message: "`testing_seed` parameter is only valid for custody=\"in_memory\""
                            .to_owned(),
                        code: codes::VALID_7009.to_owned(),
                    }));
                }
                Err(ScpNapiError::Identity {
                    message: format!(
                        "custody type {custody:?} requires a wired platform \
                         KeyCustodyProvider — use the KeyCustodyProvider callback \
                         interface to inject Secure Enclave (iOS) or Android \
                         Keystore (Android) backed custody"
                    ),
                    code: codes::IDENT_1003.to_owned(),
                }
                .into())
            }
            _ => Err(ScpNapiError::Identity {
                code: codes::IDENT_1005.to_owned(),
                message: format!(
                    "internal: unexpected custody type {custody:?} passed validate_custody_type — \
                     this is a bug in the bridge layer"
                ),
            }
            .into()),
        }
    }

    /// Per-instance equivalent of `identity_create_with_agent_key`.
    ///
    /// Same as [`Self::identity_create`] but the resulting identity also
    /// includes an `#agent` verification method in the DID document.
    #[napi(js_name = "identityCreateWithAgentKey")]
    // napi-rs requires `async` for the Promise return type. Without the
    // in-memory-custody backend the only `.await` (the `"in_memory"` arm) is
    // compiled out, so the bare build sees an await-free async fn.
    #[cfg_attr(not(feature = "testing"), allow(clippy::unused_async))]
    pub async fn identity_create_with_agent_key(
        &self,
        custody: String,
    ) -> napi::Result<crate::identity::NapiIdentity> {
        #[cfg(feature = "testing")]
        use crate::identity::NapiIdentityInner;
        use crate::identity::ensure_did_resolver_initialized_on;

        validate_custody_type(&custody).map_err(NapiError::from)?;

        let bi = &*self.inner;
        ensure_did_resolver_initialized_on(bi).map_err(NapiError::from)?;

        match custody.as_str() {
            #[cfg(feature = "testing")]
            "in_memory" => {
                use scp_platform::testing::InMemoryKeyCustody;

                let key_custody = Arc::new(crate::custody::NapiKeyCustody::InMemory(
                    crate::identity::OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()),
                ));
                let pre_rotation_custody =
                    Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
                let dht = crate::identity::shared_did_method()?;
                let (scp_identity, document, pre_rotation_handle) = dht
                    .create_with_agent_key(&*key_custody, pre_rotation_custody.as_ref())
                    .await
                    .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

                let verifying_key_hex = crate::identity::identity_verifying_key_hex(
                    &key_custody,
                    &scp_identity.identity_key,
                )
                .await;

                crate::runtime::register_identity(
                    bi,
                    &scp_identity.did,
                    crate::runtime::NapiIdentityEntry {
                        identity: scp_identity.clone(),
                        custody: Arc::clone(&key_custody),
                        document: document.clone(),
                        identity_link_attestations: Vec::new(),
                        pre_rotation_handle,
                        pre_rotation_custody,
                    },
                );

                crate::identity::publish_to_shared_dht_for(&scp_identity, &document, &key_custody)
                    .await;

                let handle = crate::identity::NapiIdentity {
                    inner: Arc::new(NapiIdentityInner {
                        did: scp_identity.did.clone(),
                        custody_type: "in_memory".to_owned(),
                        scp_identity: Some(scp_identity),
                        in_memory_custody: Some(key_custody),
                        document: Some(document),
                        bi: Arc::clone(&self.inner),
                        verifying_key_hex,
                        instance_id: bi.instance_id(),
                        rotation_event_json: None,
                    }),
                };
                crate::increment_handle_count();
                Ok(handle)
            }
            #[cfg(not(feature = "testing"))]
            "in_memory" => Err(ScpNapiError::Identity {
                message: "in_memory custody is not available in this build -- use \
                          \"software\" or \"platform\" custody for production key storage"
                    .to_owned(),
                code: codes::IDENT_1008.to_owned(),
            }
            .into()),
            "platform" | "software" => Err(ScpNapiError::Identity {
                message: format!(
                    "custody type {custody:?} requires a wired platform \
                     KeyCustodyProvider — use the KeyCustodyProvider callback \
                     interface to inject Secure Enclave (iOS) or Android \
                     Keystore (Android) backed custody"
                ),
                code: codes::IDENT_1003.to_owned(),
            }
            .into()),
            _ => Err(ScpNapiError::Identity {
                code: codes::IDENT_1005.to_owned(),
                message: format!(
                    "internal: unexpected custody type {custody:?} passed validate_custody_type — \
                     this is a bug in the bridge layer"
                ),
            }
            .into()),
        }
    }

    /// Creates a new DID identity whose key material lives in a caller-provided
    /// custody backend.
    ///
    /// `provider` is a JS object implementing the `KeyCustodyProvider` record
    /// (`generateKeypair`, `sign`, `getPublicKey`, `destroyKey`, `dhAgree`,
    /// `derivePseudonym`, `exportSigningKeyBytes`, `custodyType`). Sign,
    /// Diffie-Hellman, and pseudonym-derivation operations keep the private key
    /// inside the caller's custody — those keys are never imported into the Rust
    /// core (ADR-006); each such op is marshalled back to the Node.js event loop
    /// via threadsafe functions and awaited. The `exportSigningKeyBytes` callback
    /// is the exception: the `SigningKeyBytes`-based signing paths (UCAN mint,
    /// SCPID, event-log checkpoint, and the join-time pseudonym announcement)
    /// currently pull the raw 32-byte Ed25519 seed into Rust ownership, where it
    /// is held in `Zeroizing` for the duration of the operation and wiped on
    /// drop. That raw-export surface is tracked for migration to
    /// `KeyCustody::sign`; context export already signs via `KeyCustody::sign`
    /// (§23.16.8) and never exports the raw seed. This is the Node/Bun equivalent
    /// of the `UniFFI` bridge's `identity_create_with_custody`, used to back a DID
    /// with an OS keychain, hardware token, or HSM wrapper.
    ///
    /// The callbacks run on the JS thread; the pre-rotation seed is generated
    /// locally (it never traverses the consumer callbacks), per ADR-006.
    #[napi(
        js_name = "identityCreateWithCustody",
        ts_return_type = "Promise<NapiIdentity>"
    )]
    pub fn identity_create_with_custody<'env>(
        &self,
        env: &'env Env,
        provider: crate::custody::NapiKeyCustodyProvider,
    ) -> napi::Result<napi::bindgen_prelude::PromiseRaw<'env, crate::identity::NapiIdentity>> {
        // SYNC entry point. The JS `Function` fields on `provider` are not
        // `Send`, so they MUST be promoted to `ThreadsafeFunction`s on the JS
        // thread (here), before any work crosses to a tokio worker. We then
        // hand the resulting `Send` custody to `Env::spawn_future`, which runs
        // the async DID-creation on the tokio runtime and resolves the JS
        // Promise on the event loop — leaving the loop free to service the
        // custody callbacks the creation flow invokes. (An `async fn` taking
        // the `Function`s directly cannot compile: its future would capture
        // the non-`Send` callbacks.)
        //
        // This is a PRODUCTION path (not feature-gated): the identity registry
        // retains the caller's callback custody so later signing / event-log /
        // SCPID operations reach it, mirroring the PyO3 reference bridge. The
        // cold-storage `InMemoryPreRotationCustody` is a separate substrate for
        // the pre-rotation key only (ADR-003 §4b). Sign / Diffie-Hellman /
        // pseudonym-derivation operations keep the caller's private keys in
        // custody (never imported into Rust) per ADR-006; the
        // `SigningKeyBytes`-based paths (UCAN mint, SCPID, event-log checkpoint,
        // join-time pseudonym announcement) are the exception — they export the
        // raw seed into Rust (held in `Zeroizing`, wiped on drop), a surface
        // tracked for migration to `KeyCustody::sign`.

        // `NapiIdentityInner` is only named in the `testing`-gated success arm
        // below; the shipped build fails closed before minting a handle
        // (ADR-062 §Decision 6).
        #[cfg(feature = "testing")]
        use crate::identity::NapiIdentityInner;
        use crate::identity::ensure_did_resolver_initialized_on;

        let bi_arc = Arc::clone(&self.inner);
        ensure_did_resolver_initialized_on(&bi_arc).map_err(NapiError::from)?;

        // Promote the JS callbacks to threadsafe functions on the JS
        // thread (consuming the non-Send `Function`s). A malformed
        // provider fails fast here, before any DID-creation work.
        let callback = crate::custody::NapiCallbackKeyCustody::from_provider(provider)?;
        let key_custody = Arc::new(crate::custody::NapiKeyCustody::Callback(callback));

        env.spawn_future(async move {
            // FAIL CLOSED on a shipped (no-`testing`) build (ADR-062 §Decision
            // 6, IDENT_1059). This callback-custody path funnels through the
            // same mandatory pre-rotation commitment as every other create path
            // (spec §9.7.4.1 §3); the only `PreRotationCustody` backend is the
            // severed in-memory nullifier, so production returns a typed error
            // rather than minting it. Mirrors the `PyO3` reference bridge.
            #[cfg(not(feature = "testing"))]
            {
                let _ = (&bi_arc, &key_custody);
                Err::<crate::identity::NapiIdentity, NapiError>(NapiError::from(
                    crate::identity::no_pre_rotation_backend(),
                ))
            }
            #[cfg(feature = "testing")]
            {
                let bi = &*bi_arc;
                let pre_rotation_custody =
                    Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
                let dht = crate::identity::shared_did_method()?;
                let (scp_identity, document, pre_rotation_handle) = dht
                    .create(&*key_custody, pre_rotation_custody.as_ref())
                    .await
                    .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

                let verifying_key_hex = crate::identity::identity_verifying_key_hex(
                    &key_custody,
                    &scp_identity.identity_key,
                )
                .await;

                crate::runtime::register_identity(
                    bi,
                    &scp_identity.did,
                    crate::runtime::NapiIdentityEntry {
                        identity: scp_identity.clone(),
                        custody: Arc::clone(&key_custody),
                        document: document.clone(),
                        identity_link_attestations: Vec::new(),
                        pre_rotation_handle,
                        pre_rotation_custody,
                    },
                );

                crate::identity::publish_to_shared_dht_for(&scp_identity, &document, &key_custody)
                    .await;

                let handle = crate::identity::NapiIdentity {
                    inner: Arc::new(NapiIdentityInner {
                        did: scp_identity.did.clone(),
                        custody_type: "callback".to_owned(),
                        scp_identity: Some(scp_identity),
                        in_memory_custody: Some(key_custody),
                        document: Some(document),
                        bi: Arc::clone(&bi_arc),
                        verifying_key_hex,
                        instance_id: bi.instance_id(),
                        rotation_event_json: None,
                    }),
                };
                crate::increment_handle_count();
                Ok(handle)
            }
        })
    }

    /// Per-instance equivalent of `identity_load`.
    ///
    /// Looks the DID up in this instance's identity registry first; falls
    /// back to DHT resolution.
    #[napi(js_name = "identityLoad")]
    pub async fn identity_load(&self, did: String) -> napi::Result<crate::identity::NapiIdentity> {
        use crate::identity::NapiIdentityInner;

        if !did.starts_with("did:dht:") {
            return Err(ScpNapiError::Identity {
                message: format!("unsupported DID method: {did} — only did:dht is supported"),
                code: codes::IDENT_1004.to_owned(),
            }
            .into());
        }

        let bi = &*self.inner;

        // Look the DID up in this instance's identity registry first. Hits for
        // any locally created identity — in-memory or production callback
        // custody — before falling back to DHT resolution.
        let local_result = crate::runtime::with_identity(bi, &did, |entry| {
            Ok((
                entry.identity.clone(),
                Arc::clone(&entry.custody),
                entry.document.clone(),
            ))
        });

        if let Ok((identity, custody, document)) = local_result {
            let custody_type = custody.custody_type_label().to_owned();
            let verifying_key_hex =
                crate::identity::identity_verifying_key_hex(&custody, &identity.identity_key).await;
            let handle = crate::identity::NapiIdentity {
                inner: Arc::new(NapiIdentityInner {
                    did,
                    custody_type,
                    scp_identity: Some(identity),
                    in_memory_custody: Some(custody),
                    document: Some(document),
                    bi: Arc::clone(&self.inner),
                    verifying_key_hex,
                    instance_id: bi.instance_id(),
                    rotation_event_json: None,
                }),
            };
            crate::increment_handle_count();
            return Ok(handle);
        }

        let dht = crate::identity::shared_did_method()?;
        let document = dht
            .resolve(&did)
            .await
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

        let handle = crate::identity::NapiIdentity {
            inner: Arc::new(NapiIdentityInner {
                did,
                custody_type: "external".to_owned(),
                scp_identity: None,
                in_memory_custody: None,
                document: Some(document),
                bi: Arc::clone(&self.inner),
                verifying_key_hex: None,
                instance_id: bi.instance_id(),
                rotation_event_json: None,
            }),
        };
        crate::increment_handle_count();
        Ok(handle)
    }

    /// Per-instance equivalent of `identity_resolve`.
    #[napi(js_name = "identityResolve")]
    pub async fn identity_resolve(
        &self,
        did: String,
    ) -> napi::Result<crate::identity::NapiDIDDocument> {
        use crate::identity::NapiVerificationMethod;

        if !did.starts_with("did:dht:") {
            return Err(ScpNapiError::Identity {
                message: format!("unsupported DID method: {did} — only did:dht is supported"),
                code: codes::IDENT_1004.to_owned(),
            }
            .into());
        }

        let bi = &*self.inner;

        let local_doc =
            crate::runtime::with_identity(bi, &did, |entry| Ok(entry.document.clone())).ok();

        let document = if let Some(doc) = local_doc {
            doc
        } else {
            let dht = crate::identity::shared_did_method()?;
            dht.resolve(&did)
                .await
                .map_err(|e| NapiError::from(ScpNapiError::from(e)))?
        };

        let has_agent_key = document.has_agent_key();
        let agent_public_key = document
            .agent_verification_method()
            .map(|vm| vm.public_key_multibase.clone());

        let verification_methods = document
            .verification_method
            .iter()
            .map(|vm| NapiVerificationMethod {
                id: vm.id.clone(),
                method_type: vm.method_type.clone(),
                controller: vm.controller.clone(),
                public_key_multibase: vm.public_key_multibase.clone(),
            })
            .collect();

        Ok(crate::identity::NapiDIDDocument {
            id: document.id.clone(),
            verification_methods,
            authentication: document.authentication.clone(),
            assertion_methods: document.assertion_method.clone(),
            also_known_as: document.also_known_as.clone(),
            service_endpoints: document
                .service
                .iter()
                .map(|s| s.service_endpoint.clone())
                .collect(),
            has_agent_key,
            agent_public_key,
        })
    }

    /// Per-instance equivalent of `identity_create_link_attestation`.
    #[napi(js_name = "identityCreateLinkAttestation")]
    #[allow(clippy::unused_async)] // napi-rs requires async for Promise return
    pub async fn identity_create_link_attestation(
        &self,
        did: String,
        platform: String,
        handle: String,
        proof: String,
        verification_method: String,
        platform_id: Option<String>,
    ) -> napi::Result<String> {
        use scp_ffi_common::validate::MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID;
        use scp_platform::traits::KeyCustody as _;

        scp_ffi_common::validate::validate_attestation_fields(&platform, &handle, &proof)
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

        let bi = &*self.inner;

        let (custody, key_handle) = crate::runtime::with_identity(bi, &did, |entry| {
            Ok((
                Arc::clone(&entry.custody),
                entry.identity.active_signing_key,
            ))
        })?;

        let built = scp_ffi_common::attestation::build_unsigned_attestation(
            &did,
            platform,
            handle,
            proof,
            &verification_method,
            platform_id,
        )
        .map_err(|e| {
            let code = match &e {
                scp_ffi_common::attestation::AttestationBuildError::InvalidMethod(_)
                | scp_ffi_common::attestation::AttestationBuildError::ClockError => {
                    codes::IDENT_1040
                }
                _ => codes::IDENT_1041,
            };
            NapiError::from(ScpNapiError::Identity {
                message: e.to_string(),
                code: code.to_owned(),
            })
        })?;

        let mut attestation = built.attestation;

        let rt = tokio::runtime::Handle::try_current().map_err(|e| {
            NapiError::from(ScpNapiError::Identity {
                message: format!("no tokio runtime: {e}"),
                code: codes::IDENT_1041.to_owned(),
            })
        })?;

        let sig = tokio::task::block_in_place(|| {
            rt.block_on(custody.sign(&key_handle, &built.canonical_bytes))
        })
        .map_err(|e| {
            NapiError::from(ScpNapiError::Identity {
                message: format!("Ed25519 signing failed: {e}"),
                code: codes::IDENT_1041.to_owned(),
            })
        })?;
        attestation.signature = sig.as_bytes().to_vec();

        crate::runtime::with_identity_mut(bi, &did, |entry| {
            if entry.identity.active_signing_key != key_handle {
                return Err(ScpNapiError::Identity {
                    message: "active signing key was rotated during attestation creation — \
                             please retry"
                        .to_owned(),
                    code: codes::IDENT_1041.to_owned(),
                });
            }

            if entry.identity_link_attestations.len() >= MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID {
                return Err(ScpNapiError::Identity {
                    message: format!(
                        "DID has reached the per-identity attestation limit \
                         ({MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID}) — cannot store additional attestations"
                    ),
                    code: codes::VALID_7403.to_owned(),
                });
            }
            entry.identity_link_attestations.push(attestation.clone());
            Ok(())
        })
        .map_err(NapiError::from)?;

        serde_json::to_string(&attestation).map_err(|e| {
            NapiError::from(ScpNapiError::Identity {
                message: format!("failed to serialize attestation: {e}"),
                code: codes::IDENT_1042.to_owned(),
            })
        })
    }

    /// Per-instance equivalent of `identity_link_attestations`.
    #[napi(js_name = "identityLinkAttestations")]
    pub fn identity_link_attestations(&self, did: String) -> napi::Result<String> {
        crate::runtime::with_identity(&self.inner, &did, |entry| {
            serde_json::to_string(&entry.identity_link_attestations).map_err(|e| {
                ScpNapiError::Identity {
                    message: format!("failed to serialize attestations: {e}"),
                    code: codes::IDENT_1043.to_owned(),
                }
            })
        })
        .map_err(NapiError::from)
    }

    /// Per-instance equivalent of `identity_remove_link_attestation`.
    #[napi(js_name = "identityRemoveLinkAttestation")]
    pub fn identity_remove_link_attestation(
        &self,
        did: String,
        attestation_id: String,
    ) -> napi::Result<bool> {
        crate::runtime::with_identity_mut(&self.inner, &did, |entry| {
            let before = entry.identity_link_attestations.len();
            entry
                .identity_link_attestations
                .retain(|a| a.id != attestation_id);
            Ok(entry.identity_link_attestations.len() < before)
        })
        .map_err(NapiError::from)
    }

    // `identity_verify_link_attestation` is exposed as a module-level free
    // fn at `crates/scp-ffi/napi/src/identity.rs::identity_verify_link_attestation`
    // per ADR-048 §1 — pure Ed25519 signature verification touches no
    // bridge-instance state. The TypeScript SDK's
    // `SCP.identityVerifyLinkAttestation` routes through `addon.X` per the
    // dispatcher-invariant test. Moved out of the `Scp` impl in PR-E #28
    // along with the cleanup of the `let _ = &self.inner;` gate-defang that
    // CLAUDE.md flags as "Gaming enforcement tests with dead references".

    /// Per-instance equivalent of `identity_execute_recovery` (spec §9.12).
    ///
    /// # Fails closed (#2240)
    ///
    /// The §9.12 recovery WIRE (a real `RecoveryBackend` plus step-1 key
    /// rotation) is not yet built (custody / DID-method operations tracked as
    /// #2240 Part B, pending human sign-off). Until it is wired via the SDK
    /// layer this method **fails closed** with a typed `SCP-IDENT-1022` error
    /// ("recovery backend not configured — provide a real backend via SDK
    /// layer") after the ownership / length / concurrency gates pass — it NEVER
    /// returns a fabricated success (the former inline always-`Ok` backend
    /// returned `key_rotation_completed: true` while doing nothing, a nullifier
    /// forbidden by the builder tenets). Mirrors the sibling
    /// [`Self::identity_execute_custody_migration`] fail-closed behaviour.
    ///
    /// # Concurrency cap
    ///
    /// This method drives an async orchestrator via
    /// `crate::runtime().block_on(...)` from a sync napi entry point — each
    /// in-flight call pins one libuv worker for the duration. To prevent
    /// libuv worker-pool exhaustion (RED-PR5-002 / BLACK-PR5-002) the bridge
    /// bounds concurrent recovery + custody-migration invocations via
    /// [`NapiBridgeInstance::recovery_semaphore`] (cap =
    /// [`crate::runtime::RECOVERY_CONCURRENCY_CAP`]). When the permit pool is
    /// exhausted the call returns `SCP-VALID-7140` immediately — it does not
    /// queue on the permit wait (queueing would itself pin a libuv worker).
    #[napi(js_name = "identityExecuteRecovery")]
    pub fn identity_execute_recovery(
        &self,
        did: String,
        tier: String,
        context_ids: Vec<String>,
    ) -> napi::Result<String> {
        use scp_ffi_common::validate::validate_did;

        validate_did(&did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

        // Ownership check: reject recovery for DIDs not registered in
        // this bridge instance's identity registry (round-3 red-hat
        // RED-PR5-003). Without this, any realm-local caller could
        // drive unbounded recovery work on `crate::runtime()` against
        // arbitrary DIDs.
        //
        // Runs BEFORE the concurrency-cap check so unauthorised callers
        // cannot consume recovery permits with arbitrary DIDs.
        if !crate::runtime::identity_registry(&self.inner).contains_key(&did) {
            return Err(NapiError::from(ScpNapiError::Identity {
                message: format!(
                    "identity_execute_recovery: DID '{did}' is not owned by this SCP instance — \
                     recovery is restricted to identities registered on this instance (populated \
                     only by identity_create* / migrate, never by identity_load, on every \
                     binding). The ownership-registry keying mechanism differs across bindings \
                     (UniFFI custody registry vs PyO3/NAPI identity registry) and is unified in \
                     #2240 Part B."
                ),
                code: codes::IDENT_1020.to_owned(),
            }));
        }

        // Length cap: prevent DoS by unbounded context_ids list
        // (round-3 red-hat RED-PR5-003 amplifier).
        const MAX_CONTEXT_IDS_PER_RECOVERY: usize = 1024;
        if context_ids.len() > MAX_CONTEXT_IDS_PER_RECOVERY {
            return Err(NapiError::from(ScpNapiError::Validation {
                message: format!(
                    "identity_execute_recovery: context_ids length {} exceeds cap of {}",
                    context_ids.len(),
                    MAX_CONTEXT_IDS_PER_RECOVERY
                ),
                code: codes::VALID_7120.to_owned(),
            }));
        }

        // RED-PR5-002 / BLACK-PR5-002: bound concurrent `block_on` calls so a
        // flood of recovery requests (even with valid, owned DIDs) cannot
        // saturate the libuv worker pool. `try_acquire_owned` is non-blocking
        // — if the permit pool is exhausted we return a typed busy error
        // rather than queue the caller (queueing would itself pin a libuv
        // worker on the permit wait). The permit is dropped automatically
        // when `_permit` goes out of scope after `block_on` returns.
        //
        // Placed AFTER the ownership + length-cap checks so rejected-upstream
        // callers never consume a permit.
        let _permit = Arc::clone(&self.inner.recovery_semaphore)
            .try_acquire_owned()
            .map_err(|_| {
                NapiError::from(ScpNapiError::Validation {
                    message: format!(
                        "recovery/custody-migration concurrency cap reached ({} in flight); \
                         retry after an in-flight call completes",
                        crate::runtime::RECOVERY_CONCURRENCY_CAP
                    ),
                    code: codes::VALID_7140.to_owned(),
                })
            })?;

        // Validate the tier first so callers still get the precise invalid-tier
        // error rather than the generic fail-closed one. The `_permit` acquired
        // above is dropped when this method returns.
        match tier.as_str() {
            "agent" | "active_signing" | "identity_key" => {}
            other => {
                return Err(NapiError::from(ScpNapiError::Identity {
                    message: format!(
                        "invalid compromise tier: {other}; expected 'agent', 'active_signing', or 'identity_key'"
                    ),
                    code: codes::IDENT_1021.to_owned(),
                }));
            }
        }

        // FAIL CLOSED (#2240): there is no configured recovery backend at the
        // FFI layer, and step 1 (real key rotation) cannot be performed here.
        // Unlike custody migration — whose orchestrator surfaces its
        // NotConfigured backend's first `Err` as a fatal error —
        // `CompromiseRecoveryOrchestrator::execute_recovery` isolates
        // per-context failures (§9.12) and never returns a fatal "backend
        // absent" error, so recovery must fail closed at the bridge boundary
        // before any `KeyRotationOutcome` / `RecoveryResult` is fabricated. The
        // ownership / length / concurrency gates above still run so the DoS and
        // authorisation guarantees are preserved for the wired backend (Part B).
        Err(NapiError::from(ScpNapiError::Identity {
            message: "recovery backend not configured — provide a real backend via SDK layer"
                .to_owned(),
            code: codes::IDENT_1022.to_owned(),
        }))
    }

    /// Per-instance equivalent of `identity_execute_custody_migration`
    /// (spec §3.2.1).
    ///
    /// # Concurrency cap
    ///
    /// Shares [`NapiBridgeInstance::recovery_semaphore`] with
    /// [`Self::identity_execute_recovery`] (cap =
    /// [`crate::runtime::RECOVERY_CONCURRENCY_CAP`]). Returns
    /// `SCP-VALID-7140` when the permit pool is exhausted. See the rustdoc
    /// on [`Self::identity_execute_recovery`] for the libuv worker-pool
    /// rationale (RED-PR5-002 / BLACK-PR5-002).
    #[napi(js_name = "identityExecuteCustodyMigration")]
    pub fn identity_execute_custody_migration(
        &self,
        did: String,
        target: String,
        context_ids: Vec<String>,
    ) -> napi::Result<String> {
        use scp_core::identity::custody_migration::{
            CustodyMigrationBackend, CustodyMigrationOrchestrator, CustodyMigrationRequest,
            CustodyMigrationTarget,
        };
        use scp_did::DID;
        use scp_ffi_common::validate::validate_did;

        validate_did(&did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

        // Ownership check: reject custody migration for DIDs not
        // registered in this bridge instance's identity registry
        // (round-3 red-hat RED-PR5-004). Same rationale as
        // identity_execute_recovery above.
        //
        // Runs BEFORE the concurrency-cap check so unauthorised callers
        // cannot consume migration permits with arbitrary DIDs.
        if !crate::runtime::identity_registry(&self.inner).contains_key(&did) {
            return Err(NapiError::from(ScpNapiError::Identity {
                message: format!(
                    "identity_execute_custody_migration: DID '{did}' is not owned by this SCP \
                     instance — custody migration is restricted to identities created or loaded \
                     via this SCP"
                ),
                code: codes::IDENT_1024.to_owned(),
            }));
        }

        // Length cap: prevent DoS by unbounded context_ids list.
        const MAX_CONTEXT_IDS_PER_MIGRATION: usize = 1024;
        if context_ids.len() > MAX_CONTEXT_IDS_PER_MIGRATION {
            return Err(NapiError::from(ScpNapiError::Validation {
                message: format!(
                    "identity_execute_custody_migration: context_ids length {} exceeds cap of {}",
                    context_ids.len(),
                    MAX_CONTEXT_IDS_PER_MIGRATION
                ),
                code: codes::VALID_7120.to_owned(),
            }));
        }

        // RED-PR5-002 / BLACK-PR5-002: shared permit pool with
        // `identity_execute_recovery`. See the rustdoc on that method for
        // the full rationale.
        //
        // Placed AFTER the ownership + length-cap checks so rejected-upstream
        // callers never consume a permit.
        let _permit = Arc::clone(&self.inner.recovery_semaphore)
            .try_acquire_owned()
            .map_err(|_| {
                NapiError::from(ScpNapiError::Validation {
                    message: format!(
                        "recovery/custody-migration concurrency cap reached ({} in flight); \
                         retry after an in-flight call completes",
                        crate::runtime::RECOVERY_CONCURRENCY_CAP
                    ),
                    code: codes::VALID_7140.to_owned(),
                })
            })?;

        let did_val = DID::from(did.as_str());

        let migration_target = match target.as_str() {
            "platform_managed" => CustodyMigrationTarget::PlatformManaged,
            "hardware" => CustodyMigrationTarget::Hardware,
            "software" => CustodyMigrationTarget::Software,
            "in_memory" => CustodyMigrationTarget::InMemory,
            other => {
                return Err(NapiError::from(ScpNapiError::Identity {
                    message: format!(
                        "invalid custody migration target: {other}; expected 'platform_managed', 'hardware', 'software', or 'in_memory'"
                    ),
                    code: codes::IDENT_1024.to_owned(),
                }));
            }
        };

        struct NotConfiguredMigrationBackend;
        impl CustodyMigrationBackend for NotConfiguredMigrationBackend {
            fn generate_key(&self, _target: CustodyMigrationTarget) -> Result<Vec<u8>, String> {
                Err(
                    "custody migration backend not configured — provide a real backend via SDK layer"
                        .to_owned(),
                )
            }
            fn authorize(&self, _request: &CustodyMigrationRequest) -> Result<(), String> {
                Err(
                    "custody migration backend not configured — provide a real backend via SDK layer"
                        .to_owned(),
                )
            }
            fn rotate_did_document(
                &self,
                _did: &DID,
                _request: &CustodyMigrationRequest,
                _context_ids: &[String],
            ) -> Result<(Vec<String>, Vec<String>), String> {
                Err(
                    "custody migration backend not configured — provide a real backend via SDK layer"
                        .to_owned(),
                )
            }
            fn reissue_credentials(
                &self,
                _did: &DID,
                _request: &CustodyMigrationRequest,
            ) -> Result<(), String> {
                Err(
                    "custody migration backend not configured — provide a real backend via SDK layer"
                        .to_owned(),
                )
            }
            fn destroy_old_key(&self, _did: &DID) -> Result<(), String> {
                Err(
                    "custody migration backend not configured — provide a real backend via SDK layer"
                        .to_owned(),
                )
            }
        }

        let orchestrator =
            CustodyMigrationOrchestrator::new(did_val, migration_target, context_ids);
        let backend = NotConfiguredMigrationBackend;

        // Drive the async orchestrator on the module-local tokio runtime
        // (crate::runtime()). Same rationale as identity_execute_recovery:
        // the napi-rs worker thread has no tokio context (round-2
        // bug-catcher finding).
        let result = crate::runtime()
            .block_on(orchestrator.execute(&backend, &scp_clock::SystemClock))
            .map_err(|e| {
                NapiError::from(ScpNapiError::Identity {
                    message: format!("custody migration failed: {e}"),
                    code: codes::IDENT_1025.to_owned(),
                })
            })?;

        serde_json::to_string(&result).map_err(|e| {
            NapiError::from(ScpNapiError::Identity {
                message: format!("failed to serialize custody migration result: {e}"),
                code: codes::IDENT_1026.to_owned(),
            })
        })
    }

    // ====================================================================
    // #1549 Phase 4 PR 4 — sub-slice B: discovery / petname / handle / scope.
    //
    // Migrates the stateful `discovery.rs` free functions to methods on
    // [`Scp`]. Pure helpers (`discovery_parse_address`,
    // `discovery_create_query`, `discovery_normalize_address`,
    // `context_discover`) are retained as free functions only — they touch
    // no bridge state.
    // ====================================================================

    /// Per-instance equivalent of `petname_set`.
    #[napi(js_name = "petnameSet")]
    pub fn petname_set(
        &self,
        owner_did: String,
        target_did: String,
        name: String,
    ) -> napi::Result<()> {
        use scp_did::DID;

        scp_ffi_common::validate::validate_did(&owner_did)
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
        if target_did.is_empty() {
            return Err(NapiError::from(ScpNapiError::Validation {
                message: "target_did must not be empty".to_owned(),
                code: codes::VALID_7111.to_owned(),
            }));
        }
        let mut guard = self.inner.core.petname_maps().lock().map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("petname lock poisoned: {e}"),
                code: codes::VALID_7112.to_owned(),
            })
        })?;
        let map = guard.entry(owner_did).or_default();
        map.set_petname(DID::from(target_did.as_str()), name);
        Ok(())
    }

    /// Per-instance equivalent of `petname_remove`.
    #[napi(js_name = "petnameRemove")]
    pub fn petname_remove(&self, owner_did: String, target_did: String) -> napi::Result<()> {
        use scp_did::DID;

        scp_ffi_common::validate::validate_did(&owner_did)
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
        let mut guard = self.inner.core.petname_maps().lock().map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("petname lock poisoned: {e}"),
                code: codes::VALID_7112.to_owned(),
            })
        })?;
        if let Some(map) = guard.get_mut(&owner_did) {
            map.remove_petname(&DID::from(target_did.as_str()));
        }
        Ok(())
    }

    /// Per-instance equivalent of `petname_set_context`.
    #[napi(js_name = "petnameSetContext")]
    pub fn petname_set_context(
        &self,
        owner_did: String,
        context_id: String,
        name: String,
    ) -> napi::Result<()> {
        scp_ffi_common::validate::validate_did(&owner_did)
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
        if context_id.is_empty() {
            return Err(NapiError::from(ScpNapiError::Validation {
                message: "context_id must not be empty".to_owned(),
                code: codes::VALID_7113.to_owned(),
            }));
        }
        let mut guard = self.inner.core.petname_maps().lock().map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("petname lock poisoned: {e}"),
                code: codes::VALID_7112.to_owned(),
            })
        })?;
        let map = guard.entry(owner_did).or_default();
        map.set_context_petname(context_id, name);
        Ok(())
    }

    /// Per-instance equivalent of `petname_remove_context`.
    #[napi(js_name = "petnameRemoveContext")]
    pub fn petname_remove_context(
        &self,
        owner_did: String,
        context_id: String,
    ) -> napi::Result<()> {
        scp_ffi_common::validate::validate_did(&owner_did)
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
        let mut guard = self.inner.core.petname_maps().lock().map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("petname lock poisoned: {e}"),
                code: codes::VALID_7112.to_owned(),
            })
        })?;
        if let Some(map) = guard.get_mut(&owner_did) {
            map.remove_context_petname(&context_id);
        }
        Ok(())
    }

    /// Per-instance equivalent of `petname_resolve_did`.
    #[napi(js_name = "petnameResolveDid")]
    pub fn petname_resolve_did(&self, owner_did: String, name: String) -> napi::Result<String> {
        scp_ffi_common::validate::validate_did(&owner_did)
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
        let guard = self.inner.core.petname_maps().lock().map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("petname lock poisoned: {e}"),
                code: codes::VALID_7112.to_owned(),
            })
        })?;
        let dids: Vec<String> = guard
            .get(&owner_did)
            .map(|map| {
                map.resolve_did(&name)
                    .into_iter()
                    .map(|d| d.to_string())
                    .collect()
            })
            .unwrap_or_default();
        serde_json::to_string(&dids).map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("failed to serialize petname resolve result: {e}"),
                code: codes::VALID_7114.to_owned(),
            })
        })
    }

    /// Per-instance equivalent of `petname_resolve_context`.
    #[napi(js_name = "petnameResolveContext")]
    pub fn petname_resolve_context(&self, owner_did: String, name: String) -> napi::Result<String> {
        scp_ffi_common::validate::validate_did(&owner_did)
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
        let guard = self.inner.core.petname_maps().lock().map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("petname lock poisoned: {e}"),
                code: codes::VALID_7112.to_owned(),
            })
        })?;
        let ids: Vec<String> = guard
            .get(&owner_did)
            .map(|map| map.resolve_context(&name))
            .unwrap_or_default();
        serde_json::to_string(&ids).map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("failed to serialize petname resolve result: {e}"),
                code: codes::VALID_7114.to_owned(),
            })
        })
    }

    /// Per-instance equivalent of `petname_get_for_did`.
    #[napi(js_name = "petnameGetForDid")]
    pub fn petname_get_for_did(
        &self,
        owner_did: String,
        target_did: String,
    ) -> napi::Result<Option<String>> {
        use scp_did::DID;

        scp_ffi_common::validate::validate_did(&owner_did)
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
        let guard = self.inner.core.petname_maps().lock().map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("petname lock poisoned: {e}"),
                code: codes::VALID_7112.to_owned(),
            })
        })?;
        Ok(guard.get(&owner_did).and_then(|map| {
            map.petname_for_did(&DID::from(target_did.as_str()))
                .map(str::to_owned)
        }))
    }

    /// Per-instance equivalent of `petname_get_for_context`.
    #[napi(js_name = "petnameGetForContext")]
    pub fn petname_get_for_context(
        &self,
        owner_did: String,
        context_id: String,
    ) -> napi::Result<Option<String>> {
        scp_ffi_common::validate::validate_did(&owner_did)
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
        let guard = self.inner.core.petname_maps().lock().map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("petname lock poisoned: {e}"),
                code: codes::VALID_7112.to_owned(),
            })
        })?;
        Ok(guard
            .get(&owner_did)
            .and_then(|map| map.petname_for_context(&context_id).map(str::to_owned)))
    }

    /// Applies a serialized petname event to the owner's petname map.
    ///
    /// The event JSON must match the `PetnameEvent` serde format (§22.9.2).
    /// This is the event-driven mutation path matching `PetnameMap::apply_event`.
    #[napi(js_name = "petnameApplyEvent")]
    pub fn petname_apply_event(&self, owner_did: String, event_json: String) -> napi::Result<()> {
        use scp_core::discovery::petnames::PetnameEvent;

        scp_ffi_common::validate::validate_did(&owner_did)
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
        let event: PetnameEvent = serde_json::from_str(&event_json).map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("invalid petname event JSON: {e}"),
                code: codes::VALID_7115.to_owned(),
            })
        })?;
        let mut guard = self.inner.core.petname_maps().lock().map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("petname lock poisoned: {e}"),
                code: codes::VALID_7112.to_owned(),
            })
        })?;
        let map = guard.entry(owner_did).or_default();
        map.apply_event(&event);
        Ok(())
    }

    /// Returns the number of DID petnames for an owner.
    ///
    /// Mirrors `PetnameMap::did_petname_count`.
    #[napi(js_name = "petnameDidCount")]
    pub fn petname_did_count(&self, owner_did: String) -> napi::Result<u32> {
        scp_ffi_common::validate::validate_did(&owner_did)
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
        let guard = self.inner.core.petname_maps().lock().map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("petname lock poisoned: {e}"),
                code: codes::VALID_7112.to_owned(),
            })
        })?;
        let count = guard.get(&owner_did).map_or(
            0,
            scp_core::discovery::petnames::PetnameMap::did_petname_count,
        );
        u32::try_from(count).map_err(|_| {
            NapiError::from(ScpNapiError::Validation {
                message: "petname count exceeds u32::MAX".to_owned(),
                code: codes::VALID_7116.to_owned(),
            })
        })
    }

    /// Returns the number of context petnames for an owner.
    ///
    /// Mirrors `PetnameMap::context_petname_count`.
    #[napi(js_name = "petnameContextCount")]
    pub fn petname_context_count(&self, owner_did: String) -> napi::Result<u32> {
        scp_ffi_common::validate::validate_did(&owner_did)
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
        let guard = self.inner.core.petname_maps().lock().map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("petname lock poisoned: {e}"),
                code: codes::VALID_7112.to_owned(),
            })
        })?;
        let count = guard.get(&owner_did).map_or(
            0,
            scp_core::discovery::petnames::PetnameMap::context_petname_count,
        );
        u32::try_from(count).map_err(|_| {
            NapiError::from(ScpNapiError::Validation {
                message: "petname count exceeds u32::MAX".to_owned(),
                code: codes::VALID_7116.to_owned(),
            })
        })
    }

    /// Per-instance equivalent of `handle_register`.
    #[napi(js_name = "handleRegister")]
    pub fn handle_register(
        &self,
        discovery_context_id: String,
        handle: String,
        target_json: String,
        registrant_did: String,
        description: Option<String>,
        tags: Option<Vec<String>>,
    ) -> napi::Result<String> {
        use scp_core::discovery::handles::{HandleMetadata, HandleRegisterParams, HandleRegistry};
        use scp_did::DID;

        let target =
            scp_ffi_common::petname_helpers::parse_handle_target(&target_json).map_err(|e| {
                NapiError::from(ScpNapiError::Validation {
                    message: e.message,
                    code: codes::VALID_7126.to_owned(),
                })
            })?;
        let params = HandleRegisterParams {
            handle,
            target,
            metadata: Some(HandleMetadata { description, tags }),
        };
        let mut guard = self.inner.core.handle_registries().lock().map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("handle registry lock poisoned: {e}"),
                code: codes::VALID_7120.to_owned(),
            })
        })?;
        let registry = guard
            .entry(discovery_context_id.clone())
            .or_insert_with(|| HandleRegistry::new(discovery_context_id));
        let result = registry.register(
            &params,
            &DID::from(registrant_did.as_str()),
            &scp_clock::SystemClock,
        );
        serde_json::to_string(&result).map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("failed to serialize handle register result: {e}"),
                code: codes::VALID_7122.to_owned(),
            })
        })
    }

    /// Per-instance equivalent of `handle_lookup`.
    #[napi(js_name = "handleLookup")]
    pub fn handle_lookup(
        &self,
        discovery_context_id: String,
        handle: String,
        type_filter: Option<String>,
    ) -> napi::Result<String> {
        use scp_core::discovery::handles::{HandleLookupParams, HandleTypeFilter};

        let filter = match type_filter.as_deref() {
            Some("identity") => Some(HandleTypeFilter::Identity),
            Some("context") => Some(HandleTypeFilter::Context),
            Some(other) => {
                return Err(NapiError::from(ScpNapiError::Validation {
                    message: format!(
                        "invalid type_filter '{other}': expected 'identity' or 'context'"
                    ),
                    code: codes::VALID_7123.to_owned(),
                }));
            }
            None => None,
        };
        let guard = self.inner.core.handle_registries().lock().map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("handle registry lock poisoned: {e}"),
                code: codes::VALID_7120.to_owned(),
            })
        })?;
        let result = guard.get(&discovery_context_id).map_or_else(
            || scp_core::discovery::HandleLookupResult {
                results: Vec::new(),
            },
            |registry| {
                registry.lookup(&HandleLookupParams {
                    handle,
                    type_filter: filter,
                })
            },
        );
        serde_json::to_string(&result).map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("failed to serialize handle lookup result: {e}"),
                code: codes::VALID_7124.to_owned(),
            })
        })
    }

    /// Per-instance equivalent of `handle_deregister`.
    #[napi(js_name = "handleDeregister")]
    pub fn handle_deregister(
        &self,
        discovery_context_id: String,
        handle: String,
        did: String,
    ) -> napi::Result<String> {
        use scp_core::discovery::handles::HandleDeregisterParams;
        use scp_did::DID;

        let mut guard = self.inner.core.handle_registries().lock().map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("handle registry lock poisoned: {e}"),
                code: codes::VALID_7120.to_owned(),
            })
        })?;
        let result = guard.get_mut(&discovery_context_id).map_or_else(
            || scp_core::discovery::HandleDeregisterResult { removed: false },
            |registry| {
                registry.deregister(&HandleDeregisterParams {
                    handle,
                    did: DID::from(did.as_str()),
                })
            },
        );
        serde_json::to_string(&result).map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("failed to serialize handle deregister result: {e}"),
                code: codes::VALID_7125.to_owned(),
            })
        })
    }

    /// Per-instance equivalent of `scope_register`.
    #[napi(js_name = "scopeRegister")]
    #[allow(clippy::too_many_arguments)]
    pub fn scope_register(
        &self,
        scope_context_id: String,
        name: String,
        target_context_id: String,
        relay_urls: Vec<String>,
        registrant_did: String,
        description: Option<String>,
        tags: Option<Vec<String>>,
    ) -> napi::Result<String> {
        use scp_did::DID;

        scp_ffi_common::validate::validate_context_id(&scope_context_id)
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
        scp_ffi_common::validate::validate_context_id(&target_context_id)
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
        scp_ffi_common::validate::validate_did(&registrant_did)
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
        for url in &relay_urls {
            scp_ffi_common::validate::validate_relay_url(url).map_err(|e| {
                NapiError::from(ScpNapiError::Validation {
                    message: e.to_string(),
                    code: codes::VALID_7135.to_owned(),
                })
            })?;
        }

        let params = scp_core::discovery::ScopeRegisterParams {
            name,
            target: scp_core::discovery::ScopeTarget {
                context_id: target_context_id,
                relay_urls,
            },
            metadata: if description.is_some() || tags.is_some() {
                Some(scp_core::discovery::ScopeMetadata { description, tags })
            } else {
                None
            },
        };

        let mut guard = self.inner.core.scope_registries().lock().map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("scope registry lock poisoned: {e}"),
                code: codes::VALID_7130.to_owned(),
            })
        })?;

        let registry = guard
            .entry(scope_context_id.clone())
            .or_insert_with(|| scp_core::discovery::ScopeRegistry::new(scope_context_id));

        let result = registry
            .register(
                &params,
                &DID::from(registrant_did.as_str()),
                &scp_clock::SystemClock,
            )
            .map_err(|e| {
                NapiError::from(ScpNapiError::Validation {
                    message: format!("scope registration failed: {e}"),
                    code: codes::VALID_7131.to_owned(),
                })
            })?;

        serde_json::to_string(&result).map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("failed to serialize scope register result: {e}"),
                code: codes::VALID_7132.to_owned(),
            })
        })
    }

    /// Per-instance equivalent of `scope_lookup`.
    #[napi(js_name = "scopeLookup")]
    pub fn scope_lookup(&self, scope_context_id: String, name: String) -> napi::Result<String> {
        scp_ffi_common::validate::validate_context_id(&scope_context_id)
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

        let guard = self.inner.core.scope_registries().lock().map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("scope registry lock poisoned: {e}"),
                code: codes::VALID_7130.to_owned(),
            })
        })?;

        let result = match guard.get(&scope_context_id) {
            Some(registry) => registry
                .lookup(&scp_core::discovery::ScopeLookupParams { name })
                .map_err(|e| {
                    NapiError::from(ScpNapiError::Validation {
                        message: format!("scope lookup failed: {e}"),
                        code: codes::VALID_7133.to_owned(),
                    })
                })?,
            None => scp_core::discovery::ScopeLookupResult {
                results: Vec::new(),
            },
        };

        serde_json::to_string(&result).map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("failed to serialize scope lookup result: {e}"),
                code: codes::VALID_7133.to_owned(),
            })
        })
    }

    /// Per-instance equivalent of `scope_deregister`.
    #[napi(js_name = "scopeDeregister")]
    pub fn scope_deregister(
        &self,
        scope_context_id: String,
        name: String,
        did: String,
    ) -> napi::Result<String> {
        use scp_did::DID;

        scp_ffi_common::validate::validate_context_id(&scope_context_id)
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
        scp_ffi_common::validate::validate_did(&did)
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

        let mut guard = self.inner.core.scope_registries().lock().map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("scope registry lock poisoned: {e}"),
                code: codes::VALID_7130.to_owned(),
            })
        })?;

        let result = match guard.get_mut(&scope_context_id) {
            Some(registry) => registry
                .deregister(&scp_core::discovery::ScopeDeregisterParams {
                    name,
                    did: DID::from(did.as_str()),
                })
                .map_err(|e| {
                    NapiError::from(ScpNapiError::Validation {
                        message: format!("scope deregister failed: {e}"),
                        code: codes::VALID_7134.to_owned(),
                    })
                })?,
            None => scp_core::discovery::ScopeDeregisterResult { removed: false },
        };

        serde_json::to_string(&result).map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("failed to serialize scope deregister result: {e}"),
                code: codes::VALID_7134.to_owned(),
            })
        })
    }

    /// Per-instance equivalent of `address_resolve` (spec §22.8).
    #[napi(js_name = "addressResolve")]
    pub async fn address_resolve(
        &self,
        owner_did: String,
        address: String,
        known_contexts_json: Option<String>,
    ) -> napi::Result<String> {
        use scp_ffi_common::petname_helpers::{
            LocalHandleQuerier, address_resolution_to_json, known_contexts_from_scope_registries,
        };

        if owner_did.is_empty() {
            return Err(NapiError::from(ScpNapiError::Validation {
                message: "owner_did must not be empty".to_owned(),
                code: codes::VALID_7110.to_owned(),
            }));
        }
        let core = &self.inner.core;
        let mut known_contexts: HashMap<String, String> =
            if let Some(ref json) = known_contexts_json {
                serde_json::from_str(json).map_err(|e| {
                    NapiError::from(ScpNapiError::Validation {
                        message: format!("invalid known_contexts_json: {e}"),
                        code: codes::VALID_7090.to_owned(),
                    })
                })?
            } else {
                let guard = core.handle_registries().lock().map_err(|e| {
                    NapiError::from(ScpNapiError::Validation {
                        message: format!("handle registry lock poisoned: {e}"),
                        code: codes::VALID_7120.to_owned(),
                    })
                })?;
                guard.keys().map(|k| (k.clone(), k.clone())).collect()
            };

        let scope_contexts = known_contexts_from_scope_registries(core);
        for (name, ctx_id) in scope_contexts {
            known_contexts.entry(name).or_insert(ctx_id);
        }
        let known_domains: Vec<&str> = Vec::new();
        let petname_map = {
            let guard = core.petname_maps().lock().map_err(|e| {
                NapiError::from(ScpNapiError::Validation {
                    message: format!("petname lock poisoned: {e}"),
                    code: codes::VALID_7112.to_owned(),
                })
            })?;
            guard.get(&owner_did).cloned().unwrap_or_default()
        };
        let mut resolver = scp_core::discovery::AddressResolver::new();
        let querier = LocalHandleQuerier::new(core);
        let results = resolver
            .resolve(
                &address,
                &petname_map,
                &querier,
                &known_contexts,
                &known_domains,
                &scp_clock::SystemClock,
            )
            .await
            .map_err(|e| {
                NapiError::from(ScpNapiError::Validation {
                    message: format!("address resolution failed: {e}"),
                    code: codes::VALID_7091.to_owned(),
                })
            })?;
        let json_results: Vec<serde_json::Value> =
            results.iter().map(address_resolution_to_json).collect();
        serde_json::to_string(&json_results).map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("failed to serialize address resolution results: {e}"),
                code: codes::VALID_7092.to_owned(),
            })
        })
    }

    // ====================================================================
    // #1549 Phase 4 PR 4 — sub-slice C: context operations on SCP.
    //
    // Each method delegates to the per-bridge-instance `_on` helpers in
    // [`crate::context`] / [`crate::outlets`], routing through `&*self.inner`
    // so operations are scoped to this `SCP`'s bridge instance. The
    // free-function façade that predated this migration was deleted in
    // the Phase 4 PR 4 demolition slice (ADR-048).
    // ====================================================================

    /// Per-instance equivalent of the free-function `context_create`.
    #[napi(js_name = "contextCreate")]
    pub async fn context_create(
        &self,
        identity: &NapiIdentity,
        params_json: String,
    ) -> napi::Result<NapiContextHandle> {
        crate::napi_check_handle!(&self.inner.core, identity);
        crate::context::context_create_on(&self.inner, identity, params_json).await
    }

    /// Reserves a pooled MLS `KeyPackage` under the owning identity for a
    /// spawn-from-Welcome join (ADR-049 Phase 2J).
    ///
    /// Returns the opaque `{ reservationId, keyPackagePublic }` pair: the PUBLIC
    /// bytes are handed (out of band) to the context creator, who mints a
    /// Welcome addressed to this reservation; the `reservationId` is passed back
    /// to `contextJoinFromWelcome`. The joiner's private signer state never
    /// leaves the node. `owningDid` MUST be a locally-custodied identity.
    #[napi(js_name = "reserveKeyPackage")]
    pub async fn reserve_key_package(
        &self,
        owning_did: String,
    ) -> napi::Result<NapiKeyPackageReservation> {
        crate::context::reserve_key_package_on(&self.inner, owning_did).await
    }

    /// Joins an existing SCP context by opening a received sealed, signed
    /// invitation bundle, standing the local (joiner) identity up as a
    /// send-capable participant (ADR-049 Phase 2J; FFI-02 Option A).
    ///
    /// Completes the reserve → invite → join handshake begun by
    /// `reserveKeyPackage`. The authoritative params + MLS Welcome travel INSIDE
    /// the `sealed` bundle (produced by the creator's `inviteMember`), which the
    /// runtime opens and authenticates — the joiner supplies no loose params. The
    /// joiner's §9.10.4 routing pseudonym is DERIVED from its locally-custodied
    /// identity (never caller-supplied); a non-custodied joiner hard-fails before
    /// the single-use `KeyPackage` is consumed. Returns an active
    /// [`NapiContextHandle`] rebuilt from the AUTHENTICATED bundle params.
    #[napi(js_name = "contextJoinFromWelcome")]
    pub async fn context_join_from_welcome(
        &self,
        owning_did: String,
        sealed: NapiSealedInvitation,
        reservation_id: String,
    ) -> napi::Result<NapiContextHandle> {
        crate::context::context_join_from_welcome_on(
            &self.inner,
            owning_did,
            sealed,
            reservation_id,
        )
        .await
    }

    /// Invites a member to an existing context, producing a sealed, signed
    /// invitation bundle (ADR-049 Phase 2J; FFI-02 Option A).
    ///
    /// The creator (or admin) seals the context's genesis params + Welcome for
    /// the invitee under RFC 9180 HPKE, binding them to the invitee's
    /// `KeyPackage`. Only a `SingleAdmin` context is supported today: the invite
    /// is unilateral and returns a [`NapiInviteMemberOutcome`] whose `bundle` is
    /// the sealed `NapiSealedInvitation` — pass it directly to
    /// `contextJoinFromWelcome`. A voting-governed context throws (governed-
    /// context invitations are not yet implemented). `creatorDid` MUST be a
    /// locally-custodied identity; the invite is signed under its `#active` key.
    #[napi(js_name = "inviteMember")]
    pub async fn invite_member(
        &self,
        context_id: String,
        creator_did: String,
        invitee_did: String,
        invitee_key_package: Vec<u8>,
        relay_urls: Vec<String>,
    ) -> napi::Result<NapiInviteMemberOutcome> {
        crate::context::invite_member_on(
            &self.inner,
            context_id,
            creator_did,
            invitee_did,
            invitee_key_package,
            relay_urls,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `context_join`.
    #[napi(js_name = "contextJoin")]
    pub async fn context_join(
        &self,
        handle: &NapiContextHandle,
        identity_did: String,
        spending_ucan_jwt: Option<String>,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_join_on(&self.inner, handle, identity_did, spending_ucan_jwt).await
    }

    /// Per-instance equivalent of the free-function `context_leave`.
    #[napi(js_name = "contextLeave")]
    pub async fn context_leave(
        &self,
        handle: &NapiContextHandle,
        identity_did: String,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_leave_on(&self.inner, handle, identity_did).await
    }

    /// Per-instance equivalent of the free-function `context_close`.
    #[napi(js_name = "contextClose")]
    pub async fn context_close(
        &self,
        handle: &NapiContextHandle,
        identity_did: String,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_close_on(&self.inner, handle, identity_did).await
    }

    /// Per-instance equivalent of the free-function `context_send`.
    #[napi(js_name = "contextSend")]
    pub async fn context_send(
        &self,
        handle: &NapiContextHandle,
        identity_did: String,
        payload: Vec<u8>,
        spending_ucan_jwt: Option<String>,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_send_on(
            &self.inner,
            handle,
            identity_did,
            payload,
            spending_ucan_jwt,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `context_subscribe`.
    #[napi(js_name = "contextSubscribe")]
    pub async fn context_subscribe(
        &self,
        handle: &NapiContextHandle,
        identity_did: String,
        on_message: napi::threadsafe_function::ThreadsafeFunction<Option<NapiMessage>>,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_subscribe_on(&self.inner, handle, identity_did, on_message).await
    }

    /// Per-instance equivalent of the free-function `context_cancel_subscription`.
    #[napi(js_name = "contextCancelSubscription")]
    pub fn context_cancel_subscription(&self, handle: &NapiContextHandle) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_cancel_subscription_on(&self.inner, handle)
    }

    /// Per-instance equivalent of the free-function `context_member_count`.
    #[napi(js_name = "contextMemberCount")]
    pub async fn context_member_count(&self, handle: &NapiContextHandle) -> napi::Result<u32> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_member_count_on(&self.inner, handle).await
    }

    /// Reconnects `identity_did`'s contexts after an offline period,
    /// running the ADR-029 six-phase reconnection protocol for each of
    /// `contextIds` flagged `needs_reconnect` (§23.11).
    ///
    /// The driver lives at the FFI relay-client layer (ADR-029
    /// reconnection-driver addendum): it pulls relay-buffered messages via
    /// the `TransportManager` and reaches actor-owned reconnection state
    /// through the `Supervisor`. On success each context's `needs_reconnect`
    /// flag is cleared. `lastRelayContacts` maps context id → last-contact
    /// Unix seconds (tier classification); absent contexts default to the
    /// most conservative tier.
    #[napi(js_name = "contextReconnect")]
    pub async fn context_reconnect(
        &self,
        identity_did: String,
        context_ids: Vec<String>,
        last_relay_contacts: Option<std::collections::HashMap<String, f64>>,
    ) -> napi::Result<crate::context::NapiReconnectReport> {
        crate::context::context_reconnect_on(
            &self.inner,
            identity_did,
            context_ids,
            last_relay_contacts,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `context_is_member`.
    #[napi(js_name = "contextIsMember")]
    pub async fn context_is_member(
        &self,
        handle: &NapiContextHandle,
        did: String,
    ) -> napi::Result<bool> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_is_member_on(&self.inner, handle, did).await
    }

    /// Per-instance equivalent of the free-function `context_member_dids`.
    #[napi(js_name = "contextMemberDids")]
    pub async fn context_member_dids(
        &self,
        handle: &NapiContextHandle,
    ) -> napi::Result<Vec<String>> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_member_dids_on(&self.inner, handle).await
    }

    /// Per-instance equivalent of the free-function `context_member_role`.
    #[napi(js_name = "contextMemberRole")]
    pub async fn context_member_role(
        &self,
        handle: &NapiContextHandle,
        did: String,
    ) -> napi::Result<Option<String>> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_member_role_on(&self.inner, handle, did).await
    }

    /// Per-instance equivalent of the free-function `context_drain_events`.
    #[napi(js_name = "contextDrainEvents")]
    pub async fn context_drain_events(
        &self,
        handle: &NapiContextHandle,
    ) -> napi::Result<Vec<String>> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_drain_events_on(&self.inner, handle).await
    }

    /// Per-instance equivalent of the free-function `access_key_generate`.
    #[napi(js_name = "accessKeyGenerate")]
    pub async fn access_key_generate(
        &self,
        context_id: String,
        member_did: String,
        caller_did: String,
    ) -> napi::Result<()> {
        crate::context::access_key_generate_on(&self.inner, context_id, member_did, caller_did)
            .await
    }

    /// Per-instance equivalent of the free-function `access_key_revoke`.
    #[napi(js_name = "accessKeyRevoke")]
    pub async fn access_key_revoke(
        &self,
        context_id: String,
        member_did: String,
        caller_did: String,
    ) -> napi::Result<()> {
        crate::context::access_key_revoke_on(&self.inner, context_id, member_did, caller_did).await
    }

    /// Per-instance equivalent of the free-function `access_key_restore`.
    #[napi(js_name = "accessKeyRestore")]
    pub async fn access_key_restore(
        &self,
        context_id: String,
        member_did: String,
        caller_did: String,
    ) -> napi::Result<()> {
        crate::context::access_key_restore_on(&self.inner, context_id, member_did, caller_did).await
    }

    /// Per-instance equivalent of the free-function `context_broadcast_subscriber_count`.
    #[napi(js_name = "contextBroadcastSubscriberCount")]
    pub async fn context_broadcast_subscriber_count(
        &self,
        handle: &NapiContextHandle,
    ) -> napi::Result<Option<u32>> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_broadcast_subscriber_count_on(&self.inner, handle).await
    }

    /// Per-instance equivalent of the free-function `context_is_broadcast_subscriber`.
    #[napi(js_name = "contextIsBroadcastSubscriber")]
    pub async fn context_is_broadcast_subscriber(
        &self,
        handle: &NapiContextHandle,
        did: String,
    ) -> napi::Result<bool> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_is_broadcast_subscriber_on(&self.inner, handle, did).await
    }

    /// Per-instance equivalent of the free-function `context_broadcast_admission`.
    #[napi(js_name = "contextBroadcastAdmission")]
    pub async fn context_broadcast_admission(
        &self,
        handle: &NapiContextHandle,
    ) -> napi::Result<Option<String>> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_broadcast_admission_on(&self.inner, handle).await
    }

    /// Per-instance equivalent of the free-function `broadcast_subscribe`.
    ///
    /// For a GATED broadcast context, `messagesReadUcanJwt` MUST carry the
    /// `messages:read` JWT issued to `subscriberDid` by the context admin/creator
    /// (spec §5.14.4).
    #[napi(js_name = "broadcastSubscribe")]
    pub async fn broadcast_subscribe(
        &self,
        handle: &NapiContextHandle,
        subscriber_did: String,
        messages_read_ucan_jwt: Option<String>,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::broadcast_subscribe_on(
            &self.inner,
            handle,
            subscriber_did,
            messages_read_ucan_jwt,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `broadcast_unsubscribe`.
    #[napi(js_name = "broadcastUnsubscribe")]
    pub async fn broadcast_unsubscribe(
        &self,
        handle: &NapiContextHandle,
        subscriber_did: String,
        rotate_keys: Option<bool>,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::broadcast_unsubscribe_on(&self.inner, handle, subscriber_did, rotate_keys)
            .await
    }

    /// Per-instance equivalent of the free-function `broadcast_publish`.
    #[napi(js_name = "broadcastPublish")]
    pub async fn broadcast_publish(
        &self,
        handle: &NapiContextHandle,
        author_did: String,
        payload: Vec<u8>,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::broadcast_publish_on(&self.inner, handle, author_did, payload).await
    }

    /// Per-instance equivalent of the free-function `broadcast_publish_asset`.
    #[napi(js_name = "broadcastPublishAsset")]
    pub async fn broadcast_publish_asset(
        &self,
        handle: &NapiContextHandle,
        author_did: String,
        asset: NapiAssetEntry,
        deploy_id: Option<String>,
    ) -> napi::Result<NapiPublishResult> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::broadcast_publish_asset_on(
            &self.inner,
            handle,
            author_did,
            asset,
            deploy_id,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `broadcast_publish_assets`.
    #[napi(js_name = "broadcastPublishAssets")]
    pub async fn broadcast_publish_assets(
        &self,
        handle: &NapiContextHandle,
        author_did: String,
        assets: Vec<NapiAssetEntry>,
        deploy_id: Option<String>,
    ) -> napi::Result<NapiBatchPublishResult> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::broadcast_publish_assets_on(
            &self.inner,
            handle,
            author_did,
            assets,
            deploy_id,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `broadcast_block_subscriber`.
    #[napi(js_name = "broadcastBlockSubscriber")]
    pub async fn broadcast_block_subscriber(
        &self,
        handle: &NapiContextHandle,
        subscriber_did: String,
        blocker_did: String,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::broadcast_block_subscriber_on(
            &self.inner,
            handle,
            subscriber_did,
            blocker_did,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `broadcast_unblock_subscriber`.
    #[napi(js_name = "broadcastUnblockSubscriber")]
    pub async fn broadcast_unblock_subscriber(
        &self,
        handle: &NapiContextHandle,
        subscriber_did: String,
        unblocker_did: String,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::broadcast_unblock_subscriber_on(
            &self.inner,
            handle,
            subscriber_did,
            unblocker_did,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `broadcast_handle_key_request`.
    ///
    /// `wrapping_pubkey` is the requester's 32-byte X25519 public key; the
    /// broadcast key is HPKE-sealed to it inside the protocol layer (§5.14.2).
    /// Returns `Some(json)` (a serialized `SealedBroadcastKey`) on grant or
    /// `None` on deny.
    #[napi(js_name = "broadcastHandleKeyRequest")]
    pub async fn broadcast_handle_key_request(
        &self,
        handle: &NapiContextHandle,
        author_did: String,
        requester_did: String,
        wrapping_pubkey: Vec<u8>,
    ) -> napi::Result<Option<String>> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::broadcast_handle_key_request_on(
            &self.inner,
            handle,
            author_did,
            requester_did,
            wrapping_pubkey,
        )
        .await
    }

    /// Executes a previously-approved governance proposal BY ID. Takes only
    /// `(handle, proposalIdHex)`: the executor and consequence subject are
    /// resolved from the tracked proposal's proposer inside the runtime, never
    /// from a caller-supplied DID.
    #[napi(js_name = "contextExecuteGovernanceAction")]
    pub async fn context_execute_governance_action(
        &self,
        handle: &NapiContextHandle,
        proposal_id_hex: String,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_execute_governance_action_on(&self.inner, handle, proposal_id_hex)
            .await
    }

    /// Per-instance equivalent of the free-function `context_governance_propose`.
    #[napi(js_name = "contextGovernancePropose")]
    pub async fn context_governance_propose(
        &self,
        handle: &NapiContextHandle,
        action_json: String,
        proposer_did: String,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_governance_propose_on(
            &self.inner,
            handle,
            action_json,
            proposer_did,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `context_governance_approve`.
    #[napi(js_name = "contextGovernanceApprove")]
    pub async fn context_governance_approve(
        &self,
        handle: &NapiContextHandle,
        proposal_id_hex: String,
        voter_did: String,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_governance_approve_on(
            &self.inner,
            handle,
            proposal_id_hex,
            voter_did,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `context_governance_reject`.
    #[napi(js_name = "contextGovernanceReject")]
    pub async fn context_governance_reject(
        &self,
        handle: &NapiContextHandle,
        proposal_id_hex: String,
        voter_did: String,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_governance_reject_on(
            &self.inner,
            handle,
            proposal_id_hex,
            voter_did,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `context_governance_withdraw`.
    #[napi(js_name = "contextGovernanceWithdraw")]
    pub async fn context_governance_withdraw(
        &self,
        handle: &NapiContextHandle,
        proposal_id_hex: String,
        voter_did: String,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_governance_withdraw_on(
            &self.inner,
            handle,
            proposal_id_hex,
            voter_did,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `context_governance_get_proposal`.
    #[napi(js_name = "contextGovernanceGetProposal")]
    pub async fn context_governance_get_proposal(
        &self,
        handle: &NapiContextHandle,
        proposal_id_hex: String,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_governance_get_proposal_on(&self.inner, handle, proposal_id_hex)
            .await
    }

    /// Per-instance equivalent of the free-function `context_governance_list_proposals`.
    #[napi(js_name = "contextGovernanceListProposals")]
    pub async fn context_governance_list_proposals(
        &self,
        handle: &NapiContextHandle,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_governance_list_proposals_on(&self.inner, handle).await
    }

    /// Per-instance equivalent of the free-function `context_apply_pending_ceiling_modification`.
    #[napi(js_name = "contextApplyPendingCeilingModification")]
    pub async fn context_apply_pending_ceiling_modification(
        &self,
        handle: &NapiContextHandle,
        current_timestamp: f64,
    ) -> napi::Result<bool> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_apply_pending_ceiling_modification_on(
            &self.inner,
            handle,
            current_timestamp,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `context_finalize_close`.
    #[napi(js_name = "contextFinalizeClose")]
    pub async fn context_finalize_close(&self, handle: &NapiContextHandle) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_finalize_close_on(&self.inner, handle).await
    }

    /// Per-instance equivalent of the free-function `context_create_governance_checkpoint`.
    #[napi(js_name = "contextCreateGovernanceCheckpoint")]
    #[allow(clippy::too_many_arguments)]
    pub async fn context_create_governance_checkpoint(
        &self,
        handle: &NapiContextHandle,
        checkpoint_seq: f64,
        merkle_root_hex: String,
        event_count: f64,
        last_event_hash_hex: String,
        state_snapshot_hash_hex: String,
        creator_did: String,
        creator_signature_hex: String,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_create_governance_checkpoint_on(
            &self.inner,
            handle,
            checkpoint_seq,
            merkle_root_hex,
            event_count,
            last_event_hash_hex,
            state_snapshot_hash_hex,
            creator_did,
            creator_signature_hex,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `context_add_checkpoint_cosignature`.
    #[napi(js_name = "contextAddCheckpointCosignature")]
    pub async fn context_add_checkpoint_cosignature(
        &self,
        handle: &NapiContextHandle,
        checkpoint_json: String,
        signer_did: String,
        signature_hex: String,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_add_checkpoint_cosignature_on(
            &self.inner,
            handle,
            checkpoint_json,
            signer_did,
            signature_hex,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `context_restore`.
    #[napi(js_name = "contextRestore")]
    pub async fn context_restore(&self, context_id: String) -> napi::Result<()> {
        crate::context::context_restore_on(&self.inner, context_id).await
    }

    /// Per-instance equivalent of the free-function `context_restore_all`.
    #[napi(js_name = "contextRestoreAll")]
    pub async fn context_restore_all(&self) -> napi::Result<String> {
        crate::context::context_restore_all_on(&self.inner).await
    }

    /// Per-instance equivalent of the free-function `context_tombstone_migrated`.
    #[napi(js_name = "contextTombstoneMigrated")]
    pub async fn context_tombstone_migrated(&self, handle: &NapiContextHandle) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_tombstone_migrated_on(&self.inner, handle).await
    }

    /// Per-instance equivalent of the free-function `context_migration_state`.
    #[napi(js_name = "contextMigrationState")]
    pub async fn context_migration_state(
        &self,
        handle: &NapiContextHandle,
    ) -> napi::Result<Option<String>> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_migration_state_on(&self.inner, handle).await
    }

    /// Per-instance equivalent of the free-function `context_handle_ttl_expiry`.
    #[napi(js_name = "contextHandleTtlExpiry")]
    pub async fn context_handle_ttl_expiry(&self, handle: &NapiContextHandle) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_handle_ttl_expiry_on(&self.inner, handle).await
    }

    /// Per-instance equivalent of the free-function `context_propose_ttl_extension`.
    #[napi(js_name = "contextProposeTtlExtension")]
    pub async fn context_propose_ttl_extension(
        &self,
        handle: &NapiContextHandle,
        proposer_did: String,
        extension_secs: u32,
    ) -> napi::Result<bool> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_propose_ttl_extension_on(
            &self.inner,
            handle,
            proposer_did,
            extension_secs,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `context_reset_ttl_timer`.
    #[napi(js_name = "contextResetTtlTimer")]
    pub async fn context_reset_ttl_timer(
        &self,
        handle: &NapiContextHandle,
        new_duration_secs: u32,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_reset_ttl_timer_on(&self.inner, handle, new_duration_secs).await
    }

    /// Per-instance equivalent of the free-function `context_export`.
    #[napi(js_name = "contextExport")]
    pub async fn context_export(&self, handle: &NapiContextHandle) -> napi::Result<Vec<u8>> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_export_on(&self.inner, handle).await
    }

    /// Per-instance equivalent of the free-function `context_import`.
    ///
    /// `importer_did` identifies the importing member; the bridge resolves that
    /// identity from its registry and derives the §9.10.4 per-context pseudonym
    /// routing ID, so the importer routes under its OWN pseudonym rather than
    /// inheriting the exporter's local-instance pseudonym. Mirrors the
    /// `contextJoin` DID-string convention.
    #[napi(js_name = "contextImport")]
    pub async fn context_import(
        &self,
        data: Vec<u8>,
        importer_did: String,
    ) -> napi::Result<String> {
        crate::context::context_import_on(&self.inner, data, importer_did).await
    }

    /// Per-instance equivalent of the free-function `context_set_economic_policy`.
    #[napi(js_name = "contextSetEconomicPolicy")]
    #[allow(clippy::used_underscore_binding)] // param exists for API surface; body rejects all calls
    pub fn context_set_economic_policy(
        &self,
        handle: &mut NapiContextHandle,
        _policy_json: String,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_set_economic_policy_on(&self.inner, handle, _policy_json)
    }

    /// Per-instance equivalent of the free-function `context_get_economic_policy`.
    #[napi(js_name = "contextGetEconomicPolicy")]
    pub fn context_get_economic_policy(
        &self,
        handle: &NapiContextHandle,
    ) -> napi::Result<Option<String>> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_get_economic_policy_on(&self.inner, handle)
    }

    /// Per-instance equivalent of the free-function `validate_capability_declaration`.
    #[napi(js_name = "validateCapabilityDeclaration")]
    pub fn validate_capability_declaration(
        &self,
        declaration_json: String,
        ceiling_capabilities: Vec<String>,
        role_capabilities: Vec<String>,
    ) -> napi::Result<String> {
        crate::context::validate_capability_declaration_on(
            &self.inner,
            declaration_json,
            ceiling_capabilities,
            role_capabilities,
        )
    }

    // `check_scoped_capability` is exposed as a module-level free fn at
    // `crates/scp-ffi/napi/src/context.rs::check_scoped_capability` per
    // ADR-048 §1 — the operation reads no `Scp` state, so binding it to
    // the receiver is pure ceremony. The TypeScript SDK's
    // `SCP.checkScopedCapability` routes through `nativeFreeFn(...)` to
    // reach the module-level export.

    /// Per-instance equivalent of the free-function `evaluate_invitation`.
    #[napi(js_name = "evaluateInvitation")]
    pub fn evaluate_invitation(
        &self,
        params_json: String,
        inviter_did: String,
        identity_did: String,
        policy_json: Option<String>,
        spending_json: Option<String>,
    ) -> napi::Result<NapiEvaluationResult> {
        crate::context::evaluate_invitation_on(
            &self.inner,
            params_json,
            inviter_did,
            identity_did,
            policy_json,
            spending_json,
        )
    }

    /// Per-instance equivalent of the free-function `metadata_record_to_json`.
    #[napi(js_name = "metadataRecordToJson")]
    #[allow(clippy::too_many_arguments)]
    pub fn metadata_record_to_json(
        &self,
        context_id: String,
        sequence: u32,
        signer_did: String,
        timestamp: f64,
        structural_json: String,
        operational_json: String,
        signature_hex: String,
    ) -> napi::Result<String> {
        crate::context::metadata_record_to_json_on(
            &self.inner,
            context_id,
            sequence,
            signer_did,
            timestamp,
            structural_json,
            operational_json,
            signature_hex,
        )
    }

    // ===== sub-slice C: outlets =====

    /// Per-instance equivalent of the free-function `outlet_register`.
    #[napi(js_name = "outletRegister")]
    pub async fn outlet_register(
        &self,
        handle: &NapiContextHandle,
        definition: NapiOutletDefinition,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::outlets::outlet_register_on(&self.inner, handle, definition).await
    }

    /// Per-instance equivalent of the free-function `outlet_invoke`.
    #[napi(js_name = "outletInvoke")]
    #[allow(clippy::too_many_arguments)]
    pub async fn outlet_invoke(
        &self,
        handle: &NapiContextHandle,
        outlet_id: String,
        input_json: String,
        identity_did: String,
        ucan_token: String,
        proof_tokens: Option<Vec<String>>,
        spending_ucan_jwt: Option<String>,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::outlets::outlet_invoke_on(
            &self.inner,
            handle,
            outlet_id,
            input_json,
            identity_did,
            ucan_token,
            proof_tokens,
            spending_ucan_jwt,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `outlet_verify`.
    #[napi(js_name = "outletVerify")]
    pub async fn outlet_verify(
        &self,
        handle: &NapiContextHandle,
        outlet_id: String,
    ) -> napi::Result<NapiOutletVerificationResult> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::outlets::outlet_verify_on(&self.inner, handle, outlet_id).await
    }

    // ===== §5.4.5 streaming-native outlet invocation (SCP-OUT-037, C8a) =====

    /// Opens a §5.4.5 streaming outlet invocation, returning a `StreamHandleId`
    /// PROMPTLY (Commit transition — never block-until-terminal).
    ///
    /// The UCAN is validated ONCE at open via the full 11-step ADR-016 pipeline;
    /// the invoker is pinned for the stream's lifetime. Drive the stream via
    /// `outletStreamPollNext` / `_grantCredit` / `_cancel` / `_terminate` with
    /// the SAME `caller_did`.
    #[napi(js_name = "outletStreamOpen")]
    #[allow(clippy::too_many_arguments)]
    pub async fn outlet_stream_open(
        &self,
        handle: &NapiContextHandle,
        outlet_id: String,
        input_json: String,
        caller_did: String,
        ucan_token: String,
        proof_tokens: Option<Vec<String>>,
        spending_ucan: Option<String>,
        timeout_ms: Option<u32>,
        estimated_chunk_count: Option<u32>,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::outlet_stream::outlet_stream_open_on(
            &self.inner,
            handle,
            outlet_id,
            input_json,
            caller_did,
            ucan_token,
            proof_tokens,
            spending_ucan,
            timeout_ms,
            estimated_chunk_count,
        )
        .await
    }

    /// Drains one chunk from a live stream, awaiting the pump until a chunk
    /// arrives or the stream closes. Returns the JSON-serialized
    /// `OutletStreamChunk` bytes, or `None` at the terminal (which evicts the
    /// stream). An unknown/evicted handle is a DISTINCT error, never `None`.
    #[napi(js_name = "outletStreamPollNext")]
    pub async fn outlet_stream_poll_next(&self, handle_id: String) -> napi::Result<Option<Buffer>> {
        crate::outlet_stream::outlet_stream_poll_next_on(&self.inner, &handle_id)
            .await
            .map(|opt| opt.map(Buffer::from))
    }

    /// Grants `grant` additional billable chunks of credit to a live stream. The
    /// bridge signs the `OutletStreamCredit` internally under the pinned
    /// invoker's custody key and auto-assigns the monotonic sequence, so the
    /// caller supplies only a `u32` — no key access, no replay-counter tracking.
    #[napi(js_name = "outletStreamGrantCredit")]
    pub async fn outlet_stream_grant_credit(
        &self,
        handle_id: String,
        caller_did: String,
        grant: u32,
    ) -> napi::Result<()> {
        crate::outlet_stream::outlet_stream_grant_credit_on(
            &self.inner,
            &handle_id,
            &caller_did,
            grant,
        )
        .await
    }

    /// Signs and applies a stream cancel at the runtime-derived cursor
    /// (CRITICAL #3 — the bridge never supplies a `next_seq`).
    #[napi(js_name = "outletStreamCancel")]
    pub async fn outlet_stream_cancel(
        &self,
        handle_id: String,
        caller_did: String,
    ) -> napi::Result<()> {
        crate::outlet_stream::outlet_stream_cancel_on(&self.inner, &handle_id, &caller_did).await
    }

    /// Forces a framework terminal chunk. `slug` selects a closed-set terminal
    /// reason; the canonical code is derived internally from the reason;
    /// `message` is a human suffix.
    #[napi(js_name = "outletStreamTerminate")]
    pub async fn outlet_stream_terminate(
        &self,
        handle_id: String,
        caller_did: String,
        slug: String,
        message: String,
    ) -> napi::Result<()> {
        crate::outlet_stream::outlet_stream_terminate_on(
            &self.inner,
            &handle_id,
            &caller_did,
            &slug,
            &message,
        )
        .await
    }

    /// Pure wrapper: verifies a chunk's operator signature (§5.4.5).
    #[napi(js_name = "outletStreamVerifyChunkSignature")]
    pub fn outlet_stream_verify_chunk_signature(
        &self,
        chunk_bytes: Buffer,
        operator_pk: Buffer,
        context_id: String,
        outlet_id: String,
        caveats_binding: Buffer,
    ) -> napi::Result<bool> {
        crate::outlet_stream::outlet_stream_verify_chunk_signature_impl(
            chunk_bytes.as_ref(),
            operator_pk.as_ref(),
            &context_id,
            &outlet_id,
            caveats_binding.as_ref(),
        )
        .map_err(napi::Error::from)
    }

    /// Pure wrapper: computes the §5.4.5 `caveats_binding` (32 bytes).
    #[napi(js_name = "outletStreamComputeCaveatsBinding")]
    pub fn outlet_stream_compute_caveats_binding(
        &self,
        ucan_cid: Buffer,
        request_id: Buffer,
        invoker_did: String,
        estimated_chunk_count: u32,
        effective_caveats_jcs: Buffer,
    ) -> napi::Result<Buffer> {
        crate::outlet_stream::outlet_stream_compute_caveats_binding_impl(
            ucan_cid.as_ref(),
            request_id.as_ref(),
            &invoker_did,
            estimated_chunk_count,
            effective_caveats_jcs.as_ref(),
        )
        .map(Buffer::from)
        .map_err(napi::Error::from)
    }

    // ===== §5.4.5 / §6.2.4 cross-context streaming saga (SCP-OUT-047) =====

    /// Opens a §5.4.5 / §6.2.4 CROSS-CONTEXT streaming outlet invocation as a
    /// saga (SCP-OUT-047), returning the durable `saga_id` PROMPTLY (the
    /// Commit-transition — NOT a block-until-terminal; the seal pumps
    /// off-mailbox). Drive the stream via `outletStreamingSagaPollNext` with the
    /// returned `saga_id`.
    ///
    /// The invocation UCAN is validated ONCE at open via the full 11-step
    /// ADR-016 pipeline against the TARGET context B. `caller_did` is bound to
    /// this bridge instance's channel-authenticated principal (§6.2.4) and must
    /// be a member of `source_handle`'s context — a mismatch rejects with a typed
    /// `SagaAborted` (SCP-SAGA-13050) BEFORE the saga runs, so the receiver is
    /// never handed out.
    ///
    /// # Arguments
    ///
    /// * `source_handle` — The initiating (caller) context handle.
    /// * `target_handle` — The executing (target) context handle hosting the outlet.
    /// * `caller_did` — The initiator DID (bound to the bridge principal).
    /// * `outlet_registration_id` — The outlet to invoke across the interface.
    /// * `input_json` — Outlet input as a JSON string (schema-checked target-side).
    /// * `asserted_nonce_hex` — The 16-byte §6.2.4 envelope nonce (32-char hex).
    /// * `timestamp_ms` — Caller-asserted send time (Unix ms), passed as a JS `BigInt`.
    /// * `chain_depth` — Caller-asserted inbound provenance depth (advisory).
    /// * `ucan_token` — The invocation UCAN authorizing the outlet call.
    /// * `proof_tokens` — Optional delegation-chain proof tokens.
    /// * `ucan_proof_id` — Optional id of the spending UCAN proof, resolved
    ///   target-side at Prepare-B.
    /// * `timeout_ms` / `estimated_chunk_count` — Optional stream policy hints.
    #[napi(js_name = "outletStreamingSagaOpen")]
    #[allow(clippy::too_many_arguments)]
    pub async fn outlet_streaming_saga_open(
        &self,
        source_handle: &NapiContextHandle,
        target_handle: &NapiContextHandle,
        caller_did: String,
        outlet_registration_id: String,
        input_json: String,
        asserted_nonce_hex: String,
        timestamp_ms: napi::bindgen_prelude::BigInt,
        chain_depth: u8,
        ucan_token: String,
        proof_tokens: Option<Vec<String>>,
        ucan_proof_id: Option<String>,
        timeout_ms: Option<u32>,
        estimated_chunk_count: Option<u32>,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, source_handle, target_handle);

        // `timestamp_ms` crosses as a JS `BigInt`. Reject a negative or
        // non-lossless input so a malformed freshness field fails closed at the
        // boundary rather than wrapping into a bogus skew (parity with the unary
        // saga export).
        let (signed, timestamp_ms_u64, lossless) = timestamp_ms.get_u64();
        if signed || !lossless {
            return Err(napi::Error::from(ScpNapiError::Validation {
                message:
                    "timestamp_ms must fit in an unsigned 64-bit integer (non-negative, no loss)"
                        .to_owned(),
                code: codes::VALID_7001.to_owned(),
            }));
        }

        Box::pin(crate::outlet_stream::outlet_streaming_saga_open_on(
            &self.inner,
            source_handle,
            target_handle,
            caller_did,
            outlet_registration_id,
            input_json,
            asserted_nonce_hex,
            timestamp_ms_u64,
            chain_depth,
            ucan_token,
            proof_tokens,
            ucan_proof_id,
            timeout_ms,
            estimated_chunk_count,
        ))
        .await
    }

    /// Drains one chunk from a live cross-context streaming saga, awaiting until
    /// a chunk arrives or the stream closes. Returns the JSON-serialized
    /// `OutletStreamChunk` bytes (A's plaintext operator-signed frame), or `None`
    /// at the terminal (which evicts the saga stream). An unknown/evicted
    /// `saga_id` is a DISTINCT error, never `None`.
    #[napi(js_name = "outletStreamingSagaPollNext")]
    pub async fn outlet_streaming_saga_poll_next(
        &self,
        saga_id: String,
    ) -> napi::Result<Option<Buffer>> {
        crate::outlet_stream::outlet_streaming_saga_poll_next_on(&self.inner, &saga_id)
            .await
            .map(|opt| opt.map(Buffer::from))
    }

    /// Key-bearing in-session reconnect/repair truncated-close for a cross-context
    /// streaming saga (SCP-OUT-046 #136 AC7): seals the durable prefix with the
    /// TARGET context's Active Signing Key (resolved per-call from custody) and
    /// resolves the saga `Committed` WITHOUT re-opening the stream or re-invoking
    /// the executor. Recovers a seal that stalled / went `NeedsRepair` while THIS
    /// bridge process is still alive; the saga registry is per-instance and
    /// in-memory, so it does NOT survive a process/node restart (cross-restart
    /// recovery is a separate durable-journal operator path, §17.16).
    /// `caller_did` must be an identity hosted by this bridge instance (§6.2.4
    /// channel-auth) AND the invoker pinned at open (CRITICAL #1 — recovery is
    /// money-moving; rejects `SCP-PERM-3001` otherwise). On success the saga
    /// registry entry is evicted.
    #[napi(js_name = "outletStreamingSagaRecoverTruncatedClose")]
    pub async fn outlet_streaming_saga_recover_truncated_close(
        &self,
        saga_id: String,
        caller_did: String,
    ) -> napi::Result<()> {
        crate::outlet_stream::outlet_streaming_saga_recover_truncated_close_on(
            &self.inner,
            &saga_id,
            &caller_did,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `outlet_invoke_cross_context`.
    #[napi(js_name = "outletInvokeCrossContext")]
    #[allow(clippy::too_many_arguments)]
    pub async fn outlet_invoke_cross_context(
        &self,
        source_handle: &NapiContextHandle,
        target_handle: &NapiContextHandle,
        outlet_id: String,
        input_json: String,
        invoker_did: String,
        ucan_token: String,
        chain_depth: u8,
        proof_tokens: Option<Vec<String>>,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, source_handle, target_handle);
        crate::outlets::outlet_invoke_cross_context_on(
            &self.inner,
            source_handle,
            target_handle,
            outlet_id,
            input_json,
            invoker_did,
            ucan_token,
            chain_depth,
            proof_tokens,
        )
        .await
    }

    /// Invokes an outlet across context boundaries as an atomic two-phase saga
    /// (spec §6.2.4, ADR-049 §3a).
    ///
    /// Unlike [`Self::outlet_invoke_cross_context`] (the synchronous,
    /// single-context-side path), this drives the full §6.2.4 cross-context
    /// outlet-invocation saga over the two CO-RESIDENT participant contexts
    /// (caller = `source_handle`, target = `target_handle`): Prepare-A /
    /// Prepare-B authorize and stage both sides, the outlet executes EXACTLY ONCE
    /// supervisor-side at Commit-B, and each side records its own event-log
    /// entry. Both contexts MUST be co-resident in this bridge instance.
    ///
    /// # Caller authentication (normative — §6.2.4, ADR-049 §3a)
    ///
    /// `caller_did` is bound to the bridge-authenticated principal: it MUST be
    /// an identity THIS bridge instance hosts (created here via identity
    /// creation) AND a member of the caller (`source_handle`) context. A
    /// mismatch rejects the Promise with a `SagaAborted` error BEFORE the saga
    /// runs — the saga never observes an unauthenticated caller. The
    /// `asserted_nonce_hex` / `timestamp_ms` / `chain_depth` REMAIN
    /// caller-supplied freshness fields (the target validates them).
    ///
    /// # Trust boundary (co-resident single-tenant only)
    ///
    /// The caller-principal binding (`enforce_caller_principal_binding`) treats
    /// "hosted in this bridge instance's identity registry" as the
    /// channel-authenticated principal. That equivalence holds ONLY for a
    /// single-tenant, co-resident SDK process. This surface MUST NOT be exposed
    /// across a trust boundary within one process: a multi-tenant host loading
    /// multiple users' identities into one bridge instance could assert any
    /// hosted `caller_did`, since the registry cannot distinguish which tenant
    /// is making the call. The future cross-node leg needs real channel auth
    /// (ADR-049 §3a forward obligation) — it cannot reuse "is hosted here" as
    /// the authenticated-principal proof.
    ///
    /// The caller/target context-id axes are bound by the instance-affine
    /// handle pre-check: `source_handle` / `target_handle` must have been minted
    /// by THIS bridge instance (a foreign handle is rejected with
    /// `SCP-PERM-3030`) before the supervisor membership / outlet-interface gates
    /// run.
    ///
    /// The receipt's signer-authorization — that the target key is
    /// governance-authorized to act for the target context (§6.2.4 "Signer
    /// authorization") — is a DOWNSTREAM receipt-consumer obligation verified
    /// when the receipt is consumed, NOT enforced at this export.
    ///
    /// # Arguments
    ///
    /// * `source_handle` — The initiating (caller) context handle.
    /// * `target_handle` — The executing (target) context handle.
    /// * `caller_did` — The initiator DID (bound to the bridge principal).
    /// * `outlet_registration_id` — The outlet to invoke across the interface.
    /// * `input_json` — Outlet input as a JSON string (schema-checked target-side).
    /// * `asserted_nonce_hex` — The 16-byte §6.2.4 envelope nonce as a 32-char
    ///   hex string (the freshness/dedup token).
    /// * `timestamp_ms` — Caller-asserted send time (Unix ms; freshness check),
    ///   passed as a JS `BigInt`.
    /// * `chain_depth` — Caller-asserted inbound provenance depth (advisory).
    /// * `ucan_proof_id` — Optional id of the spending UCAN proof, resolved
    ///   target-side at Prepare-B. `null` for an ungated outlet.
    ///
    /// # Returns
    ///
    /// A [`NapiSagaResult`](crate::outlets::NapiSagaResult) on the committed
    /// terminal, carrying the supervisor-minted `saga_id`, the target's signed
    /// receipt bytes, and the captured outlet-output bytes. The `saga_id` is
    /// supervisor-minted — it is never an input.
    ///
    /// # Errors
    ///
    /// Rejects with a typed saga error — `SagaAborted` (a Prepare-phase abort
    /// that may be a permanent rejection — authorization, freshness, rate limit,
    /// or co-residency — OR a retryable transient: a rate limit, or a
    /// participant actor unavailable to complete the Prepare exchange; carries
    /// `retry_after_ms`), `SagaNeedsRepair` (Commit-retry exhausted —
    /// carries the durable `saga_id`), or `SagaBusy` (the participant context
    /// set overlapped an in-flight saga — §5.15.4). Rejects with a validation
    /// error if an id/DID/outlet-id is malformed or `asserted_nonce_hex` does not
    /// decode to 16 bytes.
    ///
    /// See spec §6.2.4 and ADR-049 §3a.
    #[napi(js_name = "outletInvokeCrossContextSaga")]
    #[allow(clippy::too_many_arguments)]
    pub async fn outlet_invoke_cross_context_saga(
        &self,
        source_handle: &NapiContextHandle,
        target_handle: &NapiContextHandle,
        caller_did: String,
        outlet_registration_id: String,
        input_json: String,
        asserted_nonce_hex: String,
        timestamp_ms: napi::bindgen_prelude::BigInt,
        chain_depth: u8,
        ucan_proof_id: Option<String>,
    ) -> napi::Result<crate::outlets::NapiSagaResult> {
        crate::napi_check_handle!(&self.inner.core, source_handle, target_handle);

        // `timestamp_ms` crosses as a JS `BigInt`. `BigInt::get_u64` returns
        // `(signed, value, lossless)` — reject a negative or non-lossless
        // input so a malformed freshness field fails closed at the boundary
        // rather than wrapping into a bogus skew.
        let (signed, timestamp_ms_u64, lossless) = timestamp_ms.get_u64();
        if signed || !lossless {
            return Err(napi::Error::from(ScpNapiError::Validation {
                message:
                    "timestamp_ms must fit in an unsigned 64-bit integer (non-negative, no loss)"
                        .to_owned(),
                code: codes::VALID_7001.to_owned(),
            }));
        }

        // Box the impl future: the multi-phase saga it drives is large enough
        // to trip `clippy::large_futures` when inlined into this method.
        Box::pin(crate::outlets::outlet_invoke_cross_context_saga_on(
            &self.inner,
            source_handle,
            target_handle,
            caller_did,
            outlet_registration_id,
            input_json,
            asserted_nonce_hex,
            timestamp_ms_u64,
            chain_depth,
            ucan_proof_id,
        ))
        .await
    }

    /// Per-instance equivalent of the free-function `outlet_session_create`.
    #[napi(js_name = "outletSessionCreate")]
    pub async fn outlet_session_create(
        &self,
        handle: &NapiContextHandle,
        outlet_id: String,
        source_context_id: String,
        ttl_seconds: Option<u32>,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::outlets::outlet_session_create_on(
            &self.inner,
            handle,
            outlet_id,
            source_context_id,
            ttl_seconds,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `outlet_session_invoke`.
    #[napi(js_name = "outletSessionInvoke")]
    pub async fn outlet_session_invoke(
        &self,
        handle: &NapiContextHandle,
        session_id: String,
        input_json: String,
        invoker_did: String,
        ucan_token: String,
        proof_tokens: Option<Vec<String>>,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::outlets::outlet_session_invoke_on(
            &self.inner,
            handle,
            session_id,
            input_json,
            invoker_did,
            ucan_token,
            proof_tokens,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `outlet_session_close`.
    #[napi(js_name = "outletSessionClose")]
    pub async fn outlet_session_close(
        &self,
        handle: &NapiContextHandle,
        session_id: String,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::outlets::outlet_session_close_on(&self.inner, handle, session_id).await
    }

    /// Per-instance equivalent of the free-function `outlet_interface_expose`.
    #[napi(js_name = "outletInterfaceExpose")]
    pub async fn outlet_interface_expose(
        &self,
        handle: &NapiContextHandle,
        outlet_id: String,
        target_context_id: String,
        rate_limit_json: Option<String>,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::outlets::outlet_interface_expose_on(
            &self.inner,
            handle,
            outlet_id,
            target_context_id,
            rate_limit_json,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `outlet_interface_accept`.
    #[napi(js_name = "outletInterfaceAccept")]
    pub async fn outlet_interface_accept(
        &self,
        handle: &NapiContextHandle,
        interface_json: String,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::outlets::outlet_interface_accept_on(&self.inner, handle, interface_json).await
    }

    /// Per-instance equivalent of the free-function `outlet_interface_revoke`.
    #[napi(js_name = "outletInterfaceRevoke")]
    pub async fn outlet_interface_revoke(
        &self,
        handle: &NapiContextHandle,
        interface_id_hex: String,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::outlets::outlet_interface_revoke_on(&self.inner, handle, interface_id_hex).await
    }

    // ====================================================================
    // #1549 Phase 4 PR 4 — sub-slice D: ucan/event-log/transport/economy/
    // trust/server operations on SCP.
    //
    // Each method delegates to the per-bridge-instance `_on` helpers in
    // [`crate::ucan`] / [`crate::event_log`] / [`crate::transport`] /
    // [`crate::economy`] / [`crate::trust`] / [`crate::server`], routing
    // through `&*self.inner` so operations are scoped to this `SCP`'s
    // bridge instance. The free-function façade that predated this
    // migration was deleted in the Phase 4 PR 4 demolition slice
    // (ADR-048).
    // ====================================================================

    // -------------------------------------------------------------------
    // UCAN
    // -------------------------------------------------------------------

    /// Per-instance equivalent of the free-function `ucan_validate`.
    #[napi(js_name = "ucanValidate")]
    pub async fn ucan_validate(
        &self,
        handle: &NapiContextHandle,
        token: String,
        capability: String,
        presenting_agent_did: String,
        proof_tokens: Option<Vec<String>>,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::ucan::ucan_validate_on(
            &self.inner,
            handle,
            token,
            capability,
            presenting_agent_did,
            proof_tokens,
        )
        .await
    }

    /// Diagnostic, read-only evaluation of a UCAN token.
    ///
    /// Counterpart to `ucanValidate`: runs the same 11-step ADR-016 pipeline
    /// but returns a structured `NapiCapabilityValidation` (six booleans,
    /// camelCased for JS) instead of throwing, and never records the token's
    /// nonce.
    ///
    /// `capability` is OPTIONAL: omit it (or pass `null`/empty) to evaluate the
    /// token's intrinsic validity with no invoked-capability grant-match
    /// challenge — the mode the SDK trust signal uses. Pass a capability to
    /// additionally require the token grants it. (The enforcing `ucanValidate`
    /// gate keeps a mandatory capability.)
    #[napi(js_name = "ucanEvaluate")]
    pub async fn ucan_evaluate(
        &self,
        handle: &NapiContextHandle,
        token: String,
        capability: Option<String>,
        presenting_agent_did: String,
        proof_tokens: Option<Vec<String>>,
    ) -> napi::Result<crate::ucan::NapiCapabilityValidation> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::ucan::ucan_evaluate_on(
            &self.inner,
            handle,
            token,
            capability,
            presenting_agent_did,
            proof_tokens,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `ucan_mint`.
    #[napi(js_name = "ucanMint")]
    pub async fn ucan_mint(
        &self,
        handle: &NapiContextHandle,
        member_did: String,
        capabilities: Vec<String>,
        proofs: Option<Vec<String>>,
    ) -> napi::Result<NapiUcanToken> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::ucan::ucan_mint_on(&self.inner, handle, member_did, capabilities, proofs).await
    }

    /// Per-instance equivalent of the free-function `ucan_delegate`.
    #[napi(js_name = "ucanDelegate")]
    pub async fn ucan_delegate(
        &self,
        handle: &NapiContextHandle,
        delegator_did: String,
        delegatee_did: String,
        parent_token: String,
        capabilities: Vec<String>,
    ) -> napi::Result<NapiUcanToken> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::ucan::ucan_delegate_on(
            &self.inner,
            handle,
            delegator_did,
            delegatee_did,
            parent_token,
            capabilities,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `ucan_revoke`.
    #[napi(js_name = "ucanRevoke")]
    pub async fn ucan_revoke(
        &self,
        handle: &NapiContextHandle,
        token: String,
        revoker_did: String,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::ucan::ucan_revoke_on(&self.inner, handle, token, revoker_did).await
    }

    // -------------------------------------------------------------------
    // Event log
    // -------------------------------------------------------------------

    /// Per-instance equivalent of the free-function `event_log_query`.
    #[napi(js_name = "eventLogQuery")]
    pub async fn event_log_query(
        &self,
        handle: &NapiContextHandle,
        filter_json: Option<String>,
    ) -> napi::Result<Vec<NapiEvent>> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::event_log::event_log_query_on(&self.inner, handle, filter_json).await
    }

    /// Per-instance equivalent of the free-function `event_log_verify`.
    #[napi(js_name = "eventLogVerify")]
    pub async fn event_log_verify(
        &self,
        handle: &NapiContextHandle,
        claim_json: String,
    ) -> napi::Result<NapiProof> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::event_log::event_log_verify_on(&self.inner, handle, claim_json).await
    }

    /// Per-instance equivalent of the free-function `event_log_checkpoint`.
    #[napi(js_name = "eventLogCheckpoint")]
    pub fn event_log_checkpoint(
        &self,
        handle: &NapiContextHandle,
        identity: &NapiIdentity,
        epoch: f64,
    ) -> napi::Result<NapiCheckpoint> {
        crate::napi_check_handle!(&self.inner.core, handle, identity);
        crate::event_log::event_log_checkpoint_on(&self.inner, handle, identity, epoch)
    }

    /// Per-instance equivalent of the free-function `event_log_checkpoint_by_did`.
    #[napi(js_name = "eventLogCheckpointByDid")]
    pub fn event_log_checkpoint_by_did(
        &self,
        handle: &NapiContextHandle,
        did: String,
        epoch: f64,
    ) -> napi::Result<NapiCheckpoint> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::event_log::event_log_checkpoint_by_did_on(&self.inner, handle, did, epoch)
    }

    /// Returns the event-log summary the MCP `events` resource publishes for a
    /// context, as a JSON string.
    ///
    /// This is the exact metadata `ContextProvider::context_events` serves for
    /// `scp://{context_id}/events` — `{"event_count": N, "merkle_root": "<hex>"}`
    /// over the AUTHORITATIVE event log, the SAME `(count, root)`
    /// `eventLogVerify` / `eventLogCheckpoint` commit to — routed through the ONE
    /// shared `context_events_metadata_json` helper so the bytes are identical
    /// across all three bridges (GitHub #1933). Never reads a bridge-local tree.
    /// FAILS CLOSED to `{"error": ..., "code": "SCP-CTX-2138"}` (no
    /// `event_count` / `merkle_root`) when the authoritative log is unreachable.
    #[napi(js_name = "mcpContextEvents")]
    pub fn mcp_context_events(&self, handle: &NapiContextHandle) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        Ok(crate::mcp::mcp_context_events_on(&self.inner, handle))
    }

    // -------------------------------------------------------------------
    // Transport
    // -------------------------------------------------------------------

    /// Per-instance equivalent of the free-function `transport_connect`.
    #[napi(js_name = "transportConnect")]
    pub async fn transport_connect(&self, relay_url: String) -> napi::Result<NapiTransportManager> {
        crate::transport::transport_connect_on(&self.inner, relay_url).await
    }

    /// Per-instance equivalent of the free-function `transport_status`.
    ///
    /// Accepts an optional transport manager handle. When `null`/`undefined`,
    /// returns the bridge-scoped handleless probe (mirrors `PyO3`).
    #[napi(js_name = "transportStatus")]
    pub async fn transport_status(
        &self,
        manager: Option<&NapiTransportManager>,
    ) -> napi::Result<NapiTransportStatus> {
        crate::transport::transport_status_on(&self.inner, manager).await
    }

    /// Per-instance equivalent of the free-function `transport_disconnect`.
    #[napi(js_name = "transportDisconnect")]
    pub async fn transport_disconnect(&self, manager: &NapiTransportManager) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, manager);
        crate::transport::transport_disconnect_on(&self.inner, manager).await
    }

    /// Per-instance equivalent of the free-function `configure_local_transport`.
    #[napi(js_name = "configureLocalTransport")]
    pub fn configure_local_transport(&self, local_did: String) -> napi::Result<()> {
        crate::transport::configure_local_transport_on(&self.inner, local_did)
    }

    /// Per-instance equivalent of the free-function `configure_relay_transport`.
    #[napi(js_name = "configureRelayTransport")]
    pub async fn configure_relay_transport(
        &self,
        relay_url: String,
        local_did: String,
    ) -> napi::Result<()> {
        crate::transport::configure_relay_transport_on(&self.inner, relay_url, local_did).await
    }

    /// Per-instance equivalent of the free-function `transport_add_relay`.
    #[napi(js_name = "transportAddRelay")]
    pub async fn transport_add_relay(&self, relay_url: String) -> napi::Result<u32> {
        crate::transport::transport_add_relay_on(&self.inner, relay_url).await
    }

    /// Per-instance equivalent of the free-function `transport_assign_relay_set`.
    #[napi(js_name = "transportAssignRelaySet")]
    pub fn transport_assign_relay_set(&self, context_id: String) -> napi::Result<Vec<u32>> {
        crate::transport::transport_assign_relay_set_on(&self.inner, context_id)
    }

    /// Per-instance equivalent of the free-function `transport_adapter_count`.
    #[napi(js_name = "transportAdapterCount")]
    pub fn transport_adapter_count(&self) -> napi::Result<u32> {
        crate::transport::transport_adapter_count_on(&self.inner)
    }

    /// Per-instance equivalent of the free-function `transport_reliability`.
    #[napi(js_name = "transportReliability")]
    pub fn transport_reliability(
        &self,
        adapter_index: u32,
    ) -> napi::Result<Option<NapiReliabilityScore>> {
        crate::transport::transport_reliability_on(&self.inner, adapter_index)
    }

    // -------------------------------------------------------------------
    // Economy
    // -------------------------------------------------------------------

    /// Per-instance equivalent of the free-function `economy_estimate_cost`.
    #[napi(js_name = "economyEstimateCost")]
    pub fn economy_estimate_cost(
        &self,
        policy_json: String,
        action_type: String,
        metrics_json: String,
    ) -> napi::Result<napi::bindgen_prelude::BigInt> {
        crate::economy::economy_estimate_cost_on(
            &self.inner,
            policy_json,
            action_type,
            metrics_json,
        )
    }

    /// Per-instance equivalent of the free-function `economy_policy_requires_payment`.
    #[napi(js_name = "economyPolicyRequiresPayment")]
    pub fn economy_policy_requires_payment(&self, policy_json: String) -> napi::Result<bool> {
        crate::economy::economy_policy_requires_payment_on(&self.inner, policy_json)
    }

    /// Per-instance equivalent of the free-function `economy_auto_accept_blocked`.
    #[napi(js_name = "economyAutoAcceptBlocked")]
    pub fn economy_auto_accept_blocked(&self, policy_json: String) -> napi::Result<bool> {
        crate::economy::economy_auto_accept_blocked_on(&self.inner, policy_json)
    }

    /// Per-instance equivalent of the free-function `economy_check_policy_lock`.
    #[napi(js_name = "economyCheckPolicyLock")]
    pub fn economy_check_policy_lock(&self, policy_json: String) -> napi::Result<bool> {
        crate::economy::economy_check_policy_lock_on(&self.inner, policy_json)
    }

    /// Per-instance equivalent of the free-function `economy_validate_policy_change`.
    #[napi(js_name = "economyValidatePolicyChange")]
    pub fn economy_validate_policy_change(
        &self,
        current_policy_json: String,
        proposed_policy_json: String,
    ) -> napi::Result<bool> {
        crate::economy::economy_validate_policy_change_on(
            &self.inner,
            current_policy_json,
            proposed_policy_json,
        )
    }

    /// Per-instance equivalent of the free-function `economy_evaluate_formula`.
    #[napi(js_name = "economyEvaluateFormula")]
    pub fn economy_evaluate_formula(
        &self,
        formula_json: String,
        metrics_json: String,
    ) -> napi::Result<napi::bindgen_prelude::BigInt> {
        crate::economy::economy_evaluate_formula_on(&self.inner, formula_json, metrics_json)
    }

    /// Per-instance equivalent of the free-function `economy_budget_remaining`.
    #[napi(js_name = "economyBudgetRemaining")]
    pub fn economy_budget_remaining(
        &self,
        context_id: String,
        did: String,
    ) -> napi::Result<napi::bindgen_prelude::BigInt> {
        crate::economy::economy_budget_remaining_on(&self.inner, context_id, did)
    }

    /// Per-instance equivalent of the free-function `economy_budget_grant`.
    ///
    /// `amount` is a JS `bigint` so a full `u64` monetary amount round-trips
    /// exactly (ADR-060 SDK-surface rule).
    #[napi(js_name = "economyBudgetGrant")]
    pub fn economy_budget_grant(
        &self,
        context_id: String,
        did: String,
        amount: napi::bindgen_prelude::BigInt,
    ) -> napi::Result<()> {
        crate::economy::economy_budget_grant_on(&self.inner, context_id, did, amount)
    }

    /// Per-instance equivalent of the free-function `economy_budget_record_spend`.
    ///
    /// `amount` is a JS `bigint` so a full `u64` monetary amount round-trips
    /// exactly (ADR-060 SDK-surface rule).
    #[napi(js_name = "economyBudgetRecordSpend")]
    pub fn economy_budget_record_spend(
        &self,
        context_id: String,
        did: String,
        amount: napi::bindgen_prelude::BigInt,
    ) -> napi::Result<()> {
        crate::economy::economy_budget_record_spend_on(&self.inner, context_id, did, amount)
    }

    /// Per-instance equivalent of the free-function `economy_antispam_record`.
    #[napi(js_name = "economyAntispamRecord")]
    pub fn economy_antispam_record(
        &self,
        context_id: String,
        sender_did: String,
        timestamp: i64,
    ) -> napi::Result<()> {
        crate::economy::economy_antispam_record_on(&self.inner, context_id, sender_did, timestamp)
    }

    /// Per-instance equivalent of the free-function `economy_antispam_velocity`.
    #[napi(js_name = "economyAntispamVelocity")]
    pub fn economy_antispam_velocity(
        &self,
        context_id: String,
        sender_did: String,
        now: i64,
    ) -> napi::Result<i64> {
        crate::economy::economy_antispam_velocity_on(&self.inner, context_id, sender_did, now)
    }

    /// Per-instance equivalent of the free-function `economy_antispam_escalated_cost`.
    ///
    /// Monetary amounts (`base_cost`, `floor`, `cap`, and the returned cost) are
    /// JS `bigint` so a full `u64` round-trips exactly (ADR-060 SDK-surface
    /// rule). `now` is a millisecond timestamp, not a monetary amount, and stays
    /// a JS `number`.
    #[napi(js_name = "economyAntispamEscalatedCost")]
    #[allow(clippy::too_many_arguments)]
    pub fn economy_antispam_escalated_cost(
        &self,
        context_id: String,
        sender_did: String,
        now: i64,
        base_cost: napi::bindgen_prelude::BigInt,
        thresholds_json: String,
        floor: Option<napi::bindgen_prelude::BigInt>,
        cap: Option<napi::bindgen_prelude::BigInt>,
    ) -> napi::Result<napi::bindgen_prelude::BigInt> {
        crate::economy::economy_antispam_escalated_cost_on(
            &self.inner,
            context_id,
            sender_did,
            now,
            base_cost,
            thresholds_json,
            floor,
            cap,
        )
    }

    /// Per-instance equivalent of the free-function `economy_verify_payment_receipts`.
    ///
    /// Verifies a JSON array of payment receipts against the supervisor and
    /// returns a JSON `{"results":[...]}` document with one entry per receipt.
    /// Synchronous: the supervisor dispatch is driven on the shared runtime
    /// inside the helper, since libuv worker threads carry no tokio context.
    #[napi(js_name = "economyVerifyPaymentReceipts")]
    pub fn economy_verify_payment_receipts(&self, receipts_json: String) -> napi::Result<String> {
        crate::economy::economy_verify_payment_receipts_on(&self.inner, receipts_json)
    }

    // -------------------------------------------------------------------
    // Trust
    // -------------------------------------------------------------------

    /// Per-instance equivalent of the free-function `trust_query_score`.
    #[napi(js_name = "trustQueryScore")]
    pub fn trust_query_score(
        &self,
        did: String,
        context_id: String,
    ) -> napi::Result<NapiTrustScoreResult> {
        crate::trust::trust_query_score_on(&self.inner, did, context_id)
    }

    /// Per-instance equivalent of the free-function `trust_verify_attestation`.
    #[napi(js_name = "trustVerifyAttestation")]
    pub fn trust_verify_attestation(
        &self,
        attestation_json: String,
    ) -> napi::Result<NapiAttestationVerificationResult> {
        crate::trust::trust_verify_attestation_on(&self.inner, attestation_json)
    }

    /// Per-instance equivalent of the free-function `trust_create_challenge`.
    #[napi(js_name = "trustCreateChallenge")]
    pub fn trust_create_challenge(&self, target_did: String) -> napi::Result<NapiChallengeResult> {
        crate::trust::trust_create_challenge_on(&self.inner, target_did)
    }

    /// Per-instance equivalent of the free-function `trust_verify_response`.
    #[napi(js_name = "trustVerifyResponse")]
    pub fn trust_verify_response(
        &self,
        challenge_json: String,
        response_json: String,
    ) -> napi::Result<bool> {
        crate::trust::trust_verify_response_on(&self.inner, challenge_json, response_json)
    }

    /// Per-instance equivalent of the free-function `verify_participation_requirements`.
    #[napi(js_name = "verifyParticipationRequirements")]
    pub fn verify_participation_requirements(
        &self,
        expected_subject: String,
        requirements_json: String,
        profile_json: String,
    ) -> napi::Result<()> {
        crate::trust::verify_participation_requirements_on(
            &self.inner,
            expected_subject,
            requirements_json,
            profile_json,
        )
    }

    /// Per-instance equivalent of the free-function `check_capability_requirements`.
    ///
    /// Verifies that an agent meets a context's capability requirements for
    /// admission (spec §7.3.4.4). `subjectDid`/`contextId` bind challenge
    /// verifications to the agent and context being admitted. Returns normally
    /// when all requirements are satisfied; throws on any unmet requirement or
    /// malformed JSON.
    #[napi(js_name = "checkCapabilityRequirements")]
    pub fn check_capability_requirements(
        &self,
        context_id: String,
        subject_did: String,
        requirements_json: String,
        agent_capabilities_json: String,
        challenge_verifications_json: String,
    ) -> napi::Result<()> {
        crate::trust::check_capability_requirements_on(
            &self.inner,
            context_id,
            subject_did,
            requirements_json,
            agent_capabilities_json,
            challenge_verifications_json,
        )
    }

    /// Per-instance equivalent of the free-function `aggregate_trust_input`.
    #[napi(js_name = "aggregateTrustInput")]
    #[allow(clippy::too_many_arguments)]
    pub fn aggregate_trust_input(
        &self,
        context_id: String,
        subject_did: String,
        events_json: String,
        merkle_root_json: String,
        consequence_rules_json: String,
        threshold_requirements_json: String,
        attestor_sets_json: String,
        cached_attestations_json: String,
        challenge_results_json: String,
    ) -> napi::Result<String> {
        crate::trust::aggregate_trust_input_on(
            &self.inner,
            context_id,
            subject_did,
            events_json,
            merkle_root_json,
            consequence_rules_json,
            threshold_requirements_json,
            attestor_sets_json,
            cached_attestations_json,
            challenge_results_json,
        )
    }

    /// Computes the structured participation record (§7.3.2) for `subjectDid`
    /// in `contextId`.
    ///
    /// The bridge sources the subject's accessible, currently-valid attestations
    /// from this instance's persistent trust store (populating any
    /// caller-supplied `cachedAttestationsJson` first), and the shared
    /// Supervisor gathers the FULL event log to derive every other fact. Returns
    /// a typed `NapiParticipationRecord` — the SDK receives the flattened facts
    /// and never re-aggregates event-log collections. See ADR-017, spec §7.3.2.
    #[napi(js_name = "participationRecord")]
    pub fn participation_record(
        &self,
        context_id: String,
        subject_did: String,
        cached_attestations_json: String,
    ) -> napi::Result<crate::trust::NapiParticipationRecord> {
        crate::trust::participation_record_on(
            &self.inner,
            context_id,
            subject_did,
            cached_attestations_json,
        )
    }

    // ====================================================================
    // #1549 Phase 4 PR 4 — sub-slice E: mcp/testing/media/provenance/sync
    // operations on SCP.
    //
    // Each method delegates to the per-bridge-instance `_on` helpers in
    // [`crate::mcp`] / [`crate::testing`] / [`crate::media`] /
    // [`crate::provenance`] / [`crate::sync`], routing through `&*self.inner`
    // so operations are scoped to this `SCP`'s bridge instance. The
    // free-function façade that predated this migration was deleted in
    // the Phase 4 PR 4 demolition slice (ADR-048).
    // ====================================================================

    // -------------------------------------------------------------------
    // MCP
    // -------------------------------------------------------------------

    /// Per-instance equivalent of the free-function `mcp_server_create`.
    #[napi(js_name = "mcpServerCreate")]
    pub async fn mcp_server_create(
        &self,
        config: NapiMcpServerConfig,
    ) -> napi::Result<NapiMcpServerHandle> {
        crate::mcp::mcp_server_create_on(&self.inner, config).await
    }

    /// Per-instance equivalent of the free-function `mcp_server_stop`.
    #[napi(js_name = "mcpServerStop")]
    pub async fn mcp_server_stop(&self, handle: &NapiMcpServerHandle) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::mcp::mcp_server_stop_on(&self.inner, handle).await
    }

    /// Per-instance equivalent of the free-function `mcp_client_connect_stdio`.
    #[napi(js_name = "mcpClientConnectStdio")]
    pub async fn mcp_client_connect_stdio(
        &self,
        command: Vec<String>,
    ) -> napi::Result<NapiMcpClientHandle> {
        crate::mcp::mcp_client_connect_stdio_on(&self.inner, command).await
    }

    /// Per-instance equivalent of the free-function `mcp_client_connect_sse`.
    #[napi(js_name = "mcpClientConnectSse")]
    pub async fn mcp_client_connect_sse(&self, url: String) -> napi::Result<NapiMcpClientHandle> {
        crate::mcp::mcp_client_connect_sse_on(&self.inner, url).await
    }

    /// Per-instance equivalent of the free-function `mcp_client_disconnect`.
    #[napi(js_name = "mcpClientDisconnect")]
    pub async fn mcp_client_disconnect(&self, handle: &NapiMcpClientHandle) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::mcp::mcp_client_disconnect_on(&self.inner, handle).await
    }

    /// Per-instance equivalent of the free-function `mcp_client_list_tools`.
    #[napi(js_name = "mcpClientListTools")]
    pub async fn mcp_client_list_tools(
        &self,
        handle: &NapiMcpClientHandle,
    ) -> napi::Result<Vec<NapiMcpToolInfo>> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::mcp::mcp_client_list_tools_on(&self.inner, handle).await
    }

    /// Per-instance equivalent of the free-function `mcp_client_invoke`.
    #[napi(js_name = "mcpClientInvoke")]
    pub async fn mcp_client_invoke(
        &self,
        handle: &NapiMcpClientHandle,
        outlet_name: String,
        input_json: String,
        context_id: String,
        invoker_did: String,
    ) -> napi::Result<NapiMcpInvokeResult> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::mcp::mcp_client_invoke_on(
            &self.inner,
            handle,
            outlet_name,
            input_json,
            context_id,
            invoker_did,
        )
        .await
    }

    /// Adds binary names to THIS instance's MCP stdio allowlist.
    /// Forwards to [`crate::mcp::mcp_configure_stdio_allowlist_on`].
    #[napi(js_name = "mcpConfigureStdioAllowlist")]
    pub fn mcp_configure_stdio_allowlist(
        &self,
        additional_binaries: Vec<String>,
    ) -> napi::Result<()> {
        crate::mcp::mcp_configure_stdio_allowlist_on(&self.inner, additional_binaries)
    }

    /// Disables THIS instance's MCP stdio allowlist (unrestricted mode).
    /// Forwards to [`crate::mcp::mcp_disable_stdio_allowlist_on`].
    #[napi(js_name = "mcpDisableStdioAllowlist")]
    pub fn mcp_disable_stdio_allowlist(&self) -> napi::Result<()> {
        crate::mcp::mcp_disable_stdio_allowlist_on(&self.inner)
    }

    /// Resets THIS instance's MCP stdio allowlist to its defaults.
    /// Forwards to [`crate::mcp::mcp_reset_stdio_allowlist_on`].
    #[napi(js_name = "mcpResetStdioAllowlist")]
    pub fn mcp_reset_stdio_allowlist(&self) -> napi::Result<()> {
        crate::mcp::mcp_reset_stdio_allowlist_on(&self.inner)
    }

    /// Returns a snapshot of THIS instance's MCP stdio allowlist state.
    /// Forwards to [`crate::mcp::mcp_get_stdio_allowlist_on`].
    #[napi(js_name = "mcpGetStdioAllowlist")]
    pub fn mcp_get_stdio_allowlist(&self) -> napi::Result<NapiAllowlistState> {
        crate::mcp::mcp_get_stdio_allowlist_on(&self.inner)
    }

    // -------------------------------------------------------------------
    // Media
    // -------------------------------------------------------------------

    /// Per-instance equivalent of the free-function `media_check_capability`.
    #[napi(js_name = "mediaCheckCapability")]
    pub fn media_check_capability(
        &self,
        ceiling: Vec<String>,
        capability: String,
    ) -> napi::Result<bool> {
        crate::media::media_check_capability_on(&self.inner, ceiling, capability)
    }

    /// Per-instance equivalent of the free-function `media_initiate_session`.
    #[napi(js_name = "mediaInitiateSession")]
    #[allow(clippy::too_many_arguments)]
    pub fn media_initiate_session(
        &self,
        context_id: String,
        ceiling: Vec<String>,
        capabilities: Vec<String>,
        participants: Vec<String>,
        timestamp: f64,
    ) -> napi::Result<String> {
        crate::media::media_initiate_session_on(
            &self.inner,
            context_id,
            ceiling,
            capabilities,
            participants,
            timestamp,
        )
    }

    /// Per-instance equivalent of the free-function `media_activate_session`.
    #[napi(js_name = "mediaActivateSession")]
    pub fn media_activate_session(&self, session_json: String) -> napi::Result<String> {
        crate::media::media_activate_session_on(&self.inner, session_json)
    }

    /// Per-instance equivalent of the free-function `media_join_session`.
    #[napi(js_name = "mediaJoinSession")]
    pub fn media_join_session(
        &self,
        session_json: String,
        participant_did: String,
    ) -> napi::Result<String> {
        crate::media::media_join_session_on(&self.inner, session_json, participant_did)
    }

    /// Per-instance equivalent of the free-function `media_end_session`.
    #[napi(js_name = "mediaEndSession")]
    pub fn media_end_session(&self, session_json: String, timestamp: f64) -> napi::Result<String> {
        crate::media::media_end_session_on(&self.inner, session_json, timestamp)
    }

    /// Per-instance equivalent of the free-function `media_create_offer`.
    #[napi(js_name = "mediaCreateOffer")]
    pub fn media_create_offer(
        &self,
        session_id: String,
        sdp: String,
        sender_did: String,
    ) -> napi::Result<String> {
        crate::media::media_create_offer_on(&self.inner, session_id, sdp, sender_did)
    }

    /// Per-instance equivalent of the free-function `media_create_answer`.
    #[napi(js_name = "mediaCreateAnswer")]
    pub fn media_create_answer(
        &self,
        session_id: String,
        sdp: String,
        sender_did: String,
    ) -> napi::Result<String> {
        crate::media::media_create_answer_on(&self.inner, session_id, sdp, sender_did)
    }

    /// Per-instance equivalent of the free-function `media_create_ice_candidate`.
    #[napi(js_name = "mediaCreateIceCandidate")]
    #[allow(clippy::too_many_arguments)]
    pub fn media_create_ice_candidate(
        &self,
        session_id: String,
        candidate: String,
        sender_did: String,
        sdp_mid: Option<String>,
        sdp_mline_index: Option<u32>,
    ) -> napi::Result<String> {
        crate::media::media_create_ice_candidate_on(
            &self.inner,
            session_id,
            candidate,
            sender_did,
            sdp_mid,
            sdp_mline_index,
        )
    }

    /// Per-instance equivalent of the free-function `media_create_session_end`.
    #[napi(js_name = "mediaCreateSessionEnd")]
    pub fn media_create_session_end(
        &self,
        session_id: String,
        sender_did: String,
    ) -> napi::Result<String> {
        crate::media::media_create_session_end_on(&self.inner, session_id, sender_did)
    }

    /// Per-instance equivalent of the free-function `media_send_signaling`.
    #[napi(js_name = "mediaSendSignaling")]
    pub fn media_send_signaling(&self, signaling_json: String) -> napi::Result<String> {
        crate::media::media_send_signaling_on(&self.inner, signaling_json)
    }

    /// Per-instance equivalent of the free-function `media_verify_sender_attribution`.
    #[napi(js_name = "mediaVerifySenderAttribution")]
    pub fn media_verify_sender_attribution(
        &self,
        signaling_json: String,
        envelope_sender_did: String,
    ) -> napi::Result<bool> {
        crate::media::media_verify_sender_attribution_on(
            &self.inner,
            signaling_json,
            envelope_sender_did,
        )
    }

    // -------------------------------------------------------------------
    // Provenance
    // -------------------------------------------------------------------

    /// Per-instance equivalent of the free-function `evaluate_provenance_quality`.
    #[napi(js_name = "evaluateProvenanceQuality")]
    pub async fn evaluate_provenance_quality(
        &self,
        source_context: Option<String>,
        source_type: String,
        context_state: String,
        counterparties: Option<Vec<String>>,
    ) -> napi::Result<u32> {
        crate::provenance::evaluate_provenance_quality_on(
            &self.inner,
            source_context,
            source_type,
            context_state,
            counterparties,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `provenance_attach`.
    #[napi(js_name = "provenanceAttach")]
    #[allow(clippy::too_many_arguments)]
    pub fn provenance_attach(
        &self,
        source_context_id: String,
        source_type: String,
        memory_scope: String,
        members: Vec<String>,
        target_context_id: String,
        actor_did: String,
        existing_chain_depth: Option<u32>,
        discovery_method: Option<String>,
        purpose: Option<String>,
        counterparty_policy: Option<String>,
    ) -> napi::Result<String> {
        crate::provenance::provenance_attach_on(
            &self.inner,
            source_context_id,
            source_type,
            memory_scope,
            members,
            target_context_id,
            actor_did,
            existing_chain_depth,
            discovery_method,
            purpose,
            counterparty_policy,
        )
    }

    /// Per-instance equivalent of the free-function `provenance_check_chain_depth`.
    #[napi(js_name = "provenanceCheckChainDepth")]
    pub fn provenance_check_chain_depth(
        &self,
        chain_depth: u32,
        max_depth: Option<u32>,
    ) -> napi::Result<bool> {
        crate::provenance::provenance_check_chain_depth_on(&self.inner, chain_depth, max_depth)
    }

    /// Per-instance equivalent of the free-function `provenance_redact_counterparties`.
    #[napi(js_name = "provenanceRedactCounterparties")]
    pub fn provenance_redact_counterparties(
        &self,
        provenance_json: String,
    ) -> napi::Result<String> {
        crate::provenance::provenance_redact_counterparties_on(&self.inner, provenance_json)
    }

    /// Per-instance equivalent of the free-function `provenance_pseudonymize_counterparties`.
    #[napi(js_name = "provenancePseudonymizeCounterparties")]
    pub fn provenance_pseudonymize_counterparties(
        &self,
        provenance_json: String,
        pseudonym_key_hex: String,
    ) -> napi::Result<String> {
        crate::provenance::provenance_pseudonymize_counterparties_on(
            &self.inner,
            provenance_json,
            pseudonym_key_hex,
        )
    }

    /// Per-instance equivalent of the free-function `provenance_update_source_type`.
    #[napi(js_name = "provenanceUpdateSourceType")]
    pub fn provenance_update_source_type(
        &self,
        provenance_json: String,
        new_state: String,
    ) -> napi::Result<String> {
        crate::provenance::provenance_update_source_type_on(&self.inner, provenance_json, new_state)
    }

    // -------------------------------------------------------------------
    // Sync / offline classification
    // -------------------------------------------------------------------

    /// Per-instance equivalent of the free-function `sync_classify_offline`.
    #[napi(js_name = "syncClassifyOffline")]
    pub fn sync_classify_offline(&self, last_relay_contact: i64, now: i64) -> napi::Result<String> {
        crate::sync::sync_classify_offline_on(&self.inner, last_relay_contact, now)
    }

    /// Per-instance equivalent of the free-function `sync_get_policy`.
    #[napi(js_name = "syncGetPolicy")]
    #[must_use]
    pub fn sync_get_policy(&self) -> NapiSyncPolicy {
        crate::sync::sync_get_policy_on(&self.inner)
    }

    /// Per-instance equivalent of the free-function `sync_classify_offline_custom`.
    #[napi(js_name = "syncClassifyOfflineCustom")]
    pub fn sync_classify_offline_custom(
        &self,
        last_relay_contact: i64,
        now: i64,
        tier_1_threshold_secs: i64,
        tier_2_threshold_secs: i64,
    ) -> napi::Result<String> {
        crate::sync::sync_classify_offline_custom_on(
            &self.inner,
            last_relay_contact,
            now,
            tier_1_threshold_secs,
            tier_2_threshold_secs,
        )
    }

    /// Per-instance equivalent of the free-function `bridge_create_shadow`.
    ///
    /// Routes through `&*self.inner` — the shadow identity state is stored
    /// in this instance's per-context `BridgeContextState`. Free function
    /// deleted in Phase 4 PR 4 demolition Phase A gap-fill.
    #[napi(js_name = "bridgeCreateShadow")]
    pub fn bridge_create_shadow(
        &self,
        bridge_id: String,
        platform_handle: String,
        bridge_mode: String,
        context_id: Option<String>,
    ) -> napi::Result<crate::bridge_connector::NapiShadowIdentity> {
        crate::bridge_connector::bridge_create_shadow_on(
            &self.inner,
            bridge_id,
            platform_handle,
            bridge_mode,
            context_id,
        )
    }

    // -------------------------------------------------------------------
    // Bridge credential store (§12.11)
    //
    // Per-instance equivalents of the PyO3 `bridge_credential_*` methods.
    // Each routes through `&*self.inner` — credentials live in THIS
    // instance's durable `FfiCredentialStore`, selected from its chosen
    // storage backend and isolated from every other `Scp` in the process
    // (ADR-048 §1; ADR-062 §Decision 5, SCP-CAPINJECT-009).
    // -------------------------------------------------------------------

    /// Provisions (stores) an encrypted credential for a bridge instance.
    #[napi(js_name = "bridgeCredentialProvision")]
    pub fn bridge_credential_provision(
        &self,
        bridge_id: String,
        credential_type: String,
        plaintext: Vec<u8>,
        bridge_credential_key: Vec<u8>,
    ) -> napi::Result<crate::bridge_connector::NapiBridgeCredential> {
        crate::bridge_connector::bridge_credential_provision_on(
            &self.inner,
            bridge_id,
            credential_type,
            plaintext,
            bridge_credential_key,
        )
    }

    /// Retrieves and decrypts a credential for a bridge instance.
    #[napi(js_name = "bridgeCredentialRetrieve")]
    pub fn bridge_credential_retrieve(
        &self,
        bridge_id: String,
        credential_type: String,
        bridge_credential_key: Vec<u8>,
    ) -> napi::Result<Vec<u8>> {
        crate::bridge_connector::bridge_credential_retrieve_on(
            &self.inner,
            bridge_id,
            credential_type,
            bridge_credential_key,
        )
    }

    /// Rotates (replaces) a credential for a bridge instance.
    #[napi(js_name = "bridgeCredentialRotate")]
    pub fn bridge_credential_rotate(
        &self,
        bridge_id: String,
        credential_type: String,
        new_plaintext: Vec<u8>,
        bridge_credential_key: Vec<u8>,
    ) -> napi::Result<crate::bridge_connector::NapiBridgeCredential> {
        crate::bridge_connector::bridge_credential_rotate_on(
            &self.inner,
            bridge_id,
            credential_type,
            new_plaintext,
            bridge_credential_key,
        )
    }

    /// Revokes all credentials for a bridge instance.
    #[napi(js_name = "bridgeCredentialRevoke")]
    pub fn bridge_credential_revoke(&self, bridge_id: String) -> napi::Result<()> {
        crate::bridge_connector::bridge_credential_revoke_on(&self.inner, bridge_id)
    }

    /// Lists all credential types stored for a bridge instance.
    #[napi(js_name = "bridgeCredentialList")]
    pub fn bridge_credential_list(&self, bridge_id: String) -> napi::Result<Vec<String>> {
        crate::bridge_connector::bridge_credential_list_on(&self.inner, bridge_id)
    }

    /// Stores a bridge credential key in the custody boundary.
    #[napi(js_name = "bridgeCredentialStoreKey")]
    pub fn bridge_credential_store_key(&self, bridge_id: String, key: Vec<u8>) -> napi::Result<()> {
        crate::bridge_connector::bridge_credential_store_key_on(&self.inner, bridge_id, key)
    }

    /// Retrieves a bridge credential key from the custody boundary.
    #[napi(js_name = "bridgeCredentialGetKey")]
    pub fn bridge_credential_get_key(&self, bridge_id: String) -> napi::Result<Vec<u8>> {
        crate::bridge_connector::bridge_credential_get_key_on(&self.inner, bridge_id)
    }

    /// Deletes and zeroizes a bridge credential key.
    #[napi(js_name = "bridgeCredentialDeleteKey")]
    pub fn bridge_credential_delete_key(&self, bridge_id: String) -> napi::Result<()> {
        crate::bridge_connector::bridge_credential_delete_key_on(&self.inner, bridge_id)
    }

    // -------------------------------------------------------------------
    // SCPID authentication (§3.11)
    // -------------------------------------------------------------------

    /// Per-instance equivalent of the free-function `scpid_challenge`.
    #[napi(js_name = "scpidChallenge")]
    pub fn scpid_challenge(&self, audience: String, ttl_seconds: u32) -> napi::Result<String> {
        crate::scpid::scpid_challenge_on(&self.inner, audience, ttl_seconds)
    }

    /// Per-instance equivalent of the free-function `scpid_sign`.
    ///
    /// `signed_at_override` is a testing-only parameter for the ADR-046
    /// cross-bridge parity harness. Only accepted when scp-core is built
    /// with the `testing` feature; production builds reject any non-`null`
    /// value via `SCP-VALID-7008`.
    #[napi(js_name = "scpidSign")]
    pub fn scpid_sign(
        &self,
        did: String,
        signing_key_id: String,
        challenge_json: String,
        #[napi(ts_arg_type = "bigint | null | undefined")] signed_at_override: Option<
            napi::bindgen_prelude::BigInt,
        >,
    ) -> napi::Result<String> {
        crate::scpid::scpid_sign_on(
            &self.inner,
            did,
            signing_key_id,
            challenge_json,
            signed_at_override,
        )
    }

    /// Per-instance equivalent of the free-function `scpid_verify`.
    #[napi(js_name = "scpidVerify")]
    pub fn scpid_verify(
        &self,
        response_json: String,
        challenge_json: String,
    ) -> napi::Result<String> {
        crate::scpid::scpid_verify_on(&self.inner, response_json, challenge_json)
    }

    /// Per-instance equivalent of `identity_remove`.
    ///
    /// Drops retained key material for the DID. Idempotent — succeeds
    /// silently when the DID is a syntactically valid DID not present in
    /// the registry. Custody-agnostic registry teardown — available in
    /// production over callback custody, mirroring the `PyO3` bridge.
    ///
    /// # Errors
    ///
    /// Throws a validation error when `did` is not a syntactically valid
    /// DID, mirroring the `PyO3` reference bridge's `identity_remove`.
    #[napi(js_name = "identityRemove")]
    pub fn identity_remove(&self, did: String) -> napi::Result<()> {
        scp_ffi_common::validate::validate_did(&did)
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
        crate::runtime::remove_identity(&self.inner, &did);
        Ok(())
    }

    /// Per-instance equivalent of `identity_remove_if_present`.
    ///
    /// Returns `true` if the identity was present and removed. Custody-agnostic
    /// registry teardown — available in production over callback custody.
    ///
    /// # Errors
    ///
    /// Throws a validation error when `did` is not a syntactically valid
    /// DID, mirroring the `PyO3` reference bridge's
    /// `identity_remove_if_present`.
    #[napi(js_name = "identityRemoveIfPresent")]
    pub fn identity_remove_if_present(&self, did: String) -> napi::Result<bool> {
        scp_ffi_common::validate::validate_did(&did)
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
        Ok(crate::runtime::remove_identity_if_present(
            &self.inner,
            &did,
        ))
    }
}

// Non-`#[napi]` impl block — Rust-only test affordance. Not exported to
// TypeScript.
impl Scp {
    /// Constructs an `Scp` with EXPLICIT in-memory storage, for Rust-side
    /// tests only.
    ///
    /// The public `#[napi(constructor)] new` takes a required JSON
    /// storage-config string (spec §17.6 — storage selection is
    /// mandatory). Rust unit tests want an infallible one-liner that
    /// selects in-memory storage. This wraps
    /// [`NapiBridgeInstance::new_napi`] (the internal in-memory builder) —
    /// an explicit dev/test selection, NOT a silent default.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn new_in_memory_for_test() -> Self {
        Self {
            inner: Arc::new(NapiBridgeInstance::new_napi()),
        }
    }
}

// ---------------------------------------------------------------------------
// Relay/node startup `#[napi] Scp` methods. Moved into a separate
// `#[cfg(feature = "server")] #[napi] impl Scp` block so napi-rs emits their
// `_c_callback` registration references ONLY when `server` is enabled. A
// single `#[cfg(feature = "server")]`-gated `#[napi]` method inside the main
// (ungated) `impl Scp` block would leave a dangling `_c_callback` symbol in
// builds without the `server` feature (e.g. `--no-default-features`).
#[cfg(feature = "server")]
#[napi]
impl Scp {
    /// Per-instance equivalent of the free-function `relay_start_in_memory`.
    #[napi(js_name = "relayStartInMemory")]
    pub async fn relay_start_in_memory(&self) -> napi::Result<NapiRelayHandle> {
        crate::server::relay_start_in_memory_on(&self.inner).await
    }

    /// Per-instance equivalent of the free-function `relay_start_local`.
    #[napi(js_name = "relayStartLocal")]
    pub async fn relay_start_local(&self, data_dir: String) -> napi::Result<NapiRelayHandle> {
        crate::server::relay_start_local_on(&self.inner, data_dir).await
    }

    /// Per-instance equivalent of the free-function `node_start_in_memory`.
    #[napi(js_name = "nodeStartInMemory")]
    pub async fn node_start_in_memory(
        &self,
        identity_did: Option<String>,
    ) -> napi::Result<NapiNodeHandle> {
        crate::server::node_start_in_memory_on(&self.inner, identity_did).await
    }

    /// Per-instance equivalent of the free-function `node_start_local`.
    #[napi(js_name = "nodeStartLocal")]
    pub async fn node_start_local(
        &self,
        data_dir: String,
        identity_did: Option<String>,
        passphrase: Option<String>,
    ) -> napi::Result<NapiNodeHandle> {
        crate::server::node_start_local_on(&self.inner, data_dir, identity_did, passphrase).await
    }
}

// ---------------------------------------------------------------------------
// Fail-closed device-attestation methods on shipped (no-`testing`) builds.
//
// Spec §9:187 — device attestation (Apple App Attest / Google Play Integrity) is
// an optional SDK-level trust signal whose absence is expected and
// non-penalizing. No production device-attestation backend is wired yet: App
// Attest / Play Integrity are hardware/platform-backed and are intentionally
// deferred (with hardware keychain custody) until an e2e-driven integration
// lands (ADR-062 §Decision 3 severs the test-harness `InMemoryDeviceAttestation`
// nullifier — always-attest / always-valid — from every production dependency
// line). So a shipped build returns a typed honest-absent error rather than a
// silently-valid attestation. See ADR-025 and #2171 for the real backend.
//
// These live in a SEPARATE `#[cfg(not(feature = "testing"))] #[napi] impl`
// block (mirroring the `testing` block below) so napi-rs emits the
// `_c_callback` registration in BOTH build configs — the TS surface is
// identical across builds; only the body differs. Mirrors the PyO3 reference
// bridge's not(testing) `identity_attest_device` /
// `identity_verify_device_attestation`.
// ---------------------------------------------------------------------------
#[cfg(not(feature = "testing"))]
#[napi]
impl Scp {
    /// Fail-closed [`Self::identity_attest_device`] on a shipped build.
    ///
    /// Returns [`codes::IDENT_1015`] (device attestation unavailable — no
    /// production backend wired yet; spec §9:187 / ADR-062 §Decision 3) rather
    /// than reaching for the severed `InMemoryDeviceAttestation` nullifier.
    #[napi(js_name = "identityAttestDevice")]
    // napi requires `async` for the `Promise` return type; the fail-closed body
    // has no `.await`. It DOES dereference `self`: the identity is resolved
    // against THIS instance's registry first, so an unregistered DID surfaces
    // the standard not-found identity error while a registered DID fails closed
    // with the typed honest-absent IDENT_1015.
    #[allow(clippy::unused_async)]
    pub async fn identity_attest_device(&self, did: String) -> napi::Result<String> {
        crate::runtime::with_identity(&self.inner, &did, |_entry| {
            Err(ScpNapiError::Identity {
                message: "device attestation unavailable: no production \
                          device-attestation backend is wired yet — Apple App Attest / \
                          Google Play Integrity are hardware/platform-backed and are \
                          intentionally deferred (with hardware keychain custody) until \
                          an e2e-driven integration lands (spec §9:187). See #2171."
                    .to_owned(),
                code: codes::IDENT_1015.to_owned(),
            })
        })
        .map_err(NapiError::from)
    }

    /// Fail-closed [`Self::identity_verify_device_attestation`] on a shipped
    /// build.
    ///
    /// Returns [`codes::IDENT_1016`] (device attestation unavailable — no
    /// production backend wired yet; spec §9:187 / ADR-062 §Decision 3) rather
    /// than a silently-valid result.
    #[napi(js_name = "identityVerifyDeviceAttestation")]
    // Fail-closed body has no `.await`; it DOES dereference `self` by resolving
    // the identity against THIS instance's registry before the typed decline.
    #[allow(clippy::unused_async)]
    pub async fn identity_verify_device_attestation(
        &self,
        did: String,
        token_base64: String,
    ) -> napi::Result<bool> {
        let _ = token_base64;
        crate::runtime::with_identity(&self.inner, &did, |_entry| {
            Err(ScpNapiError::Identity {
                message: "device attestation verification unavailable: no production \
                          device-attestation backend is wired yet — Apple App Attest / \
                          Google Play Integrity are hardware/platform-backed and are \
                          intentionally deferred (with hardware keychain custody) until \
                          an e2e-driven integration lands (spec §9:187). See #2171."
                    .to_owned(),
                code: codes::IDENT_1016.to_owned(),
            })
        })
        .map_err(NapiError::from)
    }
}

// ---------------------------------------------------------------------------
// In-memory-custody-only `Scp` methods.
//
// These methods are gated behind `testing` because they
// depend on an in-memory *backend* — the `InMemoryDeviceAttestation` software
// attestation backend (production hardware attestation per ADR-025 is not yet
// wired) or the full-stack in-memory test network. They live in a SEPARATE
// `#[napi] impl Scp` block so napi-rs emits their `_c_callback` registration
// only when the feature is enabled — a single gated method inside the main
// `#[napi] impl` block would leave a dangling registration reference in
// production builds.
//
// Production callback-custody parity (registry retention + teardown, SCPID
// signing, link attestations) lives in the main `impl Scp` block above and is
// NOT gated, mirroring the PyO3 reference bridge.
// ---------------------------------------------------------------------------
#[cfg(feature = "testing")]
#[napi]
impl Scp {
    /// Per-instance equivalent of `identity_attest_device`.
    ///
    /// The attestation is device-local; the DID argument is retained for
    /// API symmetry with the free function.
    #[napi(js_name = "identityAttestDevice")]
    pub async fn identity_attest_device(&self, did: String) -> napi::Result<String> {
        use base64::Engine;
        use scp_platform::testing::InMemoryDeviceAttestation;
        use scp_platform::traits::DeviceAttestation;

        // Retained for API symmetry (spec §9.3) — the attestation itself is
        // device-local and doesn't consult the identity's key material.
        let _ = (&self.inner, did);

        let attestation = InMemoryDeviceAttestation::new();
        let token = attestation.attest().await.map_err(|e| {
            NapiError::from(ScpNapiError::Identity {
                message: format!("device attestation failed: {e}"),
                code: codes::IDENT_1010.to_owned(),
            })
        })?;
        Ok(base64::engine::general_purpose::STANDARD.encode(token.as_bytes()))
    }

    /// Per-instance equivalent of `identity_verify_device_attestation`.
    #[napi(js_name = "identityVerifyDeviceAttestation")]
    pub async fn identity_verify_device_attestation(
        &self,
        did: String,
        token_base64: String,
    ) -> napi::Result<bool> {
        use base64::Engine;
        use scp_platform::testing::InMemoryDeviceAttestation;
        use scp_platform::traits::DeviceAttestation;

        let _ = (&self.inner, did);

        let token_bytes = base64::engine::general_purpose::STANDARD
            .decode(&token_base64)
            .map_err(|e| {
                NapiError::from(ScpNapiError::Identity {
                    message: format!("invalid base64 attestation token: {e}"),
                    code: codes::IDENT_1011.to_owned(),
                })
            })?;

        let token = scp_platform::traits::DeviceAttestationToken::new(token_bytes);
        let attestation = InMemoryDeviceAttestation::new();

        attestation.verify(&token).await.map_err(|e| {
            NapiError::from(ScpNapiError::Identity {
                message: format!("device attestation verification failed: {e}"),
                code: codes::IDENT_1012.to_owned(),
            })
        })
    }

    /// Per-instance equivalent of the free-function `fullstack_create_node`.
    #[napi(js_name = "fullstackCreateNode")]
    #[must_use]
    pub fn fullstack_create_node(&self, did: String) -> NapiFullStackNode {
        crate::testing::fullstack_create_node_on(&self.inner, did)
    }

    /// Per-instance equivalent of the free-function `fullstack_reset_network`.
    #[napi(js_name = "fullstackResetNetwork")]
    pub fn fullstack_reset_network(&self) {
        crate::testing::fullstack_reset_network_on(&self.inner);
    }

    /// Per-instance equivalent of the free-function `fullstack_create_context`.
    #[napi(js_name = "fullstackCreateContext")]
    pub fn fullstack_create_context(
        &self,
        node: &NapiFullStackNode,
        context_id: String,
        ceiling_json: String,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, node);
        crate::testing::fullstack_create_context_on(&self.inner, node, context_id, ceiling_json)
    }

    /// Per-instance equivalent of the free-function `fullstack_add_member`.
    #[napi(js_name = "fullstackAddMember")]
    pub fn fullstack_add_member(
        &self,
        node: &NapiFullStackNode,
        context_id: String,
        member_did: String,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, node);
        crate::testing::fullstack_add_member_on(&self.inner, node, context_id, member_did)
    }

    /// Per-instance equivalent of the free-function `fullstack_join_from_welcome`.
    #[napi(js_name = "fullstackJoinFromWelcome")]
    pub fn fullstack_join_from_welcome(
        &self,
        node: &NapiFullStackNode,
        context_id: String,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, node);
        crate::testing::fullstack_join_from_welcome_on(&self.inner, node, context_id)
    }

    /// Per-instance equivalent of the free-function `fullstack_sync_sender_keys`.
    #[napi(js_name = "fullstackSyncSenderKeys")]
    pub fn fullstack_sync_sender_keys(
        &self,
        node_a: &NapiFullStackNode,
        node_b: &NapiFullStackNode,
        context_id: String,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, node_a, node_b);
        crate::testing::fullstack_sync_sender_keys_on(&self.inner, node_a, node_b, context_id)
    }

    /// Per-instance equivalent of the free-function `fullstack_send_message`.
    #[napi(js_name = "fullstackSendMessage")]
    pub fn fullstack_send_message(
        &self,
        node: &NapiFullStackNode,
        context_id: String,
        payload: Buffer,
    ) -> napi::Result<Buffer> {
        crate::napi_check_handle!(&self.inner.core, node);
        crate::testing::fullstack_send_message_on(&self.inner, node, context_id, payload)
    }

    /// Per-instance equivalent of the free-function `fullstack_decrypt_message`.
    #[napi(js_name = "fullstackDecryptMessage")]
    pub fn fullstack_decrypt_message(
        &self,
        node: &NapiFullStackNode,
        context_id: String,
        ciphertext: Buffer,
        sender_did: String,
    ) -> napi::Result<Buffer> {
        crate::napi_check_handle!(&self.inner.core, node);
        crate::testing::fullstack_decrypt_message_on(
            &self.inner,
            node,
            context_id,
            ciphertext,
            sender_did,
        )
    }

    /// Per-instance equivalent of the free-function `fullstack_remove_member`.
    #[napi(js_name = "fullstackRemoveMember")]
    pub fn fullstack_remove_member(
        &self,
        node: &NapiFullStackNode,
        context_id: String,
        member_did: String,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, node);
        crate::testing::fullstack_remove_member_on(&self.inner, node, context_id, member_did)
    }

    /// Test-only: seed a peer's per-context pseudonym routing ID (§9.10.4)
    /// into this node's `Supervisor`, simulating a delivered
    /// `PseudonymAnnouncement` so multi-member encrypted sends do not fail
    /// closed with `SCP-CTX-2095`.
    #[napi(js_name = "fullstackSeedPeerPseudonym")]
    pub fn fullstack_seed_peer_pseudonym(
        &self,
        node: &NapiFullStackNode,
        context_id: String,
        peer_did: String,
        pseudonym: Buffer,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, node);
        crate::testing::fullstack_seed_peer_pseudonym_on(
            &self.inner,
            node,
            context_id,
            peer_did,
            pseudonym,
        )
    }

    /// Test-only: seed a peer's per-context pseudonym routing ID (§9.10.4) into
    /// this bridge's `Supervisor`, simulating a delivered `PseudonymAnnouncement`
    /// so multi-member encrypted sends do not fail closed with `SCP-CTX-2095`.
    /// Lives in this `testing`-gated `#[napi] impl Scp` block
    /// (never shipped in production) so napi-rs does not emit a dangling
    /// `_c_callback` registration reference in bare builds.
    #[napi(js_name = "contextSeedPeerPseudonym")]
    pub async fn context_seed_peer_pseudonym(
        &self,
        handle: &NapiContextHandle,
        peer_did: String,
        pseudonym: Buffer,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_seed_peer_pseudonym_on(&self.inner, handle, peer_did, pseudonym)
            .await
    }
}

// ---------------------------------------------------------------------------
// Recovery / custody-migration concurrency-cap tests (RED-PR5-002 /
// BLACK-PR5-002, #1549).
//
// The sync `Scp::identity_execute_recovery` +
// `Scp::identity_execute_custody_migration` methods drive their async
// orchestrators via `crate::runtime().block_on(...)`, pinning one libuv
// worker per in-flight call. A shared `tokio::sync::Semaphore` on the
// bridge instance caps concurrent invocations to `RECOVERY_CONCURRENCY_CAP`;
// excess callers get `SCP-VALID-7140` (non-blocking rejection) rather than
// queueing on the permit wait.
//
// These tests exercise the cap directly by pre-acquiring owned permits on
// the bridge's semaphore and then calling the public methods — so the
// ordering invariant ("ownership check runs BEFORE the semaphore check, so
// rejected-upstream callers never consume a permit") and the busy-error
// shape are both validated without depending on orchestrator timing.
// ---------------------------------------------------------------------------
#[cfg(all(test, feature = "testing"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod concurrency_cap_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use scp_identity::DidMethod;
    use scp_platform::testing::InMemoryKeyCustody;

    use crate::identity::OpaqueInMemoryKeyCustody;
    use crate::runtime::{NapiBridgeInstance, RECOVERY_CONCURRENCY_CAP};

    /// Builds a `Scp` with one real in-memory identity registered in its
    /// bridge instance. Returns the SCP handle and the registered DID so
    /// tests can call `identity_execute_recovery` / `..._custody_migration`
    /// against a DID the ownership check will accept.
    fn build_scp_with_identity() -> (Scp, String) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let custody = Arc::new(crate::custody::NapiKeyCustody::InMemory(
            OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()),
        ));
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let dht = scp_identity::DidDht::with_client(Arc::new(scp_dht::InMemoryDhtClient::new()));
        let (identity, document, pre_rotation_handle) = rt
            .block_on(dht.create(&*custody, pre_rotation_custody.as_ref()))
            .unwrap();
        let did = identity.did.clone();

        let bi = Arc::new(NapiBridgeInstance::new_napi());
        crate::runtime::register_identity(
            &bi,
            &did,
            crate::runtime::NapiIdentityEntry {
                identity,
                custody,
                document,
                identity_link_attestations: Vec::new(),
                pre_rotation_handle,
                pre_rotation_custody,
            },
        );

        (Scp { inner: bi }, did)
    }

    #[test]
    fn recovery_returns_busy_error_when_permits_exhausted() {
        let (scp, did) = build_scp_with_identity();

        // Pre-acquire the full permit pool — simulates RECOVERY_CONCURRENCY_CAP
        // in-flight recovery/migration calls.
        let sem = Arc::clone(&scp.inner.recovery_semaphore);
        let mut permits = Vec::with_capacity(RECOVERY_CONCURRENCY_CAP);
        for _ in 0..RECOVERY_CONCURRENCY_CAP {
            permits.push(sem.clone().try_acquire_owned().unwrap());
        }

        // N+1 call must fail-fast with SCP-VALID-7140, not block on the
        // permit wait.
        let err = scp
            .identity_execute_recovery(did.clone(), "agent".to_owned(), Vec::new())
            .expect_err("N+1 recovery call must be rejected with busy error");
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-VALID-7140"),
            "expected SCP-VALID-7140 in error, got: {msg}"
        );
        assert!(
            msg.contains("concurrency cap"),
            "expected 'concurrency cap' in error message, got: {msg}"
        );

        // Drop one permit — the next call must proceed past the permit check.
        // Recovery now fails closed (#2240, SCP-IDENT-1022) instead of
        // fabricating a success, but the point of THIS assertion is that the
        // permit gate no longer rejects it: whatever it returns, it must NOT be
        // a VALID-7140 busy rejection.
        drop(permits.pop());
        let result = scp.identity_execute_recovery(did, "agent".to_owned(), Vec::new());
        match result {
            Ok(_) => {
                // Not expected post-#2240, but a non-busy Ok would still satisfy
                // the "not busy-rejected" invariant this test guards.
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    !msg.contains("SCP-VALID-7140"),
                    "after dropping a permit, the next call must not be busy-rejected; got: {msg}"
                );
            }
        }
    }

    /// #2240: recovery must fail closed with the typed `SCP-IDENT-1022`
    /// "not configured" error — never a fabricated success — once it passes the
    /// ownership / length / concurrency gates. Mirrors the custody-migration
    /// `NotConfigured` fail-closed behaviour.
    #[test]
    fn recovery_fails_closed_with_not_configured_error() {
        let (scp, did) = build_scp_with_identity();

        let err = scp
            .identity_execute_recovery(did, "agent".to_owned(), Vec::new())
            .expect_err("recovery must fail closed — it has no configured backend (#2240)");
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-IDENT-1022"),
            "expected fail-closed SCP-IDENT-1022, got: {msg}"
        );
        assert!(
            msg.contains("not configured"),
            "expected 'not configured' in fail-closed message, got: {msg}"
        );
    }

    /// Recovery rejects an unrecognized compromise tier with the dedicated
    /// `SCP-IDENT-1021` code (distinct from the `SCP-IDENT-1020` ownership
    /// rejection), before reaching the fail-closed return. The DID is owned, so
    /// the ownership gate passes and the tier check is what rejects the call.
    #[test]
    fn recovery_rejects_unknown_tier() {
        let (scp, did) = build_scp_with_identity();

        let err = scp
            .identity_execute_recovery(did, "bogus-tier".to_owned(), Vec::new())
            .expect_err("unknown tier must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-IDENT-1021"),
            "expected dedicated invalid-tier code SCP-IDENT-1021, got: {msg}"
        );
        assert!(
            msg.contains("invalid compromise tier"),
            "expected invalid-tier message, got: {msg}"
        );
    }

    #[test]
    fn custody_migration_shares_recovery_permit_pool() {
        let (scp, did) = build_scp_with_identity();

        // Drain the shared semaphore via the recovery path first. The
        // `held_permits` binding keeps the permits alive for the duration
        // of the call below — dropping them early would repopulate the
        // pool and defeat the test.
        let sem = Arc::clone(&scp.inner.recovery_semaphore);
        let mut held_permits = Vec::with_capacity(RECOVERY_CONCURRENCY_CAP);
        for _ in 0..RECOVERY_CONCURRENCY_CAP {
            held_permits.push(sem.clone().try_acquire_owned().unwrap());
        }

        // Custody migration must observe the exhausted pool and reject with
        // the same busy error code — confirming the single shared cap.
        let err = scp
            .identity_execute_custody_migration(did, "in_memory".to_owned(), Vec::new())
            .expect_err("custody migration must share the recovery permit pool");
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-VALID-7140"),
            "expected SCP-VALID-7140 in error, got: {msg}"
        );

        // Explicitly drop at the end to silence `collection_is_never_read`
        // — the permits must outlive the call above.
        drop(held_permits);
    }

    #[test]
    fn ownership_check_runs_before_permit_acquisition() {
        // Unauthorised callers (DIDs not in the bridge's identity registry)
        // must be rejected BEFORE consuming a permit — otherwise an attacker
        // spamming invalid DIDs could starve legitimate recovery callers.
        let (scp, _did) = build_scp_with_identity();

        // The semaphore starts at full capacity.
        assert_eq!(
            scp.inner.recovery_semaphore.available_permits(),
            RECOVERY_CONCURRENCY_CAP,
            "semaphore must start at full capacity"
        );

        let unowned_did = "did:dht:unowned-attacker-did".to_owned();
        let err = scp
            .identity_execute_recovery(unowned_did, "agent".to_owned(), Vec::new())
            .expect_err("recovery against unowned DID must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-IDENT-1020"),
            "expected ownership-check rejection (SCP-IDENT-1020), got: {msg}"
        );

        // The critical invariant: the permit pool is unchanged. The
        // rejected caller did NOT consume a permit.
        assert_eq!(
            scp.inner.recovery_semaphore.available_permits(),
            RECOVERY_CONCURRENCY_CAP,
            "ownership-rejected calls must not consume a recovery permit"
        );
    }

    #[test]
    fn three_concurrent_recoveries_reject_at_least_one() {
        // Spawn `RECOVERY_CONCURRENCY_CAP + 1` threads all trying to run a
        // recovery against the same owned DID. Use a shared barrier so the
        // threads hit the semaphore near-simultaneously. To keep the cap
        // pressure observable we pre-acquire all permits in the test thread
        // and release them only after the workers have voted on their
        // outcome — this is the only reliable way to force overlap across
        // CI hosts where the orchestrator completes in microseconds.
        let (scp, did) = build_scp_with_identity();

        let worker_count = RECOVERY_CONCURRENCY_CAP + 1;
        let sem = Arc::clone(&scp.inner.recovery_semaphore);
        // Hold every permit — every worker will observe a full pool.
        let mut held_permits = Vec::with_capacity(RECOVERY_CONCURRENCY_CAP);
        for _ in 0..RECOVERY_CONCURRENCY_CAP {
            held_permits.push(sem.clone().try_acquire_owned().unwrap());
        }

        let barrier = Arc::new(Barrier::new(worker_count));
        let rejected = Arc::new(AtomicUsize::new(0));
        let scp_arc = Arc::new(scp);

        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let barrier_cl = Arc::clone(&barrier);
            let rejected_cl = Arc::clone(&rejected);
            let scp_cl = Arc::clone(&scp_arc);
            let did_cl = did.clone();
            handles.push(std::thread::spawn(move || {
                barrier_cl.wait();
                let res = scp_cl.identity_execute_recovery(did_cl, "agent".to_owned(), Vec::new());
                if let Err(e) = res
                    && e.to_string().contains("SCP-VALID-7140")
                {
                    rejected_cl.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // With every permit held externally, EVERY worker must have been
        // rejected fast — no worker could have acquired a permit.
        assert_eq!(
            rejected.load(Ordering::SeqCst),
            worker_count,
            "every concurrent worker should have been rejected while all \
             permits were held externally"
        );

        // Drop the held permits so the pool is replenished. This also
        // validates that `_permit` drop inside `identity_execute_recovery`
        // restores capacity for future callers.
        drop(held_permits);
        assert_eq!(
            scp_arc.inner.recovery_semaphore.available_permits(),
            RECOVERY_CONCURRENCY_CAP,
            "pool must return to full capacity once permits are dropped"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod petname_validation_tests {
    use super::*;

    /// Non-empty but syntactically invalid owner DIDs must be rejected by the
    /// pre-existing petname ops, matching the strict `validate_did` gate the
    /// §4.7 ops already enforce.
    #[test]
    fn petname_malformed_owner_rejected() {
        let scp = Scp::new_in_memory_for_test();
        let bad = "not-a-did".to_owned();
        assert!(
            scp.petname_set(bad.clone(), "did:dht:z1".to_owned(), "test".to_owned())
                .is_err()
        );
        assert!(
            scp.petname_remove(bad.clone(), "did:dht:z1".to_owned())
                .is_err()
        );
        assert!(
            scp.petname_set_context(bad.clone(), "ctx-1".to_owned(), "work".to_owned())
                .is_err()
        );
        assert!(
            scp.petname_remove_context(bad.clone(), "ctx-1".to_owned())
                .is_err()
        );
        assert!(
            scp.petname_resolve_did(bad.clone(), "alice".to_owned())
                .is_err()
        );
        assert!(
            scp.petname_resolve_context(bad.clone(), "work".to_owned())
                .is_err()
        );
        assert!(
            scp.petname_get_for_did(bad.clone(), "did:dht:z1".to_owned())
                .is_err()
        );
        assert!(
            scp.petname_get_for_context(bad, "ctx-1".to_owned())
                .is_err()
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod storage_mandatory_tests {
    use super::*;

    /// Storage selection is mandatory (spec §17.6): a JSON config object
    /// with no `type` is rejected, and the error carries
    /// `SCP-STORAGE-8000`. The NAPI constructor (`new SCP(config_json)`)
    /// routes through `with_storage`, so this covers both surfaces.
    #[test]
    fn missing_type_is_rejected_with_storage_8000() {
        let err = Scp::with_storage("{}".to_owned())
            .err()
            .expect("missing storage 'type' must be rejected — no default");
        assert!(
            err.reason.contains(codes::STORAGE_8000),
            "missing-selection error must carry SCP-STORAGE-8000: {}",
            err.reason
        );
    }

    /// An UNKNOWN `type` value (e.g. `{"type":"bogus"}`) is a
    /// storage-SELECTION error, so it carries `SCP-STORAGE-8000` — the same
    /// code as a missing `type` — not a generic field-validation code.
    #[test]
    fn unknown_type_is_rejected_with_storage_8000() {
        let err = Scp::with_storage(r#"{"type":"bogus"}"#.to_owned())
            .err()
            .expect("an unknown storage 'type' must be rejected");
        assert!(
            err.reason.contains(codes::STORAGE_8000),
            "unknown-selection error must carry SCP-STORAGE-8000: {}",
            err.reason
        );
    }

    /// A `config_json` that is not a JSON object is rejected.
    #[test]
    fn non_object_config_is_rejected() {
        assert!(
            Scp::with_storage("\"in_memory\"".to_owned()).is_err(),
            "a bare JSON string is not a valid storage config object"
        );
    }

    /// The explicit `{"type":"in_memory"}` dev path constructs successfully
    /// and yields a live instance with a non-zero monotonic id.
    #[test]
    fn in_memory_json_constructs_and_is_live() {
        let scp = Scp::with_storage(r#"{"type":"in_memory"}"#.to_owned())
            .expect("in_memory selection must construct");
        let id: u64 = scp
            .instance_id()
            .parse()
            .expect("instance_id is a u64 string");
        assert!(
            id > 0,
            "constructed instance must expose a non-zero instance_id"
        );
    }

    /// The `#[napi(constructor)]` entry point requires the config argument
    /// and routes to the same fail-closed parser: missing `type` is
    /// `SCP-STORAGE-8000`.
    #[test]
    fn constructor_requires_explicit_selection() {
        let err = Scp::new("{}".to_owned())
            .err()
            .expect("constructor with empty config must be rejected");
        assert!(
            err.reason.contains(codes::STORAGE_8000),
            "constructor missing-selection error must carry SCP-STORAGE-8000: {}",
            err.reason
        );
    }
}

#[cfg(all(test, feature = "testing"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod identity_remove_validation_tests {
    use super::*;

    /// `identity_remove` and `identity_remove_if_present` must reject a
    /// non-empty but syntactically invalid DID via the shared `validate_did`
    /// gate — matching the `PyO3` reference bridge — before touching the
    /// registry. Without this the NAPI bridge would be looser than `PyO3`
    /// on the same operation. Mirrors `petname_malformed_owner_rejected`.
    #[test]
    fn identity_remove_malformed_did_rejected() {
        let scp = Scp::new_in_memory_for_test();
        let bad = "not-a-did".to_owned();
        assert!(
            scp.identity_remove(bad.clone()).is_err(),
            "identity_remove must reject a malformed DID"
        );
        assert!(
            scp.identity_remove_if_present(bad).is_err(),
            "identity_remove_if_present must reject a malformed DID"
        );
    }

    /// A syntactically valid DID that is not registered is accepted: the
    /// validation gate passes and the op is a no-op (idempotent removal).
    /// `identity_remove` returns `Ok(())`; `identity_remove_if_present`
    /// returns `Ok(false)`.
    #[test]
    fn identity_remove_valid_absent_did_is_ok_noop() {
        let scp = Scp::new_in_memory_for_test();
        let valid_absent = "did:dht:z6MkNeverRegisteredIdentityForRemoveTest".to_owned();
        scp.identity_remove(valid_absent.clone())
            .expect("valid DID must not be rejected by identity_remove");
        assert!(
            !scp.identity_remove_if_present(valid_absent)
                .expect("valid DID must not be rejected by identity_remove_if_present"),
            "removing an unregistered DID must report false"
        );
    }
}
