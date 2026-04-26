//! `#[napi] Scp` class — the caller-owned SCP instance exposed to TypeScript.
//!
//! `SCP` (exposed to TS as `SCP`) is the top-level SDK-facing handle that
//! owns a [`NapiBridgeInstance`] — which in turn owns the `ContextManager`,
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

use napi::Error as NapiError;
use napi_derive::napi;
use scp_ffi_common::bridge_instance::BridgeInstanceCore as _;
use scp_ffi_common::error_codes as codes;
use scp_identity::DidMethod as _;
use scp_primitives::Clock as _;

use napi::bindgen_prelude::Buffer;

use crate::context::{
    NapiAssetEntry, NapiBatchPublishResult, NapiContextHandle, NapiEvaluationResult, NapiMessage,
    NapiPublishResult,
};
use crate::error::{ScpNapiError, validate_custody_type};
use crate::event_log::{NapiCheckpoint, NapiEvent, NapiProof};
use crate::identity::NapiIdentity;
use crate::mcp::{
    NapiAllowlistState, NapiMcpClientHandle, NapiMcpInvokeResult, NapiMcpServerConfig,
    NapiMcpServerHandle, NapiMcpToolInfo,
};
use crate::runtime::{NapiBridgeInstance, StorageConfig};
#[cfg(feature = "server")]
use crate::server::{NapiNodeHandle, NapiRelayHandle};
use crate::sync::NapiSyncPolicy;
use crate::testing::NapiFullStackNode;
use crate::tools::{NapiToolDefinition, NapiToolVerificationResult};
use crate::transport::{NapiReliabilityScore, NapiTransportManager, NapiTransportStatus};
use crate::trust::{NapiAttestationVerificationResult, NapiChallengeResult, NapiTrustScoreResult};
use crate::ucan::NapiUcanToken;

/// The SCP instance — a caller-owned handle that wraps a
/// [`NapiBridgeInstance`].
///
/// # JS usage
///
/// ```js
/// import { SCP } from '@limn-works/scp-ts-napi';
///
/// const scp = new SCP();                 // fresh in-memory instance
/// await scp.shutdown(5);                 // async graceful shutdown
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
    /// Constructs a fresh `SCP` instance with default in-memory state.
    ///
    /// Equivalent to [`NapiBridgeInstance::new_napi`]. Each call produces
    /// a brand-new instance with its own `instance_id`, registries, and
    /// transport state — no state is shared with any other `SCP`.
    #[napi(constructor)]
    #[allow(clippy::new_without_default)] // napi constructor cannot take Default
    pub fn new() -> napi::Result<Self> {
        Ok(Self {
            inner: Arc::new(NapiBridgeInstance::new_napi()),
        })
    }

    /// Constructs an `SCP` instance with a storage configuration.
    ///
    /// In PR 1 only `{"type":"in_memory"}` is honored. PR 3 adds
    /// `{"type":"sqlite", "path":..., "key":...}`.
    ///
    /// Accepts a JSON-encoded string so the API remains stable while the
    /// `StorageConfig` surface evolves (napi-rs has no stable derive for
    /// untyped JSON values). Unknown variants are rejected with
    /// `SCP-VALID-7005`.
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
        let ty = config_obj
            .get("type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("in_memory");
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
                // `key` is accepted either as a hex-encoded string (most
                // common from JS/TS where JSON has no native bytes type)
                // or as a JSON array of byte values.
                let key_bytes: Vec<u8> = match config_obj.get("key") {
                    Some(serde_json::Value::String(hex_str)) => hex::decode(hex_str)
                        .map_err(|e| {
                            napi::Error::from(ScpNapiError::Validation {
                                message: format!(
                                    "withStorage(sqlite): 'key' is not valid hex: {e}"
                                ),
                                code: codes::VALID_7005.to_owned(),
                            })
                        })?,
                    Some(serde_json::Value::Array(arr)) => arr
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
                    Some(_) | None => {
                        return Err(napi::Error::from(ScpNapiError::Validation {
                            message: "withStorage(sqlite): missing or wrongly-typed 'key' (expected hex string or byte array)".to_owned(),
                            code: codes::VALID_7005.to_owned(),
                        }));
                    }
                };
                StorageConfig::Sqlite {
                    path: std::path::PathBuf::from(path_str),
                    key: zeroize::Zeroizing::new(key_bytes),
                }
            }
            other => {
                return Err(napi::Error::from(ScpNapiError::Validation {
                    message: format!(
                        "unsupported storage type: {other:?} — expected \"in_memory\" or \"sqlite\""
                    ),
                    code: codes::VALID_7005.to_owned(),
                }));
            }
        };
        let inner = NapiBridgeInstance::with_storage_napi(storage).map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: e.to_string(),
                code: codes::VALID_7005.to_owned(),
            })
        })?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Constructs an `SCP` instance with a persistence provider placeholder.
    ///
    /// PR 1 exposes this factory so SDK consumers can prepare for the
    /// persistence-enabled path. The current implementation builds a fresh
    /// in-memory instance identical to [`Self::new`]; PR 3 wires the
    /// real [`scp_core::context::ContextPersistence`] plumbing through.
    #[napi(factory, js_name = "withPersistence")]
    pub fn with_persistence() -> napi::Result<Self> {
        // Without an exposed persistence type on the FFI surface yet
        // (Storage config lands in PR 3), fall back to the in-memory path.
        // This preserves API shape for callers while keeping the
        // constructor panic-free.
        Self::new()
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
    /// Clears the suspended flag, then runs any per-bridge async work chained
    /// by the `BridgeInstanceCore::resume` override (transport reconnect
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
    pub async fn identity_create(
        &self,
        custody: String,
        testing_seed: Option<napi::bindgen_prelude::Buffer>,
    ) -> napi::Result<crate::identity::NapiIdentity> {
        use crate::identity::{NapiIdentityInner, ensure_did_resolver_initialized_on};

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
        ensure_did_resolver_initialized_on(bi);

        match custody.as_str() {
            #[cfg(feature = "allow_in_memory_custody")]
            "in_memory" => {
                use scp_identity::DidDht;
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
                let key_custody = Arc::new(crate::identity::OpaqueInMemoryKeyCustody(in_memory));
                let dht = DidDht::new();
                let (scp_identity, document) = dht
                    .create(&key_custody.0)
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
                    }),
                };
                crate::increment_handle_count();
                Ok(handle)
            }
            #[cfg(not(feature = "allow_in_memory_custody"))]
            "in_memory" => {
                // Mirrors PyO3 `parse_custody_with_seed`
                // (cfg(not(allow_in_memory_custody))): a `testing_seed` is
                // a parity-harness affordance gated on the
                // `allow_in_memory_custody` feature, so surface it as
                // SCP-VALID-7008 ("testing-only feature requires feature
                // flag") ahead of the generic custody-unavailable error.
                if testing_seed_bytes.is_some() {
                    return Err(NapiError::from(ScpNapiError::Validation {
                        message:
                            "`testing_seed` parameter requires the allow_in_memory_custody feature"
                                .to_owned(),
                        code: codes::VALID_7008.to_owned(),
                    }));
                }
                Err(ScpNapiError::Identity {
                    message:
                        "in_memory custody is not available in this build -- enable allow_in_memory_custody"
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
    pub async fn identity_create_with_agent_key(
        &self,
        custody: String,
    ) -> napi::Result<crate::identity::NapiIdentity> {
        use crate::identity::{NapiIdentityInner, ensure_did_resolver_initialized_on};

        validate_custody_type(&custody).map_err(NapiError::from)?;

        let bi = &*self.inner;
        ensure_did_resolver_initialized_on(bi);

        match custody.as_str() {
            #[cfg(feature = "allow_in_memory_custody")]
            "in_memory" => {
                use scp_platform::testing::InMemoryKeyCustody;
                use scp_identity::DidDht;

                let key_custody = Arc::new(crate::identity::OpaqueInMemoryKeyCustody(
                    InMemoryKeyCustody::new(),
                ));
                let dht = DidDht::new();
                let (scp_identity, document) = dht
                    .create_with_agent_key(&key_custody.0)
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
                    }),
                };
                crate::increment_handle_count();
                Ok(handle)
            }
            #[cfg(not(feature = "allow_in_memory_custody"))]
            "in_memory" => Err(ScpNapiError::Identity {
                message:
                    "in_memory custody is not available in this build -- enable allow_in_memory_custody"
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

    /// Per-instance equivalent of `identity_load`.
    ///
    /// Looks the DID up in this instance's identity registry first; falls
    /// back to DHT resolution.
    #[napi(js_name = "identityLoad")]
    pub async fn identity_load(&self, did: String) -> napi::Result<crate::identity::NapiIdentity> {
        use crate::identity::NapiIdentityInner;
        use scp_identity::DidDht;

        if !did.starts_with("did:dht:") {
            return Err(ScpNapiError::Identity {
                message: format!("unsupported DID method: {did} — only did:dht is supported"),
                code: codes::IDENT_1004.to_owned(),
            }
            .into());
        }

        let bi = &*self.inner;

        #[cfg(feature = "allow_in_memory_custody")]
        {
            let local_result = crate::runtime::with_identity(bi, &did, |entry| {
                Ok((
                    entry.identity.clone(),
                    Arc::clone(&entry.custody),
                    entry.document.clone(),
                ))
            });

            if let Ok((identity, custody, document)) = local_result {
                let verifying_key_hex =
                    crate::identity::identity_verifying_key_hex(&custody, &identity.identity_key)
                        .await;
                let handle = crate::identity::NapiIdentity {
                    inner: Arc::new(NapiIdentityInner {
                        did,
                        custody_type: "in_memory".to_owned(),
                        scp_identity: Some(identity),
                        in_memory_custody: Some(custody),
                        document: Some(document),
                        bi: Arc::clone(&self.inner),
                        verifying_key_hex,
                        instance_id: bi.instance_id(),
                    }),
                };
                crate::increment_handle_count();
                return Ok(handle);
            }
        }

        let dht = DidDht::new();
        let document = dht
            .resolve(&did)
            .await
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

        let handle = crate::identity::NapiIdentity {
            inner: Arc::new(NapiIdentityInner {
                did,
                custody_type: "external".to_owned(),
                scp_identity: None,
                #[cfg(feature = "allow_in_memory_custody")]
                in_memory_custody: None,
                document: Some(document),
                bi: Arc::clone(&self.inner),
                verifying_key_hex: None,
                instance_id: bi.instance_id(),
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
        use scp_identity::DidDht;

        if !did.starts_with("did:dht:") {
            return Err(ScpNapiError::Identity {
                message: format!("unsupported DID method: {did} — only did:dht is supported"),
                code: codes::IDENT_1004.to_owned(),
            }
            .into());
        }

        let bi = &*self.inner;

        #[cfg(feature = "allow_in_memory_custody")]
        let local_doc =
            crate::runtime::with_identity(bi, &did, |entry| Ok(entry.document.clone())).ok();
        #[cfg(not(feature = "allow_in_memory_custody"))]
        let local_doc: Option<scp_identity::DidDocument> = None;

        let document = if let Some(doc) = local_doc {
            doc
        } else {
            let dht = DidDht::new();
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

    /// Per-instance equivalent of `identity_remove`.
    ///
    /// Drops retained key material for the DID. Idempotent — succeeds
    /// silently when the DID is not in the registry.
    #[cfg(feature = "allow_in_memory_custody")]
    #[napi(js_name = "identityRemove")]
    pub fn identity_remove(&self, did: String) {
        crate::runtime::remove_identity(&self.inner, &did);
    }

    /// Per-instance equivalent of `identity_remove_if_present`.
    ///
    /// Returns `true` if the identity was present and removed.
    #[cfg(feature = "allow_in_memory_custody")]
    #[napi(js_name = "identityRemoveIfPresent")]
    #[must_use]
    pub fn identity_remove_if_present(&self, did: String) -> bool {
        crate::runtime::remove_identity_if_present(&self.inner, &did)
    }

    /// Per-instance equivalent of `identity_attest_device`.
    ///
    /// The attestation is device-local; the DID argument is retained for
    /// API symmetry with the free function.
    #[cfg(feature = "allow_in_memory_custody")]
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
    #[cfg(feature = "allow_in_memory_custody")]
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

    /// Per-instance equivalent of `identity_create_link_attestation`.
    #[cfg(feature = "allow_in_memory_custody")]
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
            rt.block_on(custody.0.sign(&key_handle, &built.canonical_bytes))
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
    #[cfg(feature = "allow_in_memory_custody")]
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
    #[cfg(feature = "allow_in_memory_custody")]
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

    /// Per-instance equivalent of `identity_verify_link_attestation`.
    ///
    /// Pure Ed25519 signature verification; does not consult bridge state.
    /// Exposed on `Scp` for API symmetry so the demolition slice can drop
    /// the free function without leaving callers stranded.
    #[napi(js_name = "identityVerifyLinkAttestation")]
    #[allow(clippy::unused_async)] // napi-rs requires async for Promise return
    pub async fn identity_verify_link_attestation(
        &self,
        attestation_json: String,
        issuer_public_key_hex: String,
    ) -> napi::Result<bool> {
        use scp_core::identity::attestation::IdentityLinkAttestation;

        let _ = &self.inner;

        let attestation: IdentityLinkAttestation = serde_json::from_str(&attestation_json)
            .map_err(|e| {
                NapiError::from(ScpNapiError::Identity {
                    message: format!("failed to parse attestation JSON: {e}"),
                    code: codes::IDENT_1044.to_owned(),
                })
            })?;

        let pub_bytes = hex::decode(&issuer_public_key_hex).map_err(|e| {
            NapiError::from(ScpNapiError::Identity {
                message: format!("invalid issuer_public_key_hex: {e}"),
                code: codes::IDENT_1044.to_owned(),
            })
        })?;
        Ok(attestation.verify_signature(&pub_bytes).is_ok())
    }

    /// Per-instance equivalent of `identity_execute_recovery` (spec §9.12).
    ///
    /// Executes the compromise recovery protocol and returns the result as
    /// a JSON string. Bridge-level recovery backend is a placeholder — real
    /// backends are injected via the SDK wrapper.
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
        use std::collections::HashSet;

        use scp_core::identity::recovery::{
            CompromiseRecoveryOrchestrator, CompromiseTier, KeyRotationOutcome, PskRotationParams,
            RecoveryBackend, RecoveryStepError, active_key_rotation_outcome,
            agent_key_rotation_outcome,
        };
        use scp_ffi_common::validate::validate_did;
        use scp_identity::DID;

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
                     recovery is restricted to identities created or loaded via this SCP"
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

        let did_val = DID::from(did.as_str());

        let compromise_tier = match tier.as_str() {
            "agent" => CompromiseTier::Agent,
            "active_signing" => CompromiseTier::ActiveSigning,
            "identity_key" => CompromiseTier::IdentityKey,
            other => {
                return Err(NapiError::from(ScpNapiError::Identity {
                    message: format!(
                        "invalid compromise tier: {other}; expected 'agent', 'active_signing', or 'identity_key'"
                    ),
                    code: codes::IDENT_1020.to_owned(),
                }));
            }
        };

        let now_ms = scp_primitives::SystemClock.now_millis();
        let key_rotation = match compromise_tier {
            CompromiseTier::Agent => agent_key_rotation_outcome(&did_val, now_ms),
            CompromiseTier::ActiveSigning => active_key_rotation_outcome(&did_val, now_ms),
            CompromiseTier::IdentityKey => {
                scp_core::identity::recovery::identity_key_rotation_outcome(
                    &did_val,
                    did_val.clone(),
                    now_ms,
                )
            }
        };

        struct NapiRecoveryBackend;
        impl RecoveryBackend for NapiRecoveryBackend {
            fn mls_update(
                &self,
                _context_id: &str,
                _key_rotation: &KeyRotationOutcome,
            ) -> Result<(), RecoveryStepError> {
                Ok(())
            }
            fn revoke_ucans(
                &self,
                _context_id: &str,
                _key_rotation: &KeyRotationOutcome,
            ) -> Result<(), RecoveryStepError> {
                Ok(())
            }
            fn rotate_key_packages(
                &self,
                _context_id: &str,
                _key_rotation: &KeyRotationOutcome,
            ) -> Result<(), RecoveryStepError> {
                Ok(())
            }
            fn notify_contacts(
                &self,
                _did: &DID,
                _tier: CompromiseTier,
                _key_rotation: &KeyRotationOutcome,
                _contacts: &HashSet<DID>,
            ) -> bool {
                true
            }
            fn rotate_psk(&self, _params: &PskRotationParams) -> bool {
                true
            }
        }

        let orchestrator = CompromiseRecoveryOrchestrator::new(did_val, context_ids);
        let contacts = HashSet::new();
        let backend = NapiRecoveryBackend;

        // Drive the async orchestrator on the module-local tokio runtime
        // (crate::runtime()). The prior `Handle::try_current()` path
        // failed on the napi-rs worker thread because libuv workers
        // don't carry a tokio context (round-2 bug-catcher finding).
        let result = crate::runtime()
            .block_on(orchestrator.execute_recovery(
                compromise_tier,
                &key_rotation,
                &contacts,
                None,
                &backend,
                &scp_primitives::SystemClock,
            ))
            .map_err(|e| {
                NapiError::from(ScpNapiError::Identity {
                    message: format!("recovery failed: {e}"),
                    code: codes::IDENT_1022.to_owned(),
                })
            })?;

        serde_json::to_string(&result).map_err(|e| {
            NapiError::from(ScpNapiError::Identity {
                message: format!("failed to serialize recovery result: {e}"),
                code: codes::IDENT_1023.to_owned(),
            })
        })
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
        use scp_ffi_common::validate::validate_did;
        use scp_identity::DID;

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
            .block_on(orchestrator.execute(&backend, &scp_primitives::SystemClock))
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
        use scp_identity::DID;

        if owner_did.is_empty() {
            return Err(NapiError::from(ScpNapiError::Validation {
                message: "owner_did must not be empty".to_owned(),
                code: codes::VALID_7110.to_owned(),
            }));
        }
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
        use scp_identity::DID;

        if owner_did.is_empty() {
            return Err(NapiError::from(ScpNapiError::Validation {
                message: "owner_did must not be empty".to_owned(),
                code: codes::VALID_7110.to_owned(),
            }));
        }
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
        if owner_did.is_empty() {
            return Err(NapiError::from(ScpNapiError::Validation {
                message: "owner_did must not be empty".to_owned(),
                code: codes::VALID_7110.to_owned(),
            }));
        }
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
        if owner_did.is_empty() {
            return Err(NapiError::from(ScpNapiError::Validation {
                message: "owner_did must not be empty".to_owned(),
                code: codes::VALID_7110.to_owned(),
            }));
        }
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
        if owner_did.is_empty() {
            return Err(NapiError::from(ScpNapiError::Validation {
                message: "owner_did must not be empty".to_owned(),
                code: codes::VALID_7110.to_owned(),
            }));
        }
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
        if owner_did.is_empty() {
            return Err(NapiError::from(ScpNapiError::Validation {
                message: "owner_did must not be empty".to_owned(),
                code: codes::VALID_7110.to_owned(),
            }));
        }
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
        use scp_identity::DID;

        if owner_did.is_empty() {
            return Err(NapiError::from(ScpNapiError::Validation {
                message: "owner_did must not be empty".to_owned(),
                code: codes::VALID_7110.to_owned(),
            }));
        }
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
        if owner_did.is_empty() {
            return Err(NapiError::from(ScpNapiError::Validation {
                message: "owner_did must not be empty".to_owned(),
                code: codes::VALID_7110.to_owned(),
            }));
        }
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
        use scp_identity::DID;

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
            &scp_primitives::SystemClock,
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
        use scp_identity::DID;

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
        use scp_identity::DID;

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
                &scp_primitives::SystemClock,
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
        use scp_identity::DID;

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
                &scp_primitives::SystemClock,
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
    // [`crate::context`] / [`crate::tools`], routing through `&*self.inner`
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
    #[napi(js_name = "broadcastSubscribe")]
    pub async fn broadcast_subscribe(
        &self,
        handle: &NapiContextHandle,
        subscriber_did: String,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::broadcast_subscribe_on(&self.inner, handle, subscriber_did).await
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
    #[napi(js_name = "broadcastHandleKeyRequest")]
    pub async fn broadcast_handle_key_request(
        &self,
        handle: &NapiContextHandle,
        author_did: String,
        requester_did: String,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::broadcast_handle_key_request_on(
            &self.inner,
            handle,
            author_did,
            requester_did,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `context_execute_governance_action`.
    #[napi(js_name = "contextExecuteGovernanceAction")]
    pub async fn context_execute_governance_action(
        &self,
        handle: &NapiContextHandle,
        action_json: String,
        proposer_did: String,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::context::context_execute_governance_action_on(
            &self.inner,
            handle,
            action_json,
            proposer_did,
        )
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
    #[napi(js_name = "contextImport")]
    pub async fn context_import(&self, data: Vec<u8>) -> napi::Result<String> {
        crate::context::context_import_on(&self.inner, data).await
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

    /// Per-instance equivalent of the free-function `check_scoped_capability`.
    ///
    /// This operation is pure — it does not touch any bridge-instance state —
    /// so the method forwards to a shared inner helper with no `bi` argument.
    #[napi(js_name = "checkScopedCapability")]
    #[must_use]
    pub fn check_scoped_capability(
        &self,
        granted_capabilities: Vec<String>,
        required_capability: String,
    ) -> bool {
        crate::context::check_scoped_capability_inner(granted_capabilities, required_capability)
    }

    /// Per-instance equivalent of the free-function `evaluate_invitation`.
    #[napi(js_name = "evaluateInvitation")]
    pub fn evaluate_invitation(
        &self,
        params_json: String,
        inviter_did: String,
        identity_did: String,
        policy_json: Option<String>,
        spending_json: Option<String>,
        trusted_dids_json: Option<String>,
    ) -> napi::Result<NapiEvaluationResult> {
        crate::context::evaluate_invitation_on(
            &self.inner,
            params_json,
            inviter_did,
            identity_did,
            policy_json,
            spending_json,
            trusted_dids_json,
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

    // ===== sub-slice C: tools =====

    /// Per-instance equivalent of the free-function `tool_register`.
    #[napi(js_name = "toolRegister")]
    pub async fn tool_register(
        &self,
        handle: &NapiContextHandle,
        definition: NapiToolDefinition,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::tools::tool_register_on(&self.inner, handle, definition).await
    }

    /// Per-instance equivalent of the free-function `tool_invoke`.
    #[napi(js_name = "toolInvoke")]
    #[allow(clippy::too_many_arguments)]
    pub async fn tool_invoke(
        &self,
        handle: &NapiContextHandle,
        tool_id: String,
        input_json: String,
        identity_did: String,
        ucan_token: String,
        proof_tokens: Option<Vec<String>>,
        spending_ucan_jwt: Option<String>,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::tools::tool_invoke_on(
            &self.inner,
            handle,
            tool_id,
            input_json,
            identity_did,
            ucan_token,
            proof_tokens,
            spending_ucan_jwt,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `tool_verify`.
    #[napi(js_name = "toolVerify")]
    pub async fn tool_verify(
        &self,
        handle: &NapiContextHandle,
        tool_id: String,
    ) -> napi::Result<NapiToolVerificationResult> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::tools::tool_verify_on(&self.inner, handle, tool_id).await
    }

    /// Per-instance equivalent of the free-function `tool_invoke_cross_context`.
    #[napi(js_name = "toolInvokeCrossContext")]
    #[allow(clippy::too_many_arguments)]
    pub async fn tool_invoke_cross_context(
        &self,
        source_handle: &NapiContextHandle,
        target_handle: &NapiContextHandle,
        tool_id: String,
        input_json: String,
        invoker_did: String,
        ucan_token: String,
        chain_depth: u8,
        proof_tokens: Option<Vec<String>>,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, source_handle, target_handle);
        crate::tools::tool_invoke_cross_context_on(
            &self.inner,
            source_handle,
            target_handle,
            tool_id,
            input_json,
            invoker_did,
            ucan_token,
            chain_depth,
            proof_tokens,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `tool_session_create`.
    #[napi(js_name = "toolSessionCreate")]
    pub async fn tool_session_create(
        &self,
        handle: &NapiContextHandle,
        tool_id: String,
        source_context_id: String,
        ttl_seconds: Option<u32>,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::tools::tool_session_create_on(
            &self.inner,
            handle,
            tool_id,
            source_context_id,
            ttl_seconds,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `tool_session_invoke`.
    #[napi(js_name = "toolSessionInvoke")]
    pub async fn tool_session_invoke(
        &self,
        handle: &NapiContextHandle,
        session_id: String,
        input_json: String,
        invoker_did: String,
        ucan_token: String,
        proof_tokens: Option<Vec<String>>,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::tools::tool_session_invoke_on(
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

    /// Per-instance equivalent of the free-function `tool_session_close`.
    #[napi(js_name = "toolSessionClose")]
    pub async fn tool_session_close(
        &self,
        handle: &NapiContextHandle,
        session_id: String,
    ) -> napi::Result<()> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::tools::tool_session_close_on(&self.inner, handle, session_id).await
    }

    /// Per-instance equivalent of the free-function `tool_interface_expose`.
    #[napi(js_name = "toolInterfaceExpose")]
    pub async fn tool_interface_expose(
        &self,
        handle: &NapiContextHandle,
        tool_id: String,
        target_context_id: String,
        rate_limit_json: Option<String>,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::tools::tool_interface_expose_on(
            &self.inner,
            handle,
            tool_id,
            target_context_id,
            rate_limit_json,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `tool_interface_accept`.
    #[napi(js_name = "toolInterfaceAccept")]
    pub async fn tool_interface_accept(
        &self,
        handle: &NapiContextHandle,
        interface_json: String,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::tools::tool_interface_accept_on(&self.inner, handle, interface_json).await
    }

    /// Per-instance equivalent of the free-function `tool_interface_revoke`.
    #[napi(js_name = "toolInterfaceRevoke")]
    pub async fn tool_interface_revoke(
        &self,
        handle: &NapiContextHandle,
        interface_id_hex: String,
    ) -> napi::Result<String> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::tools::tool_interface_revoke_on(&self.inner, handle, interface_id_hex).await
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
        presenting_agent_did: Option<String>,
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
    /// returns the bridge-scoped handleless probe (mirrors PyO3/WASM).
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
    ) -> napi::Result<i64> {
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
    ) -> napi::Result<i64> {
        crate::economy::economy_evaluate_formula_on(&self.inner, formula_json, metrics_json)
    }

    /// Per-instance equivalent of the free-function `economy_budget_remaining`.
    #[napi(js_name = "economyBudgetRemaining")]
    pub fn economy_budget_remaining(&self, context_id: String, did: String) -> napi::Result<i64> {
        crate::economy::economy_budget_remaining_on(&self.inner, context_id, did)
    }

    /// Per-instance equivalent of the free-function `economy_budget_grant`.
    #[napi(js_name = "economyBudgetGrant")]
    pub fn economy_budget_grant(
        &self,
        context_id: String,
        did: String,
        amount: i64,
    ) -> napi::Result<()> {
        crate::economy::economy_budget_grant_on(&self.inner, context_id, did, amount)
    }

    /// Per-instance equivalent of the free-function `economy_budget_record_spend`.
    #[napi(js_name = "economyBudgetRecordSpend")]
    pub fn economy_budget_record_spend(
        &self,
        context_id: String,
        did: String,
        amount: i64,
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
    #[napi(js_name = "economyAntispamEscalatedCost")]
    #[allow(clippy::too_many_arguments)]
    pub fn economy_antispam_escalated_cost(
        &self,
        context_id: String,
        sender_did: String,
        now: i64,
        base_cost: i64,
        thresholds_json: String,
        floor: Option<i64>,
        cap: Option<i64>,
    ) -> napi::Result<i64> {
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
        profile_json: String,
        requirements_json: String,
    ) -> napi::Result<bool> {
        crate::trust::verify_participation_requirements_on(
            &self.inner,
            profile_json,
            requirements_json,
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

    // -------------------------------------------------------------------
    // Server (feature-gated)
    // -------------------------------------------------------------------

    /// Per-instance equivalent of the free-function `relay_start_in_memory`.
    #[cfg(feature = "server")]
    #[napi(js_name = "relayStartInMemory")]
    pub async fn relay_start_in_memory(&self) -> napi::Result<NapiRelayHandle> {
        crate::server::relay_start_in_memory_on(&self.inner).await
    }

    /// Per-instance equivalent of the free-function `relay_start_local`.
    #[cfg(feature = "server")]
    #[napi(js_name = "relayStartLocal")]
    pub async fn relay_start_local(&self, data_dir: String) -> napi::Result<NapiRelayHandle> {
        crate::server::relay_start_local_on(&self.inner, data_dir).await
    }

    /// Per-instance equivalent of the free-function `node_start_in_memory`.
    #[cfg(feature = "server")]
    #[napi(js_name = "nodeStartInMemory")]
    pub async fn node_start_in_memory(
        &self,
        identity_did: Option<String>,
    ) -> napi::Result<NapiNodeHandle> {
        crate::server::node_start_in_memory_on(&self.inner, identity_did).await
    }

    /// Per-instance equivalent of the free-function `node_start_local`.
    #[cfg(feature = "server")]
    #[napi(js_name = "nodeStartLocal")]
    pub async fn node_start_local(
        &self,
        data_dir: String,
        identity_did: Option<String>,
        passphrase: Option<String>,
    ) -> napi::Result<NapiNodeHandle> {
        crate::server::node_start_local_on(&self.inner, data_dir, identity_did, passphrase).await
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
        tool_name: String,
        input_json: String,
        context_id: String,
        invoker_did: String,
    ) -> napi::Result<NapiMcpInvokeResult> {
        crate::napi_check_handle!(&self.inner.core, handle);
        crate::mcp::mcp_client_invoke_on(
            &self.inner,
            handle,
            tool_name,
            input_json,
            context_id,
            invoker_did,
        )
        .await
    }

    /// Per-instance equivalent of the free-function `mcp_configure_stdio_allowlist`.
    #[napi(js_name = "mcpConfigureStdioAllowlist")]
    pub fn mcp_configure_stdio_allowlist(
        &self,
        additional_binaries: Vec<String>,
    ) -> napi::Result<()> {
        crate::mcp::mcp_configure_stdio_allowlist_on(&self.inner, additional_binaries)
    }

    /// Per-instance equivalent of the free-function `mcp_disable_stdio_allowlist`.
    #[napi(js_name = "mcpDisableStdioAllowlist")]
    pub fn mcp_disable_stdio_allowlist(&self) -> napi::Result<()> {
        crate::mcp::mcp_disable_stdio_allowlist_on(&self.inner)
    }

    /// Per-instance equivalent of the free-function `mcp_reset_stdio_allowlist`.
    #[napi(js_name = "mcpResetStdioAllowlist")]
    pub fn mcp_reset_stdio_allowlist(&self) -> napi::Result<()> {
        crate::mcp::mcp_reset_stdio_allowlist_on(&self.inner)
    }

    /// Per-instance equivalent of the free-function `mcp_get_stdio_allowlist`.
    #[napi(js_name = "mcpGetStdioAllowlist")]
    pub fn mcp_get_stdio_allowlist(&self) -> napi::Result<NapiAllowlistState> {
        crate::mcp::mcp_get_stdio_allowlist_on(&self.inner)
    }

    // -------------------------------------------------------------------
    // Testing (full-stack E2E harness)
    // -------------------------------------------------------------------

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
    #[cfg(feature = "allow_in_memory_custody")]
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
#[cfg(all(test, feature = "allow_in_memory_custody"))]
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

        let custody = Arc::new(OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()));
        let dht = scp_identity::DidDht::new();
        let (identity, document) = rt.block_on(dht.create(&custody.0)).unwrap();
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
        // It may still fail downstream (the bridge-level recovery backend is
        // a placeholder that returns Ok) but it must NOT be a VALID-7140
        // busy rejection.
        drop(permits.pop());
        let result = scp.identity_execute_recovery(did, "agent".to_owned(), Vec::new());
        match result {
            Ok(_) => {
                // Happy path — orchestrator completed.
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
