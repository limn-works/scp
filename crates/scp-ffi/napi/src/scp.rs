//! `#[napi] Scp` class — the caller-owned SCP instance exposed to TypeScript.
//!
//! `SCP` (exposed to TS as `SCP`) is the top-level SDK-facing handle that
//! owns a [`NapiBridgeInstance`] — which in turn owns the `ContextManager`,
//! transport, and bridge-specific registries.
//!
//! PR 1 introduces the type and its constructors plus the lifecycle
//! methods. Later PRs migrate the free-function façade onto methods on
//! this class; until then free functions continue to operate on the
//! default instance (`DEFAULT_BRIDGE_INSTANCE` in [`crate::runtime`]).
//!
//! See #1549 Phase 4 remainder plan (PR 1).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use napi::Error as NapiError;
use napi_derive::napi;
use scp_ffi_common::bridge_instance::BridgeInstanceCore as _;
use scp_ffi_common::error_codes as codes;

use crate::error::{ScpNapiError, validate_custody_type};
use crate::runtime::{NapiBridgeInstance, StorageConfig, default_bridge_instance};

/// The SCP instance — a caller-owned handle that wraps a
/// [`NapiBridgeInstance`].
///
/// # JS usage
///
/// ```js
/// import { SCP } from '@limn-works/scp-ts-napi';
///
/// const scp = new SCP();                 // fresh in-memory instance
/// const shared = SCP.default();          // shared process-wide default
/// await scp.shutdown(5);                 // async graceful shutdown
/// ```
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
    /// Equivalent to [`NapiBridgeInstance::new_napi`]. No state is shared
    /// with the process-wide default instance.
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
        Ok(Self {
            inner: Arc::new(NapiBridgeInstance::with_storage_napi(storage)),
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

    /// Returns an `SCP` wrapping the process-wide default instance.
    ///
    /// Multiple calls return distinct `SCP` objects, but each wraps the
    /// same underlying `Arc<NapiBridgeInstance>` — their `instanceId`s
    /// match, and changes made through one are visible to the other.
    #[napi(factory, js_name = "default")]
    pub fn default_instance() -> napi::Result<Self> {
        Ok(Self {
            inner: default_bridge_instance()?,
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
    /// Clears the suspended flag, then runs any per-bridge async work chained
    /// by the [`BridgeInstanceCore::resume`] override (transport reconnect
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
    /// 2^32 ms is ≈ 49.7 days, far beyond any realistic budget.
    #[napi]
    pub async fn shutdown(&self, timeout_millis: u32) -> napi::Result<()> {
        let timeout = Duration::from_millis(u64::from(timeout_millis));
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
    // Migrates the `identity_*` free functions in `crate::identity` to
    // instance methods on [`Scp`] routed through `&*self.inner`. The free
    // functions are retained until the demolition slice deletes them; both
    // paths continue to share the per-bridge `NapiBridgeInstance` state —
    // method callers use their own `SCP`'s instance while free-function
    // callers use `DEFAULT_BRIDGE_INSTANCE`.
    // ====================================================================

    /// Per-instance equivalent of the free-function `identity_create`.
    ///
    /// Creates a new DID identity under this SCP instance, routing through
    /// `&*self.inner` instead of the process-global default bridge. Key
    /// material, registry writes, and the DID resolver are all scoped to
    /// this `SCP`.
    ///
    /// See [`crate::identity::identity_create`] for argument semantics.
    #[napi(js_name = "identityCreate")]
    pub async fn identity_create(
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
                    .create(&key_custody.0)
                    .await
                    .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

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
                let handle = crate::identity::NapiIdentity {
                    inner: Arc::new(NapiIdentityInner {
                        did,
                        custody_type: "in_memory".to_owned(),
                        scp_identity: Some(identity),
                        in_memory_custody: Some(custody),
                        document: Some(document),
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

        let _ = &self.inner;

        validate_did(&did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
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

        let handle = tokio::runtime::Handle::try_current().map_err(|e| {
            NapiError::from(ScpNapiError::Identity {
                message: format!("tokio runtime not available: {e}"),
                code: codes::IDENT_1027.to_owned(),
            })
        })?;

        let result = handle
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

        let _ = &self.inner;

        validate_did(&did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
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

        let handle = tokio::runtime::Handle::try_current().map_err(|e| {
            NapiError::from(ScpNapiError::Identity {
                message: format!("tokio runtime not available: {e}"),
                code: codes::IDENT_1028.to_owned(),
            })
        })?;

        let result = handle
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
}
