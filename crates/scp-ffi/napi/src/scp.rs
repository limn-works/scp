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

use std::sync::Arc;
use std::time::Duration;

use napi_derive::napi;
use scp_ffi_common::bridge_instance::BridgeInstanceCore as _;
use scp_ffi_common::error_codes as codes;

use crate::error::ScpNapiError;
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
}
