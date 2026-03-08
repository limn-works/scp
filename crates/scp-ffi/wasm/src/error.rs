//! Error hierarchy and mapping for the WASM bridge.
//!
//! Rust `Result<T, E>` maps to JS `Promise` rejection via [`wasm_bindgen::JsError`].
//! Each error variant carries a stable error code prefix that matches the
//! cross-SDK error code format defined in `.docs/standards/sdk-common.md`.
//!
//! # Error codes
//!
//! | Prefix | Range | Category |
//! |--------|-------|----------|
//! | `SCP-IDENT-` | 1000–1999 | Identity errors |
//! | `SCP-CTX-` | 2000–2999 | Context errors |
//! | `SCP-PERM-` | 3000–3999 | UCAN / permission errors |
//! | `SCP-CRYPTO-` | 4000–4999 | Cryptographic errors |
//! | `SCP-TRANS-` | 5000–5999 | Transport errors |
//! | `SCP-TOOL-` | 6000–6999 | Tool errors |
//! | `SCP-VALID-` | 7000–7999 | Validation errors |
//! | `SCP-TRUST-` | 8000–8999 | Trust engine errors |
//!
//! # Error message format
//!
//! Every error carries:
//! - A human-readable message (what failed, why, what to do).
//! - A machine-readable code prefix (stable across SDK versions).
//!
//! Crypto errors never leak key material or internal crypto state.
//!
//! # WASM constraints
//!
//! This module does NOT import from `scp-core` to avoid pulling in tokio's
//! multi-thread runtime, which does not compile to `wasm32-unknown-unknown`.
//! The error variants mirror the scp-core error categories (Identity, Context,
//! etc.) so the TypeScript wrapper can map to the same `ScpError` hierarchy
//! documented in `.docs/standards/sdk-common.md`.
//!
//! See ADR-022 and `.docs/standards/sdk-common.md` for the full spec.

use wasm_bindgen::{JsError, JsValue};

// ---------------------------------------------------------------------------
// ScpWasmError — unified error type for the WASM bridge layer
// ---------------------------------------------------------------------------

/// Unified error type for the WASM bridge layer.
///
/// Each variant maps to one category in the cross-SDK error hierarchy defined
/// in `.docs/standards/sdk-common.md`. Bridge functions return
/// `Result<T, ScpWasmError>` and convert to [`JsError`] via
/// [`ScpWasmError::into_js`] for Promise rejection.
///
/// Every variant carries a stable error code (`SCP-{CATEGORY}-{NUMBER}`)
/// and a human-readable message. The TypeScript SDK parses the bracketed
/// code prefix to select the appropriate `ScpError` subclass.
#[derive(Debug, thiserror::Error)]
pub enum ScpWasmError {
    /// An identity operation failed (DID creation, resolution, key rotation).
    #[error("[{code}] identity error: {message}")]
    Identity {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-IDENT-1000`).
        code: String,
    },

    /// A context lifecycle operation failed.
    #[error("[{code}] context error: {message}")]
    Context {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-CTX-2001`).
        code: String,
    },

    /// A UCAN / permission operation failed.
    #[error("[{code}] permission error: {message}")]
    Permission {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-PERM-3000`).
        code: String,
    },

    /// A cryptographic operation failed (MLS, sender keys, encryption).
    ///
    /// Note: messages never include key material or internal crypto state.
    #[error("[{code}] crypto error: {message}")]
    Crypto {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-CRYPTO-4000`).
        code: String,
    },

    /// A transport operation failed (connection, send, subscription).
    #[error("[{code}] transport error: {message}")]
    Transport {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-TRANS-5000`).
        code: String,
    },

    /// A tool operation failed (registration, invocation, verification).
    #[error("[{code}] tool error: {message}")]
    Tool {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-TOOL-6000`).
        code: String,
    },

    /// Input validation failed (schema, format, constraint violation).
    #[error("[{code}] validation error: {message}")]
    Validation {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-VALID-7000`).
        code: String,
    },

    /// A trust engine operation failed (attestation, challenge, verification).
    #[error("[{code}] trust error: {message}")]
    Trust {
        /// Human-readable error message.
        message: String,
        /// Stable error code (e.g. `SCP-TRUST-8001`).
        code: String,
    },
}

impl ScpWasmError {
    /// Converts this error into a [`JsError`] suitable for Promise rejection.
    ///
    /// The resulting JS exception carries the formatted message (which includes
    /// the stable error code prefix) as its `.message` property. TypeScript
    /// SDK wrappers parse the prefix to create typed `ScpError` subclasses.
    #[must_use]
    pub fn into_js(self) -> JsError {
        JsError::new(&self.to_string())
    }

    /// Creates a `Validation` error with the standard error code.
    #[must_use]
    pub fn validation(message: &str) -> JsValue {
        let err = Self::Validation {
            message: message.to_owned(),
            code: "SCP-VALID-7000".to_owned(),
        };
        JsValue::from_str(&err.to_string())
    }
}

// ---------------------------------------------------------------------------
// From implementations for ergonomic conversion
// ---------------------------------------------------------------------------

impl From<serde_json::Error> for ScpWasmError {
    fn from(e: serde_json::Error) -> Self {
        Self::Validation {
            message: format!("JSON serialization/deserialization failed: {e} — check input format"),
            code: "SCP-VALID-7006".to_owned(),
        }
    }
}
