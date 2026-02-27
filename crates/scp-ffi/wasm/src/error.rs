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

use wasm_bindgen::JsError;

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
/// The error code prefix is embedded in the `Display` output so that the JS
/// caller can extract it via string matching or via a TypeScript wrapper that
/// parses the prefix into a typed `ScpError` subclass.
#[derive(Debug, thiserror::Error)]
pub enum ScpWasmError {
    /// An identity operation failed (DID creation, resolution, key rotation).
    ///
    /// Error code prefix: `SCP-IDENT-1000`.
    #[error("[SCP-IDENT-1000] identity error: {0}")]
    Identity(String),

    /// A context lifecycle operation failed.
    ///
    /// Error code prefix: `SCP-CTX-2000`.
    #[error("[SCP-CTX-2000] context error: {0}")]
    Context(String),

    /// A UCAN / permission operation failed.
    ///
    /// Error code prefix: `SCP-PERM-3000`.
    #[error("[SCP-PERM-3000] permission error: {0}")]
    Permission(String),

    /// A cryptographic operation failed (MLS, sender keys, encryption).
    ///
    /// Note: messages never include key material or internal crypto state.
    ///
    /// Error code prefix: `SCP-CRYPTO-4000`.
    #[error("[SCP-CRYPTO-4000] crypto error: {0}")]
    Crypto(String),

    /// A transport operation failed (connection, send, subscription).
    ///
    /// Error code prefix: `SCP-TRANS-5000`.
    #[error("[SCP-TRANS-5000] transport error: {0}")]
    Transport(String),

    /// A tool operation failed (registration, invocation, verification).
    ///
    /// Error code prefix: `SCP-TOOL-6000`.
    #[error("[SCP-TOOL-6000] tool error: {0}")]
    Tool(String),

    /// Input validation failed (schema, format, constraint violation).
    ///
    /// Error code prefix: `SCP-VALID-7000`.
    #[error("[SCP-VALID-7000] validation error: {0}")]
    Validation(String),
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
}

// ---------------------------------------------------------------------------
// From implementations for ergonomic conversion
// ---------------------------------------------------------------------------

impl From<serde_json::Error> for ScpWasmError {
    fn from(e: serde_json::Error) -> Self {
        Self::Validation(format!(
            "JSON serialization/deserialization failed: {e} — check input format"
        ))
    }
}
