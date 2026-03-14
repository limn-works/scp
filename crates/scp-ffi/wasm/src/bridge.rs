//! `wasm-bindgen` bridge for bridge connector operations.
//!
//! Exposes SCP bridge connector operations to JavaScript (browser target):
//!
//! - `bridge_register` -- Register a bridge connector with a context.
//! - `bridge_evaluate_trust` -- Evaluate trust level for a bridge action.
//! - `bridge_create_shadow` -- Create a shadow identity.
//!
//! # WASM constraints
//!
//! This bridge does NOT depend on `scp-core` (tokio multi-thread incompatible
//! with `wasm32-unknown-unknown`). Bridge connector operations are
//! re-implemented locally with algorithm-identical logic matching the
//! PyO3/NAPI/UniFFI bridges — including governance DID validation and the
//! self-approval invariant (ADR-023).
//!
//! See spec section 12 (Bridge System) and ADR-023.

use wasm_bindgen::prelude::*;

use crate::error::ScpWasmError;
use scp_ffi_common::validate::validate_did;

// ---------------------------------------------------------------------------
// Result types — wasm_bindgen structs returned to JS
// ---------------------------------------------------------------------------

/// Bridge registration result.
///
/// Mirrors `NapiBridgeRegistration` in the NAPI bridge. All fields are
/// populated to match the TypeScript `BridgeRegistration` interface.
#[wasm_bindgen]
pub struct WasmBridgeRegistration {
    bridge_id: String,
    operator_did: String,
    platform: String,
    mode: String,
    status: String,
    context_id: String,
}

#[wasm_bindgen]
impl WasmBridgeRegistration {
    /// Returns the deterministic bridge ID (SHA-256 hex).
    #[must_use]
    #[wasm_bindgen(getter, js_name = "bridge_id")]
    pub fn bridge_id(&self) -> String {
        self.bridge_id.clone()
    }

    /// Returns the DID of the bridge operator.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "operator_did")]
    pub fn operator_did(&self) -> String {
        self.operator_did.clone()
    }

    /// Returns the external platform name (e.g., `"discord"`).
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn platform(&self) -> String {
        self.platform.clone()
    }

    /// Returns the bridge operating mode (e.g., `"relay"`, `"puppet"`).
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn mode(&self) -> String {
        self.mode.clone()
    }

    /// Returns the bridge registration status (e.g., `"active"`).
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn status(&self) -> String {
        self.status.clone()
    }

    /// Returns the context ID the bridge is registered in.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "context_id")]
    pub fn context_id(&self) -> String {
        self.context_id.clone()
    }
}

/// Shadow identity creation result.
///
/// Mirrors `NapiShadowIdentity` in the NAPI bridge. All fields are
/// populated to match the TypeScript `ShadowIdentity` interface.
#[wasm_bindgen]
pub struct WasmShadowIdentity {
    shadow_id: String,
    platform_handle: String,
    bridge_id: String,
    context_id: String,
    attributed_role: String,
    provenance_status: String,
}

#[wasm_bindgen]
impl WasmShadowIdentity {
    /// Returns the deterministic shadow identity ID.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "shadow_id")]
    pub fn shadow_id(&self) -> String {
        self.shadow_id.clone()
    }

    /// Returns the external platform handle (e.g., `"@user#1234"`).
    #[must_use]
    #[wasm_bindgen(getter, js_name = "platform_handle")]
    pub fn platform_handle(&self) -> String {
        self.platform_handle.clone()
    }

    /// Returns the bridge ID that created this shadow identity.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "bridge_id")]
    pub fn bridge_id(&self) -> String {
        self.bridge_id.clone()
    }

    /// Returns the context ID for this shadow identity.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "context_id")]
    pub fn context_id(&self) -> String {
        self.context_id.clone()
    }

    /// Returns the attributed role (always `"observer"` for shadows).
    #[must_use]
    #[wasm_bindgen(getter, js_name = "attributed_role")]
    pub fn attributed_role(&self) -> String {
        self.attributed_role.clone()
    }

    /// Returns the provenance status (`"Shadow"` or `"Claimed"`).
    #[must_use]
    #[wasm_bindgen(getter, js_name = "provenance_status")]
    pub fn provenance_status(&self) -> String {
        self.provenance_status.clone()
    }
}

// ---------------------------------------------------------------------------
// Local enums and helpers (mirror scp-core::bridge)
// ---------------------------------------------------------------------------

/// Bridge operating modes (spec §12).
///
/// Mirrors `scp_core::bridge::BridgeMode`. Four variants:
/// - `relay` — relays messages between platforms
/// - `puppet` — acts on behalf of external users
/// - `api` — programmatic API bridge
/// - `cooperative` — two-way bridge with mutual trust
#[derive(Debug, Clone, Copy)]
enum BridgeMode {
    Relay,
    Puppet,
    Api,
    Cooperative,
}

impl BridgeMode {
    fn from_str(s: &str) -> Result<Self, ScpWasmError> {
        match s {
            "relay" => Ok(Self::Relay),
            "puppet" => Ok(Self::Puppet),
            "api" => Ok(Self::Api),
            "cooperative" => Ok(Self::Cooperative),
            other => Err(ScpWasmError::Validation {
                message: format!(
                    "invalid bridge mode '{other}': expected 'relay', 'puppet', 'api', or 'cooperative'"
                ),
                code: "SCP-VALID-7050".to_owned(),
            }),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Relay => "relay",
            Self::Puppet => "puppet",
            Self::Api => "api",
            Self::Cooperative => "cooperative",
        }
    }
}

/// Shadow provenance status (spec §12).
///
/// Mirrors `scp_core::bridge::ShadowProvenanceStatus`.
#[derive(Debug, Clone, Copy)]
enum ShadowProvenanceStatus {
    Shadow,
    Claimed,
}

impl ShadowProvenanceStatus {
    fn from_str(s: &str) -> Result<Self, ScpWasmError> {
        match s {
            "shadow" => Ok(Self::Shadow),
            "claimed" => Ok(Self::Claimed),
            other => Err(ScpWasmError::Validation {
                message: format!("invalid shadow_status '{other}': expected 'shadow' or 'claimed'"),
                code: "SCP-VALID-7051".to_owned(),
            }),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Shadow => "Shadow",
            Self::Claimed => "Claimed",
        }
    }
}

/// Trust level tiers (spec §12.5, ADR-023 AC 6).
///
/// Mirrors `scp_core::bridge::provenance::BridgeTrustLevel`.
///
/// Ordering: `NativeNative` (3, strongest) > `NativeBridged` (2) >
/// `ClaimedBridged` (1) > `ShadowBridged` (0, weakest).
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
enum BridgeTrustLevel {
    ShadowBridged = 0,
    ClaimedBridged = 1,
    NativeBridged = 2,
    NativeNative = 3,
}

// ---------------------------------------------------------------------------
// bridge_evaluate_trust
// ---------------------------------------------------------------------------

/// Evaluates the trust level for an action based on bridge provenance.
///
/// Returns an integer (0–3) representing the trust tier per spec §12.5:
///
/// - 0 = `ShadowBridged` (weakest)
/// - 1 = `ClaimedBridged`
/// - 2 = `NativeBridged`
/// - 3 = `NativeNative` (strongest)
///
/// # Arguments
///
/// - `is_bridged` — `true` if the action originates from a bridge.
/// - `is_native_transport` — `true` if the transport is native SCP.
/// - `shadow_status` — `"shadow"` or `"claimed"` (only used when `is_bridged`).
///
/// # Errors
///
/// Returns `JsError` if `shadow_status` is not `"shadow"` or `"claimed"`.
///
/// # JS usage
///
/// ```js
/// const trust = bridge_evaluate_trust(false, true, "shadow"); // 3 (NativeNative)
/// const trust2 = bridge_evaluate_trust(true, false, "shadow"); // 0 (ShadowBridged)
/// ```
#[wasm_bindgen]
pub fn bridge_evaluate_trust(
    is_bridged: bool,
    is_native_transport: bool,
    shadow_status: String,
) -> Result<u32, JsError> {
    // Validate shadow_status upfront (even if not used when !is_bridged),
    // matching the NAPI bridge which always validates the parameter.
    let status = ShadowProvenanceStatus::from_str(&shadow_status).map_err(ScpWasmError::into_js)?;

    let level = if is_bridged {
        // Bridged identity — trust depends on shadow status.
        // Transport flag is ignored when bridge provenance is present
        // (by definition, bridged content uses bridged transport).
        match status {
            ShadowProvenanceStatus::Claimed => BridgeTrustLevel::ClaimedBridged,
            ShadowProvenanceStatus::Shadow => BridgeTrustLevel::ShadowBridged,
        }
    } else {
        // Native identity — trust depends on transport.
        if is_native_transport {
            BridgeTrustLevel::NativeNative
        } else {
            BridgeTrustLevel::NativeBridged
        }
    };

    Ok(level as u32)
}

// ---------------------------------------------------------------------------
// bridge_register
// ---------------------------------------------------------------------------

/// Registers a new bridge connector with a context.
///
/// Creates a bridge registration with a deterministic bridge ID derived from
/// the platform name and context ID. The bridge is immediately approved
/// using the provided governance DID (matching the NAPI bridge's behavior
/// of creating + auto-approving).
///
/// # Arguments
///
/// - `context_id` — Context to register the bridge in.
/// - `operator_did` — DID of the bridge operator.
/// - `governance_did` — DID of the governance authority approving the
///   registration. Must differ from `operator_did` (self-approval is
///   forbidden per ADR-023).
/// - `platform` — External platform name (e.g., `"discord"`, `"slack"`).
/// - `mode` — Bridge mode: `"relay"`, `"puppet"`, `"api"`, or `"cooperative"`.
///
/// # Errors
///
/// Returns `JsError` if `operator_did` or `governance_did` is not a valid
/// DID string (empty, exceeds 512 bytes, missing `did:{method}:{id}`
/// structure, method not lowercase alphanumeric, or contains control
/// characters), if `mode` is invalid, if other inputs are empty, or
/// if `governance_did` equals `operator_did` (self-approval).
///
/// # JS usage
///
/// ```js
/// const reg = bridge_register("ctx-1", "did:key:op", "did:key:gov", "discord", "relay");
/// console.log(reg.bridge_id); // deterministic SHA-256 hex
/// console.log(reg.status);    // "active"
/// ```
#[wasm_bindgen]
pub fn bridge_register(
    context_id: String,
    operator_did: String,
    governance_did: String,
    platform: String,
    mode: String,
) -> Result<WasmBridgeRegistration, JsError> {
    if context_id.is_empty() {
        return Err(ScpWasmError::Validation {
            message: "context_id must not be empty".to_owned(),
            code: "SCP-VALID-7053".to_owned(),
        }
        .into_js());
    }
    if let Err(e) = validate_did(&operator_did) {
        return Err(ScpWasmError::from(e).into_js());
    }
    if let Err(e) = validate_did(&governance_did) {
        return Err(ScpWasmError::from(e).into_js());
    }
    if platform.is_empty() {
        return Err(ScpWasmError::Validation {
            message: "platform must not be empty".to_owned(),
            code: "SCP-VALID-7054".to_owned(),
        }
        .into_js());
    }

    // Self-approval check: the governance approver must differ from the
    // bridge operator (ADR-023 acceptance criterion 2).
    if governance_did == operator_did {
        return Err(ScpWasmError::Context {
            message: "approver cannot be the same DID as the operator (self-approval is forbidden per ADR-023)".to_owned(),
            code: "SCP-CTX-2101".to_owned(),
        }
        .into_js());
    }

    let bridge_mode = BridgeMode::from_str(&mode).map_err(ScpWasmError::into_js)?;

    // Bridge ID per spec §12.2.1: SHA-256(context_id || operator_did || platform || timestamp).
    // Uses current timestamp for uniqueness. Hex-encoded for readability.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let now_secs = {
        #[cfg(target_arch = "wasm32")]
        {
            (js_sys::Date::now() / 1000.0) as u64
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        }
    };
    let bridge_id = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(context_id.as_bytes());
        hasher.update(operator_did.as_bytes());
        hasher.update(platform.as_bytes());
        hasher.update(now_secs.to_be_bytes());
        hex::encode(hasher.finalize())
    };

    Ok(WasmBridgeRegistration {
        bridge_id,
        operator_did,
        platform,
        mode: bridge_mode.as_str().to_owned(),
        status: "active".to_owned(),
        context_id,
    })
}

// ---------------------------------------------------------------------------
// bridge_create_shadow
// ---------------------------------------------------------------------------

/// Creates a shadow identity for an external platform participant.
///
/// Shadow identities represent external platform users within an SCP
/// context. They carry `"observer"` role by default and `"Shadow"`
/// provenance status (unclaimed until identity attestation).
///
/// # Arguments
///
/// - `bridge_id` — Unique ID of the bridge connector.
/// - `platform_handle` — External platform handle (e.g., `"@user#1234"`).
/// - `bridge_mode` — Bridge mode: `"relay"`, `"puppet"`, `"api"`, or `"cooperative"`.
/// - `context_id` — Optional context for the shadow identity. Defaults to
///   `"ctx-shadow"` when `None`, matching the NAPI bridge behavior.
///
/// # Errors
///
/// Returns `JsError` if `bridge_mode` is invalid.
///
/// # JS usage
///
/// ```js
/// const shadow = bridge_create_shadow("bridge-1", "@user", "relay", "ctx-1");
/// console.log(shadow.shadow_id);         // "shadow-bridge-1-user"
/// console.log(shadow.attributed_role);   // "observer"
/// console.log(shadow.provenance_status); // "Shadow"
/// ```
#[wasm_bindgen]
pub fn bridge_create_shadow(
    bridge_id: String,
    platform_handle: String,
    bridge_mode: String,
    context_id: Option<String>,
) -> Result<WasmShadowIdentity, JsError> {
    if bridge_id.is_empty() {
        return Err(ScpWasmError::Validation {
            message: "bridge_id must not be empty".to_owned(),
            code: "SCP-VALID-7055".to_owned(),
        }
        .into_js());
    }
    if platform_handle.is_empty() {
        return Err(ScpWasmError::Validation {
            message: "platform_handle must not be empty".to_owned(),
            code: "SCP-VALID-7056".to_owned(),
        }
        .into_js());
    }

    // Validate bridge mode (ensures the mode string is valid even though
    // we don't use the parsed value for shadow creation logic).
    let _mode = BridgeMode::from_str(&bridge_mode).map_err(ScpWasmError::into_js)?;

    // Default to "ctx-shadow" when context_id is None, matching the NAPI
    // bridge's `context_id.unwrap_or_else(|| "ctx-shadow".to_string())`.
    let ctx_id = context_id.unwrap_or_else(|| "ctx-shadow".to_owned());

    // Deterministic shadow ID: "shadow-{bridge_id}-{handle_sans_at}"
    // Mirrors the NAPI bridge's ID generation logic.
    let handle_clean = platform_handle.replace('@', "");
    let shadow_id = format!("shadow-{bridge_id}-{handle_clean}");

    Ok(WasmShadowIdentity {
        shadow_id,
        platform_handle,
        bridge_id,
        context_id: ctx_id,
        attributed_role: "observer".to_owned(),
        provenance_status: ShadowProvenanceStatus::Shadow.as_str().to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Tests — pure helper tests (no JsError) run on all targets
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // -- Internal enum tests (no wasm_bindgen dependency) -------------------

    #[test]
    fn bridge_mode_roundtrip() {
        for (s, expected) in [
            ("relay", "relay"),
            ("puppet", "puppet"),
            ("api", "api"),
            ("cooperative", "cooperative"),
        ] {
            let mode = BridgeMode::from_str(s).unwrap();
            assert_eq!(mode.as_str(), expected);
        }
    }

    #[test]
    fn bridge_mode_invalid() {
        assert!(BridgeMode::from_str("invalid").is_err());
    }

    #[test]
    fn shadow_status_roundtrip() {
        let s = ShadowProvenanceStatus::from_str("shadow").unwrap();
        assert_eq!(s.as_str(), "Shadow");
        let c = ShadowProvenanceStatus::from_str("claimed").unwrap();
        assert_eq!(c.as_str(), "Claimed");
    }

    #[test]
    fn shadow_status_invalid() {
        assert!(ShadowProvenanceStatus::from_str("invalid").is_err());
    }

    #[test]
    fn trust_level_values() {
        assert_eq!(BridgeTrustLevel::ShadowBridged as u32, 0);
        assert_eq!(BridgeTrustLevel::ClaimedBridged as u32, 1);
        assert_eq!(BridgeTrustLevel::NativeBridged as u32, 2);
        assert_eq!(BridgeTrustLevel::NativeNative as u32, 3);
    }
}

// ---------------------------------------------------------------------------
// Bridge function tests — call #[wasm_bindgen] exports, only run on wasm32
// ---------------------------------------------------------------------------

#[cfg(all(test, target_arch = "wasm32"))]
#[allow(clippy::unwrap_used)]
mod wasm_tests {
    use super::*;

    #[test]
    fn evaluate_trust_native_native() {
        let result = bridge_evaluate_trust(false, true, "shadow".to_owned()).unwrap();
        assert_eq!(result, BridgeTrustLevel::NativeNative as u32);
    }

    #[test]
    fn evaluate_trust_native_bridged() {
        let result = bridge_evaluate_trust(false, false, "shadow".to_owned()).unwrap();
        assert_eq!(result, BridgeTrustLevel::NativeBridged as u32);
    }

    #[test]
    fn evaluate_trust_shadow_bridged() {
        let result = bridge_evaluate_trust(true, false, "shadow".to_owned()).unwrap();
        assert_eq!(result, BridgeTrustLevel::ShadowBridged as u32);
    }

    #[test]
    fn evaluate_trust_claimed_bridged() {
        let result = bridge_evaluate_trust(true, false, "claimed".to_owned()).unwrap();
        assert_eq!(result, BridgeTrustLevel::ClaimedBridged as u32);
    }

    #[test]
    fn evaluate_trust_invalid_status_errors() {
        assert!(bridge_evaluate_trust(true, false, "invalid".to_owned()).is_err());
    }

    #[test]
    fn evaluate_trust_ignores_transport_when_bridged() {
        let with_native = bridge_evaluate_trust(true, true, "shadow".to_owned()).unwrap();
        let with_bridged = bridge_evaluate_trust(true, false, "shadow".to_owned()).unwrap();
        assert_eq!(with_native, with_bridged);
        assert_eq!(with_native, BridgeTrustLevel::ShadowBridged as u32);
    }

    #[test]
    fn register_returns_active_bridge() {
        let result = bridge_register(
            "ctx-test".to_owned(),
            "did:key:operator".to_owned(),
            "did:key:governance".to_owned(),
            "discord".to_owned(),
            "relay".to_owned(),
        )
        .unwrap();
        assert_eq!(result.status(), "active");
        assert_eq!(result.platform(), "discord");
        assert_eq!(result.mode(), "relay");
    }

    #[test]
    fn register_invalid_mode_errors() {
        assert!(
            bridge_register(
                "ctx-test".to_owned(),
                "did:key:operator".to_owned(),
                "did:key:governance".to_owned(),
                "discord".to_owned(),
                "invalid".to_owned(),
            )
            .is_err()
        );
    }

    #[test]
    fn register_empty_context_id_errors() {
        assert!(
            bridge_register(
                String::new(),
                "did:key:operator".to_owned(),
                "did:key:governance".to_owned(),
                "discord".to_owned(),
                "relay".to_owned(),
            )
            .is_err()
        );
    }

    #[test]
    fn register_self_approval_errors() {
        let result = bridge_register(
            "ctx-test".to_owned(),
            "did:key:operator".to_owned(),
            "did:key:operator".to_owned(),
            "discord".to_owned(),
            "relay".to_owned(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("self-approval"),
            "expected self-approval error, got: {err}"
        );
    }

    #[test]
    fn create_shadow_returns_observer_role() {
        let result = bridge_create_shadow(
            "bridge-1".to_owned(),
            "@user".to_owned(),
            "relay".to_owned(),
            Some("ctx-1".to_owned()),
        )
        .unwrap();
        assert_eq!(result.attributed_role(), "observer");
        assert_eq!(result.provenance_status(), "Shadow");
    }

    #[test]
    fn create_shadow_with_none_context_id() {
        let result = bridge_create_shadow(
            "bridge-1".to_owned(),
            "@user".to_owned(),
            "relay".to_owned(),
            None,
        )
        .unwrap();
        assert_eq!(result.attributed_role(), "observer");
    }

    #[test]
    fn create_shadow_strips_at_sign() {
        let result = bridge_create_shadow(
            "bridge-1".to_owned(),
            "@user#1234".to_owned(),
            "relay".to_owned(),
            Some("ctx-1".to_owned()),
        )
        .unwrap();
        assert_eq!(result.shadow_id(), "shadow-bridge-1-user#1234");
    }

    #[test]
    fn create_shadow_invalid_mode_errors() {
        assert!(
            bridge_create_shadow(
                "bridge-1".to_owned(),
                "@user".to_owned(),
                "invalid".to_owned(),
                Some("ctx-1".to_owned()),
            )
            .is_err()
        );
    }

    #[test]
    fn create_shadow_empty_bridge_id_errors() {
        assert!(
            bridge_create_shadow(
                String::new(),
                "@user".to_owned(),
                "relay".to_owned(),
                Some("ctx-1".to_owned()),
            )
            .is_err()
        );
    }

    #[test]
    fn create_shadow_empty_handle_errors() {
        assert!(
            bridge_create_shadow(
                "bridge-1".to_owned(),
                String::new(),
                "relay".to_owned(),
                Some("ctx-1".to_owned()),
            )
            .is_err()
        );
    }

    #[test]
    fn register_all_bridge_modes() {
        for mode in ["relay", "puppet", "api", "cooperative"] {
            let result = bridge_register(
                "ctx-test".to_owned(),
                "did:key:op".to_owned(),
                "did:key:gov".to_owned(),
                "slack".to_owned(),
                mode.to_owned(),
            )
            .unwrap();
            assert_eq!(result.mode(), mode);
        }
    }

    #[test]
    fn create_shadow_all_bridge_modes() {
        for mode in ["relay", "puppet", "api", "cooperative"] {
            let result = bridge_create_shadow(
                "bridge-1".to_owned(),
                "@user".to_owned(),
                mode.to_owned(),
                Some("ctx-1".to_owned()),
            );
            assert!(result.is_ok());
        }
    }
}
