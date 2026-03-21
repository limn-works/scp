//! `wasm-bindgen` bridge for discovery address operations.
//!
//! Exposes address parsing, normalization, and context discovery to JavaScript
//! (browser target):
//!
//! - `discovery_parse_address` — Parse an SCP address string into components.
//!   Supports all 4 variants: `DiscoveryHandle`, `DomainHandle`,
//!   `AttestationHandle`, `Unscoped` per §22.11.3.
//! - `discovery_normalize_address` — Normalize an address to canonical form.
//! - `discovery_create_query` — Create a discovery query descriptor.
//! - `context_discover` — Discover contexts from a DID or `scp://` URI.
//! - `petname_set` / `petname_remove` — Set/remove DID petnames (§22.4).
//! - `petname_set_context` / `petname_remove_context` — Context petnames.
//! - `petname_resolve_did` / `petname_resolve_context` — Resolve petnames.
//! - `petname_get_for_did` / `petname_get_for_context` — Reverse lookup.
//! - `petname_apply_event` — Apply a `WasmPetnameEvent` matching scp-core's
//!   event-driven mutation model (§22.9.2).
//! - `petname_list_events` — List emitted events for an owner DID.
//! - `petname_did_count` / `petname_context_count` — Count stored petnames.
//!
//! CI trigger: Re-run after transient GitHub API failure.
//!
//! # WASM constraints
//!
//! This bridge does NOT depend on `scp-core` (tokio multi-thread incompatible
//! with `wasm32-unknown-unknown`). Address parsing and normalization are pure
//! string operations re-implemented locally with algorithm-identical validation.
//!
//! `context_discover` handles `scp://` URIs locally (pure parsing, no network
//! I/O). For `did:` queries, DHT resolution requires network I/O that cannot
//! be performed from Rust in WASM — the function returns an error
//! (`SCP-CTX-2022`). The TypeScript wrapper layer should implement DID-based
//! discovery via the Fetch API if needed.
//!
//! See spec section 22 and ADR-022.

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

// ---------------------------------------------------------------------------
// Constants (mirror scp-core::discovery::addressing)
// ---------------------------------------------------------------------------

/// Maximum length of the local-part of an address.
const MAX_LOCAL_PART_LENGTH: usize = 64;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Validates the local-part of an address.
///
/// Rules (mirror scp-core):
/// - Max 64 characters.
/// - ASCII lowercase, digits, `.`, `-`, `_` only.
/// - No leading/trailing `-` or `.`.
/// - No consecutive dots.
fn validate_local_part(local: &str) -> Result<(), String> {
    if local.is_empty() {
        return Err("local-part must not be empty".to_owned());
    }
    if local.len() > MAX_LOCAL_PART_LENGTH {
        return Err(format!(
            "local-part exceeds maximum length of {MAX_LOCAL_PART_LENGTH} characters"
        ));
    }
    for (i, ch) in local.chars().enumerate() {
        if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() && ch != '.' && ch != '-' && ch != '_' {
            return Err(format!(
                "invalid character '{ch}' at position {i} in local-part"
            ));
        }
    }
    if local.starts_with('-')
        || local.ends_with('-')
        || local.starts_with('.')
        || local.ends_with('.')
    {
        return Err("local-part must not start or end with '-' or '.'".to_owned());
    }
    if local.contains("..") {
        return Err("local-part must not contain consecutive dots".to_owned());
    }
    Ok(())
}

/// Validates the scope part of an address.
///
/// Rules (mirror local-part validation pattern):
/// - No control characters (< 0x20 or 0x7F).
/// - No zero-width spaces (U+200B), zero-width joiners (U+200C/U+200D),
///   or other invisible formatting characters (U+FEFF BOM, U+2060 word joiner).
fn validate_scope(scope: &str) -> Result<(), String> {
    for (i, ch) in scope.chars().enumerate() {
        if ch < '\u{0020}' || ch == '\u{007F}' {
            return Err(format!(
                "invalid control character at position {i} in scope"
            ));
        }
        if matches!(
            ch,
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{2060}'
        ) {
            return Err(format!(
                "invalid zero-width/invisible character U+{:04X} at position {i} in scope",
                ch as u32
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// discovery_parse_address
// ---------------------------------------------------------------------------

/// Parses an SCP address string into its components.
///
/// Returns a JSON string with variant-specific fields matching the NAPI
/// bridge's `discovery_parse_address` output format and `PascalCase` type
/// tags per §22.11.3.
///
/// Four address forms are supported (algorithm-identical to scp-core's
/// `parse_address`):
///
/// - **Attestation handle**: leading `@`, e.g. `@alice_cooks` or `@alice_cooks:x`
///   → `{ type: "AttestationHandle", handle, platform }`
/// - **Discovery handle**: `local@scope` where scope has no `.`,
///   e.g. `alice@photography`
///   → `{ type: "DiscoveryHandle", local_part, scope }`
/// - **Domain handle**: `local@scope` where scope contains `.`,
///   e.g. `alice@example.com`
///   → `{ type: "DomainHandle", local_part, domain }`
/// - **Unscoped**: bare name with no `@`, e.g. `alice`
///   → `{ type: "Unscoped", name }`
///
/// # Errors
///
/// Returns `JsError` if the address is empty, or the local-part is invalid.
///
/// # JS usage
///
/// ```js
/// const parsed = discovery_parse_address("alice@photography");
/// const obj = JSON.parse(parsed);
/// console.log(obj.type);       // "DiscoveryHandle"
/// console.log(obj.local_part); // "alice"
/// console.log(obj.scope);      // "photography"
/// ```
#[wasm_bindgen]
pub fn discovery_parse_address(address: String) -> Result<String, JsError> {
    // Normalize: lowercase + trim (mirrors scp-core::discovery::normalize_address).
    let normalized = address.trim().to_lowercase();

    if normalized.is_empty() {
        return Err(JsError::new("[SCP-VALID-7100] address must not be empty"));
    }

    // Attestation handle: leading `@` (e.g. `@alice_cooks` or `@alice_cooks:x`).
    if let Some(rest) = normalized.strip_prefix('@') {
        if rest.is_empty() {
            return Err(JsError::new(
                "[SCP-VALID-7100] attestation handle must not be empty after '@'",
            ));
        }
        // Check for platform qualifier: `@handle:platform`
        if let Some(colon_pos) = rest.find(':') {
            let handle = &rest[..colon_pos];
            let platform = &rest[colon_pos + 1..];
            if handle.is_empty() || platform.is_empty() {
                return Err(JsError::new(
                    "[SCP-VALID-7100] attestation handle and platform must not be empty",
                ));
            }
            let result = serde_json::json!({
                "type": "AttestationHandle",
                "handle": handle,
                "platform": platform,
            });
            return Ok(result.to_string());
        }
        let result = serde_json::json!({
            "type": "AttestationHandle",
            "handle": rest,
            "platform": null,
        });
        return Ok(result.to_string());
    }

    // Scoped address: contains `@`.
    if let Some(at_pos) = normalized.find('@') {
        let local = &normalized[..at_pos];
        let scope = &normalized[at_pos + 1..];

        if scope.is_empty() {
            return Err(JsError::new(
                "[SCP-VALID-7102] scope part must not be empty",
            ));
        }

        validate_local_part(local).map_err(|e| JsError::new(&format!("[SCP-VALID-7103] {e}")))?;
        validate_scope(scope).map_err(|e| JsError::new(&format!("[SCP-VALID-7104] {e}")))?;

        // Scope with `.` => DomainHandle; without => DiscoveryHandle.
        let result = if scope.contains('.') {
            serde_json::json!({
                "type": "DomainHandle",
                "local_part": local,
                "domain": scope,
            })
        } else {
            serde_json::json!({
                "type": "DiscoveryHandle",
                "local_part": local,
                "scope": scope,
            })
        };

        return Ok(result.to_string());
    }

    // Bare name: unscoped.
    let result = serde_json::json!({
        "type": "Unscoped",
        "name": normalized,
    });

    Ok(result.to_string())
}

// ---------------------------------------------------------------------------
// discovery_normalize_address
// ---------------------------------------------------------------------------

/// Normalizes an address to canonical form.
///
/// Canonical form: lowercase local-part, lowercase scope, trimmed whitespace.
/// If the address does not contain `@`, it is returned as-is (lowercased).
///
/// # JS usage
///
/// ```js
/// const normalized = discovery_normalize_address("Alice@Photography");
/// console.log(normalized); // "alice@photography"
/// ```
#[must_use]
#[wasm_bindgen]
pub fn discovery_normalize_address(address: String) -> String {
    address.trim().to_lowercase()
}

// ---------------------------------------------------------------------------
// discovery_create_query
// ---------------------------------------------------------------------------

/// Creates a discovery query descriptor as JSON.
///
/// Used to build structured discovery queries for the TypeScript wrapper to
/// execute against the DHT or other discovery backends.
///
/// # Arguments
///
/// - `capabilities_json` — Optional JSON array of capability filter strings.
/// - `keywords_json` — Optional JSON array of keyword strings.
/// - `min_history_secs` — Optional minimum history duration in seconds (f64
///   for JS compatibility).
///
/// Matches the NAPI bridge's `discovery_create_query(capabilities, keywords,
/// min_history_secs)` signature and the TypeScript adapter's calling
/// convention.
///
/// # Errors
///
/// Returns `JsError` if `min_history_secs` is negative, or if JSON parsing
/// fails for the provided arrays.
///
/// # JS usage
///
/// ```js
/// const query = discovery_create_query('["code_review"]', '["rust"]', 3600);
/// const obj = JSON.parse(query);
/// ```
#[wasm_bindgen]
pub fn discovery_create_query(
    capabilities_json: Option<String>,
    keywords_json: Option<String>,
    min_history_secs: Option<f64>,
) -> Result<String, JsError> {
    let capabilities: Option<Vec<String>> = match capabilities_json {
        Some(ref s) => Some(serde_json::from_str(s).map_err(|e| {
            JsError::new(&format!("[SCP-VALID-7040] invalid capabilities JSON: {e}"))
        })?),
        None => None,
    };

    let keywords: Option<Vec<String>> =
        match keywords_json {
            Some(ref s) => Some(serde_json::from_str(s).map_err(|e| {
                JsError::new(&format!("[SCP-VALID-7040] invalid keywords JSON: {e}"))
            })?),
            None => None,
        };

    let min_history = match min_history_secs {
        Some(v) if v < 0.0 || !v.is_finite() => {
            return Err(JsError::new(
                "[SCP-VALID-7040] min_history_secs must be non-negative",
            ));
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Some(v) => Some(v as u64),
        None => None,
    };

    let result = serde_json::json!({
        "capability_filter": capabilities,
        "keywords": keywords,
        "min_history": min_history,
    });

    Ok(result.to_string())
}

// ---------------------------------------------------------------------------
// scp:// URI parsing (mirrors scp-core::uri::ScpUri)
// ---------------------------------------------------------------------------

/// Validates that a string contains only hexadecimal characters and is
/// non-empty. Mirrors `scp_core::uri::is_valid_hex`.
fn is_valid_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Percent-decodes a string. Minimal implementation sufficient for scp://
/// URI query parameter values. Mirrors the percent-decoding in
/// `scp_core::uri::parse_query_params`.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let high = hex_digit(bytes[i + 1]);
            let low = hex_digit(bytes[i + 2]);
            if let (Some(h), Some(l)) = (high, low) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Converts an ASCII hex digit byte to its numeric value.
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parses query parameters from a query string. Returns key-value pairs.
/// Values are percent-decoded. Mirrors `scp_core::uri::parse_query_params`.
fn parse_query_params(query: &str) -> Vec<(String, String)> {
    if query.is_empty() {
        return Vec::new();
    }
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| {
            let eq_pos = pair.find('=')?;
            let key = percent_decode(&pair[..eq_pos]);
            let value = percent_decode(&pair[eq_pos + 1..]);
            Some((key, value))
        })
        .collect()
}

/// Parses an `scp://` URI and returns a JSON array of discovery results.
///
/// Algorithm-identical to `scp_core::uri::ScpUri::from_str` +
/// `scp_core::discovery::resolve_context_uri`. Returns a single-element
/// array on success.
fn parse_scp_uri(uri_str: &str) -> Result<String, String> {
    // Split scheme from the rest.
    let (scheme, after_scheme) = uri_str
        .split_once("://")
        .ok_or_else(|| "missing '://' separator".to_owned())?;

    if scheme != "scp" {
        return Err(format!(
            "invalid URI scheme: expected 'scp', got '{scheme}'"
        ));
    }

    // Split path from query string.
    let (path, query_str) = match after_scheme.split_once('?') {
        Some((p, q)) => (p, q),
        None => (after_scheme, ""),
    };

    // Determine path type and extract context ID.
    let (context_id_raw, is_legacy_broadcast) = if let Some(hex) = path.strip_prefix("context/") {
        (hex, false)
    } else if let Some(hex) = path.strip_prefix("broadcast/") {
        (hex, true)
    } else {
        return Err(
            "missing or invalid context path — expected 'context/<hex>' or 'broadcast/<hex>'"
                .to_owned(),
        );
    };

    let context_id = percent_decode(context_id_raw);
    if !is_valid_hex(&context_id) {
        return Err(format!("invalid context ID hex: '{context_id}'"));
    }

    // Parse query parameters.
    let params = parse_query_params(query_str);

    let mut relay_urls: Vec<String> = Vec::new();
    let mut mode: Option<&str> = if is_legacy_broadcast {
        Some("broadcast")
    } else {
        None
    };
    let mut name: Option<String> = None;

    for (key, value) in &params {
        match key.as_str() {
            "relay" => {
                if !value.starts_with("wss://") && !value.starts_with("WSS://") {
                    return Err(format!("relay URL must use wss:// scheme: '{value}'"));
                }
                relay_urls.push(value.clone());
            }
            "mode" => match value.as_str() {
                "encrypted" => mode = Some("encrypted"),
                "broadcast" => mode = Some("broadcast"),
                _ => {} // Unknown mode values are ignored (advisory field)
            },
            "name" => {
                name = Some(value.clone());
            }
            _ => {} // Unknown query parameters ignored (forward compatibility)
        }
    }

    if relay_urls.is_empty() {
        return Err("missing required 'relay' query parameter".to_owned());
    }

    // Timestamp: js_sys is not available in non-wasm test builds, so use a
    // seconds-since-epoch value. In wasm32, js_sys::Date::now() provides
    // milliseconds; we divide by 1000 for seconds.
    #[cfg(target_arch = "wasm32")]
    let now_secs = {
        let secs = js_sys::Date::now() / 1000.0;
        if !secs.is_finite() || secs < 0.0 {
            0u64
        } else {
            // f64 -> u64: sign loss is guarded above; truncation is safe
            // because Unix seconds (~1.7e9) is far below u64::MAX.
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            {
                secs as u64
            }
        }
    };
    #[cfg(not(target_arch = "wasm32"))]
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "system clock is unavailable or before Unix epoch".to_owned())?;

    // Build a single ContextDiscoveryResult matching the NAPI bridge's
    // discovery_result_to_json output format, including trust_level and
    // resolution_path per §22.2.1 / §22.11.3.
    //
    // An scp:// URI is shared out-of-band, so the trust level is
    // DirectExchange and the resolution layer is "Domain" (closest match
    // for URI-based resolution — no context is involved).
    let result = serde_json::json!([{
        "context_id": context_id,
        "relay_urls": relay_urls,
        "publisher_did": "",
        "discovery_source": "context_uri",
        "mode": mode,
        "metadata_summary": name,
        "trust_level": {
            "kind": "DirectExchange",
        },
        "resolution_path": {
            "layer": "Domain",
            "source": "context_uri",
            "source_id": null,
            "resolved_at": now_secs,
        },
    }]);

    Ok(result.to_string())
}

// ---------------------------------------------------------------------------
// context_discover
// ---------------------------------------------------------------------------

/// Discovers contexts from a DID string or `scp://` URI.
///
/// Detects whether the query is a DID or an `scp://` URI and handles
/// accordingly:
///
/// - **`scp://` URIs**: Parsed locally (pure string operation, no network I/O).
///   Returns a JSON array with a single discovery result.
/// - **`did:` queries**: DHT resolution requires network I/O that cannot be
///   performed from Rust in WASM. Returns an error (`SCP-CTX-2022`). The
///   TypeScript wrapper layer should implement DID-based discovery via the
///   Fetch API if needed.
///
/// Returns a JSON string containing an array of discovery results, each with:
/// `context_id`, `relay_urls`, `publisher_did`, `discovery_source`, `mode`,
/// `metadata_summary`, `trust_level`, `resolution_path`.
///
/// # DID query limitation
///
/// DID-based queries (`did:dht:...`, `did:web:...`, etc.) return an error
/// (`SCP-CTX-2022`) in the WASM bridge. DHT resolution requires network
/// I/O (BEP44 DHT lookups via HTTP relays), which is not available from
/// Rust compiled to `wasm32-unknown-unknown`. The TypeScript wrapper layer
/// can implement DID-based discovery via the browser Fetch API if needed —
/// this is a known architectural limitation per ADR-034, not a missing
/// feature.
///
/// See §5.14.11, §18.2.2, §18.4.
///
/// # Errors
///
/// Returns `JsError` if the query is not a valid DID or `scp://` URI, if
/// the `scp://` URI is malformed, or if the query is a DID (unsupported
/// in WASM).
///
/// # JS usage
///
/// ```js
/// // scp:// URI — parsed locally
/// const results = await context_discover(
///     "scp://context/deadbeef?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1&mode=broadcast"
/// );
/// const arr = JSON.parse(results);
/// console.log(arr[0].context_id); // "deadbeef"
///
/// // DID query — rejects with SCP-CTX-2022 (DHT unavailable in WASM)
/// try {
///     await context_discover("did:dht:z6MkTest");
/// } catch (e) {
///     console.log(e.message); // "[SCP-CTX-2022] DID-based discovery is not available..."
/// }
/// ```
#[wasm_bindgen]
pub fn context_discover(query: String) -> Promise {
    future_to_promise(async move {
        if query.starts_with("scp://") {
            // Parse scp:// URI — synchronous, no network I/O.
            let results_json = parse_scp_uri(&query).map_err(|e| {
                JsValue::from_str(&format!("[SCP-CTX-2020] failed to resolve scp:// URI: {e}"))
            })?;
            Ok(JsValue::from_str(&results_json))
        } else if query.starts_with("did:") {
            // DHT resolution requires network I/O — not available in WASM.
            // Return an explicit error so callers don't silently get empty results.
            // The TypeScript wrapper layer can implement DID-based discovery
            // via the Fetch API if needed.
            Err(JsValue::from_str(&format!(
                "[SCP-CTX-2022] DID-based discovery is not available in the WASM bridge \
                 (requires network I/O for DHT resolution): {query}"
            )))
        } else {
            Err(JsValue::from_str(&format!(
                "[SCP-VALID-7027] query must be a DID (starts with 'did:') or an scp:// URI \
                     (starts with 'scp://'), got: {query}"
            )))
        }
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Petname bridge (§22.4) — local reimplementation per ADR-034
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::sync::Mutex;

/// Petname event types mirroring `scp_core::discovery::petnames::PetnameEvent`.
///
/// Events for the identity private state event log related to petnames (§22.9.2).
/// All mutations flow through `apply_event` to match scp-core's append-only
/// event log model.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WasmPetnameEvent {
    /// Assigns a petname to a DID.
    SetPetname {
        /// The DID to assign the petname to.
        did: String,
        /// The petname string.
        name: String,
    },
    /// Removes a petname from a DID.
    RemovePetname {
        /// The DID whose petname is being removed.
        did: String,
    },
    /// Assigns a petname to a context.
    SetContextPetname {
        /// The context ID to assign the petname to.
        context_id: String,
        /// The petname string.
        name: String,
    },
    /// Removes a petname from a context.
    RemoveContextPetname {
        /// The context ID whose petname is being removed.
        context_id: String,
    },
}

/// In-memory petname map (mirrors scp-core `PetnameMap`).
///
/// All mutations go through `apply_event` to match scp-core's event-driven
/// model (§22.9.2). Convenience methods (`set_petname`, etc.) create and apply
/// events internally, recording them in `event_log` for retrieval.
struct WasmPetnameMap {
    /// petname -> list of DIDs
    did_petnames: HashMap<String, Vec<String>>,
    /// DID -> petname (reverse)
    did_to_petname: HashMap<String, String>,
    /// petname -> list of context IDs
    context_petnames: HashMap<String, Vec<String>>,
    /// context ID -> petname (reverse)
    context_to_petname: HashMap<String, String>,
    /// Append-only log of applied events (mirrors identity private state log).
    event_log: Vec<WasmPetnameEvent>,
}

impl WasmPetnameMap {
    fn new() -> Self {
        Self {
            did_petnames: HashMap::new(),
            did_to_petname: HashMap::new(),
            context_petnames: HashMap::new(),
            context_to_petname: HashMap::new(),
            event_log: Vec::new(),
        }
    }

    /// Applies a petname event, updating internal state and recording the event.
    ///
    /// This is the primary mutation method -- all changes go through events
    /// to match scp-core's append-only event log model (§3.7).
    fn apply_event(&mut self, event: &WasmPetnameEvent) {
        match event {
            WasmPetnameEvent::SetPetname { did, name } => {
                // Remove any existing petname for this DID.
                if let Some(old_name) = self.did_to_petname.remove(did.as_str()) {
                    if let Some(dids) = self.did_petnames.get_mut(&old_name) {
                        dids.retain(|d| d != did);
                    }
                    if self.did_petnames.get(&old_name).is_some_and(Vec::is_empty) {
                        self.did_petnames.remove(&old_name);
                    }
                }
                // Set the new petname.
                self.did_petnames
                    .entry(name.clone())
                    .or_default()
                    .push(did.clone());
                self.did_to_petname.insert(did.clone(), name.clone());
            }
            WasmPetnameEvent::RemovePetname { did } => {
                if let Some(name) = self.did_to_petname.remove(did.as_str()) {
                    if let Some(dids) = self.did_petnames.get_mut(&name) {
                        dids.retain(|d| d != did);
                    }
                    if self.did_petnames.get(&name).is_some_and(Vec::is_empty) {
                        self.did_petnames.remove(&name);
                    }
                }
            }
            WasmPetnameEvent::SetContextPetname { context_id, name } => {
                // Remove any existing petname for this context.
                if let Some(old_name) = self.context_to_petname.remove(context_id.as_str()) {
                    if let Some(ids) = self.context_petnames.get_mut(&old_name) {
                        ids.retain(|id| id != context_id);
                    }
                    if self
                        .context_petnames
                        .get(&old_name)
                        .is_some_and(Vec::is_empty)
                    {
                        self.context_petnames.remove(&old_name);
                    }
                }
                // Set the new petname.
                self.context_petnames
                    .entry(name.clone())
                    .or_default()
                    .push(context_id.clone());
                self.context_to_petname
                    .insert(context_id.clone(), name.clone());
            }
            WasmPetnameEvent::RemoveContextPetname { context_id } => {
                if let Some(name) = self.context_to_petname.remove(context_id.as_str()) {
                    if let Some(ids) = self.context_petnames.get_mut(&name) {
                        ids.retain(|id| id != context_id);
                    }
                    if self.context_petnames.get(&name).is_some_and(Vec::is_empty) {
                        self.context_petnames.remove(&name);
                    }
                }
            }
        }
        self.event_log.push(event.clone());
    }

    /// Convenience: sets a petname for a DID via event.
    fn set_petname(&mut self, did: &str, name: &str) {
        self.apply_event(&WasmPetnameEvent::SetPetname {
            did: did.to_owned(),
            name: name.to_owned(),
        });
    }

    /// Convenience: removes a petname from a DID via event.
    fn remove_petname(&mut self, did: &str) {
        self.apply_event(&WasmPetnameEvent::RemovePetname {
            did: did.to_owned(),
        });
    }

    /// Convenience: sets a petname for a context via event.
    fn set_context_petname(&mut self, context_id: &str, name: &str) {
        self.apply_event(&WasmPetnameEvent::SetContextPetname {
            context_id: context_id.to_owned(),
            name: name.to_owned(),
        });
    }

    /// Convenience: removes a petname from a context via event.
    fn remove_context_petname(&mut self, context_id: &str) {
        self.apply_event(&WasmPetnameEvent::RemoveContextPetname {
            context_id: context_id.to_owned(),
        });
    }

    fn resolve_did(&self, name: &str) -> Vec<String> {
        self.did_petnames.get(name).cloned().unwrap_or_default()
    }

    fn resolve_context(&self, name: &str) -> Vec<String> {
        self.context_petnames.get(name).cloned().unwrap_or_default()
    }

    fn petname_for_did(&self, did: &str) -> Option<String> {
        self.did_to_petname.get(did).cloned()
    }

    fn petname_for_context(&self, context_id: &str) -> Option<String> {
        self.context_to_petname.get(context_id).cloned()
    }

    /// Returns the number of DID petnames (mirrors `PetnameMap::did_petname_count`).
    fn did_petname_count(&self) -> usize {
        self.did_to_petname.len()
    }

    /// Returns the number of context petnames (mirrors `PetnameMap::context_petname_count`).
    fn context_petname_count(&self) -> usize {
        self.context_to_petname.len()
    }
}

/// Global petname maps keyed by owner DID.
fn wasm_petname_maps() -> &'static Mutex<HashMap<String, WasmPetnameMap>> {
    use std::sync::OnceLock;
    static MAPS: OnceLock<Mutex<HashMap<String, WasmPetnameMap>>> = OnceLock::new();
    MAPS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Acquires the petname lock, returning a `JsError` on poison.
fn lock_petname_maps()
-> Result<std::sync::MutexGuard<'static, HashMap<String, WasmPetnameMap>>, JsError> {
    wasm_petname_maps()
        .lock()
        .map_err(|e| JsError::new(&format!("[SCP-VALID-7112] petname lock poisoned: {e}")))
}

/// Validates that `owner_did` is non-empty.
fn validate_owner_did(owner_did: &str) -> Result<(), JsError> {
    if owner_did.is_empty() {
        return Err(JsError::new("[SCP-VALID-7110] owner_did must not be empty"));
    }
    Ok(())
}

/// Sets a petname for a DID.
///
/// Emits a `SetPetname` event matching scp-core's `PetnameEvent::SetPetname`.
///
/// # Errors
///
/// Returns `JsError` if `owner_did` or `target_did` is empty, or the lock is poisoned.
#[wasm_bindgen]
pub fn petname_set(owner_did: String, target_did: String, name: String) -> Result<(), JsError> {
    validate_owner_did(&owner_did)?;
    if target_did.is_empty() {
        return Err(JsError::new(
            "[SCP-VALID-7111] target_did must not be empty",
        ));
    }
    lock_petname_maps()?
        .entry(owner_did)
        .or_insert_with(WasmPetnameMap::new)
        .set_petname(&target_did, &name);
    Ok(())
}

/// Removes a petname from a DID.
///
/// Emits a `RemovePetname` event matching scp-core's `PetnameEvent::RemovePetname`.
///
/// # Errors
///
/// Returns `JsError` if `owner_did` is empty or the lock is poisoned.
#[wasm_bindgen]
pub fn petname_remove(owner_did: String, target_did: String) -> Result<(), JsError> {
    validate_owner_did(&owner_did)?;
    if let Some(map) = lock_petname_maps()?.get_mut(&owner_did) {
        map.remove_petname(&target_did);
    }
    Ok(())
}

/// Sets a petname for a context.
///
/// Emits a `SetContextPetname` event matching scp-core's
/// `PetnameEvent::SetContextPetname`.
///
/// # Errors
///
/// Returns `JsError` if `owner_did` or `context_id` is empty, or the lock is poisoned.
#[wasm_bindgen]
pub fn petname_set_context(
    owner_did: String,
    context_id: String,
    name: String,
) -> Result<(), JsError> {
    validate_owner_did(&owner_did)?;
    if context_id.is_empty() {
        return Err(JsError::new(
            "[SCP-VALID-7113] context_id must not be empty",
        ));
    }
    lock_petname_maps()?
        .entry(owner_did)
        .or_insert_with(WasmPetnameMap::new)
        .set_context_petname(&context_id, &name);
    Ok(())
}

/// Removes a petname from a context.
///
/// Emits a `RemoveContextPetname` event matching scp-core's
/// `PetnameEvent::RemoveContextPetname`.
///
/// # Errors
///
/// Returns `JsError` if `owner_did` is empty or the lock is poisoned.
#[wasm_bindgen]
pub fn petname_remove_context(owner_did: String, context_id: String) -> Result<(), JsError> {
    validate_owner_did(&owner_did)?;
    if let Some(map) = lock_petname_maps()?.get_mut(&owner_did) {
        map.remove_context_petname(&context_id);
    }
    Ok(())
}

/// Resolves a petname to DIDs. Returns a JSON array of DID strings.
///
/// # Errors
///
/// Returns `JsError` if `owner_did` is empty or the lock is poisoned.
#[wasm_bindgen]
pub fn petname_resolve_did(owner_did: String, name: String) -> Result<String, JsError> {
    validate_owner_did(&owner_did)?;
    let dids = lock_petname_maps()?
        .get(&owner_did)
        .map(|map| map.resolve_did(&name))
        .unwrap_or_default();
    Ok(serde_json::to_string(&dids).unwrap_or_else(|_| "[]".to_owned()))
}

/// Resolves a petname to context IDs. Returns a JSON array of strings.
///
/// # Errors
///
/// Returns `JsError` if `owner_did` is empty or the lock is poisoned.
#[wasm_bindgen]
pub fn petname_resolve_context(owner_did: String, name: String) -> Result<String, JsError> {
    validate_owner_did(&owner_did)?;
    let ids = lock_petname_maps()?
        .get(&owner_did)
        .map(|map| map.resolve_context(&name))
        .unwrap_or_default();
    Ok(serde_json::to_string(&ids).unwrap_or_else(|_| "[]".to_owned()))
}

/// Gets the petname for a DID. Returns the name or `null`.
///
/// # Errors
///
/// Returns `JsError` if `owner_did` is empty or the lock is poisoned.
#[wasm_bindgen]
pub fn petname_get_for_did(owner_did: String, target_did: String) -> Result<JsValue, JsError> {
    validate_owner_did(&owner_did)?;
    let name = lock_petname_maps()?
        .get(&owner_did)
        .and_then(|map| map.petname_for_did(&target_did));
    name.map_or_else(|| Ok(JsValue::NULL), |n| Ok(JsValue::from_str(&n)))
}

/// Gets the petname for a context. Returns the name or `null`.
///
/// # Errors
///
/// Returns `JsError` if `owner_did` is empty or the lock is poisoned.
#[wasm_bindgen]
pub fn petname_get_for_context(owner_did: String, context_id: String) -> Result<JsValue, JsError> {
    validate_owner_did(&owner_did)?;
    let name = lock_petname_maps()?
        .get(&owner_did)
        .and_then(|map| map.petname_for_context(&context_id));
    name.map_or_else(|| Ok(JsValue::NULL), |n| Ok(JsValue::from_str(&n)))
}

/// Applies a petname event from JSON.
///
/// The event JSON must match the `WasmPetnameEvent` serde format, which mirrors
/// scp-core's `PetnameEvent` (§22.9.2). This is the event-driven mutation path
/// matching `PetnameMap::apply_event` in scp-core.
///
/// Example JSON:
/// ```json
/// {"SetPetname": {"did": "did:dht:zAlice", "name": "alice"}}
/// {"RemovePetname": {"did": "did:dht:zAlice"}}
/// {"SetContextPetname": {"context_id": "ctx-1", "name": "work"}}
/// {"RemoveContextPetname": {"context_id": "ctx-1"}}
/// ```
///
/// # Errors
///
/// Returns `JsError` if `owner_did` is empty, the JSON is malformed,
/// or the lock is poisoned.
#[wasm_bindgen]
pub fn petname_apply_event(owner_did: String, event_json: String) -> Result<(), JsError> {
    validate_owner_did(&owner_did)?;
    let event: WasmPetnameEvent = serde_json::from_str(&event_json)
        .map_err(|e| JsError::new(&format!("[SCP-VALID-7114] invalid petname event JSON: {e}")))?;
    lock_petname_maps()?
        .entry(owner_did)
        .or_insert_with(WasmPetnameMap::new)
        .apply_event(&event);
    Ok(())
}

/// Returns all emitted petname events for an owner DID as a JSON array.
///
/// Events are returned in emission order. Each element matches the
/// `WasmPetnameEvent` serde format (same as scp-core `PetnameEvent`).
///
/// # Errors
///
/// Returns `JsError` if `owner_did` is empty or the lock is poisoned.
#[wasm_bindgen]
pub fn petname_list_events(owner_did: String) -> Result<String, JsError> {
    validate_owner_did(&owner_did)?;
    let events: Vec<WasmPetnameEvent> = lock_petname_maps()?
        .get(&owner_did)
        .map(|map| map.event_log.clone())
        .unwrap_or_default();
    Ok(serde_json::to_string(&events).unwrap_or_else(|_| "[]".to_owned()))
}

/// Returns the number of DID petnames for an owner.
///
/// Mirrors `PetnameMap::did_petname_count` in scp-core.
///
/// # Errors
///
/// Returns `JsError` if `owner_did` is empty or the lock is poisoned.
#[wasm_bindgen]
pub fn petname_did_count(owner_did: String) -> Result<u32, JsError> {
    validate_owner_did(&owner_did)?;
    let count = lock_petname_maps()?
        .get(&owner_did)
        .map_or(0, WasmPetnameMap::did_petname_count);
    u32::try_from(count)
        .map_err(|_| JsError::new("[SCP-VALID-7115] petname count exceeds u32::MAX"))
}

/// Returns the number of context petnames for an owner.
///
/// Mirrors `PetnameMap::context_petname_count` in scp-core.
///
/// # Errors
///
/// Returns `JsError` if `owner_did` is empty or the lock is poisoned.
#[wasm_bindgen]
pub fn petname_context_count(owner_did: String) -> Result<u32, JsError> {
    validate_owner_did(&owner_did)?;
    let count = lock_petname_maps()?
        .get(&owner_did)
        .map_or(0, WasmPetnameMap::context_petname_count);
    u32::try_from(count)
        .map_err(|_| JsError::new("[SCP-VALID-7116] petname count exceeds u32::MAX"))
}

// ---------------------------------------------------------------------------
// Handle registry bridge (§22.3.1) — local reimplementation per ADR-034
// ---------------------------------------------------------------------------

/// In-memory handle entry.
#[derive(Clone, serde::Serialize)]
struct WasmHandleEntry {
    handle: String,
    target: serde_json::Value,
    owner_did: String,
    registered_at: u64,
    metadata: serde_json::Value,
    entry_id: String,
}

/// In-memory handle registry for one context.
struct WasmHandleRegistry {
    entries: HashMap<String, WasmHandleEntry>,
    next_id: u64,
}

impl WasmHandleRegistry {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            next_id: 1,
        }
    }
}

fn wasm_handle_registries() -> &'static Mutex<HashMap<String, WasmHandleRegistry>> {
    use std::sync::OnceLock;
    static REGISTRIES: OnceLock<Mutex<HashMap<String, WasmHandleRegistry>>> = OnceLock::new();
    REGISTRIES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Registers a handle in a context with discovery tools. Returns JSON result.
///
/// # Errors
///
/// Returns `JsError` if `target_json` is malformed or the lock is poisoned.
#[wasm_bindgen]
#[allow(clippy::significant_drop_tightening)]
pub fn handle_register(
    discovery_context_id: String,
    handle: String,
    target_json: String,
    registrant_did: String,
    description: Option<String>,
    tags_json: Option<String>,
) -> Result<String, JsError> {
    let target: serde_json::Value = serde_json::from_str(&target_json)
        .map_err(|e| JsError::new(&format!("[SCP-VALID-7126] invalid target_json: {e}")))?;

    // Ownership check for identity targets.
    if target["type"].as_str() == Some("identity")
        && target["did"]
            .as_str()
            .is_some_and(|target_did| target_did != registrant_did)
    {
        let result = serde_json::json!({"status": "ownership_mismatch", "entry_id": null});
        return Ok(result.to_string());
    }

    let normalized = handle.to_lowercase();
    let now = crate::time::now_secs();

    let tags: Option<Vec<String>> = match tags_json.as_deref() {
        Some(s) => Some(
            serde_json::from_str(s)
                .map_err(|e| JsError::new(&format!("[SCP-VALID-7126] invalid tags_json: {e}")))?,
        ),
        None => None,
    };

    let entry_id = {
        let mut guard = wasm_handle_registries()
            .lock()
            .map_err(|e| JsError::new(&format!("[SCP-VALID-7120] lock poisoned: {e}")))?;
        let registry = guard
            .entry(discovery_context_id)
            .or_insert_with(WasmHandleRegistry::new);

        if registry.entries.contains_key(&normalized) {
            let result = serde_json::json!({"status": "conflict", "entry_id": null});
            return Ok(result.to_string());
        }

        let eid = format!("handle-{}", registry.next_id);
        registry.next_id += 1;

        let entry = WasmHandleEntry {
            handle: normalized.clone(),
            target,
            owner_did: registrant_did,
            registered_at: now,
            metadata: serde_json::json!({"description": description, "tags": tags}),
            entry_id: eid.clone(),
        };

        registry.entries.insert(normalized, entry);
        eid
    };

    let result = serde_json::json!({"status": "registered", "entry_id": entry_id});
    Ok(result.to_string())
}

/// Looks up a handle in a context with discovery tools. Returns JSON result.
///
/// # Errors
///
/// Returns `JsError` if the lock is poisoned.
#[wasm_bindgen]
pub fn handle_lookup(
    discovery_context_id: String,
    handle: String,
    type_filter: Option<String>,
) -> Result<String, JsError> {
    let normalized = handle.to_lowercase();
    let results: Vec<serde_json::Value> = wasm_handle_registries()
        .lock()
        .map_err(|e| JsError::new(&format!("[SCP-VALID-7120] lock poisoned: {e}")))?
        .get(&discovery_context_id)
        .and_then(|registry| registry.entries.get(&normalized))
        .filter(|entry| match type_filter.as_deref() {
            Some("identity") => entry.target["type"].as_str() == Some("identity"),
            Some("context") => entry.target["type"].as_str() == Some("context"),
            _ => true,
        })
        .map(|entry| serde_json::to_value(entry).unwrap_or_default())
        .into_iter()
        .collect();

    let result = serde_json::json!({"results": results});
    Ok(result.to_string())
}

/// Deregisters a handle from a context with discovery tools. Returns JSON result.
///
/// # Errors
///
/// Returns `JsError` if the lock is poisoned.
#[wasm_bindgen]
pub fn handle_deregister(
    discovery_context_id: String,
    handle: String,
    did: String,
) -> Result<String, JsError> {
    let normalized = handle.to_lowercase();
    let removed = wasm_handle_registries()
        .lock()
        .map_err(|e| JsError::new(&format!("[SCP-VALID-7120] lock poisoned: {e}")))?
        .get_mut(&discovery_context_id)
        .is_some_and(|registry| {
            if registry
                .entries
                .get(&normalized)
                .is_some_and(|entry| entry.owner_did == did)
            {
                registry.entries.remove(&normalized);
                true
            } else {
                false
            }
        });

    let result = serde_json::json!({"removed": removed});
    Ok(result.to_string())
}

// ---------------------------------------------------------------------------
// Scope registry (§22.3.5, ADR-043) — WASM reimplementation per ADR-034
// ---------------------------------------------------------------------------

/// Validates a DID string at the WASM scope boundary (defense-in-depth).
/// Non-empty, starts with "did:", no control characters.
fn wasm_validate_scope_did(did: &str) -> Result<(), JsError> {
    if did.is_empty() {
        return Err(JsError::new("[SCP-VALID-7136] DID must not be empty"));
    }
    if did.len() > 512 {
        return Err(JsError::new(
            "[SCP-VALID-7136] DID exceeds maximum length of 512 characters",
        ));
    }
    if !did.starts_with("did:") {
        return Err(JsError::new(
            "[SCP-VALID-7136] DID must start with \"did:\"",
        ));
    }
    let rest = &did[4..];
    if !rest.contains(':') {
        return Err(JsError::new(
            "[SCP-VALID-7136] DID must match 'did:<method>:<id>' format",
        ));
    }
    let method = rest.split(':').next().unwrap_or("");
    if method.is_empty()
        || !method
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return Err(JsError::new(
            "[SCP-VALID-7136] DID method must be non-empty lowercase alphanumeric",
        ));
    }
    if did.bytes().any(|b| b < 0x20) {
        return Err(JsError::new(
            "[SCP-VALID-7136] DID contains control characters",
        ));
    }
    Ok(())
}

/// Validates a context ID at the WASM scope boundary (defense-in-depth).
/// Non-empty, no control characters.
fn wasm_validate_scope_context_id(context_id: &str) -> Result<(), JsError> {
    if context_id.is_empty() {
        return Err(JsError::new(
            "[SCP-VALID-7137] context_id must not be empty",
        ));
    }
    if context_id.len() > 256 {
        return Err(JsError::new(
            "[SCP-VALID-7137] context_id exceeds 256 characters",
        ));
    }
    if !context_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(JsError::new(
            "[SCP-VALID-7137] context_id contains invalid characters: expected alphanumeric, hyphens, or underscores",
        ));
    }
    Ok(())
}

/// Validates a scope name per §22.3.5 rules (WASM-local reimplementation).
/// Charset: [a-z0-9-], max 64 chars, no leading/trailing hyphens, non-empty.
fn wasm_validate_scope_name(name: &str) -> Result<(), JsError> {
    if name.is_empty() {
        return Err(JsError::new(
            "[SCP-VALID-7131] scope name must not be empty",
        ));
    }
    if name.len() > 64 {
        return Err(JsError::new(
            "[SCP-VALID-7131] scope name exceeds maximum length of 64 characters",
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(JsError::new(
            "[SCP-VALID-7131] scope name contains invalid characters: only [a-z0-9-] allowed",
        ));
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err(JsError::new(
            "[SCP-VALID-7131] scope name must not start or end with a hyphen",
        ));
    }
    Ok(())
}

/// What a WASM scope entry resolves to. Nested under `WasmScopeEntry` to match
/// the scp-core `ScopeTarget` wire format (context-only by construction).
#[derive(Clone, serde::Serialize)]
struct WasmScopeTarget {
    context_id: String,
    relay_urls: Vec<String>,
}

/// Typed scope metadata for WASM bridge.
#[derive(Clone, serde::Serialize)]
struct WasmScopeMetadata {
    description: Option<String>,
    tags: Option<Vec<String>>,
}

/// In-memory scope entry for WASM bridge.
#[derive(Clone, serde::Serialize)]
struct WasmScopeEntry {
    name: String,
    target: WasmScopeTarget,
    owner_did: String,
    registered_at: u64,
    metadata: WasmScopeMetadata,
    entry_id: String,
}

/// Maximum number of entries in a single WASM scope registry (mirrors scp-core).
const MAX_WASM_SCOPE_ENTRIES: usize = 10_000;

/// In-memory scope registry for one context.
struct WasmScopeRegistry {
    entries: HashMap<String, WasmScopeEntry>,
    next_id: u64,
}

impl WasmScopeRegistry {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            next_id: 1,
        }
    }
}

thread_local! {
    /// Per-context scope registries. WASM is single-threaded, so `RefCell` is
    /// sufficient — no `Mutex` needed. Matches the `thread_local!` pattern
    /// used by `IDENTITY_REGISTRY`, `RATE_LIMIT_TRACKERS`, and `MANAGER`.
    static WASM_SCOPE_REGISTRIES: std::cell::RefCell<HashMap<String, WasmScopeRegistry>> =
        std::cell::RefCell::new(HashMap::new());
}

/// Collects scope name -> context ID mappings for WASM address resolution.
///
/// **Cross-context note:** Merges all scope registries globally, matching
/// how handle registries are merged in `resolve_via_handles`. A future
/// refinement could scope to caller-provided trusted registry context IDs.
fn wasm_known_contexts_from_scope_registries() -> HashMap<String, String> {
    WASM_SCOPE_REGISTRIES.with(|registries| {
        let guard = registries.borrow();
        let mut result = HashMap::new();
        for registry in guard.values() {
            for entry in registry.entries.values() {
                result
                    .entry(entry.name.clone())
                    .or_insert_with(|| entry.target.context_id.clone());
            }
        }
        result
    })
}

/// Parsed and validated scope-register inputs.
struct ValidatedScopeRegisterInput {
    relay_urls: Vec<String>,
    description: Option<String>,
    tags: Option<Vec<String>>,
}

/// Validates and parses `scope_register` inputs (relay URLs, metadata).
fn wasm_validate_scope_register_input(
    relay_urls_json: &str,
    description: Option<String>,
    tags_json: Option<&str>,
) -> Result<ValidatedScopeRegisterInput, JsError> {
    let relay_urls: Vec<String> = serde_json::from_str(relay_urls_json)
        .map_err(|e| JsError::new(&format!("[SCP-VALID-7135] invalid relay_urls_json: {e}")))?;

    if relay_urls.is_empty() {
        return Err(JsError::new(
            "[SCP-VALID-7131] relay_urls must contain at least one URL",
        ));
    }
    if relay_urls.len() > 10 {
        return Err(JsError::new(
            "[SCP-VALID-7131] relay_urls exceeds maximum count of 10",
        ));
    }
    for url in &relay_urls {
        if !(url.starts_with("ws://")
            || url.starts_with("wss://")
            || url.starts_with("http://")
            || url.starts_with("https://"))
        {
            return Err(JsError::new(&format!(
                "[SCP-VALID-7135] relay URL must start with ws://, wss://, http://, or https://, got {url:?}"
            )));
        }
        if url.len() > 2048 {
            return Err(JsError::new(
                "[SCP-VALID-7131] relay URL exceeds 2048 characters",
            ));
        }
        if url.bytes().any(|b| b == b'\r' || b == b'\n' || b < 0x20) {
            return Err(JsError::new(
                "[SCP-VALID-7131] relay URL contains control characters",
            ));
        }
    }

    if let Some(ref desc) = description
        && desc.len() > 1024
    {
        return Err(JsError::new(
            "[SCP-VALID-7131] description exceeds maximum length of 1024 characters",
        ));
    }
    let tags: Option<Vec<String>> = match tags_json {
        Some(s) => Some(
            serde_json::from_str(s)
                .map_err(|e| JsError::new(&format!("[SCP-VALID-7131] invalid tags_json: {e}")))?,
        ),
        None => None,
    };
    if let Some(ref t) = tags {
        if t.len() > 20 {
            return Err(JsError::new(
                "[SCP-VALID-7131] tags exceed maximum count of 20",
            ));
        }
        for tag in t {
            if tag.is_empty() {
                return Err(JsError::new("[SCP-VALID-7138] tag must not be empty"));
            }
            if tag.len() > 64 {
                return Err(JsError::new(
                    "[SCP-VALID-7131] tag exceeds maximum length of 64 characters",
                ));
            }
        }
    }

    Ok(ValidatedScopeRegisterInput {
        relay_urls,
        description,
        tags,
    })
}

/// Registers a scope name in a scope registry. Returns JSON result.
///
/// # Errors
///
/// Returns `JsError` if validation fails or the lock is poisoned.
#[wasm_bindgen]
pub fn scope_register(
    scope_context_id: String,
    name: String,
    target_context_id: String,
    relay_urls_json: String,
    registrant_did: String,
    description: Option<String>,
    tags_json: Option<String>,
) -> Result<String, JsError> {
    wasm_validate_scope_context_id(&scope_context_id)?;
    wasm_validate_scope_context_id(&target_context_id)?;
    wasm_validate_scope_did(&registrant_did)?;
    wasm_validate_scope_name(&name)?;

    let input =
        wasm_validate_scope_register_input(&relay_urls_json, description, tags_json.as_deref())?;
    let normalized = name.to_lowercase();
    let now = crate::time::now_secs();

    WASM_SCOPE_REGISTRIES.with(|registries| {
        let mut guard = registries.borrow_mut();
        let registry = guard
            .entry(scope_context_id)
            .or_insert_with(WasmScopeRegistry::new);

        // Same-owner re-registration -> atomic update
        if let Some(existing) = registry.entries.get_mut(&normalized) {
            if existing.owner_did == registrant_did {
                existing.target = WasmScopeTarget {
                    context_id: target_context_id,
                    relay_urls: input.relay_urls,
                };
                existing.metadata = WasmScopeMetadata {
                    description: input.description,
                    tags: input.tags,
                };
                existing.registered_at = now;
                let result =
                    serde_json::json!({"status": "updated", "entry_id": existing.entry_id});
                return Ok(result.to_string());
            }
            let result = serde_json::json!({"status": "conflict", "entry_id": null});
            return Ok(result.to_string());
        }

        // Capacity check before new registration
        if registry.entries.len() >= MAX_WASM_SCOPE_ENTRIES {
            return Err(JsError::new(
                "[SCP-VALID-7131] scope registry capacity exceeded (max 10,000 entries)",
            ));
        }

        let eid = format!("scope-{}", registry.next_id);
        registry.next_id += 1;

        let entry = WasmScopeEntry {
            name: normalized.clone(),
            target: WasmScopeTarget {
                context_id: target_context_id,
                relay_urls: input.relay_urls,
            },
            owner_did: registrant_did,
            registered_at: now,
            metadata: WasmScopeMetadata {
                description: input.description,
                tags: input.tags,
            },
            entry_id: eid.clone(),
        };

        registry.entries.insert(normalized, entry);

        let result = serde_json::json!({"status": "registered", "entry_id": eid});
        Ok(result.to_string())
    })
}

/// Looks up a scope name in a scope registry. Returns JSON result.
///
/// # Errors
///
/// Returns `JsError` if validation fails or the lock is poisoned.
#[wasm_bindgen]
pub fn scope_lookup(scope_context_id: String, name: String) -> Result<String, JsError> {
    wasm_validate_scope_context_id(&scope_context_id)?;
    wasm_validate_scope_name(&name)?;
    let normalized = name.to_lowercase();

    WASM_SCOPE_REGISTRIES.with(|registries| {
        let guard = registries.borrow();
        let results: Vec<serde_json::Value> = guard
            .get(&scope_context_id)
            .and_then(|registry| registry.entries.get(&normalized))
            .map(|entry| {
                serde_json::to_value(entry).map_err(|e| {
                    JsError::new(&format!(
                        "[SCP-VALID-7133] scope entry serialization failed: {e}"
                    ))
                })
            })
            .transpose()?
            .into_iter()
            .collect();

        let result = serde_json::json!({"results": results});
        Ok(result.to_string())
    })
}

/// Deregisters a scope name from a scope registry. Returns JSON result.
///
/// # Errors
///
/// Returns `JsError` if validation fails or the lock is poisoned.
#[wasm_bindgen]
pub fn scope_deregister(
    scope_context_id: String,
    name: String,
    did: String,
) -> Result<String, JsError> {
    wasm_validate_scope_context_id(&scope_context_id)?;
    wasm_validate_scope_did(&did)?;
    wasm_validate_scope_name(&name)?;
    let normalized = name.to_lowercase();

    WASM_SCOPE_REGISTRIES.with(|registries| {
        let mut guard = registries.borrow_mut();
        let removed = guard.get_mut(&scope_context_id).is_some_and(|registry| {
            if registry
                .entries
                .get(&normalized)
                .is_some_and(|entry| entry.owner_did == did)
            {
                registry.entries.remove(&normalized);
                true
            } else {
                false
            }
        });

        let result = serde_json::json!({"removed": removed});
        Ok(result.to_string())
    })
}

// ---------------------------------------------------------------------------
// Address resolve (§22.8) — WASM reimplementation per ADR-034
// ---------------------------------------------------------------------------

/// Resolves a human-readable address via multi-path resolution.
///
/// In WASM, resolution uses the local petname map and handle registries.
/// Domain and attestation handle resolution require network I/O and are
/// not available in WASM (empty results for those layers).
///
/// Returns a JSON array of resolution result objects.
///
/// # Errors
///
/// Returns `JsError` if `owner_did` is empty, address is empty, or the
/// address cannot be resolved.
#[wasm_bindgen]
pub fn address_resolve(
    owner_did: String,
    address: String,
    known_contexts_json: Option<String>,
) -> Result<String, JsError> {
    if owner_did.is_empty() {
        return Err(JsError::new("[SCP-VALID-7110] owner_did must not be empty"));
    }

    let normalized = address.trim().to_lowercase();
    if normalized.is_empty() {
        return Err(JsError::new("[SCP-VALID-7091] address must not be empty"));
    }

    let now = crate::time::now_secs();

    // Try petnames first (instant, no network).
    let petname_results = resolve_via_petnames(&owner_did, &normalized, now)?;
    if !petname_results.is_empty() {
        return Ok(serde_json::to_string(&petname_results).unwrap_or_else(|_| "[]".to_owned()));
    }

    // Try handle registries for unscoped or scoped addresses.
    let handle_results = resolve_via_handles(&normalized, known_contexts_json.as_deref(), now)?;
    if handle_results.is_empty() {
        return Err(JsError::new(&format!(
            "[SCP-VALID-7091] address not found: {address}"
        )));
    }

    Ok(serde_json::to_string(&handle_results).unwrap_or_else(|_| "[]".to_owned()))
}

#[allow(clippy::significant_drop_tightening)]
fn resolve_via_petnames(
    owner_did: &str,
    normalized: &str,
    now: u64,
) -> Result<Vec<serde_json::Value>, JsError> {
    let mut results = Vec::new();
    let guard = wasm_petname_maps()
        .lock()
        .map_err(|e| JsError::new(&format!("[SCP-VALID-7112] lock poisoned: {e}")))?;
    if let Some(map) = guard.get(owner_did) {
        for did in map.resolve_did(normalized) {
            results.push(serde_json::json!({
                "type": "Identity",
                "did": did,
                "trust_level": {"kind": "LocalPetname"},
                "resolution_path": {
                    "layer": "Petname",
                    "source": "local",
                    "source_id": null,
                    "resolved_at": now,
                },
            }));
        }
        for ctx_id in map.resolve_context(normalized) {
            results.push(serde_json::json!({
                "type": "Context",
                "context_id": ctx_id,
                "relay_urls": [],
                "mode": null,
                "trust_level": {"kind": "LocalPetname"},
                "resolution_path": {
                    "layer": "Petname",
                    "source": "local",
                    "source_id": null,
                    "resolved_at": now,
                },
            }));
        }
    }
    Ok(results)
}

#[allow(clippy::significant_drop_tightening)]
fn resolve_via_handles(
    normalized: &str,
    known_contexts_json: Option<&str>,
    now: u64,
) -> Result<Vec<serde_json::Value>, JsError> {
    // Parse scoped addresses: "alice@cooking-community" → local_part="alice", scope="cooking-community"
    let (local_part, scope) = normalized.find('@').map_or((normalized, None), |at_pos| {
        (&normalized[..at_pos], Some(&normalized[at_pos + 1..]))
    });

    let mut known_contexts: HashMap<String, String> = if let Some(json) = known_contexts_json {
        serde_json::from_str(json).map_err(|e| {
            JsError::new(&format!(
                "[SCP-VALID-7090] invalid known_contexts_json: {e}"
            ))
        })?
    } else {
        wasm_handle_registries()
            .lock()
            .map_err(|e| JsError::new(&format!("[SCP-VALID-7120] lock poisoned: {e}")))?
            .keys()
            .map(|k| (k.clone(), k.clone()))
            .collect()
    };

    // Merge scope registry contexts for two-hop resolution (§22.3.5).
    let scope_contexts = wasm_known_contexts_from_scope_registries();
    for (name, ctx_id) in scope_contexts {
        known_contexts.entry(name).or_insert(ctx_id);
    }

    let mut results = Vec::new();
    let guard = wasm_handle_registries()
        .lock()
        .map_err(|e| JsError::new(&format!("[SCP-VALID-7120] lock poisoned: {e}")))?;
    for (scope_name, ctx_id) in &known_contexts {
        // If a scope is specified, only search in contexts whose scope name matches.
        if scope.is_some_and(|s| scope_name != s) {
            continue;
        }
        let resolution = guard
            .get(ctx_id)
            .and_then(|r| r.entries.get(local_part))
            .and_then(|entry| entry_to_resolution(entry, ctx_id, now));
        if let Some(r) = resolution {
            results.push(r);
        }
    }

    // W1: Sort by trust level (descending rank) and deduplicate.
    sort_and_deduplicate_results(&mut results);

    Ok(results)
}

fn entry_to_resolution(
    entry: &WasmHandleEntry,
    ctx_id: &str,
    now: u64,
) -> Option<serde_json::Value> {
    let target_type = entry.target["type"].as_str()?;
    match target_type {
        "identity" => {
            let did = entry.target["did"].as_str().unwrap_or("");
            Some(serde_json::json!({
                "type": "Identity",
                "did": did,
                "trust_level": {"kind": "HandleRegistryVerified"},
                "resolution_path": {
                    "layer": "HandleRegistry",
                    "source": "local_registry",
                    "source_id": ctx_id,
                    "resolved_at": now,
                },
            }))
        }
        "context" => {
            let cid = entry.target["context_id"].as_str().unwrap_or("");
            let relay_urls = entry.target["relay_urls"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                .unwrap_or_default();
            Some(serde_json::json!({
                "type": "Context",
                "context_id": cid,
                "relay_urls": relay_urls,
                "mode": null,
                "trust_level": {"kind": "HandleRegistryVerified"},
                "resolution_path": {
                    "layer": "HandleRegistry",
                    "source": "local_registry",
                    "source_id": ctx_id,
                    "resolved_at": now,
                },
            }))
        }
        _ => None,
    }
}

/// Returns a numeric rank for a trust level kind string (higher = more trusted).
fn trust_level_rank(kind: &str) -> u8 {
    match kind {
        "DirectExchange" => 6,
        "MultiLayerCorroborated" => 5,
        "LocalPetname" => 4,
        "AttestationVerified" => 3,
        "DomainVerified" => 2,
        "HandleRegistryVerified" => 1,
        _ => 0,
    }
}

/// Sorts results by trust level (descending) and deduplicates by
/// (DID or `context_id`), keeping the highest-trust entry for each.
fn sort_and_deduplicate_results(results: &mut Vec<serde_json::Value>) {
    // Sort descending by trust rank.
    results.sort_by(|a, b| {
        let rank_a = a["trust_level"]["kind"]
            .as_str()
            .map_or(0, trust_level_rank);
        let rank_b = b["trust_level"]["kind"]
            .as_str()
            .map_or(0, trust_level_rank);
        rank_b.cmp(&rank_a)
    });

    // Deduplicate: keep the first (highest trust) entry for each unique key.
    let mut seen = std::collections::HashSet::new();
    results.retain(|r| {
        let key = match r["type"].as_str() {
            Some("Identity") => r["did"].as_str().unwrap_or("").to_owned(),
            Some("Context") => r["context_id"].as_str().unwrap_or("").to_owned(),
            _ => return true,
        };
        seen.insert(key)
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Pure helper tests — no wasm-bindgen dependency, run on all targets.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn validate_local_part_valid() {
        assert!(validate_local_part("alice").is_ok());
        assert!(validate_local_part("alice.bob").is_ok());
        assert!(validate_local_part("alice_bob").is_ok());
        assert!(validate_local_part("alice-bob").is_ok());
        assert!(validate_local_part("a123").is_ok());
    }

    #[test]
    fn validate_local_part_too_long() {
        let long = "a".repeat(65);
        assert!(validate_local_part(&long).is_err());
    }

    #[test]
    fn validate_scope_rejects_control_chars() {
        assert!(validate_scope("scope\x00bad").is_err());
        assert!(validate_scope("scope\ttab").is_err());
        assert!(validate_scope("scope\nnewline").is_err());
        assert!(validate_scope("scope\rreturn").is_err());
        assert!(validate_scope("scope\x7Fdel").is_err());
    }

    #[test]
    fn validate_scope_rejects_zero_width_chars() {
        assert!(validate_scope("scope\u{200B}zwsp").is_err());
        assert!(validate_scope("scope\u{200C}zwnj").is_err());
        assert!(validate_scope("scope\u{200D}zwj").is_err());
        assert!(validate_scope("\u{FEFF}scope").is_err());
        assert!(validate_scope("scope\u{2060}wj").is_err());
    }

    #[test]
    fn validate_scope_accepts_valid() {
        assert!(validate_scope("photography").is_ok());
        assert!(validate_scope("example.com").is_ok());
        assert!(validate_scope("did:key:z6MkTest").is_ok());
        assert!(validate_scope("_").is_ok());
    }

    #[test]
    fn scope_based_classification() {
        // Verify PascalCase type tags per §22.11.3 by parsing full addresses.
        // Domain (has `.`) → DomainHandle; no `.` → DiscoveryHandle.
        let result = discovery_parse_address("alice@example.com".to_owned()).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["type"], "DomainHandle");
        assert_eq!(json["domain"], "example.com");

        let result = discovery_parse_address("alice@photography".to_owned()).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["type"], "DiscoveryHandle");
        assert_eq!(json["scope"], "photography");
    }

    // -- scp:// URI parsing tests -------------------------------------------

    #[test]
    fn parse_scp_uri_basic() {
        let result = parse_scp_uri(
            "scp://context/deadbeef?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1&mode=broadcast",
        )
        .unwrap();
        let arr: Vec<serde_json::Value> = serde_json::from_str(&result).unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["context_id"], "deadbeef");
        assert_eq!(arr[0]["relay_urls"][0], "wss://relay.example.com/scp/v1");
        assert_eq!(arr[0]["discovery_source"], "context_uri");
        assert_eq!(arr[0]["mode"], "broadcast");
        // §22.7 / §22.11.3: trust_level and resolution_path present, matching
        // other bridges (PyO3, NAPI, UniFFI).
        assert_eq!(arr[0]["trust_level"]["kind"], "DirectExchange");
        assert_eq!(arr[0]["resolution_path"]["layer"], "Domain");
        assert_eq!(arr[0]["resolution_path"]["source"], "context_uri");
        assert!(arr[0]["resolution_path"]["source_id"].is_null());
        assert!(arr[0]["resolution_path"]["resolved_at"].as_u64().unwrap() > 0);
    }

    #[test]
    fn parse_scp_uri_legacy_broadcast() {
        let result = parse_scp_uri(
            "scp://broadcast/abcdef12?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1",
        )
        .unwrap();
        let arr: Vec<serde_json::Value> = serde_json::from_str(&result).unwrap();
        assert_eq!(arr[0]["context_id"], "abcdef12");
        assert_eq!(arr[0]["mode"], "broadcast");
    }

    #[test]
    fn parse_scp_uri_with_name() {
        let result = parse_scp_uri(
            "scp://context/aabb?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1&name=Test%20Context",
        )
        .unwrap();
        let arr: Vec<serde_json::Value> = serde_json::from_str(&result).unwrap();
        assert_eq!(arr[0]["metadata_summary"], "Test Context");
    }

    #[test]
    fn parse_scp_uri_missing_relay_fails() {
        assert!(parse_scp_uri("scp://context/abcdef").is_err());
    }

    #[test]
    fn parse_scp_uri_invalid_scheme_fails() {
        assert!(
            parse_scp_uri("https://context/abcdef?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1")
                .is_err()
        );
    }

    #[test]
    fn parse_scp_uri_invalid_hex_fails() {
        assert!(
            parse_scp_uri("scp://context/zzzz?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1")
                .is_err()
        );
    }

    #[test]
    fn parse_scp_uri_non_wss_relay_fails() {
        assert!(
            parse_scp_uri("scp://context/abcdef?relay=https%3A%2F%2Frelay.example.com%2Fscp%2Fv1")
                .is_err()
        );
    }

    #[test]
    fn parse_scp_uri_multiple_relays() {
        let result = parse_scp_uri(
            "scp://context/aabb?relay=wss%3A%2F%2Frelay1.example.com%2Fscp%2Fv1&relay=wss%3A%2F%2Frelay2.example.com%2Fscp%2Fv1",
        )
        .unwrap();
        let arr: Vec<serde_json::Value> = serde_json::from_str(&result).unwrap();
        let relays = arr[0]["relay_urls"].as_array().unwrap();
        assert_eq!(relays.len(), 2);
    }

    #[test]
    fn percent_decode_basic() {
        assert_eq!(
            percent_decode("wss%3A%2F%2Fexample.com"),
            "wss://example.com"
        );
        assert_eq!(percent_decode("Hello%20World"), "Hello World");
        assert_eq!(percent_decode("no-encoding"), "no-encoding");
    }

    #[test]
    fn percent_decode_incomplete_sequence() {
        // Incomplete percent sequence at end — treated literally.
        assert_eq!(percent_decode("test%2"), "test%2");
        assert_eq!(percent_decode("test%"), "test%");
    }

    // -- WasmPetnameMap unit tests -------------------------------------------

    #[test]
    fn wasm_petname_map_set_and_resolve() {
        let mut map = WasmPetnameMap::new();
        map.set_petname("did:dht:zAlice", "alice");
        let dids = map.resolve_did("alice");
        assert_eq!(dids.len(), 1);
        assert_eq!(dids[0], "did:dht:zAlice");
    }

    #[test]
    fn wasm_petname_map_remove() {
        let mut map = WasmPetnameMap::new();
        map.set_petname("did:dht:zAlice", "alice");
        map.remove_petname("did:dht:zAlice");
        assert!(map.resolve_did("alice").is_empty());
    }

    #[test]
    fn wasm_petname_map_context() {
        let mut map = WasmPetnameMap::new();
        map.set_context_petname("ctx-1", "work");
        let ids = map.resolve_context("work");
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], "ctx-1");
        assert_eq!(map.petname_for_context("ctx-1"), Some("work".to_owned()));

        map.remove_context_petname("ctx-1");
        assert!(map.resolve_context("work").is_empty());
    }

    #[test]
    fn wasm_petname_map_reverse_lookup() {
        let mut map = WasmPetnameMap::new();
        map.set_petname("did:dht:zBob", "bob");
        assert_eq!(map.petname_for_did("did:dht:zBob"), Some("bob".to_owned()));
        assert_eq!(map.petname_for_did("did:dht:zNonExistent"), None);
    }

    // -- WasmPetnameEvent + apply_event tests --------------------------------

    #[test]
    fn wasm_petname_event_serialization_roundtrip() {
        let events = vec![
            WasmPetnameEvent::SetPetname {
                did: "did:dht:zAlice".to_owned(),
                name: "alice".to_owned(),
            },
            WasmPetnameEvent::RemovePetname {
                did: "did:dht:zAlice".to_owned(),
            },
            WasmPetnameEvent::SetContextPetname {
                context_id: "ctx-1".to_owned(),
                name: "work".to_owned(),
            },
            WasmPetnameEvent::RemoveContextPetname {
                context_id: "ctx-1".to_owned(),
            },
        ];
        for event in &events {
            let json = serde_json::to_string(event).unwrap();
            let deserialized: WasmPetnameEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(event, &deserialized);
        }
    }

    #[test]
    fn wasm_petname_apply_event_set_petname() {
        let mut map = WasmPetnameMap::new();
        map.apply_event(&WasmPetnameEvent::SetPetname {
            did: "did:dht:zAlice".to_owned(),
            name: "alice".to_owned(),
        });
        assert_eq!(map.resolve_did("alice").len(), 1);
        assert_eq!(map.event_log.len(), 1);
    }

    #[test]
    fn wasm_petname_apply_event_remove_petname() {
        let mut map = WasmPetnameMap::new();
        map.apply_event(&WasmPetnameEvent::SetPetname {
            did: "did:dht:zAlice".to_owned(),
            name: "alice".to_owned(),
        });
        map.apply_event(&WasmPetnameEvent::RemovePetname {
            did: "did:dht:zAlice".to_owned(),
        });
        assert!(map.resolve_did("alice").is_empty());
        assert_eq!(map.event_log.len(), 2);
    }

    #[test]
    fn wasm_petname_apply_event_set_context_petname() {
        let mut map = WasmPetnameMap::new();
        map.apply_event(&WasmPetnameEvent::SetContextPetname {
            context_id: "ctx-recipes".to_owned(),
            name: "recipes".to_owned(),
        });
        assert_eq!(map.resolve_context("recipes").len(), 1);
        assert_eq!(map.event_log.len(), 1);
    }

    #[test]
    fn wasm_petname_apply_event_remove_context_petname() {
        let mut map = WasmPetnameMap::new();
        map.apply_event(&WasmPetnameEvent::SetContextPetname {
            context_id: "ctx-1".to_owned(),
            name: "work".to_owned(),
        });
        map.apply_event(&WasmPetnameEvent::RemoveContextPetname {
            context_id: "ctx-1".to_owned(),
        });
        assert!(map.resolve_context("work").is_empty());
        assert_eq!(map.event_log.len(), 2);
    }

    #[test]
    fn wasm_petname_convenience_methods_emit_events() {
        let mut map = WasmPetnameMap::new();
        map.set_petname("did:dht:zAlice", "alice");
        map.set_context_petname("ctx-1", "work");
        map.remove_petname("did:dht:zAlice");
        map.remove_context_petname("ctx-1");
        assert_eq!(map.event_log.len(), 4);
        assert!(matches!(
            &map.event_log[0],
            WasmPetnameEvent::SetPetname { did, name }
            if did == "did:dht:zAlice" && name == "alice"
        ));
        assert!(matches!(
            &map.event_log[1],
            WasmPetnameEvent::SetContextPetname { context_id, name }
            if context_id == "ctx-1" && name == "work"
        ));
        assert!(matches!(
            &map.event_log[2],
            WasmPetnameEvent::RemovePetname { did }
            if did == "did:dht:zAlice"
        ));
        assert!(matches!(
            &map.event_log[3],
            WasmPetnameEvent::RemoveContextPetname { context_id }
            if context_id == "ctx-1"
        ));
    }

    #[test]
    fn wasm_petname_set_replaces_previous_emits_single_event() {
        let mut map = WasmPetnameMap::new();
        map.set_petname("did:dht:zAlice", "old-name");
        map.set_petname("did:dht:zAlice", "new-name");
        assert!(map.resolve_did("old-name").is_empty());
        assert_eq!(map.resolve_did("new-name").len(), 1);
        assert_eq!(map.event_log.len(), 2);
    }

    #[test]
    fn wasm_petname_multiple_dids_same_name() {
        let mut map = WasmPetnameMap::new();
        map.set_petname("did:dht:zAlice1", "bob");
        map.set_petname("did:dht:zAlice2", "bob");
        assert_eq!(map.resolve_did("bob").len(), 2);
    }

    // -- WasmPetnameMap: count tests -----------------------------------------

    #[test]
    fn wasm_petname_did_count() {
        let mut map = WasmPetnameMap::new();
        assert_eq!(map.did_petname_count(), 0);
        map.set_petname("did:dht:zAlice", "alice");
        assert_eq!(map.did_petname_count(), 1);
        map.set_petname("did:dht:zBob", "bob");
        assert_eq!(map.did_petname_count(), 2);
        map.remove_petname("did:dht:zAlice");
        assert_eq!(map.did_petname_count(), 1);
    }

    #[test]
    fn wasm_petname_context_count() {
        let mut map = WasmPetnameMap::new();
        assert_eq!(map.context_petname_count(), 0);
        map.set_context_petname("ctx-1", "one");
        assert_eq!(map.context_petname_count(), 1);
        map.set_context_petname("ctx-2", "two");
        assert_eq!(map.context_petname_count(), 2);
        map.remove_context_petname("ctx-1");
        assert_eq!(map.context_petname_count(), 1);
    }

    // -- WasmPetnameEvent serde format matches scp-core PetnameEvent ---------

    #[test]
    fn wasm_petname_event_serde_matches_core_format() {
        let event = WasmPetnameEvent::SetPetname {
            did: "did:dht:zAlice".to_owned(),
            name: "alice".to_owned(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["SetPetname"].is_object());
        assert_eq!(parsed["SetPetname"]["did"], "did:dht:zAlice");
        assert_eq!(parsed["SetPetname"]["name"], "alice");

        let remove = WasmPetnameEvent::RemovePetname {
            did: "did:dht:zAlice".to_owned(),
        };
        let json = serde_json::to_string(&remove).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["RemovePetname"].is_object());
        assert_eq!(parsed["RemovePetname"]["did"], "did:dht:zAlice");

        let ctx_set = WasmPetnameEvent::SetContextPetname {
            context_id: "ctx-1".to_owned(),
            name: "work".to_owned(),
        };
        let json = serde_json::to_string(&ctx_set).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["SetContextPetname"].is_object());
        assert_eq!(parsed["SetContextPetname"]["context_id"], "ctx-1");
        assert_eq!(parsed["SetContextPetname"]["name"], "work");

        let ctx_remove = WasmPetnameEvent::RemoveContextPetname {
            context_id: "ctx-1".to_owned(),
        };
        let json = serde_json::to_string(&ctx_remove).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["RemoveContextPetname"].is_object());
        assert_eq!(parsed["RemoveContextPetname"]["context_id"], "ctx-1");
    }

    // -- WasmHandleRegistry unit tests ---------------------------------------

    #[test]
    fn wasm_handle_registry_basic() {
        let mut registry = WasmHandleRegistry::new();
        let entry = WasmHandleEntry {
            handle: "alice".to_owned(),
            target: serde_json::json!({"type": "identity", "did": "did:dht:zAlice"}),
            owner_did: "did:dht:zAlice".to_owned(),
            registered_at: 0,
            metadata: serde_json::json!({}),
            entry_id: "handle-1".to_owned(),
        };
        registry.entries.insert("alice".to_owned(), entry);
        assert!(registry.entries.contains_key("alice"));
    }
}

/// Bridge function tests — call `#[wasm_bindgen]` exports, only run on wasm32.
#[cfg(all(test, target_arch = "wasm32"))]
#[allow(clippy::unwrap_used)]
mod wasm_tests {
    use super::*;

    #[test]
    fn parse_discovery_handle() {
        let result = discovery_parse_address("alice@photography".to_owned()).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["type"], "DiscoveryHandle");
        assert_eq!(json["local_part"], "alice");
        assert_eq!(json["scope"], "photography");
        // DomainHandle-specific fields should not be present
        assert!(json["domain"].is_null());
    }

    #[test]
    fn parse_domain_handle() {
        let result = discovery_parse_address("alice@example.com".to_owned()).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["type"], "DomainHandle");
        assert_eq!(json["local_part"], "alice");
        assert_eq!(json["domain"], "example.com");
        // DiscoveryHandle-specific fields should not be present
        assert!(json["scope"].is_null());
    }

    #[test]
    fn parse_attestation_handle() {
        let result = discovery_parse_address("@alice_cooks".to_owned()).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["type"], "AttestationHandle");
        assert_eq!(json["handle"], "alice_cooks");
        assert!(json["platform"].is_null());
    }

    #[test]
    fn parse_attestation_handle_with_platform() {
        let result = discovery_parse_address("@alice_cooks:x".to_owned()).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["type"], "AttestationHandle");
        assert_eq!(json["handle"], "alice_cooks");
        assert_eq!(json["platform"], "x");
    }

    #[test]
    fn parse_unscoped() {
        let result = discovery_parse_address("alice".to_owned()).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["type"], "Unscoped");
        assert_eq!(json["name"], "alice");
    }

    #[test]
    fn parse_empty_address_fails() {
        assert!(discovery_parse_address(String::new()).is_err());
    }

    #[test]
    fn parse_bare_at_sign_fails() {
        assert!(discovery_parse_address("@".to_owned()).is_err());
    }

    #[test]
    fn parse_empty_scope_fails() {
        assert!(discovery_parse_address("alice@".to_owned()).is_err());
    }

    #[test]
    fn parse_invalid_local_part_fails() {
        assert!(discovery_parse_address("ALICE@scope".to_owned()).is_err());
    }

    #[test]
    fn parse_leading_dash_fails() {
        assert!(discovery_parse_address("-alice@scope".to_owned()).is_err());
    }

    #[test]
    fn parse_consecutive_dots_fails() {
        assert!(discovery_parse_address("al..ice@scope".to_owned()).is_err());
    }

    #[test]
    fn normalize_lowercases() {
        assert_eq!(
            discovery_normalize_address("Alice@Photography".to_owned()),
            "alice@photography"
        );
    }

    #[test]
    fn normalize_trims_whitespace() {
        assert_eq!(
            discovery_normalize_address("  alice@scope  ".to_owned()),
            "alice@scope"
        );
    }

    #[test]
    fn create_query_with_capabilities() {
        let result =
            discovery_create_query(Some(r#"["code_review"]"#.to_owned()), None, Some(3600.0))
                .unwrap();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["capability_filter"][0], "code_review");
        assert_eq!(json["min_history"], 3600);
    }

    #[test]
    fn create_query_empty_returns_nulls() {
        // Unlike the old signature, an empty query (all None) is valid —
        // it returns a query with all-null fields matching the NAPI bridge
        // which serializes an empty DiscoveryQuery.
        let result = discovery_create_query(None, None, None).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["capability_filter"].is_null());
        assert!(json["keywords"].is_null());
        assert!(json["min_history"].is_null());
    }

    #[test]
    fn create_query_with_keywords() {
        let result =
            discovery_create_query(None, Some(r#"["rust","wasm"]"#.to_owned()), None).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["keywords"][0], "rust");
        assert_eq!(json["keywords"][1], "wasm");
    }

    #[test]
    fn parse_scope_control_char_fails() {
        assert!(discovery_parse_address("alice@scope\x00bad".to_owned()).is_err());
    }

    #[test]
    fn parse_scope_zero_width_space_fails() {
        assert!(discovery_parse_address("alice@scope\u{200B}zwsp".to_owned()).is_err());
    }

    #[test]
    fn create_query_negative_min_history_errors() {
        let result = discovery_create_query(None, None, Some(-1.0));
        assert!(result.is_err(), "negative min_history_secs should error");
    }

    #[test]
    fn create_query_neg_infinity_min_history_errors() {
        let result = discovery_create_query(None, None, Some(f64::NEG_INFINITY));
        assert!(
            result.is_err(),
            "NEG_INFINITY min_history_secs should error"
        );
    }

    #[test]
    fn create_query_f64_min_min_history_errors() {
        let result = discovery_create_query(None, None, Some(f64::MIN));
        assert!(result.is_err(), "f64::MIN min_history_secs should error");
    }

    #[test]
    fn create_query_nan_min_history_errors() {
        let result = discovery_create_query(None, None, Some(f64::NAN));
        assert!(result.is_err(), "NaN min_history_secs should error");
    }

    #[test]
    fn create_query_positive_infinity_min_history_errors() {
        let result = discovery_create_query(None, None, Some(f64::INFINITY));
        assert!(result.is_err(), "INFINITY min_history_secs should error");
    }

    #[test]
    fn create_query_invalid_capabilities_json_errors() {
        let result = discovery_create_query(Some("not-valid-json".to_owned()), None, None);
        assert!(result.is_err(), "invalid capabilities JSON should error");
    }
}
