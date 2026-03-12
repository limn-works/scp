//! `wasm-bindgen` bridge for discovery address operations.
//!
//! Exposes address parsing, normalization, and context discovery to JavaScript
//! (browser target):
//!
//! - [`discovery_parse_address`] — Parse a `local@scope` address into components.
//! - [`discovery_normalize_address`] — Normalize an address to canonical form.
//! - [`discovery_create_query`] — Create a discovery query descriptor.
//! - [`context_discover`] — Discover contexts from a DID or `scp://` URI.
//!
//! # WASM constraints
//!
//! This bridge does NOT depend on `scp-core` (tokio multi-thread incompatible
//! with `wasm32-unknown-unknown`). Address parsing and normalization are pure
//! string operations re-implemented locally with algorithm-identical validation.
//!
//! `context_discover` handles `scp://` URIs locally (pure parsing, no network
//! I/O). For `did:` queries, DHT resolution requires network I/O that cannot
//! be performed from Rust in WASM — the function returns an empty results
//! array. The TypeScript wrapper layer should implement DID-based discovery
//! via the Fetch API if needed.
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

/// Determines the address type from the scope part per spec §22.2.
///
/// - Scope contains `.` => `"domain_handle"` (e.g., `alice@example.com`)
/// - Otherwise => `"discovery_handle"` (e.g., `alice@photography`)
///
/// Note: `Unscoped` (bare name, no `@`) and `AttestationHandle` (platform-
/// prefixed) are distinguished at the address parsing level in scp-core,
/// not by scope string inspection. The WASM bridge only handles the two
/// scope-based types that the spec's §22.2 disambiguation table defines.
fn classify_scope(scope: &str) -> &'static str {
    if scope.contains('.') {
        "domain_handle"
    } else {
        "discovery_handle"
    }
}

// ---------------------------------------------------------------------------
// discovery_parse_address
// ---------------------------------------------------------------------------

/// Parses a `local@scope` address into its components.
///
/// Returns a JSON string with `type`, `local_part`, `scope`, and `raw` fields,
/// matching the NAPI bridge's `discovery_parse_address` output format.
///
/// # Errors
///
/// Returns `JsError` if the address is empty, missing `@`, or the local-part is invalid.
///
/// # JS usage
///
/// ```js
/// const parsed = discovery_parse_address("alice@photography");
/// const obj = JSON.parse(parsed);
/// console.log(obj.type);       // "discovery_handle"
/// console.log(obj.local_part); // "alice"
/// console.log(obj.scope);      // "photography"
/// ```
#[wasm_bindgen]
pub fn discovery_parse_address(address: String) -> Result<String, JsError> {
    if address.is_empty() {
        return Err(JsError::new("[SCP-VALID-7100] address must not be empty"));
    }

    let Some(at_pos) = address.find('@') else {
        return Err(JsError::new(
            "[SCP-VALID-7101] address must contain '@' separator",
        ));
    };

    let local = &address[..at_pos];
    let scope = &address[at_pos + 1..];

    if scope.is_empty() {
        return Err(JsError::new(
            "[SCP-VALID-7102] scope part must not be empty",
        ));
    }

    validate_local_part(local).map_err(|e| JsError::new(&format!("[SCP-VALID-7103] {e}")))?;
    validate_scope(scope).map_err(|e| JsError::new(&format!("[SCP-VALID-7104] {e}")))?;

    let address_type = classify_scope(scope);

    let result = serde_json::json!({
        "type": address_type,
        "local_part": local,
        "scope": scope,
        "raw": address,
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
        .unwrap_or(0);

    // Build a single ContextDiscoveryResult matching the NAPI bridge's
    // discovery_result_to_json output format, including trust_level and
    // resolution_path per §22.2.1 / §22.11.3.
    //
    // An scp:// URI is shared out-of-band, so the trust level is
    // DirectExchange and the resolution layer is "Domain" (closest match
    // for URI-based resolution — no discovery context is involved).
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
///   performed from Rust in WASM. Returns an empty JSON array `"[]"`. The
///   TypeScript wrapper layer should implement DID-based discovery via the
///   Fetch API if needed.
///
/// Returns a JSON string containing an array of discovery results, each with:
/// `context_id`, `relay_urls`, `publisher_did`, `discovery_source`, `mode`,
/// `metadata_summary`, `trust_level`, `resolution_path`.
///
/// # DID query limitation
///
/// DID-based queries (`did:dht:...`, `did:web:...`, etc.) always return an
/// empty results array `"[]"` in the WASM bridge. DHT resolution requires
/// network I/O (BEP44 DHT lookups via HTTP relays), which is not available
/// from Rust compiled to `wasm32-unknown-unknown`. The TypeScript wrapper
/// layer can implement DID-based discovery via the browser Fetch API if
/// needed — this is a known architectural limitation per ADR-034, not a
/// missing feature.
///
/// See §5.14.11, §18.2.2, §18.4.
///
/// # Errors
///
/// Returns `JsError` if the query is not a valid DID or `scp://` URI, or
/// if the `scp://` URI is malformed.
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
/// // DID query — returns empty array (DHT unavailable in WASM)
/// const empty = await context_discover("did:dht:z6MkTest");
/// console.log(JSON.parse(empty)); // []
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
            // Return empty results array. The TypeScript wrapper layer can
            // implement DID-based discovery via the Fetch API if needed.
            Ok(JsValue::from_str("[]"))
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

/// In-memory petname map (mirrors scp-core `PetnameMap`).
struct WasmPetnameMap {
    /// petname -> list of DIDs
    did_petnames: HashMap<String, Vec<String>>,
    /// DID -> petname (reverse)
    did_to_petname: HashMap<String, String>,
    /// petname -> list of context IDs
    context_petnames: HashMap<String, Vec<String>>,
    /// context ID -> petname (reverse)
    context_to_petname: HashMap<String, String>,
}

impl WasmPetnameMap {
    fn new() -> Self {
        Self {
            did_petnames: HashMap::new(),
            did_to_petname: HashMap::new(),
            context_petnames: HashMap::new(),
            context_to_petname: HashMap::new(),
        }
    }

    fn set_petname(&mut self, did: &str, name: &str) {
        // Remove old petname for this DID if any.
        if let Some(old_name) = self.did_to_petname.remove(did) {
            if let Some(dids) = self.did_petnames.get_mut(&old_name) {
                dids.retain(|d| d != did);
            }
            if self.did_petnames.get(&old_name).is_some_and(Vec::is_empty) {
                self.did_petnames.remove(&old_name);
            }
        }
        self.did_petnames
            .entry(name.to_owned())
            .or_default()
            .push(did.to_owned());
        self.did_to_petname.insert(did.to_owned(), name.to_owned());
    }

    fn remove_petname(&mut self, did: &str) {
        if let Some(name) = self.did_to_petname.remove(did) {
            if let Some(dids) = self.did_petnames.get_mut(&name) {
                dids.retain(|d| d != did);
            }
            if self.did_petnames.get(&name).is_some_and(Vec::is_empty) {
                self.did_petnames.remove(&name);
            }
        }
    }

    fn set_context_petname(&mut self, context_id: &str, name: &str) {
        if let Some(old_name) = self.context_to_petname.remove(context_id) {
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
        self.context_petnames
            .entry(name.to_owned())
            .or_default()
            .push(context_id.to_owned());
        self.context_to_petname
            .insert(context_id.to_owned(), name.to_owned());
    }

    fn remove_context_petname(&mut self, context_id: &str) {
        if let Some(name) = self.context_to_petname.remove(context_id) {
            if let Some(ids) = self.context_petnames.get_mut(&name) {
                ids.retain(|id| id != context_id);
            }
            if self.context_petnames.get(&name).is_some_and(Vec::is_empty) {
                self.context_petnames.remove(&name);
            }
        }
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
}

/// Global petname maps keyed by owner DID.
fn wasm_petname_maps() -> &'static Mutex<HashMap<String, WasmPetnameMap>> {
    use std::sync::OnceLock;
    static MAPS: OnceLock<Mutex<HashMap<String, WasmPetnameMap>>> = OnceLock::new();
    MAPS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Sets a petname for a DID.
///
/// # Errors
///
/// Returns `JsError` if `owner_did` is empty or the lock is poisoned.
#[wasm_bindgen]
pub fn petname_set(owner_did: String, target_did: String, name: String) -> Result<(), JsError> {
    if owner_did.is_empty() {
        return Err(JsError::new("[SCP-VALID-7110] owner_did must not be empty"));
    }
    if target_did.is_empty() {
        return Err(JsError::new(
            "[SCP-VALID-7111] target_did must not be empty",
        ));
    }
    wasm_petname_maps()
        .lock()
        .map_err(|e| JsError::new(&format!("[SCP-VALID-7112] petname lock poisoned: {e}")))?
        .entry(owner_did)
        .or_insert_with(WasmPetnameMap::new)
        .set_petname(&target_did, &name);
    Ok(())
}

/// Removes a petname from a DID.
///
/// # Errors
///
/// Returns `JsError` if `owner_did` is empty or the lock is poisoned.
#[wasm_bindgen]
pub fn petname_remove(owner_did: String, target_did: String) -> Result<(), JsError> {
    if owner_did.is_empty() {
        return Err(JsError::new("[SCP-VALID-7110] owner_did must not be empty"));
    }
    if let Some(map) = wasm_petname_maps()
        .lock()
        .map_err(|e| JsError::new(&format!("[SCP-VALID-7112] petname lock poisoned: {e}")))?
        .get_mut(&owner_did)
    {
        map.remove_petname(&target_did);
    }
    Ok(())
}

/// Sets a petname for a context.
///
/// # Errors
///
/// Returns `JsError` if `owner_did` is empty or the lock is poisoned.
#[wasm_bindgen]
pub fn petname_set_context(
    owner_did: String,
    context_id: String,
    name: String,
) -> Result<(), JsError> {
    if owner_did.is_empty() {
        return Err(JsError::new("[SCP-VALID-7110] owner_did must not be empty"));
    }
    if context_id.is_empty() {
        return Err(JsError::new(
            "[SCP-VALID-7113] context_id must not be empty",
        ));
    }
    wasm_petname_maps()
        .lock()
        .map_err(|e| JsError::new(&format!("[SCP-VALID-7112] petname lock poisoned: {e}")))?
        .entry(owner_did)
        .or_insert_with(WasmPetnameMap::new)
        .set_context_petname(&context_id, &name);
    Ok(())
}

/// Removes a petname from a context.
///
/// # Errors
///
/// Returns `JsError` if `owner_did` is empty or the lock is poisoned.
#[wasm_bindgen]
pub fn petname_remove_context(owner_did: String, context_id: String) -> Result<(), JsError> {
    if owner_did.is_empty() {
        return Err(JsError::new("[SCP-VALID-7110] owner_did must not be empty"));
    }
    if let Some(map) = wasm_petname_maps()
        .lock()
        .map_err(|e| JsError::new(&format!("[SCP-VALID-7112] petname lock poisoned: {e}")))?
        .get_mut(&owner_did)
    {
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
    if owner_did.is_empty() {
        return Err(JsError::new("[SCP-VALID-7110] owner_did must not be empty"));
    }
    let dids = wasm_petname_maps()
        .lock()
        .map_err(|e| JsError::new(&format!("[SCP-VALID-7112] petname lock poisoned: {e}")))?
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
    if owner_did.is_empty() {
        return Err(JsError::new("[SCP-VALID-7110] owner_did must not be empty"));
    }
    let ids = wasm_petname_maps()
        .lock()
        .map_err(|e| JsError::new(&format!("[SCP-VALID-7112] petname lock poisoned: {e}")))?
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
    if owner_did.is_empty() {
        return Err(JsError::new("[SCP-VALID-7110] owner_did must not be empty"));
    }
    let name = wasm_petname_maps()
        .lock()
        .map_err(|e| JsError::new(&format!("[SCP-VALID-7112] petname lock poisoned: {e}")))?
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
    if owner_did.is_empty() {
        return Err(JsError::new("[SCP-VALID-7110] owner_did must not be empty"));
    }
    let name = wasm_petname_maps()
        .lock()
        .map_err(|e| JsError::new(&format!("[SCP-VALID-7112] petname lock poisoned: {e}")))?
        .get(&owner_did)
        .and_then(|map| map.petname_for_context(&context_id));
    name.map_or_else(|| Ok(JsValue::NULL), |n| Ok(JsValue::from_str(&n)))
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

/// In-memory handle registry for one discovery context.
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

/// Registers a handle in a discovery context. Returns JSON result.
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

    let tags: Option<Vec<String>> = tags_json
        .as_deref()
        .map(|s| serde_json::from_str(s).unwrap_or_default());

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

/// Looks up a handle in a discovery context. Returns JSON result.
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

/// Deregisters a handle from a discovery context. Returns JSON result.
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

    let known_contexts: HashMap<String, String> = if let Some(json) = known_contexts_json {
        serde_json::from_str(json).map_err(|e| JsError::new(&format!("[SCP-VALID-7090] invalid known_contexts_json: {e}")))?
    } else {
        wasm_handle_registries()
            .lock()
            .map_err(|e| JsError::new(&format!("[SCP-VALID-7120] lock poisoned: {e}")))?
            .keys()
            .map(|k| (k.clone(), k.clone()))
            .collect()
    };

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
                "trust_level": {"kind": "DiscoveryContextVerified"},
                "resolution_path": {
                    "layer": "DiscoveryContext",
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
                "trust_level": {"kind": "DiscoveryContextVerified"},
                "resolution_path": {
                    "layer": "DiscoveryContext",
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
        "DiscoveryContextVerified" => 1,
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
    fn classify_scope_types() {
        // Only two scope-based types per spec §22.2: domain (has `.`) or discovery
        assert_eq!(classify_scope("example.com"), "domain_handle");
        assert_eq!(classify_scope("photography"), "discovery_handle");
        // "_" and "did:" scopes are regular scopes — not special-cased
        assert_eq!(classify_scope("_"), "discovery_handle");
        assert_eq!(classify_scope("did:key:z6MkTest"), "discovery_handle");
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
        assert_eq!(json["type"], "discovery_handle");
        assert_eq!(json["local_part"], "alice");
        assert_eq!(json["scope"], "photography");
    }

    #[test]
    fn parse_domain_handle() {
        let result = discovery_parse_address("alice@example.com".to_owned()).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["type"], "domain_handle");
    }

    #[test]
    fn parse_attestation_handle() {
        let result = discovery_parse_address("alice@did:key:z6MkTest".to_owned()).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["type"], "attestation_handle");
    }

    #[test]
    fn parse_unscoped() {
        let result = discovery_parse_address("alice@_".to_owned()).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["type"], "unscoped");
    }

    #[test]
    fn parse_empty_address_fails() {
        assert!(discovery_parse_address(String::new()).is_err());
    }

    #[test]
    fn parse_no_at_sign_fails() {
        assert!(discovery_parse_address("alice".to_owned()).is_err());
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
