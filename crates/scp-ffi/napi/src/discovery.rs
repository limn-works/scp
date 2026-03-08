//! napi-rs bridge for discovery operations.
//!
//! Exposes SCP discovery operations to Node.js/Bun:
//!
//! - [`discovery_parse_address`] -- Parse an SCP address string.
//! - [`discovery_create_query`] -- Create a discovery query.
//! - [`discovery_normalize_address`] -- Normalize an address string.
//! - [`context_discover`] -- Discover contexts from a DID or `scp://` URI.
//!
//! See ADR-020 in `.docs/adrs/phase-4.md` and spec section 22 (Addressing).

use napi_derive::napi;

use scp_core::discovery::addressing::ParsedAddress;
use scp_core::discovery::{DiscoveryQuery, normalize_address, parse_address};

use crate::error::ScpNapiError;

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Parses an SCP address string into its components.
///
/// Returns a JSON string with the parsed address type and fields.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn discovery_parse_address(address: String) -> napi::Result<String> {
    let parsed = parse_address(&address).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid address '{address}': {e}"),
            code: "SCP-VALID-7020".to_owned(),
        })
    })?;

    let result = match parsed {
        ParsedAddress::DiscoveryHandle { local_part, scope } => {
            serde_json::json!({
                "type": "discovery_handle",
                "local_part": local_part,
                "scope": scope,
            })
        }
        ParsedAddress::DomainHandle { local_part, domain } => {
            serde_json::json!({
                "type": "domain_handle",
                "local_part": local_part,
                "domain": domain,
            })
        }
        ParsedAddress::AttestationHandle { handle, platform } => {
            serde_json::json!({
                "type": "attestation_handle",
                "handle": handle,
                "platform": platform,
            })
        }
        ParsedAddress::Unscoped { name } => {
            serde_json::json!({
                "type": "unscoped",
                "name": name,
            })
        }
    };

    serde_json::to_string(&result).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize parsed address: {e}"),
            code: "SCP-VALID-7021".to_owned(),
        })
    })
}

/// Creates a discovery query as a JSON string.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn discovery_create_query(
    capabilities: Option<Vec<String>>,
    keywords: Option<Vec<String>>,
    min_history_secs: Option<i64>,
) -> napi::Result<String> {
    #[allow(clippy::cast_sign_loss)]
    let query = DiscoveryQuery {
        capability_filter: capabilities,
        keywords,
        min_history: min_history_secs.map(|s| std::time::Duration::from_secs(s as u64)),
    };

    serde_json::to_string(&query).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize query: {e}"),
            code: "SCP-VALID-7022".to_owned(),
        })
    })
}

/// Normalizes an address string per SCP addressing rules.
///
/// Lowercases and trims whitespace.
#[napi]
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn discovery_normalize_address(address: String) -> String {
    normalize_address(&address)
}

// ---------------------------------------------------------------------------
// context_discover — DHT-based context discovery (SCP-336)
// ---------------------------------------------------------------------------

/// Converts a [`ContextDiscoveryResult`] into a JSON value.
fn discovery_result_to_json(
    result: &scp_core::discovery::ContextDiscoveryResult,
) -> serde_json::Value {
    let source_str = match &result.discovery_source {
        scp_core::discovery::ContextDiscoverySource::DhtDidDocument => "dht_did_document",
        scp_core::discovery::ContextDiscoverySource::WellKnown => "well_known",
        scp_core::discovery::ContextDiscoverySource::DiscoveryContext { .. } => "discovery_context",
        scp_core::discovery::ContextDiscoverySource::ContextUri => "context_uri",
    };

    let mut obj = serde_json::json!({
        "context_id": result.context_id,
        "relay_urls": result.relay_urls,
        "publisher_did": &*result.publisher_did,
        "discovery_source": source_str,
        "mode": result.mode,
        "metadata_summary": result.metadata_summary,
    });

    // Add discovery_context_id if applicable.
    if let scp_core::discovery::ContextDiscoverySource::DiscoveryContext { context_id } =
        &result.discovery_source
    {
        obj["discovery_context_id"] = serde_json::Value::String(context_id.clone());
    }

    obj
}

/// Discovers contexts from a DID string or `scp://` URI.
///
/// Detects whether the query is a DID or an `scp://` URI and delegates to
/// the appropriate core discovery function.
///
/// Returns a JSON string containing an array of discovery results, each with:
/// `context_id`, `relay_urls`, `publisher_did`, `discovery_source`, `mode`,
/// `metadata_summary`.
///
/// See §5.14.11, §18.2.2, §18.4.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub async fn context_discover(query: String) -> napi::Result<String> {
    if query.starts_with("scp://") {
        // Parse scp:// URI — synchronous, no network I/O.
        let result = scp_core::discovery::resolve_context_uri(&query).map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("failed to resolve scp:// URI: {e}"),
                code: "SCP-CTX-7023".to_owned(),
            })
        })?;

        let results = vec![discovery_result_to_json(&result)];
        serde_json::to_string(&results).map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("failed to serialize discovery results: {e}"),
                code: "SCP-CTX-7024".to_owned(),
            })
        })
    } else if query.starts_with("did:") {
        let did_dht = scp_identity::DidDht::new();
        let results = scp_core::discovery::resolve_contexts_from_did(&query, &did_dht)
            .await
            .map_err(|e| {
                napi::Error::from(ScpNapiError::Context {
                    message: format!("DHT discovery failed for '{query}': {e}"),
                    code: "SCP-CTX-7025".to_owned(),
                })
            })?;

        let json_results: Vec<serde_json::Value> =
            results.iter().map(discovery_result_to_json).collect();
        serde_json::to_string(&json_results).map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("failed to serialize discovery results: {e}"),
                code: "SCP-CTX-7026".to_owned(),
            })
        })
    } else {
        Err(napi::Error::from(ScpNapiError::Validation {
            message: format!(
                "query must be a DID (starts with 'did:') or an scp:// URI \
                 (starts with 'scp://'), got: {query}"
            ),
            code: "SCP-VALID-7027".to_owned(),
        }))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn create_query_with_capabilities() {
        let result = discovery_create_query(Some(vec!["code_review".to_string()]), None, None);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("code_review"));
    }

    #[test]
    fn create_query_empty() {
        let result = discovery_create_query(None, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn normalize_lowercases_and_trims() {
        let result = discovery_normalize_address("  ALICE@Cooking  ".to_string());
        assert_eq!(result, "alice@cooking");
    }

    #[test]
    fn context_discover_uri_path() {
        // Test the URI parsing path directly via core.
        let result = scp_core::discovery::resolve_context_uri(
            "scp://context/deadbeef?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1&mode=broadcast",
        )
        .unwrap();

        assert_eq!(result.context_id, "deadbeef");
        assert_eq!(result.relay_urls, vec!["wss://relay.example.com/scp/v1"]);
        assert_eq!(
            result.discovery_source,
            scp_core::discovery::ContextDiscoverySource::ContextUri
        );
    }

    #[test]
    fn context_discover_result_serialization() {
        let result = scp_core::discovery::ContextDiscoveryResult {
            context_id: "abc123".to_owned(),
            relay_urls: vec!["wss://relay.example.com".to_owned()],
            publisher_did: "did:dht:zTest".into(),
            discovery_source: scp_core::discovery::ContextDiscoverySource::DhtDidDocument,
            mode: Some("broadcast".to_owned()),
            metadata_summary: None,
        };

        let json = discovery_result_to_json(&result);
        assert_eq!(json["context_id"], "abc123");
        assert_eq!(json["discovery_source"], "dht_did_document");
        assert_eq!(json["mode"], "broadcast");
    }
}
