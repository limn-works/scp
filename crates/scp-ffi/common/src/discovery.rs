//! Shared discovery result mapping for SCP FFI bridges.
//!
//! Consolidates the `ContextDiscoverySource` → trust/resolution metadata
//! mapping that was previously duplicated across the `PyO3`, NAPI, and `UniFFI`
//! bridges. WASM is excluded (cannot depend on `scp-core` per ADR-034).
//!
//! See §22.2.1, §22.7, §22.11.3 in `.docs/specs/`.

use scp_core::discovery::{ContextDiscoveryResult, ContextDiscoverySource};

/// Maps a [`ContextDiscoverySource`] to trust/resolution metadata.
///
/// Returns `(source_str, trust_level_kind, resolution_layer, resolution_source, resolution_source_id)`.
///
/// This is the single source of truth for the source-to-trust/layer mapping
/// used by all non-WASM FFI bridges.
#[must_use]
pub const fn map_discovery_source(
    source: &ContextDiscoverySource,
) -> (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    Option<&str>,
) {
    match source {
        ContextDiscoverySource::DhtDidDocument => {
            ("dht_did_document", "DomainVerified", "Domain", "dht", None)
        }
        ContextDiscoverySource::WellKnown => {
            ("well_known", "DomainVerified", "Domain", "well-known", None)
        }
        ContextDiscoverySource::HandleRegistry { context_id } => (
            "discovery_context",
            "HandleRegistryVerified",
            "HandleRegistry",
            "discovery_context",
            Some(context_id.as_str()),
        ),
        // §22.7: An scp:// URI is shared out-of-band, so the trust level is
        // `DirectExchange` and the resolution layer is `"Domain"` (closest match
        // for URI-based resolution — no context is involved).
        ContextDiscoverySource::ContextUri => (
            "context_uri",
            "DirectExchange",
            "Domain",
            "context_uri",
            None,
        ),
    }
}

/// Converts a [`ContextDiscoveryResult`] into a `serde_json::Value`.
///
/// Builds a JSON object with keys: `context_id`, `relay_urls`, `publisher_did`,
/// `discovery_source`, `mode`, `metadata_summary`, `trust_level`,
/// `resolution_path`, and optionally `discovery_context_id`.
///
/// `trust_level` and `resolution_path` are derived from the discovery source
/// via [`map_discovery_source`]. `resolution_path.resolved_at` is set to the
/// current wall-clock time (seconds since UNIX epoch).
///
/// Used by the `PyO3` (test-only JSON path), NAPI, and `UniFFI` bridges.
#[must_use]
pub fn discovery_result_to_json(result: &ContextDiscoveryResult) -> serde_json::Value {
    let (source_str, trust_level_kind, resolution_layer, resolution_source, resolution_source_id) =
        map_discovery_source(&result.discovery_source);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut obj = serde_json::json!({
        "context_id": result.context_id,
        "relay_urls": result.relay_urls,
        "publisher_did": &*result.publisher_did,
        "discovery_source": source_str,
        "mode": result.mode,
        "metadata_summary": result.metadata_summary,
        "trust_level": {
            "kind": trust_level_kind,
        },
        "resolution_path": {
            "layer": resolution_layer,
            "source": resolution_source,
            "source_id": resolution_source_id,
            "resolved_at": now_secs,
        },
    });

    // Add discovery_context_id if applicable.
    if let ContextDiscoverySource::HandleRegistry { context_id } = &result.discovery_source {
        obj["discovery_context_id"] = serde_json::Value::String(context_id.clone());
    }

    obj
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make_result(source: ContextDiscoverySource) -> ContextDiscoveryResult {
        ContextDiscoveryResult {
            context_id: "test-ctx".to_owned(),
            relay_urls: vec!["wss://relay.example.com".to_owned()],
            publisher_did: "did:dht:zTest".into(),
            discovery_source: source,
            mode: Some("broadcast".to_owned()),
            metadata_summary: Some("summary".to_owned()),
        }
    }

    #[test]
    fn map_dht_did_document() {
        let (src, trust, layer, source, source_id) =
            map_discovery_source(&ContextDiscoverySource::DhtDidDocument);
        assert_eq!(src, "dht_did_document");
        assert_eq!(trust, "DomainVerified");
        assert_eq!(layer, "Domain");
        assert_eq!(source, "dht");
        assert!(source_id.is_none());
    }

    #[test]
    fn map_well_known() {
        let (src, trust, layer, source, source_id) =
            map_discovery_source(&ContextDiscoverySource::WellKnown);
        assert_eq!(src, "well_known");
        assert_eq!(trust, "DomainVerified");
        assert_eq!(layer, "Domain");
        assert_eq!(source, "well-known");
        assert!(source_id.is_none());
    }

    #[test]
    fn map_discovery_context() {
        let disc_source = ContextDiscoverySource::HandleRegistry {
            context_id: "disc-1".to_owned(),
        };
        let (src, trust, layer, source, source_id) = map_discovery_source(&disc_source);
        assert_eq!(src, "discovery_context");
        assert_eq!(trust, "HandleRegistryVerified");
        assert_eq!(layer, "HandleRegistry");
        assert_eq!(source, "discovery_context");
        assert_eq!(source_id, Some("disc-1"));
    }

    #[test]
    fn map_context_uri() {
        let (src, trust, layer, source, source_id) =
            map_discovery_source(&ContextDiscoverySource::ContextUri);
        assert_eq!(src, "context_uri");
        assert_eq!(trust, "DirectExchange");
        assert_eq!(layer, "Domain");
        assert_eq!(source, "context_uri");
        assert!(source_id.is_none());
    }

    #[test]
    fn result_to_json_dht_source() {
        let result = make_result(ContextDiscoverySource::DhtDidDocument);
        let json = discovery_result_to_json(&result);

        assert_eq!(json["context_id"], "test-ctx");
        assert_eq!(json["discovery_source"], "dht_did_document");
        assert_eq!(json["mode"], "broadcast");
        assert_eq!(json["metadata_summary"], "summary");
        assert_eq!(json["trust_level"]["kind"], "DomainVerified");
        assert_eq!(json["resolution_path"]["layer"], "Domain");
        assert_eq!(json["resolution_path"]["source"], "dht");
        assert!(json["resolution_path"]["source_id"].is_null());
        assert!(json["resolution_path"]["resolved_at"].as_u64().unwrap() > 0);
    }

    #[test]
    fn result_to_json_discovery_context_source() {
        let result = make_result(ContextDiscoverySource::HandleRegistry {
            context_id: "disc-ctx-1".to_owned(),
        });
        let json = discovery_result_to_json(&result);

        assert_eq!(json["trust_level"]["kind"], "HandleRegistryVerified");
        assert_eq!(json["resolution_path"]["layer"], "HandleRegistry");
        assert_eq!(json["resolution_path"]["source"], "discovery_context");
        assert_eq!(json["resolution_path"]["source_id"], "disc-ctx-1");
        assert_eq!(json["discovery_context_id"], "disc-ctx-1");
    }

    #[test]
    fn result_to_json_context_uri_source() {
        let result = make_result(ContextDiscoverySource::ContextUri);
        let json = discovery_result_to_json(&result);

        assert_eq!(json["trust_level"]["kind"], "DirectExchange");
        assert_eq!(json["resolution_path"]["layer"], "Domain");
        assert_eq!(json["resolution_path"]["source"], "context_uri");
        assert!(json["resolution_path"]["source_id"].is_null());
        assert!(json["resolution_path"]["resolved_at"].as_u64().unwrap() > 0);
    }

    #[test]
    fn result_to_json_well_known_source() {
        let result = make_result(ContextDiscoverySource::WellKnown);
        let json = discovery_result_to_json(&result);

        assert_eq!(json["trust_level"]["kind"], "DomainVerified");
        assert_eq!(json["resolution_path"]["layer"], "Domain");
        assert_eq!(json["resolution_path"]["source"], "well-known");
        assert!(json["resolution_path"]["source_id"].is_null());
    }
}
