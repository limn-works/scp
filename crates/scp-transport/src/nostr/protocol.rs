//! Nostr protocol types and message construction (NIP-01).
//!
//! Implements the subset of the Nostr protocol needed for SCP transport:
//! event construction, subscription filters, and relay message parsing.
//! All messages are JSON per NIP-01.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::TransportError;

/// Custom Nostr event kind for SCP envelopes.
///
/// Kind 29078 is in the regular event range (1000-9999), ensuring relays
/// store all events (not just the latest). Avoids parameterized-replaceable
/// kinds (30000-39999) which would silently discard prior messages.
pub const SCP_EVENT_KIND: u64 = 29078;

/// NIP-09 deletion event kind.
pub const DELETION_EVENT_KIND: u64 = 5;

/// Tag name used for routing ID filtering.
pub const ROUTING_TAG: &str = "r";

/// A Nostr event (NIP-01).
///
/// Events are the fundamental data type in Nostr. SCP uses custom kind 29078
/// events with the outer envelope base64-encoded in `.content` and the
/// `routing_id` in an `r` tag for relay-side filtering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrEvent {
    /// 32-byte hex-encoded SHA-256 of the serialized event.
    pub id: String,
    /// 32-byte hex-encoded public key of the event author.
    pub pubkey: String,
    /// Unix timestamp (seconds).
    pub created_at: u64,
    /// Event kind (29078 for SCP envelopes, 5 for NIP-09 deletions).
    pub kind: u64,
    /// Array of tag arrays. SCP uses `["r", "<hex(routing_id)>"]`.
    pub tags: Vec<Vec<String>>,
    /// Event content. Base64-encoded SCP outer envelope for kind 29078.
    pub content: String,
    /// 64-byte hex-encoded Schnorr signature (NIP-01).
    pub sig: String,
}

impl NostrEvent {
    /// Compute the NIP-01 event ID: SHA-256 of the canonical serialization.
    ///
    /// The canonical form is:
    /// `[0, pubkey, created_at, kind, tags, content]`
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ProtocolError`] if the canonical form
    /// cannot be serialized to JSON (should not happen with valid inputs).
    pub fn compute_id(
        pubkey: &str,
        created_at: u64,
        kind: u64,
        tags: &[Vec<String>],
        content: &str,
    ) -> Result<String, TransportError> {
        let canonical = serde_json::json!([0, pubkey, created_at, kind, tags, content]);
        let serialized = serde_json::to_string(&canonical).map_err(|e| {
            TransportError::ProtocolError(format!(
                "failed to serialize Nostr event canonical form: {e}"
            ))
        })?;
        let hash = Sha256::digest(serialized.as_bytes());
        Ok(hex::encode(hash))
    }

    /// Compute the raw SHA-256 hash of the event ID (for signing).
    ///
    /// BIP-340 Schnorr signatures sign the 32-byte message hash directly.
    /// The event ID is already the hex-encoded SHA-256, so we decode it
    /// back to 32 bytes for signing.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ProtocolError`] if the event ID is not
    /// valid 32-byte hex.
    pub fn id_bytes(&self) -> Result<[u8; 32], TransportError> {
        let bytes = hex::decode(&self.id)
            .map_err(|e| TransportError::ProtocolError(format!("invalid event ID hex: {e}")))?;
        let mut arr = [0u8; 32];
        if bytes.len() != 32 {
            return Err(TransportError::ProtocolError(format!(
                "event ID must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// A Nostr subscription filter (NIP-01 REQ).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrFilter {
    /// Filter by event kind.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<u64>>,
    /// Filter by tag values. Key is tag name prefixed with `#`.
    #[serde(rename = "#r", skip_serializing_if = "Option::is_none")]
    pub r_tag: Option<Vec<String>>,
    /// Only events after this timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    /// Maximum number of events to return (initial query).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
}

/// Messages sent from client to relay (NIP-01).
#[derive(Debug, Clone)]
pub enum ClientMessage {
    /// Publish an event: `["EVENT", <event>]`
    Event(NostrEvent),
    /// Subscribe with filters: `["REQ", <sub_id>, <filter>...]`
    Req {
        /// Subscription ID (arbitrary string).
        subscription_id: String,
        /// One or more filters.
        filters: Vec<NostrFilter>,
    },
    /// Close a subscription: `["CLOSE", <sub_id>]`
    Close {
        /// Subscription ID to close.
        subscription_id: String,
    },
}

impl ClientMessage {
    /// Serialize to JSON wire format.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ProtocolError`] if JSON serialization fails.
    pub fn to_json(&self) -> Result<String, TransportError> {
        match self {
            Self::Event(event) => {
                let event_json = serde_json::to_value(event).map_err(|e| {
                    TransportError::ProtocolError(format!(
                        "failed to serialize Nostr event to JSON: {e}"
                    ))
                })?;
                Ok(serde_json::json!(["EVENT", event_json]).to_string())
            }
            Self::Req {
                subscription_id,
                filters,
            } => {
                let mut arr: Vec<serde_json::Value> =
                    vec![serde_json::json!("REQ"), serde_json::json!(subscription_id)];
                for filter in filters {
                    let val = serde_json::to_value(filter).map_err(|e| {
                        TransportError::ProtocolError(format!(
                            "failed to serialize Nostr filter to JSON: {e}"
                        ))
                    })?;
                    arr.push(val);
                }
                Ok(serde_json::Value::Array(arr).to_string())
            }
            Self::Close { subscription_id } => {
                Ok(serde_json::json!(["CLOSE", subscription_id]).to_string())
            }
        }
    }
}

/// Messages received from relay to client (NIP-01).
#[derive(Debug, Clone)]
pub enum RelayMessage {
    /// An event matching a subscription: `["EVENT", <sub_id>, <event>]`
    Event {
        /// Subscription ID this event matches.
        subscription_id: String,
        /// The event.
        event: NostrEvent,
    },
    /// End of stored events for a subscription: `["EOSE", <sub_id>]`
    Eose {
        /// Subscription ID.
        subscription_id: String,
    },
    /// Acceptance status of a published event: `["OK", <event_id>, <accepted>, <message>]`
    Ok {
        /// Event ID.
        event_id: String,
        /// Whether the event was accepted.
        accepted: bool,
        /// Human-readable message.
        message: String,
    },
    /// A notice from the relay: `["NOTICE", <message>]`
    Notice {
        /// Human-readable notice.
        message: String,
    },
}

impl RelayMessage {
    /// Parse a JSON relay message.
    ///
    /// Returns `None` if the message cannot be parsed as a known relay message type.
    #[must_use]
    pub fn from_json(json: &str) -> Option<Self> {
        let arr: Vec<serde_json::Value> = serde_json::from_str(json).ok()?;
        let msg_type = arr.first()?.as_str()?;

        match msg_type {
            "EVENT" => {
                let sub_id = arr.get(1)?.as_str()?.to_owned();
                let event: NostrEvent = serde_json::from_value(arr.get(2)?.clone()).ok()?;
                Some(Self::Event {
                    subscription_id: sub_id,
                    event,
                })
            }
            "EOSE" => {
                let sub_id = arr.get(1)?.as_str()?.to_owned();
                Some(Self::Eose {
                    subscription_id: sub_id,
                })
            }
            "OK" => {
                let event_id = arr.get(1)?.as_str()?.to_owned();
                let accepted = arr.get(2)?.as_bool()?;
                let message = arr.get(3)?.as_str().unwrap_or("").to_owned();
                Some(Self::Ok {
                    event_id,
                    accepted,
                    message,
                })
            }
            "NOTICE" => {
                let message = arr.get(1)?.as_str()?.to_owned();
                Some(Self::Notice { message })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn event_id_computation_is_deterministic() {
        let pubkey = "a".repeat(64);
        let tags = vec![vec!["r".to_owned(), "deadbeef".to_owned()]];
        let id1 = NostrEvent::compute_id(&pubkey, 1000, SCP_EVENT_KIND, &tags, "hello").unwrap();
        let id2 = NostrEvent::compute_id(&pubkey, 1000, SCP_EVENT_KIND, &tags, "hello").unwrap();
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64); // hex-encoded SHA-256
    }

    #[test]
    fn event_id_differs_for_different_content() {
        let pubkey = "a".repeat(64);
        let tags = vec![vec!["r".to_owned(), "deadbeef".to_owned()]];
        let id1 = NostrEvent::compute_id(&pubkey, 1000, SCP_EVENT_KIND, &tags, "hello").unwrap();
        let id2 = NostrEvent::compute_id(&pubkey, 1000, SCP_EVENT_KIND, &tags, "world").unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn client_event_message_serializes_correctly() {
        let event = NostrEvent {
            id: "abc".to_owned(),
            pubkey: "def".to_owned(),
            created_at: 1000,
            kind: SCP_EVENT_KIND,
            tags: vec![],
            content: "test".to_owned(),
            sig: "sig".to_owned(),
        };
        let msg = ClientMessage::Event(event);
        let json = msg.to_json().unwrap();
        assert!(json.starts_with("[\"EVENT\""));
    }

    #[test]
    fn client_req_message_serializes_correctly() {
        let msg = ClientMessage::Req {
            subscription_id: "sub1".to_owned(),
            filters: vec![NostrFilter {
                kinds: Some(vec![SCP_EVENT_KIND]),
                r_tag: Some(vec!["deadbeef".to_owned()]),
                since: None,
                limit: None,
            }],
        };
        let json = msg.to_json().unwrap();
        assert!(json.contains("\"REQ\""));
        assert!(json.contains("sub1"));
    }

    #[test]
    fn client_close_message_serializes_correctly() {
        let msg = ClientMessage::Close {
            subscription_id: "sub1".to_owned(),
        };
        let json = msg.to_json().unwrap();
        assert_eq!(json, r#"["CLOSE","sub1"]"#);
    }

    #[test]
    fn relay_event_message_parses() {
        let json = r#"["EVENT","sub1",{"id":"abc","pubkey":"def","created_at":1000,"kind":29078,"tags":[],"content":"test","sig":"sig"}]"#;
        let msg = RelayMessage::from_json(json).unwrap();
        match msg {
            RelayMessage::Event {
                subscription_id,
                event,
            } => {
                assert_eq!(subscription_id, "sub1");
                assert_eq!(event.id, "abc");
                assert_eq!(event.kind, SCP_EVENT_KIND);
            }
            other => panic!("expected Event, got {other:?}"),
        }
    }

    #[test]
    fn relay_eose_message_parses() {
        let json = r#"["EOSE","sub1"]"#;
        let msg = RelayMessage::from_json(json).unwrap();
        match msg {
            RelayMessage::Eose { subscription_id } => {
                assert_eq!(subscription_id, "sub1");
            }
            other => panic!("expected Eose, got {other:?}"),
        }
    }

    #[test]
    fn relay_ok_message_parses() {
        let json = r#"["OK","eventid123",true,""]"#;
        let msg = RelayMessage::from_json(json).unwrap();
        match msg {
            RelayMessage::Ok {
                event_id,
                accepted,
                message,
            } => {
                assert_eq!(event_id, "eventid123");
                assert!(accepted);
                assert_eq!(message, "");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn relay_notice_message_parses() {
        let json = r#"["NOTICE","rate limited"]"#;
        let msg = RelayMessage::from_json(json).unwrap();
        match msg {
            RelayMessage::Notice { message } => {
                assert_eq!(message, "rate limited");
            }
            other => panic!("expected Notice, got {other:?}"),
        }
    }

    #[test]
    fn unknown_relay_message_returns_none() {
        let json = r#"["UNKNOWN","foo"]"#;
        assert!(RelayMessage::from_json(json).is_none());
    }

    #[test]
    fn invalid_json_returns_none() {
        assert!(RelayMessage::from_json("not json").is_none());
    }
}
