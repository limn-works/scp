//! Push notification registration types for SCP.
//!
//! Implements `PushRegistration` and `PushDeregistration` wire formats per
//! spec §10.7.1. Clients register for push notifications with relays so that
//! mobile devices can be woken on new message arrival.
//!
//! Push payloads are fully opaque — the relay sends exactly `{ "scp": 1 }`
//! as a wake signal. No context ID, no sender DID, no message preview.
//! Apple/Google learn only that the device received a notification at a
//! specific time.

use serde::{Deserialize, Serialize};

use scp_primitives::DID;

// ---------------------------------------------------------------------------
// Type aliases (match codebase pattern)
// ---------------------------------------------------------------------------

pub use super::ContextId;

/// An Ed25519 signature (64 bytes).
pub type Ed25519Signature = Vec<u8>;

// ---------------------------------------------------------------------------
// PushPlatform
// ---------------------------------------------------------------------------

/// Push notification service platform.
///
/// Maps to the `platform` field in `PushRegistration` (spec §10.7.1).
/// The 1-byte tag values are used in the canonical signed structure:
/// `0x01` = APNS, `0x02` = FCM, `0x03` = `WebPush`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PushPlatform {
    /// Apple Push Notification service (iOS, macOS).
    Apns,
    /// Firebase Cloud Messaging (Android).
    Fcm,
    /// Web Push API (browsers).
    WebPush,
}

impl PushPlatform {
    /// Returns the 1-byte tag used in the canonical signed structure.
    #[must_use]
    pub const fn tag_byte(self) -> u8 {
        match self {
            Self::Apns => 0x01,
            Self::Fcm => 0x02,
            Self::WebPush => 0x03,
        }
    }
}

impl std::fmt::Display for PushPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Apns => write!(f, "APNS"),
            Self::Fcm => write!(f, "FCM"),
            Self::WebPush => write!(f, "WebPush"),
        }
    }
}

// ---------------------------------------------------------------------------
// PushRegistration (§10.7.1)
// ---------------------------------------------------------------------------

/// Push notification registration message.
///
/// Sent by clients to relays to register for push notifications. The relay
/// associates the push token with the DID and listed context routing IDs.
/// On new message arrival for a registered context, the relay sends an
/// opaque push notification to the registered token.
///
/// The signature covers `did || platform (1-byte tag) || token || contexts
/// (length-prefixed concatenation) || timestamp` using the canonical signed
/// structure format (§9.5.2).
///
/// Registrations are idempotent — re-registering with the same token is a
/// no-op. The relay replaces previous registrations for the same
/// DID + platform combination.
///
/// See spec §10.7.1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushRegistration {
    /// The registering identity.
    pub did: DID,
    /// Push service platform (APNS, FCM, or `WebPush`).
    pub platform: PushPlatform,
    /// Platform-specific push token (APNs device token, FCM registration
    /// token, or `WebPush` endpoint URL).
    pub token: String,
    /// Contexts for which to receive push notifications. Empty means all
    /// contexts on this relay.
    pub contexts: Vec<ContextId>,
    /// Registration timestamp (Unix seconds).
    pub timestamp: u64,
    /// Ed25519 signature by the DID's Active Signing Key (`#active`).
    #[serde(with = "serde_bytes")]
    pub signature: Ed25519Signature,
}

// ---------------------------------------------------------------------------
// PushDeregistration (§10.7.1)
// ---------------------------------------------------------------------------

/// Push notification deregistration message.
///
/// Sent by clients to explicitly remove their push registration for a
/// specific platform. The relay deletes the stored registration for the
/// DID + platform combination.
///
/// Implicit deregistration also occurs when the relay observes push
/// delivery failures — the relay MUST remove registrations after 3
/// consecutive delivery failures for the same token.
///
/// See spec §10.7.1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushDeregistration {
    /// The deregistering identity.
    pub did: DID,
    /// Push service platform to deregister from.
    pub platform: PushPlatform,
    /// Deregistration timestamp (Unix seconds).
    pub timestamp: u64,
    /// Ed25519 signature by the DID's Active Signing Key (`#active`).
    #[serde(with = "serde_bytes")]
    pub signature: Ed25519Signature,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn push_platform_tag_bytes() {
        assert_eq!(PushPlatform::Apns.tag_byte(), 0x01);
        assert_eq!(PushPlatform::Fcm.tag_byte(), 0x02);
        assert_eq!(PushPlatform::WebPush.tag_byte(), 0x03);
    }

    #[test]
    fn push_platform_display() {
        assert_eq!(PushPlatform::Apns.to_string(), "APNS");
        assert_eq!(PushPlatform::Fcm.to_string(), "FCM");
        assert_eq!(PushPlatform::WebPush.to_string(), "WebPush");
    }

    #[test]
    fn push_registration_serialization_roundtrip() {
        let reg = PushRegistration {
            did: DID::from("did:dht:zAlice"),
            platform: PushPlatform::Apns,
            token: "device-token-abc123".to_owned(),
            contexts: vec!["ctx-001".to_owned(), "ctx-002".to_owned()],
            timestamp: 1_700_000_000,
            signature: vec![0u8; 64],
        };
        let json = serde_json::to_string(&reg).unwrap();
        let deserialized: PushRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.did, DID::from("did:dht:zAlice"));
        assert_eq!(deserialized.platform, PushPlatform::Apns);
        assert_eq!(deserialized.token, "device-token-abc123");
        assert_eq!(deserialized.contexts.len(), 2);
        assert_eq!(deserialized.timestamp, 1_700_000_000);
    }

    #[test]
    fn push_registration_empty_contexts_means_all() {
        let reg = PushRegistration {
            did: DID::from("did:dht:zAlice"),
            platform: PushPlatform::Fcm,
            token: "fcm-token".to_owned(),
            contexts: Vec::new(),
            timestamp: 1_700_000_000,
            signature: vec![0u8; 64],
        };
        assert!(
            reg.contexts.is_empty(),
            "empty contexts means all contexts on this relay"
        );
    }

    #[test]
    fn push_deregistration_serialization_roundtrip() {
        let dereg = PushDeregistration {
            did: DID::from("did:dht:zAlice"),
            platform: PushPlatform::WebPush,
            timestamp: 1_700_000_000,
            signature: vec![0u8; 64],
        };
        let json = serde_json::to_string(&dereg).unwrap();
        let deserialized: PushDeregistration = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.did, DID::from("did:dht:zAlice"));
        assert_eq!(deserialized.platform, PushPlatform::WebPush);
        assert_eq!(deserialized.timestamp, 1_700_000_000);
    }

    #[test]
    fn push_platform_serialization_roundtrip() {
        for platform in [PushPlatform::Apns, PushPlatform::Fcm, PushPlatform::WebPush] {
            let json = serde_json::to_string(&platform).unwrap();
            let deserialized: PushPlatform = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, platform);
        }
    }
}
