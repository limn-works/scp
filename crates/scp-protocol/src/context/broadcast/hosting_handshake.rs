//! Broadcast hosting handshake saga signed types (spec §5.14.13).
//!
//! A **hosting handshake** is the agreement by which a separate **host context**
//! (A) undertakes to *relay* a broadcast context's (B) content to its own
//! members. It establishes state in two contexts — A's forwarding registry and
//! B's accepted-host snapshot — so it executes as a cross-context saga under
//! §5.15.4. This module defines the wire-level signed protocol types §5.15.4
//! leaves abstract for this use case:
//!
//! - [`BroadcastHostConfig`] — the per-host relay limits (`max_forward_rate_per_minute`,
//!   `max_subscribers`, `forwarding_policy`, `expires_at_ms`). The host's
//!   `requested_config` is its ask; B's `granted_config` is the authoritative,
//!   clamped result. JCS-serializable (RFC 8785); rides both signatures inside
//!   `VarBytes(jcs(config))`.
//! - [`BroadcastHostingRequest`] — the host representative's signed ask, signed
//!   by the Active Signing Key of `subscriber_did`. Carries an OPTIONAL `ucan`
//!   field (present iff B is gated), encoded with the §9.5.1 optional-field rule.
//! - [`BroadcastHostingGrant`] — B's broadcast-author-signed authorization. Its
//!   `subscriber_did`, `wrapping_pubkey`, and `nonce` echo the request, binding
//!   *who* hosting was granted to and *which* X25519 key the post-grant
//!   broadcast key is sealed under — closing the key-redirection vector.
//! - [`AcceptedHostSnapshotEntry`] — the durable B-side record persisted on
//!   Commit; it (not the re-presented grant) authorizes the host's post-grant
//!   §5.14.2 HPKE key pull. JCS-serializable.
//!
//! Both signature preimages use the §9.5.1 canonical hash construction
//! (domain-separated, field-enumerated, length-prefixed variable fields) — never
//! `SHA-256(prefix ‖ JCS(struct))` — keeping one signing discipline
//! protocol-wide. The wire body is JCS, but the bytes signed are the §9.5.1
//! field-enumerated construction.
//!
//! Domain separators (registered in §9.18.2), distinct from each other and from
//! `"SCP-BROADCAST-ENVELOPE-V1:"` / `"scp-broadcast-key-v1"` (§5.14.2, §5.14.5):
//! - `"SCP-BCAST-HOST-REQ-V1:"` — [`BroadcastHostingRequest`] signing.
//! - `"SCP-BCAST-HOST-GRANT-V1:"` — [`BroadcastHostingGrant`] signing.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::crypto::canonical::{CanonicalField, canonical_hash};

/// Domain separator for [`BroadcastHostingRequest`] signature preimages (§5.14.13, §9.18.2).
pub const BCAST_HOST_REQ_DOMAIN: &str = "SCP-BCAST-HOST-REQ-V1:";

/// Domain separator for [`BroadcastHostingGrant`] signature preimages (§5.14.13, §9.18.2).
pub const BCAST_HOST_GRANT_DOMAIN: &str = "SCP-BCAST-HOST-GRANT-V1:";

/// Default `max_forward_rate_per_minute` for a [`BroadcastHostConfig`] (§5.14.13).
pub const DEFAULT_MAX_FORWARD_RATE_PER_MINUTE: u32 = 600;
/// Inclusive permitted range for `max_forward_rate_per_minute` (§5.14.13): `[1, 6000]`.
pub const MAX_FORWARD_RATE_PER_MINUTE_RANGE: (u32, u32) = (1, 6000);

/// Default `max_subscribers` for a [`BroadcastHostConfig`] (§5.14.13).
pub const DEFAULT_MAX_SUBSCRIBERS: u32 = 10_000;
/// Inclusive permitted range for `max_subscribers` (§5.14.13): `[1, 1_000_000]`.
pub const MAX_SUBSCRIBERS_RANGE: (u32, u32) = (1, 1_000_000);

/// Errors produced while signing, verifying, or validating broadcast hosting
/// handshake types (§5.14.13).
///
/// Error codes use the `SCP-SAGA-` band (`13000-13999`, ADR-049 §3a;
/// see `.docs/standards/sdk-common.md`). The code is embedded in each message
/// so the `check-error-codes.sh` gate can enumerate and range-check it.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BroadcastHostingError {
    /// A canonical-hash field exceeded the `u32::MAX` length-prefix ceiling, or
    /// the embedded `BroadcastHostConfig` could not be JCS-serialized.
    ///
    /// The length-prefix case is unreachable in practice: protocol messages are
    /// bounded to 256 KB by the envelope layer (§9.10.3). Present to eliminate a
    /// panic path.
    #[error("SCP-SAGA-13003: canonical preimage construction failed: {0}")]
    PreimageConstruction(String),

    /// The Ed25519 signature did not verify against the reconstructed preimage.
    #[error("SCP-SAGA-13004: Ed25519 signature verification failed: {0}")]
    SignatureInvalid(String),

    /// A [`BroadcastHostConfig`] field violated a hard validity invariant that
    /// clamping cannot repair — concretely, `expires_at_ms == 0` (§5.14.13:
    /// "`expires_at_ms` MUST be > 0 — no perpetual grants"). Out-of-range
    /// `max_forward_rate_per_minute` / `max_subscribers` values are *clamped*
    /// (not errors); only a zero `expires_at_ms` is rejected here.
    #[error("SCP-SAGA-13005: broadcast host config invalid: {0}")]
    ConfigInvalid(String),
}

/// The forwarding policy a host applies when relaying B's signed
/// `BroadcastEnvelope` (§5.14.13, *`forwarding_policy` semantics*).
///
/// Neither variant may remove or alter any field of the inner signed
/// `BroadcastEnvelope` (§5.14.5) — `author_did`, `sequence`, `provenance`, and
/// the author `signature` MUST survive forwarding intact (provenance everywhere).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ForwardingPolicy {
    /// Forward the signed `BroadcastEnvelope` unchanged.
    Verbatim,
    /// Strip ONLY host-local outer-envelope routing/recipient-hint fields
    /// (§9.10.2), which the forwarding host re-derives for its own members
    /// anyway (`routing_id = SHA-256(context_id)`, §5.14.6). The inner signed
    /// `BroadcastEnvelope` is never touched.
    RoutingStripped,
}

impl Default for ForwardingPolicy {
    /// The §5.14.13 default is `verbatim`.
    fn default() -> Self {
        Self::Verbatim
    }
}

/// Per-host relay limits for a broadcast hosting grant (§5.14.13, *`BroadcastHostConfig`*).
///
/// JCS-serializable (RFC 8785). The host's [`BroadcastHostingRequest::requested_config`]
/// is its ask; B's [`BroadcastHostingGrant::granted_config`] is the authoritative
/// result of [`BroadcastHostConfig::clamp`]. The config rides both signatures
/// inside `VarBytes(jcs(config))`, where JCS enforces integer-exactness.
///
/// # Integer encoding (normative, §5.14.13)
///
/// `max_forward_rate_per_minute` and `max_subscribers` are `u32`;
/// `expires_at_ms` is `u64`. Each is an exact unsigned integer — JCS serializes
/// it as a JSON integer (never an IEEE-754 double), and every value is well
/// below `2^53` so it round-trips losslessly per RFC 8785.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BroadcastHostConfig {
    /// Maximum messages per minute the host may forward (default 600, range `[1, 6000]`).
    pub max_forward_rate_per_minute: u32,
    /// Maximum subscribers the host may relay to (default 10000, range `[1, 1_000_000]`).
    pub max_subscribers: u32,
    /// How the host forwards B's signed envelopes (default `verbatim`).
    pub forwarding_policy: ForwardingPolicy,
    /// Grant expiry, Unix milliseconds. MUST be `> 0` — no perpetual grants.
    ///
    /// The static `[1, 6000]` / `[1, 1_000_000]` ranges of the other fields are
    /// applied by [`BroadcastHostConfig::clamp`]. The *lifetime ceiling* on
    /// `expires_at_ms` (`min(requested, granted_at_ms + max_grant_lifetime_ms)`,
    /// §5.14.13) depends on B's Prepare-B `granted_at_ms` and aggregate-cap
    /// `max_grant_lifetime_ms`, which are not config fields, so that clamp is a
    /// B-side Prepare-B decision (a later 2C runtime step), not a property of
    /// this leaf type. This type only enforces the `> 0` floor.
    pub expires_at_ms: u64,
}

impl BroadcastHostConfig {
    /// Construct a config with the §5.14.13 defaults for the range fields.
    ///
    /// `max_forward_rate_per_minute = 600`, `max_subscribers = 10000`,
    /// `forwarding_policy = verbatim`. `expires_at_ms` has no default (a grant is
    /// always explicitly time-bounded), so it is the sole argument.
    ///
    /// # Errors
    ///
    /// Returns [`BroadcastHostingError::ConfigInvalid`] if `expires_at_ms == 0`
    /// (§5.14.13: perpetual grants are disallowed).
    pub fn with_defaults(expires_at_ms: u64) -> Result<Self, BroadcastHostingError> {
        let config = Self {
            max_forward_rate_per_minute: DEFAULT_MAX_FORWARD_RATE_PER_MINUTE,
            max_subscribers: DEFAULT_MAX_SUBSCRIBERS,
            forwarding_policy: ForwardingPolicy::default(),
            expires_at_ms,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validate the hard invariants clamping cannot repair (§5.14.13).
    ///
    /// The only such invariant is `expires_at_ms > 0`. Out-of-range
    /// `max_forward_rate_per_minute` / `max_subscribers` values are *clamped* by
    /// [`Self::clamp`], not rejected.
    ///
    /// # Errors
    ///
    /// Returns [`BroadcastHostingError::ConfigInvalid`] if `expires_at_ms == 0`.
    pub fn validate(&self) -> Result<(), BroadcastHostingError> {
        if self.expires_at_ms == 0 {
            return Err(BroadcastHostingError::ConfigInvalid(
                "expires_at_ms must be > 0 (no perpetual grants)".to_owned(),
            ));
        }
        Ok(())
    }

    /// Clamp each range field of a *requested* config into its B-authoritative
    /// permitted range, producing the *granted* config (§5.14.13).
    ///
    /// `max_forward_rate_per_minute` is clamped into `[1, 6000]` and
    /// `max_subscribers` into `[1, 1_000_000]`. `forwarding_policy` is already a
    /// valid enum and is carried through unchanged. `expires_at_ms` is carried
    /// through unchanged here: its static invariant is the `> 0` floor (validated
    /// separately), and its *upper* lifetime ceiling
    /// (`min(requested, granted_at_ms + max_grant_lifetime_ms)`, §5.14.13)
    /// requires B's Prepare-B `granted_at_ms` and aggregate `max_grant_lifetime_ms`,
    /// which are applied by B at Prepare-B — not by this leaf clamp.
    ///
    /// This is total and infallible: clamping cannot produce an out-of-range
    /// value. (`expires_at_ms == 0` is a *validity* error surfaced by
    /// [`Self::validate`], not a clamp target — `0` has no in-range value to
    /// clamp toward without inventing one.)
    #[must_use]
    pub fn clamp(requested: &Self) -> Self {
        let (rate_lo, rate_hi) = MAX_FORWARD_RATE_PER_MINUTE_RANGE;
        let (sub_lo, sub_hi) = MAX_SUBSCRIBERS_RANGE;
        Self {
            max_forward_rate_per_minute: requested
                .max_forward_rate_per_minute
                .clamp(rate_lo, rate_hi),
            max_subscribers: requested.max_subscribers.clamp(sub_lo, sub_hi),
            forwarding_policy: requested.forwarding_policy,
            expires_at_ms: requested.expires_at_ms,
        }
    }

    /// The JCS (RFC 8785) canonical serialization of this config — the exact
    /// bytes that ride the `VarBytes(jcs(config))` term of both handshake
    /// signature preimages.
    ///
    /// # Errors
    ///
    /// Returns [`BroadcastHostingError::PreimageConstruction`] if JCS
    /// serialization fails (unreachable for this fixed, simple struct).
    pub fn to_jcs(&self) -> Result<Vec<u8>, BroadcastHostingError> {
        crate::jcs::to_vec(self).map_err(BroadcastHostingError::PreimageConstruction)
    }
}

/// The host representative's signed hosting ask (§5.14.13, *Handshake messages*).
///
/// Signed by the **Active Signing Key of `subscriber_did`** — the host
/// representative holding `messages:read` for B. B binds the signature to
/// `subscriber_did`, not to an unspecified "requester": the request is valid only
/// if signed by the DID it claims (see [`Self::verify`]).
///
/// # Field semantics (normative, §5.14.13)
///
/// - `host_context_id` / `broadcast_context_id` — ALWAYS the raw 32-byte
///   context-id digest (`Fixed32` in the preimage, 64-hex on the wire). For a
///   standing-context participant this is the raw `derived_context_id` *before*
///   the `"standing-"` prefix (§5.15.8), never the prefixed display string.
/// - `wrapping_pubkey` — the X25519 recipient key the post-grant broadcast key
///   is sealed under; echoed into the grant and bound into the author signature.
/// - `requested_config` — the host's ask; B clamps it to `granted_config`.
/// - `ucan` — present iff B is a *gated* broadcast context (the `messages:read`
///   token the host already holds as a §5.14.3 subscriber); absent for an *open*
///   context. Encoded with the §9.5.1 optional-field rule (see [`Self::signing_preimage`]).
/// - `nonce` — 16-byte freshness/anti-replay token (the grant echoes it).
/// - `timestamp_ms` — the request send time, freshness-checked at Prepare-B.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BroadcastHostingRequest {
    /// Raw 32-byte digest of the host (relaying) context.
    #[serde(with = "crate::serde_util::serde_hash_32")]
    pub host_context_id: [u8; 32],
    /// Raw 32-byte digest of the broadcast (hosted) context.
    #[serde(with = "crate::serde_util::serde_hash_32")]
    pub broadcast_context_id: [u8; 32],
    /// The host representative DID holding `messages:read` for B; the request's signer.
    pub subscriber_did: String,
    /// X25519 recipient key the post-grant broadcast key is sealed under.
    #[serde(with = "crate::serde_util::serde_pubkey_32")]
    pub wrapping_pubkey: [u8; 32],
    /// The host's requested relay limits (B clamps these to the grant).
    pub requested_config: BroadcastHostConfig,
    /// `messages:read` UCAN — present iff B is a gated context, absent if open.
    pub ucan: Option<String>,
    /// 16-byte freshness/anti-replay nonce (the grant echoes this value).
    #[serde(with = "crate::serde_util::serde_nonce_16")]
    pub nonce: [u8; 16],
    /// Request send time in Unix milliseconds (freshness-checked at Prepare-B).
    pub timestamp_ms: u64,
    /// The requester's Ed25519 signature over [`Self::signing_preimage`].
    #[serde(with = "crate::serde_util::serde_signature_64")]
    pub signature: [u8; 64],
}

/// The unsigned field set for [`BroadcastHostingRequest::sign`], named so the
/// call site cannot transpose same-typed arguments.
///
/// `host_context_id` / `broadcast_context_id` are two adjacent `[u8; 32]` ids; a
/// positional swap would sign a self-consistent-but-wrong request. Naming every
/// field at the call site makes a swap a compile-visible field-name error. Per
/// the Agent-first API tenet: one flat named-field object, no builder, no
/// ordering to track. The requester's Active Signing Key stays a SEPARATE
/// parameter of [`BroadcastHostingRequest::sign`] — it is signing capability
/// material, not a request field.
pub struct BroadcastHostingRequestFields {
    /// Raw 32-byte digest of the host (relaying) context.
    pub host_context_id: [u8; 32],
    /// Raw 32-byte digest of the broadcast (hosted) context.
    pub broadcast_context_id: [u8; 32],
    /// The host representative DID holding `messages:read` for B; the request's signer.
    pub subscriber_did: String,
    /// X25519 recipient key the post-grant broadcast key is sealed under.
    pub wrapping_pubkey: [u8; 32],
    /// The host's requested relay limits (B clamps these to the grant).
    pub requested_config: BroadcastHostConfig,
    /// `messages:read` UCAN — present iff B is a gated context, absent if open.
    pub ucan: Option<String>,
    /// 16-byte freshness/anti-replay nonce (the grant echoes this value).
    pub nonce: [u8; 16],
    /// Request send time in Unix milliseconds (freshness-checked at Prepare-B).
    pub timestamp_ms: u64,
}

impl BroadcastHostingRequest {
    /// Build the §9.5.1 canonical signing preimage for this request.
    ///
    /// Field order is **normative** (§5.14.13, *Handshake messages*):
    /// `Fixed32(host_context_id)`, `Fixed32(broadcast_context_id)`,
    /// `VarBytes(subscriber_did)`, `Fixed32(wrapping_pubkey)`,
    /// `VarBytes(jcs(requested_config))`, `OptVarBytes(ucan)`,
    /// `RawBytes16(nonce)`, `U64(timestamp_ms)`.
    ///
    /// `OptVarBytes(ucan)` follows the §9.5.1 optional-field rule exactly:
    /// **present** ⇒ `VarBytes` (4-byte BE length prefix + raw UCAN bytes);
    /// **absent** ⇒ the 32-byte sentinel `SHA-256(0x00)` (the
    /// [`CanonicalField::Absent`] arm). An absent value is NOT a zero-length
    /// `VarBytes` (`00 00 00 00`), so a gated and an ungated request with
    /// otherwise-identical fields never collide in the preimage.
    ///
    /// # Errors
    ///
    /// Returns [`BroadcastHostingError::PreimageConstruction`] if the embedded
    /// config cannot be JCS-serialized, or a variable-length field exceeds
    /// `u32::MAX` bytes (unreachable in practice; §9.10.3 bounds messages to
    /// 256 KB).
    pub fn signing_preimage(&self) -> Result<[u8; 32], BroadcastHostingError> {
        let config_jcs = self.requested_config.to_jcs()?;
        let ucan_field = self.ucan.as_deref().map_or(CanonicalField::Absent, |ucan| {
            CanonicalField::VarBytes(ucan.as_bytes())
        });
        canonical_hash(
            BCAST_HOST_REQ_DOMAIN,
            &[
                CanonicalField::Fixed32(&self.host_context_id),
                CanonicalField::Fixed32(&self.broadcast_context_id),
                CanonicalField::VarBytes(self.subscriber_did.as_bytes()),
                CanonicalField::Fixed32(&self.wrapping_pubkey),
                CanonicalField::VarBytes(&config_jcs),
                ucan_field,
                CanonicalField::RawBytes(&self.nonce),
                CanonicalField::U64(self.timestamp_ms),
            ],
        )
        .map_err(|e| BroadcastHostingError::PreimageConstruction(e.to_string()))
    }

    /// Construct and sign a [`BroadcastHostingRequest`] with the requester's
    /// Active Signing Key.
    ///
    /// # Errors
    ///
    /// - [`BroadcastHostingError::ConfigInvalid`] if `requested_config` has
    ///   `expires_at_ms == 0` (§5.14.13: no perpetual grants).
    /// - [`BroadcastHostingError::PreimageConstruction`] if the preimage cannot
    ///   be built (unreachable in practice).
    pub fn sign(
        requester_signing_key: &SigningKey,
        fields: BroadcastHostingRequestFields,
    ) -> Result<Self, BroadcastHostingError> {
        let BroadcastHostingRequestFields {
            host_context_id,
            broadcast_context_id,
            subscriber_did,
            wrapping_pubkey,
            requested_config,
            ucan,
            nonce,
            timestamp_ms,
        } = fields;
        requested_config.validate()?;
        let mut request = Self {
            host_context_id,
            broadcast_context_id,
            subscriber_did,
            wrapping_pubkey,
            requested_config,
            ucan,
            nonce,
            timestamp_ms,
            signature: [0u8; 64],
        };
        let preimage = request.signing_preimage()?;
        request.signature = sign_prehashed_preimage(requester_signing_key, &preimage);
        Ok(request)
    }

    /// Verify a hosting request against the **Active Signing Key of the DID it
    /// claims** (`subscriber_did`).
    ///
    /// **Signer authorization (normative, §5.14.13).** The caller MUST pass the
    /// Active Signing Key resolved for `subscriber_did` via DID resolution. The
    /// request is valid only if signed by the DID it names; this function does
    /// not trust the request to name its own authorizing key. By requiring the
    /// resolved key as an input, signature validity here is equivalent to
    /// "signed by the Active Signing Key of `subscriber_did`".
    ///
    /// # Errors
    ///
    /// - [`BroadcastHostingError::PreimageConstruction`] if the preimage cannot
    ///   be built (unreachable in practice).
    /// - [`BroadcastHostingError::SignatureInvalid`] if the signature does not
    ///   verify against the reconstructed preimage and the supplied key.
    pub fn verify(
        &self,
        authorized_subscriber_signing_key: &VerifyingKey,
    ) -> Result<(), BroadcastHostingError> {
        let preimage = self.signing_preimage()?;
        let signature = Signature::from_bytes(&self.signature);
        authorized_subscriber_signing_key
            .verify_strict(&preimage, &signature)
            .map_err(|e| BroadcastHostingError::SignatureInvalid(e.to_string()))
    }
}

/// B's broadcast-author-signed hosting authorization (§5.14.13, *Handshake messages*).
///
/// Signed by the **broadcast author's signing key**. `subscriber_did`,
/// `wrapping_pubkey`, and `nonce` echo the [`BroadcastHostingRequest`]: the grant
/// non-repudiably commits *who* hosting was granted to and *which* X25519 key the
/// post-grant broadcast key is sealed under (closing the key-redirection vector
/// and restoring amplification-accountability non-repudiation).
///
/// The grant's `nonce` is **never independently drawn** — it always echoes the
/// request's, so the grant is not separately nonce-dedup-checked (§5.14.13,
/// *Freshness*). The broadcast key is never in the grant; it is delivered
/// post-grant via the §5.14.2 HPKE pull, gated on the durable
/// [`AcceptedHostSnapshotEntry`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BroadcastHostingGrant {
    /// Raw 32-byte digest of the host (relaying) context.
    #[serde(with = "crate::serde_util::serde_hash_32")]
    pub host_context_id: [u8; 32],
    /// Raw 32-byte digest of the broadcast (hosted) context.
    #[serde(with = "crate::serde_util::serde_hash_32")]
    pub broadcast_context_id: [u8; 32],
    /// The host representative DID hosting was granted to (echoes the request).
    pub subscriber_did: String,
    /// X25519 recipient key the broadcast key is sealed under (echoes the request).
    #[serde(with = "crate::serde_util::serde_pubkey_32")]
    pub wrapping_pubkey: [u8; 32],
    /// The authoritative, clamped relay limits B grants (the snapshot persists these).
    pub granted_config: BroadcastHostConfig,
    /// The broadcast key epoch captured at Prepare-B and bound into the grant.
    pub current_key_epoch: u64,
    /// 16-byte nonce — echoes the request's `nonce` (never independently drawn).
    #[serde(with = "crate::serde_util::serde_nonce_16")]
    pub nonce: [u8; 16],
    /// Grant signing time in Unix milliseconds (the Prepare-B instant).
    pub timestamp_ms: u64,
    /// The broadcast author's Ed25519 signature over [`Self::signing_preimage`].
    #[serde(with = "crate::serde_util::serde_signature_64")]
    pub signature: [u8; 64],
}

/// The unsigned field set for [`BroadcastHostingGrant::sign`], named so the call
/// site cannot transpose same-typed arguments.
///
/// `host_context_id` / `broadcast_context_id` are two adjacent `[u8; 32]` ids; a
/// positional swap would sign a self-consistent-but-wrong grant. Naming every
/// field at the call site makes a swap a compile-visible field-name error,
/// symmetric with [`BroadcastHostingRequestFields`]. The broadcast author's
/// signing key stays a SEPARATE parameter of [`BroadcastHostingGrant::sign`] —
/// it is signing capability material, not a grant field.
pub struct BroadcastHostingGrantFields {
    /// Raw 32-byte digest of the host (relaying) context.
    pub host_context_id: [u8; 32],
    /// Raw 32-byte digest of the broadcast (hosted) context.
    pub broadcast_context_id: [u8; 32],
    /// The host representative DID hosting was granted to (echoes the request).
    pub subscriber_did: String,
    /// X25519 recipient key the broadcast key is sealed under (echoes the request).
    pub wrapping_pubkey: [u8; 32],
    /// The authoritative, clamped relay limits B grants (the snapshot persists these).
    pub granted_config: BroadcastHostConfig,
    /// The broadcast key epoch captured at Prepare-B and bound into the grant.
    pub current_key_epoch: u64,
    /// 16-byte nonce — echoes the request's `nonce` (never independently drawn).
    pub nonce: [u8; 16],
    /// Grant signing time in Unix milliseconds (the Prepare-B instant).
    pub timestamp_ms: u64,
}

impl BroadcastHostingGrant {
    /// Build the §9.5.1 canonical signing preimage for this grant.
    ///
    /// Field order is **normative** (§5.14.13, *Handshake messages*):
    /// `Fixed32(host_context_id)`, `Fixed32(broadcast_context_id)`,
    /// `VarBytes(subscriber_did)`, `Fixed32(wrapping_pubkey)`,
    /// `VarBytes(jcs(granted_config))`, `U64(current_key_epoch)`,
    /// `RawBytes16(nonce)`, `U64(timestamp_ms)`.
    ///
    /// The grant has no optional `ucan` term (only the request carries one).
    ///
    /// # Errors
    ///
    /// Returns [`BroadcastHostingError::PreimageConstruction`] if the embedded
    /// config cannot be JCS-serialized, or a variable-length field exceeds
    /// `u32::MAX` bytes (unreachable in practice; §9.10.3).
    pub fn signing_preimage(&self) -> Result<[u8; 32], BroadcastHostingError> {
        let config_jcs = self.granted_config.to_jcs()?;
        canonical_hash(
            BCAST_HOST_GRANT_DOMAIN,
            &[
                CanonicalField::Fixed32(&self.host_context_id),
                CanonicalField::Fixed32(&self.broadcast_context_id),
                CanonicalField::VarBytes(self.subscriber_did.as_bytes()),
                CanonicalField::Fixed32(&self.wrapping_pubkey),
                CanonicalField::VarBytes(&config_jcs),
                CanonicalField::U64(self.current_key_epoch),
                CanonicalField::RawBytes(&self.nonce),
                CanonicalField::U64(self.timestamp_ms),
            ],
        )
        .map_err(|e| BroadcastHostingError::PreimageConstruction(e.to_string()))
    }

    /// Construct and sign a [`BroadcastHostingGrant`] with the broadcast author's
    /// signing key.
    ///
    /// `granted_config` MUST already be the clamped, authoritative config
    /// ([`BroadcastHostConfig::clamp`]); this is the exact config the snapshot
    /// persists and the grant is signed over.
    ///
    /// # Errors
    ///
    /// - [`BroadcastHostingError::ConfigInvalid`] if `granted_config` has
    ///   `expires_at_ms == 0` (§5.14.13: no perpetual grants).
    /// - [`BroadcastHostingError::PreimageConstruction`] if the preimage cannot
    ///   be built (unreachable in practice).
    pub fn sign(
        broadcast_author_signing_key: &SigningKey,
        fields: BroadcastHostingGrantFields,
    ) -> Result<Self, BroadcastHostingError> {
        let BroadcastHostingGrantFields {
            host_context_id,
            broadcast_context_id,
            subscriber_did,
            wrapping_pubkey,
            granted_config,
            current_key_epoch,
            nonce,
            timestamp_ms,
        } = fields;
        granted_config.validate()?;
        let mut grant = Self {
            host_context_id,
            broadcast_context_id,
            subscriber_did,
            wrapping_pubkey,
            granted_config,
            current_key_epoch,
            nonce,
            timestamp_ms,
            signature: [0u8; 64],
        };
        let preimage = grant.signing_preimage()?;
        grant.signature = sign_prehashed_preimage(broadcast_author_signing_key, &preimage);
        Ok(grant)
    }

    /// Verify a hosting grant against the **broadcast author's authorized signing
    /// key**.
    ///
    /// As with [`BroadcastHostingRequest::verify`], the caller MUST resolve and
    /// pass the signing key authorized for the broadcast author of
    /// `broadcast_context_id`; this function does not trust the grant to name its
    /// own authorizing key.
    ///
    /// # Errors
    ///
    /// - [`BroadcastHostingError::PreimageConstruction`] if the preimage cannot
    ///   be built (unreachable in practice).
    /// - [`BroadcastHostingError::SignatureInvalid`] if the signature does not
    ///   verify against the reconstructed preimage and the supplied key.
    pub fn verify(
        &self,
        authorized_author_signing_key: &VerifyingKey,
    ) -> Result<(), BroadcastHostingError> {
        let preimage = self.signing_preimage()?;
        let signature = Signature::from_bytes(&self.signature);
        authorized_author_signing_key
            .verify_strict(&preimage, &signature)
            .map_err(|e| BroadcastHostingError::SignatureInvalid(e.to_string()))
    }
}

/// The durable B-side accepted-host record persisted on Commit (§5.14.13,
/// *`AcceptedHostSnapshotEntry`*).
///
/// This — NOT a re-presented [`BroadcastHostingGrant`] — authorizes the host's
/// subsequent §5.14.2 HPKE key pull. It is part of B's broadcast-context state
/// (§5.14.7), persisted on the §5.15.3 sync-persisted path together with the
/// `MemberJoined` append, so it survives a crash immediately after Commit.
///
/// JCS-serializable (RFC 8785). The `saga_id` anchor makes a replayed Commit a
/// no-op; B holds **at most one live entry per `(host_context_id, subscriber_did)`
/// pair** (the at-most-one-live invariant), a successful re-handshake superseding
/// the prior entry (writing a fresh `saga_id`) rather than coexisting with it.
///
/// The persisted `wrapping_pubkey` is the grant-committed recipient key: the
/// post-grant pull's recipient key is checked against this durable record and a
/// differing key is refused (*Sealing binds to the grant-committed key*).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedHostSnapshotEntry {
    /// Raw 32-byte digest of the host (relaying) context — the snapshot lookup key.
    #[serde(with = "crate::serde_util::serde_hash_32")]
    pub host_context_id: [u8; 32],
    /// The host representative DID — the other half of the snapshot lookup key.
    ///
    /// Compared in its canonical DID string form as produced by DID resolution
    /// (§5.14.13), so two encodings of the same DID cannot key to two entries.
    pub subscriber_did: String,
    /// The grant-committed X25519 recipient key; the post-grant pull MUST present
    /// this exact key or be refused.
    #[serde(with = "crate::serde_util::serde_pubkey_32")]
    pub wrapping_pubkey: [u8; 32],
    /// The authoritative, clamped config the grant was signed over and B persists.
    pub granted_config: BroadcastHostConfig,
    /// Wall-clock ms captured at Prepare-B and bound into the snapshot at Commit.
    pub granted_at_ms: u64,
    /// The broadcast key epoch captured at Prepare-B (matches the grant's `current_key_epoch`).
    pub key_epoch_at_grant: u64,
    /// The supervisor-minted `UUIDv4` saga id — the internal Commit replay anchor.
    ///
    /// Never presented by the host on a pull (it rides no handshake wire body); a
    /// re-handshake supersedes the entry by writing a fresh `saga_id`, so a
    /// replayed Commit of the old saga is a no-op against the live entry.
    pub saga_id: String,
}

impl AcceptedHostSnapshotEntry {
    /// The JCS (RFC 8785) canonical serialization of this snapshot entry.
    ///
    /// # Errors
    ///
    /// Returns [`BroadcastHostingError::PreimageConstruction`] if JCS
    /// serialization fails (unreachable for this fixed struct).
    pub fn to_jcs(&self) -> Result<Vec<u8>, BroadcastHostingError> {
        crate::jcs::to_vec(self).map_err(BroadcastHostingError::PreimageConstruction)
    }
}

/// Sign a 32-byte §9.5.1 canonical preimage with Ed25519.
///
/// The canonical construction already hashes the field set into a 32-byte digest
/// (§9.5.1); Ed25519 then signs that digest as its message — the same pattern as
/// the cross-context saga types ([`crate::context::tools::cross_context_saga`])
/// and the broadcast envelope. Verification mirrors this with
/// `verify_strict(&preimage, &sig)`.
fn sign_prehashed_preimage(signing_key: &SigningKey, preimage: &[u8; 32]) -> [u8; 64] {
    use ed25519_dalek::Signer;
    signing_key.sign(preimage).to_bytes()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    fn test_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn sample_config() -> BroadcastHostConfig {
        BroadcastHostConfig {
            max_forward_rate_per_minute: 600,
            max_subscribers: 10_000,
            forwarding_policy: ForwardingPolicy::Verbatim,
            expires_at_ms: 1_709_654_400_000,
        }
    }

    /// A fully-populated *gated* request (carries a UCAN) for round-trip tests.
    fn gated_request(sk: &SigningKey) -> BroadcastHostingRequest {
        BroadcastHostingRequest::sign(
            sk,
            BroadcastHostingRequestFields {
                host_context_id: [0x11; 32],
                broadcast_context_id: [0x22; 32],
                subscriber_did: "did:example:host-rep".to_owned(),
                wrapping_pubkey: [0x44; 32],
                requested_config: sample_config(),
                ucan: Some("eyJhbGciOiJFZERTQSJ9.messages-read".to_owned()),
                nonce: [0x55; 16],
                timestamp_ms: 1_709_654_400_000,
            },
        )
        .expect("sign gated request")
    }

    fn sample_grant(sk: &SigningKey) -> BroadcastHostingGrant {
        BroadcastHostingGrant::sign(
            sk,
            BroadcastHostingGrantFields {
                host_context_id: [0x11; 32],
                broadcast_context_id: [0x22; 32],
                subscriber_did: "did:example:host-rep".to_owned(),
                wrapping_pubkey: [0x44; 32],
                granted_config: sample_config(),
                current_key_epoch: 7,
                nonce: [0x55; 16],
                timestamp_ms: 1_709_654_400_000,
            },
        )
        .expect("sign grant")
    }

    // -----------------------------------------------------------------------
    // Request sign / verify
    // -----------------------------------------------------------------------

    #[test]
    fn request_round_trip_sign_verify() {
        let sk = test_signing_key(0xAA);
        let request = gated_request(&sk);
        request
            .verify(&sk.verifying_key())
            .expect("valid request must verify against the authorized subscriber key");
    }

    #[test]
    fn request_wrong_signer_fails() {
        let sk = test_signing_key(0xAA);
        let request = gated_request(&sk);
        let wrong = test_signing_key(0xBB).verifying_key();
        assert!(
            request.verify(&wrong).is_err(),
            "a valid signature by a non-claimed DID's key must fail verify"
        );
    }

    #[test]
    fn request_tamper_each_covered_field_fails_verify() {
        let sk = test_signing_key(0xAA);
        let vk = sk.verifying_key();
        let base = gated_request(&sk);

        let mut t = base.clone();
        t.host_context_id[0] ^= 0xFF;
        assert!(t.verify(&vk).is_err());

        let mut t = base.clone();
        t.broadcast_context_id[0] ^= 0xFF;
        assert!(t.verify(&vk).is_err());

        let mut t = base.clone();
        t.subscriber_did.push('x');
        assert!(t.verify(&vk).is_err());

        let mut t = base.clone();
        t.wrapping_pubkey[0] ^= 0xFF;
        assert!(t.verify(&vk).is_err());

        // requested_config (changes embedded jcs(config))
        let mut t = base.clone();
        t.requested_config.max_subscribers = 9_999;
        assert!(t.verify(&vk).is_err());

        // ucan present → different present value
        let mut t = base.clone();
        t.ucan = Some("a-different-ucan".to_owned());
        assert!(t.verify(&vk).is_err());

        // ucan present → absent (gated vs ungated)
        let mut t = base.clone();
        t.ucan = None;
        assert!(t.verify(&vk).is_err());

        let mut t = base.clone();
        t.nonce[0] ^= 0xFF;
        assert!(t.verify(&vk).is_err());

        let mut t = base;
        t.timestamp_ms += 1;
        assert!(t.verify(&vk).is_err());
    }

    #[test]
    fn request_preimage_is_byte_exact_gated() {
        let sk = test_signing_key(0xAA);
        let request = gated_request(&sk);

        let config_jcs = sample_config().to_jcs().expect("jcs");
        let ucan = b"eyJhbGciOiJFZERTQSJ9.messages-read";

        let mut h = Sha256::new();
        h.update(b"SCP-BCAST-HOST-REQ-V1:");
        h.update([0x11; 32]); // Fixed32(host_context_id)
        h.update([0x22; 32]); // Fixed32(broadcast_context_id)
        h.update(20u32.to_be_bytes()); // len("did:example:host-rep")
        h.update(b"did:example:host-rep");
        h.update([0x44; 32]); // Fixed32(wrapping_pubkey)
        h.update(u32::try_from(config_jcs.len()).unwrap().to_be_bytes());
        h.update(&config_jcs); // VarBytes(jcs(requested_config))
        h.update(u32::try_from(ucan.len()).unwrap().to_be_bytes());
        h.update(ucan); // OptVarBytes present → VarBytes
        h.update([0x55; 16]); // RawBytes16(nonce)
        h.update(1_709_654_400_000u64.to_be_bytes()); // U64(timestamp_ms)
        let expected: [u8; 32] = h.finalize().into();

        assert_eq!(
            request.signing_preimage().expect("preimage"),
            expected,
            "request preimage must match the normative §5.14.13 field order"
        );
    }

    // -----------------------------------------------------------------------
    // OptVarBytes(ucan): gated-vs-ungated non-collision (present-zero-length ≠ absent)
    // -----------------------------------------------------------------------

    #[test]
    fn ucan_absent_differs_from_present_empty() {
        let sk = test_signing_key(0xAA);
        let common = |ucan: Option<String>| BroadcastHostingRequestFields {
            host_context_id: [0x11; 32],
            broadcast_context_id: [0x22; 32],
            subscriber_did: "did:example:host-rep".to_owned(),
            wrapping_pubkey: [0x44; 32],
            requested_config: sample_config(),
            ucan,
            nonce: [0x55; 16],
            timestamp_ms: 1_709_654_400_000,
        };

        let absent = BroadcastHostingRequest::sign(&sk, common(None)).expect("absent");
        let present_empty =
            BroadcastHostingRequest::sign(&sk, common(Some(String::new()))).expect("present empty");
        let present_nonempty =
            BroadcastHostingRequest::sign(&sk, common(Some("x".to_owned()))).expect("present x");

        let p_absent = absent.signing_preimage().expect("absent preimage");
        let p_empty = present_empty.signing_preimage().expect("empty preimage");
        let p_x = present_nonempty.signing_preimage().expect("x preimage");

        // Absent (SHA-256(0x00) sentinel) must differ from a zero-length present
        // VarBytes (00 00 00 00) — the core §9.5.1 optional-field invariant.
        assert_ne!(
            p_absent, p_empty,
            "absent ucan must not collide with present zero-length ucan"
        );
        assert_ne!(p_absent, p_x);
        assert_ne!(p_empty, p_x);
    }

    // -----------------------------------------------------------------------
    // Grant sign / verify
    // -----------------------------------------------------------------------

    #[test]
    fn grant_round_trip_sign_verify() {
        let sk = test_signing_key(0xCC);
        let grant = sample_grant(&sk);
        grant
            .verify(&sk.verifying_key())
            .expect("valid grant must verify against the authorized author key");
    }

    #[test]
    fn grant_wrong_signer_fails() {
        let sk = test_signing_key(0xCC);
        let grant = sample_grant(&sk);
        let wrong = test_signing_key(0xDD).verifying_key();
        assert!(grant.verify(&wrong).is_err());
    }

    #[test]
    fn grant_tamper_each_covered_field_fails_verify() {
        let sk = test_signing_key(0xCC);
        let vk = sk.verifying_key();
        let base = sample_grant(&sk);

        let mut t = base.clone();
        t.host_context_id[0] ^= 0xFF;
        assert!(t.verify(&vk).is_err());

        let mut t = base.clone();
        t.broadcast_context_id[0] ^= 0xFF;
        assert!(t.verify(&vk).is_err());

        let mut t = base.clone();
        t.subscriber_did.push('x');
        assert!(t.verify(&vk).is_err());

        let mut t = base.clone();
        t.wrapping_pubkey[0] ^= 0xFF;
        assert!(t.verify(&vk).is_err());

        let mut t = base.clone();
        t.granted_config.max_forward_rate_per_minute = 599;
        assert!(t.verify(&vk).is_err());

        let mut t = base.clone();
        t.current_key_epoch += 1;
        assert!(t.verify(&vk).is_err());

        let mut t = base.clone();
        t.nonce[0] ^= 0xFF;
        assert!(t.verify(&vk).is_err());

        let mut t = base;
        t.timestamp_ms += 1;
        assert!(t.verify(&vk).is_err());
    }

    #[test]
    fn grant_preimage_is_byte_exact() {
        let sk = test_signing_key(0xCC);
        let grant = sample_grant(&sk);
        let config_jcs = sample_config().to_jcs().expect("jcs");

        let mut h = Sha256::new();
        h.update(b"SCP-BCAST-HOST-GRANT-V1:");
        h.update([0x11; 32]);
        h.update([0x22; 32]);
        h.update(20u32.to_be_bytes());
        h.update(b"did:example:host-rep");
        h.update([0x44; 32]);
        h.update(u32::try_from(config_jcs.len()).unwrap().to_be_bytes());
        h.update(&config_jcs);
        h.update(7u64.to_be_bytes()); // U64(current_key_epoch)
        h.update([0x55; 16]);
        h.update(1_709_654_400_000u64.to_be_bytes());
        let expected: [u8; 32] = h.finalize().into();

        assert_eq!(grant.signing_preimage().expect("preimage"), expected);
    }

    // -----------------------------------------------------------------------
    // Config clamp + validate
    // -----------------------------------------------------------------------

    #[test]
    fn clamp_forward_rate_into_range() {
        let lo = BroadcastHostConfig {
            max_forward_rate_per_minute: 0,
            max_subscribers: 10_000,
            forwarding_policy: ForwardingPolicy::Verbatim,
            expires_at_ms: 1,
        };
        assert_eq!(
            BroadcastHostConfig::clamp(&lo).max_forward_rate_per_minute,
            1
        );

        let hi = BroadcastHostConfig {
            max_forward_rate_per_minute: 1_000_000,
            max_subscribers: 10_000,
            forwarding_policy: ForwardingPolicy::Verbatim,
            expires_at_ms: 1,
        };
        assert_eq!(
            BroadcastHostConfig::clamp(&hi).max_forward_rate_per_minute,
            6000
        );
    }

    #[test]
    fn clamp_subscribers_into_range() {
        let lo = BroadcastHostConfig {
            max_forward_rate_per_minute: 600,
            max_subscribers: 0,
            forwarding_policy: ForwardingPolicy::Verbatim,
            expires_at_ms: 1,
        };
        assert_eq!(BroadcastHostConfig::clamp(&lo).max_subscribers, 1);

        let hi = BroadcastHostConfig {
            max_forward_rate_per_minute: 600,
            max_subscribers: 5_000_000,
            forwarding_policy: ForwardingPolicy::Verbatim,
            expires_at_ms: 1,
        };
        assert_eq!(BroadcastHostConfig::clamp(&hi).max_subscribers, 1_000_000);
    }

    #[test]
    fn clamp_in_range_values_unchanged() {
        let in_range = sample_config();
        let granted = BroadcastHostConfig::clamp(&in_range);
        assert_eq!(granted, in_range);
    }

    #[test]
    fn clamp_preserves_forwarding_policy_and_expiry() {
        let requested = BroadcastHostConfig {
            max_forward_rate_per_minute: 99_999,
            max_subscribers: 99_999_999,
            forwarding_policy: ForwardingPolicy::RoutingStripped,
            expires_at_ms: 42,
        };
        let granted = BroadcastHostConfig::clamp(&requested);
        assert_eq!(granted.forwarding_policy, ForwardingPolicy::RoutingStripped);
        assert_eq!(granted.expires_at_ms, 42);
    }

    #[test]
    fn validate_rejects_zero_expiry() {
        let config = BroadcastHostConfig {
            max_forward_rate_per_minute: 600,
            max_subscribers: 10_000,
            forwarding_policy: ForwardingPolicy::Verbatim,
            expires_at_ms: 0,
        };
        assert_eq!(
            config.validate(),
            Err(BroadcastHostingError::ConfigInvalid(
                "expires_at_ms must be > 0 (no perpetual grants)".to_owned()
            ))
        );
    }

    #[test]
    fn validate_accepts_positive_expiry() {
        assert!(sample_config().validate().is_ok());
    }

    #[test]
    fn sign_rejects_zero_expiry_request() {
        let sk = test_signing_key(0xAA);
        let result = BroadcastHostingRequest::sign(
            &sk,
            BroadcastHostingRequestFields {
                host_context_id: [0x11; 32],
                broadcast_context_id: [0x22; 32],
                subscriber_did: "did:example:host-rep".to_owned(),
                wrapping_pubkey: [0x44; 32],
                requested_config: BroadcastHostConfig {
                    max_forward_rate_per_minute: 600,
                    max_subscribers: 10_000,
                    forwarding_policy: ForwardingPolicy::Verbatim,
                    expires_at_ms: 0,
                },
                ucan: None,
                nonce: [0x55; 16],
                timestamp_ms: 1,
            },
        );
        assert!(matches!(
            result,
            Err(BroadcastHostingError::ConfigInvalid(_))
        ));
    }

    #[test]
    fn with_defaults_sets_spec_defaults() {
        let config = BroadcastHostConfig::with_defaults(1_000).expect("defaults");
        assert_eq!(config.max_forward_rate_per_minute, 600);
        assert_eq!(config.max_subscribers, 10_000);
        assert_eq!(config.forwarding_policy, ForwardingPolicy::Verbatim);
        assert_eq!(config.expires_at_ms, 1_000);
    }

    #[test]
    fn with_defaults_rejects_zero_expiry() {
        assert!(matches!(
            BroadcastHostConfig::with_defaults(0),
            Err(BroadcastHostingError::ConfigInvalid(_))
        ));
    }

    // -----------------------------------------------------------------------
    // JCS round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn config_jcs_round_trip() {
        let config = sample_config();
        let bytes = config.to_jcs().expect("jcs");
        let back: BroadcastHostConfig = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(config, back);
    }

    #[test]
    fn config_jcs_is_deterministic() {
        let config = sample_config();
        assert_eq!(config.to_jcs().expect("a"), config.to_jcs().expect("b"));
    }

    #[test]
    fn forwarding_policy_serializes_kebab_case() {
        let verbatim = serde_json::to_string(&ForwardingPolicy::Verbatim).expect("ser");
        let stripped = serde_json::to_string(&ForwardingPolicy::RoutingStripped).expect("ser");
        assert_eq!(verbatim, "\"verbatim\"");
        assert_eq!(stripped, "\"routing-stripped\"");
    }

    #[test]
    fn snapshot_entry_jcs_round_trip() {
        let entry = AcceptedHostSnapshotEntry {
            host_context_id: [0x11; 32],
            subscriber_did: "did:example:host-rep".to_owned(),
            wrapping_pubkey: [0x44; 32],
            granted_config: sample_config(),
            granted_at_ms: 1_709_654_400_000,
            key_epoch_at_grant: 7,
            saga_id: "550e8400-e29b-41d4-a716-446655440000".to_owned(),
        };
        let bytes = entry.to_jcs().expect("jcs");
        let back: AcceptedHostSnapshotEntry = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(entry, back);
    }

    #[test]
    fn request_serde_round_trip() {
        let sk = test_signing_key(0xAA);
        let request = gated_request(&sk);
        let json = serde_json::to_string(&request).expect("serialize");
        let back: BroadcastHostingRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(request, back);
        back.verify(&sk.verifying_key())
            .expect("round-tripped request still verifies");
    }

    #[test]
    fn grant_serde_round_trip() {
        let sk = test_signing_key(0xCC);
        let grant = sample_grant(&sk);
        let json = serde_json::to_string(&grant).expect("serialize");
        let back: BroadcastHostingGrant = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(grant, back);
        back.verify(&sk.verifying_key())
            .expect("round-tripped grant still verifies");
    }

    // -----------------------------------------------------------------------
    // Domain separators distinct (each other + broadcast envelope/key labels)
    // -----------------------------------------------------------------------

    #[test]
    fn domain_separators_are_distinct() {
        // The two handshake separators differ from each other.
        assert_ne!(BCAST_HOST_REQ_DOMAIN, BCAST_HOST_GRANT_DOMAIN);
        // …and from the broadcast envelope / key-derivation labels (§5.14.2, §5.14.5).
        assert_ne!(BCAST_HOST_REQ_DOMAIN, "SCP-BROADCAST-ENVELOPE-V1:");
        assert_ne!(BCAST_HOST_GRANT_DOMAIN, "SCP-BROADCAST-ENVELOPE-V1:");
        assert_ne!(BCAST_HOST_REQ_DOMAIN, "scp-broadcast-key-v1");
        assert_ne!(BCAST_HOST_GRANT_DOMAIN, "scp-broadcast-key-v1");
    }

    #[test]
    fn request_and_grant_preimages_differ_on_shared_fields() {
        // A request and a grant with identical shared fields must produce
        // different preimages — the domain separator alone guarantees this even
        // before the differing field sets (ucan vs current_key_epoch) are reached.
        let sk = test_signing_key(0xAA);
        let request = BroadcastHostingRequest::sign(
            &sk,
            BroadcastHostingRequestFields {
                host_context_id: [0x11; 32],
                broadcast_context_id: [0x22; 32],
                subscriber_did: "did:example:host-rep".to_owned(),
                wrapping_pubkey: [0x44; 32],
                requested_config: sample_config(),
                ucan: None,
                nonce: [0x55; 16],
                timestamp_ms: 1_709_654_400_000,
            },
        )
        .expect("sign request");
        let grant = sample_grant(&sk);
        assert_ne!(
            request.signing_preimage().expect("req"),
            grant.signing_preimage().expect("grant"),
            "distinct domain separators must keep request and grant preimages apart"
        );
    }
}
