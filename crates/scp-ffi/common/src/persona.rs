//! ADR-039 Enforcement-Stack Layer 2 — the message-send **persona-source seam**.
//!
//! The runtime is already persona-dynamic: [`MessageSigner`] binds the signing
//! key and its `#active`/`#agent` verification method as one value so the
//! stamp and the signature cannot diverge. What was hardcoded was the FFI
//! boundary — every native bridge's message-send site pinned
//! `MessageSigner::Active`. This module supplies the shared pieces that
//! de-hardcode it, identically across the three native bridges (`PyO3`, NAPI,
//! `UniFFI`). WASM has no send/signing path, so it does not use this module.
//!
//! Two pieces:
//! 1. [`PersonaSource`] — a per-send callable returning the [`SigningKeyId`]
//!    persona for the next send. Injected per bridge instance (like custody —
//!    no singletons). [`default_persona_source`] always returns
//!    [`SigningKeyId::Active`].
//! 2. [`ResolvedMessageSigner`] — an owned `(key, persona)` pair resolved
//!    together from ONE persona, whose [`ResolvedMessageSigner::message_signer`]
//!    derives the [`MessageSigner`] variant from that same persona. This makes
//!    an `#agent`-stamped-but-`#active`-signed message (or the reverse)
//!    unrepresentable at the bridge boundary.
//!
//! ## What this is NOT
//!
//! This is **plumbing only**. It does not build the *determiner* — the policy
//! that *selects* the persona non-forgeably — nor the Layer-1 custody
//! enforcement that makes a persona claim unfakeable. Those are owned by
//! RFC #2242 (<https://github.com/limn-works/scp/discussions/2242>). The
//! default `#active` is the permanent conservative fail-safe
//! (persona-uncertain ⇒ attribute to the human), not a stop-gap: a future
//! determiner *overrides* it only when it can positively establish `#agent`.
//!
//! The seam's input contract is deliberately **minimal** (zero args) — it is an
//! empty socket. RFC #2242 widens the input when the determiner's real inputs
//! (biometric / custody / auth-path / context) are known; they are not baked in
//! here.

use std::sync::Arc;

use scp_core::context::supervisor::MessageSigner;
use scp_did::SigningKeyId;

/// A per-send callable returning the [`SigningKeyId`] persona under which the
/// next message-send should be signed (ADR-039 Enforcement-Stack Layer 2).
///
/// Injected per bridge instance. The default ([`default_persona_source`])
/// always returns [`SigningKeyId::Active`] — the permanent conservative
/// fail-safe. There is intentionally no caller-settable per-call persona flag
/// on the SDK surface: that would be the lie-able API the ADR forbids. The
/// callable is where RFC #2242's determiner attaches.
pub type PersonaSource = Arc<dyn Fn() -> SigningKeyId + Send + Sync>;

/// The default persona source: always [`SigningKeyId::Active`].
///
/// `#active` is the conservative fail-safe — a persona-uncertain send is
/// attributed to the human, never silently to `#agent`.
#[must_use]
pub fn default_persona_source() -> PersonaSource {
    Arc::new(|| SigningKeyId::Active)
}

/// An owned `(signing key, persona)` pair resolved together from ONE persona.
///
/// Constructed by each bridge's persona-aware resolver, which matches on the
/// requested [`SigningKeyId`] exactly once to pick BOTH the key handle (active
/// vs agent, fail-closed when `#agent` has no agent key) AND the persona stored
/// here. [`Self::message_signer`] derives the [`MessageSigner`] variant from
/// that same stored persona and borrows the stored key — so the persona stamped
/// on the wire and the key that signs are one source of truth, and an
/// `#agent`-stamped-but-`#active`-signed message is unrepresentable.
pub struct ResolvedMessageSigner {
    key: ed25519_dalek::SigningKey,
    persona: SigningKeyId,
}

impl std::fmt::Debug for ResolvedMessageSigner {
    /// Redacts the signing key — private key material must never reach logs or
    /// panic messages (ADR-006).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedMessageSigner")
            .field("persona", &self.persona)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl ResolvedMessageSigner {
    /// Pairs an exported signing key with the persona it was resolved for.
    ///
    /// The caller MUST pass the key that belongs to `persona` (the active key
    /// for [`SigningKeyId::Active`], the agent key for [`SigningKeyId::Agent`]).
    /// The bridge `resolve_*` helpers enforce this by selecting the key handle
    /// and the persona in a single match, so the two cannot drift apart.
    #[must_use]
    pub const fn new(key: ed25519_dalek::SigningKey, persona: SigningKeyId) -> Self {
        Self { key, persona }
    }

    /// The atomic [`MessageSigner`]: the variant is derived from the stored
    /// persona and borrows the stored key, so the stamp and the key are one
    /// source of truth.
    #[must_use]
    pub const fn message_signer(&self) -> MessageSigner<'_> {
        match self.persona {
            SigningKeyId::Active => MessageSigner::Active(&self.key),
            SigningKeyId::Agent => MessageSigner::Agent(&self.key),
        }
    }

    /// The persona this signer stamps.
    #[must_use]
    pub const fn persona(&self) -> SigningKeyId {
        self.persona
    }

    /// The resolved signing key, regardless of persona. Exposed for the NAPI
    /// bridge, which decomposes the signer into `(bytes, signing_key_id)` across
    /// the actor mailbox — both fields taken from the same
    /// [`Self::message_signer`] so they cannot diverge.
    #[must_use]
    pub const fn key(&self) -> &ed25519_dalek::SigningKey {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_source_returns_active() {
        let source = default_persona_source();
        assert_eq!(source(), SigningKeyId::Active);
    }

    #[test]
    fn message_signer_variant_matches_persona() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);

        let active = ResolvedMessageSigner::new(key.clone(), SigningKeyId::Active);
        assert_eq!(active.persona(), SigningKeyId::Active);
        assert!(matches!(active.message_signer(), MessageSigner::Active(_)));
        assert_eq!(
            active.message_signer().signing_key_id(),
            SigningKeyId::Active
        );

        let agent = ResolvedMessageSigner::new(key, SigningKeyId::Agent);
        assert_eq!(agent.persona(), SigningKeyId::Agent);
        assert!(matches!(agent.message_signer(), MessageSigner::Agent(_)));
        assert_eq!(agent.message_signer().signing_key_id(), SigningKeyId::Agent);
    }

    #[test]
    fn message_signer_and_key_share_one_key() {
        // The NAPI decomposition path takes `.key()` and `.signing_key_id()`
        // from the same signer; assert they reference the same key bytes.
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let resolved = ResolvedMessageSigner::new(key.clone(), SigningKeyId::Agent);
        let signer = resolved.message_signer();
        assert_eq!(
            signer.key().to_bytes(),
            resolved.key().to_bytes(),
            "message_signer() and key() must expose the same key"
        );
        assert_eq!(signer.key().to_bytes(), key.to_bytes());
    }
}
