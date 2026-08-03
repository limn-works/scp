//! MLS `LeafNode` `scp_keypackage_attestation` extension (`0xFF03`) — the
//! DID-to-leaf `KeyPackage` attestation (§9.5.2, §9.7.1, §9.18.7).
//!
//! SCP's MLS leaf `signature_key` is an **ephemeral, context-scoped** key that
//! is NOT the member's DID identity key (§9.7.4). Admission and attribution are
//! instead provided by a **`KeyPackage` attestation**: an `#active`/`#agent`-signed
//! statement that binds **all four** of the leaf's own public keys — the Ed25519
//! leaf `signature_key`, and the three distinct X25519 HPKE keys (the `LeafNode`
//! ratchet-tree `encryption_key`, the `KeyPackage` `init_key`, and the
//! `scp_wrapping_key` (`0xFF01`) `wrapping_key`) — to the member's `did`
//! (§9.5.2). The attestation rides in the leaf as an MLS `LeafNode` extension,
//! mirroring [`crate::wrapping_extension`] (`scp_wrapping_key`, `0xFF01`).
//!
//! # Extension type ID
//!
//! Uses `0xFF03` from the RFC 9420 §17.3 private-use range (`0xFF00..=0xFFFF`).
//!
//! # This module (CRYPTO-22 slice 1)
//!
//! This slice provides the pure data type, its byte-exact serialization, and the
//! `0xFF03` `LeafNode`-extension helpers ONLY. It carries **no** signer, **no**
//! verifier, and **no** runtime wiring — those are later CRYPTO-22 slices. The
//! signature is stored/parsed as an opaque `[u8; 64]`.
//!
//! # What a later signer signs
//!
//! The **only** signable output is [`signing_hash`]: the 32-byte
//! `SHA-256(signing_preimage())` prehash. A later CRYPTO-22 slice's signer MUST
//! compute the Ed25519 signature over that 32-byte hash — and over **nothing
//! else**. It MUST NOT sign the raw `signing_preimage()` bytes, and it MUST NOT
//! sign the [`to_extension_body`] output. `signing_preimage()` is
//! module-private: it exists only to build the hash and to
//! reproduce the §25.23 Vector 37 known-answer test. Signing the wrong bytes
//! would silently diverge from Vector 37 and from every other binding.
//!
//! [`signing_hash`]: KeyPackageAttestation::signing_hash
//! [`to_extension_body`]: KeyPackageAttestation::to_extension_body
//!
//! # Serialization (§9.5.1 canonical construction)
//!
//! The **signing preimage** is the domain separator followed by the eight fields
//! in order, encoded per §9.5.1 (variable-length fields carry a 4-byte
//! big-endian length prefix; the four public keys are raw 32-byte values with no
//! prefix; `issued_at`/`expires_at` are 8-byte big-endian). The **signing hash**
//! is `SHA-256(preimage)`; the Ed25519 signature (a later slice) covers that
//! 32-byte hash. The **`0xFF03` extension body** is the same eight fields in the
//! same order **without** the domain separator, followed by the raw 64-byte
//! signature. A byte-exact known-answer vector is §25.23 Vector 37, pinned by the
//! [`tests::vector_37_*`] tests below.
//!
//! See spec §9.5.2 (field table + wire format) and §9.7.1 (the full model).

use openmls::prelude::*;
use scp_did::{DidDocument, SigningKeyId};
use scp_protocol::crypto::canonical::{CanonicalField, canonical_hash_bytes};
use sha2::{Digest, Sha256};

use crate::credential::ScpCredential;
use crate::error::MlsError;

/// Extension type ID for `scp_keypackage_attestation` in the RFC 9420 §17.3
/// private-use range (§9.18.7).
pub const SCP_KEYPACKAGE_ATTESTATION_EXTENSION_TYPE: u16 = 0xFF03;

/// Domain separator for the KeyPackage-attestation signing preimage (§9.18.2).
///
/// 30 ASCII bytes, prepended (with **no** length prefix, per §9.5.1) to the
/// canonical field encoding to form the signing preimage. It is deliberately
/// **absent** from the `0xFF03` extension body (§9.5.2).
pub const SCP_KEYPACKAGE_ATTESTATION_DOMAIN: &[u8] = b"SCP-KEYPACKAGE-ATTESTATION-V1:";

/// Maximum accepted `expires_at - issued_at` for a `KeyPackage` attestation
/// (§9.18.7; §9.7.1 verifier check 12): 7,261,200 seconds (84 days + 1 hour).
///
/// **Tied to the leaf/KeyPackage `Lifetime` maximum range.** Because §9.7.1
/// check 11 pins the attestation window to the leaf `Lifetime`
/// (`[not_before, not_after]`), the attestation's maximum range MUST equal the
/// leaf-`Lifetime` maximum range
/// ([`KEY_PACKAGE_LIFETIME_MAX_RANGE_SECS`](crate::lifetime::KEY_PACKAGE_LIFETIME_MAX_RANGE_SECS)) —
/// a tighter cap would reject every honestly-minted leaf, a wider one would let a
/// self-asserted attestation outlive its leaf. It is therefore defined *as* that
/// constant (single source of truth) and the compile-time assertion below pins it
/// to the spec-stated value.
pub const MAX_KEYPACKAGE_ATTESTATION_LIFETIME: u64 =
    crate::lifetime::KEY_PACKAGE_LIFETIME_MAX_RANGE_SECS;

// Pin the tied constant to the exact §9.18.7 value so a future change to the
// leaf-Lifetime range can never silently drift the spec-normative attestation
// cap without tripping the build.
const _: () = assert!(MAX_KEYPACKAGE_ATTESTATION_LIFETIME == 7_261_200);

/// Maximum staleness of the DID document used for the attestation current-key
/// check: 300 seconds (5 minutes).
///
/// §9.18.7; §9.7.1 verifier checks 1–2. Tied to the §9.14 clock-skew tolerance.
/// Consumed by the (later-slice) verifier; defined here so the constant lives
/// alongside the type it governs.
pub const MAX_ATTESTATION_KEY_RESOLUTION_STALENESS: u64 = 300;

/// Size of a raw Ed25519 or X25519 public key in bytes.
const PUBLIC_KEY_SIZE: usize = 32;

/// Size of a raw Ed25519 signature in bytes.
const SIGNATURE_SIZE: usize = 64;

/// Size of a 4-byte big-endian length prefix.
const LEN_PREFIX_SIZE: usize = 4;

/// Which handshake event triggers attestation verification (§9.7.1 "Verification
/// (MUST) — when it runs").
///
/// Defined here for use by later CRYPTO-22 slices (the verifier). Verification
/// runs on **leaf introduction or change** only — an `Add` (a `KeyPackage`
/// introducing a new leaf) or an `Update` (a member replacing its own leaf via
/// an Update / Commit-with-`UpdatePath`). A Commit/Proposal that does not change
/// the committer's leaf carries no new attestation and MUST NOT be re-verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttestationTrigger<'a> {
    /// A new leaf is being **added** via a `KeyPackage` (the cross-group
    /// fail-closed path; the only trigger at which the `init_key` checks apply).
    ///
    /// Carries the `KeyPackage`'s `init_key` (checks 7–8) **inside** the variant:
    /// an `Add` structurally *always* has a `KeyPackage`, and a `KeyPackage`
    /// always has an `init_key` (RFC 9420 §7.1). Folding it here makes the
    /// Add-requires-`init_key` / Update-has-none coupling a **type-system**
    /// guarantee — an `Add` with no `init_key` is unrepresentable — rather than a
    /// runtime fail-closed check (per the SCP "encode required choices as required
    /// fields" tenet).
    Add {
        /// The `KeyPackage`'s `init_key`: a raw 32-byte X25519 public key. Check 7
        /// binds `attestation.init_key` to it; check 8 (RFC 9420 §10.1) rejects a
        /// `KeyPackage` whose `init_key` equals its `encryption_key`.
        kp_init_key: &'a [u8; PUBLIC_KEY_SIZE],
    },
    /// An already-admitted member is **replacing its own leaf** (Update /
    /// Commit-with-`UpdatePath`). A ratchet-tree leaf has no `init_key`, so checks
    /// 7–8 do not run.
    Update,
}

/// A `KeyPackage` attestation (§9.5.2): an `#active`/`#agent`-signed binding of a
/// DID to **all four** of an MLS leaf's public keys.
///
/// The struct is deliberately **context-agnostic** — it carries no `context_id`.
/// A `KeyPackage` is a per-identity, pre-published pre-key bundle mintable
/// offline before any group it will join is known, so context scope is unknowable
/// at mint time; group scope is bound separately by the `scp_context_params`
/// `GroupContext` extension (`0xFF02`, §5.13.3).
///
/// # Fields
///
/// The four public keys are **distinct** and each is an independent decryption
/// (or self-signing) capability; the attestation must vouch for the *whole* leaf
/// (§9.5.2) — any unbound key is one a leaf-`signature_key` thief could
/// substitute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPackageAttestation {
    /// The attested DID. MUST equal the leaf's `ScpCredential.did` (§9.7.1
    /// check 9).
    pub did: String,
    /// The MLS leaf `signature_key` being bound: the raw 32-byte Ed25519 public
    /// key that self-signs the `LeafNode` (§9.5.2 field 2).
    pub leaf_signature_key: [u8; PUBLIC_KEY_SIZE],
    /// The `LeafNode` ratchet-tree `encryption_key`: a raw 32-byte X25519 public
    /// key that receives HPKE-sealed path secrets (RFC 9420 §7.2, §9.5.2
    /// field 3). Distinct from [`init_key`](Self::init_key).
    pub leaf_encryption_key: [u8; PUBLIC_KEY_SIZE],
    /// The `KeyPackage` `init_key`: a raw 32-byte X25519 public key the Welcome's
    /// `EncryptedGroupSecrets` is HPKE-sealed to at join (RFC 9420 §7.1, §9.5.2
    /// field 4). On a bare creator/PCS-Update leaf (no `KeyPackage`) this carries
    /// [`leaf_encryption_key`](Self::leaf_encryption_key); distinctness is a
    /// `KeyPackage`-only property.
    pub init_key: [u8; PUBLIC_KEY_SIZE],
    /// The `scp_wrapping_key` (`0xFF01`) LeafNode-extension value: a raw 32-byte
    /// X25519 public key used for §9.16 per-sender-key wrapping (§9.5.2 field 5).
    pub wrapping_key: [u8; PUBLIC_KEY_SIZE],
    /// Which DID verification method signed this attestation (`#active` or
    /// `#agent` — never `#0`, §9.5.2 field 6).
    pub signing_key_id: SigningKeyId,
    /// Unix seconds; equals the leaf's `Lifetime.not_before` (§9.5.2 field 7).
    pub issued_at: u64,
    /// Unix seconds; equals the leaf's `Lifetime.not_after` (§9.5.2 field 8).
    pub expires_at: u64,
    /// The raw 64-byte Ed25519 signature over [`signing_hash`](Self::signing_hash).
    ///
    /// Produced by a later CRYPTO-22 slice's signer; this slice stores and parses
    /// it opaquely.
    pub signature: [u8; SIGNATURE_SIZE],
}

impl KeyPackageAttestation {
    /// Returns the eight attestation fields as [`CanonicalField`]s in §9.5.2
    /// order, ready for the shared §9.5.1 canonical builder
    /// ([`canonical_hash_bytes`]).
    ///
    /// This is the single canonicalization codepath shared by
    /// [`signing_preimage`](Self::signing_preimage) (which passes the domain
    /// separator) and [`to_extension_body`](Self::to_extension_body) (which
    /// passes an empty domain and appends the signature). The two
    /// variable-length fields (`did`, `signing_key_id`) are encoded as
    /// [`CanonicalField::VarBytes`] (4-byte big-endian length prefix + bytes);
    /// the four public keys are [`CanonicalField::Fixed32`] (raw 32 bytes, no
    /// prefix); the two timestamps are [`CanonicalField::U64`] (8-byte
    /// big-endian).
    const fn canonical_fields(&self) -> [CanonicalField<'_>; 8] {
        [
            // Field 1: did.
            CanonicalField::VarBytes(self.did.as_bytes()),
            // Fields 2–5: the four raw 32-byte public keys.
            CanonicalField::Fixed32(&self.leaf_signature_key),
            CanonicalField::Fixed32(&self.leaf_encryption_key),
            CanonicalField::Fixed32(&self.init_key),
            CanonicalField::Fixed32(&self.wrapping_key),
            // Field 6: signing_key_id ("#active"/"#agent").
            CanonicalField::VarBytes(self.signing_key_id.as_bytes()),
            // Fields 7–8: the two timestamps.
            CanonicalField::U64(self.issued_at),
            CanonicalField::U64(self.expires_at),
        ]
    }

    /// Returns the §9.5.1 canonical **signing preimage**: the domain separator
    /// followed by the eight fields (§9.5.2). This is the byte string whose
    /// SHA-256 is the [`signing_hash`](Self::signing_hash) that the Ed25519
    /// signature covers. For §25.23 Vector 37 this is exactly 211 bytes.
    ///
    /// Module-private: the only external signable output is
    /// [`signing_hash`](Self::signing_hash). This method exists to build that
    /// hash and to reproduce the §25.23 Vector 37 known-answer test.
    ///
    /// Infallible: the shared builder only errors on a >`u32::MAX` `VarBytes`
    /// field (`did`/`signing_key_id` are orders of magnitude smaller), so
    /// `unwrap_or_default` is a total function here and never panics.
    #[must_use]
    fn signing_preimage(&self) -> Vec<u8> {
        canonical_hash_bytes(SCP_KEYPACKAGE_ATTESTATION_DOMAIN, &self.canonical_fields())
            .unwrap_or_default()
    }

    /// Returns the 32-byte signing hash `SHA-256(signing_preimage())` (§9.5.1).
    ///
    /// The Ed25519 signature (a later slice) is computed over this hash. For
    /// §25.23 Vector 37 this is
    /// `50cf61db5a97e0ddbd762de07e107684dfd0f00cfe53bad2750a70103ac38957`.
    #[must_use]
    pub fn signing_hash(&self) -> [u8; 32] {
        Sha256::digest(self.signing_preimage()).into()
    }

    /// Serializes the `scp_keypackage_attestation` (`0xFF03`) extension body: the
    /// eight fields in signing-preimage order (§9.5.2) — **without** the domain
    /// separator — followed by the raw 64-byte signature. A deterministic
    /// length-prefixed binary encoding (explicitly NOT MessagePack/JCS) so all
    /// bindings produce byte-identical bytes. For §25.23 Vector 37 this is exactly
    /// 245 bytes (181 field bytes + 64 signature bytes).
    ///
    /// This is NOT a signable input: the Ed25519 signature is computed over
    /// [`signing_hash`](Self::signing_hash), never over this body.
    ///
    /// Infallible: as with [`signing_preimage`](Self::signing_preimage), the
    /// shared builder cannot error for these bounded fields, so
    /// `unwrap_or_default` never panics.
    #[must_use]
    pub fn to_extension_body(&self) -> Vec<u8> {
        // Empty domain: the extension body is the canonical field encoding with
        // NO domain separator (b"" prepends nothing), then the raw signature.
        let mut buf = canonical_hash_bytes(b"", &self.canonical_fields()).unwrap_or_default();
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Parses a `KeyPackageAttestation` from an `scp_keypackage_attestation`
    /// (`0xFF03`) extension body produced by [`to_extension_body`](Self::to_extension_body).
    ///
    /// **Strict.** The parse rejects (with a typed [`MlsError::ExtensionError`],
    /// never a panic):
    ///
    /// - truncated / short input (any field extending past the buffer end),
    /// - trailing bytes after the trailing 64-byte signature,
    /// - a length prefix that overruns the remaining bytes (implausible/oversized
    ///   length),
    /// - non-UTF-8 `did` or `signing_key_id`, and
    /// - a `signing_key_id` that is not exactly `"#active"` or `"#agent"`.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::ExtensionError`] on any of the conditions above.
    pub fn from_extension_body(body: &[u8]) -> Result<Self, MlsError> {
        let mut cursor = Cursor::new(body);

        let did_bytes = cursor.take_var_bytes()?;
        let did = core::str::from_utf8(did_bytes)
            .map_err(|_| ext_err("scp_keypackage_attestation did is not valid UTF-8"))?
            .to_owned();

        let leaf_signature_key = cursor.take_array::<PUBLIC_KEY_SIZE>()?;
        let leaf_encryption_key = cursor.take_array::<PUBLIC_KEY_SIZE>()?;
        let init_key = cursor.take_array::<PUBLIC_KEY_SIZE>()?;
        let wrapping_key = cursor.take_array::<PUBLIC_KEY_SIZE>()?;

        let skid_bytes = cursor.take_var_bytes()?;
        let skid_str = core::str::from_utf8(skid_bytes)
            .map_err(|_| ext_err("scp_keypackage_attestation signing_key_id is not valid UTF-8"))?;
        let signing_key_id = SigningKeyId::from_fragment(skid_str).ok_or_else(|| {
            ext_err(format!(
                "scp_keypackage_attestation signing_key_id must be \"#active\" or \"#agent\", got {skid_str:?}"
            ))
        })?;

        let issued_at = cursor.take_u64()?;
        let expires_at = cursor.take_u64()?;
        let signature = cursor.take_array::<SIGNATURE_SIZE>()?;

        cursor.expect_end()?;

        Ok(Self {
            did,
            leaf_signature_key,
            leaf_encryption_key,
            init_key,
            wrapping_key,
            signing_key_id,
            issued_at,
            expires_at,
            signature,
        })
    }

    /// Builds the `Extension::Unknown(0xFF03, ...)` carrying this attestation's
    /// [`to_extension_body`](Self::to_extension_body), for inclusion in a
    /// `LeafNode`'s extensions. Mirrors
    /// [`make_wrapping_key_extension`](crate::wrapping_extension::make_wrapping_key_extension).
    #[must_use]
    pub fn make_attestation_extension(&self) -> Extension {
        Extension::Unknown(
            SCP_KEYPACKAGE_ATTESTATION_EXTENSION_TYPE,
            UnknownExtension(self.to_extension_body()),
        )
    }

    /// Extracts and parses the `scp_keypackage_attestation` (`0xFF03`) extension
    /// from a `LeafNode`'s extensions, if present.
    ///
    /// Returns `Ok(None)` if the extension is absent. Mirrors
    /// [`extract_wrapping_key`](crate::wrapping_extension::extract_wrapping_key).
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::ExtensionError`] if the extension is present but its
    /// body is malformed (see [`from_extension_body`](Self::from_extension_body)).
    pub fn extract_attestation(
        extensions: &Extensions<LeafNode>,
    ) -> Result<Option<Self>, MlsError> {
        match extensions.unknown(SCP_KEYPACKAGE_ATTESTATION_EXTENSION_TYPE) {
            None => Ok(None),
            Some(ext) => Ok(Some(Self::from_extension_body(&ext.0)?)),
        }
    }
}

/// Clock-skew tolerance for the attestation freshness check (§9.14): 300
/// seconds (5 minutes).
///
/// §9.7.1 verifier check 13 rejects any attestation whose `issued_at` is dated
/// more than this far beyond the verifier's current time. §9.14 states: "Clock
/// skew tolerance: 5 minutes. Messages with timestamps more than 5 minutes in
/// the future are rejected."
///
/// This is numerically equal to
/// [`MAX_ATTESTATION_KEY_RESOLUTION_STALENESS`] (both 300s, both anchored to the
/// §9.14 tolerance) but is a **distinct** semantic constant: this bounds how far
/// an attestation's `issued_at` may lead the verifier's clock, whereas that one
/// bounds how stale the resolver-cache document backing the current-key check
/// (checks 1–2) may be. They are kept separate so a future change to one does
/// not silently move the other.
pub const CLOCK_SKEW_TOLERANCE_SECS: u64 = 300;

/// A specific, typed reason a [`KeyPackageAttestation`] failed
/// [`verify_attestation`] (§9.7.1 "Verification (MUST) — the checks").
///
/// Exactly one variant per failing check, so a caller (and a wiring-slice
/// verifier) learns *which* invariant broke without string parsing. The numbers
/// in each variant's docs are the §9.7.1 check numbers.
///
/// Checks **1 and 2** (the `signing_key_id` names the DID's *current*
/// `#active`/`#agent` verification method, and the resolving document is no
/// older than [`MAX_ATTESTATION_KEY_RESOLUTION_STALENESS`]) are **NOT** in this
/// enum: they are the runtime caller's responsibility — the caller performs DID
/// resolution and passes the already-resolved current key in
/// [`AttestationVerificationContext::resolved_current_vm_pubkey`]. See
/// [`verify_attestation`] for the exact caller contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AttestationVerifyError {
    /// Check 3: the Ed25519 signature does not verify against the resolved
    /// current verification method. This is also what makes **rotation =
    /// revocation** (§9.12): an attestation signed by a rotated-away key fails
    /// here once the caller resolves the DID's current key.
    #[error("attestation signature does not verify against the resolved current key")]
    SignatureInvalid,

    /// Check 4: the attestation's `leaf_signature_key` does not equal the leaf's
    /// actual `signature_key`.
    #[error("attestation leaf_signature_key does not match the leaf's signature_key")]
    LeafSignatureKeyMismatch,

    /// Check 5: the attestation's `leaf_encryption_key` does not equal the
    /// leaf's actual ratchet-tree `encryption_key`.
    #[error("attestation leaf_encryption_key does not match the leaf's encryption_key")]
    LeafEncryptionKeyMismatch,

    /// Check 6: the attestation's `wrapping_key` does not equal the leaf's
    /// `scp_wrapping_key` (`0xFF01`) extension value.
    #[error("attestation wrapping_key does not match the leaf's scp_wrapping_key extension")]
    WrappingKeyMismatch,

    /// Check 7 (Add/Welcome only): the attestation's `init_key` does not equal
    /// the `KeyPackage`'s `init_key` — the read-as-victim-at-join vector.
    #[error("attestation init_key does not match the KeyPackage init_key")]
    InitKeyMismatch,

    /// Check 8 (Add/Welcome only): the `KeyPackage`'s `init_key` equals its
    /// `encryption_key` — a malformed `KeyPackage` per RFC 9420 §10.1.
    #[error("KeyPackage init_key equals encryption_key (RFC 9420 §10.1 malformed KeyPackage)")]
    InitKeyEqualsEncryptionKey,

    /// Check 9: the attestation's `did` does not equal the DID in the leaf's
    /// `ScpCredential`.
    #[error("attestation did does not match the leaf credential did")]
    DidMismatch,

    /// Check 10: the attestation's `signing_key_id` does not equal the
    /// `signing_key_id` in the leaf's `ScpCredential`.
    #[error("attestation signing_key_id does not match the leaf credential signing_key_id")]
    SigningKeyIdMismatch,

    /// Check 11: the attestation's `[issued_at, expires_at]` window does not
    /// exactly equal the leaf's `Lifetime` `[not_before, not_after]`.
    #[error("attestation validity window does not equal the leaf Lifetime window")]
    LifetimeWindowMismatch,

    /// Check 12: `expires_at - issued_at` exceeds
    /// [`MAX_KEYPACKAGE_ATTESTATION_LIFETIME`].
    #[error("attestation lifetime exceeds the protocol maximum")]
    LifetimeTooLong,

    /// Check 13a: `expires_at <= issued_at` (the window is non-positive).
    #[error("attestation expires_at is not strictly after issued_at")]
    ExpiresNotAfterIssued,

    /// Check 13b: the attestation is expired at the verifier's current time
    /// (`now > expires_at`).
    #[error("attestation is expired at the verifier's current time")]
    Expired,

    /// Check 13c: `issued_at` is dated further into the future than the §9.14
    /// clock-skew tolerance ([`CLOCK_SKEW_TOLERANCE_SECS`]).
    #[error("attestation issued_at is too far in the future (beyond clock-skew tolerance)")]
    IssuedInFuture,
}

/// The already-resolved ground-truth inputs [`verify_attestation`] checks a
/// [`KeyPackageAttestation`] against (§9.7.1 "the checks").
///
/// Flat named-field bundle (per the SCP agent-first API standard) of everything
/// the **pure** verifier needs; it performs **no** I/O, DID resolution, or leaf
/// parsing. The wiring slice populates each field from the processing
/// leaf/`KeyPackage`, the leaf's `ScpCredential`, and the DID resolver, then
/// calls [`verify_attestation`].
///
/// # There is no `context_id` / same-context field — by design
///
/// A [`KeyPackageAttestation`] is **context-agnostic** (§9.5.2, §9.7.1): a
/// `KeyPackage` is a pre-published, offline-mintable pre-key bundle, so the
/// context it will be added to is unknowable at mint time. **§9.7.1 defines no
/// "same-context" attestation check** — group/context binding is provided
/// separately and structurally by the `scp_context_params` `GroupContext`
/// extension (`0xFF02`, §5.13.3), which is enforced elsewhere, NOT by this
/// verifier. This struct therefore carries no context field; adding one would be
/// a fabricated check implying a guarantee the attestation does not make.
#[derive(Debug, Clone, Copy)]
pub struct AttestationVerificationContext<'a> {
    /// The **current** `#active`/`#agent` public key the caller resolved from
    /// the signer's DID document (raw 32-byte Ed25519). The signature (check 3)
    /// is verified against this key.
    ///
    /// **Caller contract (§9.7.1 checks 1–2 — NOT re-checked here).** The caller
    /// MUST resolve the verification method named by
    /// `attestation.signing_key_id` from the signer's DID document, and that
    /// document MUST be no older than
    /// [`MAX_ATTESTATION_KEY_RESOLUTION_STALENESS`] (300s). On an
    /// [`AttestationTrigger::Add`] this resolution is **fail-closed** (a
    /// resolution failure rejects the join; no stale/pre-rotation fallback). On
    /// an [`AttestationTrigger::Update`] a *transient resolution failure* may use
    /// the member's last-known-good document (bounded grace), but a resolution
    /// *success* returning a rotated-away key MUST pass a rotated key here so
    /// that check 3 fails (rotation = revocation). Passing a stale or
    /// wrong-persona key silently defeats revocation — this pure function cannot
    /// detect that and trusts the caller for it.
    pub resolved_current_vm_pubkey: &'a [u8; PUBLIC_KEY_SIZE],
    /// The leaf's actual `signature_key` (check 4).
    pub leaf_signature_key: &'a [u8; PUBLIC_KEY_SIZE],
    /// The leaf's actual ratchet-tree `encryption_key` (check 5).
    pub leaf_encryption_key: &'a [u8; PUBLIC_KEY_SIZE],
    /// The value of the leaf's `scp_wrapping_key` (`0xFF01`) extension (check 6).
    pub leaf_wrapping_key: &'a [u8; PUBLIC_KEY_SIZE],
    /// The DID carried in the leaf's `ScpCredential` (check 9).
    pub leaf_credential_did: &'a str,
    /// The `signing_key_id` carried in the leaf's `ScpCredential` (check 10).
    pub leaf_credential_signing_key_id: SigningKeyId,
    /// The leaf's `Lifetime.not_before` (check 11).
    pub leaf_lifetime_not_before: u64,
    /// The leaf's `Lifetime.not_after` (check 11).
    pub leaf_lifetime_not_after: u64,
    /// The verifier's current Unix time in seconds (check 13).
    pub now: u64,
    /// Which handshake event is being verified — the **structural** gate for the
    /// Add-only `init_key` checks (7–8), and the carrier of the `KeyPackage`
    /// `init_key` itself on [`AttestationTrigger::Add`] (a ratchet-tree leaf on an
    /// [`AttestationTrigger::Update`] has none). Per §9.7.1 this gate is on the
    /// trigger, **never** on `attestation.init_key == leaf_encryption_key` field
    /// equality.
    pub trigger: AttestationTrigger<'a>,
}

/// Verifies a [`KeyPackageAttestation`] against already-resolved ground-truth
/// inputs — the **pure** core of §9.7.1 "Verification (MUST) — the checks".
///
/// This function is deterministic, side-effect-free, and wasm-safe: it performs
/// **no** DID resolution, network, or clock I/O. All resolution-dependent inputs
/// (the current verification-method key, the leaf keys, the credential fields,
/// the leaf `Lifetime`, and `now`) are supplied by the caller in `ctx`. It rides
/// the browser MLS path, so it must stay allocation-light and dependency-free.
///
/// # Which checks this performs (pure) vs. the caller's job
///
/// Performs §9.7.1 checks **3–13**: signature (3); the four key bindings (4–6
/// always, 7 on Add); the RFC 9420 §10.1 malformed-KeyPackage guard (8, Add);
/// `did` (9) and `signing_key_id` (10) credential equality; the leaf-`Lifetime`
/// window equality (11); the lifetime cap (12); and freshness/expiry/future-date
/// (13). See [`AttestationVerifyError`] for the variant each check maps to.
///
/// Checks **1–2** — that `attestation.signing_key_id` names the DID's *current*
/// `#active`/`#agent` verification method and that the resolving document is no
/// older than [`MAX_ATTESTATION_KEY_RESOLUTION_STALENESS`] — are the runtime
/// caller's responsibility and are documented as a contract on
/// [`AttestationVerificationContext::resolved_current_vm_pubkey`]. **This is what
/// a later wiring slice (S4/S6/S7) MUST enforce before calling**, including the
/// Add-vs-Update resolution-failure policy (§9.7.1 "Resolution failure policy").
///
/// # The `init_key` structural gate (anti-trap)
///
/// Checks 7–8 run **iff `ctx.trigger` is [`AttestationTrigger::Add`]** — the
/// handshake structure — **never** because `attestation.init_key` happens to
/// equal `leaf_encryption_key`. A bare creator/PCS-Update leaf legitimately
/// carries `init_key == encryption_key`; keying the carve-out on that equality
/// would reopen the read-as-victim vector (§9.5.2 field 4, §9.7.1). The
/// `KeyPackage` `init_key` those checks need lives **inside** the
/// `Add { kp_init_key }` variant, so an `Add` with no `init_key` is
/// unrepresentable — the coupling is a type-system guarantee, not a runtime
/// fail-closed check. An `Update` carries no `init_key` and skips 7–8.
///
/// # Errors
///
/// Returns the [`AttestationVerifyError`] for the first failing check (checks
/// are evaluated signature-first, then bindings, then credential equality, then
/// the time/lifetime window).
pub fn verify_attestation(
    attestation: &KeyPackageAttestation,
    ctx: &AttestationVerificationContext<'_>,
) -> Result<(), AttestationVerifyError> {
    use AttestationVerifyError as E;

    // --- Check 3: signature over the §9.5.1 signing hash against the CURRENT
    // key (rotation ⇒ revocation). The attestation's eight fields are all inside
    // the signed hash, so this authenticates every field the bindings below
    // compare; a tampered attestation field fails here.
    scp_crypto::verify_ed25519_signature(
        ctx.resolved_current_vm_pubkey,
        &attestation.signing_hash(),
        &attestation.signature,
    )
    .map_err(|_| E::SignatureInvalid)?;

    // --- Checks 4–6: bind all three per-leaf keys (present on every leaf, both
    // triggers). Compared against the leaf's ACTUAL keys, not attestation-vs-
    // attestation, so a mismatch is a substituted leaf key.
    if attestation.leaf_signature_key != *ctx.leaf_signature_key {
        return Err(E::LeafSignatureKeyMismatch);
    }
    if attestation.leaf_encryption_key != *ctx.leaf_encryption_key {
        return Err(E::LeafEncryptionKeyMismatch);
    }
    if attestation.wrapping_key != *ctx.leaf_wrapping_key {
        return Err(E::WrappingKeyMismatch);
    }

    // --- Checks 7–8: init_key, Add/Welcome ONLY. Gated on the trigger
    // (structure), NEVER on field-value equality (§9.7.1 anti-trap). An Update
    // replaces a ratchet-tree leaf that has no init_key, so these do not run.
    match ctx.trigger {
        AttestationTrigger::Add { kp_init_key } => {
            // The KeyPackage's init_key rides inside the Add variant, so an Add
            // with no init_key is unrepresentable — no runtime fail-closed check
            // is needed (or possible) here.
            // Check 7: the attestation binds the KeyPackage's init_key.
            if attestation.init_key != *kp_init_key {
                return Err(E::InitKeyMismatch);
            }
            // Check 8 (RFC 9420 §10.1): the KeyPackage's two HPKE keys must be
            // distinct. Compared on the ACTUAL KeyPackage/leaf keys.
            if *kp_init_key == *ctx.leaf_encryption_key {
                return Err(E::InitKeyEqualsEncryptionKey);
            }
        }
        AttestationTrigger::Update => {
            // No init_key on a ratchet-tree leaf; checks 7–8 are correctly
            // skipped. A bare leaf's init_key == encryption_key is legitimate.
        }
    }

    // --- Check 9: did equals the leaf credential DID.
    if attestation.did != ctx.leaf_credential_did {
        return Err(E::DidMismatch);
    }
    // --- Check 10: signing_key_id equals the leaf credential signing_key_id.
    if attestation.signing_key_id != ctx.leaf_credential_signing_key_id {
        return Err(E::SigningKeyIdMismatch);
    }

    // --- Check 11: the attestation window equals the leaf Lifetime exactly (not
    // a wider self-asserted one).
    if attestation.issued_at != ctx.leaf_lifetime_not_before
        || attestation.expires_at != ctx.leaf_lifetime_not_after
    {
        return Err(E::LifetimeWindowMismatch);
    }

    // --- Check 13a: strictly-positive window (also makes the check-12
    // subtraction underflow-safe).
    if attestation.expires_at <= attestation.issued_at {
        return Err(E::ExpiresNotAfterIssued);
    }
    // --- Check 12: lifetime cap. `expires_at > issued_at` above ⇒ no underflow.
    if attestation.expires_at - attestation.issued_at > MAX_KEYPACKAGE_ATTESTATION_LIFETIME {
        return Err(E::LifetimeTooLong);
    }
    // --- Check 13b: unexpired at the verifier's current time (now == expires_at
    // is still valid; not_after is inclusive).
    if ctx.now > attestation.expires_at {
        return Err(E::Expired);
    }
    // --- Check 13c: issued_at not dated beyond the §9.14 clock-skew tolerance.
    // Saturating add so a near-`u64::MAX` `now` cannot overflow.
    if attestation.issued_at > ctx.now.saturating_add(CLOCK_SKEW_TOLERANCE_SECS) {
        return Err(E::IssuedInFuture);
    }

    Ok(())
}

/// The leaf/credential ground-truth for [`verify_attestation_with_resolution`].
///
/// It carries everything needed to build the pure
/// [`AttestationVerificationContext`], **minus** the two resolution-dependent
/// inputs that layer supplies itself: the current verification-method key
/// (extracted from the resolved document, §9.7.1 check 1) and `now` (a
/// caller-supplied clock read).
///
/// Flat named-field bundle (per the SCP agent-first API standard). It holds
/// **no** resolved key and **no** timestamps — the resolution seam owns those —
/// so it cannot be used to smuggle a caller-chosen "current" key past check 1.
#[derive(Debug, Clone, Copy)]
pub struct AttestationLeafGroundTruth<'a> {
    /// The leaf's `ScpCredential`. Its `did` and `signing_key_id` are the
    /// check-9/10 ground truth, and its `signing_key_id` names the current
    /// verification method resolved for check 1 via
    /// [`ScpCredential::resolve_signing_key`].
    pub credential: &'a ScpCredential,
    /// The leaf's actual `signature_key` (check 4).
    pub leaf_signature_key: &'a [u8; PUBLIC_KEY_SIZE],
    /// The leaf's actual ratchet-tree `encryption_key` (check 5).
    pub leaf_encryption_key: &'a [u8; PUBLIC_KEY_SIZE],
    /// The value of the leaf's `scp_wrapping_key` (`0xFF01`) extension (check 6).
    pub leaf_wrapping_key: &'a [u8; PUBLIC_KEY_SIZE],
    /// The leaf's `Lifetime.not_before` (check 11).
    pub leaf_lifetime_not_before: u64,
    /// The leaf's `Lifetime.not_after` (check 11).
    pub leaf_lifetime_not_after: u64,
    /// Which handshake event is being verified — the structural gate for the
    /// Add-only `init_key` checks (7–8) and the carrier of the `KeyPackage`
    /// `init_key` on [`AttestationTrigger::Add`].
    pub trigger: AttestationTrigger<'a>,
}

/// A typed reason [`verify_attestation_with_resolution`] rejected a
/// [`KeyPackageAttestation`] (§9.7.1 "Verification (MUST) — the checks",
/// checks 1–13).
///
/// This enum **wraps** the pure-core [`AttestationVerifyError`] (checks 3–13,
/// [`Delegated`](Self::Delegated)) and adds the two variants for the
/// resolution-dependent checks the pure core deliberately defers to the caller:
/// check 2 ([`ResolvedDocumentStale`](Self::ResolvedDocumentStale)) and check 1
/// ([`CurrentKeyNotFound`](Self::CurrentKeyNotFound)). The pure
/// [`AttestationVerifyError`] is left **byte-unchanged** — the new checks live
/// only here (CRYPTO-22 S4; §9.7.1 checks 1–2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AttestationResolutionVerifyError {
    /// Check 2 (§9.7.1; §9.18.7): the DID document used to satisfy check 1 was
    /// resolved more than [`MAX_ATTESTATION_KEY_RESOLUTION_STALENESS`] (300s)
    /// before `now`. Enforced **first**, before check 1 and before the pure
    /// checks 3–13, so a stale document can never mask a later failure.
    #[error(
        "DID document for the attestation current-key check is stale: resolved \
         {age_secs}s before now (max {MAX_ATTESTATION_KEY_RESOLUTION_STALENESS}s)"
    )]
    ResolvedDocumentStale {
        /// `now - resolved_at`, in seconds — how stale the resolving document is.
        age_secs: u64,
    },

    /// Check 1 (§9.7.1; §9.12 rotation-is-revocation): the credential's
    /// `signing_key_id` names **no current** `#active`/`#agent` verification
    /// method in the resolved document — it is absent, or has been rotated away
    /// and now lives only under a `#retired-*` fragment. Rejected **without**
    /// delegating to [`verify_attestation`] (checks 3–13 never run). A key that
    /// is still present at its `#active`/`#agent` fragment but rotated away is
    /// instead surfaced by the pure core as
    /// [`AttestationVerifyError::SignatureInvalid`] (check 3) via
    /// [`Delegated`](Self::Delegated).
    #[error(
        "the credential's signing_key_id names no current #active/#agent \
         verification method in the resolved DID document (absent or #retired-*)"
    )]
    CurrentKeyNotFound,

    /// Checks 3–13: the pure [`verify_attestation`] core rejected. The wrapped
    /// [`AttestationVerifyError`] is surfaced **verbatim** so a delegated
    /// failure is indistinguishable from calling the pure core directly.
    #[error(transparent)]
    Delegated(#[from] AttestationVerifyError),
}

/// The wasm-safe current-key + freshness seam for a [`KeyPackageAttestation`].
///
/// Enforces §9.7.1 verifier checks **1 and 2**, layered on top of the pure
/// checks-3–13 core [`verify_attestation`] (CRYPTO-22 S4, Layer A).
///
/// This function is deterministic, side-effect-free, and wasm-safe: it performs
/// **no** DID resolution, **no** network, and **no** clock read. Both
/// resolution-dependent inputs are caller-supplied — the already-resolved
/// `resolved_document` and its `resolved_at` timestamp, plus the verifier's
/// `now` — keeping it reusable by the in-browser MLS client (ADR-057). The
/// runtime `DidResolver`-backed caller (Layer B,
/// `scp-runtime`) obtains `resolved_document`/`resolved_at`/`now` and calls
/// through here.
///
/// # Order of checks (§9.7.1 checks 1–2, then 3–13)
///
/// 1. **Check 2 first** (freshness): reject with
///    [`AttestationResolutionVerifyError::ResolvedDocumentStale`] when
///    `now - resolved_at` exceeds
///    [`MAX_ATTESTATION_KEY_RESOLUTION_STALENESS`]. Enforced *before* the
///    current-key extraction so a stale document cannot pass on the strength of
///    a still-present key.
/// 2. **Check 1** (current key): extract the `#active`/`#agent` verification
///    method named by `ground_truth.credential.signing_key_id` from
///    `resolved_document` via the existing [`ScpCredential::resolve_signing_key`]
///    path. If that method is absent — including the rotated-away key that now
///    lives only under a `#retired-*` fragment — reject with
///    [`AttestationResolutionVerifyError::CurrentKeyNotFound`] **without**
///    calling [`verify_attestation`].
/// 3. **Checks 3–13**: build the [`AttestationVerificationContext`] with
///    `resolved_current_vm_pubkey` set to the extracted current key and delegate
///    **unchanged** to [`verify_attestation`]. A rotated-away-but-present key
///    thus surfaces as the existing [`AttestationVerifyError::SignatureInvalid`]
///    (check 3, rotation ⇒ revocation, §9.12).
///
/// # Errors
///
/// Returns the [`AttestationResolutionVerifyError`] for the first failing check
/// in the order above.
pub fn verify_attestation_with_resolution(
    attestation: &KeyPackageAttestation,
    ground_truth: &AttestationLeafGroundTruth<'_>,
    resolved_document: &DidDocument,
    resolved_at: u64,
    now: u64,
) -> Result<(), AttestationResolutionVerifyError> {
    // --- Check 2 (FIRST): the resolving document must be no older than the
    // §9.18.7 staleness bound. `saturating_sub` so a `resolved_at` that leads
    // `now` (benign clock skew across the resolve→verify hop) reads as age 0,
    // never a wrapping underflow.
    let age_secs = now.saturating_sub(resolved_at);
    if age_secs > MAX_ATTESTATION_KEY_RESOLUTION_STALENESS {
        return Err(AttestationResolutionVerifyError::ResolvedDocumentStale { age_secs });
    }

    // --- Check 1: the credential's signing_key_id must name a CURRENT
    // #active/#agent verification method in the resolved document. A rotated-away
    // key that has been retired no longer occupies that fragment, so resolution
    // fails here and we reject WITHOUT delegating to the pure core (checks 3–13
    // never run). A rotated-away key still present at its #active/#agent fragment
    // resolves fine and instead fails check 3 below (SignatureInvalid).
    let resolved_current_vm_pubkey = ground_truth
        .credential
        .resolve_signing_key(resolved_document)
        .map_err(|_| AttestationResolutionVerifyError::CurrentKeyNotFound)?;

    // --- Checks 3–13: delegate UNCHANGED to the pure core with the extracted
    // current key as `resolved_current_vm_pubkey`. The `?` maps any
    // `AttestationVerifyError` through the `#[from]` into `Delegated(..)`.
    let ctx = AttestationVerificationContext {
        resolved_current_vm_pubkey: &resolved_current_vm_pubkey,
        leaf_signature_key: ground_truth.leaf_signature_key,
        leaf_encryption_key: ground_truth.leaf_encryption_key,
        leaf_wrapping_key: ground_truth.leaf_wrapping_key,
        leaf_credential_did: &ground_truth.credential.did,
        leaf_credential_signing_key_id: ground_truth.credential.signing_key_id,
        leaf_lifetime_not_before: ground_truth.leaf_lifetime_not_before,
        leaf_lifetime_not_after: ground_truth.leaf_lifetime_not_after,
        now,
        trigger: ground_truth.trigger,
    };
    verify_attestation(attestation, &ctx)?;
    Ok(())
}

/// Builds [`Capabilities`] declaring both SCP `LeafNode` extension types.
///
/// Declares support for BOTH the `scp_wrapping_key` (`0xFF01`) and
/// `scp_keypackage_attestation` (`0xFF03`) `LeafNode` extension types, in
/// addition to the SCP ciphersuite defaults.
///
/// `OpenMLS` validates (`valn0107`) that any extension present on a `LeafNode`
/// has its type listed in the node's capabilities. A real SCP leaf carries both
/// `0xFF01` and `0xFF03`, so it must declare both. This is the superset that a
/// later wiring slice will adopt at the leaf-creation sites; declaring an extra
/// supported type that is not (yet) present is harmless. This slice does NOT
/// change existing call sites — it is additive only.
#[must_use]
pub fn scp_capabilities_with_keypackage_attestation() -> Capabilities {
    Capabilities::new(
        None, // default versions
        None, // default ciphersuites
        Some(&[
            ExtensionType::Unknown(crate::wrapping_extension::SCP_WRAPPING_KEY_EXTENSION_TYPE),
            ExtensionType::Unknown(SCP_KEYPACKAGE_ATTESTATION_EXTENSION_TYPE),
        ]),
        None, // default proposals
        None, // default credentials
    )
}

/// Constructs an [`MlsError::ExtensionError`] with the given message.
fn ext_err(msg: impl Into<String>) -> MlsError {
    MlsError::ExtensionError(msg.into())
}

/// A minimal forward-only byte cursor for the strict `0xFF03` body parse.
///
/// Every read is bounds-checked via `slice::get`, so a truncated or
/// oversized-length-prefix body yields a typed error rather than a panic.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Takes exactly `n` bytes, advancing the cursor. Errors if fewer than `n`
    /// bytes remain.
    fn take(&mut self, n: usize) -> Result<&'a [u8], MlsError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| ext_err("scp_keypackage_attestation length overflow"))?;
        let slice = self.data.get(self.pos..end).ok_or_else(|| {
            ext_err(format!(
                "scp_keypackage_attestation truncated: need {n} bytes at offset {}, have {} total",
                self.pos,
                self.data.len()
            ))
        })?;
        self.pos = end;
        Ok(slice)
    }

    /// Takes exactly `N` bytes as a fixed-size array.
    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], MlsError> {
        let slice = self.take(N)?;
        <[u8; N]>::try_from(slice)
            .map_err(|_| ext_err("scp_keypackage_attestation fixed-field length mismatch"))
    }

    /// Reads a 4-byte big-endian length prefix, then that many bytes.
    fn take_var_bytes(&mut self) -> Result<&'a [u8], MlsError> {
        let len_bytes = self.take(LEN_PREFIX_SIZE)?;
        let len_u32 = u32::from_be_bytes(
            <[u8; LEN_PREFIX_SIZE]>::try_from(len_bytes)
                .map_err(|_| ext_err("scp_keypackage_attestation length-prefix read failed"))?,
        );
        let len = usize::try_from(len_u32)
            .map_err(|_| ext_err("scp_keypackage_attestation length prefix exceeds usize"))?;
        self.take(len)
    }

    /// Reads an 8-byte big-endian `u64`.
    fn take_u64(&mut self) -> Result<u64, MlsError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(<[u8; 8]>::try_from(bytes).map_err(
            |_| ext_err("scp_keypackage_attestation u64 read failed"),
        )?))
    }

    /// Errors if any bytes remain unconsumed (rejects trailing bytes).
    fn expect_end(&self) -> Result<(), MlsError> {
        if self.pos == self.data.len() {
            Ok(())
        } else {
            Err(ext_err(format!(
                "scp_keypackage_attestation has {} trailing byte(s) after the signature",
                self.data.len() - self.pos
            )))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Decodes a hex string (whitespace/newlines ignored) into bytes.
    fn hex(s: &str) -> Vec<u8> {
        let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(compact.len().is_multiple_of(2), "hex must be even length");
        (0..compact.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    /// Builds the §25.23 Vector 37 attestation from the spec's exact input
    /// values. `leaf_signature_key`, the three X25519 keys, and the signature
    /// are the literal 32/64-byte values from the vector (this slice does not
    /// sign; the signature is an authoritative KAT constant).
    fn vector_37() -> KeyPackageAttestation {
        let arr32 = |s: &str| -> [u8; 32] { hex(s).try_into().expect("32 bytes") };
        KeyPackageAttestation {
            did: "did:dht:z6MkLeafAttest".to_owned(),
            leaf_signature_key: arr32(
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            ),
            leaf_encryption_key: arr32(
                "b6c6192e66300f4bbb4e3d870bfd02e416154ebb06661a70a84ea376244b3c20",
            ),
            init_key: arr32("7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13"),
            wrapping_key: arr32("0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20"),
            signing_key_id: SigningKeyId::Active,
            issued_at: 1_700_000_000,
            expires_at: 1_700_086_400,
            signature: hex(
                "fcf01ea58941c9e88acc14ef1ada7d00ac4c0239c75655160fc5b248ee0299e0\
                 18526235bc9b6d2a3efa37ab8db5d86b45b58deb5ad24540229d2804052e3509",
            )
            .try_into()
            .expect("64 bytes"),
        }
    }

    /// KAT: the signing preimage reproduces the §25.23 Vector 37 211-byte hex
    /// byte-for-byte.
    #[test]
    fn vector_37_signing_preimage_matches_spec() {
        let expected = hex(
            "5343502d4b45595041434b4147452d4154544553544154494f4e2d56313a
             000000166469643a6468743a7a364d6b4c656166417474657374
             3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
             b6c6192e66300f4bbb4e3d870bfd02e416154ebb06661a70a84ea376244b3c20
             7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13
             0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20
             0000000723616374697665
             000000006553f100
             0000000065554280",
        );
        let preimage = vector_37().signing_preimage();
        assert_eq!(
            preimage.len(),
            211,
            "Vector 37 preimage must be exactly 211 bytes"
        );
        assert_eq!(
            preimage, expected,
            "signing_preimage() must reproduce §25.23 Vector 37 byte-for-byte"
        );
    }

    /// KAT: the signing hash equals the §25.23 Vector 37 SHA-256.
    #[test]
    fn vector_37_signing_hash_matches_spec() {
        let expected: [u8; 32] =
            hex("50cf61db5a97e0ddbd762de07e107684dfd0f00cfe53bad2750a70103ac38957")
                .try_into()
                .unwrap();
        assert_eq!(
            vector_37().signing_hash(),
            expected,
            "signing_hash() must equal §25.23 Vector 37 SHA-256"
        );
    }

    /// KAT: the `0xFF03` extension body reproduces the §25.23 Vector 37 245-byte
    /// hex byte-for-byte.
    #[test]
    fn vector_37_extension_body_matches_spec() {
        let expected = hex("000000166469643a6468743a7a364d6b4c656166417474657374
             3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
             b6c6192e66300f4bbb4e3d870bfd02e416154ebb06661a70a84ea376244b3c20
             7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13
             0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20
             0000000723616374697665
             000000006553f100
             0000000065554280
             fcf01ea58941c9e88acc14ef1ada7d00ac4c0239c75655160fc5b248ee0299e0
             18526235bc9b6d2a3efa37ab8db5d86b45b58deb5ad24540229d2804052e3509");
        let body = vector_37().to_extension_body();
        assert_eq!(
            body.len(),
            245,
            "Vector 37 extension body must be exactly 245 bytes"
        );
        assert_eq!(
            body, expected,
            "to_extension_body() must reproduce §25.23 Vector 37 byte-for-byte"
        );
    }

    /// The extension body is exactly the preimage minus the 30-byte domain
    /// separator, plus the 64-byte signature (§9.5.2 wire-format invariant).
    #[test]
    fn extension_body_is_preimage_minus_domain_plus_signature() {
        let att = vector_37();
        let preimage = att.signing_preimage();
        let body = att.to_extension_body();
        // Body's field portion == preimage without the domain prefix.
        let domain_len = SCP_KEYPACKAGE_ATTESTATION_DOMAIN.len();
        assert_eq!(
            &body[..body.len() - SIGNATURE_SIZE],
            &preimage[domain_len..]
        );
        // Body ends with the raw signature.
        assert_eq!(&body[body.len() - SIGNATURE_SIZE..], &att.signature);
    }

    /// Round-trip: `from_extension_body(to_extension_body())` reconstructs an
    /// equal struct.
    #[test]
    fn vector_37_extension_body_roundtrips() {
        let att = vector_37();
        let body = att.to_extension_body();
        let parsed = KeyPackageAttestation::from_extension_body(&body).unwrap();
        assert_eq!(parsed, att);
    }

    /// Round-trip with the `#agent` signing key id (exercises the other
    /// `SigningKeyId` arm).
    #[test]
    fn agent_signing_key_id_roundtrips() {
        let mut att = vector_37();
        att.signing_key_id = SigningKeyId::Agent;
        let body = att.to_extension_body();
        let parsed = KeyPackageAttestation::from_extension_body(&body).unwrap();
        assert_eq!(parsed.signing_key_id, SigningKeyId::Agent);
        assert_eq!(parsed, att);
    }

    // -- strict-parse negative tests -----------------------------------------

    #[test]
    fn from_extension_body_rejects_truncated() {
        let body = vector_37().to_extension_body();
        // Drop the final signature byte.
        let truncated = &body[..body.len() - 1];
        assert!(KeyPackageAttestation::from_extension_body(truncated).is_err());
    }

    #[test]
    fn from_extension_body_rejects_empty() {
        assert!(KeyPackageAttestation::from_extension_body(&[]).is_err());
    }

    #[test]
    fn from_extension_body_rejects_trailing_byte() {
        let mut body = vector_37().to_extension_body();
        body.push(0x00); // one extra trailing byte after the signature
        assert!(KeyPackageAttestation::from_extension_body(&body).is_err());
    }

    #[test]
    fn from_extension_body_rejects_oversized_length_prefix() {
        let mut body = vector_37().to_extension_body();
        // The first 4 bytes are the `did` length prefix. Set it to a value that
        // overruns the remaining bytes.
        body[0] = 0xFF;
        body[1] = 0xFF;
        body[2] = 0xFF;
        body[3] = 0xFF;
        assert!(KeyPackageAttestation::from_extension_body(&body).is_err());
    }

    /// Helper: hand-builds an `0xFF03`-style body from raw component byte
    /// slices, so a test can inject a malformed `did` / `signing_key_id`
    /// (invalid UTF-8, oversized length prefix) that [`to_extension_body`]
    /// could never emit.
    fn build_body(
        did_len_prefix: [u8; 4],
        did: &[u8],
        skid_len_prefix: [u8; 4],
        skid: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&did_len_prefix);
        body.extend_from_slice(did);
        body.extend_from_slice(&[0u8; PUBLIC_KEY_SIZE]); // leaf_signature_key
        body.extend_from_slice(&[0u8; PUBLIC_KEY_SIZE]); // leaf_encryption_key
        body.extend_from_slice(&[0u8; PUBLIC_KEY_SIZE]); // init_key
        body.extend_from_slice(&[0u8; PUBLIC_KEY_SIZE]); // wrapping_key
        body.extend_from_slice(&skid_len_prefix);
        body.extend_from_slice(skid);
        body.extend_from_slice(&1_700_000_000u64.to_be_bytes());
        body.extend_from_slice(&1_700_086_400u64.to_be_bytes());
        body.extend_from_slice(&[0u8; SIGNATURE_SIZE]);
        body
    }

    #[test]
    fn from_extension_body_rejects_non_utf8_did() {
        // did bytes 0xFF 0xFE are not valid UTF-8.
        let bad_did: &[u8] = &[0xFF, 0xFE];
        let body = build_body(
            u32::try_from(bad_did.len()).unwrap().to_be_bytes(),
            bad_did,
            u32::try_from(b"#active".len()).unwrap().to_be_bytes(),
            b"#active",
        );
        assert!(
            KeyPackageAttestation::from_extension_body(&body).is_err(),
            "non-UTF-8 did must be rejected, not panic"
        );
    }

    #[test]
    fn from_extension_body_rejects_non_utf8_signing_key_id() {
        // signing_key_id bytes 0xFF 0xFE are not valid UTF-8 (rejected at the
        // UTF-8 check, before the "#active"/"#agent" fragment check).
        let bad_skid: &[u8] = &[0xFF, 0xFE];
        let did = b"did:dht:z6MkLeafAttest";
        let body = build_body(
            u32::try_from(did.len()).unwrap().to_be_bytes(),
            did,
            u32::try_from(bad_skid.len()).unwrap().to_be_bytes(),
            bad_skid,
        );
        assert!(
            KeyPackageAttestation::from_extension_body(&body).is_err(),
            "non-UTF-8 signing_key_id must be rejected, not panic"
        );
    }

    #[test]
    fn from_extension_body_rejects_oversized_signing_key_id_length_prefix() {
        // Oversized length prefix on the signing_key_id field specifically
        // (the `did` field parses cleanly first, isolating the skid overrun).
        let did = b"did:dht:z6MkLeafAttest";
        let body = build_body(
            u32::try_from(did.len()).unwrap().to_be_bytes(),
            did,
            [0xFF, 0xFF, 0xFF, 0xFF], // claims ~4 GiB skid — overruns the buffer
            b"#active",
        );
        assert!(
            KeyPackageAttestation::from_extension_body(&body).is_err(),
            "oversized signing_key_id length prefix must be rejected, not panic"
        );
    }

    #[test]
    fn from_extension_body_rejects_unknown_signing_key_id() {
        // Hand-build a body with a bogus signing_key_id fragment ("#0").
        let mut body = Vec::new();
        let did = b"did:dht:z6MkLeafAttest";
        body.extend_from_slice(&u32::try_from(did.len()).unwrap().to_be_bytes());
        body.extend_from_slice(did);
        body.extend_from_slice(&[0u8; PUBLIC_KEY_SIZE]); // leaf_signature_key
        body.extend_from_slice(&[0u8; PUBLIC_KEY_SIZE]); // leaf_encryption_key
        body.extend_from_slice(&[0u8; PUBLIC_KEY_SIZE]); // init_key
        body.extend_from_slice(&[0u8; PUBLIC_KEY_SIZE]); // wrapping_key
        let bad_skid = b"#0";
        body.extend_from_slice(&u32::try_from(bad_skid.len()).unwrap().to_be_bytes());
        body.extend_from_slice(bad_skid);
        body.extend_from_slice(&1_700_000_000u64.to_be_bytes());
        body.extend_from_slice(&1_700_086_400u64.to_be_bytes());
        body.extend_from_slice(&[0u8; SIGNATURE_SIZE]);
        assert!(KeyPackageAttestation::from_extension_body(&body).is_err());
    }

    // -- extension helper round-trip -----------------------------------------

    #[test]
    fn make_and_extract_attestation_roundtrip() {
        let att = vector_37();
        let ext = att.make_attestation_extension();
        assert_eq!(
            ext.extension_type(),
            ExtensionType::Unknown(SCP_KEYPACKAGE_ATTESTATION_EXTENSION_TYPE)
        );
        let extensions = Extensions::<LeafNode>::single(ext).unwrap();
        let extracted = KeyPackageAttestation::extract_attestation(&extensions)
            .unwrap()
            .expect("attestation must be present");
        assert_eq!(extracted, att);
    }

    #[test]
    fn extract_attestation_returns_none_when_absent() {
        let extensions = Extensions::<LeafNode>::default();
        assert_eq!(
            KeyPackageAttestation::extract_attestation(&extensions).unwrap(),
            None
        );
    }

    #[test]
    fn extract_attestation_propagates_malformed_body_error() {
        let ext = Extension::Unknown(
            SCP_KEYPACKAGE_ATTESTATION_EXTENSION_TYPE,
            UnknownExtension(vec![0x00, 0x01, 0x02]), // too short to parse
        );
        let extensions = Extensions::<LeafNode>::single(ext).unwrap();
        assert!(KeyPackageAttestation::extract_attestation(&extensions).is_err());
    }

    // -- capabilities --------------------------------------------------------

    #[test]
    fn capabilities_declare_attestation_and_wrapping_types() {
        let caps = scp_capabilities_with_keypackage_attestation();
        assert!(
            caps.extensions().contains(&ExtensionType::Unknown(
                SCP_KEYPACKAGE_ATTESTATION_EXTENSION_TYPE
            )),
            "capabilities must list scp_keypackage_attestation (0xFF03)"
        );
        assert!(
            caps.extensions().contains(&ExtensionType::Unknown(
                crate::wrapping_extension::SCP_WRAPPING_KEY_EXTENSION_TYPE
            )),
            "capabilities must also list scp_wrapping_key (0xFF01)"
        );
    }

    // -- constant pins -------------------------------------------------------

    #[test]
    fn constants_match_spec() {
        assert_eq!(SCP_KEYPACKAGE_ATTESTATION_EXTENSION_TYPE, 0xFF03);
        assert_eq!(MAX_KEYPACKAGE_ATTESTATION_LIFETIME, 7_261_200);
        assert_eq!(MAX_ATTESTATION_KEY_RESOLUTION_STALENESS, 300);
        assert_eq!(
            SCP_KEYPACKAGE_ATTESTATION_DOMAIN,
            b"SCP-KEYPACKAGE-ATTESTATION-V1:"
        );
        assert_eq!(SCP_KEYPACKAGE_ATTESTATION_DOMAIN.len(), 30);
    }

    // == verify_attestation (§9.7.1 "the checks") ============================

    use ed25519_dalek::{Signer, SigningKey};
    use rand::{RngCore, rngs::OsRng};

    const ISSUED: u64 = 1_700_000_000;
    const EXPIRES: u64 = 1_700_086_400; // ISSUED + 86_400 (1 day)
    const NOW: u64 = 1_700_000_100; // inside [ISSUED, EXPIRES]

    /// A fresh random 32-byte key (CSPRNG; test-only ground-truth material).
    fn rand_key() -> [u8; PUBLIC_KEY_SIZE] {
        let mut b = [0u8; PUBLIC_KEY_SIZE];
        OsRng.fill_bytes(&mut b);
        b
    }

    /// Signs `att` in place under `signer`, over its §9.5.1 `signing_hash()`
    /// (the *only* correct signable input). The real signer is a later slice;
    /// this test helper stands in for it.
    fn sign_in_place(att: &mut KeyPackageAttestation, signer: &SigningKey) {
        att.signature = signer.sign(&att.signing_hash()).to_bytes();
    }

    /// Which handshake event a fixture is built for. A test-only selector: the
    /// real [`AttestationTrigger::Add`] carries a borrow of the `KeyPackage`
    /// `init_key`, which would make [`Truth`] self-referential, so [`Truth`]
    /// stores this plain discriminant and [`Truth::ctx`] constructs the real
    /// (borrowing) trigger on demand from `self.kp_init`.
    #[derive(Clone, Copy)]
    enum TriggerKind {
        Add,
        Update,
    }

    /// Owned ground-truth values a test can mutate, then borrow into a context
    /// via [`Truth::ctx`]. Fields that are ALSO signed (`did`, `signing_key_id`,
    /// `issued_at`, `expires_at`, `init_key` on Add) must be changed on the
    /// attestation and re-signed to test their check; fields that are ONLY
    /// context inputs (the resolved key, the leaf keys, `now`, the leaf
    /// `Lifetime` bounds, `leaf_credential_*`) can be flipped here alone, leaving
    /// a still-valid signature so the target check fails in isolation.
    struct Truth {
        signer_pubkey: [u8; PUBLIC_KEY_SIZE],
        leaf_sig: [u8; PUBLIC_KEY_SIZE],
        leaf_enc: [u8; PUBLIC_KEY_SIZE],
        leaf_wrap: [u8; PUBLIC_KEY_SIZE],
        kp_init: [u8; PUBLIC_KEY_SIZE],
        did: String,
        skid: SigningKeyId,
        not_before: u64,
        not_after: u64,
        now: u64,
        kind: TriggerKind,
    }

    impl Truth {
        fn ctx(&self) -> AttestationVerificationContext<'_> {
            AttestationVerificationContext {
                resolved_current_vm_pubkey: &self.signer_pubkey,
                leaf_signature_key: &self.leaf_sig,
                leaf_encryption_key: &self.leaf_enc,
                leaf_wrapping_key: &self.leaf_wrap,
                leaf_credential_did: &self.did,
                leaf_credential_signing_key_id: self.skid,
                leaf_lifetime_not_before: self.not_before,
                leaf_lifetime_not_after: self.not_after,
                now: self.now,
                trigger: match self.kind {
                    TriggerKind::Add => AttestationTrigger::Add {
                        kp_init_key: &self.kp_init,
                    },
                    TriggerKind::Update => AttestationTrigger::Update,
                },
            }
        }
    }

    /// A fully-valid, signed `(attestation, Truth, signer)` triple for the given
    /// trigger. On `Update` the leaf has no `KeyPackage`, so the attestation's
    /// `init_key` field carries `leaf_encryption_key` (a bare leaf) — this
    /// exercises the anti-trap path where `init_key == encryption_key` is
    /// legitimate.
    fn valid_fixture(kind: TriggerKind) -> (KeyPackageAttestation, Truth, SigningKey) {
        let signer = SigningKey::generate(&mut OsRng);
        let leaf_sig = rand_key();
        let leaf_enc = rand_key();
        let leaf_wrap = rand_key();
        let kp_init = rand_key();
        let att_init = match kind {
            TriggerKind::Add => kp_init,
            TriggerKind::Update => leaf_enc,
        };
        let did = "did:dht:z6MkVerifyTest".to_owned();
        let skid = SigningKeyId::Active;
        let mut att = KeyPackageAttestation {
            did: did.clone(),
            leaf_signature_key: leaf_sig,
            leaf_encryption_key: leaf_enc,
            init_key: att_init,
            wrapping_key: leaf_wrap,
            signing_key_id: skid,
            issued_at: ISSUED,
            expires_at: EXPIRES,
            signature: [0u8; SIGNATURE_SIZE],
        };
        sign_in_place(&mut att, &signer);
        let truth = Truth {
            signer_pubkey: signer.verifying_key().to_bytes(),
            leaf_sig,
            leaf_enc,
            leaf_wrap,
            kp_init,
            did,
            skid,
            not_before: ISSUED,
            not_after: EXPIRES,
            now: NOW,
            kind,
        };
        (att, truth, signer)
    }

    // -- positive ------------------------------------------------------------

    #[test]
    fn valid_add_passes() {
        let (att, truth, _s) = valid_fixture(TriggerKind::Add);
        assert_eq!(verify_attestation(&att, &truth.ctx()), Ok(()));
    }

    #[test]
    fn valid_update_passes() {
        let (att, truth, _s) = valid_fixture(TriggerKind::Update);
        assert_eq!(verify_attestation(&att, &truth.ctx()), Ok(()));
    }

    // -- check 3: signature / rotation = revocation --------------------------

    #[test]
    fn add_wrong_resolved_key_is_signature_error() {
        // A rotated-away #active key: the caller resolves a DIFFERENT current
        // key than the one that signed. Signature must fail (rotation revokes).
        let (att, mut truth, _s) = valid_fixture(TriggerKind::Add);
        truth.signer_pubkey = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        assert_eq!(
            verify_attestation(&att, &truth.ctx()),
            Err(AttestationVerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn update_wrong_resolved_key_is_signature_error() {
        // Rotation revokes on an Update's resolution SUCCESS too, exactly as on
        // an Add (§9.7.1 check 1: a rotated key still rejects).
        let (att, mut truth, _s) = valid_fixture(TriggerKind::Update);
        truth.signer_pubkey = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        assert_eq!(
            verify_attestation(&att, &truth.ctx()),
            Err(AttestationVerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn tampered_signature_is_signature_error() {
        let (mut att, truth, _s) = valid_fixture(TriggerKind::Add);
        att.signature[0] ^= 0x01;
        assert_eq!(
            verify_attestation(&att, &truth.ctx()),
            Err(AttestationVerifyError::SignatureInvalid)
        );
    }

    // -- checks 4–6: key bindings (flip the LEAF input, keep signature valid) -

    #[test]
    fn leaf_signature_key_mismatch() {
        let (att, mut truth, _s) = valid_fixture(TriggerKind::Add);
        truth.leaf_sig = rand_key();
        assert_eq!(
            verify_attestation(&att, &truth.ctx()),
            Err(AttestationVerifyError::LeafSignatureKeyMismatch)
        );
    }

    #[test]
    fn leaf_encryption_key_mismatch() {
        let (att, mut truth, _s) = valid_fixture(TriggerKind::Add);
        truth.leaf_enc = rand_key();
        assert_eq!(
            verify_attestation(&att, &truth.ctx()),
            Err(AttestationVerifyError::LeafEncryptionKeyMismatch)
        );
    }

    #[test]
    fn wrapping_key_mismatch() {
        let (att, mut truth, _s) = valid_fixture(TriggerKind::Add);
        truth.leaf_wrap = rand_key();
        assert_eq!(
            verify_attestation(&att, &truth.ctx()),
            Err(AttestationVerifyError::WrappingKeyMismatch)
        );
    }

    // -- checks 7–8: init_key, Add-only --------------------------------------

    #[test]
    fn add_init_key_mismatch() {
        // The KeyPackage's init_key (context input, unsigned) differs from the
        // attested init_key — the read-as-victim-at-join substitution.
        let (att, mut truth, _s) = valid_fixture(TriggerKind::Add);
        truth.kp_init = rand_key();
        assert_eq!(
            verify_attestation(&att, &truth.ctx()),
            Err(AttestationVerifyError::InitKeyMismatch)
        );
    }

    #[test]
    fn add_init_key_equals_encryption_key() {
        // Malformed KeyPackage (RFC 9420 §10.1): init_key == encryption_key.
        // Set the attested init_key to leaf_enc AND the KeyPackage init_key to
        // leaf_enc so check 7 passes and check 8 fires; re-sign the changed field.
        let (mut att, mut truth, signer) = valid_fixture(TriggerKind::Add);
        att.init_key = truth.leaf_enc;
        sign_in_place(&mut att, &signer);
        truth.kp_init = truth.leaf_enc;
        assert_eq!(
            verify_attestation(&att, &truth.ctx()),
            Err(AttestationVerifyError::InitKeyEqualsEncryptionKey)
        );
    }

    // NOTE: there is no "Add without a KeyPackage init_key" test, because that
    // state is now UNREPRESENTABLE. The `KeyPackage` `init_key` rides inside the
    // `AttestationTrigger::Add { kp_init_key }` variant, so an `Add` with no
    // `init_key` is a compile error — the coupling is enforced by the type system,
    // not by a runtime fail-closed check. Concretely,
    // `AttestationTrigger::Add {}` (or `AttestationTrigger::Add` with no field)
    // does not compile, so the former `MissingKeyPackageInitKey` runtime error was
    // removed. This comment stands in for the deleted
    // `add_missing_kp_init_key_fails_closed` runtime test.

    /// ANTI-TRAP: an Update leaf with `init_key == encryption_key` is legitimate
    /// (a bare ratchet-tree leaf) and MUST be accepted — the Add-only checks
    /// (7–8) are gated on the TRIGGER, never on that field equality (§9.7.1).
    #[test]
    fn update_with_init_key_equal_to_encryption_key_is_accepted() {
        let (att, truth, _s) = valid_fixture(TriggerKind::Update);
        assert_eq!(
            att.init_key, att.leaf_encryption_key,
            "the Update fixture must exhibit init_key == encryption_key to guard the trap"
        );
        assert_eq!(verify_attestation(&att, &truth.ctx()), Ok(()));
    }

    // -- checks 9–10: credential equality ------------------------------------

    #[test]
    fn did_mismatch() {
        let (att, mut truth, _s) = valid_fixture(TriggerKind::Add);
        truth.did = "did:dht:z6MkDifferent".to_owned();
        assert_eq!(
            verify_attestation(&att, &truth.ctx()),
            Err(AttestationVerifyError::DidMismatch)
        );
    }

    #[test]
    fn signing_key_id_mismatch() {
        // Attestation signed under #active; credential claims #agent.
        let (att, mut truth, _s) = valid_fixture(TriggerKind::Add);
        assert_eq!(att.signing_key_id, SigningKeyId::Active);
        truth.skid = SigningKeyId::Agent;
        assert_eq!(
            verify_attestation(&att, &truth.ctx()),
            Err(AttestationVerifyError::SigningKeyIdMismatch)
        );
    }

    // -- check 11: window equals the leaf Lifetime ---------------------------

    #[test]
    fn lifetime_window_mismatch() {
        // Flip the leaf Lifetime (context input) so it no longer equals the
        // attested window; signature stays valid.
        let (att, mut truth, _s) = valid_fixture(TriggerKind::Add);
        truth.not_after = EXPIRES + 1;
        assert_eq!(
            verify_attestation(&att, &truth.ctx()),
            Err(AttestationVerifyError::LifetimeWindowMismatch)
        );
    }

    // -- checks 12–13: lifetime cap, freshness -------------------------------

    #[test]
    fn lifetime_too_long() {
        // Window one second past the cap; leaf Lifetime matches (check 11 OK).
        let (mut att, mut truth, signer) = valid_fixture(TriggerKind::Add);
        att.expires_at = att.issued_at + MAX_KEYPACKAGE_ATTESTATION_LIFETIME + 1;
        sign_in_place(&mut att, &signer);
        truth.not_after = att.expires_at;
        assert_eq!(
            verify_attestation(&att, &truth.ctx()),
            Err(AttestationVerifyError::LifetimeTooLong)
        );
    }

    #[test]
    fn lifetime_exactly_max_passes() {
        // Boundary: a window of exactly the cap is accepted (`>` rejects).
        let (mut att, mut truth, signer) = valid_fixture(TriggerKind::Add);
        att.expires_at = att.issued_at + MAX_KEYPACKAGE_ATTESTATION_LIFETIME;
        sign_in_place(&mut att, &signer);
        truth.not_after = att.expires_at;
        assert_eq!(verify_attestation(&att, &truth.ctx()), Ok(()));
    }

    #[test]
    fn expires_not_after_issued() {
        // Degenerate window (expires == issued); leaf Lifetime matches.
        let (mut att, mut truth, signer) = valid_fixture(TriggerKind::Add);
        att.expires_at = att.issued_at;
        sign_in_place(&mut att, &signer);
        truth.not_after = att.expires_at;
        // `now` must not itself trip Expired before check 13a is reached: put it
        // at the window so `now > expires_at` is false.
        truth.now = att.issued_at;
        assert_eq!(
            verify_attestation(&att, &truth.ctx()),
            Err(AttestationVerifyError::ExpiresNotAfterIssued)
        );
    }

    #[test]
    fn expired() {
        // `now` past expiry (context input, unsigned).
        let (att, mut truth, _s) = valid_fixture(TriggerKind::Add);
        truth.now = EXPIRES + 1;
        assert_eq!(
            verify_attestation(&att, &truth.ctx()),
            Err(AttestationVerifyError::Expired)
        );
    }

    #[test]
    fn issued_in_future_beyond_skew() {
        // issued_at leads `now` by more than the §9.14 skew tolerance.
        let (att, mut truth, _s) = valid_fixture(TriggerKind::Add);
        truth.now = ISSUED - (CLOCK_SKEW_TOLERANCE_SECS + 1);
        assert_eq!(
            verify_attestation(&att, &truth.ctx()),
            Err(AttestationVerifyError::IssuedInFuture)
        );
    }

    #[test]
    fn issued_at_skew_boundary_is_inclusive() {
        // Exactly at the skew boundary (issued_at == now + skew): accepted.
        let (att, mut truth, _s) = valid_fixture(TriggerKind::Add);
        truth.now = ISSUED - CLOCK_SKEW_TOLERANCE_SECS;
        assert_eq!(verify_attestation(&att, &truth.ctx()), Ok(()));
        // One second tighter: rejected.
        truth.now = ISSUED - CLOCK_SKEW_TOLERANCE_SECS - 1;
        assert_eq!(
            verify_attestation(&att, &truth.ctx()),
            Err(AttestationVerifyError::IssuedInFuture)
        );
    }
}

// ==========================================================================
// CRYPTO-22 S4 Layer A — verify_attestation_with_resolution (§9.7.1 checks 1–2)
// ==========================================================================
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod resolution_seam_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    const ISSUED: u64 = 1_700_000_000;
    const EXPIRES: u64 = 1_700_086_400; // ISSUED + 86_400 (1 day)
    const NOW: u64 = 1_700_000_100; // inside [ISSUED, EXPIRES]
    const TEST_DID: &str = "did:dht:z6MkResolveSeamTest";

    /// A fresh random Ed25519 public key (a valid curve point — required by
    /// `decode_multibase_key`, so raw `[u8; 32]` patterns won't do).
    fn fresh_pub() -> [u8; PUBLIC_KEY_SIZE] {
        SigningKey::generate(&mut OsRng).verifying_key().to_bytes()
    }

    /// Whether the fixture models an Add (`KeyPackage`, distinct `init_key`) or an
    /// Update (bare ratchet-tree leaf, `init_key == encryption_key`). Mirrors the
    /// pure-core tests' selector; kept local so this module borrows no private
    /// item from `mod tests`.
    #[derive(Clone, Copy)]
    enum Kind {
        Add,
        Update,
    }

    /// Owned fixture: a fully-valid signed attestation, its leaf ground-truth
    /// material, the signer's keypair, and a resolved DID document whose
    /// `#active` verification method is the signer's current key.
    struct Fx {
        att: KeyPackageAttestation,
        credential: ScpCredential,
        leaf_sig: [u8; PUBLIC_KEY_SIZE],
        leaf_enc: [u8; PUBLIC_KEY_SIZE],
        leaf_wrap: [u8; PUBLIC_KEY_SIZE],
        kp_init: [u8; PUBLIC_KEY_SIZE],
        doc: DidDocument,
        kind: Kind,
    }

    impl Fx {
        fn ground_truth(&self) -> AttestationLeafGroundTruth<'_> {
            AttestationLeafGroundTruth {
                credential: &self.credential,
                leaf_signature_key: &self.leaf_sig,
                leaf_encryption_key: &self.leaf_enc,
                leaf_wrapping_key: &self.leaf_wrap,
                leaf_lifetime_not_before: ISSUED,
                leaf_lifetime_not_after: EXPIRES,
                trigger: match self.kind {
                    Kind::Add => AttestationTrigger::Add {
                        kp_init_key: &self.kp_init,
                    },
                    Kind::Update => AttestationTrigger::Update,
                },
            }
        }
    }

    /// Builds a DID document whose `#active` verification method carries
    /// `active_key` (the pattern `resolve_signing_key` decodes back to 32 bytes).
    fn did_doc_with_active(active_key: &[u8; PUBLIC_KEY_SIZE]) -> DidDocument {
        let identity_key = fresh_pub();
        let commitment = [0u8; 32];
        DidDocument::new(TEST_DID, &identity_key, active_key, &commitment)
    }

    /// A fully-valid `Fx`: the signer's key is the document's current `#active`
    /// key, the attestation is signed over its §9.5.1 hash, and every pure-core
    /// binding (checks 3–13) holds. Callers then perturb ONE input to isolate a
    /// single check.
    fn valid_fixture(kind: Kind) -> Fx {
        let signer = SigningKey::generate(&mut OsRng);
        let signer_pub = signer.verifying_key().to_bytes();
        let leaf_sig = fresh_pub();
        let leaf_enc = fresh_pub();
        let leaf_wrap = fresh_pub();
        let kp_init = fresh_pub();
        let att_init = match kind {
            Kind::Add => kp_init,
            Kind::Update => leaf_enc,
        };
        let mut att = KeyPackageAttestation {
            did: TEST_DID.to_owned(),
            leaf_signature_key: leaf_sig,
            leaf_encryption_key: leaf_enc,
            init_key: att_init,
            wrapping_key: leaf_wrap,
            signing_key_id: SigningKeyId::Active,
            issued_at: ISSUED,
            expires_at: EXPIRES,
            signature: [0u8; SIGNATURE_SIZE],
        };
        att.signature = signer.sign(&att.signing_hash()).to_bytes();
        Fx {
            att,
            credential: ScpCredential::new(TEST_DID.to_owned(), None, SigningKeyId::Active)
                .unwrap(),
            leaf_sig,
            leaf_enc,
            leaf_wrap,
            kp_init,
            doc: did_doc_with_active(&signer_pub),
            kind,
        }
    }

    /// A fully-valid **`#agent`-persona** Add `Fx`: the credential and
    /// attestation both use [`SigningKeyId::Agent`], the attestation is signed by
    /// the **agent** key, and the resolved document carries an *unrelated*
    /// `#active` VM plus (when `include_agent_vm`) an `#agent` VM equal to the
    /// signer's agent key. The unrelated `#active` is the discriminator: a
    /// persona-blind verifier that hardwired `#active` would resolve that
    /// unrelated key and fail check 3, so reaching `Ok` / `CurrentKeyNotFound`
    /// proves the seam resolved the credential-named `#agent` VM.
    fn agent_fixture(include_agent_vm: bool) -> Fx {
        let signer = SigningKey::generate(&mut OsRng);
        let agent_pub = signer.verifying_key().to_bytes();
        let leaf_sig = fresh_pub();
        let leaf_enc = fresh_pub();
        let leaf_wrap = fresh_pub();
        let kp_init = fresh_pub();
        let mut att = KeyPackageAttestation {
            did: TEST_DID.to_owned(),
            leaf_signature_key: leaf_sig,
            leaf_encryption_key: leaf_enc,
            init_key: kp_init,
            wrapping_key: leaf_wrap,
            signing_key_id: SigningKeyId::Agent,
            issued_at: ISSUED,
            expires_at: EXPIRES,
            signature: [0u8; SIGNATURE_SIZE],
        };
        att.signature = signer.sign(&att.signing_hash()).to_bytes();
        // `#active` is an UNRELATED key — the persona discriminator.
        let mut doc = did_doc_with_active(&fresh_pub());
        if include_agent_vm {
            doc.verification_method.push(scp_did::VerificationMethod {
                id: format!("{TEST_DID}#agent"),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: TEST_DID.to_owned(),
                public_key_multibase: format!("z{}", bs58::encode(agent_pub).into_string()),
            });
        }
        Fx {
            att,
            credential: ScpCredential::new(TEST_DID.to_owned(), None, SigningKeyId::Agent).unwrap(),
            leaf_sig,
            leaf_enc,
            leaf_wrap,
            kp_init,
            doc,
            kind: Kind::Add,
        }
    }

    // -- FIX 2: #agent persona resolves the persona-correct VM ----------------

    #[test]
    fn agent_persona_resolves_agent_vm_and_delegates_ok() {
        // Check 1 resolves the `#agent` VM (NOT the unrelated `#active`), and
        // delegation succeeds because the signature verifies against the resolved
        // agent key. Proves the seam reaches the pure core on the agent persona.
        let fx = agent_fixture(true);
        assert_eq!(fx.credential.signing_key_id, SigningKeyId::Agent);
        assert_eq!(
            verify_attestation_with_resolution(&fx.att, &fx.ground_truth(), &fx.doc, NOW, NOW),
            Ok(())
        );
    }

    #[test]
    fn agent_persona_missing_agent_vm_is_current_key_not_found() {
        // The resolved doc lacks an `#agent` VM (only the unrelated `#active`):
        // check 1 must reject with CurrentKeyNotFound — proving the seam resolves
        // the VM named by the credential's signing_key_id (`#agent`), never a
        // hardwired `#active`.
        let fx = agent_fixture(false);
        let err =
            verify_attestation_with_resolution(&fx.att, &fx.ground_truth(), &fx.doc, NOW, NOW)
                .unwrap_err();
        assert_eq!(err, AttestationResolutionVerifyError::CurrentKeyNotFound);
    }

    // -- AC1: the function is pure and callable from a scp-mls unit test -------

    #[test]
    fn valid_add_with_fresh_resolution_passes() {
        let fx = valid_fixture(Kind::Add);
        assert_eq!(
            verify_attestation_with_resolution(&fx.att, &fx.ground_truth(), &fx.doc, NOW, NOW),
            Ok(())
        );
    }

    #[test]
    fn valid_update_with_fresh_resolution_passes() {
        let fx = valid_fixture(Kind::Update);
        assert_eq!(
            verify_attestation_with_resolution(&fx.att, &fx.ground_truth(), &fx.doc, NOW, NOW),
            Ok(())
        );
    }

    // -- AC2: check-2 freshness boundary (300 pass / 301 reject) ---------------

    #[test]
    fn freshness_boundary_300s_passes() {
        // age == MAX_ATTESTATION_KEY_RESOLUTION_STALENESS (300) is accepted (`>`
        // rejects, so the boundary is inclusive).
        let fx = valid_fixture(Kind::Add);
        let resolved_at = NOW - MAX_ATTESTATION_KEY_RESOLUTION_STALENESS; // age = 300
        assert_eq!(
            verify_attestation_with_resolution(
                &fx.att,
                &fx.ground_truth(),
                &fx.doc,
                resolved_at,
                NOW
            ),
            Ok(())
        );
    }

    #[test]
    fn freshness_boundary_301s_rejected_before_verify() {
        // age == 301 > 300 → ResolvedDocumentStale, reached before check 1 and
        // before the pure checks 3–13.
        let fx = valid_fixture(Kind::Add);
        let resolved_at = NOW - (MAX_ATTESTATION_KEY_RESOLUTION_STALENESS + 1); // age = 301
        let err = verify_attestation_with_resolution(
            &fx.att,
            &fx.ground_truth(),
            &fx.doc,
            resolved_at,
            NOW,
        )
        .unwrap_err();
        assert_eq!(
            err,
            AttestationResolutionVerifyError::ResolvedDocumentStale { age_secs: 301 }
        );
    }

    // -- AC3(a): check-1 absent / #retired-* rejection (no verify_attestation) -

    #[test]
    fn current_active_absent_is_current_key_not_found() {
        // The resolved document has NO #active verification method: the signer's
        // key is simply gone. Check 1 rejects WITHOUT delegating to the pure core.
        let mut fx = valid_fixture(Kind::Add);
        fx.doc
            .verification_method
            .retain(|vm| !vm.id.ends_with("#active"));
        let err =
            verify_attestation_with_resolution(&fx.att, &fx.ground_truth(), &fx.doc, NOW, NOW)
                .unwrap_err();
        assert_eq!(err, AttestationResolutionVerifyError::CurrentKeyNotFound);
        // Prove the pure core was NOT reached: a Delegated(..) variant would mean
        // verify_attestation ran.
        assert!(
            !matches!(err, AttestationResolutionVerifyError::Delegated(_)),
            "check 1 must reject before delegating to verify_attestation"
        );
    }

    #[test]
    fn current_active_retired_is_current_key_not_found() {
        // Model rotation-is-revocation (§9.12): the signer's key survives in the
        // document ONLY under a #retired-1 fragment (the current #active is gone).
        // `resolve_signing_key("active")` finds nothing → CurrentKeyNotFound, and
        // the pure core is never reached.
        let mut fx = valid_fixture(Kind::Add);
        for vm in &mut fx.doc.verification_method {
            if vm.id.ends_with("#active") {
                vm.id = format!("{TEST_DID}#retired-1");
            }
        }
        let err =
            verify_attestation_with_resolution(&fx.att, &fx.ground_truth(), &fx.doc, NOW, NOW)
                .unwrap_err();
        assert_eq!(err, AttestationResolutionVerifyError::CurrentKeyNotFound);
        assert!(!matches!(
            err,
            AttestationResolutionVerifyError::Delegated(_)
        ));
    }

    // -- AC3(b): rotated-away-but-PRESENT key → delegated SignatureInvalid -----

    #[test]
    fn rotated_but_present_key_is_delegated_signature_invalid() {
        // The document's current #active is a DIFFERENT key than the one that
        // signed (the signer rotated; a fresh #active is present). Check 1 passes
        // (an #active VM exists) but the pure core's check 3 fails: the signature
        // does not verify against the resolved CURRENT key.
        let mut fx = valid_fixture(Kind::Add);
        fx.doc = did_doc_with_active(&fresh_pub()); // a new, unrelated #active key
        let err =
            verify_attestation_with_resolution(&fx.att, &fx.ground_truth(), &fx.doc, NOW, NOW)
                .unwrap_err();
        assert_eq!(
            err,
            AttestationResolutionVerifyError::Delegated(AttestationVerifyError::SignatureInvalid)
        );
    }

    // -- AC4: check-2 is enforced BEFORE check-1 and before checks 3–13 --------

    #[test]
    fn staleness_takes_precedence_over_a_valid_current_key() {
        // A 301s-stale document that ALSO carries a perfectly valid current key
        // (checks 1 and 3–13 would all pass) must still fail with the staleness
        // error — never a check-1 or checks-3–13 error.
        let fx = valid_fixture(Kind::Add);
        // Sanity: with a FRESH resolution this exact fixture verifies Ok, so any
        // failure below is attributable solely to staleness ordering.
        assert_eq!(
            verify_attestation_with_resolution(&fx.att, &fx.ground_truth(), &fx.doc, NOW, NOW),
            Ok(())
        );
        let resolved_at = NOW - (MAX_ATTESTATION_KEY_RESOLUTION_STALENESS + 1); // age = 301
        let err = verify_attestation_with_resolution(
            &fx.att,
            &fx.ground_truth(),
            &fx.doc,
            resolved_at,
            NOW,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                AttestationResolutionVerifyError::ResolvedDocumentStale { .. }
            ),
            "stale document must fail check 2 first, got {err:?}"
        );
    }

    // -- AC5-style: a checks-4..13 failure surfaces the EXACT unchanged variant -

    #[test]
    fn delegated_check4_leaf_signature_key_mismatch_surfaces_verbatim() {
        // Flip the leaf's actual signature_key (a context-only input): check 2 and
        // check 1 pass, then the pure core's check 4 fails. The wrapped
        // AttestationVerifyError must surface verbatim through Delegated(..).
        let mut fx = valid_fixture(Kind::Add);
        fx.leaf_sig = fresh_pub();
        let err =
            verify_attestation_with_resolution(&fx.att, &fx.ground_truth(), &fx.doc, NOW, NOW)
                .unwrap_err();
        assert_eq!(
            err,
            AttestationResolutionVerifyError::Delegated(
                AttestationVerifyError::LeafSignatureKeyMismatch
            )
        );
    }

    #[test]
    fn delegated_check13_expired_surfaces_verbatim() {
        // A check-13 (freshness/expiry) failure also delegates verbatim: `now`
        // past the attestation's expiry with a FRESH resolution (resolved_at ==
        // now, so check 2 passes) yields Delegated(Expired), proving the whole
        // 3–13 band is delegated, not just early checks.
        let fx = valid_fixture(Kind::Add);
        let now = EXPIRES + 1;
        let err = verify_attestation_with_resolution(
            &fx.att,
            &fx.ground_truth(),
            &fx.doc,
            now, // resolved_at == now ⇒ age 0 ⇒ check 2 passes
            now,
        )
        .unwrap_err();
        assert_eq!(
            err,
            AttestationResolutionVerifyError::Delegated(AttestationVerifyError::Expired)
        );
    }
}
