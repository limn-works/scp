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
//! crate-internal (`pub(crate)`): it exists only to build the hash and to
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
use scp_did::SigningKeyId;
use scp_protocol::crypto::canonical::{CanonicalField, canonical_hash_bytes};
use sha2::{Digest, Sha256};

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
pub enum AttestationTrigger {
    /// A new leaf is being **added** via a `KeyPackage` (the cross-group
    /// fail-closed path; the only trigger at which the `init_key` checks apply).
    Add,
    /// An already-admitted member is **replacing its own leaf** (Update /
    /// Commit-with-`UpdatePath`).
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
    /// Crate-internal: the only external signable output is
    /// [`signing_hash`](Self::signing_hash). This method exists to build that
    /// hash and to reproduce the §25.23 Vector 37 known-answer test.
    ///
    /// Infallible: the shared builder only errors on a >`u32::MAX` `VarBytes`
    /// field (`did`/`signing_key_id` are orders of magnitude smaller), so
    /// `unwrap_or_default` is a total function here and never panics.
    #[must_use]
    pub(crate) fn signing_preimage(&self) -> Vec<u8> {
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
}
