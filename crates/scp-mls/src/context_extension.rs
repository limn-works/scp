//! MLS `group_context` `scp_context_params` extension helpers (spec §5.13.3).
//!
//! Every SCP context binds its parameters into the MLS group's `group_context`
//! via a custom extension (IANA private-use type ID `0xFF02`, RFC 9420 §17.3)
//! whose `ExtensionData` is the RFC 8785 (JCS) canonical-JSON encoding of an
//! [`ScpContextExtension`]. Because the `group_context` is folded into the MLS
//! key schedule and the confirmation tag, the committed parameters are
//! cryptographically bound to the group: they cannot be silently altered after
//! creation, and any member — including a Welcome-based joiner — reads the same
//! bytes the creator committed.
//!
//! This closes finding **FFI-02**: a joiner must not build authority from
//! parameters it merely received out-of-band from the (untrusted) caller. It
//! reads [`ScpContextExtension`] out of `group_context` here and verifies it
//! against the context's declared parameters via
//! [`ScpContextExtension::verify_against`].
//!
//! # Layering
//!
//! [`ScpContextExtension`] and its canonical encoding / verification predicate
//! are the pure protocol layer (`scp_protocol::context`). This module is the MLS
//! glue: it wraps the canonical bytes in an `Extension::Unknown`, attaches it to
//! a group's `group_context` at creation (via
//! [`create_group_with_context`](crate::group::create_group_with_context)), and
//! reads it back off any member's replicated `group_context`
//! ([`ScpMlsGroup::group_context_extension`]). The creator/joiner orchestration
//! (deciding *which* [`ScpContextExtension`] to commit and calling
//! `verify_against`) lives in `scp-runtime`.
//!
//! # Extension type ID
//!
//! Uses `0xFF02` from the RFC 9420 §17.3 private-use range (`0xFF00`-`0xFFFF`),
//! sourced from the single canonical constant
//! [`scp_protocol::context::SCP_CONTEXT_EXTENSION_TYPE_ID`]. Unlike the
//! `scp_wrapping_key` `LeafNode` extension (`0xFF01`), this is a **`group_context`
//! extension**: it lives once on the group rather than once per leaf.
//!
//! # Member capabilities and `RequiredCapabilities`
//!
//! Every member's leaf declares the `0xFF02` type in its [`Capabilities`]
//! ([`scp_capabilities_with_context_params`]). This is **mandatory**, not
//! cosmetic: `OpenMLS` rejects an Add proposal (RFC 9420 §12.1.8.2, `valn0502`)
//! unless the joiner's leaf supports *every* extension present in the group's
//! `group_context`. A context-group joiner must therefore present a `KeyPackage`
//! minted by
//! [`prepare_key_package`](crate::keypackage_mint::prepare_key_package) and
//! [`finish_key_package`](crate::keypackage_mint::finish_key_package),
//! whose leaf declares `0xFF02`; a wrapping-key-only `KeyPackage` (which declares
//! only `0xFF01`) is rejected. The creator's own leaf gets the declaration from
//! [`create_group_with_context`](crate::group::create_group_with_context).
//!
//! The `0xFF02` type is deliberately **not** additionally placed in a
//! `RequiredCapabilitiesExtension`. `valn0502` already guarantees every member
//! supports it, so a `RequiredCapabilities` entry would be redundant, and it
//! would pull `0xFF02` into the stricter GroupContextExtensions-proposal
//! validation machinery for no benefit.
//!
//! See spec §5.13.3 and `.docs/specs/05-contexts.md`.

use openmls::group::GroupContext;
use openmls::prelude::*;

use scp_protocol::context::{SCP_CONTEXT_EXTENSION_TYPE_ID, ScpContextExtension};

use crate::error::MlsError;
use crate::group::ScpMlsGroup;
use crate::wrapping_extension::SCP_WRAPPING_KEY_EXTENSION_TYPE;

/// Builds an `Extension::Unknown` for the `scp_context_params` `group_context`
/// extension from an [`ScpContextExtension`].
///
/// The extension's `ExtensionData` is the RFC 8785 (JCS) canonical-JSON encoding
/// of `ext`, produced by [`ScpContextExtension::to_canonical_bytes`]. The type ID
/// is [`SCP_CONTEXT_EXTENSION_TYPE_ID`] (`0xFF02`).
///
/// # Errors
///
/// Returns [`MlsError::ExtensionError`] if the extension cannot be canonically
/// serialized.
pub fn make_context_params_extension(ext: &ScpContextExtension) -> Result<Extension, MlsError> {
    let bytes = ext.to_canonical_bytes().map_err(|e| {
        MlsError::ExtensionError(format!("encoding scp_context_params extension: {e}"))
    })?;
    Ok(Extension::Unknown(
        SCP_CONTEXT_EXTENSION_TYPE_ID,
        UnknownExtension(bytes),
    ))
}

/// Builds the `Extensions<GroupContext>` set to hand to
/// [`MlsGroupCreateConfig`]'s `with_group_context_extensions`, containing exactly
/// the `scp_context_params` (`0xFF02`) extension.
///
/// # Errors
///
/// Returns [`MlsError::ExtensionError`] if the extension cannot be canonically
/// serialized, or if the single-element extension set cannot be constructed
/// (e.g. `0xFF02` is somehow not valid in a `group_context`).
pub fn group_context_extensions(
    ext: &ScpContextExtension,
) -> Result<Extensions<GroupContext>, MlsError> {
    let extension = make_context_params_extension(ext)?;
    Extensions::<GroupContext>::single(extension)
        .map_err(|e| MlsError::ExtensionError(format!("building group_context extension set: {e}")))
}

/// Extracts the [`ScpContextExtension`] from a group's `group_context` extension
/// set, if the `scp_context_params` (`0xFF02`) extension is present.
///
/// Returns `Ok(None)` when the extension is absent (e.g. a wrapping-key-only
/// group created before context binding was wired). Returns an error only when
/// the `0xFF02` extension *is* present but its `ExtensionData` is not the
/// canonical encoding of an [`ScpContextExtension`].
///
/// # Errors
///
/// Returns [`MlsError::ExtensionError`] if the `0xFF02` extension is present but
/// its payload fails canonical decoding.
pub fn extract_context_params(
    exts: &Extensions<GroupContext>,
) -> Result<Option<ScpContextExtension>, MlsError> {
    match exts.unknown(SCP_CONTEXT_EXTENSION_TYPE_ID) {
        None => Ok(None),
        Some(unknown) => {
            let ext = ScpContextExtension::from_canonical_bytes(&unknown.0).map_err(|e| {
                MlsError::ExtensionError(format!("decoding scp_context_params extension: {e}"))
            })?;
            Ok(Some(ext))
        }
    }
}

/// Builds [`Capabilities`] declaring support for both SCP extension types.
///
/// Declares the `scp_wrapping_key` `LeafNode` extension (`0xFF01`) and the
/// `scp_context_params` `group_context` extension (`0xFF02`), in addition to the
/// SCP ciphersuite defaults.
///
/// A context group carries both: a `0xFF01` `LeafNode` extension (each member's
/// wrapping key) and a `0xFF02` `group_context` extension (the shared context
/// parameters). Both declarations are required. `OpenMLS` validates (`valn0107`)
/// that any extension present on a `LeafNode` has its type listed in that node's
/// capabilities, so `0xFF01` is required for the wrapping-key leaf; and it
/// rejects an Add proposal (`valn0502`) unless the joiner's leaf supports every
/// `group_context` extension, so `0xFF02` is required to join a context group
/// (spec §5.13.3, RFC 9420 §7.2, §12.1.8.2).
///
/// This is the context-group counterpart of
/// [`scp_capabilities_with_wrapping_key`](crate::wrapping_extension::scp_capabilities_with_wrapping_key),
/// which declares only `0xFF01` for wrapping-key-only groups.
#[must_use]
pub fn scp_capabilities_with_context_params() -> Capabilities {
    Capabilities::new(
        None, // default versions
        None, // default ciphersuites
        Some(&[
            ExtensionType::Unknown(SCP_WRAPPING_KEY_EXTENSION_TYPE),
            ExtensionType::Unknown(SCP_CONTEXT_EXTENSION_TYPE_ID),
        ]),
        None, // default proposals
        None, // default credentials
    )
}

impl ScpMlsGroup {
    /// Reads the [`ScpContextExtension`] committed into this group's
    /// `group_context`, if present.
    ///
    /// This is the joiner's (and any member's) read path: it inspects the
    /// replicated `group_context` extensions — the same bytes the creator
    /// committed and that every member's key schedule is bound to — and decodes
    /// the `scp_context_params` (`0xFF02`) extension. The `scp-runtime` layer
    /// then calls [`ScpContextExtension::verify_against`] to check the committed
    /// parameters against the context's declared identity and parameters
    /// (spec §5.13.3, finding FFI-02).
    ///
    /// Returns `Ok(None)` for a group with no `0xFF02` extension (e.g. a
    /// wrapping-key-only group).
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
    /// Returns [`MlsError::ExtensionError`] if the `0xFF02` extension is present
    /// but its payload fails canonical decoding.
    pub fn group_context_extension(&self) -> Result<Option<ScpContextExtension>, MlsError> {
        let exts = self.inner()?.extensions();
        extract_context_params(exts)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::panic
)]
mod tests {
    use super::*;

    use crate::keypackage_mint::mint_key_package_for_testing;
    use ed25519_dalek::SigningKey;
    use openmls_basic_credential::SignatureKeyPair;
    use rand::rngs::OsRng;
    use scp_clock::SystemClock;
    use scp_did::DID;
    use scp_protocol::context::params::{CeilingPolicy, ContextMode};
    use scp_protocol::context::roles::{Capability, CapabilityCeiling};
    use scp_protocol::context::{GovernanceModel, ScpContextExtension};

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    fn test_credential(name: &str) -> crate::credential::ScpCredential {
        crate::credential::ScpCredential::new(
            format!("did:dht:z6Mk{name}"),
            None,
            scp_did::SigningKeyId::Active,
        )
        .unwrap()
    }

    fn sample_context_extension(context_id: &str) -> ScpContextExtension {
        let governance = GovernanceModel::Threshold {
            threshold: 2,
            signers: vec![
                DID::from("did:dht:z6MkAlice".to_owned()),
                DID::from("did:dht:z6MkBob".to_owned()),
            ],
        };
        let ceiling = CapabilityCeiling::new([Capability::MessagesRead, Capability::MessagesWrite]);
        ScpContextExtension::for_root(
            context_id.to_owned(),
            DID::from("did:dht:z6MkAlice".to_owned()),
            ContextMode::Encrypted,
            &governance,
            CeilingPolicy::Immutable,
            &ceiling,
        )
        .unwrap()
    }

    // -----------------------------------------------------------------------
    // Pure helper unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn make_and_extract_context_params_roundtrip() {
        let ext = sample_context_extension("ctx:roundtrip");
        let extension = make_context_params_extension(&ext).unwrap();

        assert_eq!(
            extension.extension_type(),
            ExtensionType::Unknown(SCP_CONTEXT_EXTENSION_TYPE_ID),
            "extension must carry the 0xFF02 type id"
        );

        let exts = Extensions::<GroupContext>::single(extension).unwrap();
        let extracted = extract_context_params(&exts).unwrap();
        assert_eq!(extracted, Some(ext));
    }

    #[test]
    fn extract_context_params_returns_none_when_absent() {
        let exts = Extensions::<GroupContext>::default();
        let extracted = extract_context_params(&exts).unwrap();
        assert_eq!(extracted, None);
    }

    #[test]
    fn extract_context_params_rejects_malformed_payload() {
        let extension = Extension::Unknown(
            SCP_CONTEXT_EXTENSION_TYPE_ID,
            UnknownExtension(b"not canonical json".to_vec()),
        );
        let exts = Extensions::<GroupContext>::single(extension).unwrap();
        let result = extract_context_params(&exts);
        assert!(
            matches!(result, Err(MlsError::ExtensionError(_))),
            "malformed 0xFF02 payload must yield ExtensionError, got {result:?}"
        );
    }

    #[test]
    fn scp_capabilities_declares_both_scp_extension_types() {
        let caps = scp_capabilities_with_context_params();
        assert!(
            caps.extensions()
                .contains(&ExtensionType::Unknown(SCP_WRAPPING_KEY_EXTENSION_TYPE)),
            "capabilities must declare the 0xFF01 wrapping-key extension type"
        );
        assert!(
            caps.extensions()
                .contains(&ExtensionType::Unknown(SCP_CONTEXT_EXTENSION_TYPE_ID)),
            "capabilities must declare the 0xFF02 context-params extension type"
        );
    }

    // -----------------------------------------------------------------------
    // MLS group integration: creator read-back
    // -----------------------------------------------------------------------

    /// The creator's own `group_context` carries the committed extension,
    /// byte-identical to what was embedded.
    #[test]
    fn create_group_with_context_embeds_extension_for_creator() {
        let cred = test_credential("alice");
        let wrapping_key = [0xAA_u8; 32];
        let ctx_ext = sample_context_extension("ctx:creator");

        let group =
            crate::group::create_group_with_context(&cred, &wrapping_key, &ctx_ext, &SystemClock)
                .unwrap();

        let read_back = group.group_context_extension().unwrap();
        assert_eq!(
            read_back,
            Some(ctx_ext),
            "creator's group_context must contain the committed ScpContextExtension"
        );
    }

    /// A wrapping-key-only group has no `0xFF02` extension: the reader returns
    /// `None` (not an error).
    #[test]
    fn wrapping_only_group_has_no_context_extension() {
        let cred = test_credential("alice");
        let wrapping_key = [0xAA_u8; 32];
        let group =
            crate::group::create_group_with_wrapping_key(&cred, Some(&wrapping_key), &SystemClock)
                .unwrap();

        let read_back = group.group_context_extension().unwrap();
        assert_eq!(
            read_back, None,
            "a wrapping-key-only group must not report a context extension"
        );
    }

    /// Regression for the OpenMLS `valn0502` requirement: a wrapping-key-only
    /// `KeyPackage` (leaf declares only `0xFF01`) cannot be added to a context
    /// group, because its leaf does not support the `0xFF02` `group_context`
    /// extension. Joiners must present a `KeyPackage` minted by
    /// [`prepare_key_package`](crate::keypackage_mint::prepare_key_package) and
    /// [`finish_key_package`](crate::keypackage_mint::finish_key_package), whose
    /// leaf declares all three SCP extension types.
    #[test]
    fn wrapping_only_key_package_rejected_by_context_group() {
        let alice_cred = test_credential("alice");
        let alice_wrapping = [0xAA_u8; 32];
        let ctx_ext = sample_context_extension("ctx:valn0502");
        let mut alice_group = crate::group::create_group_with_context(
            &alice_cred,
            &alice_wrapping,
            &ctx_ext,
            &SystemClock,
        )
        .unwrap();

        // Bob's key package declares only 0xFF01 (wrapping key), not 0xFF02.
        // `mint_key_package_for_testing` cannot produce it: the mint declares
        // all three SCP extension types unconditionally, which is exactly the
        // property this test denies its fixture. The leaf is therefore built
        // here directly, with the 0xFF01-only capability set and the 0xFF01
        // wrapping-key leaf extension.
        let bob_cred = test_credential("bob");
        let bob_wrapping = [0xBB_u8; 32];
        let bob_provider = crate::InMemoryMlsProvider::default();
        let bob_signer =
            SignatureKeyPair::new(crate::group::SCP_CIPHERSUITE.signature_algorithm()).unwrap();
        bob_signer.store(bob_provider.storage()).unwrap();
        let bob_kp = KeyPackage::builder()
            .leaf_node_capabilities(crate::wrapping_extension::scp_capabilities_with_wrapping_key())
            .leaf_node_extensions(
                Extensions::<LeafNode>::single(
                    crate::wrapping_extension::make_wrapping_key_extension(&bob_wrapping),
                )
                .unwrap(),
            )
            .key_package_lifetime(crate::lifetime::key_package_lifetime(&SystemClock))
            .build(
                crate::group::SCP_CIPHERSUITE,
                &bob_provider,
                &bob_signer,
                CredentialWithKey {
                    credential: BasicCredential::new(bob_cred.to_bytes().unwrap()).into(),
                    signature_key: bob_signer.to_public_vec().into(),
                },
            )
            .unwrap();
        assert!(
            !bob_kp
                .key_package()
                .leaf_node()
                .capabilities()
                .extensions()
                .contains(&ExtensionType::Unknown(SCP_CONTEXT_EXTENSION_TYPE_ID)),
            "the fixture leaf must NOT declare 0xFF02, or the test proves nothing"
        );
        let bob_kp_in: KeyPackageIn = bob_kp.key_package().clone().into();

        match crate::group::add_member(&mut alice_group, bob_kp_in, &SystemClock) {
            Err(MlsError::AddMemberFailed(_)) => {}
            Err(other) => panic!("expected AddMemberFailed, got {other:?}"),
            Ok(_) => {
                panic!("a leaf without 0xFF02 support must be rejected from a context group")
            }
        }
    }

    /// The leaf-level invariant behind the reserve / plain-join fix: a minted
    /// `KeyPackage` declares the `0xFF02` (`scp_context_params`) capability —
    /// that capability is what `valn0502` checks and what makes the KP addable
    /// to an encrypted context group — and carries the `0xFF01` wrapping-key
    /// LEAF extension holding the key the caller passed. Two independently
    /// minted `KeyPackage`s are checked, so the properties hold per mint rather
    /// than for one lucky draw.
    ///
    /// The mint takes a required wrapping key (§9.5.2 field 5 binds the `0xFF01`
    /// value into the attestation), so there is no wrapping-key-less minted leaf
    /// to check. `mint_key_package_for_testing` replaced
    /// `generate_key_package_with_context_params`, whose `None` arm produced a
    /// leaf that declared `0xFF02` and carried no `0xFF01` extension.
    #[test]
    fn minted_key_package_declares_0xff02_capability_and_carries_its_wrapping_key() {
        for (name, wrapping) in [
            ("kp-caps-first", [0x5A_u8; 32]),
            ("kp-caps-second", [0xA5_u8; 32]),
        ] {
            let cred = test_credential(name);
            let att_key = SigningKey::generate(&mut OsRng);
            let (kp, _s, _p) =
                mint_key_package_for_testing(&cred, &wrapping, &SystemClock, &att_key).unwrap();
            let caps = kp.key_package().leaf_node().capabilities();
            assert!(
                caps.extensions()
                    .contains(&ExtensionType::Unknown(SCP_CONTEXT_EXTENSION_TYPE_ID)),
                "a minted KP MUST declare the 0xFF02 capability (valn0502): {name}"
            );
            assert!(
                caps.extensions()
                    .contains(&ExtensionType::Unknown(SCP_WRAPPING_KEY_EXTENSION_TYPE)),
                "a minted KP declares the 0xFF01 capability: {name}"
            );
            assert_eq!(
                crate::wrapping_extension::extract_wrapping_key(
                    kp.key_package().leaf_node().extensions()
                )
                .unwrap(),
                Some(wrapping),
                "a minted KP carries the 0xFF01 leaf extension holding the key it was minted with: \
                 {name}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // MLS group integration: through-join (the FFI-02 read path)
    // -----------------------------------------------------------------------

    /// AC (rules 1/2 substrate): a Welcome-based joiner reads the *same*
    /// [`ScpContextExtension`] the creator committed into `group_context`,
    /// byte-identical.
    #[test]
    fn context_extension_survives_welcome_join() {
        let alice_cred = test_credential("alice");
        let alice_wrapping = [0xAA_u8; 32];
        let ctx_ext = sample_context_extension("ctx:through-join");

        let mut alice_group = crate::group::create_group_with_context(
            &alice_cred,
            &alice_wrapping,
            &ctx_ext,
            &SystemClock,
        )
        .unwrap();

        let bob_cred = test_credential("bob");
        let bob_wrapping = [0xBB_u8; 32];
        let (bob_kp, bob_signer, bob_provider) = mint_key_package_for_testing(
            &bob_cred,
            &bob_wrapping,
            &SystemClock,
            &SigningKey::generate(&mut OsRng),
        )
        .unwrap();

        let bob_kp_in: KeyPackageIn = bob_kp.key_package().clone().into();
        let add_result =
            crate::group::add_member(&mut alice_group, bob_kp_in, &SystemClock).unwrap();

        let bob_group =
            crate::group::join_group(&add_result.welcome, bob_provider, bob_signer).unwrap();

        // The joiner recovers the committed extension from the replicated
        // group_context — the FFI-02 read path.
        let bob_read = bob_group.group_context_extension().unwrap();
        assert_eq!(
            bob_read,
            Some(ctx_ext.clone()),
            "joiner must read the creator's committed ScpContextExtension"
        );

        // And it is byte-identical to the creator's own view.
        assert_eq!(
            bob_group.group_context_extension().unwrap(),
            alice_group.group_context_extension().unwrap(),
            "joiner and creator must observe identical context extensions"
        );

        // Byte-for-byte identity on the canonical wire encoding.
        assert_eq!(
            bob_read.unwrap().to_canonical_bytes().unwrap(),
            ctx_ext.to_canonical_bytes().unwrap(),
            "canonical bytes must match exactly"
        );
    }

    /// AC (OpenMLS uncertainty flagged by the plan): the `group_context`
    /// extension survives *later* commits. Add a second member (epoch advance),
    /// have the first joiner process that commit, and confirm every member still
    /// reads the original extension.
    #[test]
    fn context_extension_survives_later_commits() {
        let alice_cred = test_credential("alice");
        let alice_wrapping = [0xAA_u8; 32];
        let ctx_ext = sample_context_extension("ctx:multi-commit");

        let mut alice_group = crate::group::create_group_with_context(
            &alice_cred,
            &alice_wrapping,
            &ctx_ext,
            &SystemClock,
        )
        .unwrap();

        // Add Bob (epoch 1).
        let bob_cred = test_credential("bob");
        let bob_wrapping = [0xBB_u8; 32];
        let (bob_kp, bob_signer, bob_provider) = mint_key_package_for_testing(
            &bob_cred,
            &bob_wrapping,
            &SystemClock,
            &SigningKey::generate(&mut OsRng),
        )
        .unwrap();
        let bob_kp_in: KeyPackageIn = bob_kp.key_package().clone().into();
        let add_bob = crate::group::add_member(&mut alice_group, bob_kp_in, &SystemClock).unwrap();
        let mut bob_group =
            crate::group::join_group(&add_bob.welcome, bob_provider, bob_signer).unwrap();

        // Add Carol (epoch 2) — a later commit distributed to existing members.
        let carol_cred = test_credential("carol");
        let carol_wrapping = [0xCC_u8; 32];
        let (carol_kp, _carol_signer, _carol_provider) = mint_key_package_for_testing(
            &carol_cred,
            &carol_wrapping,
            &SystemClock,
            &SigningKey::generate(&mut OsRng),
        )
        .unwrap();
        let carol_kp_in: KeyPackageIn = carol_kp.key_package().clone().into();
        let add_carol =
            crate::group::add_member(&mut alice_group, carol_kp_in, &SystemClock).unwrap();

        // Bob processes the Carol-add commit to advance to epoch 2.
        let commit_bytes = crate::ratchet::serialize_mls_message(&add_carol.commit).unwrap();
        let mut grace_store = crate::epoch_grace::EpochGraceStore::new();
        crate::ratchet::process_commit(&mut bob_group, &commit_bytes, &mut grace_store).unwrap();

        assert_eq!(
            alice_group.epoch().unwrap(),
            2,
            "alice at epoch 2 after two adds"
        );
        assert_eq!(bob_group.epoch().unwrap(), 2, "bob advanced to epoch 2");

        // The context extension is unchanged for both members after the later
        // commit.
        assert_eq!(
            alice_group.group_context_extension().unwrap(),
            Some(ctx_ext.clone()),
            "creator's context extension must survive later commits"
        );
        assert_eq!(
            bob_group.group_context_extension().unwrap(),
            Some(ctx_ext),
            "joiner's context extension must survive later commits it processed"
        );
    }
}
