//! SCP Context Parameters MLS `group_context` extension (spec §5.13.3).
//!
//! Every SCP MLS group carries a custom `group_context` extension (IANA
//! private-use type ID `0xFF02`, RFC 9420 §17.3) whose `ExtensionData` is the
//! RFC 8785 (JCS) canonical-JSON encoding of an [`ScpContextExtension`]. Binding
//! the context's parameters into the MLS group identity makes them part of the
//! `group_id` derivation, so they are cryptographically committed and cannot be
//! silently altered after the group is created.
//!
//! This closes finding **FFI-02**: on a Welcome-based join, a joiner must not
//! build authority from parameters it merely received out-of-band from the
//! (untrusted) caller. Instead, the joiner recomputes the parameter hashes from
//! the context's declared parameters and checks them against the values the
//! group creator committed into `group_context` via [`ScpContextExtension`].
//! [`ScpContextExtension::verify_against`] performs that check (spec §5.13.3
//! validation rules 2-6 plus the creator-DID binding, rule 8).
//!
//! # Creator (genesis-admin) binding
//!
//! The extension also commits the group's **genesis `creator_did`** (rule 8).
//! For a DID-less governance model such as [`GovernanceModel::SingleAdmin`] the
//! `governance_policy_hash` is a *constant* — it carries no identity — so
//! without a committed creator a joiner has no cryptographic proof that the
//! `creator_did` its (untrusted) inviter supplied is the group's real
//! creator/admin. Committing `creator_did` into the `0xFF02` extension (part of
//! the group's committed cryptographic identity, immutable in `group_context`)
//! lets every joiner prove "this group's genesis creator is X" and refuse a
//! bundle that names any other admin. The committed value pins the **genesis**
//! creator (the initial `SingleAdmin` admin); admin *transfers* are not tracked
//! here — they apply from the authenticated event log AFTER join.
//!
//! This module is the pure protocol layer: the type, its canonical encoding,
//! the hash constructors, and the verification predicate. The MLS glue (writing
//! the extension into / reading it out of the `group_context`) lives in
//! `scp-mls`; the creator/joiner wiring lives in `scp-runtime`.
//!
//! # Canonical hashing
//!
//! All hashes are `SHA-256(RFC-8785-JCS(value))`, mirroring
//! [`ParentGovernanceConfig::content_hash`](super::nesting::ParentGovernanceConfig::content_hash)
//! and the cross-implementation canonical-hashing mandate in §9.5. JCS gives a
//! byte-identical serialization across independent implementations; SHA-256 over
//! those bytes yields a hash any conforming implementation reproduces exactly.
//!
//! See spec §5.13.3 and `.docs/specs/05-contexts.md`.

use scp_did::DID;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::nesting::{ContextId, ParentGovernanceConfig, ParentRef};
use super::params::{CeilingPolicy, ContextMode, ContextParams, GovernanceModel};
use super::roles::CapabilityCeiling;

/// MLS `group_context` extension type ID for SCP context parameters.
///
/// `0xFF02` is in the IANA private-use range for MLS extension types
/// (`0xFF00`-`0xFFFF`, RFC 9420 §17.3). If SCP registers with IANA, an assigned
/// value will be introduced and accepted alongside this one during a transition
/// period (spec §5.13.3, "Extension type ID"). Defining it here gives the
/// `scp-mls` layer a single canonical source for the constant.
pub const SCP_CONTEXT_EXTENSION_TYPE_ID: u16 = 0xFF02;

/// The largest `creation_timestamp_secs` an `0xFF02` extension may carry.
///
/// The value is 2^53 − 1 (spec §5.13.3 "Serialization"). RFC 8785 writes every
/// number as an IEEE 754 double, which holds every integer up to this value
/// exactly.
pub const MAX_CREATION_TIMESTAMP_SECS: u64 = (1 << 53) - 1;

/// How far past a member's own clock a committed `creation_timestamp_secs`
/// may lie.
///
/// This is the 5-minute future bound of `09-security-model.md` §9.8.2, which
/// spec §5.13.3 rule 9 applies to the committed creation timestamp.
pub const CREATION_TIMESTAMP_FUTURE_BOUND_SECS: u64 = 300;

// ---------------------------------------------------------------------------
// ScpContextBindingError
// ---------------------------------------------------------------------------

/// Failure kinds for [`ScpContextExtension::verify_against`] and the canonical
/// encode/decode helpers.
///
/// The mismatch variants correspond to spec §5.13.3 validation rules 2-6 plus
/// the creator-DID binding (rule 8). The runtime maps them onto its own
/// `ContextError` when a Welcome-based join is rejected. The two infrastructural
/// variants ([`SerializationFailed`] / [`DeserializationFailed`]) surface
/// canonical-JSON failures — they are kept distinct from the semantic mismatches
/// because they signal an internal / wire-format fault rather than a
/// parameter-binding violation, and neither may be discarded with an `unwrap`
/// (§ "No shortcuts").
///
/// [`SerializationFailed`]: ScpContextBindingError::SerializationFailed
/// [`DeserializationFailed`]: ScpContextBindingError::DeserializationFailed
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScpContextBindingError {
    /// Rule 2: the extension's `context_id` does not match the context's
    /// declared identity.
    #[error("context_id mismatch: extension binds {expected:?}, context is {actual:?}")]
    ContextIdMismatch {
        /// The `context_id` committed in the extension.
        expected: ContextId,
        /// The context's actual declared identity.
        actual: ContextId,
    },

    /// Rule 8: the extension's committed `creator_did` does not match the
    /// creator/admin DID the joiner presents (the bundle's `creator_did` on a
    /// Welcome-based join; the snapshot's `role_state.creator_did` on
    /// import/restore).
    ///
    /// The committed value pins the group's **genesis** creator/admin. This is
    /// the sole cryptographic anchor of admin identity for DID-less governance
    /// models (e.g. [`GovernanceModel::SingleAdmin`], whose
    /// `governance_policy_hash` is a constant): a mismatch means the presented
    /// creator is NOT the party the group committed at creation, so no authority
    /// may be built for them.
    #[error("creator DID mismatch: extension binds {expected}, presented {actual}")]
    CreatorMismatch {
        /// The genesis `creator_did` committed in the extension.
        expected: DID,
        /// The `creator_did` the joiner presented.
        actual: DID,
    },

    /// Rule 3: `governance_policy_hash` does not match
    /// `SHA-256(JCS(params.governance))`.
    #[error("governance policy hash does not match the context's declared governance model")]
    GovernanceHashMismatch,

    /// Rule 4: `ceiling_hash` does not match
    /// `SHA-256(JCS(capability_ceiling))`.
    #[error("ceiling hash does not match the context's declared capability ceiling")]
    CeilingHashMismatch,

    /// Rule 4: `ceiling_policy` does not match `params.ceiling_policy`.
    #[error("ceiling policy mismatch: extension={extension}, params={params}")]
    CeilingPolicyMismatch {
        /// The `ceiling_policy` byte committed in the extension.
        extension: u8,
        /// The `ceiling_policy` byte derived from the context's parameters.
        params: u8,
    },

    /// Rule 4: `context_mode` does not match `params.mode`.
    #[error("context mode mismatch: extension={extension}, params={params}")]
    ModeMismatch {
        /// The `context_mode` byte committed in the extension.
        extension: u8,
        /// The `context_mode` byte derived from the context's parameters.
        params: u8,
    },

    /// Rules 5-6: the root/child parent structure is malformed (a root carries
    /// parent data, a child is missing it, or `parent_context_ids` is not
    /// sorted lexicographically without duplicates).
    #[error("parent structure invalid: {reason}")]
    ParentStructureInvalid {
        /// Human-readable description of the structural violation.
        reason: String,
    },

    /// Spec §5.13.3 "Serialization": `creation_timestamp_secs` is above
    /// [`MAX_CREATION_TIMESTAMP_SECS`] (2^53 − 1), a value RFC 8785 cannot
    /// write exactly.
    #[error("creation_timestamp_secs {value} exceeds 2^53 - 1")]
    CreationTimestampOutOfRange {
        /// The out-of-range creation timestamp.
        value: u64,
    },

    /// Spec §5.13.3 rule 9: `creation_timestamp_secs` lies later than the
    /// member's clock plus [`CREATION_TIMESTAMP_FUTURE_BOUND_SECS`].
    #[error(
        "creation_timestamp_secs {value} lies more than {bound_secs} s after the member's clock {now_secs}"
    )]
    CreationTimestampInFuture {
        /// The committed creation timestamp.
        value: u64,
        /// The member's clock, in Unix seconds.
        now_secs: u64,
        /// The future bound, [`CREATION_TIMESTAMP_FUTURE_BOUND_SECS`].
        bound_secs: u64,
    },

    /// Canonical (JCS) serialization of the extension or a hash input failed.
    #[error("canonical serialization failed: {0}")]
    SerializationFailed(String),

    /// Canonical decoding of extension bytes failed.
    #[error("canonical deserialization failed: {0}")]
    DeserializationFailed(String),
}

// ---------------------------------------------------------------------------
// ScpContextExtension
// ---------------------------------------------------------------------------

/// The SCP context parameters bound into an MLS group's `group_context`
/// (spec §5.13.3).
///
/// Carried as the `ExtensionData` of the `0xFF02` extension, serialized with
/// RFC 8785 canonical JSON. Field order is fixed by the spec; JCS re-sorts JSON
/// object keys by Unicode code point, so the on-wire byte order is independent
/// of this declaration order (the declaration order is kept aligned with the
/// spec for readability).
///
/// The hashes commit to the context's governance model, capability ceiling, and
/// — for child contexts — parent lineage, so a joiner can verify the parameters
/// it was handed against the ones the creator cryptographically committed. The
/// `creator_did` field commits the group's genesis creator/admin, so a joiner
/// can prove the `creator_did` its untrusted inviter supplied is the real one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScpContextExtension {
    /// The SCP context ID this group represents.
    pub context_id: ContextId,
    /// The group's genesis creator/admin DID (spec §5.13.3 rule 8). Committed at
    /// group creation and immutable in `group_context`; pins the INITIAL admin
    /// (e.g. the `SingleAdmin` admin). Admin transfers are NOT tracked here —
    /// they apply from the authenticated event log after join.
    pub creator_did: DID,
    /// `T0`: the Unix-seconds `timestamp` the creator stamped on the context's
    /// `ContextCreated` event-log leaf (spec §5.13.3 "Creation timestamp"). A
    /// genesis fact no Commit changes. Members install it as the base of the
    /// pseudonym rotation schedule (`09-security-model.md` §9.10.4.1) and of
    /// the TTL deadline (§5.10) under rule 9. At most
    /// [`MAX_CREATION_TIMESTAMP_SECS`]; required on the wire, so an extension
    /// that omits it does not decode.
    pub creation_timestamp_secs: u64,
    /// Context processing mode: `0` = Encrypted, `1` = Broadcast
    /// (matches [`ContextMode`] discriminants).
    pub context_mode: u8,
    /// `SHA-256(JCS(governance_policy))` — commits the governance model.
    pub governance_policy_hash: [u8; 32],
    /// Ceiling mutability policy: `0` = Immutable, `1` = Governed
    /// (matches [`CeilingPolicy`] discriminants).
    pub ceiling_policy: u8,
    /// `SHA-256(JCS(capability_ceiling))` — commits the capability ceiling.
    pub ceiling_hash: [u8; 32],
    /// Parent context IDs, sorted lexicographically. Empty for root contexts.
    pub parent_context_ids: Vec<ContextId>,
    /// `SHA-256(JCS(parent_governance_configs))` — commits the parent lineage's
    /// governance configuration. `None` for root contexts.
    pub parent_governance_hash: Option<[u8; 32]>,
}

/// The genesis facts every [`ScpContextExtension`] constructor commits (spec
/// §5.13.3): the context's identity, its genesis creator, its creation
/// timestamp, and the parameters the hashes bind.
#[derive(Debug, Clone)]
pub struct ScpContextGenesis<'a> {
    /// The SCP context ID (rule 2).
    pub context_id: ContextId,
    /// The group's genesis creator/admin (rule 8).
    pub creator_did: DID,
    /// The `timestamp` of the context's `ContextCreated` leaf, `T0` (rule 9).
    /// At most [`MAX_CREATION_TIMESTAMP_SECS`].
    pub creation_timestamp_secs: u64,
    /// The context mode (rule 4).
    pub mode: ContextMode,
    /// The governance model `governance_policy_hash` commits (rule 3).
    pub governance: &'a GovernanceModel,
    /// The ceiling mutability policy (rule 4).
    pub ceiling_policy: CeilingPolicy,
    /// The capability ceiling `ceiling_hash` commits (rule 4).
    pub ceiling: &'a CapabilityCeiling,
}

impl ScpContextGenesis<'_> {
    /// Builds the extension with the given parent data, after rejecting a
    /// creation timestamp above [`MAX_CREATION_TIMESTAMP_SECS`].
    fn into_extension(
        self,
        parent_context_ids: Vec<ContextId>,
        parent_governance_hash: Option<[u8; 32]>,
    ) -> Result<ScpContextExtension, ScpContextBindingError> {
        check_creation_timestamp_range(self.creation_timestamp_secs)?;
        Ok(ScpContextExtension {
            context_id: self.context_id,
            creator_did: self.creator_did,
            creation_timestamp_secs: self.creation_timestamp_secs,
            context_mode: self.mode as u8,
            governance_policy_hash: jcs_sha256(self.governance)?,
            ceiling_policy: self.ceiling_policy as u8,
            ceiling_hash: jcs_sha256(self.ceiling)?,
            parent_context_ids,
            parent_governance_hash,
        })
    }
}

/// Rejects a creation timestamp above [`MAX_CREATION_TIMESTAMP_SECS`].
const fn check_creation_timestamp_range(value: u64) -> Result<(), ScpContextBindingError> {
    if value > MAX_CREATION_TIMESTAMP_SECS {
        return Err(ScpContextBindingError::CreationTimestampOutOfRange { value });
    }
    Ok(())
}

impl ScpContextExtension {
    /// Builds the extension for a **root** context (no parents).
    ///
    /// Per validation rule 6, `parent_context_ids` is empty and
    /// `parent_governance_hash` is `None`.
    ///
    /// # Errors
    ///
    /// Returns [`ScpContextBindingError::CreationTimestampOutOfRange`] if
    /// `genesis.creation_timestamp_secs` exceeds [`MAX_CREATION_TIMESTAMP_SECS`],
    /// or [`ScpContextBindingError::SerializationFailed`] if the governance
    /// model or capability ceiling cannot be canonically serialized.
    pub fn for_root(genesis: ScpContextGenesis<'_>) -> Result<Self, ScpContextBindingError> {
        genesis.into_extension(Vec::new(), None)
    }

    /// Builds the extension for a **child** context from already-computed parent
    /// data: the parent context IDs and the parent-governance hash (see
    /// [`Self::parent_governance_hash`]).
    ///
    /// `parent_context_ids` is normalized (sorted lexicographically, duplicates
    /// removed) so the result always satisfies validation rule 5. A child must
    /// have at least one parent.
    ///
    /// # Errors
    ///
    /// Returns [`ScpContextBindingError::ParentStructureInvalid`] if
    /// `parent_context_ids` is empty,
    /// [`ScpContextBindingError::CreationTimestampOutOfRange`] if
    /// `genesis.creation_timestamp_secs` exceeds [`MAX_CREATION_TIMESTAMP_SECS`],
    /// or [`ScpContextBindingError::SerializationFailed`] if the governance
    /// model or capability ceiling cannot be canonically serialized.
    pub fn for_child(
        genesis: ScpContextGenesis<'_>,
        mut parent_context_ids: Vec<ContextId>,
        parent_governance_hash: [u8; 32],
    ) -> Result<Self, ScpContextBindingError> {
        parent_context_ids.sort();
        parent_context_ids.dedup();
        if parent_context_ids.is_empty() {
            return Err(ScpContextBindingError::ParentStructureInvalid {
                reason: "child context requires at least one parent context id".to_owned(),
            });
        }
        genesis.into_extension(parent_context_ids, Some(parent_governance_hash))
    }

    /// Convenience constructor for a **child** context that derives the sorted
    /// parent context IDs and the parent-governance hash directly from the
    /// parent references.
    ///
    /// # Errors
    ///
    /// Returns [`ScpContextBindingError::ParentStructureInvalid`] if `parents`
    /// is empty, [`ScpContextBindingError::CreationTimestampOutOfRange`] if
    /// `genesis.creation_timestamp_secs` exceeds [`MAX_CREATION_TIMESTAMP_SECS`],
    /// or [`ScpContextBindingError::SerializationFailed`] if any hash input
    /// cannot be canonically serialized.
    pub fn for_child_from_parents(
        genesis: ScpContextGenesis<'_>,
        parents: &[ParentRef],
    ) -> Result<Self, ScpContextBindingError> {
        if parents.is_empty() {
            return Err(ScpContextBindingError::ParentStructureInvalid {
                reason: "child context requires at least one parent context".to_owned(),
            });
        }
        let parent_governance_hash = Self::parent_governance_hash(parents)?;
        let parent_context_ids = parents.iter().map(|p| p.context_id.clone()).collect();
        Self::for_child(genesis, parent_context_ids, parent_governance_hash)
    }

    /// Computes `parent_governance_hash` per spec §5.13.3:
    /// `SHA-256(JCS(parent_governance_configs))`, where
    /// `parent_governance_configs` is the list of each parent's
    /// [`ParentGovernanceConfig`] ordered by parent context ID (matching the
    /// lexicographic order of `parent_context_ids`).
    ///
    /// # Errors
    ///
    /// Returns [`ScpContextBindingError::SerializationFailed`] if the
    /// configuration list cannot be canonically serialized.
    pub fn parent_governance_hash(
        parents: &[ParentRef],
    ) -> Result<[u8; 32], ScpContextBindingError> {
        let mut sorted: Vec<&ParentRef> = parents.iter().collect();
        sorted.sort_by(|a, b| a.context_id.cmp(&b.context_id));
        let configs: Vec<&ParentGovernanceConfig> =
            sorted.iter().map(|p| &p.governance_config).collect();
        jcs_sha256(&configs)
    }

    /// Serializes the extension to its canonical (RFC 8785 JCS) byte
    /// representation — the `ExtensionData` payload for the `0xFF02` extension.
    ///
    /// # Errors
    ///
    /// Returns [`ScpContextBindingError::SerializationFailed`] on canonical
    /// serialization failure.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ScpContextBindingError> {
        crate::jcs::to_vec(self).map_err(ScpContextBindingError::SerializationFailed)
    }

    /// Deserializes an extension from canonical bytes produced by
    /// [`Self::to_canonical_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`ScpContextBindingError::DeserializationFailed`] if the bytes
    /// are not valid canonical JSON for this type, including bytes that omit a
    /// field such as `creation_timestamp_secs` (spec §5.13.3 rule 1), or
    /// [`ScpContextBindingError::CreationTimestampOutOfRange`] if the decoded
    /// `creation_timestamp_secs` exceeds [`MAX_CREATION_TIMESTAMP_SECS`].
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ScpContextBindingError> {
        let extension: Self = serde_json::from_slice(bytes)
            .map_err(|e| ScpContextBindingError::DeserializationFailed(e.to_string()))?;
        check_creation_timestamp_range(extension.creation_timestamp_secs)?;
        Ok(extension)
    }

    /// The committed `T0` a member installs under spec §5.13.3 rule 9, after
    /// checking it against the member's clock `now_secs`.
    ///
    /// # Errors
    ///
    /// Returns [`ScpContextBindingError::CreationTimestampOutOfRange`] for a
    /// value above [`MAX_CREATION_TIMESTAMP_SECS`], or
    /// [`ScpContextBindingError::CreationTimestampInFuture`] for a value later
    /// than `now_secs` plus [`CREATION_TIMESTAMP_FUTURE_BOUND_SECS`].
    pub fn committed_creation_timestamp(
        &self,
        now_secs: u64,
    ) -> Result<u64, ScpContextBindingError> {
        let value = self.creation_timestamp_secs;
        check_creation_timestamp_range(value)?;
        if value > now_secs.saturating_add(CREATION_TIMESTAMP_FUTURE_BOUND_SECS) {
            return Err(ScpContextBindingError::CreationTimestampInFuture {
                value,
                now_secs,
                bound_secs: CREATION_TIMESTAMP_FUTURE_BOUND_SECS,
            });
        }
        Ok(value)
    }

    /// Verifies the extension against a context's declared identity, genesis
    /// creator, and parameters (spec §5.13.3 validation rules 2-6 plus the
    /// creator-DID binding, rule 8).
    ///
    /// - **Rule 2:** `context_id` matches `context_id`.
    /// - **Rule 8:** `creator_did` matches the presented `creator_did` (the
    ///   bundle's `creator_did` on join; the snapshot's `role_state.creator_did`
    ///   on import/restore). This is the sole cryptographic anchor of admin
    ///   identity for DID-less governance models.
    /// - **Rule 3:** `governance_policy_hash == SHA-256(JCS(params.governance))`.
    /// - **Rule 4:** `ceiling_hash == SHA-256(JCS(capability_ceiling))`,
    ///   `ceiling_policy == params.ceiling_policy`, and
    ///   `context_mode == params.mode`.
    /// - **Rules 5-6 (structural):** a root has empty parents and no
    ///   parent-governance hash; a child has non-empty, lexicographically-sorted
    ///   parents and a parent-governance hash.
    ///
    /// # Structural-only parent check
    ///
    /// The parent-lineage check here is *structural self-consistency only*. A
    /// full re-verification of `parent_governance_hash` requires the parents'
    /// governance configurations, which a Welcome-based joiner may not hold at
    /// this layer. When those configurations are available, the caller
    /// recomputes the hash via [`Self::parent_governance_hash`] and compares.
    ///
    /// # Errors
    ///
    /// Returns the [`ScpContextBindingError`] variant for the first failing rule,
    /// or [`ScpContextBindingError::SerializationFailed`] if a comparison hash
    /// cannot be computed.
    pub fn verify_against(
        &self,
        context_id: &ContextId,
        creator_did: &DID,
        params: &ContextParams,
    ) -> Result<(), ScpContextBindingError> {
        // Rule 2: context_id binding.
        if &self.context_id != context_id {
            return Err(ScpContextBindingError::ContextIdMismatch {
                expected: self.context_id.clone(),
                actual: context_id.clone(),
            });
        }

        // Rule 8: genesis creator/admin binding. The committed `creator_did`
        // pins the group's real creator; a caller-supplied `creator_did` that
        // diverges is refused BEFORE any authority (governance engine, admin
        // set) is built for it. This closes the DID-less-governance
        // (SingleAdmin) admin-substitution path where `governance_policy_hash`
        // is a constant and therefore commits no identity.
        if &self.creator_did != creator_did {
            return Err(ScpContextBindingError::CreatorMismatch {
                expected: self.creator_did.clone(),
                actual: creator_did.clone(),
            });
        }

        // Rule 3: governance policy hash.
        let expected_governance = jcs_sha256(&params.governance)?;
        if self.governance_policy_hash != expected_governance {
            return Err(ScpContextBindingError::GovernanceHashMismatch);
        }

        // Rule 4a: ceiling hash. The ceiling is committed as a `CapabilityCeiling`
        // (content-sorted set), so the hash is independent of the ordering of
        // `params.ceiling`.
        let ceiling = CapabilityCeiling::new(params.ceiling.iter().cloned());
        let expected_ceiling = jcs_sha256(&ceiling)?;
        if self.ceiling_hash != expected_ceiling {
            return Err(ScpContextBindingError::CeilingHashMismatch);
        }

        // Rule 4b: ceiling policy.
        let params_ceiling_policy = params.ceiling_policy as u8;
        if self.ceiling_policy != params_ceiling_policy {
            return Err(ScpContextBindingError::CeilingPolicyMismatch {
                extension: self.ceiling_policy,
                params: params_ceiling_policy,
            });
        }

        // Rule 4c: context mode.
        let params_mode = params.mode as u8;
        if self.context_mode != params_mode {
            return Err(ScpContextBindingError::ModeMismatch {
                extension: self.context_mode,
                params: params_mode,
            });
        }

        // Rules 5-6: root/child parent structure.
        self.verify_parent_structure()
    }

    /// Structural check for validation rules 5-6: a root context has empty
    /// parents and no parent-governance hash; a child context has non-empty,
    /// lexicographically-sorted (no-duplicate) parents and a parent-governance
    /// hash.
    fn verify_parent_structure(&self) -> Result<(), ScpContextBindingError> {
        match (
            self.parent_context_ids.is_empty(),
            self.parent_governance_hash.is_some(),
        ) {
            // Root: no parents, no parent-governance hash.
            (true, false) => Ok(()),
            // Child: parents present with a parent-governance hash.
            (false, true) => {
                let strictly_sorted = self
                    .parent_context_ids
                    .windows(2)
                    .all(|pair| pair[0] < pair[1]);
                if strictly_sorted {
                    Ok(())
                } else {
                    Err(ScpContextBindingError::ParentStructureInvalid {
                        reason: "parent_context_ids must be sorted lexicographically \
                                 without duplicates"
                            .to_owned(),
                    })
                }
            }
            // Empty parents but a parent-governance hash: malformed root.
            (true, true) => Err(ScpContextBindingError::ParentStructureInvalid {
                reason: "root context must not carry a parent_governance_hash".to_owned(),
            }),
            // Parents present but no parent-governance hash: malformed child.
            (false, false) => Err(ScpContextBindingError::ParentStructureInvalid {
                reason: "child context must carry a parent_governance_hash".to_owned(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Canonical hashing helper
// ---------------------------------------------------------------------------

/// Computes `SHA-256(RFC-8785-JCS(value))`.
///
/// Mirrors [`ParentGovernanceConfig::content_hash`](super::nesting::ParentGovernanceConfig::content_hash):
/// JCS canonicalization for cross-implementation determinism, then SHA-256 over
/// the canonical bytes.
fn jcs_sha256<T: Serialize>(value: &T) -> Result<[u8; 32], ScpContextBindingError> {
    let bytes = crate::jcs::to_vec(value).map_err(ScpContextBindingError::SerializationFailed)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::context::nesting::OnSeverPolicy;
    use crate::context::roles::Capability;
    use scp_did::DID;
    use std::collections::BTreeSet;

    /// The creation timestamp the constructor fixtures commit.
    const TEST_T0: u64 = 1_700_000_000;

    fn did(name: &str) -> DID {
        DID::from(format!("did:dht:z6Mk{name}"))
    }

    /// The genesis creator/admin DID used across the `verify_against` fixtures.
    fn creator() -> DID {
        did("Creator")
    }

    fn ceiling(caps: &[Capability]) -> CapabilityCeiling {
        CapabilityCeiling::new(caps.iter().cloned())
    }

    fn governance() -> GovernanceModel {
        GovernanceModel::Threshold {
            threshold: 2,
            signers: vec![did("Alice"), did("Bob")],
        }
    }

    fn parent_ref(id: &str, on_sever: OnSeverPolicy) -> ParentRef {
        ParentRef {
            context_id: id.to_owned(),
            ceiling: ceiling(&[Capability::MessagesRead, Capability::ChildContextCreate]),
            governance_config: ParentGovernanceConfig {
                can_close_child: false,
                can_evict_members: false,
                can_restrict_ceiling: false,
                requires_approval_for: BTreeSet::new(),
                on_sever,
            },
            members: std::iter::once(did("Alice")).collect(),
        }
    }

    /// A root fixture with fully-pinned hash fields so the canonical encoding is
    /// deterministic and independent of the runtime hash computation.
    fn root_fixture() -> ScpContextExtension {
        ScpContextExtension {
            context_id: "ctx:root".to_owned(),
            creator_did: DID("did:example:root-creator".to_owned()),
            creation_timestamp_secs: 1_700_000_000,
            context_mode: 0,
            governance_policy_hash: [0x11; 32],
            ceiling_policy: 0,
            ceiling_hash: [0x22; 32],
            parent_context_ids: Vec::new(),
            parent_governance_hash: None,
        }
    }

    /// A child fixture with fully-pinned hash fields.
    fn child_fixture() -> ScpContextExtension {
        ScpContextExtension {
            context_id: "ctx:child".to_owned(),
            creator_did: DID("did:example:child-creator".to_owned()),
            creation_timestamp_secs: 1_700_000_001,
            context_mode: 1,
            governance_policy_hash: [0x33; 32],
            ceiling_policy: 1,
            ceiling_hash: [0x44; 32],
            parent_context_ids: vec!["ctx:a".to_owned(), "ctx:b".to_owned()],
            parent_governance_hash: Some([0x55; 32]),
        }
    }

    // -----------------------------------------------------------------------
    // KAT: pinned canonical bytes + round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn kat_root_canonical_bytes() {
        let ext = root_fixture();
        let bytes = ext.to_canonical_bytes().unwrap();
        let json = String::from_utf8(bytes.clone()).unwrap();

        // JCS sorts object keys by Unicode code point. `[u8; 32]` serializes as
        // a JSON array of decimal numbers; `creator_did` (a `DID`) serializes as
        // a JSON string (its `#[serde(transparent)]` inner `String`).
        let expected = concat!(
            "{",
            "\"ceiling_hash\":[34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,",
            "34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34],",
            "\"ceiling_policy\":0,",
            "\"context_id\":\"ctx:root\",",
            "\"context_mode\":0,",
            "\"creation_timestamp_secs\":1700000000,",
            "\"creator_did\":\"did:example:root-creator\",",
            "\"governance_policy_hash\":[17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,",
            "17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17],",
            "\"parent_context_ids\":[],",
            "\"parent_governance_hash\":null",
            "}"
        );
        assert_eq!(json, expected, "root canonical JSON KAT");

        // Pinned SHA-256 of the canonical bytes (independent-implementation check).
        let digest = {
            let mut h = Sha256::new();
            h.update(&bytes);
            hex::encode(h.finalize())
        };
        assert_eq!(
            digest, "1230cd6e542ed91e785362d35e9135acc87e4ed112bfecadefc54601e9e5a07b",
            "root canonical-bytes SHA-256 KAT"
        );
    }

    #[test]
    fn kat_child_canonical_bytes() {
        let ext = child_fixture();
        let bytes = ext.to_canonical_bytes().unwrap();
        let json = String::from_utf8(bytes).unwrap();

        let expected = concat!(
            "{",
            "\"ceiling_hash\":[68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,",
            "68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68],",
            "\"ceiling_policy\":1,",
            "\"context_id\":\"ctx:child\",",
            "\"context_mode\":1,",
            "\"creation_timestamp_secs\":1700000001,",
            "\"creator_did\":\"did:example:child-creator\",",
            "\"governance_policy_hash\":[51,51,51,51,51,51,51,51,51,51,51,51,51,51,51,51,",
            "51,51,51,51,51,51,51,51,51,51,51,51,51,51,51,51],",
            "\"parent_context_ids\":[\"ctx:a\",\"ctx:b\"],",
            "\"parent_governance_hash\":[85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,",
            "85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85]",
            "}"
        );
        assert_eq!(json, expected, "child canonical JSON KAT");
    }

    #[test]
    fn canonical_bytes_round_trip_root() {
        let ext = root_fixture();
        let bytes = ext.to_canonical_bytes().unwrap();
        let decoded = ScpContextExtension::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(ext, decoded);
    }

    #[test]
    fn canonical_bytes_round_trip_child() {
        let ext = child_fixture();
        let bytes = ext.to_canonical_bytes().unwrap();
        let decoded = ScpContextExtension::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(ext, decoded);
    }

    #[test]
    fn from_canonical_bytes_rejects_garbage() {
        let err = ScpContextExtension::from_canonical_bytes(b"not json").unwrap_err();
        assert!(matches!(
            err,
            ScpContextBindingError::DeserializationFailed(_)
        ));
    }

    // -----------------------------------------------------------------------
    // Hash wiring: constructor hashes equal SHA-256(JCS(fixture))
    // -----------------------------------------------------------------------

    #[test]
    fn governance_hash_equals_jcs_sha256() {
        let gov = governance();
        let cap = ceiling(&[Capability::MessagesRead]);
        let ext = ScpContextExtension::for_root(ScpContextGenesis {
            context_id: "ctx:r".to_owned(),
            creator_did: creator(),
            creation_timestamp_secs: TEST_T0,
            mode: ContextMode::Encrypted,
            governance: &gov,
            ceiling_policy: CeilingPolicy::Immutable,
            ceiling: &cap,
        })
        .unwrap();

        let bytes = crate::jcs::to_vec(&gov).unwrap();
        let mut h = Sha256::new();
        h.update(&bytes);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&h.finalize());

        assert_eq!(ext.governance_policy_hash, expected);
    }

    #[test]
    fn ceiling_hash_equals_jcs_sha256() {
        let gov = governance();
        let cap = ceiling(&[Capability::MessagesRead, Capability::MessagesWrite]);
        let ext = ScpContextExtension::for_root(ScpContextGenesis {
            context_id: "ctx:r".to_owned(),
            creator_did: creator(),
            creation_timestamp_secs: TEST_T0,
            mode: ContextMode::Encrypted,
            governance: &gov,
            ceiling_policy: CeilingPolicy::Immutable,
            ceiling: &cap,
        })
        .unwrap();

        let bytes = crate::jcs::to_vec(&cap).unwrap();
        let mut h = Sha256::new();
        h.update(&bytes);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&h.finalize());

        assert_eq!(ext.ceiling_hash, expected);
    }

    #[test]
    fn ceiling_hash_independent_of_input_order() {
        let gov = governance();
        let cap_ab = ceiling(&[Capability::MessagesRead, Capability::MessagesWrite]);
        let cap_ba = ceiling(&[Capability::MessagesWrite, Capability::MessagesRead]);
        let ext_ab = ScpContextExtension::for_root(ScpContextGenesis {
            context_id: "ctx:r".to_owned(),
            creator_did: creator(),
            creation_timestamp_secs: TEST_T0,
            mode: ContextMode::Encrypted,
            governance: &gov,
            ceiling_policy: CeilingPolicy::Immutable,
            ceiling: &cap_ab,
        })
        .unwrap();
        let ext_ba = ScpContextExtension::for_root(ScpContextGenesis {
            context_id: "ctx:r".to_owned(),
            creator_did: creator(),
            creation_timestamp_secs: TEST_T0,
            mode: ContextMode::Encrypted,
            governance: &gov,
            ceiling_policy: CeilingPolicy::Immutable,
            ceiling: &cap_ba,
        })
        .unwrap();
        assert_eq!(ext_ab.ceiling_hash, ext_ba.ceiling_hash);
    }

    // -----------------------------------------------------------------------
    // Constructors: root / child shape
    // -----------------------------------------------------------------------

    #[test]
    fn for_root_has_no_parent_data() {
        let ext = ScpContextExtension::for_root(ScpContextGenesis {
            context_id: "ctx:r".to_owned(),
            creator_did: creator(),
            creation_timestamp_secs: TEST_T0,
            mode: ContextMode::Broadcast,
            governance: &governance(),
            ceiling_policy: CeilingPolicy::Governed,
            ceiling: &ceiling(&[Capability::MessagesRead]),
        })
        .unwrap();
        assert_eq!(ext.creator_did, creator());
        assert_eq!(ext.context_mode, 1); // Broadcast
        assert_eq!(ext.ceiling_policy, 1); // Governed
        assert!(ext.parent_context_ids.is_empty());
        assert!(ext.parent_governance_hash.is_none());
    }

    #[test]
    fn for_child_normalizes_parent_ids_and_sets_hash() {
        let ext = ScpContextExtension::for_child(
            ScpContextGenesis {
                context_id: "ctx:c".to_owned(),
                creator_did: creator(),
                creation_timestamp_secs: TEST_T0,
                mode: ContextMode::Encrypted,
                governance: &governance(),
                ceiling_policy: CeilingPolicy::Immutable,
                ceiling: &ceiling(&[Capability::MessagesRead]),
            },
            vec!["ctx:b".to_owned(), "ctx:a".to_owned(), "ctx:b".to_owned()],
            [0x99; 32],
        )
        .unwrap();
        assert_eq!(ext.creator_did, creator());
        assert_eq!(ext.parent_context_ids, vec!["ctx:a", "ctx:b"]);
        assert_eq!(ext.parent_governance_hash, Some([0x99; 32]));
    }

    #[test]
    fn for_child_rejects_empty_parents() {
        let err = ScpContextExtension::for_child(
            ScpContextGenesis {
                context_id: "ctx:c".to_owned(),
                creator_did: creator(),
                creation_timestamp_secs: TEST_T0,
                mode: ContextMode::Encrypted,
                governance: &governance(),
                ceiling_policy: CeilingPolicy::Immutable,
                ceiling: &ceiling(&[Capability::MessagesRead]),
            },
            Vec::new(),
            [0x00; 32],
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ScpContextBindingError::ParentStructureInvalid { .. }
        ));
    }

    #[test]
    fn for_child_from_parents_matches_manual_hash() {
        let parents = vec![
            parent_ref("ctx:b", OnSeverPolicy::EvictUniqueMembers),
            parent_ref("ctx:a", OnSeverPolicy::CascadeClose),
        ];
        let ext = ScpContextExtension::for_child_from_parents(
            ScpContextGenesis {
                context_id: "ctx:c".to_owned(),
                creator_did: creator(),
                creation_timestamp_secs: TEST_T0,
                mode: ContextMode::Encrypted,
                governance: &governance(),
                ceiling_policy: CeilingPolicy::Immutable,
                ceiling: &ceiling(&[Capability::MessagesRead]),
            },
            &parents,
        )
        .unwrap();

        assert_eq!(ext.parent_context_ids, vec!["ctx:a", "ctx:b"]);
        let expected_hash = ScpContextExtension::parent_governance_hash(&parents).unwrap();
        assert_eq!(ext.parent_governance_hash, Some(expected_hash));
    }

    #[test]
    fn parent_governance_hash_is_order_independent() {
        let ab = vec![
            parent_ref("ctx:a", OnSeverPolicy::CascadeClose),
            parent_ref("ctx:b", OnSeverPolicy::EvictUniqueMembers),
        ];
        let ba = vec![
            parent_ref("ctx:b", OnSeverPolicy::EvictUniqueMembers),
            parent_ref("ctx:a", OnSeverPolicy::CascadeClose),
        ];
        assert_eq!(
            ScpContextExtension::parent_governance_hash(&ab).unwrap(),
            ScpContextExtension::parent_governance_hash(&ba).unwrap()
        );
    }

    #[test]
    fn parent_governance_hash_matches_spec_sha256_jcs() {
        // Spec §5.13.3: SHA-256(JCS(parent_governance_configs)), configs ordered
        // by parent context id.
        let mut parents = vec![
            parent_ref("ctx:b", OnSeverPolicy::EvictUniqueMembers),
            parent_ref("ctx:a", OnSeverPolicy::CascadeClose),
        ];
        let actual = ScpContextExtension::parent_governance_hash(&parents).unwrap();

        // Manual reference computation: sort by ctx id, JCS the list of configs.
        parents.sort_by(|a, b| a.context_id.cmp(&b.context_id));
        let configs: Vec<&ParentGovernanceConfig> =
            parents.iter().map(|p| &p.governance_config).collect();
        let bytes = crate::jcs::to_vec(&configs).unwrap();
        let mut h = Sha256::new();
        h.update(&bytes);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&h.finalize());

        assert_eq!(actual, expected);
    }

    // -----------------------------------------------------------------------
    // verify_against: success + each failure kind
    // -----------------------------------------------------------------------

    fn params_for(mode: ContextMode, policy: CeilingPolicy) -> ContextParams {
        ContextParams {
            mode,
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            ceiling_policy: policy,
            governance: governance(),
            ..ContextParams::default()
        }
    }

    fn extension_for(params: &ContextParams, context_id: &str) -> ScpContextExtension {
        ScpContextExtension::for_root(ScpContextGenesis {
            context_id: context_id.to_owned(),
            creator_did: creator(),
            creation_timestamp_secs: TEST_T0,
            mode: params.mode,
            governance: &params.governance,
            ceiling_policy: params.ceiling_policy,
            ceiling: &CapabilityCeiling::new(params.ceiling.iter().cloned()),
        })
        .unwrap()
    }

    #[test]
    fn verify_against_accepts_matching_root() {
        let params = params_for(ContextMode::Encrypted, CeilingPolicy::Immutable);
        let ext = extension_for(&params, "ctx:r");
        assert!(
            ext.verify_against(&"ctx:r".to_owned(), &creator(), &params)
                .is_ok()
        );
    }

    #[test]
    fn verify_against_rejects_context_id_mismatch() {
        let params = params_for(ContextMode::Encrypted, CeilingPolicy::Immutable);
        let ext = extension_for(&params, "ctx:r");
        let err = ext
            .verify_against(&"ctx:other".to_owned(), &creator(), &params)
            .unwrap_err();
        assert!(matches!(
            err,
            ScpContextBindingError::ContextIdMismatch { .. }
        ));
    }

    #[test]
    fn verify_against_rejects_creator_mismatch() {
        // BLACK-2J10-001-R regression (protocol layer): an honest SingleAdmin
        // group commits creator = Alice; a joiner presenting creator = Mallory
        // (a valid DID, matching params) is refused with `CreatorMismatch`. With
        // SingleAdmin governance `governance_policy_hash` is a constant, so NO
        // other rule catches the substitution — this is the sole anchor.
        let mut params = params_for(ContextMode::Encrypted, CeilingPolicy::Immutable);
        params.governance = GovernanceModel::SingleAdmin;
        let ext = ScpContextExtension::for_root(ScpContextGenesis {
            context_id: "ctx:r".to_owned(),
            creator_did: did("Alice"),
            creation_timestamp_secs: TEST_T0,
            mode: params.mode,
            governance: &params.governance,
            ceiling_policy: params.ceiling_policy,
            ceiling: &CapabilityCeiling::new(params.ceiling.iter().cloned()),
        })
        .unwrap();
        let err = ext
            .verify_against(&"ctx:r".to_owned(), &did("Mallory"), &params)
            .unwrap_err();
        assert!(matches!(
            err,
            ScpContextBindingError::CreatorMismatch { .. }
        ));
        // The honest creator still verifies.
        assert!(
            ext.verify_against(&"ctx:r".to_owned(), &did("Alice"), &params)
                .is_ok()
        );
    }

    #[test]
    fn verify_against_rejects_governance_mismatch() {
        let mut params = params_for(ContextMode::Encrypted, CeilingPolicy::Immutable);
        let ext = extension_for(&params, "ctx:r");
        // Different governance model than committed.
        params.governance = GovernanceModel::SingleAdmin;
        let err = ext
            .verify_against(&"ctx:r".to_owned(), &creator(), &params)
            .unwrap_err();
        assert!(matches!(
            err,
            ScpContextBindingError::GovernanceHashMismatch
        ));
    }

    #[test]
    fn verify_against_rejects_ceiling_mismatch() {
        let mut params = params_for(ContextMode::Encrypted, CeilingPolicy::Immutable);
        let ext = extension_for(&params, "ctx:r");
        params.ceiling = vec![Capability::MessagesRead]; // narrower than committed
        let err = ext
            .verify_against(&"ctx:r".to_owned(), &creator(), &params)
            .unwrap_err();
        assert!(matches!(err, ScpContextBindingError::CeilingHashMismatch));
    }

    #[test]
    fn verify_against_rejects_ceiling_policy_mismatch() {
        let mut params = params_for(ContextMode::Encrypted, CeilingPolicy::Immutable);
        let ext = extension_for(&params, "ctx:r");
        params.ceiling_policy = CeilingPolicy::Governed;
        let err = ext
            .verify_against(&"ctx:r".to_owned(), &creator(), &params)
            .unwrap_err();
        assert!(matches!(
            err,
            ScpContextBindingError::CeilingPolicyMismatch {
                extension: 0,
                params: 1
            }
        ));
    }

    #[test]
    fn verify_against_rejects_mode_mismatch() {
        let mut params = params_for(ContextMode::Encrypted, CeilingPolicy::Immutable);
        let ext = extension_for(&params, "ctx:r");
        params.mode = ContextMode::Broadcast;
        let err = ext
            .verify_against(&"ctx:r".to_owned(), &creator(), &params)
            .unwrap_err();
        assert!(matches!(
            err,
            ScpContextBindingError::ModeMismatch {
                extension: 0,
                params: 1
            }
        ));
    }

    #[test]
    fn verify_against_rejects_root_carrying_parent_hash() {
        let params = params_for(ContextMode::Encrypted, CeilingPolicy::Immutable);
        let mut ext = extension_for(&params, "ctx:r");
        // Structurally corrupt: root with a parent-governance hash.
        ext.parent_governance_hash = Some([0x01; 32]);
        let err = ext
            .verify_against(&"ctx:r".to_owned(), &creator(), &params)
            .unwrap_err();
        assert!(matches!(
            err,
            ScpContextBindingError::ParentStructureInvalid { .. }
        ));
    }

    #[test]
    fn verify_against_rejects_child_missing_parent_hash() {
        let params = params_for(ContextMode::Encrypted, CeilingPolicy::Immutable);
        let mut ext = extension_for(&params, "ctx:c");
        ext.parent_context_ids = vec!["ctx:a".to_owned()];
        ext.parent_governance_hash = None;
        let err = ext
            .verify_against(&"ctx:c".to_owned(), &creator(), &params)
            .unwrap_err();
        assert!(matches!(
            err,
            ScpContextBindingError::ParentStructureInvalid { .. }
        ));
    }

    #[test]
    fn verify_against_rejects_unsorted_parents() {
        let params = params_for(ContextMode::Encrypted, CeilingPolicy::Immutable);
        let mut ext = extension_for(&params, "ctx:c");
        // Not sorted (would never be produced by the constructor).
        ext.parent_context_ids = vec!["ctx:b".to_owned(), "ctx:a".to_owned()];
        ext.parent_governance_hash = Some([0x01; 32]);
        let err = ext
            .verify_against(&"ctx:c".to_owned(), &creator(), &params)
            .unwrap_err();
        assert!(matches!(
            err,
            ScpContextBindingError::ParentStructureInvalid { .. }
        ));
    }

    #[test]
    fn verify_against_accepts_well_formed_child() {
        let params = params_for(ContextMode::Encrypted, CeilingPolicy::Immutable);
        let ext = ScpContextExtension::for_child(
            ScpContextGenesis {
                context_id: "ctx:c".to_owned(),
                creator_did: creator(),
                creation_timestamp_secs: TEST_T0,
                mode: params.mode,
                governance: &params.governance,
                ceiling_policy: params.ceiling_policy,
                ceiling: &CapabilityCeiling::new(params.ceiling.iter().cloned()),
            },
            vec!["ctx:a".to_owned(), "ctx:b".to_owned()],
            [0x01; 32],
        )
        .unwrap();
        assert!(
            ext.verify_against(&"ctx:c".to_owned(), &creator(), &params)
                .is_ok()
        );
    }

    // -----------------------------------------------------------------------
    // creation_timestamp_secs (spec §5.13.3 "Creation timestamp", rule 9)
    // -----------------------------------------------------------------------

    /// A genesis whose creation timestamp is `creation_timestamp_secs`.
    fn genesis_at<'a>(
        creation_timestamp_secs: u64,
        gov: &'a GovernanceModel,
        cap: &'a CapabilityCeiling,
    ) -> ScpContextGenesis<'a> {
        ScpContextGenesis {
            context_id: "ctx:t".to_owned(),
            creator_did: creator(),
            creation_timestamp_secs,
            mode: ContextMode::Encrypted,
            governance: gov,
            ceiling_policy: CeilingPolicy::Immutable,
            ceiling: cap,
        }
    }

    /// The parents the child-constructor cases use.
    fn two_parents() -> Vec<ParentRef> {
        vec![
            parent_ref("ctx:a", OnSeverPolicy::CascadeClose),
            parent_ref("ctx:b", OnSeverPolicy::CascadeClose),
        ]
    }

    #[test]
    fn every_constructor_commits_the_genesis_creation_timestamp() {
        let gov = governance();
        let cap = ceiling(&[Capability::MessagesRead]);
        let root = ScpContextExtension::for_root(genesis_at(TEST_T0, &gov, &cap)).unwrap();
        let child = ScpContextExtension::for_child(
            genesis_at(TEST_T0, &gov, &cap),
            vec!["ctx:a".to_owned()],
            [0x01; 32],
        )
        .unwrap();
        let from_parents = ScpContextExtension::for_child_from_parents(
            genesis_at(TEST_T0, &gov, &cap),
            &two_parents(),
        )
        .unwrap();
        for ext in [root, child, from_parents] {
            assert_eq!(ext.creation_timestamp_secs, TEST_T0);
            let decoded =
                ScpContextExtension::from_canonical_bytes(&ext.to_canonical_bytes().unwrap())
                    .unwrap();
            assert_eq!(decoded.creation_timestamp_secs, TEST_T0);
        }
    }

    #[test]
    fn every_constructor_accepts_two_to_the_53_minus_one() {
        let gov = governance();
        let cap = ceiling(&[Capability::MessagesRead]);
        let max = MAX_CREATION_TIMESTAMP_SECS;
        assert_eq!(max, 9_007_199_254_740_991);
        let ext = ScpContextExtension::for_root(genesis_at(max, &gov, &cap)).unwrap();
        let decoded =
            ScpContextExtension::from_canonical_bytes(&ext.to_canonical_bytes().unwrap()).unwrap();
        assert_eq!(decoded.creation_timestamp_secs, max);
        ScpContextExtension::for_child(
            genesis_at(max, &gov, &cap),
            vec!["ctx:a".to_owned()],
            [1; 32],
        )
        .unwrap();
        ScpContextExtension::for_child_from_parents(genesis_at(max, &gov, &cap), &two_parents())
            .unwrap();
    }

    #[test]
    fn every_constructor_rejects_a_creation_timestamp_above_two_to_the_53_minus_one() {
        let gov = governance();
        let cap = ceiling(&[Capability::MessagesRead]);
        let over = MAX_CREATION_TIMESTAMP_SECS + 1;
        let expected = ScpContextBindingError::CreationTimestampOutOfRange { value: over };
        assert_eq!(
            ScpContextExtension::for_root(genesis_at(over, &gov, &cap)).unwrap_err(),
            expected
        );
        assert_eq!(
            ScpContextExtension::for_child(
                genesis_at(over, &gov, &cap),
                vec!["ctx:a".to_owned()],
                [0x01; 32],
            )
            .unwrap_err(),
            expected
        );
        assert_eq!(
            ScpContextExtension::for_child_from_parents(
                genesis_at(over, &gov, &cap),
                &two_parents()
            )
            .unwrap_err(),
            expected
        );
        assert_eq!(
            ScpContextExtension::for_root(genesis_at(u64::MAX, &gov, &cap)).unwrap_err(),
            ScpContextBindingError::CreationTimestampOutOfRange { value: u64::MAX }
        );
    }

    #[test]
    fn decoding_rejects_an_extension_without_a_creation_timestamp() {
        let mut json = serde_json::to_value(root_fixture()).unwrap();
        json.as_object_mut()
            .unwrap()
            .remove("creation_timestamp_secs")
            .expect("the fixture carries the field");
        let bytes = crate::jcs::to_vec(&json).unwrap();
        let err = ScpContextExtension::from_canonical_bytes(&bytes).unwrap_err();
        assert!(
            matches!(&err, ScpContextBindingError::DeserializationFailed(reason)
                if reason.contains("creation_timestamp_secs")),
            "{err:?}"
        );
    }

    #[test]
    fn decoding_rejects_a_creation_timestamp_above_two_to_the_53_minus_one() {
        let over = MAX_CREATION_TIMESTAMP_SECS + 1;
        let ext = ScpContextExtension {
            creation_timestamp_secs: over,
            ..root_fixture()
        };
        let bytes = serde_json::to_vec(&ext).unwrap();
        assert_eq!(
            ScpContextExtension::from_canonical_bytes(&bytes).unwrap_err(),
            ScpContextBindingError::CreationTimestampOutOfRange { value: over }
        );
    }

    #[test]
    fn the_committed_creation_timestamp_is_bounded_by_the_members_clock() {
        let now = 1_800_000_000;
        let at = |value: u64| ScpContextExtension {
            creation_timestamp_secs: value,
            ..root_fixture()
        };
        assert_eq!(at(now - 1).committed_creation_timestamp(now), Ok(now - 1));
        let edge = now + CREATION_TIMESTAMP_FUTURE_BOUND_SECS;
        assert_eq!(at(edge).committed_creation_timestamp(now), Ok(edge));
        assert_eq!(
            at(edge + 1).committed_creation_timestamp(now),
            Err(ScpContextBindingError::CreationTimestampInFuture {
                value: edge + 1,
                now_secs: now,
                bound_secs: 300,
            })
        );
        let over = MAX_CREATION_TIMESTAMP_SECS + 1;
        assert_eq!(
            at(over).committed_creation_timestamp(u64::MAX),
            Err(ScpContextBindingError::CreationTimestampOutOfRange { value: over })
        );
    }
}
