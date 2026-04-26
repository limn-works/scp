//! Outlet-interface accept-time cryptographic constructions
//! (spec §6.2.0.1, SCP-OUT-042b).
//!
//! This module hosts the runtime-side crypto for the bidirectional
//! consent protocol that establishes a cross-context outlet interface:
//!
//! - [`ikm_commitment::IkmCommitment`] — the per-side accept-time IKM
//!   commitment + Ed25519 signature under the
//!   `SCP-OUTLET-IKM-COMMITMENT-V1:` domain separator (§6.2.0.1
//!   "Committed-IKM signing"). The struct encapsulates the
//!   `(context_a_id, context_b_id)` pair so the canonical lexicographic
//!   ordering invariant is enforced inside the type instead of leaving
//!   the swap-risk to call sites (closes the API MINOR OUT-031 round-6
//!   swap-risk; ADR-049 round 6 §"`IkmCommitment` encapsulation").
//! - [`hop_salt::derive_hop_salt_from_committed_ikms`] — the deterministic
//!   `hop_salt` derivation from the committed `(ikm_a, ikm_b)` pair
//!   (§6.2.0.1 step 2). HKDF-SHA-256 with the
//!   `SCP-CONTEXT-HOP-SALT-V1:` info string and canonically ordered
//!   inputs. Symmetric across both contexts.
//! - [`cluster_detection`] — the round-6 four-predicate
//!   cluster-detection rolling-window algorithm, the population-weighted
//!   interface-spam floor, the `(k+1)²` quadratic fee, the
//!   `outlet:offer:* / query:* / call:*` capability-holder enumerator,
//!   and the `RemoveMember`-admin induced-rotations validator
//!   (SCP-OUT-042d).
//!
//! See `.docs/specs/06-cross-context-communication.md` §6.2.0.1 for the
//! full protocol; `.docs/specs/09-security-model.md` §9.18.2 registers
//! both `SCP-OUTLET-IKM-COMMITMENT-V1:` and `SCP-OUTLET-IKM-ROTATE-V1:`
//! domain separators (the latter is consumed in OUT-042c). §9.18.B
//! registers the round-6 `ContextParams::base_cost_scale` and
//! `ContextParams::outlet_error_buffer_max_secs`.

pub mod cluster_detection;
pub mod hop_salt;
pub mod ikm_commitment;

pub use cluster_detection::{
    CLUSTER_DETECTION_WINDOW_MS, InducedRotationsError, InterfaceCandidate,
    compute_cluster_match_count, compute_interface_fee, enumerate_capability_holders,
    interface_base_cost_floor, is_outlet_interface_capability,
    validate_remove_member_induced_rotations,
};
pub use hop_salt::{HOP_SALT_INFO_PREFIX, derive_hop_salt_from_committed_ikms};
pub use ikm_commitment::{
    IKM_COMMITMENT_DOMAIN_SEPARATOR, IKM_EXPORTER_LABEL_PREFIX, IkmCommitment,
    IkmCommitmentDeriveError, IkmSignatureError, MlsExporter, canonical_pair,
};
