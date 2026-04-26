//! Governance handlers extracted from `context::manager` for cohesion
//! around §6.2.0.1 round-6 atomic-removal+rotation invariants
//! (SCP-OUT-042c).
//!
//! The [`admin_removal`] submodule hosts the
//! `RemoveMember`-with-admin-role handler that emits one
//! `InterfaceSaltRotated` per active interface as a sibling MLS-commit
//! batch entry, plus the `hop_salt` state machine
//! (`PreRotation → Frozen → PostRotation`), the Frozen-window
//! outbound-queue discipline, and the round-6 verifier rule.
//!
//! See `.docs/specs/06-cross-context-communication.md` §6.2.0.1
//! "Admin-removal salt rotation" and ADR-049 round 6 §"Admin-removal
//! rotation TOCTOU closure".

pub mod admin_removal;
