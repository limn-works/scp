//! Provenance attachment at cross-context boundaries.
//!
//! Provides [`attach_provenance`] for automatic provenance tagging when data
//! crosses context boundaries, and [`check_chain_depth`] for enforcing the
//! protocol maximum hop count. Chain path management utilities track the
//! ordered list of intermediary context IDs.
//!
//! See ADR-019 acceptance criteria 2-3, 6.
//!
//! **Status:** Stub -- implementation in SCP-071.
