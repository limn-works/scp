//! Provenance marking for bridged content.
//!
//! All actions and content attributed to shadow identities carry
//! [`BridgeProvenance`](super::BridgeConnector) metadata extending
//! `DataProvenance`. This includes the originating platform, bridge
//! connector ID, operator DID, operating mode, and shadow/claimed status.
//! No shadow action is mistakable for a native SCP action.
//!
//! See ADR-023 in `.docs/adrs/phase-5.md`.
