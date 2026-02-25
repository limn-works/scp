//! Shadow claiming via identity attestation.
//!
//! When an external platform participant wants to transition from a shadow
//! identity to a native SCP identity, they publish an identity attestation
//! (Spec section 3.5) binding their external handle to a DID. The protocol
//! verifies the attestation matches the shadow's platform handle, retires
//! the shadow, and retroattributes historical actions to the claimant DID.
//! Claiming is one-way and irreversible.
//!
//! See ADR-023 in `.docs/adrs/phase-5.md`.
