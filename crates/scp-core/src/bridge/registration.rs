//! Bridge registration and governance approval.
//!
//! Handles the lifecycle of registering a bridge connector with a context:
//! the operator DID presents a registration request, context governance
//! approves or rejects, and the registered bridge becomes visible in context
//! metadata. Registration is recorded as a context event in the Merkle log.
//!
//! See ADR-023 in `.docs/adrs/phase-5.md`.
