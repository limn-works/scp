//! The MLS backend, its storage adapter and `KeyPackage` attestation verification.

// The adder's KeyPackage-attestation verifier over the supervisor's
// `KeyResolver` — §9.7.1 checks 1 and 3–13 on an Add (CRYPTO-22 S4, Layer B),
// wired at `Supervisor::invite_member`.
pub mod attestation_verification;

// Test-only minting of attested KeyPackages with a local Ed25519 key.
#[cfg(any(test, feature = "testing"))]
pub mod test_support;

// The async MLS backend and its storage adapter (tokio-coupled, node-only).
pub mod backend;
pub mod production_backend;
pub mod storage_adapter;
