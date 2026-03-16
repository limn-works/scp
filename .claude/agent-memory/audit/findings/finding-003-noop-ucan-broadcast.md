# Finding 003: NoOp UCAN validators on broadcast subscription (all non-WASM bridges)

## Severity: moderate

## Summary

All three non-WASM bridges (PyO3, NAPI, UniFFI) use NoOp UCAN validation trait implementations for broadcast subscription. This means broadcast subscription in gated mode bypasses DID resolution, nonce tracking, revocation checking, and proof resolution.

## Evidence

**PyO3 bridge:** `crates/scp-ffi/src/context.rs`, lines 1582-1620
```rust
// No-op UCAN validation trait stubs for subscribe_broadcast (#369)
struct NoOpDidResolver;
struct NoOpNonceTracker;
struct NoOpRevocationChecker;
struct NoOpProofResolver;
```

**NAPI bridge:** `crates/scp-ffi/napi/src/context.rs`, lines 902-906
```rust
// No-op UCAN validation trait stubs for subscribe_broadcast
// does not require UCAN validation; gated mode validation will be wired
```

**UniFFI bridge:** `crates/scp-ffi/uniffi/src/bridge.rs`, lines 8030-8075
```rust
// No-op validation trait stubs for subscribe_broadcast generic params
pub(crate) struct NoOpDidResolver;
pub(crate) struct NoOpNonceTracker;
pub(crate) struct NoOpRevocationChecker;
pub(crate) struct NoOpProofResolver;
```

**WASM bridge** has full validation — it performs the complete 11-step UCAN pipeline.

## Expected Behavior

Gated broadcast mode should validate UCAN tokens using real resolvers:
- `DidResolver` should resolve the subscriber's public key from their DID document
- `NonceTracker` should prevent replay attacks
- `RevocationChecker` should reject revoked tokens
- `ProofResolver` should resolve delegation chains

## Root Cause

The comments in all three bridges indicate this was deferred: "gated mode validation will be wired when the full UCAN pipeline is integrated with the FFI layer." The WASM bridge was implemented later with full validation from the start.

## Suggested Fix

Wire the real UCAN validation adapters (already present in each bridge for `ucan_validate` calls) into the broadcast subscription path.
