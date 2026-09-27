---
name: browser-client-transport-facts
description: Non-obvious facts behind the ADR-057 in-browser client transport (scp-mls, scp-client, scp-client-wasm) — openmls seed extraction, relay self-echo, no backfill, and why the test relay must be faithful
metadata:
  type: project
---

- **openmls stores the Ed25519 seed, and its accessor is test-only.**
  `openmls_basic_credential::SignatureKeyPair` for Ed25519 stores
  `ed25519_dalek::SigningKey::to_bytes()`, the 32-byte RFC 8032 seed that
  `SigningKey::from_bytes` consumes, not the 64-byte expanded key. Its `private()` accessor is
  gated behind openmls's `test-utils` feature, so production code recovers the seed through
  serde (`extract_ed25519_seed` in `crates/scp-mls/src/group.rs`). Never enable `test-utils` to
  reach it.
- **The relay echoes a publish back to its publisher.** `deliver_to_subscribers` in
  `scp-transport` delivers every PUBLISH to all subscribers of the routing id, including the
  publisher. A member that publishes to and subscribes on the same routing id receives its own
  MLS message, which openmls rejects with `CannotDecryptOwnMessage`; classify and drop
  self-echo before decryption.
- **Native subscribes with `since: None`, so there is no backfill.** A joiner that subscribes
  after existing members announced misses those announcements. The fix is reciprocal
  announcement: the joiner announces on join, and each member re-announces the first time it
  records a new peer.
- **A test relay must model the real one.** A loopback harness without self-echo,
  subscribe-before-publish timing, and backfill semantics validated a design that failed on
  the real relay. A relay mock for these tests needs a subscription table, self-echo, the
  real timing order, backfill on `since: Some`, and a pump that iterates until quiescent so
  the reciprocal-announcement cascade completes.
- **wasm-bindgen error values panic on the host.** `JsValue::from`, `JsError::new`, and any
  conversion into them call wasm-bindgen imports that panic off wasm32, so a host `#[test]`
  cannot exercise the `Err` arm of a `#[wasm_bindgen]` function. Test the underlying
  validator, which returns a plain Rust error, and test the `Ok` arm through the wrapper.
