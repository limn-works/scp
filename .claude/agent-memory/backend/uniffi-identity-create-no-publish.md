---
name: uniffi-identity-create-no-publish
description: UniFFI identity_create does NOT publish the minted DID document to a resolver-visible store (PyO3/NAPI do via publish_to_resolver_dht_for / publish_to_shared_dht_for). In-process resolution of locally-created identities fails on UniFFI.
metadata:
  type: project
---

The UniFFI bridge's `identity_create` (and `identity_create_with_custody` / `_with_agent_key`) does NOT publish the minted DID document to a resolver-visible store. It only calls `ensure_did_resolver_initialized_on` (which builds a `DualLayerResolver` over a FRESH, unretained `InMemoryDhtClient`) and mints the document on a throwaway local `DidDht`.

**Why this matters:** PyO3 `identity_create` calls `publish_to_resolver_dht_for` (`crates/scp-ffi/src/identity.rs`); NAPI calls `publish_to_shared_dht_for`. UniFFI has no equivalent publish step. Consequence: a locally-created UniFFI in-memory identity is NOT resolvable by its own bridge instance in a single-process harness. Any in-bridge flow needing that — governance vote verification (proposer-key resolution), UCAN proof validation, receipt signer-authorization — fails. It is fail-CLOSED (governance key resolver returns None → vote verification fails, never fails open), so it's an availability/parity gap, not an auth bypass. In real production both PyO3/NAPI and UniFFI rely on the shared Mainline DHT, so external resolution works; the gap bites in-process unit/single-bridge use.

**How to apply:** Surfaced by FFI task #116 Slice C (its in-crate e2e had to manually seed the resolver via a BEP44 sign+publish mirroring `publish_to_shared_dht_for` to reach a real Committed). Flagged by alignment + security reviewers. A follow-up issue should add the publish step to all three UniFFI create paths and have `ensure_did_resolver_initialized_on` retain the DHT client so publish targets the resolver's store. If you touch UniFFI identity creation or hit "unknown voter: cannot resolve public key for DID" in a UniFFI test, this is why.
