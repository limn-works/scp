---
name: pr2235-appbound-appunbound
description: Crypto review of PR #2235 (§8.4 AppBound/AppUnbound durable event-log appends) — convergence, canonicalization, signature-scope findings
metadata:
  type: project
---

# PR #2235 — §8.4 AppBound/AppUnbound durable Merkle appends (review pass 1, commit 60ad49aac)

Verified facts (re-check before reusing; state may have moved):

- **EventType tags 74/75 pre-exist on main** (`crates/scp-event-log/src/tree.rs` `event_type_tag`). PR does NOT touch tree.rs. No collision; next free = 78 (59 retired).
- **`AppBoundPayload` / `AppUnboundPayload` pre-exist** in `crates/scp-event-log/src/payload.rs`. `encode_payload` = `rmp_serde::to_vec` (positional array, no map keys) — deterministic, no key-order hazard. The "sort before encode" claim is *necessary and sufficient for the payload itself*.
- **Leaf preimage** = `SHA-256(0x00 ‖ rmp_serde(Event))` (`tree::leaf_hash`), includes the (empty) signature. `EventType` serializes by NAME string under rmp_serde — adding variants does not shift other leaves.
- **Production appends are UNSIGNED**: `ContextLog::append` (`crates/scp-runtime/src/context/providers/event_log.rs:94-108`) sets `signature: Vec::new()` and calls `tree::append_unsigned_event`. `append_unsigned_event`'s rustdoc "legitimate callers" list is stale (claims only the MCP bridge + tests).
- **No propagation**: `EventType::AppBound/AppUnbound` appear only in payload/tree/pruning/app_sandbox/tests. No receive-side or MLS-commit handler. Appends are node-local ⇒ violates ADR-011 Amendment convergence requirement (`.docs/adrs/phase-2.md` explicitly lists "app-binding" in the MLS-commit-ordered convergent stream).
- **`Capability` Display is injective** (`Custom` → `custom:{name}`) and round-trips through `Capability::new`. Sort is `sort_unstable()` on `String` = UTF-8 byte order (locale-free). Hazard: `Custom` can carry arbitrary UTF-8 from the declaration ⇒ a JS/UTF-16 reimplementation would sort astral-plane chars differently.
- **`CapabilityDeclaration::verify` uses non-strict `ed25519_dalek::Verifier::verify`** (`app_sandbox.rs:~610`), while the rest of the repo uses `verify_strict` (scp-crypto, scp-did, scp-dht, checkpoint, governance, outlets, bridge_auth).
- **actor_did trim divergence**: UniFFI passes `actor_did.trim()`; PyO3 and NAPI pass the raw string. `validate_did` accepts trailing whitespace ⇒ cross-bridge leaf-hash divergence for the same input.
- **Caller-supplied `timestamp_secs`** on all 4 SDKs. `timestamp_secs: u64` occurs ONLY at bridge.rs:15729/15875 (the two new fns) in the whole UniFFI bridge; every other site uses `scp_clock::SystemClock.now_secs()`.
- **Fabricated spec citations**: `MAX_APP_VERSION_BYTES = 64` and `MAX_ACTIONS_PER_CAPABILITY_ENTRY = 32` are commented "(spec 8.4.1)" but `.docs/specs/08-products-and-apps-in-the-graph.md` §8.4.1 defines neither.
- **`declaration_content_hash` deleted** by this PR; nothing else referenced it. Consequence: the AppBound leaf has no cryptographic binding to the signed declaration.
- **UniFFI ceiling source divergence**: UniFFI reads `handle.ceiling_strings` (immutable create/join snapshot) while PyO3/NAPI read the mutable per-context UCAN state `ceiling_strings`.
- §25 KAT (`crates/scp-event-log/tests/test_vectors.rs:~379`) pins one AppBound leaf with a SINGLE ASCII capability — does not pin sort order or non-ASCII.

Related open issues (do not re-litigate as blockers): #2230 actor routing, #2231 persist declaration, #2232 `check_scoped_capability` never called in prod.
