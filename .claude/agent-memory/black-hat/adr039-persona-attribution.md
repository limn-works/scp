---
name: adr039-persona-attribution
description: ADR-039 persona attribution (#active vs #agent) wiring audit — the cryptographic binding is sound, but every production key resolver returns None, so the guarantee is wired through types and not through any shipping resolver.
metadata:
  type: project
---

Branch `claude/scp-network-architecture-7zq21l`, commits ba06a8e0 + 7d4cdcf0.

**Binding is cryptographically sound.** `signing_key_id` is inside the signed inner-envelope preimage
(`compute_canonical_hash`, `crates/scp-protocol/src/envelope/inner/mod.rs:557`), domain-separated and
length-prefixed. `verify_inner_signature` (:330) reconstructs the hash from `inner.signing_key_id` (:370),
the same value used for resolution at `messaging_helpers.rs:309-310`. `context_id` is in the preimage
(:549), so a persona claim cannot be replayed cross-context. A MITM, relay, or non-member cannot flip
`signing_key_id`; a malicious sender cannot make an agent message read as `#active` **unless the resolver
returns the same key for both verification methods**. Genuinely tested — `document_backed_resolver`
(`agent_binding_pipeline_tests.rs:106`) maps `(DID, Active)` and `(DID, Agent)` to distinct keys and
test 302 proves wrong-key rejection.

**HIGH — wiring gap (not live-exploitable in that diff): every production resolver collapses or returns
`None`.** `self_host.rs:452-453`, all FFI bridges, `bridge_runtime.rs` `not_configured_key_resolver`, and
`bridge_instance.rs` all return `|_, _| None`. The VM-aware guarantee is threaded through the types but no
shipping resolver returns distinct keys, and a lazy future resolver `|did, _| lookup(did)` silently
reintroduces the collapse — an agent message then verifies as `#active`. No mechanical check forbids
ignoring the `SigningKeyId` argument.

**MEDIUM — all FFI send paths hardcode `SigningKeyId::Active`** (`napi/context.rs`, `ffi/src/context.rs`,
`uniffi/bridge.rs`). No SDK lets an agent send under `#agent`, so the accountability claim is not
expressible from any binding.

**LOW (honest, fail-closed) — governance votes resolve `#active` unconditionally** (`mod.rs:1593`;
majority/multisig/unanimity). An attacker holding only `#agent` gets `verify_vote` failure → vote
rejected. No false-accept, and the vote carries no `signing_key_id`, so there is no downgrade vector.

**Sound:** economy kid parsing routes through `from_fragment` (`identity.rs:200`) — exact byte match,
rejects `"active"`, `"agent"`, `"#0"`, `""`, `"#unknown"` as `MalformedToken`; no unicode/case coercion,
no panic.

**Nits:** `validate.rs:702-710` `enforce_ucan_category_a` hand-rolls the kid match instead of using
`from_fragment` (drift risk). `enforce_inner_envelope_category_a` is never called on the live receive
path (only `sign.rs` tests) — pre-existing.
