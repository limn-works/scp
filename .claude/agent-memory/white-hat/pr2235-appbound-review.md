---
name: pr2235-appbound-review
description: White-hat review of PR #2235 (§8.4 AppBound/AppUnbound durable event-log appends, tags 74/75) across PyO3/UniFFI/NAPI bridges
metadata:
  type: project
---

# PR #2235 feat/app-bound-unbound-event-log (2026-08-03)

§8.4 AppBound(74)/AppUnbound(75) durable leaves. Error codes CTX_2056-2059.
Core: crates/scp-runtime/src/context/app_sandbox.rs (bind_app/unbind_app, shared).
Payload: crates/scp-event-log/src/payload.rs (AppBoundPayload/AppUnboundPayload).

## Findings (no BLOCKERs)
- **WARNING TOCTOU**: was-bound check NOT race-free. contains_key (lock A) →
  block_on append → remove (lock B), await between. Two concurrent unbinds both
  pass is_bound → duplicate AppUnbound durable leaves. bind has NO idempotency
  guard (double-bind = 2 leaves + registry lost-update). Subsumed by #2230
  (route through ContextActor serializes per-context).
- **WARNING uncapped actions**: CapabilityEntry.actions Vec has NO max in
  validate_structure (only is_empty check). 64 entries x unbounded actions →
  unbounded derived capability set → inflated AppBoundPayload.capabilities leaf.
- **WARNING trim parity**: UniFFI unbind trims trimmed_app for is_bound/remove;
  PyO3+NAPI use RAW app_did. bind stores scoped.app_did().trim() key everywhere.
  validate_did allows trailing space (not control char). So "did:key:z... "
  unbinds on UniFFI, fails CTX_2059 on PyO3/NAPI. Cross-bridge non-uniformity.
- **WARNING timestamp**: timestamp_secs caller-supplied, unvalidated → arbitrary
  timestamps into durable Merkle leaves (participation-fact time distortion).
  Compounds actor_did-unauthenticated.
- INFO: EventLogFailed propagates raw underlying error string to FFI caller.
- INFO: bind appends leaf BEFORE in-memory insert; insert-fail after append =
  durably bound, unenforceable, un-unbindable.
- INFO: app_did (from decl) not run through validate_did on bind (relies on
  signature verify); unbind does validate it.

## Well-Defended
- capabilities.sort_unstable() before encode_payload in shared bind_app →
  deterministic Merkle bytes (positional MessagePack, HashSet order neutralized).
- Fail-closed: insert-after-append (bind), remove-after-append (unbind). No
  silent attach/detach on EventLogFailed.
- Suspension-aware role derivation (ceiling filtered by member_has_capability).
- Signature verify (ed25519 Verifier) + JCS canonical excluding sig + all-or-nothing.
- project_payload total/panic-free; encode_payload Result-handled (no new unwrap).
- did:dht single-parser delegation (extract_public_key_from_did) fixes prior
  33-byte 'z'-prefix bug.
