---
name: saga-uniffi-export-116
description: Black-hat audit of UniFFI §6.2.4 xctx-saga export (commit 82e7b1e5e, branch feat/116-ffi-saga-export) — caller-principal binding holds; documented design stances, no break
metadata:
  type: project
---

UniFFI export of §6.2.4 cross-context tool-invocation saga (`tool_invoke_cross_context_saga`), the C slice mirroring PyO3 reference (`crates/scp-ffi/src/tools.rs:1006+`).

**Why:** verify the bridge's §6.2.4 *Caller authentication* binding (`enforce_caller_principal_binding`) can't be bypassed.

**How to apply:** the binding HELD against all 6 attack axes. Key load-bearing lines/facts:

- Axis (a) "hosted" = `identity_custody_registry(bi).contains_key(caller_did)`. Sound because the registry is populated ONLY by `identity_create*` on THIS instance (bridge.rs register_identity_custody), and a DID is derived from a keypair — an attacker cannot insert a *victim's* DID without holding its secret. Hosting proves custody-of-secret. Co-resident trust model: anyone holding the Scp instance may act as any identity it hosts (by design).
- Caller's key is NEVER used to sign an authenticating request in this path — presence + membership only. That's the co-resident seam contract (the forward obligation for a real transport leg is at supervisor.rs:5438 doc).
- Actors are registered under the context-id STRING = `handle.context_id()` = `hex(digest)` canonical 64-lowercase-hex for real contexts (supervisor.rs:3927 comment + state.rs:2072 `context_id_to_bytes` round-trip). So bridge `is_member(raw_string)` and producer gate-1 `is_member(hex(context_id_to_bytes(raw)))` coincide for canonical ids. Non-canonical ids fail closed (no actor + no handle).
- `validate_context_id` (common/src/validate.rs:208) permits alphanumeric+`-`+`_`, NOT just 64-hex — but a non-canonical string has no registered actor/handle ⇒ fail-closed (spurious abort, NOT confused deputy).
- Signing-key resolution divergence vs PyO3: UniFFI uses `handle.signing_key` (resolve_context_signing_key_uniffi); PyO3 uses `rt.creator_did`→registry. Both = the local context's active key. Handle registered ONLY in context_create (bridge.rs:9169), context_id runtime-minted, key = creator's. No path to register a handle under an attacker-chosen id with an attacker key.
- **Signer-authorization is DEFERRED to the receipt consumer** (supervisor.rs:7223-7240 doc): the in-saga verify checks the receipt against the very key the bridge handed B — "cannot stand in for an independent resolution." This is a documented ADR-049 §3a stance, NOT a bridge bug. The bridge faithfully resolves the local active key; independent governance-resolution of "is this THE authorized key for target_context" is the auditor/A's burden at consume time.
- Governance vote key resolution FAILS CLOSED (runtime.rs:1387 `key_resolver_for_core` → `not_configured_key_resolver` when no resolver). Production UniFFI wires a real `FfiDhtClient`-backed DualLayerResolver (`ensure_did_resolver_initialized_on` bridge.rs:8492). The test's manual resolver-seed is an InMemoryDhtClient-not-shared unit-harness artifact, NOT a production fail-open. Attack #6 yields nothing.

**Minor (LOW, not a break):** the two SagaAborted messages on the caller-binding distinguish "not hosted" vs "hosted but not a member" (bridge.rs ~334 vs ~347), same code SCP-SAGA-13050. Tiny enumeration oracle, but the caller already holds the instance (can enumerate hosted identities otherwise) — negligible in the co-resident model.

retry_after_ms None-never-0 is correctly preserved (map_saga_error + tests). decode_asserted_nonce fail-closed. Verdict: NO BLOCKER.
