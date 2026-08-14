---
name: attack-xctx-saga-caller-binding
description: Adversarial review of §6.2.4 cross-context tool-invocation saga FFI export caller-authentication binding (#116); what holds and the one real parity gap
metadata:
  type: project
---

# §6.2.4 cross-context saga FFI export — caller-binding attack surface

Reviewed commit `6edac5f41` (UniFFI Slice C, branch feat/116-ffi-saga-export). The
saga's only security guarantee against caller impersonation is the bridge-side
`enforce_caller_principal_binding`. The producer
(`Supervisor::start_cross_context_tool_invocation_saga`, supervisor.rs:5478) signs
receipts with whatever `signing_keys.target`/`caller` it is handed — it does NOT
independently verify those keys belong to the named contexts. The in-saga
`verify_commit_b_receipt` (supervisor.rs:7260) is **integrity-only by design**
(verifies against the SAME key the FSM handed B; comment at 7226–7235 is explicit).
So the whole trust rests on the bridge resolving the correct per-context key.

## What holds (cited)
- **Handle affinity** `check_handle` (bridge_instance.rs:754, `const fn`, no TOCTOU)
  kills foreign-instance handles before anything else.
- **UniFFI is STRONGER than PyO3 reference** on the chokepoint axis: UniFFI takes
  typed `Arc<ContextHandle>` and derives ids from affine handles; PyO3 (tools.rs:1062)
  takes free STRING ids + registry lookup. Handle-derivation structurally closes the
  string-naming confused-deputy surface. ids/keys/binding all from the SAME handle ⇒
  no caller/target transposition gap.
- **Two-axis binding** (bridge.rs ~5506 custody-registry contains_key; ~5521
  supervisor.is_member) layered over producer gate-1 (membership, supervisor.rs:5504)
  + gate-2 (bidirectional interface, supervisor.rs:5528, the BLACK-624-02 fix).
- `ContextHandle.signing_key` is the CREATOR's key (bridge.rs:2779) — contexts sign
  with creator/Active Signing Key; member-auth is is_member/role. Separate concerns,
  no "sign as a member I'm not" gap.
- retry_after_ms None never coerced to 0; supervisor-minted SagaId; fail-closed nonce.

## The one real finding (defense-in-depth, fail-closed, NOT a saga blocker)
UniFFI `identity_create*` (bridge.rs:8610/8630) mints the DID doc on a throwaway
`DidDht::new()` and calls `ensure_did_resolver_initialized_on` but has **no
`publish_to_resolver_dht_for` equivalent** (PyO3 has it at identity.rs:129/1021/1124).
So governance vote verification (which resolves the proposer key — a LIVE gate, proven
by the test having to seed the doc) works in-process only via the test's manual
`seed_owner_document_into_resolver`. Impact: fail-closed (missing publish ⇒ verify
FAILS, never spuriously passes) but a real UniFFI-vs-PyO3/NAPI parity gap. File an issue.

## Threat-model notes
- "Hosted by this instance" == channel-authenticated holds ONLY under single-principal
  process isolation. Multi-tenant bridge hosting distrusting identities: axis-a alone
  doesn't separate co-tenants — is_member is the only gate. Embedder must isolate.
- Receipt consumers MUST independently resolve the signer is the governance-authorized
  Active Signing Key (SagaResult.receipt doc bridge.rs:188 already says this) — the
  in-saga verify is integrity-only.
