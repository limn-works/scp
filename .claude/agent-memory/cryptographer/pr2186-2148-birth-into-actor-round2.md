---
name: pr2186-2148-birth-into-actor-round2
description: Round-2 crypto re-review of PR #2186 (#2148 birth-into-actor) fixes F1/F3/F6/F11 — core SOUND, 2 open LOW items (F6 incomplete, F3 two overclaim comments)
metadata:
  type: project
---

# PR #2186 (#2148 birth-into-actor) Round-2 crypto re-review

Round-1: dissolution SOUND. Round-2 verifies fixes. Core remains SOUND; two LOW open items.

**Why:** provider per-context crypto fully dissolved into actor-owned PerContextState; birth returns OwnedMlsCryptoState directly (no take_crypto_state round-trip → #2167 TOCTOU impossible by construction).
**How to apply:** if re-reviewing, the two open items below are the only crypto findings.

## RESOLVED
- **F1** Class-S fail-closed rotation seam re-homed onto actor. state.rs:2703 rotate_sender_key: fault check at 2716-2721 fires BEFORE generate_sender_key(2724)/epoch checked_add(2732)/store set(2741). Only mutation on fault path = mem::replace of the one-shot flag itself. Gating airtight — ALL refs cfg(any(test,feature="testing")): field 512, Debug 556, Default 573, seed init 2222, arm fn 2233, read 2716. Nothing prod-reachable. Test state.rs:4249 asserts epoch unchanged (fail-closed) then +1 (normal). SOUND.
- **F11** OwnedMlsCryptoState::fresh_birth (provider.rs:372) collapses 3 birth sites (699/739/769). sender_key=generate_sender_key(), epoch=1, send_sequence=0, empty stores. Byte-identical to pre-collapse (verified in diff). SOUND.
- **dispose_secrets** (state.rs:2130 ContextCryptoState / 2249 PerContextState / provider.rs:392 OwnedMlsCryptoState): runs scp_mls::group::destroy_group → best-effort-zeroizes Ed25519 signer (SignatureKeyPair has NO Zeroize, scp-mls#82); SenderKey ZeroizeOnDrop. Idempotent. Wired sites (supervisor 4548 dup-reg, 13913 WELCOME persist-fail, builder 999/1034 CREATE steps 4&6) safe — no double-free/use-after-dispose.

## OPEN (LOW, both defense-in-depth / doc accuracy — NOT breaks in soundness)
- **F6 INCOMPLETE**: builder.rs create_context has 4 post-birth creation-rollback branches; only steps 4(999)/6(1034) dispose. **Steps 7 (ContextCreated append fail, 1054-1060) and 8 (MemberJoined append fail, 1085-1090) return Err with owned_crypto still Some and do NOT dispose** → Ed25519 signer bare-dropped (freed, NOT zeroized) for Encrypted context. Same class F6 fixes. Fix: add `if let Some(mut owned) = owned_crypto { owned.dispose_secrets(); }` before receipt.rollback at 1056 & 1086 (borrow-check OK, each Err branch diverges). Also makes builder docs 705-776 ("post-birth failure disposes owned material") overclaim.
- **F3 two overclaim comments remain**: canonical zeroize wording precise in state.rs 2113-2118, builder.rs 707-710, ttl.rs 749-751, provider.rs 777. BUT lifecycle.rs:603-604 and ttl_close_helpers.rs:894-895 still claim a bare drop "would leave epoch secrets resident in OpenMLS storage" — contradicts corrected "bare drop DOES free that in-memory InMemoryMlsProvider storage; only the SIGNER isn't zeroized." Reword to match canonical sites.

## Key crypto-memory facts (this move)
- Each ScpMlsGroup owns its OWN in-memory OpenMLS provider (InMemoryMlsProvider) — NOT a shared persistent store. Bare drop frees epoch secrets but does NOT zeroize the Ed25519 signer.
- Live-actor close/TTL seams (lifecycle CloseContext, ttl finalize, ttl_close_helpers) call dispose_secrets because PerContextState is NOT dropped there — nothing else frees the material.
