---
name: standing-pair-not-saga-okreturn-softening
description: Spec §5.15.8 standing-pair get-or-create API surface — Ok-return latency-softening confirming pass; APPROVED clean
metadata:
  type: project
---

Spec `spec/standing-pair-not-a-saga-v2` @ a6a2c3ceb (.docs/specs/05-contexts.md §5.15.8), docs-only.

Standing-pair creation reclassified from a 2PC cross-context saga to **single-context async creation** via `standing_context(peer)` get-or-create (a 2-member MLS group is ONE context, sync'd by MLS + event-log layer, not a saga). ADR-049 §3a pins: NO `start_*_saga` FFI export; `register_standing_context` is internal contact-graph only, never an FFI export; auto-revive (§212/§10); spawn-from-Welcome send-gating (§396).

**Why:** PR #1793 originally specced it as a saga (miscategorization). Reframe corrected 2026-06-18.

**The api-design focus — Ok-return softening (this commit):** Wording softened from "the only create-vs-found distinction the caller can observe is none at all on the happy path" to "no **typed** create-vs-found discriminant — a verified member MAY observe the found-vs-create **latency** for their own pair (§5.12.5); what is foreclosed is a typed discriminant + any non-member observation."

**Self-consistency verified (3 layers agree):**
1. §5.15.8 Ok-return contract (line ~1876) — softened wording references §5.12.5 latency.
2. §5.15.8 existence-oracle clause (line ~1880) — already said the §5.12.5 `~0ms found vs ~200ms create` hint "applies ONLY to a verified member's own pair on the success path... MUST NOT apply to the constant-time non-member path."
3. §5.12.5 worked example (line ~951) — literally `sdk.standing_context(bob_did) [get-or-create, ~0ms or ~200ms]`.
No contradiction: member-observable latency (own pair, success path) is orthogonal to the non-member constant-time-wrt-existence MUST.

**How to apply:** The get-or-create surface is clean and misuse-resistant: uniform `Ok`, identical handle type create-vs-found, FFI binding-enrichment prohibition (`created:bool`/`peer_joined:bool` forbidden), no synchronous join confirmation (async consent-on-receipt forecloses the synchronous block oracle — but NOT the relay-observable published-KeyPackage bit, which they correctly scope), reaper/transparent-re-drive auto-revive so handles never dangle. Verdict: APPROVED clean. Don't re-litigate the latency carve-out — member-side latency observability is intentional and already bounded by two MUSTs on the non-member path.

Related: [[pr1744_pseudonym_routing_rehome]] (sibling standing-context work).
