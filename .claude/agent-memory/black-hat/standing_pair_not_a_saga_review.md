---
name: standing-pair-not-a-saga-review
description: Black-hat review of spec/standing-pair-not-a-saga-v2 (HEAD aaa4e1460) — auto-accept allowlist-only, single-context async, length-prefix derivation. No viable attack remains; residuals honestly disclosed.
metadata:
  type: project
---

# Standing-pair-not-a-saga spec review (branch spec/standing-pair-not-a-saga-v2, HEAD aaa4e1460)

Docs-only change. §5.12.2/§5.13.7/§5.15.8/§3.8.1 + §09 + ADR-049 + DEFERRED + sdk-common + sketch + technical-overview.

**Verdict: no viable protocol attack remains; no sibling bug found.** All residuals I probed are ALREADY disclosed honestly in the text.

## What I verified holds
- Auto-accept is allowlist-only (`known_did`/`Explicit`). `Any`+`SharedContext`+`discovery_context` removed at BOTH sites (scp-protocol enum + WASM check_trust). No silent-auto-accept path: shared-context co-membership, child-context eligibility floor (§5.13.2 relay-enforced), discovery — all explicitly NOT trust signals. Default = no-policy ⇒ prompt (default-deny). Tool-bearing + stranger-standing-pair caps are non-overridable MUSTs.
- No self-clear: candidate cannot add itself to evaluator's allowlist (stated normatively).
- Length-prefix derivation `SHA-256("standing:" ‖ len32(did_lo)‖did_lo ‖ len32(did_hi)‖did_hi)` — injectivity unconditional by construction (len32 fixes field boundaries), no longer depends on colon-freedom. §3.8.1 narrowed to canonical AGREEMENT only.
- Collision resolution sound: did_lo survives, ignores all inbound (builds no state) ⇒ did_hi's destroy of its own orphan equivocates against nobody (did_lo never observed it). did_hi's self-group can only ever have did_lo as 2nd member by derivation, and did_lo ignores ⇒ orphan stays single-member ⇒ destroy is clean. join-then-destroy gated on SAME single-use init-key consumption (ADR-049 §9) + §9.7.1 bound-creator + generation check, all under per-context actor mutex. Forecloses forged-creator DoS, replayed-stale-destroy, confused-deputy recreate-then-destroy.
- §9.7.1 bound-creator check is REAL and supports the claim (ScpCredential.did==did_lo AND leaf sig key resolves to VM in did_lo's DID doc).
- Existence-oracle: non-member path constant-time in value AND timing; AlreadyExists→Ok only for verified-self-membership. §5.12.5 latency hint scoped to member's own pair only.
- Block gate: best-effort propagation self-heals post-join; honestly discloses the send-gated did_hi cannot SEVER until Phase-2E (sender-key rotation is a SEND) — an ACTIVE attacker-refreshable did_lo→did_hi channel disclosed, bounded to one pair, no key exposure, receive-side drop-filter is SHOULD-only.

## Honestly-disclosed residuals (NOT new findings — already in text)
- Reflected-resolution DoS: convergence-candidate carve-out exempts from cooldown; forged Welcome under publicly-computable id forces 1 un-throttled DID-resolve + 1 sig-verify (network op against 3rd-party DID host). Bounded, no amplification. DISCLOSED in §5.15.8 anti-spam clause.
- Fresh-DID-fleet approval-prompt spam: bounded by §9.3 minting cost, N prompts not N joins. DISCLOSED.
- did:web exotic canonicalization divergence → undiagnosable pairing-denial (availability dual). did:web is fallback-only; did:dht airtight. DISCLOSED in §3.8.1.
- Wire-observable solicitation: Welcome rides publicly-computable invitations routing-id before consent gate; only reply-oracle closed, not solicitation visibility. DISCLOSED.

## Coherence checks passed
- No residual "standing-pair saga" / "three sagas" mislabel anywhere (all are not-a-saga/superseded/historical-framing).
- ADR-049 §9 fused-join two-anchor single-use + §10 auto-revive both real and support claims.
- bilateral-persistent memory_scope:full (line 637) grounds the non-overridable stranger default-deny.

## Minor framing note (non-blocking)
- standing_context(identity, peer) signature ⇒ caller is always a member by construction. The "non-member caller" existence-oracle path is reachable only via a lower-level raw-context-id entrypoint; the clause is preemptive defense-in-depth (sound), not a defended non-threat.
