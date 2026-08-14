# Standing-Pair Consent-Model Audit (spec/standing-pair-not-a-saga-v2)

Docs-only spec change: standing-pair = single-context async (not saga); length-prefixed derived_context_id;
§3.8.1 canonical DID; Welcome-receipt mismatch guard; HEADLINE: auto-accept ALLOWLIST-ONLY
(§5.12.2 — shared_context + discovery_context arms REMOVED; only known_did(list) survives; no default policy = default-deny).

## Verdict (HEAD 01db91cf1, confirming pass 2026-06-24): FULLY CLOSED. No silent-auto-accept path, no sibling remains.

### What the prior LOW finding was, and how 01db91cf1 fixed it:
- Prior HEAD 43cc189f0 §5.13.7 line 1381 said child-context lineage "provides a stronger trust signal" — same phrasing-shape as the removed shared_context arm (co-membership = trust). I flagged it LOW (wording could let a reader re-derive shared_context under another name).
- 01db91cf1 REWROTE 1381: lineage is now an explicit "eligibility FLOOR on who can reach you (relay-enforced §5.13.2), NOT a trust signal, does NOT trigger auto-accept. Auto-accepting a child follows §5.12.2: inviter DID MUST be on known_did allowlist; else prompt (default-deny). Co-membership is the floor that lets the invitation reach you, never a substitute for the allowlist." This is the THIRD inference path closed (after the two §5.12.2 arms). Floor-vs-trust conflation closed by construction.

## Why structurally closed (not just prose):
- Allowlist has NO self-clear path — candidate cannot add itself to evaluator's allowlist.
- Weak signals appear ONLY as discovery/provenance labels, never accept inputs:
  - §24 DiscoveryMethod::SharedContext/Registry = provenance label (how discovered), not accept input.
  - §09.6.4 "shared context membership / registry discovery / referral" = ways to ENCOUNTER a DID, not trust it. §09:113 "from a known DID", §09:115 strangers => human facilitation. Consistent.
  - §22 high_trust()/DiscoveryContextVerified = registry Sybil-admission + resolution trust level, consumer-decision input, not context-join auto-accept. §22 "join" = user deliberately resolving+joining a sought context, not inbound auto-accept.
  - §05:1022 first-contact optimization (shared context => cached keys) = perf only (skip DID resolution); §5.15.8 consent gate still runs.
- WASM divergence risk noted in-spec: code PR must remove Any+SharedContext at BOTH scp-protocol context::policy (+invitation.rs satisfies_trust) AND WASM check_trust reimpl (scp-ffi/wasm ADR-034) or WASM silently retains accept-from-any.

## Length-prefix injectivity (§5.15.8): SHA-256("standing:" ‖ len32(did_lo)‖did_lo ‖ len32(did_hi)‖did_hi), len32=4B BE (§9.5.1). Unconditional by construction; colon-freedom assumption RETIRED. §3.8.1 narrowed to byte-AGREEMENT only. did:dht airtight; did:web best-effort, backstopped by step-4(a0) receive-side mismatch guard.

## Existence-oracle (§5.15.8 line 1889): AlreadyExists→Ok ONLY for verified-self-membership; non-member path constant-time + value-indistinguishable from generic rejection. No create-vs-found/peer_joined discriminant; identical shape all bindings. Sound.

## Collision resolution (§5.15.8): did_lo survives by construction; did_hi joins-then-destroys gated on SAME single-use init-key + §9.7.1 bound-creator under actor mutex + generation check. Forecloses forged-creator DoS, replayed-Welcome stale-destroy, confused-deputy recreate-then-destroy. Sound.

## Honest residuals spec ALREADY discloses (NOT new findings, bounded):
- Anti-spam convergence-candidate exemption: reflected-resolution DoS (1 DID-resolve + 1 sig-verify per forged Welcome, publicly-computable id, network op against 3rd-party DID host). Disclosed §5.15.8.
- Send-gated did_hi: durable decrypt-capable did_lo→did_hi channel until Phase-2E; receive-side drop-filter SHOULD-only, unenforced; close_context re-derives same id (no escape). In-pair only, no key exposure. Disclosed.
- step-4(b) default-deny is MUST at SDK consent-gate layer, NOT protocol-enforced (non-conformant SDK could ignore) — same class as tool-bearing hard rule.
- Wire-observable solicitation: Welcome rides B's publicly-computable invitations routing id before gate. Inherent to untrusted relay.
- did:web canonicalization availability dual (undiagnosable pairing-denial). Disclosed §3.8.1.

All disclosed with honest bounds. Model fully closed; no sibling weak-signal inference path remains.
