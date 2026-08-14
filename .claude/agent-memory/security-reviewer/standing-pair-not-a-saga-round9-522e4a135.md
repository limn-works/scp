# Standing-Pair "Not a Saga" §5.15.8 — Round-9 (522e4a135, spec/standing-pair-not-a-saga-v2) — 2026-06-24 — ZERO FINDINGS / SOUND

Successor to round-8 (a0e02ab3b). HEAD=522e4a135, merge-base=f37372b25. Commit msg names the
deltas: reaper observe-contradiction fix + anti-spam gate-decidability + new §3.8.1 canonical
DID form + §5.15.8 de-dup + sketch/sdk-common sync + §9.3 phantom-cite fix. DOCS-ONLY (7 files).
ALL clean/STRONGER, no load-bearing guarantee dropped.

## 6 round-9 deltas — all sound:
1. NEW §3.8.1 canonical DID string form (03-identity L752-760). did:dht=lowercase z-base-32
   (single form, §9.6.1); did:web=W3C method canon (host lowercased + IDN->punycode/A-label +
   default :443 omitted + no trailing dot + path %-enc UPPERCASE hex + literal `:`->`%3A`).
   TECHNICALLY CORRECT vs RFC 3986 §6.2.2.1 + RFC 5890 IDNA + did:web method. Adds FAIL-LOUD
   method-admission gate for any method w/ no canonical form ("never silently coerced"). Sound
   fail-closed posture; gives §5.15.8/§5.14.13 the single comparison form their derivations need.
2. INJECTIVITY RETRACTION (05 L1825). Round-8 claimed length-prefix "would add no security"
   — round-9 RETRACTS it (colon-join was ALWAYS sole structural isolation anchor; the saga-cut
   `group_id` was the saga's SEPARATE MLS id, not an isolation co-anchor). Now: length-prefix
   (§9.5.1 len32 — VERIFIED L347 exists) is RECOMMENDED unconditional hardening that RETIRES the
   human admission gate; deferred only as coordinated spec+code change. HONEST, STRICTLY BETTER
   framing — corrects a prior false claim. No security weakened (encoding byte-identical).
3. NEW "MLS-layer defense-in-depth" para (05 L1827). Even on hypothetical id collision, OpenMLS
   GroupId + key schedule + per-member credentials are INDEPENDENT barriers — "a collision alone
   grants no plaintext." Accurate for OpenMLS. Correctly frames colon-join as DiD, not sole line.
4. ANTI-SPAM gate-decidable carve-out (05 L1867). Per-initiator cooldown default 60s/floor 1s;
   EXEMPT = Welcome under derived_context_id where THIS NODE already holds its own self-created
   group (convergence candidate). SOUND: attacker cannot manufacture the exemption precondition
   on victim's side (derived_context_id is pure fn of (atk,victim) pair; victim only self-creates
   if victim initiated). Even when exempt, forged variant "consumes no init key, destroys nothing"
   (settled downstream by confirm-bound-creator + init-key single-use). Decidable on LOCAL state
   only — no post-gate creator-binding needed. Convergence never gated on cooldown. No bypass.
5. REAPER observe-contradiction fix (05 L1865). Keeps round-8 A-local/observation-free
   `now > max(per-relay emit ts) + welcome_ttl`; ADDS Collision-guard: `did_lo` MUST NOT key
   reap-suppression on OBSERVING `did_hi`'s competing Welcome (consistent w/ "builds no state
   from did_hi's group"). Resolves a latent self-contradiction; strictly clarifying. §5.12.3.3
   L863 7-day welcome_ttl VERIFIED.
6. §9.3 PHANTOM-CITE fix. §5.15.8 + §5.12.2 L754 now say "in the SPIRIT of §9.3's not-self-created
   discriminator" / "mirroring §9.3's (not self-created) qualifier" — no longer claim §9.3 DEFINES
   the stranger predicate. §9.3 L227 VERIFIED: "participation records from distinct contexts (not
   self-created)". Predicate HOME is §5.12.2 (L754 carries the first-contact not-self-created-by-
   either-party qualifier). Cite now ACCURATE — no phantom provenance.

## Re-verified UNCHANGED-and-sound from round-8:
- Collision atomic bundle {block-list consent gate FIRST -> confirm-bound-creator(§9.7.1 BOTH
  ScpCredential.did==did_lo AND sig key in did_lo DID-doc VM) -> fresh-join(init-key single-use)
  -> destroy} under per-context actor mutex + generation check. Forecloses forged-creator DoS +
  replayed-Welcome stale-destroy + confused-deputy recreate. did_hi destroy-rejoin IS a Welcome-
  join => inherits send-gating.
- Self-heal scope HONEST: §3.7.1 L534-540 severance = sender-key ROTATE (a SEND, §9.16.3) =>
  send-gated did_hi CANNOT sever until Phase-2E. Spec states the durable did_lo->did_hi decrypt-
  capable channel exists NOW, bound exact (1 pair, receive-not-sever, no key exposure). Honest.
- Existence-oracle (value+timing): resolve membership FIRST, branch only on membership, constant-
  time wrt existence; §5.12.5 ~0ms/~200ms latency hint scoped to member-own-pair success path.
- KeyPackage residual: did_hi self-only re-drive consumes 1 of did_lo's KPs (upstream of consent
  gate, at MLS layer); bounded by did_hi re-drive rate + general MLS pool / §9.3; no new vector.
- "two sagas" cleanup COMPLETE: no residual three-saga ref in touched files. SCP-SAGA- band
  13000-13999 IS registered (sdk-common L45, check-error-codes.sh L19/71-73) — ADR-049 §3a's
  "IS registered" claim is ACCURATE (no phantom). 13200-13999 row retitled to "Future cross-
  context saga families."

## Anchors re-verified live at 522e4a135:
§3.8.1 L752-760 (NEW). §3.7.1 L534-540 propagate+sever / L545 is_globally_blocked. §5.12.2 L754
not-self-created qualifier (predicate home). §5.12.3.3 L863 7-day TTL. §5.12.5 L953 latency hint.
§9.3 L227 not-self-created. §9.5.1 L347 len32. §9.7.1 DID-VM/sig binding.

## Notes
- Working tree is DIFFERENT branch — use worktree path /Users/alec/Developer/limn/scp/.claude/
  worktrees/agent-a22990a7afe431575 or git show.
- Prompt focus (consent gate / existence-oracle / KP-drain / unsolicited-join / phantom-cite /
  §3.8.1 sec implication / regression) ALL independently checked — no actionable finding.
