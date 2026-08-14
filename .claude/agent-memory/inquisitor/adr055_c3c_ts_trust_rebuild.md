---
name: adr055-c3c-ts-trust-rebuild
description: Interrogation of branch c3c-ts (ADR-055 structured trust validation, TS+Py SDK rebuild) — 5 scrutinized decisions SOUND; Layer-2 behavioral record has 2 UNSOUND adjacent fields (phantom event type + hardcoded duration)
metadata:
  type: project
---

Interrogated branch `c3c-ts` (worktree agent-a1400c1b005b502a3), 2026-06-27. ADR-055
structured capability/trust validation across FFI; C3c SDK rebuild (TS + Python).

**Why:** Inquisitor pass requested on 5 named decisions. ADR-055 lives in phase-2.md by
subject; spec §7.2.4 + §7.3.2.1 are the normative prose. See [[adr055_structured_ffi_validation]]
for the prior pass on the same ADR family.

**How to apply:** When this branch (or its successor PR) returns for re-review, the 5 core
decisions are settled SOUND — do not re-litigate. The open items are the Layer-2 defects below.

### The 5 scrutinized decisions — all SOUND
1. Optional challenge cap / intrinsic-validity diagnostic — `validate.rs:836` gates ONLY
   check_capability_match; every other stage runs; `*`-sentinel (bridge REJECTS it as malformed
   URI per §5.3.1.1) correctly retired. `None` never flips a field true that Some leaves false.
2. Six closed booleans + `all_valid`/`allValid` accessor — closed-by-construction beats prose
   denylist; accessor prevents silent under-check when a stage is added. Reservation: record is
   SHORT-CIRCUITING (field true only if stage RAN) — documented in §7.2.4, not type-enforced.
3. Subject-as-presenting-agent — correct; prevents aud==aud tautological trust inflation. Sharp
   edge: bridge default-to-aud is a SILENT security default for raw-bridge callers (only a doc
   WARNING in crates/scp-ffi/src/ucan.rs guards it; SDK path always passes subject).
4. Single error chokepoint (TS mapBridgeError + wrapBridgeErrors Proxy) with already-typed
   pass-through — closes 2nd-location string-classification; pass-through is security-load-bearing
   (prevents typed-subclass→generic downgrade), test added.
5. Gate/diagnostic split — enforced by check_and_record (gate) vs check_replay (diagnostic),
   not convention. Rests on live ADR-009 NonceTracker contract.

### toolInvocations single bucket — HONEST interim (decision 4, the asked one)
Map<string,int> collapsed to one "ToolInvoked" key. Sum == flat count, so
`ToolInvocationCount = values().sum()` (spec §7.3.2.1) is correct. Per-tool keying genuinely
awaits ADR-051 (spec §189 confirms). Forward-compatible. NOT a lie.

### UNSOUND — adjacent Layer-2 fields the "interim" narrative masks (FIX BEFORE MERGE)
- **TS scp.ts evaluateTrust branches `eventType === "GovernanceActionAgainst"` — NO SUCH EVENT
  EXISTS.** Protocol emits only `GovernanceActionExecuted` (membership.rs:851). Spec §7.3.2.1
  distinguishes by-vs-against by FIELD comparison (subject_did==target vs actor_did==target), not
  event name. So governanceActionsAgainst = dead-code-always-0; governanceActionsBy counts ALL
  actors not just subject.
- **TS `participationDurationSeconds: 0` hardcoded** — spec defines it as latest_ts − MemberJoined_ts;
  data is in rawEvents. CLAUDE.md "never 0 when data exists" violation.
- **Python evaluate_trust** populates only contexts_participated=1 + tool_invocations; never wires
  governance_actions_against (stays 0), total_duration defaults. Two SDKs, two different incomplete
  behavioral records, neither matching spec's 7-fact model. Cross-SDK incoherence.

### Root cause
Spec §7.2.4/§7.3.2.1 SOUND as written — code diverges. Fix flows DOWN (code, not spec). Originating
defect: Layer-2 scan built per-SDK against an imagined taxonomy, no shared {event,field}→fact map.

### Sunk-cost note (the good part)
This branch is a CORRECTLY-executed sunk-cost reversal: deleted trust.py prose-parser
(_classify_ucan_error + 6 prefix-tuples + _PASSED_BEFORE) reconstructing a structured truth that
already existed at all 4 bridges. Killed the `*`-sentinel cargo-cult. Exactly the wrong-decision-
caught-before-compounding this charter blesses.
