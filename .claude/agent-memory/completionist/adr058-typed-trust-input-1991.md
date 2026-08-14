---
name: adr058-typed-trust-input-1991
description: ADR-058 typed SDK trust-input ops A/B across 4 SDKs (resolves #1991) — INCOMPLETE(narrow), sole finding = Kotlin phase-file provenance mis-cite
metadata:
  type: project
---

# ADR-058 typed SDK trust-input ops A/B (#1991) — INCOMPLETE(narrow) @e6aa96a9a

Branch feat/... worktree fu-1991, base origin/main. Diff = ADR-058 (standalone + phase-4.md pointer) + typed trust-input Ops A (`verify_participation_requirements`) & B (`check_capability_requirements`) across all 4 SDKs. **Zero crates/ change** (confirmed; ADR-058 keeps FFI bridges JSON per ADR-048 §1/§7 — input-side analog of ADR-057).

**Why:** #1991 (inquisitor-surfaced) — TS/Swift/Kotlin took raw `requirementsJson`/`profileJson` strings (no compiler help); Python already typed for participation. ADR-058 decision: SDK surfaces take typed objects, serialize internally over unchanged JSON bridge.

**How to apply / what's COMPLETE:**
- Full field fidelity vs Rust structs verified: `ChallengeVerification` 16 fields (challenge.rs:305, incl unsigned result/completed_at/verification_method), `ParticipationProfile` 13 (participation.rs:696), `RequireParticipation` 4, `CapabilityRequirement` 2. Wire-shape subtleties all correct: `ChallengeType` serializes as bare URI string (custom Serialize, NOT `{"Uri":...}` — challenge.rs:143), so SDKs store challenge_type as plain str = correct; `VerificationMethod` externally-tagged `{"ChallengeVerified":{"challenge_type":<uri>}}`; `ParticipationThreshold` `{"AtLeast":n}`; `ParticipationFact`/`VerificationLevel` bare PascalCase; Ed25519Signature=Vec<u8>→number array; [u8;32/64]→number arrays.
- Python: only check_capability_requirements newly typed (verify_participation already typed on main). Full range/byte-len validation in __post_init__.
- TS: encoders in types.ts (snake_case + tagged), scp.ts both wrappers typed, exhaustive-never guard.
- Swift: typed free-function OVERLOADS (requirements:/profiles: labels) calling generated JSON free funcs; UInt32/UInt64 give compile-time range safety; explicit-null encoder.
- Kotlin: kotlinx.serialization, in-place signature change (not overload); custom serializers for threshold+method; UInt/ULong/UByte.
- Tests exact-JSON at every SDK: Python mock-bridge json.loads==[...]; TS JSON.parse().toEqual + REAL-napi call-through (met/rejected/wrong-len-sig rejected at bridge); Swift JSONSerialization field-by-field + byte-len 32/32/64; Kotlin parseToJsonElement structural + REAL-FFI TrustAdmissionFfiTest (probeNativeLibrary loads native lib, crosses FFI). Swift has no call-through (can't link w/o XCFramework — consistent w/ Swift SDK constraint).
- Matrix UNCHANGED and still accurate (records op names + 4 SDK bools + prose wrapper NAMES which are unchanged; bridge stays JSON so no stale signature recorded). validate-prd 370 stories exit 0; check-sdk-coverage 0 errors PASS.
- Ops C (`aggregate_trust_input`, still eventsJson etc.) + D (`trustVerify*`) correctly DEFERRED to #2010 (verified OPEN, titled exactly for C+D) — legit tracked deferral, NOT flagged.
- No orphaned old PUBLIC API: all surviving requirementsJson refs are bridge-param names in wrapper→bridge calls, internal json.dumps locals, or _scp_core.pyi bridge stub (stays JSON). No test calls old public signature.

**SOLE FINDING (artifact divergence → INCOMPLETE narrow):** `bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/TrustAdmission.kt:15` header cites `Provenance: ADR-058 (.docs/adrs/phase-2.md)` but ADR-058's phase pointer lives in **phase-4.md:1799** (standalone file relates to trust spec §7.3, phase 4). Phantom provenance — author pattern-matched ADR-057→phase-2. One-token fix: phase-2.md → phase-4.md. Only Kotlin pairs ADR-058 with a phase path (Swift/TS/Python cite ADR-058 without a file).

**Non-blocking observations:** (1) byte-array length (64/32) runtime-validated ONLY in Python; TS/Swift/Kotlin don't check at construction though ADR rationale lists byte-len checks as a misuse-resistance benefit (Swift/Kotlin get u32/u64 range safety free via UInt types; TS `number` gets neither). Wire still correct; bridge rejects wrong length as before. (2) ADR-058 scope note states A/B-vs-rest boundary generically, doesn't name C/D or #2010 — boundary IS stated, not a hard finding.

LESSON: on "analog-of-ADR-X" slices, grep new files for `ADR-<new> ... phase-N.md` pairings — authors copy the SOURCE ADR's phase path; verify against where the new ADR's `## ADR-NNN` heading actually lives.
