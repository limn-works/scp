---
name: pr2141-r3delta-att0-honesty-08fccffdc
description: PR #2141 Round-3 delta @ 08fccffdc (12 commits past R2 76d95fba3) — honesty docs for att[0]-only withinCeiling, context_id fullmatch pre-flight, WASM tools.rs CTX_2023 routing; ALIGNED delta, 1 pre-existing SHOULD-FIX
metadata:
  type: project
---

# PR #2141 Round-3 delta @ 08fccffdc (fix/sdk-coverage-fail-closed-and-parity, /tmp/scp-review-r25, 2026-07-15) — ALIGNED

Delta = 12 commits past R2 ([[pr2141_r2delta_closed_allowlist_wasm_routing_76d95fba3]]). Mostly polish/docs. All verified against code.

**Delta commits ALIGNED:**
- WASM tools.rs CTX_2023 routing (647f28b4c): tool_invoke / tool_invoke_cross_context / tool_session_invoke now route `code==CTX_2023` → ScpWasmError::Context, else → Permission. REACHABLE: validate_tool_ucan_wasm (ucan.rs:629) returns CTX_2023 for WasmValidateError::Context (state-lookup faults). Prior comment "All branches return PERM_3001" was STALE — delta corrects it. Matches ucan_validate (ucan.rs:625-629) + NAPI parity. Context-state fault ≠ permission denial (correct classification — conflation would let trust.ts/.py absorb infra faults as all-false = the fail-open bug the PR fixes).
- Python context_id pre-flight (de0077f13/6b39f6ac9): `_CONTEXT_ID_RE=re.compile(r"[a-zA-Z0-9_-]{1,256}")` + `fullmatch` at line 888, BEFORE any bridge call using context_id (nothing consumes context_id before it — "at entry" docstring accurate). Mirrors Rust validate_context_id (validate.rs:208: non-empty, ≤256, alnum+hyphen+underscore, reject control chars) — regex functionally equivalent. Raises ValidationError code SCP-VALID-7001 (VALID_7001 = context-validation code, used in wasm/context.rs). fullmatch (not match) rejects trailing \n. Fail-closed: malformed context_id propagates as genuine caller error, NOT absorbed into all-false.
- TS PIPELINE_ABSORBED_CODE_PREFIX constant (bba5b5d23/b49a5b64a): extracted "[SCP-PERM-3001]", @internal, startsWith replaces regex, coupled to lockstep test. Layer 3-4 facade honesty docs (attestations/endorsements/challengeResults always []/null "reserved for future") in trust.py + trust.ts. Honest, no overclaim.
- Swift (prior fix, not in this delta): evaluateTrust(subjectDid:contextId:) has NO tokens param → TrustEvaluation(from:score) sets Layer-1 all-FALSE (Trust.swift:92-96,115-119) = fail-closed. Matches prompt's described fix. Scaffold swift.md only references file/symbol (no behavioral contradiction).

**SUBSTANTIVE FINDING — att[0]-only withinCeiling (SHOULD-FIX, PRE-EXISTING to this delta):**
Branch swapped main's whole-token `instance.ucan_evaluate(ctx,token,None,subject_did)` (structured diagnostic, validates ALL att in Rust core, subject_did audience binding) → att[0]-only `instance.ucan_validate(ctx,token,cap_uri)` where cap_uri=`_extract_first_capability_uri`=att[0]["with"] (trust.py:915,922). ucan_evaluate + structured_to_capability_validation CLEANLY REMOVED (grep=0 across crates/+bindings, no orphan). Swap PREDATES this delta (present at R2 base 76d95fba3; git log -S ucan_validate 76d95..HEAD = empty). This delta only ADDS honest docs (sketch.md:807-814, trust.py:158-190/906-914, trust.ts).
- Spec §7.2.1 step 8 = "capability within immutable ceiling" for the TOKEN (att is an array; full pipeline checks all). Facade checks only att[0].
- NOT an enforcement hole: real ceiling enforcement (all att) runs in Rust core at actual presentation boundaries (role assign / xctx invoke / broadcast admission). A multi-att token with out-of-ceiling att[1] is still REJECTED there.
- IS a fail-OPEN reporting gap: evaluate_trust().withinCeiling can report TRUE for a multi-att token whose att[1..] is out-of-ceiling — trust inflation in the diagnostic. Mitigated in practice: SCP role tokens are single-capability (mint_role_tokens = one cap/token).
- Honesty docs are the right move, BUT "requires a dedicated bridge op that does not yet exist. Until that op lands..." is an UNBOUNDED deferral with NO PRD story ID — tension with builder tenets (No deferral / Completeness is baseline / stub policy = every stub cites a story). SHOULD-FIX: file a PRD story for the multi-att single-nonce bridge op and reference it in sketch.md + trust.py/trust.ts annotations (or implement it). Pre-existing branch scope, not introduced by this delta, but Q4 explicitly targets it.

**OBS:**
- Swift has NO token-accepting evaluateTrust overload (Python/TS do) → Swift can't surface Layer-1 verdicts at all. Capability-parity gap, but fail-CLOSED-parity (PR's stated goal) holds (all-false when no tokens).
- R2 OBS-1 still stands: lockstep sync gate one-directional (completeness not minimality); a future fail-open via ADDING a code to the allowlist passes both gates.

VERDICT: ALIGNED (delta). One SHOULD-FIX (att[0]-only deferral needs story-ID provenance), pre-existing; observations non-blocking.
