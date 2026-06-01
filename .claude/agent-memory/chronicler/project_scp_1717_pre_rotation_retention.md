---
name: SCP-1717 pre-rotation key retention fix and pending spec drift
description: Fix retains pre-rotation key on ScpIdentity to satisfy spec §3.7; this contradicts §9.7.4.1 #3/#5f and §9.12 cold-storage threat model. ADR-003 struct text is stale. Spec amendment or custody-handoff redesign still owed.
type: project
---

Three commits at HEAD of `worktree-scp-1717-wasm-rotate-key` (2026-04-27):

- 19bd8ccba: retains `pre_rotation_key: KeyHandle` on `ScpIdentity`. Native bridges (PyO3, NAPI, UniFFI) had silently generated a fresh keypair at migrate time, breaking spec §3.7 `SHA-256(revealed_key) == commitment`. WASM was unaffected (already retained locally).
- 8a8bf4544: regen Swift bindings to expose `rotationEventJson` on Identity.
- 753d461b2: `WasmIdentity::fromDid` registers a `Resolved` registry record so subsequent migrate surfaces IDENT_1028 instead of IDENT_1002. New `native_emitted_rotation_event_json_matches_wasm_encoding` reverse-parity test.

**Why:** Native bridges destroyed pre-rotation key at create per literal §9.7.4.1 #5f ("destroy from memory after backup is confirmed") but had no backup callback for in-memory custody. The fix retains the key in operational custody.

**Spec drift owed:** §9.7.4.1 #3 (storage isolation) and §9.12 line 1067 ("from cold storage") now contradict the implementation. Either spec needs in-memory exemption, or custody-handoff callback needs to be added. Per CLAUDE.md artifact-flow invariant, code does not inform specs — the spec must be amended downstream.

**ADR-003 stale text:** `.docs/adrs/phase-1.md` lines 364-388 still shows 4-field `ScpIdentity` struct without `pre_rotation_key`. ADR-003 §4 line 295 still says "stored in cold/offline custody" for the Pre-Rotation Key bullet.

**How to apply:** When SCP-1717 lands, follow up by either (a) amending §9.7.4.1 / §9.12 to acknowledge in-memory exemption and the threat-model regression, or (b) reworking to a callback-based custody handoff. Update ADR-003 phase-1.md regardless to reflect the new struct shape.

**Lessons captured this PR:**
- `.docs/lessons/behavioral-invariant-must-be-asserted-on-every-bridge.md` (new) — matrix-name parity is not byte parity.
- `.docs/lessons/hash-commitment-preimage-lifetime.md` (new) — generalizes pre-rotation-key-must-be-stored-at-creation across all hash-then-reveal schemes in SCP.

**CLAUDE.md addition pending:** Integration checklist item 6: every bridge emitting a wire artifact with a spec-defined cryptographic invariant must have a behavioral assertion recomputing the invariant from emitted bytes.
