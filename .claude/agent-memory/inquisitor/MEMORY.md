# Inquisitor Memory

Persistent notes for the inquisitor review agent. Each entry: the decision interrogated, the
premise it rested on, whether that premise held, and the root-cause decision when rot was
found — so future passes can spot expired premises and compounding drift faster.

## Interrogations
- [SCP-OUT-046 streaming-saga seal FSM](scp-out-046-streaming-saga-seal-fsm.md) — SOUND; custody split is architecture-forced (ADR-049 no-autonomous-key), consistent w/ unary keyless recovery. Do not re-litigate.
- [PR #2235 AppBound/AppUnbound durable](pr2235-app-bound-unbound-durable.md) — BLOCKER: "durable binding" premise smuggled — bound_apps gate is in-memory, never rehydrated from the log (state-replay no-op arm) ⇒ is_bound gives wrong answers post-restart. Ceiling read from FFI mirror w/o JIT resync (durable over-grant risk). Branch base stale (local main=55).
- [ADR-057 reciprocal-announce mesh](adr057-reciprocal-announce-mesh.md) — SOUND online-quiescent only; epoch/sender-key race + offline residual leave permanent gaps w/ NO recovery; offline drift vs T4 (T4 names+pulls, mesh doesn't); test harness can't exercise the race (pump panics on error).
- [SCP-OUT-031 PR-1 invalid-grant class](out031-pr1-invalid-grant-class.md) — P1 UNSOUND/REVERSE: `protocol.invalid-grant` cargo-culted from shipped Python; §5.4.4 "range violations" + `estimate-exceeds-bound`→Input(6120) precedent put it in Input, not Protocol. Never crosses wire (client-side Credit guard). Cheap to flip now. P2 prose OK (spec-documents-code inversion @05-contexts.md:299 is root of divergence risk). P3 AC17→042b severance SOUND.
- [PR #2234 broadcast KEA fail-closed](pr2234-broadcast-kea-fail-closed.md) — BLOCKERs: ADR-011 convergence is defined over the MLS-commit-ordered stream but broadcast has NO MLS ⇒ doctrine cited outside its domain; native runtime has ZERO author-grant wiring (WASM has it) ⇒ multi-author unreachable in native prod; §5.14.8 clause back-filled after #2218 code that cited *line numbers* as spec sections.
- [reply-await-sweep 2-min backstop](reply-await-sweep-2min-backstop.md) — SOUND + 1 QUESTION. Uniform 2-min REPLY_TIMEOUT on ~57 supervisor reply-oneshots holds: handlers 30s-bounded (HANDLER_TIMEOUT), custody-sign outside actor, xctx 30s phase timers ⇒ 2min pure backstop. #130's 3 sites converged = exact behavior preserved. Deferred saga.rs = actor-internal, correctly NOT swept. 15/16 folds fail-closed; QUESTION RESOLVED @1728385f6: `const fn hard_rate_limit_allow` now maps Elapsed(wedged-alive)→deny, Dropped/handler-Err(no live bucket)→pass. Principled (pass only when no live per-ctx bucket); Dropped residual inert (reserve path fails closed on gone actor); only permissive-bool fold in file; const fn + regression test = right shape.
- [SCP-RELAYRES-004 relay WRITE path](scp-relayres-004-relay-write-path.md) — @5b89baada the latch/read-back REVERSAL is SOUND (arm always on + fail-closed + real self-heal test; signed record now a publish OUTPUT; 3 live watch slots; §3.10.6 cb wired; no nullifier). 2 BLOCKERs remain: self_host.rs:1404-07 "loopback relay is a protocol-unaware blob pipe (§10.4)" is FALSE (DidRecordValidation::Enabled is #[default], node overrides only bind_addr/bridge_secret; node advertises that relay as its own SCPRelay endpoint; §10.4 is about encrypted context blobs) and it is the rationale 006 must overturn; PRD last edited BEFORE the latch deletion ⇒ 8 sites (004/006/007, 5 ACs) still prescribe deleted `bound_relay_count()`, incl. 006 AC[6] re-imposing "manager never observes a zero-relay publisher".
- [ADR-063 provenance-bearing projection](adr063-provenance-bearing-projection.md) — design SOUND (V2 ciphertext-bind, attestation-in-AEAD, delete `open_broadcast_trusted`); 5 BLOCKERs at the seams. Worst: #2294/#2295 predate the ADR's own Decision-3 reversal by ~25min and ask Alec to ratify the *reversed* key-publication design while omitting the one item that needs a signature.
- [Plan Tracks H+I (nullifier-seal plan)](plan-nullifier-seal-tracks-h-i.md) — forgery + Track I facts CONFIRMED; but D7/D8 already exist, D9 cuts its own branch's text, D4 blocked by §9.5.1+§13.2.2's spent V2, D15↔D20 unresolved & contra ADR-003 §4a, D20's provenance collapses, "lost ruling" is in open Discussion #2139.
- CRYPTO-22 S4 Layer B attestation seam (crypto22-s4-code @ e51741b6) — Q2 RESOLVED by construction. Prior finding: `verify_add_or_update_attestation` prose-gated Update (fail-closed no grace) inviting future wirer to reintroduce BLACK-C22-10 censorship. Fix: renamed `verify_add_attestation` taking new `AttestationAddGroundTruth` (NO trigger field, carries kp_init_key), builds `AttestationTrigger::Add` internally ⇒ Update unrepresentable at async resolver seam. Old name 0 grep hits; only resolver seam; Layer A `verify_attestation_with_resolution` unchanged + correctly trigger-general (no resolution → no grace). Seam still 0 non-test callers (unwired; Update-with-grace honestly absent, deferred S7). SOUND. Do not re-litigate.

- [ADR-003 §4a retired-key retention bound](adr003-retired-key-retention-bound.md) — UNSOUND/REVERSE. Never a human decision (PR #274, zero human comments); back-filled to fix a FALSE "mirrors" claim a bot flagged. Arithmetically incapable (doc already ~1,140B vs 1,000B BEP44 w/ 0 retired keys). Spec §18.2.2A forbids the VMs entirely ("No other verification methods permitted"); §9.7.1 makes `#retired-*` a REJECT. Bifurcation hypothesis REFUTED — §3.10.5 byte-identity + `publish_document` sends raw `to_json()` to DHT.
- [Nullifier-seal + crate-split plan audit](nullifier-seal-crate-split-plan-audit.md) — code citations near-perfect; every error is in *external* state: stale remotes (already force-pushed), conflicting OPEN PR #2283, ~12 uncited prior-art issues, and a false "no rule makes `Proposed` blocking".

## Operating reminders
- The code is evidence, not the defendant. Cite code to prove a claim about a *decision*;
  keep the verdict about the decision's soundness.
- Sunk cost is never an argument. "Already built," "big change," "would redo the bindings" —
  strike them and re-derive the decision as if nothing existed yet. You are the project's
  chartered defense against sunk-cost reasoning.
- Status quo is a claim to be explained, not a default to be accepted. When code matches an
  existing pattern, trace the pattern's origin and confirm it was a decision, not an accident
  (deprecated workaround, serializer default, first-thing-that-compiled).
- Take nothing on faith — not the doc-comment, not the ADR's assertion, not a prior verdict,
  not your own prior memory. Re-derive from the *current* code.
- Premises expire. A decision sound for a smaller / single-transport / pre-MLS codebase may
  be unsound now. Verify the assumption against today's code.
- Look across slices and in singles. Rot is usually invisible in a single diff and only
  legible across the set of decisions. Name the originating decision, not the latest symptom.
- Respect the one-way flow when prescribing: you may challenge a spec/ADR (your unique
  license), but the fix flows down — correct the artifact first, then the code.
- Reserve UNSOUND for false/expired/never-existed premises or decisions that contradict
  another decision. "I'd have chosen differently" is taste, not a finding.
