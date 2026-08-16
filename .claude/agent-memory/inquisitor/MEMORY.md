# Inquisitor Memory

Persistent notes for the inquisitor review agent. Each entry: the decision interrogated, the
premise it rested on, whether that premise held, and the root-cause decision when rot was
found — so future passes can spot expired premises and compounding drift faster.

## Interrogations
- [SCP-OUT-046 streaming-saga seal FSM](scp-out-046-streaming-saga-seal-fsm.md) — SOUND; custody split is architecture-forced (ADR-049 no-autonomous-key), consistent w/ unary keyless recovery. Do not re-litigate.
- [Track-F fail-opens branch](trackf-fail-opens-branch.md) — 5 capability-selection fixes, ZERO artifact edits; SCP-CAPINJECT-010 already governed the relay work; issue #342 AC2 is Alec's; napi returns Debug-formatted governance results.
- [ADR-057 reciprocal-announce mesh](adr057-reciprocal-announce-mesh.md) — SOUND online-quiescent only; epoch/sender-key race + offline residual leave permanent gaps w/ NO recovery; offline drift vs T4 (T4 names+pulls, mesh doesn't); test harness can't exercise the race (pump panics on error).

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
