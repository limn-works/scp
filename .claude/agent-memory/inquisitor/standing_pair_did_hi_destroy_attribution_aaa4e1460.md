---
name: standing-pair-did-hi-destroy-attribution-aaa4e1460
description: Final-pass interrogation (SOUND) of the one-line did_lo-ignores actor-attribution fix in §5.15.8; the destroy is did_hi's, not did_lo's
metadata:
  type: project
---

Branch `spec/standing-pair-not-a-saga-v2` @ HEAD `aaa4e1460` (docs-only, 1 line in §5.15.8). Interrogated 2026-06-24; verdict **SOUND**, artifact DONE for this pass. Builds on [[standing-pair-not-a-saga]] and [[standing_pair_spec_c81fcce95_final]].

**The edit (line 1848, `did_lo`-ignores bullet):**
- Pre-edit: "...builds no state from `did_hi`'s group (so **its** later destroy equivocates against no peer...)" — "its" antecedent = the survivor `did_lo`, which destroys NOTHING. Genuinely wrong.
- Post-edit: "...builds no state from `did_hi`'s group, **so `did_hi`'s later destroy of that orphan equivocates against no peer** (`did_lo` having never observed it)." Correct actor.

**Why SOUND (the destroy-actor invariant, verified across the section):** the ONLY destroy on the convergence path is `did_hi` destroying its OWN self-created orphan after joining `did_lo`'s group. Corroborated at lines 1846 ("exactly one group survives: `did_lo`'s"), 1849 (sibling bullet: "`did_hi` joins `did_lo`'s and then destroys its self-created group"), 1851 ("a group reached via the peer's Welcome is never destroyed by this rule"), 1855, 1887. The pre-edit pronoun misattributed `did_hi`'s destroy to the survivor `did_lo`. Fix removes an internal contradiction; introduces no new premise.

**Reusable test applied — pronoun/actor attribution in dense normative prose:** when a bullet's grammatical subject (here `did_lo`) is the party that does NOT perform the action ("destroy"), the possessive ("its destroy") is a latent contradiction even if the surrounding paragraph is correct. Cross-check every action verb against the role invariant stated elsewhere in the same section, not against the local sentence subject.

**Three headline premises re-verified intact (untouched by this edit):**
- Standing-pair = single-context async creation (line 1823: one MLS group / two members / MLS+event-log replica sync / no cross-context atomicity).
- Auto-accept allowlist-only (line 1862 step-4(b): auto-join ONLY if initiator DID on operator `known_did` allowlist; stranger default-deny non-overridable; else human prompt).
- Floor-vs-trust consistent (allowlist = eligibility floor, not trust grant; per §5.12.2/§9.3).

**Coherence:** the edit REMOVES an island of contradiction rather than creating one. No sunk-cost exposure (reverses an error, doesn't extend one). Root cause = prose pronoun ambiguity, fixed at prose level — correct level; standing-pair path still unwired so no code/downstream artifact implicated.
