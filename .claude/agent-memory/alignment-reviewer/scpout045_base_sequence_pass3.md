---
name: scpout045-base-sequence-pass3
description: SCP-OUT-045 base_sequence gap-key scar-tissue sweep pass-3 (commit 387d3781e) — story sweep clean but one CODE residual remains
metadata:
  type: project
---

# SCP-OUT-045 base_sequence gap-key sweep — PASS-3 (2026-07-16) — NEEDS DISCUSSION (one code residual)

Branch `feat/outlet-xctx-045-gap-detector`, HEAD `387d3781e` (doc-only sweep of outlet.json 044/049). Prior: 045 re-keyed the reassembly gap-detector from `base_sequence` → `chunk.sequence` (§5.4.5:513/515; base_sequence is §5.15.7 send-seq anchor, minted locally by SendSequenceTracker, +1-by-construction → tautological gap key). Pass-2 flagged residual scar tissue in siblings 044/049.

**Story sweep (outlet.json) = COMPLETE + CORRECT.** 044 reframed: base_sequence = per-sender MLS send-anchor consumed by SCP-OUT-047 A-context re-seal (matches merged code invoke.rs:4344/4373); 045 keys on chunk.sequence. 049 vector-5 fixed "drops a base_sequence"(impossible) → "drops a chunk (non-contiguous chunk.sequence)" — now buildable. ACs NOT weakened: grep-parts of AC4/AC5 unchanged, still machine-verifiable. Line 3048 (SCP-OUT-046, done) co-mention is neutral ("044 per-sender base_sequence anchor"), not a misframing. Forward-ref 044(done)→047(pending) is legitimate: descriptive provenance, NOT a blockedBy inversion (044.blockedBy=[036]); forward-only graph intact; matches code.

**ONE RESIDUAL (code, not story):** `crates/scp-runtime/src/context/outlets/invoke.rs:5568` — best-effort-bridge fn docstring still says frame "exposed as `(request_id, base_sequence)` to the SCP-OUT-045 gap-detector" — the EXACT misframing the whole effort kills, and it SELF-CONTRADICTS the same file at 4344-4381 + 4410-4421 (ForwardedStreamFrame doc + ReassemblyGapDetector doc both say "NOT the gap key; keys on chunk.sequence"). Pre-existing from 045 commit d7512ef21, outside doc-only sweep scope. `grep -rn base_sequence crates/ .docs/ | grep -i gap` → this is the ONLY remaining non-corrective co-mention repo-wide. FIX: reword 5565-5571 to mirror 4344 (carried for SCP-OUT-047 A-context re-seal, NOT the gap-detector). Same PR (it's literally the 045 bridge fn).

GOTCHA: don't reflexively distrust "047 = FFI-surface story, can't do re-seal" — the CODE (4344/4373) authoritatively attributes the SDK-delivery-seam A-context re-seal to SCP-OUT-047; sweep's story framing matches code. Not invented.
