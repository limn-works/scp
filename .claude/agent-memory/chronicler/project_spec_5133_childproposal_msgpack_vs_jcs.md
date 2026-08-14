---
name: spec-5133-childproposal-msgpack-vs-jcs
description: Flagged spec-internal follow-up — §5.13.3 ChildCreationProposal match_hash still mandates canonical_msgpack while the protocol-wide policy + the same section's extension hashes mandate JCS
metadata:
  type: project
---

`.docs/specs/05-contexts.md` §5.13.3 has an internal canonicalization inconsistency, flagged for a human (NOT edited).

**The fact:** the `ChildCreationProposal` matching hash (line ~1180) and the derived `coordination_routing_id` (line ~1189) still mandate `canonical_msgpack(child_params)` for cross-SDK deterministic hashing. Line ~1184 even claims msgpack "ensure[s] deterministic hashing across independent serialization by different SDKs."

**Why it's suspect:** the SAME section's extension-serialization block (line ~1249) and the protocol-wide canonical-hashing policy in §09-security-model.md §9.5.2 (line ~490) both say the opposite — "MessagePack has no canonical form standard and field ordering varies by library; JSON... has RFC 8785 (JCS) as a formal canonicalization standard" — and §9.5.2 explicitly lists "governance config hashing for multi-parent contexts (§5.13)" as JCS. All three §5.13.3 extension hashes (governance_policy_hash / ceiling_hash / parent_governance_hash) are JCS. The match_hash is the lone remaining msgpack cross-SDK hash in that section.

**Why I did NOT fix it (per launch instructions "do not guess"):** (1) the code implements NONE of this — `grep` for `canonical_msgpack`, `match_hash`, `ChildCreationProposal` in `crates/` = zero hits; multi-parent coordinated creation (§5.13.3 case B) is not yet wired, so there is no code to "unambiguously prove" direction. (2) Changing msgpack→JCS is a wire-protocol decision (matching algorithm + routing-address derivation, touching lines ~1180/1184/1189), not a clean one-line fix — a genuine judgment call for a human.

**How to apply:** when the coordinated-creation path is implemented, or on the next §5.13.3 doc-hygiene pass, resolve this by moving the match_hash to `canonical_json_jcs(child_params)` to match §9.5.2 policy — but only under human sign-off since it defines the coordinated-creation wire matching. This is a latent cross-impl-canonicalization concern (Defect-B class), not a live bug.

Related: FFI-02 closure work (commit 408cf3787 on branch feat/adr049-2j-ffi-slice) added the §5.13.3 "Implementation status" note and closed FFI-02 in ADR-049; that work corrected §5.14→§5.13.3 but deliberately left this msgpack/JCS item for a human.
