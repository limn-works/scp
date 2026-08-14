# Spec review: §5.15.8 standing-pair drop redundant group_id (branch spec/standing-group-id-redundant)

## Verified CODE CLAIM (the central one)
The spec claims the MLS provider's `create_mls_group` `Entry::Vacant` guard keys on
`SHA-256("standing-" ‖ hex(derived_context_id))`. This is CORRECT. Chain:
- `provider.rs:735 create_mls_group(&self, context_id: &[u8;32])` — `Entry::Vacant`
  keys on the `[u8;32]` arg directly (no internal hashing). Key = whatever caller passes.
- `supervisor.rs:5160 standing_context()` → `generate_standing_context_id` =
  `"standing-" + hex(SHA-256("standing:"||did_lo||":"||did_hi))` (standing_helpers.rs:46).
  derived_context_id = the raw 32-byte SHA-256 digest before prefix+hex.
- `standing_context` calls `lifecycle_helpers::create_context(context_id_string, ...)`.
- `builder.rs:658 id_bytes = context_id_bytes(&context_id)`; `context_id_bytes` (mod.rs:74)
  = raw `SHA-256(utf8)`. So id_bytes = SHA-256("standing-"+hex(derived_context_id)).
- `builder.rs:667 crypto.create_mls_group(&id_bytes)` — matches spec exactly.
So the removed "as-built code allocates the group id randomly" claim was correctly excised;
MLS group id IS deterministically derived (via the display-id hash), no random allocation.

## Code/spec divergence (follow-on, NOT a defect in this spec-only diff)
`saga_prepared_state.rs:100 StandingPairCreatePrepared` STILL has `pub group_id: Vec<u8>`
and doc comments referencing "the newly-generated MLS group ID". Spec PR drops group_id
from saga evidence. Artifact flow is spec→code so code update is expected to follow.
Also: that struct's doc cites §5.15.7 but the section is §5.15.8 (pre-existing, out of scope).

## Cross-refs all resolve
§9.6.1 (line 519), §9.5.1 (338), §9.3 (162), §5.12.1, §5.15.4 (1589), ADR-049 §5
(ADR-049-actor-per-context.md:94 OwnedIdentityDid). §9.18.2 table well-formed after
"scp-standing-group-v1:" row removal; preamble enumeration matches surviving rows.

## NOTE: git grep against repo root hits MAIN (pre-change). The branch lives in worktree
/Users/alec/Developer/limn/scp/.claude/worktrees/spec-groupid — grep THAT path for branch text.
