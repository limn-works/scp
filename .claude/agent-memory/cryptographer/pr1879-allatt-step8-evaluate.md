---
name: pr1879-allatt-step8-evaluate
description: PR #1879 UCAN step-8 all-attestations + structured evaluate_ucan + mint-time role ceiling — SOUND no blocking
metadata:
  type: project
---

# PR #1879 @63dc89094 (feat/ucan-all-att-and-structured-eval) — SOUND, APPROVE, no blocking findings

5 review axes, all sound. Diff = validate.rs + capability.rs + roles.rs + 2 test files. ZERO new crate deps (Cargo.lock/toml clean).

**Why:** closes two gaps — step 8 only checked invoked cap (smuggled out-of-ceiling att escaped); and roles `new_unchecked` could reach mint with out-of-ceiling caps.

**How to apply:** baseline for future UCAN validate/evaluate drift checks; the parse_granted_caps/verify_root_issuer/verify_audience shared helpers are the anti-drift mechanism — gate and diagnostic MUST keep calling them.

- **Axis 1 step 8 all-att:** validate.rs:608 `verify_ceiling_compliance(&granted_caps, ctx.ceiling)` over FULL parsed att set (was `from_ref(required_capability)`). Runs BEFORE step 9 nonce `check_and_record` (~613) → no nonce burn on ceiling failure. Steps 6/6b/7 unchanged. Cannot reject legitimate token by induction: mint enforces same verify_ceiling_compliance over all caps before signing (scp-runtime mint.rs:96) → root att⊆ceiling; step 7 attenuation preserves att⊆parent down chain ⇒ full att set ⊆ ceiling.
- **Axis 2 evaluate_ucan faithfulness:** calls EXACT same sub-checks (verify_signature/verify_delegation_chain/verify_root_issuer/verify_audience/validate_key_scope/check_capability_match/enforce_ucan_category_a/verify_attenuation/verify_ceiling_compliance/is_revoked/verify_expiry). Takes `&ValidationContext` (shared ref) → cannot mutate nonce. 6-field struct = pure data (#[allow(struct_excessive_bools)] justified). Short-circuit: field true only if its stage ran+passed; later fields false after first failure. within_ceiling reflects step6 grant-match (inside signatures stage) AND step8 all-att ceiling.
- **Axis 3 nonce isolation:** `check_replay` is &self read-only (nonce.rs:200, only seen.contains_key, no insert). Test `evaluate_ucan_does_not_consume_nonce_but_validate_does`: evaluate twice→nonce_valid true both; validate twice→NonceReused on 2nd. Plus `validate_ucan_ceiling_violation_does_not_consume_nonce` proves step8 short-circuits before step9.
- **Axis 4 roles mint-time:** assign_role:3a + system_assign_role:2a call validate_role_definition(&role_def,&state.ceiling) BEFORE mint_role_tokens and BEFORE any state.assignments/member_capabilities insert → `?` early-return leaves state untouched. validate_role_definition iterates FULL role.capabilities, fail-closed first out-of-ceiling. Tests inject new_unchecked smuggled role + assert reject + no state mutation. Closes new_unchecked mint gap.
- **Axis 5 drift:** gate & diagnostic both call identical shared helpers w/ identical `granted_caps` for step 8. Only differences: throw-vs-struct, check_and_record-vs-check_replay. capability.rs multi-colon test confirms is_within_ceiling/capability_name agree (messages:write:extra fails-closed against messages:write ceiling).

LOW (non-blocking): mint_role_tokens still emits unsigned role tokens (documented complete design decision per §7.2.2 Tier-2, authority grounded in signed governance action, never crosses trust boundary / never enters Tier-1 JWT pipeline) — unchanged by this PR, not a regression.
