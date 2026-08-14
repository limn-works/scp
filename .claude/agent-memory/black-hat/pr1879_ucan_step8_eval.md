---
name: pr1879-ucan-step8-eval
description: PR #1879 feat/ucan-all-att-and-structured-eval black-hat review (63dc89094) — step8 all-att ceiling, evaluate_ucan, mint-time gate
metadata:
  type: project
---

# PR #1879 (63dc89094) black-hat review — UCAN step-8 all-att ceiling + evaluate_ucan

Reviewed `feat/ucan-all-att-and-structured-eval`. Three changes: (1) validate_ucan step8 now
`verify_ceiling_compliance(&granted_caps, ...)` over WHOLE att set not just invoked cap; (2) new
side-effect-free `evaluate_ucan` → `CapabilityValidation` (6 bools); (3) mint-time
`validate_role_definition` in assign_role + system_assign_role.

## Verdict: SOUND. No CRITICAL/HIGH against the PR's own changes. One MEDIUM pre-existing-amplified.

## VERIFIED CLEAN (probed empirically, tokens minted + run):
- evaluate_ucan is genuinely nonce read-only: evaluate×3 keeps nonce valid; only validate records (check_replay vs check_and_record). No nonce-burn DoS via evaluate.
- evaluate vs validate ceiling axis: IDENTICAL call `verify_ceiling_compliance(&granted_caps, ctx.ceiling)` — cannot disagree on within_ceiling. Only documented disagreement = time-race (nonce/revocation flip between calls), honestly documented.
- Step 8 (line 607) is BEFORE step 9 nonce record (line 610). Ceiling violation short-circuits, never burns nonce. Confirmed.
- Mint-time gate bypass (#4): construction path ContextRoleState::new ceiling-validates custom_roles inline (l.863-873); admin minted at l.896 is either validated-custom-admin or builtin_admin(derived-from-ceiling). 3 mint_role_tokens callers (896 construct, 1072 assign, 1141 system) — last two now gated. No gap.
- Cross-context att smuggle: att `scp:ctx:OTHER/messages:write` passes step8 (is_within_ceiling strips context_id) BUT ceiling is resource:action-only per spec §7.2.1 (context-agnostic is spec-faithful), and Tier-1 token att is NOT propagated to any cache (broadcast/invoke add member as plain subscriber, only required_cap authorizes). No escalation.
- pipeline_wiring ratchet 42→43: only-increases, adds positive+negative assertion. Non-vacuous: PROVEN by reverting step8 to from_ref → both pipeline_wiring `ucan_step8_enforces_ceiling_over_all_att` AND integration `validate_ucan_step8_rejects_smuggled_out_of_ceiling_attestation` FAIL. Restored after.

## MEDIUM (pre-existing in is_within_ceiling/ucan_resource_action, AMPLIFIED by step-8-over-all-att):
No-colon Custom ceiling entry → silent wildcard. `Capability::Custom("payments")` (single token, no colon, reachable from EVERY SDK via create_context ceiling param → Capability::new("payments")) → `to_ucan_string_set()` = `"payments:*"`. Consumer is_within_ceiling treats `payments:*` as WILDCARD → atts `payments:approve`/`payments:withdraw`/`payments:ANYTHING` all pass step 8. E2E PROVEN: ceiling {Custom("payments")} → mint(payments:withdraw)=ok → validate_ucan(payments:withdraw)=Ok(()). The declared ceiling intended ONE cap "payments" but grants the whole `payments` resource. ASYMMETRY: mint-side enum CapabilityCeiling::contains(Custom("payments:approve"))=FALSE (rejects) while consumer string step8=ACCEPTS — the PR's two new sibling gates disagree. Builtin `Bridging`→`bridging:*` and `ToolInvokeAll`→`tool_invoke:*` are INTENTIONAL wildcards; the Custom no-colon case is an unintentional one. Fix: reject no-colon Custom in ceiling, or make is_within_ceiling not treat a non-wildcard-declared `x:*` derived from a no-action cap as a wildcard, or require explicit `:*`. Legibility tenet violation (member sees "payments" ceiling, gets payments:*).

## LOW (pre-existing ordering, not this PR): steps 10 (revoke) + 11 (expiry) run AFTER nonce record. Revoked-but-fresh / expired-but-fresh token burns its OWN nonce. Self-defeating (own token), not victim DoS.

Method: detached worktree, minted real signed tokens via mint_ucan, ran probes with --nocapture, reverted gate to prove non-vacuity. All probes deleted, worktree removed.
