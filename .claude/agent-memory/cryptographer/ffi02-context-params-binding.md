---
name: ffi02-context-params-binding
description: §5.13.3 0xFF02 scp_context_params MLS group_context extension closing FFI-02 — crypto review (SOUND)
metadata:
  type: project
---

# §5.13.3 0xFF02 SCP Context Parameters MLS group_context binding (closes FFI-02)

Reviewed branch feat/adr049-2j-ffi-slice @408cf3787 (2026-07). Verdict: **SOUND**, no CRITICAL/HIGH.

**Why:** FFI-02 = a Welcome-based joiner must not build authority from untrusted caller-supplied `params`. Fix binds governance/ceiling/mode/policy/context_id/lineage into the MLS `group_context` (0xFF02 extension, RFC 9420 §17.3 private range), verified against caller params BEFORE any crypto/authority install.

**How to apply:** this is the reference for how SCP binds context params to MLS group identity. Files:
- `scp-protocol/src/context/group_context_extension.rs` — `ScpContextExtension`, `verify_against` (rules 2-6), `for_root`/`for_child`, `SCP_CONTEXT_EXTENSION_TYPE_ID=0xFF02`. Hashes = SHA-256(RFC-8785-JCS(value)). KAT-pinned canonical bytes + digest.
- `scp-mls/src/context_extension.rs` — MLS glue; `scp_capabilities_with_context_params()` declares 0xFF01+0xFF02; `extract_context_params`. 3-member survival test proves OpenMLS carries+authenticates extension across epochs.
- `scp-runtime/.../lifecycle_helpers.rs::verify_scp_context_binding` — single shared check for join/import/restore; fail-closed (Ok(None)=rule-1 reject).
- `supervisor.rs` step 1b — join path: verify AFTER ConfirmConsume (KP burned) but BEFORE install_joined_group/build_welcome_joiner_state. Correct placement.
- `provider.rs` — `create_mls_group_with_context`, `group_context_extension`; join KP now via `generate_key_package_with_context_params` (always has wrapping key).

**Key soundness facts:**
- Extension IS part of MLS crypto identity: signed GroupInfo + confirmation_tag; joiner reads authenticated bytes; survives commits (verified). Attacker/member cannot present a Welcome with divergent extension without failing MLS validation.
- context_id transposition blocked: verify checks ext.context_id==supplied id; ext is creator-committed ground truth.
- Ceiling determinism: `CapabilityCeiling` = HashSet serialized via `serde_util::serde_sorted_set` (sorts by per-element JCS bytes, fails loud on JCS error). No floats anywhere. Cross-impl deterministic.
- Discriminants match spec u8: ContextMode Encrypted=0/Broadcast=1; CeilingPolicy Immutable=0/Governed=1.
- Import binding closes real gap: snapshot signature authenticates exporter identity, NOT params↔embedded-mls-group consistency — this check adds that.

**Open findings (none blocking):**
- MEDIUM (spec-scope): binding covers ONLY governance+ceiling+ceiling_policy+mode+context_id+lineage. NOT bound: roles, economic_policy, ttl, memory_scope, promotion_policy, template_id. roles⊆ceiling and changes go via bound governance so bounded, but initial roles/economic_policy/ttl divergence between inviter-supplied params and group's real state is undetected. Spec decision needed (extend binding OR document why unbound).
- MEDIUM (defense-in-depth): no re-validation that a later MLS GroupContextExtensions proposal rewrites the 0xFF02 extension post-creation. Join-time binds to CURRENT value; epoch-N rewrite of governance/ceiling not re-checked against original consent. Confirm SCP commit-processing governance rejects unauthorized group_context mutation.
- LOW: GovernanceModel::{Threshold.signers, Majority/Unanimity.eligible_voters} are Vec — order is hash-significant but semantically insignificant. Honest flow matches (params transit preserves Vec order); a future SDK that reorders signers would spuriously fail binding. Document order as load-bearing or sort in canonical form.
- LOW: `ScpContextExtension` lacks `#[serde(deny_unknown_fields)]` (harmless — MLS authenticates bytes, verify recomputes from parsed fields — but cheap DiD, consistent w/ InnerEnvelope).
- LOW/availability (fail-closed): production `generate_key_package(None)` → KP declares neither 0xFF01 nor 0xFF02 → context-unjoinable (valn0502 fail-closed). Reachability rests on KeyPackageStore always sourcing published wrapping key for context participants.
