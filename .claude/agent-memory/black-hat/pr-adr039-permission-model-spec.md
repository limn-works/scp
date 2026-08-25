---
name: pr-adr039-permission-model-spec
description: Attack surfaces found in commit 832ed9b2f9 (feat/adr-039-permission-model-spec) — spec §4.9, IDENTITY_KEY_RESERVED_RESOURCES, chain-walk step 6b
metadata:
  type: project
---

# ADR-039 permission-model spec + Category A code fixes (commit 832ed9b2f9)

## BLOCKER — `#agent` can mint a root UCAN granting itself the whole context ceiling

- `crates/scp-protocol/src/crypto/ucan/validate.rs:1355-1396` — `enforce_ucan_category_a`
  applies rules 1 and 2 only. No rule rejects a root token (empty `prf`) signed by `#agent`.
- ADR-039 §Permission Model, Category A bullet 4: "Root UCAN issuance — requires `#active`."
- `verify_root_issuer` (validate.rs:1227) is a plain string compare against
  `context_creator_did`; nothing reads `kid`.
- Exploit: agent shares its human's DID (ADR-039 shared-DID). In a context the human
  created, the agent mints `iss = aud = own DID`, `kid = "#agent"`,
  `fct.scp_key_scope = "#agent"` (satisfies steps 5a/5b), `prf = []`,
  `att` = every capability in the ceiling. Steps 2-11 all pass.
- Deferred to pending story SCP-AB-025 in `.docs/prds/agent-binding.json`.

## MAJOR — chain-walk step 6b runs before the parent's signature is verified

- `validate.rs:1569-1570` (`parse_granted_caps` + `enforce_ucan_category_a` on parent)
  runs before `verify_signature(&parent, ...)` at `validate.rs:1573`.
- A `CategoryAViolation` verdict — the ADR-039 layer-4 permanent-record trigger — is
  reached on attacker-supplied, unauthenticated proof bytes.

## Rule 2 is inert by construction

- `IDENTITY_KEY_RESERVED_RESOURCES` (`custody_violation.rs:181-188`) holds six tokens,
  all carrying `_`. `is_kebab_token` (`context/roles.rs:1080-1085`) forbids `_` in a
  custom ceiling entry, and none is a built-in, so step 8 already rejects them.
- Rule 2's only non-redundant coverage is the chain-walk parent path (parents are not
  ceiling-checked; only the leaf's `granted_caps` reaches
  `verify_ceiling_compliance` at `validate.rs:817`).

## Namespace collision — `service` / `identity`

- `CATEGORY_A_RESOURCES` mixes DID-document field names with context capability
  resources in one flat namespace. `service:read` and `identity:read` satisfy the
  §5.3.1.1 custom-ceiling grammar, so rule 1 rejects `#agent` on a context's own
  `service:*` capability. Recorded as an open question rather than fixed
  (`.docs/specs/00-open-questions.md:5-6`).

## Spec text that reads as a shipped guarantee

- `.docs/specs/04-agents.md:180-215` (Category B) and `:217-226` (Category C) are
  written in normative present tense. `fct.scp_agent_permissions`, `agent_keys_allowed`,
  `agent_rate_limit`, `agent_cosign_required` exist in zero source files;
  `ContextParams` (`crates/scp-protocol/src/context/params.rs:663-720`) has none of them.
- `.docs/specs/05-contexts.md:726` adds the three fields to §5.7's structural-metadata list.
- Contrast §4.9.1 rule 1 (04-agents.md:171) and §7.2.1 step 6b
  (07-trust-validation-and-capabilities.md:86), which DO state their absence honestly.

## What resists attack

- Capability-URI parsing is exact and fail-closed (`parse_granted_caps`, validate.rs:623).
  Resource must match exactly in `CapabilityUri::matches` — a `*` resource confers nothing.
- Every token in a chain is checked exactly once (leaf by `validate_ucan`, each parent
  by the walk, root as its child's parent). No gap.
- `verify_edge_attenuation` already parses parents' full `att` fail-closed, so the new
  parse adds no rejection — only a duplicate allocation.
- No mirror UCAN validator exists in `scp-client`/`scp-client-wasm`/`scp-mls`, so step 6b
  introduces no cross-implementation divergence.
