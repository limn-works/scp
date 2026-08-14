---
name: ceiling-builtin-wildcard-shadow
description: PR #1894 §5.3.1.1 wildcard-shadow fix — premise verified sound; projection identity holds; one spec/code divergence (tool_register phantom)
metadata:
  type: project
---

PR #1894 (branch fix/ceiling-builtin-collision-validator, HEAD 7bd7b4293) adds a
"No built-in-resource wildcard shadow" rule: a custom shape-3 wildcard `{resource}:*`
is rejected at validation when `{resource}` is a built-in resource token.

**Why:** `CapabilityUri::is_within_ceiling` (crypto/ucan/capability.rs:196-203) treats a
stored `{resource}:*` ceiling entry as covering EVERY action on that resource via
`ceiling.contains(format!("{}:*", self.resource))`. A `Custom("member:*")` does NOT
resolve to a built-in (`Capability::new("member:*")` stays `Custom` — there is no
`member:*` variant), so the pre-existing no-collision rule admits it; once stored it
would silently grant `member:ban` (gates governance Revoke).

**Verdict: SOUND.** Verified against current code, not docs:
- Projection identity PROVEN: mint.rs:264-266 builds the enforced grant's
  (resource,action) via the SAME `Capability::ucan_resource_action()` the fix's reserved
  set uses; CapabilityUri.resource == ucan_resource_action().0; is_within_ceiling keys on
  that exact token. Reserved set and coverage key are the same function — cannot diverge.
- Threat COMPLETE across both is_within_ceiling grant paths: exact-match path covered by
  no-collision rule (`Custom("member:ban")` → `Capability::new` = MemberBan, rejected);
  wildcard path covered by new shadow rule. Untrusted-deserialize boundary covered
  (`#[serde(try_from)]` → validate_entries → validate_as_ceiling_entry, roles.rs:530/566/684).
- Closed-by-construction: reserved set iterates BUILTIN_CAPABILITIES (completeness enforced
  by existing "all 18 built-ins" test); extends automatically to new built-ins.
- No false-reject of legit built-ins: import path rule 1 early-accepts built-in UCAN forms
  (bridging:*, tool_invoke:*) before reaching the custom core.

**Root-cause layer decision (forbid-entry vs narrow-coverage): forbid-entry is the SOUNDER
permanent design.** Narrowing is_within_ceiling to exclude built-in actions under a custom
wildcard would (a) make a stored entry's meaning depend on the built-in set at read time,
(b) keep the malformed/misleading entry in the legible ceiling members opt into (violates
§5.7 legibility), (c) push the check onto the hot grant path instead of the one-time write.
Reject-at-write keeps the stored ceiling honest and the read path simple. Not DOA.

**One finding — SPEC/CODE DIVERGENCE (low severity, not blocking the security fix):**
spec §5.3.1.1 hand-lists `tool_register` as a built-in resource token to shadow-reject,
but NO built-in projects to a `tool_register` resource (ToolRegister/ToolInterface →
resource "tool", roles.rs:268-303). The code's reserved set (correctly driven from
ucan_resource_action over BUILTIN_CAPABILITIES) does NOT include `tool_register`. Code is
correct (a `tool_register:*` custom shadows nothing); the spec's enumeration is a phantom.
The spec frames the list as "closed by construction over BUILTIN_CAPABILITIES" yet
hand-maintains a literal list that diverges from that source of truth — exactly the
hand-list-vs-generated drift the closed-by-construction framing is supposed to prevent.
Fix flows down: correct the spec enumeration (drop `tool_register`, or state the list is
illustrative of the generated set), not the code.
