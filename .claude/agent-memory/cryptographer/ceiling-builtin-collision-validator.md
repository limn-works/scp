# Ceiling-entry §5.3.1.1 validation (PR #1894, branch fix/ceiling-builtin-collision-validator @ca6cadbf7)

SOUND — capability-security review APPROVE, no actionable findings. roles.rs context::roles 131/131 pass; my adversarial probe (enum/ucan-import/serde surfaces × all privileged families) passes once corrected.

## Construction
§5.3.1.1 enforced by TWO closed-by-construction rules in scp-protocol/src/context/roles.rs:
1. No-collision: `Capability::validate_as_ceiling_entry` (L428) re-resolves a `Custom(name)` through `Capability::new` (L150); if it does NOT round-trip to `Custom(_)` it names a built-in in SOME spelling (colon OR UCAN form, incl parameterized tool:invoke:{id}) -> reject. `Capability::new` is the single authority on "what string is a built-in".
2. No-wildcard-shadow: `validate_custom_ceiling_entry` (L1058) rejects custom `{resource}:*` where resource ∈ {c.ucan_resource_action().0 for c in BUILTIN_CAPABILITIES} (L1107).

## Projection equivalence (the load-bearing fact)
is_within_ceiling (capability.rs:196) wildcard key = format!("{}:*", self.resource) where resource = CapabilityUri.resource = split_once(':') of the {resource}:{action} URI segment (from_str L244). For EVERY built-in, ucan_resource_action().0 == split_once(':')[0] of its ucan_capability_name() == the resource is_within_ceiling derives. So the shadow-check reserved set is EXACTLY the wildcard keys is_within_ceiling matches. Verified all 18 built-ins by table. Closed over BUILTIN_CAPABILITIES, not a denylist.

## Edges confirmed
- bridging:* IS a legit built-in canonical form (Bridging). Custom("bridging:*") rejected by no-collision (resolves to Bridging); raw UCAN-import "bridging:*" accepted (it IS the built-in). Same for tool_invoke:* (ToolInvokeAll), member:ban, etc. — legit built-in forms granting their own family is CORRECT, not a bypass.
- _-resources (tool_invoke, context_child) unreachable as custom (kebab forbids _), so absent from shadow set harmlessly.
- No false-reject: member:promote, payments:*, messages:archive, governance:draft all accepted (shape-2 grants only itself; wildcard over non-builtin resource OK).

## Intake surfaces all gated
- enum/create+governance: validate_as_ceiling_entry
- raw UCAN import (WASM from_ucan_strings manager.rs:371): validate_ucan_ceiling_string -> validate_custom_ceiling_entry shadow check reachable+load-bearing
- WASM from_colon_entries (manager.rs:326): Capability::new + validate_as_ceiling_entry
- serde from-bytes: CapabilityCeiling has #[serde(try_from=CapabilityCeilingRaw)] -> validate_entries; ContextRoleState.ceiling is typed CapabilityCeiling so embedding-struct deser also gated
- native create lifecycle_helpers.rs:1381+1790; governance ModifyCeiling governance_helpers.rs:489 set_ceiling -> validate_entries; class_s.rs:5188 set_ceiling
- set_ceiling (roles.rs:1786) re-validates whole replacement

## NOTE (out of scope, not a finding here)
ContextRoleState.member_capabilities: HashMap<String,HashSet<Capability>> deserializes WITHOUT ceiling-entry validation (it's derived grant data, not ceiling entries). Authorization re-checks against ceiling via contains() at use, but a malicious signed export could seed member_capabilities with Custom("member:*"). Worth a separate look at whether any auth path trusts member_capabilities without a ceiling intersection. Not part of §5.3.1.1 ceiling-entry scope.
