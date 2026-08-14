# WASM PerContextState adopts shared ContextRoleState (#1877 slice 1, branch wasm/1877-slice1-adopt-context-role-state, c65552c9e)

State-representation refactor: WASM `PerContextState` replaced flat role model
(MemberEntry{did,role,seq}, ceiling_strings:HashSet<String>, suspended_capabilities,
creator_did) with shared `scp_protocol::context::roles::ContextRoleState` +
`member_sequence_numbers: HashMap<String,u64>` (MLS seq counter, the ONLY field
not living in ContextRoleState). VERDICT: cryptographically SOUND, no blocking findings.

## Verified properties
- **★ Ceiling wire-format (default case) PRESERVED, byte-equal.** default_ceiling().to_ucan_string_set()
  == old build_ceiling_strings(empty) exactly (10 caps, all round-trip clean). Confirmed by enumeration.
- **Explicit-ceiling case NOT format-identical for 3 input classes (convergent fix, not regression):**
  Capability::new(s).ucan_capability_name() differs from old capability_to_ucan_format(s) for:
  (a) colon-less protocol caps: "bridging" → "bridging:*" (old: "bridging");
  (b) colon-less customs: "foo" → "foo:*";
  (c) "custom:"-prefixed: "custom:thing" → "thing:*", "custom:a:b" → "a:b" (old: "custom_a:b").
  IMPACT NIL: CapabilityUri (UCAN step-8 required cap) MUST have a colon (FromStr split_once(':')),
  so a colon-less ceiling entry like old "bridging" was DEAD/unreachable in is_within_ceiling
  (capability.rs:196). NEW "bridging:*" is reachable and matches native to_ucan_string_set. Pre-release,
  no old signed exports exist (feedback_no_migration_prerelease), so cross-version import is moot.
- **NEW→NEW export/import/re-export idempotent (0 breaks)** over all to_ucan_string_set outputs incl
  edge "bridging:*"→Custom("bridging:*")→"bridging:*". Signed §23.16.8 snapshot byte-stable for NEW exports.
- **Signed snapshot (WasmContextExportSnapshot) byte layout UNCHANGED** — struct fields + canonicalize_snapshot_sets
  identical; only the SOURCE of field values moved (flat → role_state projections). creator_did reads
  same string. role_state itself NOT serialized into snapshot (rebuilt from flat fields on import).
  Tamper tests (manager.rs:8506+) operate on the unchanged struct → still protect format. Role TOKENS
  (mint_role_tokens, OsRng nonces) are in-memory assignments[].tokens, NOT in snapshot → cannot change signed bytes.
- **MLS seq counter (member_sequence_numbers): no nonce-reuse.** send path (1880) read+(+=1) behaviorally
  identical to old member.sequence_number; feeds encrypt_message(...,seq) sender-key nonce. or_insert(0)
  fallback only fires on membership/counter desync — no path removes counter while keeping membership
  (leave/remove drop both; reset re-seeds 0 = old behavior). Counter seeded alongside membership at
  every insert site (create/join/add_member/subscribe/import).
- **suspend_all semantics change (whole-ceiling → role-granted set): NO access-control regression.**
  member_has_capability returns false iff cap ∈ suspended AND ∈ member_capabilities; member can only
  exercise role-granted caps, so suspending exactly member_capabilities yields identical deny decision.
  Old whole-ceiling extra entries were unreachable. CONVERGES WASM to native (native uses same suspend_all).
- **member_has_capability exact-match vs old wildcard:** shared type does member_capabilities.contains()
  EXACT — ToolInvoke(specific) query against a member holding ToolInvokeAll returns FALSE (no wildcard
  special-case like CapabilityCeiling::contains). NOT reachable: prod call sites use only fixed strings
  context:close / governance:propose / governance:vote. tool-invoke authz uses the separate UCAN path
  (context.rs:2121-2155) which keeps its own tool_invoke:* wildcard handling.
- **#1886 fix (system_assign_role validates role against role_definitions):** undefined/out-of-ceiling
  ChangeRole/AddMember now REJECTED (was silently accepted as free-form string stripping caps). AddMember
  rolls back membership insert on assignment failure (fail-closed atomicity). Matches native.
- **Event-log/Merkle leaves UNTOUCHED:** no added line touches push_event/leaf append/EventType/EventPayload/
  hash. creator_did→actor reads resolve to identical string.
- **Role-token minting CSPRNG/clock OK:** generate_nonce uses OsRng (nonce.rs:69-77); clock=WasmClock
  (js_sys::Date, SystemTime fallback on native test). Tokens never signed/hashed/exported.

## Tests: 382 pass (incl change_role_to_undefined_role_is_rejected_wasm, _to_defined_role_succeeds,
add_member_with_undefined_role_is_rejected, snapshot tamper tests). Run: cargo test -p scp-ffi-wasm --lib

## Minor (non-blocking) observations
- PR claim "format-preserving, exactly equals" is precise ONLY for the default ceiling (verified) and the
  NEW-code round-trip. It is NOT literally true for explicit colon-less / custom: ceiling inputs — but
  every divergence is a convergent fix toward native semantics, with no reachable security impact.
- "bridging:*" round-trips as Custom("bridging:*") not Bridging (ucan_string_to_capability only knows
  colon form "bridging"). Byte-identical on re-export so harmless, but a latent typed-variant mismatch
  if any code later pattern-matches Capability::Bridging on an imported ceiling. Cosmetic.
