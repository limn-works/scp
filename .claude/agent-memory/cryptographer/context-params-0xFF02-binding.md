# §5.13.3 context-params (0xFF02) group_context binding — creator/KP slice (2j-ffi-slice, commit 3ecb933bf)

Closes the creator/KP half of FFI-02. scp-mls glue (prior commit 5c19deb26):
`create_group_with_context`, `generate_key_package_with_context_params`,
`scp_capabilities_with_context_params`, `ScpMlsGroup::group_context_extension()`.
Extension type 0xFF02 = SCP_CONTEXT_EXTENSION_TYPE_ID; canonical = JCS(ScpContextExtension).

## The coupling (OpenMLS valn0502 — LOAD-BEARING)
A group carrying the 0xFF02 group_context extension REJECTS (AddMemberFailed,
"capabilities insufficient") any Add whose KeyPackage leaf does NOT declare 0xFF02
in its Capabilities. So creator-writes-0xFF02 and every KP-declares-0xFF02 MUST ship
together. NOTE: 0xFF02 is a GROUP_CONTEXT extension, not a leaf ext — the KP only
DECLARES CAPABILITY for it (no leaf value). 0xFF01 (wrapping) IS a leaf ext requiring
a wrapping key. A KP declaring MORE caps than a group requires is fine (extra caps OK),
so 0xFF02 KPs join wrapping-only groups too — no regression.

## What this slice wired (crypto/** + builder.rs only)
- production_backend.rs `MlsBackend::generate_key_package`: Some(wrap)→context_params
  (0xFF01+0xFF02); None→wrapping-only fallback. This is the KeyPackageStoreActor pool
  path (key_package_actor.rs:1726 passes self.wrapping_pubkey.as_ref()).
- provider.rs: added `create_mls_group_with_context` (creator write, commits ext);
  factored shared reserve/overwrite-refusal into `create_group_into_slot`; kept
  wrapping-only `create_mls_group` for the ~7 out-of-scope test callers (lifecycle_helpers,
  ttl, key_destruction, supervisor tests, recovery, agent_binding_pipeline_tests).
  Also switched `prepare_key_package_for_join` (test/feature-gated joiner KP mint,
  #[cfg(any(test,feature="testing"))]) to context_params — provider always holds a
  wrapping key. This was the source of the 2 agent_binding_pipeline_tests failures.
- builder.rs `create_context` Encrypted branch: ScpContextExtension::for_root(context_id,
  params.mode, &params.governance, params.ceiling_policy, &CapabilityCeiling::new(params.ceiling.clone()))
  → create_mls_group_with_context. Broadcast untouched (init_broadcast_key, no MLS group).
  Production path confirmed: supervisor → lifecycle_helpers::create_context → builder::create_context.

## OPEN GENUINE FINDINGS (flag to next-step reviewer)
1. NON-UNIVERSAL None branch: MlsBackend::generate_key_package with wrapping_pubkey=None
   produces a NON-0xFF02 KP (no scp-mls API gives 0xFF02-cap-without-wrapping-leaf; scp-mls
   out of scope). handle.rs:2235 maps wrapping_pubkey = wrapping_keys.get(identity) → CAN be
   None in production (stale comment there calls the extension "optional"). Such a pooled KP
   is context-UNJOINABLE (fail-closed, not a hole). To make 0xFF02 truly universal, production
   must guarantee a wrapping key before pooling (handle.rs/registry — out of this slice's scope).
2. FOOTGUN: wrapping-only `create_mls_group` remains pub — a future production caller could
   create a 0xFF02-less (non-param-binding) context group. Only builder uses the context variant
   today. Kept to avoid editing ~7 out-of-scope test files. Consider making it pub(crate)/test-only
   or deleting once callers migrate.

## NEXT STEP (not this slice): supervisor.rs join/import verification
Joiner must read group_context_extension() and call ScpContextExtension::verify_against the
context's declared params before building authority (the FFI-02 read/verify side).
