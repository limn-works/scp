# UCAN A+A Delegation Fix (remediation/ucan-core-impl, base caf098986)

## The bug
- `delegate_ucan` (mint.rs ~625) FLATTENED prf: `proofs = parent.prf.clone(); proofs.push(parent_cid)`.
  Depth-3 leaf got `prf=[root_cid, mid_cid]`. Validator `verify_chain_recursive` (validate.rs ~1128)
  treats EVERY prf entry as a DIRECT parent (checks `parent.aud == token.iss`). Flattened grandparent
  fails linkage -> DelegationChainBroken. ALL depth>=3 honest delegation rejected; R4 per-edge attenuation
  never engaged on real chains.
- `verify_edge_attenuation` (validate.rs ~1335) SKIPPED narrow() when EITHER side resolved None ->
  absent-nb intermediate launders ancestor's bound (leaf can widen).

## The fix (A+A, no backward compat)
- 1A: `delegate_ucan` emits NESTED prf: `let proofs = vec![parent_cid];` (direct parent ONLY).
  Validator walk resolves direct parent via resolver, recurses into parent.prf. Production NEVER
  reconstructs chain from flattened leaf.prf -- uses CID->token resolver. FFI bridges pass-through prf.
  WASM has no delegate (mint takes caller proofs); validate delegates to shared scp_protocol validate.
- 2A mint fold (build_delegated_caveats): child nb = COMPLETE self-contained narrowed set.
  Start from parent.nb, overlay caller-supplied child fields, materialize origin_kind (inherit parent's
  Some, or infer from delegated cap stems when parent root None: outlet_query->Query, outlet_call->Action,
  mixed->error), then parent.narrow(&materialized) final gate, then try_new for mint limits.
  caller None + parent Some -> inherit parent verbatim. caller None + parent None + non-outlet caps -> None.
- 2A validator (verify_edge_attenuation): STOP skipping on absent. New per-edge stateless rule:
  parent Some + child None -> REJECT (CaveatAttenuationViolation FieldRemoved). both Some -> narrow.
  parent None + child Some -> narrow (handles None parent). both None -> OK.

## Spec amendment
- §7.3.8 line 773-775: removed contradiction. Canonical model: non-root tokens carry COMPLETE
  re-materialized effective set (mint folds); validator enforces per-edge narrow at EVERY edge and
  REJECTS non-root child omitting a parent-bound field. No absent->skip/inherit at validate.

## Key invariant interactions
- narrow() already rejects child origin_kind=None (OriginKindUnspecified) and present-parent-field
  removal (FieldRemoved). Mint fold producing complete set => narrow passes; validator reject-absent
  composes with these.
- effective_caveats (§5.4.5 line 649) = leaf nb directly is now sound (no SDK fold).

## Tests fixed (bug-encoded)
- ucan_validate_integration.rs ~1969: gamed test minted leaf via mint_ucan(proofs:[mid_cid]) to dodge
  flatten -> rewritten to use REAL delegate_ucan at every hop, assert PASS.
- mint.rs ~1665: delegate_ucan_chained_delegation_accumulates_proof_chain asserted carol_to_dave.prf.len()==2
  (FLATTENED) -> rewritten to assert nested (len==1, direct parent only).
