---
name: adr057-t1cb-parser-consolidation
description: ADR-057 T1c-b review — consolidate did:dht z-base-32 parser onto single scp-did authority; COMPLETE, zero findings
metadata:
  type: project
---

# ADR-057 T1c-b — did:dht parser consolidation

COMPLETE, zero findings. Branch feat/adr057-t1cb-parser-consolidation @ebda42b1f atop 0d4db22b5. READ-ONLY review. Diff is 3 files only: crates/scp-identity/src/dht.rs, crates/scp-identity/src/lib.rs, .docs/adrs/ADR-057-in-browser-client-over-shared-mls.md.

**Why:** last slice before T2 in the ADR-057 T-series (T1 topology split, T1c-a scp-dht extract, T1c-b this, T2 client storage next). Pure behavior-preserving refactor — collapses the last inline did:dht z-base-32 decoder onto the single hardened authority scp_did::extract_public_key_from_did.

**How to apply / what was verified:**
- `scp_identity::dht::extract_public_key` rewritten as thin wrapper: unconditional `did:dht:z` positive-prefix gate → delegate to scp_did authority. Private `DidDht::extract_public_key` delegate method DELETED; 2 production callers (publish dht.rs:848, resolve :943) + 7 test sites retargeted to free fn (count matches ADR exactly). DidDht::verify (dht.rs:2106) untouched — reaches authority via `extract_public_key(...).is_ok_and(...)`.
- ONE authority: sole production `zbase32::decode` workspace-wide = scp-did/src/lib.rs:123. Every other hit (dht.rs 2669 comment; 2805/3273/3333 tests under #[cfg(test)] mod tests @2673; app_sandbox 2166 test; resolvers 77 comment / 1133 test; scp-did 551 test) is comment or test. app_sandbox production delegates at :912 to scp_did fn (no inline decode).
- `IdentityError::ZBase32DecodeError` variant DELETED (lib.rs); folded into single InvalidDidFormat channel. Repo-wide sweep: zero surviving refs except ADR-057 historical narrative. No From<IdentityError> match arm referenced it (compiles). Only asserted message string "not canonical" still satisfied by authority wording.
- Unconditional gate (NOT cfg(not(test/testing))) is correct: scp-identity/testing rides in transitively via custody chain (allow_in_memory_custody→scp-testing→scp-identity/testing unifies scp-did/testing), so a cfg-gate would be OFF in exactly the custody builds it must protect. New test extract_public_key_rejects_did_key_in_every_build pins it with honest caveat that CI feature-unified run is the load-bearing execution.
- Cross-parser test renamed native_and_scp_did_parsers_agree_on_canonicality → wrapper_delegates_to_scp_did_authority_on_accept_and_reject; old name referenced NOWHERE. Two new tests added (did:key rejection, decode-failure→InvalidDidFormat taxonomy).
- (f) No Cargo.toml/lock changes — edge pre-existed. (g) scp-did untouched (not in diff). (h) BridgeDidResolver local did:key gate (resolvers.rs:80-81 `#[cfg(not(any(test, feature="testing")))]`) present + NOT in diff — its retirement belongs to #1733; slice correctly left it.
- ADR line 83 slice framing reads correctly (T1 + T1c-a landed first; T1c-b landed own follow-on; T2 follows). Line 85 T1 bullet's "two parity-tested parsers, not (yet) a single one — consolidation is T1c-b" is coherent historical record, forward-refs the now-landed T1c-b bullet (line 87). No "two parsers"/ZBase32DecodeError-exists claims anywhere in .docs/ error tables/FFI docs/PRDs/specs.

No new protocol op → Integration checklist N/A (unchanged wrapper signature + callers, unchanged public surface except removed error variant). LESSON confirmed from prior T-series entries: on ADR-057 slices the ADR landed/deferred STATUS must move — here it DID (line 87 "immediate next slice" → "landed in this change set", both blockers' resolutions recorded accurately: taxonomy fold + unconditional-gate rationale). See [[adr057-t1c-dht-extract]], [[adr057-t1-primitives-dissolve]], [[adr057-t2-client-storage]].
