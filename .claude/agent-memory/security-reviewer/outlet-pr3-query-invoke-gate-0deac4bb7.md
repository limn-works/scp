# Outlet PR-3 OutletQuery kind-aware invoke gate (feat/outlet-report-pr3, 2f45eefa6..0deac4bb7) -- 2026-07-10 -- SOUND, zero findings; 1 completeness obs

Delta "completes the OutletQuery path": adds `kind: OutletKind{Query=0x00,Action=0x01}` to outlet
registration (already in §5.4.1 V2 signing preimage from earlier PR commits), threads it core→bridges→SDKs,
adds `has_outlet_query_capability`/`has_outlet_invocation_capability(kind)` and a kind-aware invoke gate.

VERDICT: gate sound. No read(Query)→mutate(Call) escalation, no bypass.

- **Mapping/amplification barrier**: Query→`outlet_query` stem, Action→`outlet_call` stem. CapabilityUri::matches
  (capability.rs:177) hard-returns false on resource mismatch; `*` wildcard applies ONLY to action(outlet_id)
  NOT resource, so `outlet_query:*` can NEVER satisfy required `outlet_call:x`. is_within_ceiling keys on
  resource too → independent ceilings. Role-state helpers check distinct OutletQuery/QueryAll vs Call/CallAll
  enum variants (exact set membership). Proven by wildcard_..._independent + validate_..._selects_stem_by_kind tests.
- **Authentic binding**: kind_byte in V2 preimage (hash.rs:83); verify_outlet_registration_signature
  (registry.rs:583) verifies Ed25519 over compute_outlet_registration_canonical_bytes (same funnel as signing).
  ALL 7 invoke callers source kind from registry.get().map(|r|r.kind), NEVER caller input:
  runtime invoke.rs:266/462/698, uniffi bridge.rs:12887/13138/4612, pyo3 outlets.rs:343, napi outlets.rs:39,
  mcp mcp.rs:728. SDK `kind` is on registration OutletDefinition only, never on invoke path.
- **No TOCTOU**: runtime invoke_outlet fetches `registration` ONCE, uses same snapshot for gate+execute.
  Bridge kind-read→UCAN→execute divergence needs concurrent re-registration (requires OutletRegister cap) and
  runtime kind-aware role-state gate re-checks at execute time.
- **default()==Action = FAIL-SAFE**: absent/malformed kind → Action → requires stronger OutletCall →
  OutletQuery holder CANNOT invoke defaulted outlet. No fail-open.
- **Residual call-based checks are defense-in-depth only** (session.rs:356, outlets.rs:924/1480, mcp.rs:799,
  bridge.rs:4706, interface.rs:1797): all REQUIRE OutletCall → can only DENY, never permit Query→Action
  escalation. Sessions inherently mutating (correctly Action). MCP/xctx ones run AFTER kind-aware primary gate.

OBS (completeness, NOT security): MCP agent surface + xctx source-governance call-based checks are STRICTER
than the primary gate — they require OutletCall even for Query outlets → a pure-Query grant passes the primary
UCAN gate then gets denied by the secondary check → Query outlets effectively non-invokable via MCP/interface
by query-only principals. Fail-closed (over-denial), so not a vuln, but defeats the functional goal of the split
on those surfaces. Reconcile mcp.rs:799/bridge.rs:4706/outlets.rs:924/interface.rs:1797 to
has_outlet_invocation_capability. Keep session.rs/outlets.rs:1480 call-based (sessions genuinely mutate).

CARRY: empty-signature registrations skip verification (registry.rs:569) → kind unverified for those;
pre-existing backward-compat, not an injection vector (registration requires OutletRegister cap; local registry
built by local node), kind rests on registrant honesty absent a signature.
