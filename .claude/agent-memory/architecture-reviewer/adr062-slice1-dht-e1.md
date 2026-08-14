---
name: adr062-slice1-dht-e1
description: ADR-062 Slice 1 (DHT E1) architecture review — sound structural default-removal + enum dispatch, but host_site publish-mode re-derivation is incoherent (two DHT sources of truth)
metadata:
  type: project
---

ADR-062 Slice 1 / SCP-CAPINJECT-001 (branch feat/adr062-slice1-dht-e1, diff 9ff9eadde..e54de4fae). Review verdict: APPROVE-WITH-CHANGES.

SOUND (by construction): D-A default-type-param removal (`DidDht<D: DhtClient>` no default) makes silent in-memory DHT unexpressible; `FfiDhtClient` enum (Pkarr unconditional, InMemory `#[cfg(feature=testing)]`) in scp-ffi-common; `ClientDhtConfig::into_client` fail-closed (no in-memory fallback); `DisabledDhtClient` in scp-dht (leaf) is an honest non-nullifier (publish→Err(DhtError::Disabled), resolve→Ok(None)); `DhtMode::Disabled` fail-safe default replacing test-only `Memory`. G1 feature-absence==type-absence is closed-by-construction. Layering clean (no core→bridge dep).

**PRIMARY DEFECT — two DHT sources of truth disagree (self_host.rs).** `dispatch_hosted_site_by_dht_mode` selects concrete D from `config.dht` (Disabled→DidDht<DisabledDhtClient>). But `build_host_site_node` (self_host.rs:2156) RE-DERIVES the publish-decision `DhtMode` from `skip_nat` (i.e. from `reach`), ignoring config.dht: `skip_nat ? (Local,Disabled) : (NatTraversal,Production)`. So `HostSiteConfig{reach:NatTraversal, dht:Disabled}` → D=DisabledDhtClient + NodeConfig.dht=Production → publish_did_document_for_mode(Production) calls DisabledDhtClient.publish() → Err(DhtError::Disabled) → Node::start fails → HostSiteError::NodeBuild. Node FAILS TO START on a config every docstring (self_host.rs:918-923 "valid with any reach... never an error"; NodeConfig test 12) explicitly blesses. Reachable from shipped `--self-host` binary (main.rs:751-760): reach and dht come from independent env vars (SCP_NODE_SELF_HOST_NO_NAT vs SCP_DHT_MODE=disabled). FIX: thread the real dht_mode into build_host_site_node and use it for NodeConfig.dht instead of re-deriving from skip_nat.

Doc staleness: HostSiteConfig.dht doc still says "DhtMode::Memory (no publish) is the fail-safe" (self_host.rs:918, :940) — Memory is now test-only, Disabled is the fail-safe. NodeConfig.dht doc (config.rs) still calls the field "advisory... not yet wired" but it now drives the publish decision.

Q5 napi SHARED_DHT_CLIENT (finding D) defer to #2151: ACCEPTABLE for this slice — pre-existing #1144 storage-topology global, merely retyped InMemory→FfiDhtClient (not a nullifier, ships Pkarr, doesn't defeat G1/fail-closed), ratchet-allowlisted (tracked, not silent), bundling a cross-cutting bridge refactor into a focused security slice violates atomic-commit discipline. CONDITION: #2151 must land before Slice 6/9/10/11 re-touch bridges; a later slice COPYING the global pattern to another capability would entrench a DOA decision and must block.
