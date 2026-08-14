# ADR-052 P5 downstream-updates review (feat/p5-downstream-updates @ fe3eca2fd)

Reviewed docs/example migration from old HostSiteOptions bool API to HostSiteConfig enum API.
Files: examples/website.rs, examples/README.md, deploying-an-scp-website.md,
self-hosting-a-website-on-scp.md, main.rs, self_host.rs.

## Result: NO BUGS FOUND. Clean.

## Verified facts (avoid re-deriving):
- `NodeConfig.dht` / `dht_gateways` are INERT in the no-domain path — dropped in
  `split_config` (config.rs:549-552). Actual publish behavior = the concrete
  `did_method` (InMemoryDhtClient vs PkarrDhtClient), which `host_site_until`
  selects from the user's `dht` field (self_host.rs:1085-1109). So
  `build_host_site_node` deriving `(reach,dht)` from `skip_nat` (1831-1835) is
  redundant-but-harmless: the dht half is dropped, only `reach` is used.
- `Reach::NatTraversal` + `DhtMode::Memory` (reachable-but-unpublished) works:
  skip_nat=false → NatTraversal probes NAT; did_method=Memory → no publish. Correct.
- `Reach::Tunnel.public_url` silently dropped on host_site path (no warning),
  WARNS on NodeConfig path (config.rs:769 warn_tunnel_public_url_deferred). Guide
  line 18 documents this honestly. Pre-existing known limitation, not a defect.
- website-site/ has index.html + style.css (2 files); README says exactly that;
  embedded default (embedded_assets) has 3 (index/style/app.js). Both correct for
  their context — no mismatch.
- Example compiles clean. All imports exported from crate root (lib.rs:48-60).
- build_no_domain_inner STILL EXISTS (lib.rs:3170, pub(crate)) — guide §3 ref OK.
- Line 379 ref to deleted ApplicationNodeBuilder::identity_with_storage() is
  INSIDE the 2026-06-14 running-log entry, explicitly preserved as historical per
  the 2026-06-16 entry (line 396). Acceptable per doc's own convention.

## Pattern note
ADR-052 P5 docs migration: prose §sections updated to enum API; running-log
entries intentionally frozen with old-API refs + a forward-pointer correction
entry. When reviewing, distinguish present-tense prose claims (must be current)
from dated running-log history (may cite deleted symbols — OK if a later entry
flags the deletion).
