---
name: adr051-construction-standard
description: API-design review of construction.md + ADR-051 unified construction pattern (flat config-object, entry-verb rule, M1-M5)
metadata:
  type: project
---

# ADR-051 Construction Pattern Standard review (branch docs/adr-051-construction-pattern, 2026-06-14)

Reviewed `.docs/standards/construction.md` + ADR-051 (`.docs/adrs/phase-2.md` lines 1524-1595) as an API-design standard for first-pass LLM authorability.

**Why:** New cross-cutting standard governing every developer-facing construction entry point (Node/Relay/host_site/Context/Identity) across all 5 languages. Supersedes ADR-032 §AC-6 typestate builder. Verdict: NEEDS REVISION.

**How to apply:** When this standard ships or its AC-9 structural check (`scripts/check-construction-pattern.py`) is implemented, re-check these 5 findings are resolved.

## What's solid (confirmed consistent)
- Entry-verb rule deterministic: `start`=spawns runtime (Node,Relay), `create`=value/handle (Identity,Context). All shapes obey; RelayServer::new + host_site free-fn exempted explicitly.
- Exactly ONE TlsMode enum — SiteConfig.tls explicitly "same enum as NodeConfig.tls".
- Storage vocab pinned: Storage(trait) / StorageSlot(core selector, incl Rust-only Custom) / StorageConfig(FFI mirror, omits Custom). Used consistently incl IdentityConfig.persistence: Option<StorageSlot>.
- M5 single-exception (EncryptedStorage start/start_for_testing) tight, backed by structural unreachability test.
- M2-vs-M3 axes explicitly disambiguated (default-direction vs runtime-satisfiability).

## Findings (NEEDS REVISION)
- F1 [Med]: SiteConfig has TWO security-relevant fields (tls, dht) but M2 only names "Site TLS" — doesn't state SiteConfig inherits Node's DHT-publish loud-error rule too. M2 should fire twice.
- F2 [Med]: M4 asserts RelayConfig keeps Default ("every field fail-safe") but new BridgeRole enum makes that depend on unstated `Default for BridgeRole = Disabled`. State it.
- F3 [Med]: IdentityConfig{method,custody,persistence:Option<StorageSlot>} vs NodeConfig.identity:IdentitySource{Generate/Persisted/Explicit} cover same ground with DIFFERENT shapes. IdentitySource::Persisted carries NO StorageSlot while IdentityConfig.persistence does — "persisted identity" means two different things. Ambiguous how Node persisted-identity routes key storage.
- F4 [Low]: StorageSlot::Custom may be non-EncryptedStorage. Node::start guards via S:EncryptedStorage bound; IdentityConfig.persistence has no stated bound — could silently persist plaintext key material. M2 designates identity-key-persistence as THE security-critical Identity choice, so gap matters.
- F5 [Low]: Context M2 "Template resolves only to fail-safe parameters" is a property of template DATA, not config shape — check-construction-pattern.py cannot mechanically verify it. Note it's human-review, not mechanical (standard is otherwise scrupulous about that distinction).

## Recurring pattern relevant to this project
Provenance verified: cited machinery (DhtMode, HostSiteOptions, plaintext/skip_nat, RelayServer::new, private IdentitySource collision) all exist on-branch in crates/scp-node/src/self_host.rs + lib.rs. Standard is forward-looking (governs not-yet-built reshape), so review is internal-consistency only.
