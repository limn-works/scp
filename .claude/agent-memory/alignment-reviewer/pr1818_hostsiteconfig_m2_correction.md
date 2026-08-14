---
name: pr1818-hostsiteconfig-m2-correction
description: PR #1818 ADR-052 P3c HostSiteOptions→HostSiteConfig + DhtMode promotion + M2 fail-safe-direction correction (removed error on safe direction) — ALIGNED, ready to merge
metadata:
  type: project
---

PR #1818 branch `feat/p3c-site-config` (SCP). ADR-052 Phase B-P3c. Reviewed at origin/feat/p3c-site-config. Verdict ALIGNED, 0 findings, ready to merge.

**What it does:** (1) folds `HostSiteOptions`→`HostSiteConfig` (construction-pattern flat config): `plaintext:bool`→`tls:TlsMode`, `skip_nat:bool`→`reach:Reach`, `dht_mode`→`dht:DhtMode` (M1); no whole-struct Default, `HostSiteConfig::defaults(reach)` factory (M4). (2) promotes `DhtMode` from self_host.rs into config.rs (ONE shared def for Node+Site) — verified on remote: exactly 1 `pub enum DhtMode` at config.rs:210, old def deleted, 0 `HostSiteOptions` residual. (3) **M2 correction** + banner fix.

**The M2 correction (load-bearing).** Previously `validate_config` errored on publishing `Reach` (`Domain`/`NatTraversal`) + `DhtMode::Memory`. This PR DELETES that error (the `if dht==Memory {…}` block, both in config.rs `validate_config` which dropped its `dht` param, AND removed from self_host's new `lower_host_site_reach_tls`). Sound and does NOT weaken security:
- M2 (construction.md:59/61) = "security-critical choice required or fail-safe-defaulted, never silently **unsafe**." The one failure M2 guards is **silent disclosure**.
- DECISIVE downstream fact I traced: `DhtMode::Memory`→`build_memory_did_method`→`InMemoryDhtClient` which "**never reaches the network**" (self_host.rs:1630 doc/:1637). `Production`→`PkarrDhtClient`→publishes. Memory has NO publish path.
- ∴ old rule errored on the SAFE direction. `NatTraversal+Memory` = legitimate more-private "reachable but address not in DHT, share out-of-band" config (the `SCP_NODE_DHT_MODE=memory` posture). It could not disclose.
- No config now silently discloses that previously errored: only `*+Production` discloses, unchanged, still explicit opt-in (defaults yield Memory). Removing the error adds ZERO disclosure surface.
- The fix removes an M2 VIOLATION: erroring on the fail-safe direction nudges callers toward `Production` to clear the error = "inferable into the unsafe value," exactly what M2 forbids.
- No enforcement file (scripts/, scp-testing/) referenced the removed rule → no CI gate broken, no CLAUDE.md enforcement-file bypass.

**Kept guards (correct):** TLS axis — `Domain+Plaintext`, `Acme` on non-`Domain` (config.rs); host-site — `Domain` reach rejected for self-host (no-domain node), `Acme`/`Terminated`/`Custom` TLS rejected (no DNS name / no terminator). DHT axis correctly never gates validity.

**Banner fix (accurate):** `self_host_banner(port,plaintext,publishes_dht)` — `publishes_dht=matches!(dht_mode,Production)` computed BEFORE banner. Under memory: IP-disclosure lines replaced with "DHT publishing is OFF … NOT DHT-discoverable." Fixes a REAL legibility defect (banner previously unconditionally claimed publication even under memory = false statement). New test asserts both negative + positive.

**Provenance:** ADR-052 (phase-2.md:55/64) + construction.md (:86/102) renamed `SiteConfig`→`HostSiteConfig` in SAME PR because `projection::SiteConfig` already FFI-exported (verified: server bridges + all 4 SDKs; 0 diff lines on projection.rs; `grep host_site crates/scp-ffi/ bindings/`=0). Legitimate compiler-level-constraint down-flow correction, documented in both artifacts — not phantom provenance.

**LESSON (fail-safe-direction M2 reviews):** when a PR REMOVES a validation error, don't assume "removed check = weakened." Trace the downstream behavior of the value the check rejected: if that value has NO unsafe path (here Memory→InMemoryDhtClient→never-network), the check was guarding the SAFE direction and erroring on it was itself the M2 violation (forces callers toward the unsafe value to clear the error). The test inversion (`*_is_invalid_config`→`*_is_valid`) is correct ONLY if the new tests assert a real downstream property (domain still lowers / NatTraversal builds no-domain node), not bare `Ok` — verify that, else it's a string-search game.
