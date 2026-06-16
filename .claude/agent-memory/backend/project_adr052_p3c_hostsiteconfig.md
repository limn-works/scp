---
name: project-adr052-p3c-hostsiteconfig
description: ADR-052 Phase B-P3c — fold HostSiteOptions into HostSiteConfig (name avoids projection::SiteConfig FFI collision), promote DhtMode to shared config; collision resolution + reshape map
metadata:
  type: project
---

ADR-052 Phase B-P3c reshapes the host_site config to the construction-pattern flat-config shape.

**Name collision (critical).** The construction standard (`.docs/standards/construction.md` §host_site, ~L179-194) and ADR-052 (`.docs/adrs/phase-2.md` items 5 + Dependencies, L1581/1590) named the new host config `SiteConfig`. But `pub struct SiteConfig` ALREADY exists at `crates/scp-node/src/projection.rs:~165` — FFI-exported (virtual-host deploy limits: hostname/index_path/max_assets_per_deploy/max_deploy_size_bytes/deploy_retention_count/csp_override). Renaming projection::SiteConfig is a bridge-parity hazard (sdk-capability-matrix.json/bridge exports) — forbidden. **Resolution: new type is `HostSiteConfig`.** Amended standard + ADR-052 to `HostSiteConfig` with a one-line note that bare `SiteConfig` was taken (compiler-level constraint = valid artifact-flow deviation).

**Reshape (`crates/scp-node/src/self_host.rs`):** `HostSiteOptions` → `pub struct HostSiteConfig { reach: Reach, tls: TlsMode, dht: DhtMode, site_dir, port, storage_path, dht_gateways, projection_rate_limit, refresh_interval, on_ready }`.
- `plaintext: bool` → `tls: TlsMode` (SAME enum as NodeConfig.tls): true⇒Plaintext, false⇒SelfSigned.
- `skip_nat: bool` → `reach: Reach`: true⇒Reach::Local, false⇒Reach::NatTraversal.
- dht_mode bool-derived behavior → explicit `dht: DhtMode`, subject to SAME M2 rule as Node (publishing reach + DhtMode::Memory ⇒ loud error). Added `HostSiteError::InvalidConfig(String)` variant.
- M4: reach required → NO whole-struct Default; provide `HostSiteConfig::defaults(reach)` factory.
- Internal plumbing (`ServeHostedSite`, `build_self_host_tls_config(plaintext)`, `build_host_site_node(skip_nat)`) stays on private booleans — derived from tls/reach at top of `host_site_until`. The bools are impl details, not public surface.

**DhtMode promotion:** moved from self_host.rs into `crates/scp-node/src/config.rs` (beside Reach/TlsMode); re-exported from crate root so Node + Site share ONE DhtMode. lib.rs `pub use self_host::{...DhtMode...}` → `pub use config::DhtMode`.

**Sugar tier:** NO pre-existing `host_site(dir)` one-liner existed — only `host_site(opts)` + `host_site_until(opts, shutdown)`. Per standard L194, `host_site(HostSiteConfig)` IS the sugar tier over Node::start. Did NOT invent a parallel `host_site(dir)` path (forbidden).

**No FFI/enforcement touch:** `host_site` is NOT FFI-exported (verified: 0 hits `grep -rn host_site crates/scp-ffi/ bindings/`). Reshape needs no capability-matrix/bridge-aliases/pipeline change. projection::SiteConfig untouched.

**Consumers of HostSiteOptions (all renamed):** self_host.rs (def), lib.rs (re-export), main.rs (binary: builds config from env plaintext/skip_nat/dht_mode bools — keeps own bools for banner display, maps to enums for config), examples/website.rs, tests/host_site.rs. `HostSiteReady.plaintext: bool` is a REPORT field (output), not config — stays bool (M1 governs config inputs).

Branch `feat/p3c-site-config` off main @138c85baa (P3a ApplicationNodeBuilder deleted). See [[project-actor-phase2a-step-b]] for actor context, [[feedback-worktree-absolute-path]].
