---
name: adr057-prereq1-keypackage-lifetime-clock
description: ADR-057 Prereq-1 (#1965) — MLS KeyPackage/leaf Lifetime minting+validation routed through injected scp_clock::Clock; soundness + 2 LOW findings
metadata:
  type: project
---

# ADR-057 Prereq-1: KeyPackage Lifetime clock routing (branch fix/1965-lifetime-clock, base 3d8bc2cc0)

**Why:** openmls 0.8.1 mints/validates `Lifetime` from its OWN internal clock (`SystemTime::now()` native; under `js` feature = `fluvio_wasm_timer` live un-captured `Date.now()` — a 2nd, attacker-overridable clock in-browser). Prereq-1 routes SCP's Lifetime use through the injected hardened Clock. Seam = `Lifetime::init(nb, na)` (pure constructor, bypasses internal now()); openmls exposes no clock-injection seam.

**Construction (crates/scp-mls/src/lifetime.rs) — SOUND, verified vs openmls-0.8.1/src/key_packages/lifetime.rs:**
- Constants mirror openmls private ones EXACTLY: SECS=7_257_600 (3*28d), MARGIN=3_600 (1h), MAX_RANGE=7_261_200 (MARGIN+SECS). `key_package_lifetime` = init(now-margin, now+SECS) saturating (openmls `Lifetime::new` shape but SAFER — openmls `now-margin` underflow-panics at T=0).
- `validate_key_package_lifetime`: temporal `nb<now && now<na` (identical to openmls is_valid strict `<`) AND range `na.sat_sub(nb)<=MAX_RANGE` (identical to openmls `has_acceptable_range`, which openmls DEFINES but never calls in KeyPackageIn::validate). Pure logical AND, no ordering dependence.
- Effective acceptance = INTERSECTION of openmls internal is_valid (still runs) + SCP check → SCP surface is strict SUBSET, never wider. No wrap/overflow mints always-valid/never-valid window; minted range always <= MAX_RANGE.

**Bracketing (accept sites, all call validate_key_package_lifetime):** add_member (group.rs:476), key_package_in_did (group.rs:559), both staged-commit Add loops (encrypt.rs:386/706, fail-closed: validate BEFORE merge_staged_commit, `?` drops StagedCommit unmerged → epoch/tree untouched), ProductionMlsBackend::validate_key_package (production_backend.rs:470), add_member_raw + MlsCryptoProvider::add_member (delegate to group::add_member), scp-client add (client.rs:415/406). Generation: exactly 2 routed sites — create_group `.lifetime()` (group.rs:370), generate_key_package `.key_package_lifetime()` (group.rs:780). No other KeyPackage::builder/MlsGroupCreateConfig non-test. No external-commit accept surface.

**LOW-1 (non-exploitable):** `MlsCryptoProvider::validate_key_package` (provider.rs:1019) is the ONE accept-family method NOT bracketed (missing max-range + hardened re-check). Reachable prod via join_context (lifecycle_helpers.rs:727). NOT exploitable: still runs openmls is_valid; authoritative admission join_context→add_member (provider.rs:1149) IS bracketed; provider.rs native-only (tokio, no wasm clock). Fix = add bracket for parity (self.clock available at :1147).

**LOW-2 (doc accuracy):** V3 Welcome tree-leaf residual (StagedWelcome::new_from_welcome, group.rs:862) is GENUINELY unbracketable — VERIFIED: RatchetTree has NO pub leaf accessor (only pub(crate) try_from_nodes); TreeSync::full_leaves is pub but treesync() is private; struct Member exposes credential not LeafNode; only own_leaf_node() reachable (= joiner's own self-minted leaf). BUT docs (lifetime.rs:46, time.rs:46, ADR-057) justify with "LeafNode::life_time / leaf_node_source are pub(crate)" — WRONG: life_time() is pub(crate) (correct) but leaf_node_source() is PUB (leaf_node.rs:437) + LeafNodeSource::KeyPackage(Lifetime) is pub variant. Real reason = no pub tree-leaf enumeration. Fix the parenthetical so nobody "corrects" it and thinks V3 is closeable.

**Browser (wasm) fully bracketed** gen+accept; WasmClock (scp-client-wasm/src/time.rs) = captured `Date.now` bound at module init (survives post-init override), native fallback SystemTime. PCS claim "hardened clock governs acceptance; unhardened can only false-REJECT at bracketed sites" is TRUE from code (AND-composition). At unbracketed V3 site unhardened CAN false-accept = disclosed residual; CSP/SRI/COOP/COEP load-bearing there.
