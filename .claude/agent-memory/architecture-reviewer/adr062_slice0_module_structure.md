---
name: adr062-slice0-module-structure
description: ADR-062 Slice 0 (PR #2138) review — scp-platform in_memory/ (durability-only) vs testing/ (nullifier) module split; APPROVED w/ LOW spec-drift
metadata:
  type: project
---

# ADR-062 Slice 0 module structure (PR #2138, branch feat/adr062-slice0-module-structure)

Core commit 76796c890 (91 files), tip 026420ed5 (doc-only CAPSEL-token fix). ADR-062 §Decision 0 / PRD SCP-CAPINJECT-000.

**What it does:** Split `scp-platform`'s `pub mod testing` by truth: `InMemoryStorage`/`InMemoryPush` moved to `src/in_memory/` behind NEW durability-only features `in-memory-storage`/`in-memory-push` (latter pulls dep:uuid). Nullifier doubles (`InMemoryKeyCustody`/`InMemoryDeviceAttestation`/`InMemoryPreRotationCustody`) stay in `testing/` behind `testing`. Deleted `pub use testing as software` + bridge-local `BridgeInMemoryStorage` (~120-line hand-rolled Storage impl). F1 storage-half: `server` feature edge `scp-platform/testing`→`scp-platform/in-memory-storage`.

**VERDICT: architecturally sound + mergeable.** All 4 axes sound. Verified by build:
- Headline property HOLDS: `cargo check -p scp-platform --no-default-features --features in-memory-storage,in-memory-push` compiles clean (0 err) — durable in-memory adapter ships WITHOUT compiling InMemoryKeyCustody. The whole point.
- uniffi DEFAULT build (no allow_in_memory_custody) compiles clean. My initial hypothesis (server.rs:23 `use scp_platform::testing::InMemoryKeyCustody` breaks when server feature dropped the testing edge) was WRONG — `scp-platform/testing` stays reachable via **scp-identity + scp-node normal deps** (cargo tree confirmed), which is exactly what Slices 1 (DHT)/6 (custody) + G1 target. Slice 0 removed only the STORAGE reason for server→testing; clean incremental seam, nothing foreclosed.

**Coder's 3 decisions all sound (not scar tissue):**
- (a) `testing = [software_platform, in-memory-storage, in-memory-push]`: one-way implication, does NOT re-couple (in-memory-storage alone does NOT pull testing — verified). Doesn't undermine G1 (testing still in resolved set, still not allowlisted). Avoids churning ~90 consumer Cargo.tomls. Documented in Cargo.toml comment. Aligns w/ ADR G1 soundness invariant (testing transitively pulls test-harness features).
- (b) alias rename `BridgeInMemoryStorageHandle`→`EventLogInMemoryStorageHandle`: proportionate — "Bridge" prefix named the deleted type; "EventLog" reflects actual purpose. Tracks real semantic change, not churn.
- (c) `in-memory-storage` in common/Cargo.toml base scp-platform dep: acceptable — durability-only/allowlisted; needed because resolvers-gated bridge_runtime references the type. MINOR: could attach to `resolvers` feature edge for tighter precision (custody-only build now compiles it unnecessarily), but consistent w/ existing encrypting/sqlite bundling.

**BridgeInMemoryStorage deletion = net simplification** (~120 lines removed). Existed only to avoid pulling scp-platform/testing for event-log persistence; now the durability-only InMemoryStorage serves directly via `EncryptingAdapter<scp_platform::in_memory::InMemoryStorage>`. Split's payoff realized. No new gate in Slice 0 (G1 is Slice 6) — simplifier lens clean.

**LOW findings (doc-drift, not blockers):**
- `.docs/specs/17-persistence-and-storage.md:432` still names deleted `BridgeInMemoryStorage`. Branch ALREADY edits spec 17 (added §17.17, +95 lines) → in-file miss. Fix: drop "the FFI-layer `BridgeInMemoryStorage`" from the sentence.
- 2 stale `.claude/agent-memory/backend/*.md` notes reference BridgeInMemoryStorage (housekeeping).
