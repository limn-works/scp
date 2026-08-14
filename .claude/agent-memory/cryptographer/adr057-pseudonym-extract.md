---
name: adr057-pseudonym-extract
description: ADR-057 T-1 §9.10.4 pseudonym-announcement logic extraction into wasm-safe scp-protocol::context::pseudonym — SOUND
metadata:
  type: project
---

# ADR-057 T-1 pseudonym extraction (branch refactor/adr057-pseudonym-extract)

VERDICT SOUND. §9.10.4 unlinkability/anti-hijack logic moved from scp-runtime `messaging_helpers.rs` (was `pub(crate)`) into wasm-safe `scp-protocol/src/context/pseudonym.rs` (now `pub`), shared verbatim native+browser.

**Why:** so native orchestrator + in-browser client driver share ONE copy of the pseudonym-announcement wire type + classifier, cannot drift on wire format or accept/reject decision.

**How to apply / key facts (all verified byte-identical):**
- `is_reserved_pseudonym` (pseudonym.rs:98) retains all 3 reserved values: `[0u8;32]` sentinel, `context_routing_id` (domain-sep SHA256), `broadcast_routing_id` (raw SHA256 = context_id_bytes). No value dropped.
- `pseudonym_collides_with_other_did` (pseudonym.rs:122): `other_pseudonym==pseudonym && other_did!=announcer_did` — rejects cross-DID, allows same-DID re-announce (key rotation). Only add = `#[allow(clippy::implicit_hasher)]` (concrete-hasher signature deliberate per agent-first tenet).
- `classify_pseudonym_announcement` (pseudonym.rs:215) preserves ORDER: tag-decode→NotAnnouncement; **sender==member FIRST** (announced_did only built AFTER match, never trusts claimed member_did before verify); reserved-reject (before registry); broadcast-None reject; cross-DID collision; Accept. claimed_did carried ONLY on REJECT_SENDER_MISMATCH.
- Native wrapper reads registry via immutable `peer_registry()` inside classify, re-borrows `peer_registry_mut()` in Accept to insert. Both accessors (actor/state.rs:667/679) have IDENTICAL match arms (None for Broadcast) → broadcast-None semantics preserved; single-threaded so Accept⇒Some invariant total (if-let safe). Metric + per-branch tracing::warn reproduced identically.
- Wire type: identical serde (`deny_unknown_fields`, `serde_bytes` on pseudonym, field order tag/member_did/pseudonym, tag `"\0scp:pseudonym-announce:v1"`). pub(crate)→pub has no wire effect.

**KAT** `crates/scp-client-wasm/tests/pseudonym_cross_target_kat.rs`: FIXED committed golden hex (`GOLDEN_PSEUDONYM_ANNOUNCEMENT_HEX`, 140B, decoded=fixmap3 tag-str8/member_did-str8-51/pseudonym-bin8-32×0x42, meaningful — reorder/tag/serde_bytes change breaks it), NOT runtime recompute. Same body from native `#[test]` + `#[wasm_bindgen_test]` vs same constants ⇒ native==golden ∧ wasm==golden ⇒ native==wasm. Pins all 6 classifier decisions + exact REJECT_* strings + claimed_did + reserved trio + honest negative. Spec-anchored §25.19/Vector 36 (table matches code). Ran native: 13 protocol unit tests + 1 KAT pass.

**Wasm fence:** module pulls only HashMap/scp_did::DID/serde/rmp_serde/pure-SHA256 routing helpers — no key material/OsRng/tokio/transport. scp-protocol already deps serde_bytes+rmp-serde, wasm-targeted. scp-client-wasm deps only scp-protocol+scp-did (MUST NOT touch scp-runtime — confirmed). No findings.
