---
name: relay-did-record-cleanroom-design
description: Clean-room minimal design for relay-based DID resolution — why the "reuse dumb blob store" spec approach is broken and single-slot is the minimal-correct fix
metadata:
  type: project
---

Clean-room (first-principles/minimal) design of SCP relay-based DID resolution (#482, ADR-062 area), done independent of the prior attempt.

CORE CONCLUSION: spec §3.10.2's "reuse opaque blob store, QUERY {limit:1}" is NOT minimal-correct — it is broken two ways, so a single-highest-seq slot on the relay is the *simplest* design that is actually correct, not gold-plating.

**Why the dumb-store approach fails (both derivable from code):**
- `storage.rs` `query` sorts oldest-first then truncates to `limit` ⇒ `QUERY {limit:1}` returns the OLDEST doc, not newest. Once a 2nd version exists, honest resolvers get stale. Freshness broken even without an attacker.
- Store accumulates unbounded distinct content-addressed blobs per routing_id; anyone can PUBLISH (per-IP rate limit only) ⇒ flood junk to evict genuine record from any bounded window, or hit global StorageFull. Suppression handed to attacker.

**Why single-slot is minimal, not a tenet violation:** the "dumb pipe" tenet protects ENCRYPTED content confidentiality + no-trust-anchor. A DID doc is public + self-certifying; relay learns nothing new (can already derive routing_id). Precedent: relay ALREADY does DID↔key verification in `BridgeRegister`/SCP-247 (`protocol.rs`): checks `SHA-256("scp:did:"||did)==routing_id` + Ed25519 sig. Single-slot relay verify = spam/availability filter, NOT trust; client still re-verifies every QUERY result.

**Design shape:**
- `DidRecordV1` frame in scp-protocol (pure/wasm): magic+public_key+seq(BE)+value_len(BE)+value(VERBATIM JSON)+sig. Sig over SAME `bep44_signable(value,seq)` bytes as DHT ⇒ one sig serves both layers, byte-identical. value carried verbatim, never re-serialized (byte-exact determinism across bindings).
- Relay single-slot store: on PUBLISH_DID verify frame→routing_id binding→sig→`seq>stored.seq` (equal=idempotent TTL refresh, lower=reject). One slot per routing_id, writable only by key holder ⇒ nothing to flood.
- Verify in BOTH: client=authoritative trust root (sig vs DID-key + durable seq floor per #1855); relay=advisory spam filter.
- Wire: dedicated PUBLISH_DID/QUERY_DID ops (do NOT overload `send(&OuterEnvelope)` — category mismatch, same trap as KeyPackages misusing encrypted_blob). Resolver composes MultiRelayQuerier ∥ DhtClient::resolve, highest verified seq wins, DHT arm unchanged (§3.10.6).

**RATIFIED + SPECCED 2026-08-02 (Model B, #482).** The owner ratified "Model B" and it is now written into spec (branch `feat/relay-resolution-modelb`, worktree pass): §3.10.2/§3.10.4/§3.10.5/§3.10.8 (03-identity), §9.10.12 (09-security-model, retitled "Relay DID-Record Frame"), §10.12.4 carve-out (10-infra), tenet clarification in white-paper #4 / technical-overview / CLAUDE.md ("untrusted, not content-blind"). Model A (opaque-blob + "no special relay behavior" + SCPR multi-kind magic taxonomy) is DELETED. Corrections to my earlier sketch above, now authoritative:
- **Existing PUBLISH/QUERY verbatim** — NOT dedicated PUBLISH_DID/QUERY_DID ops. Frame is a raw blob at the DID routing_id; wire ops unchanged; QUERY limit:1 works because a validating relay keeps one slot.
- **Frame `DidRecordV1` = version:u8=1 ‖ public_key:[u8;32] ‖ seq:u64(BE) ‖ signature:[u8;64] ‖ value:bytes(trailing remainder).** NO magic tag, NO kind byte (address = type discriminant; KeyPackages #2202 get their own frame at their own routing_id, no shared taxonomy), NO value_len prefix (value = frame[105..]; fixed prefix 105B). Sig covers bencode(seq,value) only.
- **public_key IS carried** (for the RELAY's verify — it holds only one-way routing_id; mirrors BRIDGE_REGISTER). Client IGNORES frame key, verifies with DID-derived key. (My earlier "omit k" was wrong for Model B.)
- **Relay-side validation is the load-bearing addition** (OPTIONAL capability of SCP-native relays): verify sig + SHA-256("scp:did:"||did(pubkey))==routing_id binding + single highest-seq slot. Binding is the discriminant (no new wire type needed). Foreign transports store opaque; correctness via client-verify+DHT+multi-relay.
- **ADR-062 scope split:** relay resolution (querier/publisher/frame/validation + republish sig/seq-drop fix) = feature #482, OUT of ADR-062. ADR-062 Slice 11 keeps ONLY severing `RepublishManager<R=InMemoryRelayPublisher>` default + demote to test-cfg. NoOpRelayQuerier ships honestly unchanged. Consequence: co-located self-DID governance regression window widens to "until #482" (was "until ADR-062 Slice 11").

**Post-review refinements (5-reviewer pass, direction sound):**
- **Slot-exclusivity (HIGH fix):** frame-shape validation alone is insufficient — the base relay stores MULTIPLE opaque blobs/routing_id (ADR-004, no cap), so non-frame junk or PRE-SEEDED junk (published before victim's first DID publish, when relay can't recognize routing_id as DID-domain since SHA-256 is one-way) would sit alongside the slot and be QUERY-returnable. Fix: once a binding-valid frame first ESTABLISHES a slot, the routing_id becomes slot-exclusive — (a) reject any later non-binding-valid/non-seq-advancing PUBLISH, (b) EVICT pre-existing opaque blobs on first establish, (c) QUERY returns only the slot. **Requires a companion ADR-004 update (relay storage: DID-domain routing_ids slot-exclusive once claimed), tracked under #482 — NOT yet written.** Spec §3.10.2/§9.10.12/§3.10.8 are authoritative for the behavior.
- **QUERY limit reverted 1→N (N=16):** limit:N dominates limit:1 (free vs validating relay=1 slot; preserves intra-relay shadow-defeat + gives DhtMode::Disabled node a chance vs non-validating relay). Client sifts up to N to highest-seq-VALID.
- **Validation step order = cheapest-first:** decode → binding-hash-check → Ed25519 sig verify → single-slot. Binding (plain hash) before sig so mis-addressed/non-frame blobs never cost a verify. Whole path behind existing per-IP PUBLISH rate limit.
- **#2226 RealMultiRelayQuerier (relay_querier.rs, MAX_CANDIDATES_PER_RELAY=16, Vec/shadow-defeat) already MERGED on main.** Model B RETAINS its client-side multi-candidate collection as the non-validating-relay sift; #482 COMPLETES+CORRECTS it (first-valid→highest-seq; adds TransportRelayQuerier, frame, relay validation+slot-exclusivity, real RelayPublisher, republish fix). #482 builds ON #2226, does not delete it.
- **Frame "alternative rejected" rationale corrected:** the "omit k" argument is void (frame carries public_key); the true reason is determinism — fixed-layout binary is byte-reproducible across all bindings (incl. wasm scp-protocol) WITHOUT importing a bencode CONTAINER codec; bencode appears only as the hand-rolled BEP44 signed-buffer snippet, never a general serialization.

Relates to [[adr062-relay-public-record-framing.md]] (which flagged relay public-record framing as NET-NEW), [[relay-did-suppression-resistance.md]] (the impossibility result Model B answers), and [[relay-resolution-late-binding.md]].
