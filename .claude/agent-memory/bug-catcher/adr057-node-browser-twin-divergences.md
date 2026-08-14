---
name: adr057-node-browser-twin-divergences
description: ADR-057 node-vs-browser twin audit (origin/main d1ebc5ab9) — browser omits 0xFF02 context-params, InnerEnvelope, and the whole §9.8.1/§9.17 verify layer; no native↔browser interop test exists anywhere.
metadata:
  type: project
---

# ADR-057 NODE vs BROWSER twin audit — origin/main `d1ebc5ab9` (2026-08-08)

**Root enabler:** there is **zero** native↔browser interop test in the repo.
`git grep -rln "scp_client\|scp-client" origin/main -- 'crates/scp-testing' 'crates/scp-runtime'`
returns only three doc-comment hits. `crates/scp-client-wasm/tests/cross_target_determinism_kat.rs`
pins cross-**TARGET** byte determinism of *shared primitives*, NOT a node-runtime ↔ browser-driver
exchange. Every divergence below survives because both sides pass their own tests.

## Confirmed divergences (see the review output for full evidence)

1. **`0xFF02 scp_context_params` absent browser-side.** Node births via
   `group::create_group_with_context` (`crates/scp-runtime/src/crypto/mls/provider.rs:689-706`,
   "the production CREATE birth seam") and mints joiner KPs via
   `generate_key_package_with_context_params` (node + all 3 FFI bridges). Browser uses the
   pre-fix twins `create_group_with_wrapping_key` (`crates/scp-client/src/client.rs:426`) and
   `generate_key_package_with_wrapping_key` (`:497`). `crates/scp-mls/src/group.rs:1102-1109`
   states outright that a `_with_wrapping_key` KP "**cannot be added to a context group**"
   (openmls `valn0502`). ⇒ browser can never join a node context; browser contexts don't bind
   §5.13.3 params into the MLS key schedule.
2. **Browser has NO `InnerEnvelope` / access-key layer.**
   `git grep -n "InnerEnvelope\|access_key\|wrap_content\|payload_hash\|verify_inner_signature\|MessageType" origin/main -- 'crates/scp-client' 'crates/scp-client-wasm'`
   → EMPTY. Node: `build_inner_wire` (`messaging_helpers.rs:126-199`) + `verify_and_unwrap`
   (`:435-495`) + cross-injection/credential-spoof checks (`:1504-1518`). Browser seals raw
   plaintext at §9.16 (`crates/scp-client/src/crypto_state.rs:687-704`).
3. **Browser `add_member` has no governance/capability gate.** Node routes through
   `Supervisor::invite_member` → `propose_governance_action_checked_carrying_key_package`
   (`crates/scp-runtime/src/context/supervisor/supervisor.rs:13030+`).
4. **`OuterEnvelope` parse.** Browser uses the hardened `OuterEnvelope::from_bytes`
   (`client.rs:1165`; MAX_ENVELOPE_SIZE pre-check + §13.5 version compat); node uses bare
   `rmp_serde::from_slice` (`crates/scp-runtime/src/context/actor/state.rs:1889`) — the ONLY
   production native inbound parse.
5. **`handle_relay_frame` fail-closed arm gap** (`client.rs:1165-1211`): the
   `OuterEnvelope::from_bytes` `?` sits ABOVE the benign-drop categorizing match, so relay-injected
   non-MessagePack junk on a known routing id THROWS while junk inside a valid envelope is
   benign-dropped. Same attacker capability, opposite outcome.

## Checked and CLEAN (do not re-derive)

- **HPKE sender-key context binding is NOT divergent for canonical ids.** Native binds
  `hex::encode(context_id_digest)`, browser binds the raw `context_id` string — but per ADR-056
  a canonical context id IS 64-lowercase-hex, and `context_id_to_bytes`
  (`crates/scp-runtime/src/context/state.rs:2254`) decodes rather than re-hashes it, so the two
  are byte-equal. Diverges only for non-canonical labels (`ctx-…`, `standing-…`). I nearly
  filed this as a bug — commit `598a56c37`'s message says "HPKE §9.16.2 info path unchanged",
  which reads like a missed twin but is not one.
- `classify_pseudonym_announcement` S1 own-pseudonym guard: present on BOTH
  (`messaging_helpers.rs:608-627` / `client.rs:1975-1980`), emit-on-change on both.
- `INITIAL_SENDER_KEY_EPOCH = 1` on both (browser `crypto_state.rs:123`; native
  `crates/scp-runtime/src/crypto/mls/provider.rs:377`).
- Sender-DID binding before install: both (browser `crypto_state.rs:582`; native
  `provider.rs:930`). MAX_EPOCH_ADVANCE ceiling: both (browser `crypto_state.rs:594`; native via
  `Supervisor::check_and_advance_sender_epoch`).
- Browser snapshot restore is well-guarded (owner-DID binding, storage-key↔embedded-id match,
  §9.9.3 checkpoint recompute, atomic staged install) — `crates/scp-client/src/snapshot.rs:415+`,
  `client.rs:1817-1920`.
- `scp_mls::keypackage_attestation::verify_attestation*` (CRYPTO-22 `0xFF03`) has NO production
  call site on EITHER side; `crates/scp-runtime/src/crypto/mls/attestation_verification.rs`
  documents itself as "NOT yet wired … gated on SCP-CRYPTO22-005". Not a twin divergence yet.
- `EpochGraceStore` has no consumer outside `crates/scp-mls/src/ratchet.rs` + tests on either side.

## Designed absences (cite, don't report)

- No browser Cancel signing predicate for outlet streaming — ADR-057 / SCP-OUT-048 Option A.
- Browser excludes governance / economy / saga coordination / media / DHT / broadcast hosting —
  ADR-057 §Scope fence.
- Browser cannot mint its own KeyPackage attestation — ADR-057 Amendment (2026-08-01),
  §Relationship to component 3, gated on #1980.
- Browser identity key not in wasm (MLS-key-derived pseudonym) — ADR-057 Amendment
  (2026-07-16 — Option A) §A1 as-built.
- Native lacks reciprocal-announce — ADR-057 §Announce-mesh as-built, tracked #2179.
- Node deliberately admits wrapping-key-less members (§9.16.1 publication unwired) — see
  `production_key_package_without_wrapping_key_joins_context_group` in
  `crates/scp-runtime/src/crypto/mls/production_backend.rs:1259`.
