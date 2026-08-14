---
name: adr057-dissolve-primitives-head-c1ef1394d
description: ADR-057 Amendment (dissolve scp-primitives; extract scp-did) + T1 canonicality port final review at c1ef1394d — ALIGNED, 0 findings
metadata:
  type: project
---

# ADR-057 Amendment "Dissolve scp-primitives; extract scp-did" — final review @ c1ef1394d (2026-07-03) — ALIGNED, 0 findings

Branch `refactor/dissolve-primitives-split-identity`, range `86519aa6f..c1ef1394d` (11 commits, 371 files). Supersedes 3 prior reviews. Both prior findings RESOLVED:
- **Release-pipeline break** (flagged @81ef76c56: scp-client-wasm `publish=false` in release.yml) — FIXED by 5b35cb9aa. All 3 lists (Publish steps 363-486, TAGS 168-183, dry-run summary 863) now = EXACTLY the 16 publishable crates; scp-client-wasm fully absent (grep=NONE). 16 = 19 crate dirs − 3 publish=false (scp-client-wasm, scp-ffi, scp-testing). Verified set-equal.
- **Dead scp-protocol dep in scp-identity** (flagged @033a12d4c) — resolved: no scp-protocol in manifest, 0 `scp_protocol` uses in src.

**Deliberate behavior change (the one on this branch): z-base-32 canonicality port into `scp_did::extract_public_key_from_did`** (c1ef1394d, scp-did/src/lib.rs:141-147). VERIFIED SOUND:
- Byte-exact re-encode-and-compare (`zbase32::encode(&bytes) != suffix` → Err), mirrors native `scp_identity::dht::extract_public_key` (dht.rs:2751-2756) verbatim. Both crates share the SINGLE workspace `z-base-32` dep (lock=0.1.4) → "reject identical inputs" holds by construction, not by coincidence.
- Rationale sound: z-base-32 over 32B not injective on trailing padding (52nd char = 1 payload + 4 pad bits → 16 alternates decode to same key); browser/wasm sig-verify path (scp-event-log tree.rs, scp-protocol bridge/claiming.rs) reaches ONLY the scp-did parser.
- Tests RAN GREEN + mutation-resistant: scp-did `extract_public_key_rejects_non_canonical_zbase32_padding` (asserts accept-canonical AND reject-mutated, runtime-verifies mutated input genuinely decodes to same key via `^1` LSB/padding-bit toggle); scp-identity `native_and_scp_did_parsers_agree_on_canonicality` (feeds same fixture to both, both reject).
- ADR framing correct: T1c bullet (line 86) + T1 bullet (85) + rejected-alt 5 all say canonicality LANDS IN T1, T1c = consolidation only ("never adopt the weaker one"). Internally consistent.

**Full-document + artifact fidelity all CLEAN:**
- Anchors resolve: heading `## Amendment (2026-06-30): Dissolve scp-primitives; extract scp-did` (line 95) → slug `amendment-2026-06-30-dissolve-scp-primitives-extract-scp-did`; both refs (line 3, 41) match; no stale `split-scp-identity` slug repo-wide.
- Crate table accurate: scp-did = pure leaf (Cargo.toml deps all external: ed25519-dalek + serde/json/bytes/hex/base64/bs58/z-base-32/thiserror; NO scp-* dep). ClockError now annotated `(crate-internal)` (line 107) — my prior informational nit CLOSED.
- MLS citation (line 14) past-tensed accurately: "since lifted to crates/scp-mls/src/ — Slice 1"; dir exists.
- Gates PASS: check-no-shim-reexports.sh (exit 0), check-protocol-deps.sh (exit 0). Comment-filter change (280983dd7/5b35cb9aa/c1ef1394d) is SOUND not a weakening: skips only lines whose trimmed content starts with `//` AND lacks `*/` — a `//`-line is live code only if a block comment closes with `*/` on it (guard excludes those from skipping), so true-positive coverage preserved. Positive closed set {scp_clock,scp_crypto,scp_did,scp_mls}, scp-core facade exempt.
- READMEs (scp-clock/crypto/did) mention scp-primitives only as provenance narration ("extracted from the dissolved junk-drawer"); scp-primitives dir gone; no stale live refs.
- ADR-055 (phase-4.md:1468, "Remove the WASM Bridge") untouched + consistent: still 3 FFI bridges, scp-ffi/wasm still gone; scp-client-wasm (ADR-057 wasm-bindgen surface) is not an FFI bridge — no contradiction.

Verdict ALIGNED, 0 findings. This is the double-zero-clean HEAD; ready for PR.
