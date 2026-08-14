---
name: adr057-transport-pass2-4c8afb284
description: ADR-057 browser relay transport PASS-2 double-zero review @ 4c8afb284 — D1-D5 fix verification; one residual major (line-200 byte-parity contradiction survives D2)
metadata:
  type: project
---

# ADR-057 Transport (JsSocket + §9.10.4 pseudonym fan-out) PASS-2 @ `4c8afb284`

Branch `feat/adr057-transport-jssocket`, rebased on origin/main. PASS 2 of double-zero. Verified fix-commit doc amendments D1-D5 (meant to close PASS-1: 1 BLOCKER unrecorded T-2 deferral, 2 majors byte-parity self-contradiction + MLS-key provenance, 1 minor announce-mesh undocumented).

**Verdict: NEEDS DISCUSSION — one residual major; D1/D3/D4/D5/DOA all honest & confirmed.**

## The one finding (MAJOR — D2 fix incomplete)
`.docs/adrs/ADR-057-*.md:200` (T-1 Slice-3 amendment) still carries the UNSCOPED claim: "byte-parity by construction" + "The browser custody's byte-parity obligation (**identical pseudonyms native vs. browser**, once the seam exists) is validated by the §25.19 KAT." This is exactly the same-human native↔browser pseudonym equality that A1 (line 232) + Option-A Decision (line 224, D2-scoped) now say is FALSE pre-#1980 (browser keys on MLS key, native on identity key). D2 scoped lines 224/232 and added A1 but MISSED the parallel claim at line 200. The "once the seam exists" seam = the as-built MLS-keyed derivation seam wired in THIS slice → parity does NOT hold → real residual self-contradiction. Fix: scope line-200's parity claim to the post-#1980 identity-key seam / cross-ref A1. Not a BLOCKER (code matches corrected A1; internal doc inconsistency, not phantom provenance or artifact-flow violation).

## Confirmed honest
- **D1 (was BLOCKER):** BOTH ADR T-2 re-slice + PS-10 T-2 as-built amended; premise "nothing external blocks it" explicitly FALSIFIED (HPKE-open needs browser custody DH key absent pre-#1980); flow human-ruling→artifact. Code matches: `join_context_encrypted` consumes MLS Welcome (not InvitationBundle); NO `hpke_open_invitation`/`dhAgree` call site; `dhAgree` extern declared-but-unwired in `scp-client-wasm/src/custody.rs` (honest note). No phantom provenance.
- **D3:** PS-10 decision-record adds "T-1 Option A as-built key-source ruling (2026-07-17; human-ruled)" — human ACCEPTED MLS-keying, breaking same-human parity that PS-10/Option-A had ASSUMED. In decision record, not just ADR prose.
- **D4 (§9.10.4.4 spec 09:990+):** 3 residuals accurate & not understated — (1) subscriber-cardinality correlator (1 subscriber per pseudonym RID vs N for shared RID; distinct from blob-match, NOT closed by per-recipient re-encryption), (2) cross-context linkage via single connection (contradicts "unlinkable across contexts"), (3) ships without partitioning/cover traffic.
- **D5 announce mesh:** ADR §"Announce-mesh as-built" matches code — no-announce-at-create (`create_context` installs routing only), joiner seed-announce (`join_context_encrypted`→`announce_pseudonym`), reciprocal-announce guarded first-time-per-peer (`learned_new_peer = !peer_pseudonyms.contains_key`), self-echo drop (openmls `CannotDecryptOwnMessage`→typed `MlsError::CannotDecryptOwnMessage`→benign drop at shared scp-mls layer). Native-parity follow-up recorded honestly (line 216): native `ingest_pseudonym_announcement` VERIFIED to stop at "record+emit" (no reciprocal), native inherits shared self-echo fix.
- **DOA:** MLS-keyed pseudonym + reciprocal-announce bake in NO painful #1980 lock-in — pseudonyms are announced/never-recomputed (device-local model), so #1980 key-source move just triggers re-announce; acknowledged in A1.

`#1980` in one rustdoc (scp-mls group.rs derive_pseudonym) is NOT a finding — 575 issue-refs already in src, convention-consistent.
