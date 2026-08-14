---
name: adr049-2fb-9b-joiner-send
description: ADR-049 §9(b) joiner-send — H1 sender-key membership gate change (mls_group.members not member_wrapping_keys) + cfg(testing) TestInstallAccessKey actor seam. chore/adr049-2f-residual @8acbd3cbb.
metadata:
  type: project
---

# ADR-049 §9(b) joiner-send security review — chore/adr049-2f-residual @8acbd3cbb vs origin/main — 2026-07-06 — NO CRITICAL/HIGH; 1 MEDIUM(def-in-depth)+1 carried OBS

## Surface 1: §9.16 H1 sender-key membership gate (provider.rs handle_sender_key_request) — SAFE
Old gate: `member_wrapping_keys.contains_key(requester_did)`. New: DID-match loop over `state.mls_group.members()` (leaf BasicCredential→ScpCredential::from_bytes.did == request.requester_did).
- SAFE because member_wrapping_keys populated at ONE prod site add_member_from_bytes(provider.rs:1239) from added leaf KP => member_wrapping_keys ⊆ MLS-tree members. New gate = authoritative superset; every newly-admitted DID is a genuine MLS member. Old gate was UNDER-inclusive (rejected joiner whose cache is empty = the receive-only bug fixed).
- blocked_dids.contains still enforced AFTER membership loop (order preserved). members() Err→CryptoFailed (fail-closed). Response HPKE-sealed to fresh ephemeral request.wrapping_pubkey (pull §9.16.2) so no stable key needed. Encrypted-path only (reads state.mls_group); Broadcast is separate broadcast_helpers::handle_key_request. Correct per §9.16.6.
- Credential DID↔leaf binding enforced at add-time (same trust remove_member places in members()), not a regression.
- CARRIED OBS (pre-existing, unchanged shape old==new): sig verified vs caller-supplied requester_public_key while authz keys off request.requester_did. Method has NO prod caller today (test/harness only). When wired to inbound path, caller MUST resolve requester_public_key FROM requester_did or attacker sets requester_did=victim(passes membership)+signs/seals with own key => key theft. Flag at wiring time.
- scp-mls wrapping_extension.rs change (remote member→MemberNotFound) = doc-only/behavior-preserving.

## Surface 2: cfg(feature="testing") TestInstallAccessKey actor seam — AIRTIGHT at threat boundary; 1 MEDIUM
4 sites ALL #[cfg(feature="testing")]: enum variant commands.rs:389; dispatch arm messaging.rs:133; handler handle_test_install_access_key(has require_active) messaging.rs:255; Supervisor::test_install_access_key supervisor.rs:11939.
- ZERO FFI/SDK exposure: grep TestInstallAccessKey/test_install_access_key in scp-ffi/src/testing.rs, napi/src/testing.rs, scp-testing/src/, bindings/ = EMPTY. FFI testing.rs diffs are unrelated (spawn_from_welcome join seam).
- testing feature opt-in everywhere (not default). BUT leaks into allow_in_memory_custody builds: scp-ffi[allow_in_memory_custody]→dep:scp-testing→scp-core[testing]→scp-runtime/testing (scp-ffi Cargo.toml comment says testing "always enabled in deps"). So seam COMPILES into allow_in_memory_custody FFI builds.
- NOT exploitable: allow_in_memory_custody itself non-production ("Production builds must never enable"); and seam is pub Rust method w/ no FFI wrapper => only callable by code already holding Arc<Supervisor> = already has full key access. No boundary-crossing capability gain.
- MEDIUM (def-in-depth, matches project's OWN standard): gated on LEAKY `testing` not a dedicated feature. This is exactly the leak saga-witness-test-mint was created to avoid (scp-runtime Cargo.toml ~L26-33: testing-gated back-door "re-opening the forge" via the same chain; witness minter uses dedicated feature enabled only by test targets' required-features). RECOMMEND: gate all 4 sites behind dedicated non-leaking feature (e.g. access-key-test-install) enabled only by harness test targets' required-features, so it stays out of allow_in_memory_custody FFI artifacts. Not a blocker (no FFI wrapper today).

## Gotcha
Working tree was DETACHED at 1620de983 (main-ish), NOT the branch. Use `git show chore/adr049-2f-residual:<file>` for branch content; plain `grep -rn` reads the wrong tree.
