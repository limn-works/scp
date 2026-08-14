---
name: adr049-9b-joiner-send-harness
description: ADR-049 §9(b) joiner-send closed at HARNESS level via REAL §9.16/§9.17 pull; production distribution honestly deferred to #2049/#2050/#2051 — COMPLETE+HONEST
metadata:
  type: project
---

Review of branch `chore/adr049-2f-residual` (tip 8acbd3cbb, base 2da67645d) — ADR-049 §9(b) bidirectional joiner-send. **COMPLETE + HONEST.**

**What it does:** closes §9(b) at the HARNESS level (Python + TS bidirectional tripwires now do REAL send→decrypt→assert-equal, replacing the old fail-closed `pytest.raises(...not found in node's handles)` tripwire). Production actor-loop key distribution is DEFERRED to real OPEN issues #2049 (§9.16 actor-loop pull), #2050 (§9.17 prod distribution), #2051 (spec↔ADR reconciliation) — all verified OPEN with matching titles.

**Why it's honest, not gamed:**
- Tripwires are genuine: real `fullstack_send_message`(bob)→`fullstack_decrypt_message`(alice), `assert bytes(decrypted)==plaintext` + ciphertext≠plaintext + len>. No xfail/skip/relaxed.
- Test comments (py+ts) honestly scope: "crypto+protocol compose over the harness's SIMULATED transport", explicitly cite #2049/#2050, say "not exercised here" for production. No overclaim.
- Harness pull is the REAL spec path, not a deposit/pickup shortcut: node.rs `pull_access_keys_from_creator` drives `request_access_key`→`handle_access_key_request`→`open_access_key_response` (real §9.17 wire fns); `incumbents_pull_joiner_sender_key` drives `request_sender_key`→provider `handle_sender_key_request`→`open_sender_key_response` (real §9.16.2). Fail-loud on missing key (no silent skip).
- Cross-layer symmetric: join_from_welcome now block_on(async)→returns ContextHandle stored in node handle map, IDENTICAL shape in both napi (testing.rs:223) and pyo3 (testing.rs:216) bridges. TestInstallAccessKey seam `#[cfg(feature="testing")]` — never in prod, never FFI-reachable (commands.rs, messaging.rs handler, Supervisor::test_install_access_key).
- `governance:propose` ceiling additions (5 sites, py+ts) are a LEGITIMATE protocol-requirement fix, NOT a relaxation: harness switched from `join_context` (direct add) to `Supervisor::invite_member` (SingleAdmin governance-gated auto-execute of AddMember proposal), which requires propose capability in ceiling. Adding a required capability is a tightening; masking would loosen an assertion. Load-bearing (every add_member ceiling got it).
- Membership-gate fix real: provider.rs `handle_sender_key_request` now reads membership from MLS group tree `members()`+DID-match (same as remove_member), NOT the stale empty `member_wrapping_keys` cache — this is the §9.16.6 Mitigation 1 fix that made joiner send actually work (joiner's cache is empty). wrapping_extension.rs changes are doc-only (still MemberNotFound for remote).
- Rust B→A tests present + non-vacuous: pre-existing `spawn_from_welcome_group_round_trips_both_directions`(706) + `invite_member_round_trip_stands_up_a_bidirectional_joiner`(2305) intact (untouched by harness commits); NEW `spawn_from_welcome_joiner_is_active_and_send_capable`(3091, direct Active-pin + behavioral send through require_active gate + wire-count≥1) + `spawn_from_welcome_application_data_round_trips_joiner_to_creator`(3230, full application-path B→A with documented non-vacuity). These pin the joiner→Active fix (supervisor.rs step 3a transition_to Active + rollback-on-fail).
- Enforcement change ADDITIVE only: check-deleted-primitives.sh promotes commented-out `pending_joins` ban to active (legacy join primitive deleted). Allowed modification type.

**Closes the memory-flagged critical finding:** "spawn_actor_from_welcome leaves joiner in Creating not Active → receive but not send" is FIXED here (step 3a) and pinned by Test N.

LESSON: honest deferral pattern to emulate — real crypto/protocol composed over a documented SIMULATED transport, production gap carved to real OPEN issues cited AT the deferral seam (the cfg(testing) doc-comment names #2049/#2050/#2051), tripwire tightened not relaxed, and a runtime test that FAILS if the fix reverts.
