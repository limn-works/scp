---
name: pr2234-rotate-content-keys-followup
description: PR #2234 fix/rotate-content-keys-review-followup — KEA best-effort convergence finding + sort/counter/validate_kp all clean
metadata:
  type: project
---

# PR #2234 (fast-follow to #2218/#1847) @39a19e90c

Base #2218 (19681f4b1) NOT in local main; reviewable surface = #2218 + #2217 + fast-follow (39a19e90c). Fast-follow itself is tiny: sort in broadcast/mod.rs + reconfigure counter split (9 lines) + TODO(spec) comments + tests.

## HEADLINE FINDING (MEDIUM) — KeyEpochAdvance best-effort violates §9.9.3 convergent-log MUST
- governance_helpers.rs execute_revoke:~987 and execute_rotate_content_keys:3205 emit KeyEpochAdvance leaves BEST-EFFORT (warn-and-continue). KEA is a CONVERGENT EventType (ADR-011 taxonomy). §9.9.3 convergent-log requirement: every honest member MUST derive the same leaves. Each member runs execute_* on its own local event_log (per-member logs). A per-member append failure (transient backend, byzantine backend per eventtype-audit-1847, disk) => that member's log missing a convergent leaf => equal-count-different-root FALSE-POSITIVE equivocation + checkpoint-position drift. Attacker who can induce append failures on some members = self-inflicted §9.9.3 divergence weaponizable into equivocation-governance (tier b) against honest members/relays.
- SMOKING GUN: SAME PR treats the equally-convergent GovernanceDeadlockRecovery leaf (reconfigure:3381) FAIL-CLOSED (.await?) "to surface failure", but KEA best-effort. Inconsistent durability discipline for two convergent leaves.
- Author already flagged: `TODO(spec): §2033 vs §5.14.10/ADR-011 tension unresolved — convergent trigger may require fail-closed here`. This finding = characterizing that TODO.
- Deeper: canonical log has NON-ATOMIC multi-leaf appends w/ no rollback; ContentKeysRotated+rotation already durable before KEA loop, so fail-closed can't roll back either — it only surfaces. True fix needs atomic multi-leaf or spec exclusion.

## CLEAN / RESISTANT
- Sort fix (broadcast/mod.rs:1651 + 1720): sort_unstable_by(author_did.cmp). author_did are UNIQUE HashMap keys => no equal elements => sort_unstable fully deterministic. String::cmp = bytewise UTF-8, cross-platform total order, no locale/float. NO DID-collision/crafting attack (byte-equal DIDs = same HashMap entry). RESISTANT.
- Pre-fix asymmetry WAS exploitable: once #2218 emitted KEA in HashMap-iteration order, two honest members appended same N leaves in DIFFERENT per-process RandomState order => different root at equal count => §9.9.3 false-positive. Sort closes the ORDERING vector (necessary, correct) but NOT the presence/count vector (best-effort, above).
- Counter split (reconfigure:3354 + 3391): each fail-closed leaf gets own paired +=1; encode/append err returns Err after 1st durable leaf already counted => no under/over-count. execute_revoke/rotate counter `+= 1 + kea_success_count`: the `1` only reached if AccessRevoked/ContentKeysRotated `.await?` succeeded; kea_success_count only ++ on Ok append => local counter == local durable-leaf count. SOUND (no drift WITHIN a node; cross-node divergence is the leaf-presence issue not the counter).
- validate_key_package migration (execute_add_member:1278, deps.mls stateless): identity binding PRESERVED — extracts credential_did from validated leaf, rejects `credential_did != owner_did` at :1284. Lifetime checked via hardened deps.clock (same clock as add). Bytes immutable between validate + add_member closure => no TOCTOU. SOUND.
- no_pre_rotation_backend gate (uniffi/napi/py bridges, IDENT_1059/1056): in-memory custody fallback entirely behind `#[cfg(feature="testing")]`; `#[cfg(not(feature="testing"))]` early-returns coded error. COMPILE-TIME exclusion, not runtime — not attacker-reachable. Same fail-closed pattern as ADR-062 Slice 6. Residual = build-hygiene (testing feature must not leak into shipped wheel via feature unification, cf plan1733) — not in this diff.

## NOTE: prompt items 4/9 partially inaccurate
- Item 9 "drain_and_deliver_sender_keys now takes crypto:&mut ActorCrypto" — FALSE for this branch; sig still (deps, context_id, context_id_bytes) at lifecycle_helpers.rs:405.
