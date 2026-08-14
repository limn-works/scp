---
name: nodeconfig-adr051-1807
description: PR #1807 NodeConfig/Node::start ADR-051 flat-config test review (crates/scp-node/src/config.rs, 16 tests)
metadata:
  type: project
---

# NodeConfig / Node::start tests (PR #1807, ADR-051 Phase B-P1)

File: `crates/scp-node/src/config.rs`. 16 tests on `Node::start_for_testing`.

## Strengths (replicate)
- Behavioral, not compile-only: produces a real `ApplicationNode`, asserts on observable accessors (`identity().did()`, `domain()`, `relay_url()`) — survive lowering refactors.
- `MockNatStrategy` returns fixed `ReachabilityTier::Stun{external_addr}` → offline, no real STUN. Clean pattern for any NAT-path test.
- Offline discipline: STUN/ACME avoided via MockNat + `skip_nat_probe` + non-Domain reach. Low flakiness, no time/order/global-state hazards. `bind_addr 127.0.0.1:0` ephemeral.
- Test 9 `defaults_are_fail_safe` exemplary: exhaustively pins every default field incl. `#[cfg(http3)]`.
- Tests 11/12 assert error *message* names both sides of contradiction, not just variant.

## Gaps found (CHANGES-NEEDED before merge)
1. `TlsMode::SelfSigned`+`Reach::Domain` — the ONLY apply_tls arm doing real work (installs SelfSignedTlsProvider) is NEVER executed. Domain tests (1/2/7) leave tls defaulted but assert only DID.
2. `Node::start` (production `S: EncryptedStorage` seal) NEVER tested — every test uses `start_for_testing`. `finish_build` vs `finish_build_for_testing` are HAND-DUPLICATED (config.rs ~620 vs ~645); a divergence ships green.
3. `TlsMode::Terminated` — zero tests, distinct match arm.
4. Tests 3 (acme), 14 (nat_tuned), 15 (blob Some-path) assert no-panic-on-build as a proxy for "setter lowered" — if acme_email/stun_server/bridge_relay silently dropped, still pass. Comments are honest but names oversell. Assert value landed if a getter/relay_url exposes it, else rename to `_does_not_panic_`.

## Recurring anti-pattern (general)
"build succeeds therefore setter X lowered correctly" is a no-panic proxy, NOT behavioral verification. Common in builder-lowering test suites. Flag it: demand assertion on observable effect or honest test name.
