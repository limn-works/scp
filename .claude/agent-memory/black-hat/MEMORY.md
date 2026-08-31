# Black Hat Agent Memory

Index only. Open the linked topic file for detail. One line per entry — this file is
truncated past line 200 when it loads, so detail belongs in the topic file, never here.

Working notes:
- Agent threads reset cwd between bash calls. Use absolute paths only.
- Final responses share absolute file paths and, where the exact text is load-bearing, the snippet.
- No emojis. No colon before a tool call.

## Per-PR and per-branch findings

- [PR #2415 custody vocabulary](pr2415-custody-vocabulary.md) — derive-only published custody reduces to an unverified foreign self-report, and nothing publishes the attestation at all.
- [SCP-294 custody naming](pr-scp294-custody-name-one-thing.md) — bridges fail closed; four upstream docs still say custody="platform" reaches an OS keystore.
- [PR #2141 R25 batch 3](pr2141-r25-batch3.md)
- [PR #1628 BridgeInstance extraction](pr1628-bridge-instance.md) — post-shutdown ghost ops, placeholder DID confusion, rate-limiter ephemeral bypass.
- [Refactor plan adversarial analysis](refactor-plan-adversarial-analysis.md) — BLACK-301..311: facade divergence, Phase B TOCTOU, asymmetric wiring, BridgeInstance split-brain.
- [2026-Q2 branches](surfaces-2026q2-branches.md) — PR #1606 sender-key AAD, the consequence/economy/FFI review, ADR-039 persona wiring, TS SDK fail-closed parity.
- [HTTP features and transport expansion](surfaces-http-and-transport.md) — scp-node HTTP (PR #195) and commit 8873a54 transports.
- [Early audits](surfaces-early-audits.md) — PR #76, spec 22 addressing, PR #127 UCAN bridges.
- [FFI bridge audit](ffi-bridge-audit.md)
- [Historical audits](historical-audits.md)

## Standing lessons

- A malicious or merely lazy platform-callback implementation is the weakest link in every
  "the bridge derives this, so a caller cannot declare it" claim. Trace the value back to
  the party that actually answers, then ask who verifies that party.
- A `#[derive(Deserialize)]` on a struct with private fields is a public constructor. It
  defeats every "no field exists to write it in" invariant.
- Check whether the production path calls the function at all before judging the function.
  Several custody, attestation, and event-log guarantees in this repo are unwired.
