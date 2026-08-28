---
name: scp-294-custody-name-one-meaning
description: SCP-294 custody-string fail-closed change — severing the PyO3 "platform"→file substitution was compelled; deleting the SDK CustodyType members decided OQ-9, which §3.2 of the identity spec owns and an unmerged PR routed to a human.
metadata:
  type: project
---

Branch `fix/scp-294-custody-name-means-one-thing` (base `5e7e5b4e67`). Verdict: **UNSOUND in part** —
keep the bridge half, reverse the SDK-enum and ADR half.

**Two questions, one owner, two opposite handlings in one change.** §3.2 of `.docs/specs/03-identity.md`
(lines 9–19) names four custody *sources* in prose and no option string at all. Open question OQ-9, added
by pull request #2411 on branch `spec/one-section-governs-the-four-identity-keys` (commit `00d784f1ef`,
OPEN), assigns the custody-option vocabulary to §3.2 "with the three SDK enums following it". The change
withheld the `"file"`-vs-`"software"` spelling from decision and pinned it in a test (correct), and
decided the `"platform"` half by deleting `CustodyType.platform`/`.software` from the Swift, Kotlin, and
TypeScript SDKs and rewriting ADR-025/026/027/028's factory APIs (wrong — §3.2 owns it).

**Compelled independently of §3.2 (keep):** severing PyO3's `"platform"` → `FileKeyCustody` silent
substitution, and giving `"platform"` the same `SCP-IDENT-1003` on all three bridges. The fail-closed
builder tenet is upstream of §3.2.

**Root cause the change perpetuated instead of naming:** `crates/scp-ffi/Cargo.toml:80` resolves
`scp-platform` with the `file` feature; `napi/Cargo.toml:86` and `uniffi/Cargo.toml:82` do not. Nobody
decided that. `"file"` therefore reaches a real encrypted-file custody on one bridge and nothing on two,
and the shipped TypeScript SDK is left with **no** production identity-creation path (its
`KeyCustodyProvider` ships as an interface with no implementation).

**Human ruling that constrains any future answer** (§3.9.3 of the PR-#2411 spec, quoted verbatim):
Alec, 2026-08-25 — "active generally would not go in hardware but it's an option. it would go behind a
passkey or something. so platform would be the expectation." And: "LET PEOPLE CHOOSE. LIKE IS ALREADY
FUCKING WRITTEN INTO THE GODDAMN PROTOCOL." Do not re-derive the custody vocabulary without it.

**Nine live custody vocabularies** (the change reduced none): `scp_platform::CustodyType`
(`crates/scp-platform/src/traits.rs:223`); the `KeyCustodyProvider` callback strings
`hardware|software|software_biometric`; `scp_did::KeyCustodyModel`
(`crates/scp-did/src/attestation.rs:86`); UniFFI `CustodyMethod`; the three bridge create-string sets;
the four SDK `CustodyType` enums; `works.limn.scp.android.platform.CustodyType`; §3.2.1's
`target_custody_type` enum; §3.2's four prose options.

See [[scp-out-046-streaming-saga-seal-fsm]] for the contrasting case where an architecture-forced split
was SOUND and should not be re-litigated.
