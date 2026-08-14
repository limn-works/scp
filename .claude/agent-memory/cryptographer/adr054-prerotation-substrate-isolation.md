---
name: adr054-prerotation-substrate-isolation
description: ADR-054 / spec §9.7.4.1 §3 crux — where pre-rotation key/passphrase must live for substrate isolation; encrypted-offline auto-gen passphrase is NOT a valid standalone non-interactive server backend
metadata:
  type: project
---

# ADR-054 §9.7.4.1 §3 substrate-isolation crux (resolved 2026-07)

**Load-bearing conclusion:** substrate isolation is a property of the *decryption
authority's residence*, NOT of the cipher. AES-256-GCM+Argon2id protect the blob
against someone who LACKS the passphrase; §3's threat model is precisely someone
who HAS compromised operational custody. If the passphrase/KEK is reachable from
operational custody, the cipher gives ZERO marginal protection vs the §3 adversary
→ encrypted-offline degenerates to InMemory-equivalent (satisfies §4 letter:
AES/Argon2id/≥128-bit; nullifies §3 property).

**Rule to encode (spec-first, new §9.7.4.1 sub-clause):** there MUST NOT exist any
secret or capability reachable from the operational custody provider / operational
(daily) authentication flow that is sufficient to recover the pre-rotation private
key. The decryption authority (passphrase, KEK, KMS-use grant, ≥quorum Shamir
shares, hw possession/PIN) MUST reside under a principal whose compromise is
independent of operational-custody compromise.

**Non-interactive server (scp-node):** encrypted-offline auto-gen passphrase is
§3-valid IFF passphrase/KEK held under a DISTINCT principal (separate KMS/HSM/
secret-manager IAM role) the operational role has no grant to — and then THAT store
is the real §3 substrate, encrypted-offline is just its serialization. Co-located =
INVALID. Migration ≠ daily op: a distinct migration-time principal (even automated)
is compliant; the crux is principal-distinctness, not human interaction.

**Per-backend §3-soundness:** KMS/cloud-vault = canonical server answer (iff separate
IAM principal). HW-key/FIDO2 & secondary-enclave = sound but interactive (user
presence) → on server collapses to HSM-with-own-policy. Shamir 3-of-5 = sound IFF
≥3 shares in independent trust domains outside operational blast radius; all-shares-
local = InMemory-equiv. BIP39 = human/paper, no non-interactive server residence.

**Conformance test (beyond "separate provider"):** NEGATIVE reachability assertion —
harness handed (operational KeyCustody full surface + all artifacts operational
principal can read + public blob) MUST FAIL to reconstruct the 32B pre-rotation seed;
INCLUDE the auto-gen passphrase in the recovery attempt; assert pre-rotation KEK
principal (KMS key id / IAM role / keychain access-group / TPM policy) is structurally
distinct from operational principal's grant set.

**Answers ADR-054 OQ2 (backend minimum):** encrypted-offline NOT a sufficient floor
for non-interactive scp-node; floor MUST be KMS/HSM independent-principal backend.
OQ3: YES a §9.7.4.1 sub-clause is needed (residence rule above), lands spec-first.

Nuance: §3 is at-rest; the transient consume-window (seed live in operational memory
during an AUTHORIZED migration) is irreducible and out of §3 scope — don't over-claim.

## ADR-053 migration-reveal disclosure (ae3a4238f, R26 doc-only) — ACCURATE/COMPLETE, APPROVED
Sibling ADR-053 = callback-custody realization. R26 corrected 2 Consequences lines:
(1) dropped "enforced by the type system" → "structurally encouraged" — CORRECT: separate
`PreRotationCustody` vs `KeyCustody` trait prevents SAME object dual-role but Rust sig cannot
verify two distinct callback objects aren't backed by same Keychain access-group/biometric;
conformance NEGATIVE-reachability test is the real enforcement (consistent w/ this file's thesis:
isolation = residence property, not type/cipher). (2) NEW migration-reveal transit disclosure —
VERIFIED accurate against dht.rs:1588-1597: `destroy_after_migration`→Zeroizing<[u8;32]>
`revealed_private` passed by-ref to `key_custody.import_ed25519_signing_key`, drops after. For
callback custody BOTH ends cross FFI ⇒ old pre-rotation seed materializes plaintext in shared
bridge process mem for the hand-off window; Zeroizing narrows not eliminates (core-dump/debugger/
cold-boot observable). Matches this file's nuance (transient consume-window irreducible, out of §3
at-rest scope). Note: new-seed store side (store_committed_pre_rotation_key, caller-generated seed)
is a symmetric transit window not separately enumerated, but "during migration the seed is
transiently observable" covers it. NO over-claim, honest.

## Trust-SDK Layer 1 (trust.py / trust.ts, R26 same branch) — SOUND
`_extract_first_capability_uri` base64url pad math correct: `4 - len%4` then `%4` → r0→0,r2→2,
r3→1 pads; r1 (invalid b64) decode-fails→None fail-closed. TS uses Buffer base64url (lenient).
att[0]-only documented limitation, null→all-false fail-closed both SDKs (real crypto is at
ucan_validate bridge; Layer1 = self-consistency not authority). PERM-3030 re-raises both (caller-
misuse must surface, NOT folded to false verdict); only PERM-3001 absorbed→narrowed, VALID-*
→all-false. Revocation prefixes = ("token revoked:",) only; operational "revocation unauthorized/
failed:" REMOVED → fall to unknown→all-false (SAFER: had they classified "revoked", _PASSED_BEFORE
would falsely report tokens/sig/ceiling/nonce True). Python/TS parity intact.

## PR #2136 reframe-correction (b6dd698e0, docs-only 4 files) — VERDICT SOUND/MERGEABLE
The reframe punts pre-rotation *realization* (per-profile floors, §3-soundness table,
conformance PAIR, §5/§6 ceremony) to RFC #2130; ADR-054 Accepted→Proposed; only the
§3a residence RULE stays canonical in spec §9.7.4.1. Re-review confirmed:
- §9.7.4.1 numbered list 1,2,3,3a,4,5(a-f),6,7 INTACT; item 3a core residence paragraph
  byte-unchanged; items 4/5/6/7 undamaged (4's parenthetical stripped of 3a(a)/(b) xref,
  5b simplified, 6 lost per-profile re-select sentence — all correct punts). ZERO dangling
  3a(a)/(b)/(c) refs remain (orphaned "c." fixed). A5 RFC-pointer paragraph keeps items 4/5
  canonical, only per-profile filtering→RFC #2130.
- RESTORED fail-closed clause SOUND + correctly scoped: MUST fail closed w/ typed error,
  no fallback to co-located operational storage NOR in-memory/dev stand-in, reachable-from-
  operational = violation never degraded default. Core invariant ONLY (no KMS/HSM/menu/
  ceremony smuggled). STRENGTHENS vs deleted text: old fail-closed lived only in per-profile
  server para; now general → applies to ALL identity creation. Consistent w/ storage-spec
  "Storage Selection Fails Closed"/"Runtime Never Defaults" (§17.17-analog, SCP-STORAGE-8000).
- No crypto guarantee lost: ONLY concrete PreRotationCustody impl is InMemoryPreRotationCustody
  in scp-platform/src/testing/, minted at config.rs:334 in prod create path (warn!+non-durable
  handle). NO real durable backend exists; punted detail describes unimplemented behavior.
- Severance HONEST: code severance attributed to ADR-062 §Decision 6 (Proposed/unexecuted),
  NOT this PR. commit L3 + config.rs warn! explicit that current identities get valid-but-
  non-durable commitment (real key, process-local, lost on restart), moot pre-release. Not a
  false commitment, not a silent-nullifier completion claim.
NITS (non-blocking): (1) ADR-054 forward note present-tense "production identity creation
FAILS CLOSED" reads as shipped behavior but code does NOT yet fail closed (config.rs:334) —
qualified by "code edits are ADR-062's" so defensible spec-first, but recommend tense softening.
(2) ADR-062 header cites "§17.17"/"SCP-CAPSEL-8000" numbered IDs absent from specs (storage
spec uses prose titles, no §17.17/CAPSEL) — PRE-EXISTING, both old+new header lines carry it,
outside this diff's crypto surface.
