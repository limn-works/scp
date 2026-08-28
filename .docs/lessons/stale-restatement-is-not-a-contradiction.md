# A Stale Restatement Is Not a Contradiction

**Date:** 2026-08-28
**Source:** ADR-039, the shared-DID human-agent identity model
(`.docs/adrs/phase-1.md:1231`); §3.2.1 of the identity spec, the key custody migration
protocol (`.docs/specs/03-identity.md:20`); `ScpKeyCustodyAttestation` and
`KeyCustodyModel` (`crates/scp-did/src/attestation.rs`)

## The Rule

Two artifacts diverge only when you can write the sentence stating why both cannot be
true. Write that sentence before you record a divergence or take the question to a human.
When you cannot write it, you found a copy that drifted from its source, and the artifact
flow — plans → specs → ADRs → stories → source code (`CLAUDE.md:91`) — names which copy is
wrong.

## What Happened

An agent read two passages of ADR-039, reported them as contradicting each other, searched
for three custody field names, found none of them, and reported that no custody field
covers `#0`. It took both findings to the human as open questions. The identity spec and
the shipped type answered both.

**1. The two passages.** The Backing row of the key-properties table gives one value per
key and names no platform: `| Backing | Hardware (SE/AKS) | Software | Software |` for
`#0`, `#active`, and `#agent` (`.docs/adrs/phase-1.md:1268`). Enforcement Stack layer 1
states hardware custody for `#active`, then makes the guarantee depend on the platform
class: "`#active` in hardware (Secure Enclave / Android Keystore) with session-based
biometric unlock. … Agent physically cannot invoke `#active` on hardware-backed platforms.
On software-only platforms, isolation is process-level (different keychains, different
access controls)." (`.docs/adrs/phase-1.md:1296`). The two passages state different things
only if the Backing row asserts one custody model for `#active` on every platform. Whether
the row asserts that is a question about which artifact governs, and the agent reported a
contradiction without asking it.

**2. What governs.** The identity spec governs both passages. §3.2.1 states that custody
migration moves the operational signing capability from one custody provider to another
without changing the DID string (`.docs/specs/03-identity.md:22`), names `#active` as the
key that case 1 migrates (`.docs/specs/03-identity.md:26`), and enumerates the providers
that the `#active` migration targets: `target_custody_type: enum { SecureEnclave,
AndroidKeystore, HardwareKey, Passkey, Software }` (`.docs/specs/03-identity.md:30` for the
case-1 heading, `.docs/specs/03-identity.md:37` for the enum). `#active` custody therefore
varies per identity and changes over an identity's life, so the Backing row asserts no
fixed custody model for `#active`, and the row and layer 1 do not contradict each other.

**3. The invented names.** The agent searched the repository for `identity_key_custody`,
`root_key_custody`, and `zero_key_custody`. No source file, spec, ADR, story, or binding
uses any of the three; this lesson holds the only occurrences of the three strings in the
repository, because it quotes them. Zero hits for an identifier that no author chose
establishes that the identifier is absent, and establishes nothing about whether the
protocol covers `#0`'s custody.

**4. What owns the custody choice.** `ScpKeyCustodyAttestation`
(`crates/scp-did/src/attestation.rs:41`) declares five fields:
`active_key_custody: KeyCustodyModel` (line 43), `agent_key_custody:
Option<KeyCustodyModel>` (line 47), `platform: Platform` (line 50),
`platform_attestation: Option<PlatformAttestation>` (line 55), and `created_at: u64`
(line 58). `KeyCustodyModel` (line 86) enumerates `HardwareBiometric` (line 90),
`HardwarePin` (line 95), and `Software` (line 100). Reading the five fields answers the
`#0` question in one step: the attestation declares a custody model for `#active` and for
`#agent`, and declares no field for `#0`. The three greps could not have established that
answer in either direction.

## The Lesson

- Quote both sides in full, then enumerate the cases each side covers. A restatement
  usually drops a condition its source carried, which leaves the two texts agreeing
  everywhere except in the case the condition names.
- Find what governs. An ADR restating a spec, and a table restating a type the source code
  defines, hold no authority over the artifact they restate.
- Read the type that owns a capability. A grep for a name you invented reports on the name
  and never on the capability.
- Search the shipped code, the human's prior words in the conversation, the persistent
  memory, and the plan of record before you ask the human. A human's general statement
  usually decides a narrow question, and arrives in a shape that the question's wording
  does not match.

`CLAUDE.md` carries the rule under "A stale restatement is not a contradiction", beside
"Never write your extrapolation as the contract", which names the same class of failure
from the other direction.

`.docs/lessons/per-identity-op-placement-two-axes.md` records the opposite case: an ADR
that contradicted itself across two passages, where the fix is to name the invariant once
in the upstream artifact and cross-reference every downstream mention to that name.
