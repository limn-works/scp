# A Stale Restatement Is Not a Contradiction: a Worked Example

AGENTS.md states the rule under "A stale restatement is not a contradiction": two artifacts
diverge only when you can write the sentence stating why both cannot be true. This file is
the worked example it cites.

## What the agent reported

An agent reported two passages of ADR-039, the shared-DID human-agent identity model, as
contradicting each other, then searched for three custody field names, found none, and
reported that no custody field covers `#0`. It took both findings to the human as open
questions. The identity spec and the shipped type answered both.

## The two passages

- The Backing row of the key-properties table gives one value per key and names no platform:
  `| Backing | Hardware (SE/AKS) | Software | Software |` for `#0`, `#active`, and `#agent`
  (`.docs/adrs/phase-1.md:1268`).
- Enforcement Stack layer 1 makes the guarantee depend on the platform class: "`#active` in
  hardware (Secure Enclave / Android Keystore) with session-based biometric unlock. … On
  software-only platforms, isolation is process-level" (`.docs/adrs/phase-1.md:1296`).

They conflict only if the Backing row asserts one custody model for `#active` on every
platform, and whether it does is a question about which artifact governs.

## What governs

§3.2.1 of the identity spec, the key custody migration protocol, governs both passages. It
moves the operational signing capability between custody providers without changing the DID,
names `#active` as the key that case 1 migrates, and enumerates the targets:
`target_custody_type: enum { SecureEnclave, AndroidKeystore, HardwareKey, Passkey, Software }`
(`.docs/specs/03-identity.md`). `#active` custody therefore varies per identity and over its
life, so the Backing row asserts no fixed model and the two passages agree.

## The invented names

The agent searched for `identity_key_custody`, `root_key_custody`, and `zero_key_custody`.
No author ever chose those names, so zero hits established only that the strings are absent.
The type that owns the capability, `ScpKeyCustodyAttestation` in
`crates/scp-did/src/attestation.rs`, declares `active_key_custody: KeyCustodyModel`,
`agent_key_custody: Option<KeyCustodyModel>`, `platform`, `platform_attestation`, and
`created_at`. Reading those five fields answers the `#0` question in one step: the
attestation declares a custody model for `#active` and `#agent` and none for `#0`.
