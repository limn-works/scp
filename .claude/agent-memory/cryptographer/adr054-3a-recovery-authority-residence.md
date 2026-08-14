---
name: adr054-3a-recovery-authority-residence
description: Review of §9.7.4.1 item 3a (recovery-authority residence) + ADR-054 amendment — normative clause SOUND but has completeness gaps in conformance tests + §5/§6 ceremony
metadata:
  type: project
---

# §9.7.4.1 item 3a "Recovery-authority residence" + ADR-054 amendment (reviewed 2026-07-14)

Branch `docs/adr-054-accept-substrate-residence`, commits 3b81b5db4 (spec §3a) + 90b6388d6 (ADR amendment). Verdict: **SOUND but INCOMPLETE**.

**Why:** the clause fixes the real ADR-054 gap — substrate isolation is residence of the *recovery authority* (minimal secret/handle/capability to recover pre-rotation key), NOT cipher strength. Encrypted-offline + auto-gen server-reachable passphrase = degenerate = isomorphic to InMemory. Umbrella normative sentence is outcome-based ("suffices to recover") = sound. Per-backend §3-soundness table is correct (KMS canonical; FIDO2→interactive/collapses-to-KMS-on-server; secondary-enclave separate domain; Shamir <3-reachable; BIP39 not-server; encrypted-offline conditional). At-rest caveat correctly scoped (can't prevent plaintext seed in operational memory during authorized migration `consume`→import-as-#0).

**How to apply (gaps found, if this clause is revised):**
- MEDIUM-HIGH: conformance PAIR (ADR lines 162-163) under-approximates the umbrella. Test#1 concrete enum ("config, env, keychain, on-disk files") is local-host-centric — misses cloud-IAM-reachable secrets (Secrets Manager GetSecretValue), assume-role indirection, KEK-of-KEK chains. Test#2 grant-exclusion scoped to "the pre-rotation KEK" only, not the full derivation/wrapping chain or assume/delegate. A KMS/SecretsManager backend can PASS both tests while VIOLATING §3a. Tests are the mechanical enforcement → this is the load-bearing gap.
- MEDIUM: §5 ceremony (present/guide/verify) and §6 re-selection are human-centric, lack §3a cross-ref, and have NO non-interactive-server variant despite server profile being in scope (3a(a)). §5(b) presents all options unfiltered; the "MUST NOT offer non-conforming backend" normative hook lives only in 3a(a)/OQ2, not in §5b.
- MEDIUM/clarity: item-4 "Platform-backed cloud key store (recoverable through platform account recovery)" not mapped in table for same-platform-account case → operationally-reachable if account == operational account.
- LOW: 3a(a) grant enum "read/use/decrypt" omits assume/delegate; umbrella doesn't say "transitively ... following wrapping/derivation chain to root."
- LOW-MEDIUM: interactive 3a(b) leans on human-presence principal but §3a hands ciphertext to adversary → security reduces to user-passphrase entropy, and item-4 ≥128-bit floor applies only to auto-generated passphrases (no floor for user-chosen).

Related: [[finding_hpke_not_rfc9180]] pattern (ADR realizes spec). ADR-003 §4b reveal→import, §9.12 migration.
