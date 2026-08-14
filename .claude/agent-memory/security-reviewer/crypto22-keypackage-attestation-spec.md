---
name: crypto22-keypackage-attestation-spec
description: CRYPTO-22 spec amendment (§9.7.1) replacing leaf==DID with ephemeral-leaf + #active/#agent-signed KeyPackage attestation — SOUND, fail-closed, 0 blocking
metadata:
  type: project
---

# CRYPTO-22 KeyPackage attestation spec (branch crypto-22-attestation-spec, 26b45229c) -- 2026-08-01 -- SOUND, FAIL-CLOSED, 0 blocking

Spec-only change. Replaces old §9.7.1 "leaf signature_key == #active DID key" with: MLS leaf key is
EPHEMERAL context-scoped Ed25519 (SignatureKeyPair::new, self-signs leaf per RFC 9420); a separate
**KeyPackageAttestation** (domain "SCP-KEYPACKAGE-ATTESTATION-V1:", §9.5.2) binds
{context_id, did, leaf_signature_key(32B), signing_key_id(#active|#agent), issued_at, expires_at},
signed by #active/#agent (never #0, Category-B), carried as LeafNode ext scp_keypackage_attestation 0xFF03.
Closes CRYPTO-22 (attacker adds self as victim DID) + the handshake-attribution hole (committer/proposer
DIDs were unauthenticated because DID binding was UNIMPLEMENTED — resolve_signing_key unused).

Why SOUND:
- **Fail-closed (pt1):** §9.7.1 Verification(MUST) lists "absent, malformed, expired, mis-scoped, or not
  verifiable ... MUST be rejected (fail-closed) for production DIDs (did:dht:z*)". "absent" explicitly rejected —
  no accept-if-absent hole.
- **Testing carve-out (pt2):** prefix-scoped (did:test:/did:key: skip resolution), mirrors existing
  cfg!(any(test, feature="testing")) precedent at provider.rs:832-851 validate_creator_identity (prod requires
  did:dht:z*). A did:dht victim credential can NEVER match the carve-out prefixes → full verify always applies.
- **Every trust point (pt3):** "processes an Add/join, AND whenever it processes another member's Commit or
  Proposal" — Proposal covers Add/Remove/Update (table row). Attribution chain sound: MLS verifies Commit sig
  vs leaf_key (RFC 9420) + attestation binds leaf_key→credential.did (§9.7.1).
- **Re-grounding (pt4):** message/sender identity was ALWAYS inner-envelope Ed25519 vs DID doc (§9.8.1), NOT
  leaf key — unaffected. Standing-context bound-creator check (05-contexts.md §5.12) re-grounded on attestation.
  grep: zero residual "leaf==DID"/"KeyPackage sig verifiable against DID doc" assertions remain in specs/adrs.
- **Downgrade (pt5):** context_id + leaf_signature_key + did all in signed preimage & checked → no cross-context
  replay, no leaf-key substitution, no self-add-as-victim. Rotated/stale key fails closed: verifier resolves
  signing_key_id fragment against CURRENT DID doc, old-key signature fails. #active vs #agent both valid
  Category-B signers by ADR-039 design (not a downgrade).

MINOR hardening (non-blocking, for the follow-on impl PR #2187):
- Spec doesn't state attestation field-4 signing_key_id MUST equal credential.signing_key_id (only fails closed
  implicitly via signature verifying under wrong key). Recommend explicit equality check like the did/leaf_key ones.
- expires_at "matches KeyPackage Lifetime.not_after" stated as construction, not a verification MUST (harmless —
  MLS caps leaf Lifetime independently, tighter bound wins).
- Testing-carve-out gating stated by reference ("mirroring existing carve-out") not explicit `testing`-feature words.

Follow-on: impl PR #2187 adds prod resolve_signing_key call site + attestation mint/verify.

# CRYPTO-22 HARDENED FINAL (49ace8b5, BLACK-C22-1 fix pass) -- 2026-08-02 -- CONFIRMED-CLEAN, 0 fail-closed gap
Spec-only. 6-field attestation now {did, leaf_signature_key(32B Ed25519), leaf_encryption_key(32B X25519),
signing_key_id, issued_at, expires_at} — context_id already dropped in prior FINAL (20f7a036b). 9-item verifier
MUST-list (§9.7.1). All prior 3 MINOR RESOLVED (check6=explicit signing_key_id==credential eq; check7=expires/issued
== leaf Lifetime as MUST; testing gate now explicit `testing`-feature words). Fix pass adds:
1. 6th field leaf_encryption_key + check4 hard-reject (closes stolen-sig-key + attacker-chosen-enc-key HPKE-recv
   substitution). MLS LeafNode always has an encryption_key → absent/malformed = malformed attestation = reject.
2. Lifetime cap MAX_KEYPACKAGE_ATTESTATION_LIFETIME=7,261,200s (84d+1h) == leaf Lifetime max range
   (KEY_PACKAGE_LIFETIME_MAX_RANGE_SECS); check8 hard-reject expires-issued>cap. Cap MUST equal (not tighter/wider)
   because check7 pins window to leaf Lifetime — sound reasoning.
4. POSITIVE WHITELIST (§9.7.1 line 631): MANDATORY verify for EVERY production DID method ("without exception",
   "No production DID method is exempt"), explicitly forbids single-prefix keying (did:dht:z), did:web:* in scope;
   only testing-feature-gated did:test:/did:key: exempt. Default=verify→unknown method resolves→fail→reject. TRUE
   fail-closed. Grep: only did:dht:z mention is the one forbidding prefix-keying.
5. Resolution failure (DHT timeout/unreachable/did:web TLS) = REJECT, "never accept-if-uncertain". Resolver cache
   = SHOULD, bounded size+TTL, cache-miss-on-unresolvable still rejects.
6. §9.12 "leaf-key/MLS-state compromise" Tier-1: rotate #active/#agent (existing op) invalidates ALL outstanding
   attestations (check1 current-key-only). Containment ACCURATE: leaked leaf key = ephemeral SignatureKeyPair, does
   NOT expose #active/#agent (attacker holds a signature BY the key, not the key). No #retired accept path.
7. check1 verify vs CURRENT #active/#agent VM only, never #retired-* — this is what makes rotation revoke.
KAT Vector 37 §25.22 recomputed byte-exact self-consistent: 147B preimage = 30(domain)+26(did)+32+32+11(skid)+8+8;
181B ext body = 117 fields + 64 sig; issued/expires hex + delta 86400 verified.
OBSERVATION (non-blocking, spec precision): resolver-cache TTL slightly qualifies "rotation invalidates
immediately everywhere" → really "within cache TTL at each verifier". [RESOLVED in 8-field FINAL below.]

# CRYPTO-22 8-FIELD FINAL (c7773cad4, BLACK-C22-HIGH + BLACK-C22-MED fix pass 2) -- 2026-08-02 -- CONFIRMED-CLEAN, 0 fail-closed gap
Spec-only. Supersedes 6-field above. Now 8 fields {did, leaf_signature_key(Ed25519), leaf_encryption_key(X25519
ratchet-tree), init_key(X25519 Welcome-seal), wrapping_key(X25519 0xFF01), signing_key_id, issued_at, expires_at} —
binds ALL 4 leaf public keys. 11-item verifier MUST-list (§9.7.1 L630-642).
Two new fixes both confirmed genuinely fail-closed:
- **init_key (check6, Add/Welcome-time ONLY):** closes read-as-victim-at-join — RFC9420 init_key != encryption_key,
  Welcome's EncryptedGroupSecrets HPKE-sealed to init_key; sig-key thief crafting KP w/ victim sig+enc + copied
  attestation + ATTACKER init_key → Welcome sealed to attacker. Check6 = hard reject (attestation.init_key ==
  KeyPackage.init_key). Carve-out (creator/PCS leaf: init_key field == leaf_encryption_key, check6 skipped) is NOT
  join-triggerable: carve-out selected by MSG TYPE (Add vs Commit/creation), structurally MLS-determined, not
  attacker-chosen. On a real join (always an Add of a KP), check6 fires unconditionally; attacker KP's chosen
  init_key won't match victim's attested init_key → reject. No fail-open.
- **wrapping_key (check5, EVERY leaf read Add+Commit/Proposal):** hard reject; closes sig-key thief substituting own
  0xFF01 wrapping key to harvest §9.16 per-sender keys. In mandatory list, not advisory.
- KEEP check3(sig_key)/check4(enc_key) every read → PCS-Update leaf can't substitute enc_key on Commit; leaf-key
  thief can't even mint a valid Update (fresh leaf keys need fresh attestation = needs #active/#agent).
**BLACK-C22-MED resolver stale-fallback hole FIXED (§9.7.1 L646 "Resolution failure is a reject — no stale
fallback"):** on current-#active/#agent resolution failure verifier MUST REJECT (fail-closed); MUST NOT fall back
to stale/pre-rotation cached doc. Cache retained ONLY as positive same-or-fresher optimization w/ SHORT TTL; failure
+ no fresh-enough entry = reject. Closes attacker-induced-resolution-failure → pin verifiers on pre-rotation doc →
retired key keeps resolving past rotation. Genuinely fail-closed: no surviving accept-if-uncertain path.
**§9.12↔§9.7.1 consistency:** ALL 3 revocation-latency statements (§9.7.1 L648, §9.12 L1252, §9.12 L1268) now say
"within the (short) resolver-cache TTL — near-immediate, not instantaneous". No surviving "immediately/at once"
overclaim. My prior 6-field OBSERVATION is RESOLVED. ADR-057 amendment (L243-269) fully consistent w/ 8-field +
init/wrapping + resolver fail-closed. Vector 37 §25.22 recomputed 8-field: 211B preimage
(30+26+32+32+32+32+11+8+8), SHA-256 50cf61db…8957, sig fcf01ea5…3509, 245B ext body (181+64). Self-consistent.
