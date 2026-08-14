---
name: crypto22-s2-verify-attestation
description: CRYPTO-22 slice 2 pure verify_attestation (§9.7.1 checks 3-13) @24de49690 — COULD NOT BREAK; residuals are caller-contract (wiring S4/S6/S7)
metadata:
  type: project
---

# CRYPTO-22 Slice 2 `verify_attestation` (§9.7.1) — COULD NOT BREAK

File: `crates/scp-mls/src/keypackage_attestation.rs` (fn `verify_attestation` L560-650), branch `crypto22-s2-verify-attestation` @24de49690. Pure/inert: ZERO external callers of THIS fn / `AttestationVerificationContext` (the many `verify_attestation` grep hits are unrelated `scp_protocol::trust::verify_attestation` for IdentityLinkAttestation — name collision). Wiring is S4/S6/S7.

## Why it holds
- Check 3 unconditional & FIRST; `scp_primitives::verify_ed25519_signature` = `verify_strict` (cofactorless, rejects small-order, validates 32/64 len + pubkey point). Sig covers recomputed `signing_hash()` = SHA-256 of all 8 canonical fields → every compared field authenticated; no field-tamper survives. Forger needs victim's #active/#agent PRIVATE key → can't.
- Cross-context transplant of a COPIED public attestation fails checks 4-6 (leaf's actual keys must == attested keys) AND is unoperable (no private leaf keys → can't self-sign LeafNode / decrypt Welcome/path). The ONLY residual cross-ctx reuse needs FULL leaf-key compromise = the acknowledged §9.7.3 in-group-PCS-scope threat, BOUNDED HERE by check 12 (84-day cap, `expires-issued` underflow-guarded by 13a-first ordering) + rotation=revocation (check 1/3, caller resolves CURRENT key). Dropping same-context check opens NOTHING new — verifier never was the ctx-isolation layer.
- init_key trap sound: checks 7-8 gated on `ctx.trigger==Add` (structural), never on `init_key==enc` field equality. Update skips (no init_key on ratchet leaf); Add w/ kp_init=None → fail-closed MissingKeyPackageInitKey.
- Time edges clean: 13a (`expires<=issued`) BEFORE 12 subtraction; 13b `now>expires` (not_after inclusive); 13c saturating_add skew; check 11 pins window==leaf Lifetime so attacker can't widen (issued/expires are signed).
- SigningKeyId closed 2-enum; check 10 enum-equality; #active↔#agent confusion blocked (skid in signed hash field 6 as `#active`/`#agent`).

## Residuals (all caller-side, not this fn's defect)
1. STRONGEST — escalate to wiring reviewer: security rests ENTIRELY on S4/S6/S7 honoring the contract: (a) `trigger` MUST be handshake-structural — misclassifying an Add as Update silently skips checks 7-8 → reopens read-as-victim-at-join; (b) checks 1-2 (resolve VM named by signing_key_id, ≤300s freshness, Add=fail-closed / Update=bounded-LKG) defeated if caller uses stale/pre-rotation doc or wrong VM. Pure fn cannot detect any of these.
2. LOW doc-precision (upstream spec §9.5.2 framing, mirrored in code L134/465): "0xFF02 GroupContext ... binds the leaf's actual group" overstates 0xFF02's role — 0xFF02 binds GROUP params/lineage to group_id, NOT leaf-keys-to-context; it does NOT close cross-ctx leaf reuse (rotation+lifetime-cap do). Code relies on nothing from 0xFF02, so framing-only.
