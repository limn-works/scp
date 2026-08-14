---
name: pr2144-error-code-ledger-primitive
description: #2144 browser-vs-native error-code reconciliation — is sdk-common.md ledger + hand-copy the right permanent single-source, or a DOA workaround for a crate-layering accident
metadata:
  type: project
---

# #2144 error-code reconciliation (branch fix/2144-error-code-reconcile) — INTERROGATE FURTHER

Fix: `scp-client-wasm/src/error.rs` `error_code()` renumbered browser participant codes OFF the
native FFI-common band it was colliding with. On main the browser blindly reused native numbers
with DIFFERENT meanings (UnknownContext=CTX-2001 but native 2001="Context operation failed";
ContextAlreadyExists=2002 but native 2002="not found"; Codec=VALID-7010 but native 7010="UCAN
token"; Transport=TRANS-5010 but native="subscription"; PseudonymRegistryEmpty=CTX-2040 but native
2040="governance"; etc.). Both surfaces feed ONE TS ScpError prefix-dispatch → same string, two
meanings = genuine contradiction. Fix moved browser to browser-owned numbers (2077-2080,
4020/4030/4040/4041, 5005, 7018/7019) keeping ONLY CTX-2003 (already-exists) + CTX-2095
(pseudonym-registry-empty) as intentional shared-meaning reuses. VERIFIED sound at snapshot: all 11
browser-owned numbers ABSENT from native registry; 2003/2095 native meanings genuinely match.

## ROOT CAUSE (top finding, No-DOA): ledger-as-primitive rests on a smuggled premise
Ledger claims scp-client-wasm "CANNOT import the native registry — the ADR-057 wasm/tokio fence".
TRUE-as-written (scp-ffi-common unconditionally deps scp-dht which unconditionally deps tokio →
won't compile wasm32) BUT MISLOCATED: `error_codes.rs` is a ZERO-import pure-const module,
`pub mod error_codes;` is NOT feature-gated (lib.rs:19), and scp-client-wasm ALREADY deps
scp-protocol+scp-clock+scp-did (Cargo.toml:36-38) = 3 of scp-ffi-common's 4 unconditional deps.
Only scp-dht/tokio blocks import. So the constraint forbids the TOKIO STACK, not sharing constants.
Sound available alternative: hoist const table into a leaf no-deps crate (or into scp-protocol,
already wasm-safe + already shared by both) → true single source, Phase-3 in-band-uniqueness gate
then covers WHOLE space, collision impossible by construction. "Ledger + hand-copy" chosen over
this = the wrong PERMANENT primitive (a manually-synced "single source" whose failure mode IS
#2144). SOUND as immediate stop-the-bleeding, UNSOUND as permanent.

## Recurrence guard is ASYMMETRIC (premise "test prevents recurrence" overclaimed)
Browser exhaustive allowlist test (error.rs:182-310, no-wildcard match) pins ONLY the WASM enum
path vs silent renumber; it is NATIVE-BLIND. Nothing stops the NATIVE registry (or a 3rd surface)
from later minting a number colliding INTO a browser-owned code: check-error-codes.sh Phase-2 can't
see it (const-def + match-arm lines carry no `message:`/`JsError::new` literal — THAT is why #2144
was latent), Phase-3 is single-file, browser test ignores native. Two hand-allocators, one
un-partitioned category space, no boundary. Fix: reserve a contiguous browser sub-band OR leaf-crate
unification — NOT a Phase-2 extension (its msg-fingerprint heuristic IS the wrong tool for code→code;
the "don't broaden Phase-2" ruling is correct but must not be conflated with "no mechanism needed").

## Second UNPINNED hand-copy (undercuts "exhaustive test sufficient")
lib.rs free-fn validators emit HAND-WRITTEN literal `"[SCP-VALID-7018]"` at 8 sites (lib.rs:824,
871,875,879,883,905,911,919,926) — NOT routed through ClientError::Codec→error_code(), so the
touted exhaustive test never covers them. Pinned only by Phase-1 RANGE check → a wrong-but-in-range
typo (7019=ChannelContentMismatch) passes silently. Exactly the hand-copy class #2144 exists to kill.

## SOUND (verified, not findings)
- Collapsing input-validators to one 7018 erases NO distinction — already unified under one code
  (7010) pre-PR; coarse-code+message matches native convention.
- Bare-number citations ("distinct from native VALID-7010") = legit provenance, not scar tissue.
- 7025/7026 registration documents PRE-EXISTING codes (4 occurrences already on origin/main
  client.ts) = closing a ledger gap, in scope.

Heuristic: when a fix says "surface X CANNOT import Y (fence)", check whether the fence is the
DEPENDENCY or the HOUSING — a zero-dep module in a heavy crate is a layering accident, not a fence.

## ROUND 2 (HEAD 457487275) — RESOLVED, verdict SOUND/CLEAN
All 3 R1 premises dispositioned honestly:
- #3 (unpinned lib.rs hand-copy) GENUINELY CLOSED, not cosmetic: all 9 free-fn validators now
  interpolate `[{WASM_INPUT_VALIDATION_CODE}]` (pub(crate) const in error.rs, imported by lib.rs);
  error_code(Codec) returns the SAME const → allowlist test `codes_match_the_reconciled_allowlist`
  asserts error_code(Codec)=="SCP-VALID-7028" which transitively pins the const value, so any const
  change fails the test AND flips every lib.rs emitter together. Belt: dedicated
  `lib_rs_input_validation_code_is_pinned`. Single-source across both the Codec map path and the
  free-fn path — mechanically airtight. Only remaining literals are docs + wasm-test assertions
  (fail loudly on drift, not emitters).
- #1/#2 (ledger-as-primitive / asymmetric guard) escalated to owner → confirmed the
  sdk-common source-of-truth + check-error-codes.sh (with its REAL, verified documented KNOWN
  LIMITATION at check-error-codes.sh:198-206: Phase-2 doesn't inspect SDK-wrapper literals, "must be
  reviewed manually") is the INTENTIONAL cross-LANGUAGE mechanism; systemic gate-strengthening tracked
  in discussion #2208. This is No-DOA-acceptable, NOT deferral-of-work: the renumber WORK is complete;
  #2208 improves the mechanical GATE (additive, spans all 5 surfaces/all bands), it does not replace
  the ledger. Crucially the R1 "shared const crate would be mechanical" finding LARGELY DISSOLVES
  post-renumber: browser codes are now browser-OWNED + DISJOINT from the native registry (no Rust↔Rust
  duplicated const left to co-locate), and the residual single-source that matters — the union across
  5 LANGUAGES (Swift/Kotlin/TS literals) — is unreachable by any Rust const crate, so the ledger is the
  PERMANENT home, not a placeholder. Ledger no longer overclaims: explicitly states "NOT a claim that
  every SCP code has one meaning across all surfaces," names the pre-existing 7010/7011/7012 + 2003
  overlaps as out-of-scope, and says "not a new enforcement mechanism." No scar tissue.
- VERIFIED empirically: all 12 browser-owned numbers (2082-2086, 4020/4030/4040/4041, 5005,
  7028/7029) ABSENT from native/Swift/Kotlin/ts-native; the only "found elsewhere" hits are the
  ts-wasm SDK wrapper (bindings/typescript-wasm/, the paired consumer) + scp-client ClientError
  doc-comments = the browser's own two-crate surface, exactly as the ledger names. 2003 overload
  CONFIRMED 3-way (error_codes.rs "already exists" / Swift Context.swift:520 "message stream active" /
  Kotlin "not a member") → minting fresh 2083 instead of a 4th meaning is SOUND. 2095 native-registered
  (CTX_2095) = legit shared-meaning reuse. Note the R1 numbers (2077-2080, 7018/7019) were superseded
  by the R2 renumber to 2082-2086/7028/7029 — the codes were re-done to be genuinely cross-surface-free.
