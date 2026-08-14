# BLACK-G06: check-owned-identity-did.py cfg(not(test)) macro-ban bypass

Branch feat/actor-2e-owned-identity (saga-2e worktree), gate scripts/check-owned-identity-did.py.
Cycle-5 finding. Self-test (23 modes) + real scan both PASS at baseline.

## The hole (HIGH/CRITICAL, in-remit, NOT out-of-remit)
`_attr_is_cfg_test` (line ~786) classifies ANY cfg attribute containing a word-boundaried
`test` token (string-stripped) AFTER `cfg(` as a test gate — with NO understanding of
not()/any()/all() boolean semantics. So these PRODUCTION-active forms are mis-exempted:
  - `#[cfg(not(test))]`            -> production-ONLY, exempted
  - `#[cfg(all(not(test)))]`       -> production-ONLY, exempted
  - `#[cfg(not(all(test)))]`       -> production-ONLY, exempted
  - `#[cfg(any(test, feature="x"))]` -> compiles in prod when feature on, exempted
The declaring-file macro CATEGORY BAN (the whole point of the BLACK-G05 redesign, since
tree-sitter can't expand macros) consults `_inside_cfg_test`->`_has_preceding_cfg_test`->
`_attr_is_cfg_test`. Wrap a prod macro in `#[cfg(not(test))] mod m { ... }` in
identity_capability.rs and the macro ban is fully bypassed.

PROBE 3c (confirmed PASS = forgery): a metavar macro under cfg(not(test)) synthesizing
`pub(in crate::context) fn forge_any(did) -> Self { Self { did } }` — mints a token for
ANY raw DID, reachable by any context-module handler, AST-invisible. PROBE 9: paste!
token-split `impl super::[<Owned Identity Did>]` under cfg(not(test)) — the EXACT G05
evasion the redesign claimed to close, reopened.

## Why this is in-remit (type system does NOT save us)
Inside identity_capability.rs the private field `did` and pub(super) issue_for_actor are
both reachable (same module). A macro there genuinely CAN construct/forge. The category
ban is the ONLY defense for AST-invisible mints in this file. cfg(not(test)) defeats it.

## Why it's not theoretical
The crate uses `#[cfg(any(test, feature = "testing"))]` PERVASIVELY (provider.rs,
supervisor.rs, mod.rs, key_package_actor.rs ...). That idiom is mis-classified as a test
gate AND is production-active when `testing` feature is on. An attacker's prod macro under
that idiom looks completely native to the codebase.

## Root cause / fix direction
`_attr_is_cfg_test` must return True only when activation REQUIRES `test` — i.e. `test`
appears NOT negated and NOT merely one disjunct of an `any(...)`. Simplest robust fix:
treat as test-gate only `cfg(test)` exactly, or a cfg where every activating config
includes test (test as top-level predicate or sole/all-of an `all(...)`), and explicitly
reject if `not(` or `any(` encloses the test token. Declaring file only uses plain
`#[cfg(test)]` so a strict fix does NOT false-fail real code. Add fixture modes:
cfg(not(test)) macro, any(test,feature) macro -> must FAIL.

## Probes that CORRECTLY held (gate robust)
- Probe 1/2: prod macro after cfg(test) block / cfg(not(test)) directly on macro -> CAUGHT
  (_inside_cfg_test walks ANCESTORS not siblings; attr directly on the node isn't consulted).
- Probe 4/5: generic/assoc-type trait mint w/ standalone alias -> CAUGHT by F.2 alias ban.
- Probe 6/7: assoc-type / FQ-projection return -> CAUGHT (_returns_self over-matches `Self`
  and literal `OwnedIdentityDid` token anywhere in return text).
- Probe 8: `impl Mint for u8` returning cap -> PASSES gate but NOT a forgery (out-of-remit,
  type system primary: issue_for_actor is pub(super), private field unreachable from u8 impl).
- Probe 10: #[path] climbing ../ back into src -> PASSES (legitimately in-src, scanned).
