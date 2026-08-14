# OwnedIdentityDid — scanner→compiler sole-minter rebase (sole-minter, HEAD b8b648339)

Change: DELETE source-text CI gate scripts/check-owned-identity-did.py (2217 lines) + fixture
(579) + ci.yml `owned-identity-did` job; ADD `#![deny(non_local_definitions)]` to
supervisor/mod.rs (alongside pre-existing `#![deny(unsafe_code)]`); ADD compile_fail doctest
witness in mod.rs; doc/spec/ADR rewrites; CLAUDE.md over-engineering guardrail; new lesson
ast-gate-checks-definition-not-name-resolution.md. NO code-logic change.

VERDICT: CRYPTO-CLEAN / key-isolation boundary PRESERVED. The deleted scanner was always
defense-in-depth over a property the type system already enforces soundly; its removal loses
no real guarantee the compiler+lints+review don't keep.

Isolation chain (UNCHANGED by diff, re-traced @HEAD):
- mint: supervisor.rs:1421 build_actor_deps → OwnedIdentityDid::issue_for_actor(owning_did.clone());
  `issue_for_actor` is `pub(super)` const fn → ONLY supervisor-module mint path. Arg is the very
  owning_did the rest of the bundle (KP-store, crypto scope) is built for → wrong-owner token
  structurally impossible.
- per-identity-state read: handle.rs:284 my_wrapping_public_key / :305 my_key_package_store take
  `&OwnedIdentityDid`, key the DashMap by `identity.as_did()` (the DID INSIDE the token), NEVER a
  caller-supplied &DID. So an actor reads only its own identity's wrapping key / KP pool. No
  &DID-keyed surface exists.
- struct: `pub(in crate::context) struct OwnedIdentityDid { did: DID }` — field PRIVATE (E0451
  blocks external struct-literal), name-vis pub(in crate::context) (nameable by actor sibling
  module, NOT constructible). No Clone/Copy/Serialize/From/etc derives.

reissue / as_did NON-amplifying (Q2 = YES):
- reissue(&self)->Self: clones self.did, takes NO raw DID param → can only duplicate a token the
  caller already holds; cannot widen reachable identity set. Strictly weaker than issue_for_actor.
- as_did(&self)->&DID: read-only borrow, no From<&DID>/no public ctor → reference cannot
  reconstruct a token. Returns only the token's OWN did (the same one used to key the map). Not a
  cross-identity lookup oracle.
- Both `pub(in crate::context)` (spec §9.4.1 now mandates exactly this, never pub/pub(crate)).

non_local_definitions = CORRECT lint for the one insider vector type-system doesn't cover:
a body-nested `impl OwnedIdentityDid { fn smuggled(did)->Self {..} }` inside a fn — Rust applies
nested impls GLOBALLY (never scopes to enclosing fn) = a 2nd in-module minter. deny→hard compile
error. Verified lint present mod.rs:112; compile_fail doctest witness mod.rs ~L66 guards against a
future toolchain narrowing the lint (doctest would start compiling → test fails). Module-level 2nd
impl + one-token visibility widen are NOT caught by the lint but are visible diffs to a ~155-line
single-struct/single-impl file = review's job (honestly scoped in ADR §5 + file doc).

Crypto-material check (Q4): diff touches ZERO key bytes / zeroization / capability-to-key binding.
Zeroizing<[u8;32]> wrapping secret untouched. forbid(unsafe_code) crate-level (lib.rs:21) +
deny(unsafe_code) module both intact → no transmute/unsafe-Send fabrication.

Enforcement-file rule: deleted script was NEVER in CLAUDE.md protected enforcement-files list
(confirmed vs origin/main) → deletion does not violate "never modify enforcement files". No
dangling refs to the script remain in .github/ or scripts/. pretooluse list unaffected.

Spec/ADR framing (Q3) now ACCURATE: §9.4.1 4-point criterion updated — (1) permits &self-only
reissue, (2) permits read-only &DID accessor, closing line changed from "MUST enforce ... with a
mechanical check (CI lint)" to "MUST enforce ... by the language and compiler — not a bespoke
external scanner". ADR-049 §5 rewritten to 3-layer (type system / lints / review) with honest
per-layer coverage boundaries; tree-sitter-rust dev-dep mention dropped from §Dependencies.

Only residual = the standing colon-join CONDITIONALLY-SOUND-by-design item from prior saga review
is UNRELATED to this diff. No HIGH/MED/LOW. NIT-level only.
