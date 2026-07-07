# AST / structural CI gates: check definitions, stay bounded, back the compiler up

The actor-per-context refactor (ADR-049) ships a family of structural CI gates. They are
worth understanding as a *class*, because they share one design and one set of failure
modes. The terminal lesson from the sharpest of them —
`ast-gate-checks-definition-not-name-resolution.md` — is a prerequisite; this lesson
generalizes it to the whole roster.

## The roster (what each asserts)

- `scripts/check-block-in-place.py` — tree-sitter AST gate banning `block_in_place` /
  `.block_on(…)` in the actor scope. Structural: it flags any identifier that *resolves to*
  `block_in_place` at a call site, including aliased imports and fn-pointer rebinds tracked
  through `let` declarations. Opt-outs come two ways: explicit inline allow-list directives
  (`// ci-allow: block-on: <reason>`) for individual sites, and wholesale file-scope
  exclusions (`crypto/mls/storage.rs`, the `crates/scp-ffi/**` prefix) for boundaries that
  require a sync→async bridge by construction.
- `scripts/check-deleted-primitives.sh` — bans token patterns for primitives the refactor
  deleted, so they cannot reappear (production *and* test scope). Ships with an **empty**
  ban list and is populated only as the corresponding deletions land.
- `scripts/check-construction-pattern.py` — ADR-052 unified-construction gate: forbids
  `*Builder` types / typestate markers and boolean fields for semantic choices in
  construction modules, with a named allowlist for the few legitimately-binary bools.
- `scripts/check-call-invariants.py` — declarative call-precedence rules (from
  `sdk-capability-matrix.json`): a caller matching a `fullmatch` regex must call a required
  callee in-body (or one hop into a same-file helper). `fullmatch` is deliberate so a
  sloppy pattern can't silently capture unrelated helpers.
- `scripts/check-saga-gating-granularity.sh` — ADR-049 §3a: positively asserts the
  per-participant-context-set reservation machinery is present *and* resists the common
  rename/retype laundering of an instance-wide guard. Its own header states it is a
  **tripwire, not a proof**.
- `scripts/check-handle-affinity.sh` + `crates/scp-ffi/uniffi/tests/check_ready_coverage.rs`
  — every FFI method taking a handle-typed parameter must call the per-bridge
  handle-affinity check, so a handle minted by one instance cannot be used against another.

## The three durable properties

**1. Gates check a *definition*, never use-site name resolution.** A sound structural gate
asserts facts about how something is *defined* — a type's visibility, its fields, its
closed set of constructors, the presence of a required call token in a matching function.
The moment a gate tries to answer "does *this argument* at *this call site* resolve to the
trusted binding, unshadowed?" it is reimplementing the compiler's name resolution in an
AST walker, which is an unbounded arms race. `ast-gate-checks-definition-not-name-resolution.md`
is the full autopsy: a gate that crossed that line grew to 6,000+ lines over ~17 review
passes and was ultimately deleted. Draw the line at the definition.

**2. Sound and bounded = positive whitelist, fail-closed, not a growing denylist.** Per
CLAUDE.md §"Guard against over-engineering and non-convergent enforcement," a gate must be
*closed by construction*: a whitelist of permitted shapes that rejects anything else **by
its kind**, not a denylist chasing "one more spelling" of a forbidden thing. The saga-gating
gate resists laundering because it *positively* asserts the reservation store, the
participant-set extractor, and the overlap-reject are wired — its header is candid that a
sufficiently obscure field-name/type could still slip a negative-only scan. That candor is
the point: a denylist is never complete; a whitelist is. And gates must **fail closed** —
see `coverage-gates-must-fail-closed.md` and `fail-closed-gate-escape-hatch-must-be-verified.md`
for how a gate that errors-open silently stops enforcing.

**3. Gates are defense-in-depth, never the primary guarantee.** Where the type system,
a compiler lint, or a cryptographic mechanism already enforces a property *soundly*, a
weaker source-text re-check of the *same* property is **negative value** — a maintenance
liability that rots against language-syntax evolution and gives false confidence. Before
adding or growing a gate, ask CLAUDE.md's three questions: is it sound+bounded; does it
redundantly re-check something already sound; is its cost proportionate? And ask the
capstone question: *can the gate's own threat model defeat the gate?* If the only attacker
is an insider with commit access, and that insider can equally edit the gate and its CI
wiring, the gate adds zero marginal security — prefer the compiler (`OwnedIdentityDid` did
exactly this: see `owned-identity-did-capability.md`).

## The convergence signal

**Review-pass count is diagnostic.** More than ~3 review passes on one gate that keep
surfacing "a new spelling of the same bypass" means the *approach* is non-convergent — stop
and reframe, do not grind. The correct merge-blocking bar for a defense-in-depth gate is a
*compiling, mechanism-evading* counterexample, not a theoretical AST-spelling gap (least of
all one that cannot compile). The `simplifier` review agent is charged with flagging this
class as a BLOCKER; treat it as seriously as a correctness finding.

## Cross-refs

- `ast-gate-checks-definition-not-name-resolution.md` — the terminal, worked-through case.
- `coverage-gates-must-fail-closed.md`, `fail-closed-gate-escape-hatch-must-be-verified.md`,
  `suffix-matcher-becomes-bypass-when-gate-fails-closed.md` — fail-closed gate failure modes.
- `owned-identity-did-capability.md` — a boundary held by the compiler, no gate.
- CLAUDE.md §"Guard against over-engineering and non-convergent enforcement";
  §"NEVER modify enforcement files to bypass failures."
