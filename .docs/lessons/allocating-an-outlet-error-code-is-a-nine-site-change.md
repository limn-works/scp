# Allocating a §5.4.4 Outlet Error Code Touches Nine Sites, and Only Three Fail Loudly

Lesson from the branch that added `SCP-OUTLET-6137` (`execution.signing-refused`)
for §5.4.5 "Signature refusal".

## Decide code-versus-slug by the retry policy, not by novelty

§5.4.4 of `.docs/specs/05-contexts.md` says new failure conditions are minted as
new **slugs** under an existing code. That is the default, and most conditions
take it. §5.4.4 also names the one criterion that overrides it, in the sentence
that explains why `SCP-OUTLET-6132` was split out of `SCP-OUTLET-6131`: the
retry policy is keyed on the *code*, so a condition whose correct policy differs
from its host code's needs a code of its own.

Apply that criterion before writing anything. Ask what a caller should do on
receiving this error, look up the host code's policy in the §5.4.4 registry
table, and split only when the two differ. `SCP-OUTLET-6137` split from
`SCP-OUTLET-6130` because 6130 is `Never` and a signing refusal reported by a
terminal the key just signed is a condition the caller may find cleared.

A second, weaker signal points the same way: `error_code_to_default_slug` maps a
code to one slug, so a condition that rides a host code inherits that code's
default slug wherever a reader resolves the code alone. Riding
`SCP-OUTLET-6130` would have resolved to `execution.handler-panic` — an
executor bug — for an operator's own key refusing to sign.

## `ChunkPayload::Error` has no slug field; the message prefix carries it

The §5.4.5 stream chunk carries `code`, `message`, and `terminal` — no slug.
Every framework-generated terminal on that path commits its §5.4.4 slug as the
message prefix, `format!("{slug}: {suffix}")`:
`CancelAckTracker::cancel_ack_timeout_payload`, `credit_stall_payload`,
`build_pending_terminate_payload`, and the cross-context bridge's synthesized
terminals. A new terminal payload that omits the prefix leaves the code as the
only machine-readable field, and the code resolves to its default slug.

## The nine sites

Three of these fail loudly. Six do not, and a change that stops at the loud ones
compiles, passes clippy, and ships a half-registered code.

Fails the build or a gate:

1. `crates/scp-protocol/src/context/outlets/error_codes.rs` — `ALL_CODES` and
   `ALL_SLUGS` are fixed-size arrays, so a new entry without a length bump is a
   compile error, and a `SLUG_*` constant missing from `ALL_SLUGS` fails
   `tests::all_slugs_lists_exactly_the_defined_slug_constants`, which parses
   this module's own source.
2. `tests/conformance/vectors/outlet_error_fixtures.json` — the cross-SDK
   corpus. `outlet_error_conformance::every_allocated_code_has_a_valid_fixture`
   and `valid_fixtures_cover_every_code_slug_pair` set-equate the corpus against
   the registry, so a code without a fixture fails both.
3. `crates/scp-testing/tests/integration/outlet_error_conformance.rs` —
   `EXPECTED_PAIRS`, which the same two tests compare against. Adding the
   fixture without the pair fails with "fixtures contain unexpected (code, slug)
   pairs not in the registry"; adding the pair without the fixture fails with
   the inverse.

Silent — nothing catches an omission:

4. `error_code_to_class` — an unlisted code returns `None` and the error loses
   its routing class.
5. `error_code_to_default_slug` — an unlisted code returns `None`.
6. `error_code_to_retry_policy` — an unlisted code returns `None`, and the
   caller loses the guidance the code split existed to give.
7. `slug_to_class` — an unlisted slug returns `None`.
8. The module-level doc table in `error_codes.rs`, and its
   "codes … are **reserved**" sentence, which enumerates the unallocated set.
9. `.docs/specs/05-contexts.md` §5.4.4 — the registry table, the class-range
   row's meaning column, the allocated-count sentence ("Only *N* codes are
   allocated"), the retry-guidance paragraph, and the unallocated-gaps sentence,
   which names example gaps by number and must stop naming the one you just
   took.

Run `bash scripts/check-error-codes.sh` as well. It rejects a raw
`"SCP-OUTLET-NNNN"` literal anywhere in Rust outside the registry, including in
a test assertion, and it is **not** in `CLAUDE.md`'s enforcement-file list, so a
local gate sweep driven from that list misses it.

## A source-text enforcement assertion couples to a variable name

`crates/scp-testing/tests/integration/pipeline_wiring.rs`'s AC8 assertion locates
the streaming-saga seal loop by searching the function's source for the literal
`while let Some(chunk) = inner_rx.recv().await`, then brace-matches the body and
asserts over it. Renaming the loop's binder breaks the locator while leaving
every asserted property intact.

When that happens, renaming the binder back is the wrong fix if the new name is
the honest one — here the channel item became a `Result`, so `chunk` would have
named a value that is not a chunk. Update the locator, keep the assertions
byte-identical, and say in the report that an enforcement file was touched and
why. Prefer locating such a loop by a token that does not encode a binder name
when writing a new assertion of this kind.

## Related

- `.docs/lessons/test-error-code-fixtures-must-pass-conformance-gate.md` — the
  fixture corpus half, from the other direction.
- `.docs/lessons/enforcement-wiring-gap.md` — the same shape of multi-site
  registration obligation, on a different registry.
- `.docs/specs/05-contexts.md` §5.4.4 (the registry) and §5.4.5 ("Signature
  refusal").
