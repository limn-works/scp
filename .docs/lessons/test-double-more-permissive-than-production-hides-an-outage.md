# A Test Double More Permissive Than Production Hides an Outage

**Context**: `crates/scp-ffi/common/src/export_verify.rs`, `resolve_export_verifying_key`,
asked its resolver for the verification-method fragment `"active"` and then `"agent"` —
both without a leading `#`. The production resolver,
`IdentityBackedDidResolver::resolve_public_key_by_kid`, absorbed that spelling with a
`kid.strip_prefix('#').unwrap_or(kid)` call. A later commit replaced that line with
`SigningKeyId::from_fragment(kid)`, which decodes `"#active"` and `"#agent"` and returns
`None` for everything else. Every import of a snapshot a remote creator signed then failed
closed, on all three FFI bridges.

The eight tests in that module stayed green. Their `StubResolver` stripped a leading `#`
itself, and a comment recorded that it did so to mirror the production resolver. After the
production resolver stopped stripping, the stub kept stripping, so the pair disagreed and
no test saw it.

**Problem**: A test double that accepts an input the production implementation rejects
reports success over a broken shipped path. The failure it hides is an outage rather than
a forgery — the capability is gone, not weakened — which is why no security test caught it
either. A reviewer reading the suite sees full coverage of `resolve_export_verifying_key`
and every branch green.

**Root cause**: Two spellings of one value sat on either side of a call, and the production
resolver absorbed the mismatch with a normalization step. Removing the absorber exposed a
split that had always been there. The type system could not see it, because the value
crossed the boundary as a `&str` when a two-variant enum, `SigningKeyId`, already modelled
it.

**Rule**:
- **Pair every production caller with the production implementation in at least one test.**
  A suite built entirely on doubles proves the caller and the double agree, which is not the
  claim anyone wants. Add one test that drives the real pair, even when constructing the real
  implementation costs more setup.
- **A test double must reject every input the production implementation rejects.** When you
  write a double, read the production implementation's accepted set and narrow the double to
  match it exactly. A double that is deliberately more permissive needs a comment saying
  which production rejection it suppresses and why the test still means something.
- **Do not normalize at the callee when a type can carry the value.** `strip_prefix('#')`
  inside a resolver is a callee absorbing a caller's spelling. Passing `SigningKeyId` rather
  than `&str` removes the spelling from the interface, and the compiler then finds every
  caller.
- **When you narrow what a function accepts, grep every call site for the inputs you just
  removed.** The commit that introduced `from_fragment` here narrowed one function's accepted
  set and did not sweep its callers for the bare-fragment spelling.

Related: `.docs/lessons/mock-test-must-not-invert-real-bridge-behavior.md` (a double that
encodes the opposite semantics), `.docs/lessons/did-string-key-verifies-no-content-signature.md`
(the resolver class this call site belongs to).
