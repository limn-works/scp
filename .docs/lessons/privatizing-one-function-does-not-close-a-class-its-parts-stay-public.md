# Privatizing One Function Does Not Close a Class While Its Parts Stay Public

**Context**: `DidDocument::verification_method_key(fragment)` resolved a public key from a
DID document by arbitrary fragment string, checking a method's identifier, its type, and
its controller, and reading no verification relationship. Two callers passed an
attacker-controlled fragment to it, so a `#retired-{n}` method an owner had rotated out
still supplied a key that authenticated a bridge login token and a UCAN.

The fix made `verification_method_key` private and left two public callers, each pinning
its fragment: `identity_key` for `#0`, and `signing_key_for` for a `SigningKeyId` plus a
`VerificationRelationship`. A doc comment then claimed the crate exposes no way to resolve
a key by arbitrary fragment string.

That claim was false. `DidDocument::verification_method` is a public `Vec` field,
`VerificationMethod::public_key_multibase` is a public field, `verification_method_by_fragment`
is public and takes a free `&str`, and `decode_multibase_key` is re-exported. Four public
items compose into exactly the function that was privatized, and the composition is weaker
than it: `verification_method_by_fragment` reads neither type nor controller.

`scp_runtime::identity::scpid::scpid_verify` — the SCP-ID sign-in verifier all three FFI
bridges export — was already doing that composition in production, keyed on a
caller-supplied DID rather than the document's own `id`, with `.find()` returning the first
of two identical identifiers.

**Problem**: Privatization removes one name. It removes a capability only when the parts
that reconstruct that name are also unreachable. A reviewer who checks `grep -c "pub fn
verification_method_key"` and reads zero concludes the class is closed, and the doc comment
that says so then travels forward as a fact.

**Root cause**: The class was "a caller composes document fields into a verifying key
without reading a verification relationship." Privatizing one convenience function narrows
one route to that outcome. A data type whose fields are public offers as many routes as a
caller can write.

**Rule**:
- **State a closure claim over the capability, not over one name.** Before writing "this
  crate exposes no way to X," enumerate every public item that participates in X and check
  whether they compose. If they do, either narrow them or state what they are for and what
  composing them costs.
- **Search for the composition, not the symbol.** After privatizing a resolver, grep for its
  constituent parts — the public collection field, the decoder, the by-name lookup — across
  every crate and every binding. The site that already reimplemented it is the one the
  privatization was supposed to catch.
- **Prefer a type that cannot express the wrong call.** `signing_key_for(SigningKeyId,
  VerificationRelationship)` is closed by construction because neither argument can name a
  fragment outside the admitted set. That property comes from the parameter types, not from
  the function's visibility.
- **A universal claim in a commit subject invites a counterexample.** "Gate every DID-document
  key resolver on document facts" was falsified by a resolver the sweep did not find. Either
  enumerate the set the claim covers, or write the claim over the set you checked.

Related: `.docs/lessons/did-string-key-verifies-no-content-signature.md` (the sibling class:
a resolver that reads no document at all), and
`.docs/lessons/ast-gate-checks-definition-not-name-resolution.md` (a check that reads a name
where it should read a definition).
