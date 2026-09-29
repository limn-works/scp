# Testing

This standard decides which behavior gets a test and what makes a test useful. Each language file (`rust.md`, `python.md`, `typescript.md`, `kotlin.md`, `swift.md`) says how to write and run a test in that language. The test-quality reviewer (`.claude/agents/test-quality-reviewer.md`) enforces this standard.

## A useful test

**Criterion:** a test is useful only when all four conditions hold.

1. **It runs production code.** The test drives the code through the entry point a real caller uses, not through a fake, a testing hook, or a test-only helper. A fake may stand in for a collaborator outside the code under test, such as the host side of a bridge callback.
2. **One production edit turns it red, and no other test catches that edit.** You can name the edit. A test that no edit can fail, or that fails on the same edits as another test, adds nothing.
3. **Its expected value comes from outside the code under test.** The source is a spec vector, an RFC value, a Wycheproof case, or a literal derived by an independent computation. A value copied from the code's own output, or computed by running the production algorithm again, fails together with the code.
4. **It gives the same result on every run.** The result does not depend on the thread scheduler, the wall clock, test order, or uncontrolled random input.

The tables below list common cases. They help a writer or a reviewer spot the answer quickly. The criterion decides every case, including a case that matches no row.

## What gets a test

| The change | Test? | Where and what shape |
|---|---|---|
| A spec MUST, a security check, or a fail-closed path (authorization, crypto validation, key destroy) | Yes, one per invariant | In the layer that owns the invariant, and in each boundary that transforms the data on its way through |
| A spec vector or a wire format | Yes, once | A known-answer test in the owning crate; a bridge gets one only when it re-encodes the data |
| A bug fix | Yes | A regression test that reproduces the bug and fails without the fix |
| An error-code mapping across an FFI bridge | Yes, one table test per bridge | Not one test per code per call site |
| A secret-redaction guarantee (`Debug`, logs, zeroization) | Yes | A security invariant, although the code looks trivial |
| A hand-written wrapper that passes data to a bridge | Yes, one per wrapper | Call the real bridge with a different value for each argument, and check that each value and the error code arrive unchanged |
| A race or ordering guarantee | Only with a forced interleaving | A test hook or a barrier forces the order; a test that relies on the scheduler is not written |
| A refactor or a docs change with no behavior change | No new test | The existing tests still pass |

## What does not get a test

Each row fails the numbered condition in its last column. Delete such a test when you find one.

| The test | Condition it fails |
|---|---|
| Checks what a fake or test double does, not what production does | 1 |
| Exercises a testing hook or a test-only helper instead of the production entry point | 1 |
| Computes its expected value by running the production algorithm again | 3 |
| Compares a constant to its own literal | 3 |
| Repeats a known-answer vector in a layer that passes the bytes through unchanged | 2 |
| Repeats an error-code check for each call site when one table test per bridge covers it | 2 |
| Tests a third-party library's own property, such as ECDH symmetry or a serde derive round trip | 2 |
| Can never fail, such as `assert_ne!` on two independently random values | 2 |
| Checks that a symbol exists, as `let _ = function_name;` does | 2 |
| Checks that deleted code is gone | 2 |
| Checks which internal calls the code under test makes, or their order | 2 |
| Covers a getter, a setter, a `Default` impl, or a field accessor with no logic | 2 |
| Checks log text, human-readable error wording, or `Debug` output of a non-secret type | 2 |
| Checks a rule that a CI gate or lint already enforces, when that gate has a case that must fail | 2 |
| Relies on the thread scheduler or the wall clock to hit a race | 4 |
| Covers a wrapper that UniFFI or napi-rs generates | 2 |

## Weak tests

A weak test runs production code, but its assertion cannot catch the defect the test exists to catch. Strengthen a weak test when the spec, an ADR, or a security invariant requires the property it targets. Delete it when nothing requires that property.

| Weak test | Why it misses the defect | Strengthen by |
|---|---|---|
| Asserts whatever the code outputs today, with no expected value from outside the code | It passes on a wrong output, and it fails on any change, including a correct one | Taking the expected value from the spec, an RFC, or an independent derivation |
| Asserts a property the type or the construction already guarantees, such as the length of a `[u8; 64]` | No production edit can make it fail | Deleting it |
| Asserts a property no caller or spec depends on, such as map iteration order | A failure would not signal a defect | Deleting it |
| Asserts only `is_err`, only the error variant, only `is_some`, or only `len() > 0` | A different error, or a wrong value, passes the same assertion | Asserting the error code the spec defines, or the exact value |
| Reaches the error through a check earlier than the one under test, such as a point-at-infinity test whose one-byte input fails the length check first | Deleting the check under test leaves the test green | Choosing an input that passes every earlier check |
| Round trip with no known answer: encode then decode, or sign then verify with the same code | A symmetric bug in both halves passes | Adding a fixed vector for one direction |
| Checks that a validator accepts valid input and never that it rejects invalid input | A validator that accepts everything passes | Adding a rejection row for each rule the validator enforces |
| Uses one identity, one context, or one epoch where the defect needs two | Destroying the wrong identity, or ignoring the context, passes | Adding a second instance and asserting that it is untouched, or that it differs |
| Gives distinct arguments the same value | Swapped or dropped arguments pass | Giving each argument a distinct value |
| Asserts the canned value a fake returned | The production code the test claims to cover never ran | Driving the production path with the fake only on the far side of the boundary |
| Holds its assertion inside a loop or an `if let` that may not run | The test passes with zero assertions run | Asserting the collection's length, or unwrapping the match, before the assertion |
| Checks only that a derivation is deterministic | A deterministic wrong derivation passes | Adding a known-answer vector |
