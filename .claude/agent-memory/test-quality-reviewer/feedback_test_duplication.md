---
name: Multi-pass agent test generation creates systematic duplication
description: Coder agents that write tests in several batched passes duplicate earlier tests with trivially different inputs instead of extending existing coverage
type: feedback
---

When coder agents write tests in several batched passes ("batch 2 wiring tests", "remaining
tests"), each pass tends to duplicate earlier tests with small variations (a different
context id, a slightly different threshold) instead of checking for existing coverage. One
governance test file grew by 5,440 lines, of which about 2,500 were near-exact duplicates; at
least 25 test functions had functionally identical twins.

**How to apply:** when reviewing agent-written tests, look for duplicate test bodies first and
count the distinct code paths tested, not the number of tests. When dispatching a coder to
write tests, tell it to find existing tests for the same path and extend them with new
assertions rather than add a new function.
