# Wrap Error-Sibling Methods Together

**Date:** 2026-07-16
**Source:** PR #2141 review+fix session — Python SDK `identity_remove` family

## The Problem

When adding `_coded_bridge_error` wrapping to a Python SDK method, it is easy to
wrap one method and miss its behavioral sibling. `identity_remove` and
`identity_remove_if_present` (`bindings/python/scp_sdk/scp.py`) have near-identical
semantics — both drop retained identity state for a DID. If only one is wrapped,
the two surface errors through different types:

- wrapped method → a typed `ScpError` subclass (e.g. `IdentityError`)
- unwrapped sibling → the raw native exception from the bridge

## Why This Is a Footgun

A caller reasonably assumes two methods that do the same thing fail the same way.
`try/except IdentityError` around `identity_remove_if_present` silently misses the
raw exception if only `identity_remove` was wrapped. The inconsistency is invisible
at the call site and only shows up on the error path.

## The Pattern

When you wrap one method's errors, wrap its **entire behavioral family** in the same
change. Before finishing, grep for sibling names (`_if_present`, `_or_default`,
paired create/remove, get/list variants) and confirm every member routes errors
through the same `_coded_bridge_error` path.

## How to Catch This

- After adding error wrapping, list the wrapped method's siblings and diff their
  error handling — same wrapper, or a justified reason not to.
- A method and its `*_if_present` / `*_or_*` variant should almost never differ in
  error type.

## Related

- `.docs/lessons/python-bridge-error-message-strip-double-bracket.md`
- `.docs/lessons/test-error-code-fixtures-must-pass-conformance-gate.md`
