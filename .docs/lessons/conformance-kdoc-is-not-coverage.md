# KDoc `Covers:` Lines Are Not Test Coverage

**Discovered:** SCP-120 review
**Category:** Testing, cross-platform conformance, review methodology

## What Happened

Each conformance test file in `bindings/kotlin/scp-sdk-kotlin/src/test/kotlin/com/limn/scp/conformance/` carries a class-level KDoc listing the protocol operations it covers, copied from `.docs/scaffold/shared.md`. Several listed operations are neither implemented in `ConformanceDispatcher` nor exercised by any `@Test` method:

| File | Claimed in KDoc | Actually Implemented |
|------|----------------|---------------------|
| `IdentityConformanceTest` | rotate key, verify self-certification | create, load, resolve |
| `UcanConformanceTest` | delegate | validate, mint, revoke |
| `ContextConformanceTest` | TTL expiry | create, join, leave, close, state transitions |
| `EncryptionConformanceTest` | sender key create/distribute/rotate/wrapping key lifecycle | MLS error propagation via context_send |
| `TransportConformanceTest` | send envelope, subscribe, multi-relay fanout, dedup | connect, status |
| `EventLogConformanceTest` | append, prove inclusion, consistency checkpoint, absence proof | query, verify |

## Why It Matters

A reviewer scanning KDoc headers gets a false picture of conformance completeness. During acceptance review, this appears as satisfied criteria that are actually open gaps. The docstrings satisfy none of the conformance requirement for the uncovered operations.

## The Rule

When reviewing conformance tests, verify coverage by two independent counts:

1. **Dispatcher `when` branches:** Count the `when (operation)` cases in `ConformanceDispatcher`. Each case is one coverable operation.
2. **`@Test` methods:** Count methods that exercise each dispatcher case.

Cross-check both counts against the category table in `.docs/scaffold/shared.md`. Any operation listed in the table but absent from both the dispatcher and `@Test` methods is uncovered, regardless of what the KDoc says.

KDoc is documentation. `@Test` methods are evidence.

## When Writing Conformance Tests

Do not copy `.docs/scaffold/shared.md` category entries into KDoc unless you are simultaneously adding the dispatcher case and at least one test. If an operation is not yet implemented in the dispatcher, omit it from the KDoc. Aspirational documentation creates phantom provenance.
