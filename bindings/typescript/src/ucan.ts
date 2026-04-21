/**
 * UCAN module for the SCP TypeScript SDK.
 *
 * UCAN token lifecycle (validate / mint / revoke / delegate) moved onto
 * the {@link SCP} class in Phase 4 PR 4 (#1549, ADR-048):
 *
 * - `scp.ucanValidate(contextHandle, token, capability, ...)` —
 *   full validation pipeline (signature, time bounds, delegation chain,
 *   nonce replay, capability match).
 * - `scp.ucanMint(contextHandle, memberDid, capabilities, proofs?)` —
 *   mint a context-scoped token with the admin's key.
 * - `scp.ucanRevoke(contextHandle, token, revokerDid)` — add to the
 *   context revocation list and append a `TokenRevoked` event.
 * - `scp.ucanDelegate(contextHandle, delegatorDid, delegateeDid,
 *   parentToken, capabilities)` — attenuation-enforced delegation.
 *
 * The free-function shims that predated ADR-048 were deleted in the
 * same commit.
 *
 * See ADR-016 (UCAN Enforcement) and ADR-022 in `.docs/adrs/phase-4.md`.
 */

// Intentionally empty — this module used to export wrappers around the
// above four operations. All consumers now call methods on `SCP`
// directly. Types live in `./types::UcanToken`. The module is kept as a
// placeholder so the barrel export in `./index` stays stable across the
// Agent A → B → C migration. Agent B will remove this file entirely.

export {};
