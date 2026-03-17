[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / verifyParticipationRequirements

# Function: verifyParticipationRequirements()

> **verifyParticipationRequirements**(`requirements`, `profiles`): `void`

Defined in: [src/trust.ts:229](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/trust.ts#L229)

Verifies participation profiles against admission requirements.

Delegates to the Rust bridge (`scp-core` via NAPI, or the WASM local
re-implementation), which performs the full verification including:

1. Freshness/staleness checking (`maxAgeSecs`).
2. Distinct signer counting (`minContexts`).
3. Threshold operator semantics (`ParticipationThreshold`).
4. Ed25519 signature verification (both NAPI and WASM via `ed25519-dalek`).

Success is indicated by returning without exception. Verification
failures throw an error with diagnostic details.

## Parameters

### requirements

readonly [`RequireParticipation`](../interfaces/RequireParticipation.md)[]

The participation requirements to verify against.

### profiles

readonly [`ParticipationProfile`](../interfaces/ParticipationProfile.md)[]

The participation profiles to evaluate.

## Returns

`void`

## Throws

If verification fails (with diagnostic details).

## Throws

If the bridge module is not available.
