[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / BroadcastAdmissionPolicy

# Type Alias: BroadcastAdmissionPolicy

> **BroadcastAdmissionPolicy** = `"Open"` \| `"Gated"`

Defined in: [src/types.ts:65](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L65)

Admission policy for a broadcast context.

- `"Open"` — any DID can subscribe without authorization.
- `"Gated"` — subscription requires a valid `messages:read` UCAN.
