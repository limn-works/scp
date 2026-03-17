[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / TrustLevel

# Type Alias: TrustLevel

> **TrustLevel** = \{ `kind`: `"DirectExchange"`; \} \| \{ `kind`: `"LocalPetname"`; \} \| \{ `kind`: `"DomainVerified"`; \} \| \{ `kind`: `"AttestationVerified"`; \} \| \{ `kind`: `"DiscoveryContextVerified"`; \} \| \{ `kind`: `"MultiLayerCorroborated"`; `sources`: readonly [`ResolutionPath`](../interfaces/ResolutionPath.md)[]; \}

Defined in: [src/types.ts:582](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L582)

Trust level indicating the strength and source of a handle-to-identifier
binding. Every resolution result carries a trust level.

Trust levels are not strictly ordered -- their relative strength is
context-dependent. The SDK exposes them to consumers; consumers decide
what is sufficient.

Modeled as a discriminated union so that `MultiLayerCorroborated` can
carry its required `sources` field (§22.7).

Variant names use PascalCase matching the spec definitions.

See §22.7 Trust Levels.
