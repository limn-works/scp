[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / ParticipationFact

# Type Alias: ParticipationFact

> **ParticipationFact** = `"ParticipationDuration"` \| `"GovernanceActionsAgainst"` \| `"GovernanceActionsBy"` \| `"ToolInvocationCount"` \| `"ContextCreationCount"` \| `"RoleProgressionCount"` \| `"AttestationCount"`

Defined in: [src/types.ts:482](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L482)

Which category of participation fact to evaluate for admission.

Each variant corresponds to one of the 7 fact categories in a
`ParticipationProfile`. See §7.3.2.1.

Values match the Rust `ParticipationFact` enum in `scp-core`.
