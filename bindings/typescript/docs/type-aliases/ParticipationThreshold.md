[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / ParticipationThreshold

# Type Alias: ParticipationThreshold

> **ParticipationThreshold** = \{ `GreaterThan`: `number`; \} \| \{ `LessThan`: `number`; \} \| \{ `AtLeast`: `number`; \} \| \{ `AtMost`: `number`; \} \| \{ `Equals`: `number`; \}

Defined in: [src/types.ts:500](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L500)

Comparison operator and value for participation admission thresholds.

Used in `RequireParticipation` to specify the comparison a fact value
must satisfy. See §7.3.2.1.

Serialization matches the Rust `ParticipationThreshold` enum:
`{ "GreaterThan": 50 }`, `{ "AtLeast": 100 }`, etc.
