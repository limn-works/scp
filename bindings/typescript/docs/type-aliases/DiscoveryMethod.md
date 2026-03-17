[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / DiscoveryMethod

# Type Alias: DiscoveryMethod

> **DiscoveryMethod** = `"OutOfBand"` \| `"None"` \| \{ `SharedContext`: `string`; \} \| \{ `Registry`: `string`; \}

Defined in: [src/provenance.ts:26](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/provenance.ts#L26)

Discovery method describing how the data source was found (§24.2.3).

- `"OutOfBand"` — no protocol-level discovery path (out-of-band introduction).
- `"None"` — backward-compatible alias for `"OutOfBand"`.
- `{ SharedContext: string }` — found via shared context membership.
- `{ Registry: string }` — found via a discovery registry context.
