[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / scpidChallenge

# Function: scpidChallenge()

> **scpidChallenge**(`audience`, `ttlSeconds?`): `Promise`\<[`ScpIdChallenge`](../interfaces/ScpIdChallenge.md)\>

Defined in: [src/auth.ts:77](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/auth.ts#L77)

Generate an SCPID challenge for a relying party (section 3.11.8).

## Parameters

### audience

`string`

URI identifying the relying party
  (e.g. `"https://app.example.com"`).

### ttlSeconds?

`number` = `300`

Challenge validity window in seconds (1-300).
  Defaults to 300.

## Returns

`Promise`\<[`ScpIdChallenge`](../interfaces/ScpIdChallenge.md)\>

A new `ScpIdChallenge`.

## Throws

If `audience` is empty, exceeds 2048 bytes,
  or `ttlSeconds` is 0 or exceeds 300.
