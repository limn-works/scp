[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / parseAddress

# Function: parseAddress()

> **parseAddress**(`address`): `Promise`\<[`ParsedAddress`](../interfaces/ParsedAddress.md)\>

Defined in: [src/discovery.ts:154](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L154)

Parses an SCP address string into its components.

## Parameters

### address

`string`

The address string to parse (e.g., `"alice@cooking-community"`).

## Returns

`Promise`\<[`ParsedAddress`](../interfaces/ParsedAddress.md)\>

The parsed address object.

## Throws

If the address is malformed.
