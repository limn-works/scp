[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / GovernanceActionResult

# Type Alias: GovernanceActionResult

> **GovernanceActionResult** = `"MemberAdded"` \| `"MemberRemoved"` \| `"RoleChanged"` \| `"ToolRegistered"` \| `"ToolRemoved"` \| `"CeilingModified"` \| `"ContextClosed"` \| `"TtlExtended"` \| `"PruningPolicyModified"` \| `"AdminTransferred"` \| `"SignerAdded"` \| `"SignerRemoved"` \| `"ThresholdModified"` \| `"ChildContextCreated"` \| `"ToolInterfaceEstablished"` \| `"MemberReset"` \| `"ConflictResolved"` \| `"ContextPromoted"` \| `"ReadAccessRevoked"` \| `"ReadAccessRestored"` \| `"WriteAccessRevoked"` \| `"WriteAccessRestored"` \| `"ContentKeysRotated"` \| `"GovernanceReconfigured"` \| `"AuthorBlocked"` \| `"SubscriberBanned"` \| `"SubscriberUnbanned"` \| `"Executed"`

Defined in: [src/types.ts:116](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L116)

Result of executing a governance action (ADR-031).

Each variant corresponds to one of the 28 governance action outcomes.
