# DID Values in Storage Key Construction

## Problem

The `DID` type (`scp-core/src/identity/mod.rs`) accepts arbitrary strings via `From<&str>` and `From<String>` with no character validation. When DID values are interpolated into storage keys (e.g., `format!("identity/{did}/adapter_credentials/{adapter_id}")`), a DID containing `/` or `../` sequences can address keys outside the intended namespace.

## Why It Matters

- The `ProtocolStore` key convention uses `/` as a hierarchy separator (spec section 17.3).
- Every `ProtocolStore` domain method that constructs keys from DID values inherits this risk.
- Current `InMemoryStorage` treats keys as opaque strings (safe), but filesystem-backed or hierarchical storage backends could be vulnerable.
- The adapter_id side of this is already defended: `validate_adapter()` restricts adapter_id to `[a-zA-Z0-9_-]`.

## Correct Approach

Validate DID strings at the `DID` type level, not piecemeal at each usage site. W3C DID Core syntax: `did:method-name:method-specific-id`. The method-specific-id allows `[a-zA-Z0-9._%-]` and `:` separators but not `/`. A validation constructor on `DID` (e.g., `DID::try_new()`) that rejects strings containing `/` would close this class of issue across the entire codebase.

## Affected Files

- `crates/scp-core/src/identity/mod.rs` -- DID type definition
- `crates/scp-core/src/store/economy.rs` -- `adapter_credential_key()` constructs keys from DID
- Any future `ProtocolStore` domain methods using the `identity/{did}/...` key convention

## Found In

SCP-162 crypto review (adapter credential management).
