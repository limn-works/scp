# DID Values in Storage Key Construction

## Problem

The `DID` type (`crates/scp-did/src/lib.rs`) accepts arbitrary strings via `From<&str>` and `From<String>` with no character validation. A DID interpolated into a storage key (`format!("identity/{did}/adapter_credentials/{adapter_id}")`) and containing `/` or `../` addresses keys outside the intended namespace.

## Why It Matters

- The `ProtocolRepository` key convention uses `/` as a hierarchy separator (spec section 17.3).
- Every `ProtocolRepository` domain method that constructs keys from DID values inherits this risk.
- `InMemoryStorage` treats keys as opaque strings, but a filesystem-backed or hierarchical backend does not.
- The adapter_id side of this is already defended: `validate_adapter()` restricts adapter_id to `[a-zA-Z0-9_-]`.

## Correct Approach

Validate at the `DID` type level, not piecemeal at each usage site. The identifier is 32 raw digest bytes (root-authority recovery and fork precedence, `09-security-model.md` §9.7.4.2 R13), so a `DID` wrapping an unvalidated string carries no shape the storage layer can rely on. A constructor that rejects a value containing `/` closes this class across the codebase.

## Affected Files

- `crates/scp-did/src/lib.rs` -- DID type definition
- `crates/scp-runtime/src/store/economy.rs` -- `adapter_credential_key()` constructs keys from DID
- Any future `ProtocolRepository` domain methods using the `identity/{did}/...` key convention

## Found In

SCP-162 crypto review (adapter credential management).
