# Finding 002: Hardcoded placeholder DID in PyO3 tool operator field

## Severity: moderate

## Summary

When converting Python tool parameters to `ContextParams` in the PyO3 bridge, the `operator_did` field of `ToolDefinition` is hardcoded to `"did:key:placeholder"` instead of using the actual tool operator's DID.

## Evidence

**File:** `crates/scp-ffi/src/context.rs`, line 1417

```rust
operator_did: scp_identity::DID("did:key:placeholder".to_owned()),
```

This is inside the `build_params` helper that converts `PyContextParams` to `scp_core::context::ContextParams`. The tool definitions loop (lines 1404-1422) constructs `ToolDefinition` with empty descriptions, empty schemas, zero implementation hashes, and a placeholder operator DID.

## Expected Behavior

The `operator_did` should be set to the DID of the identity creating the context (available as `creator_did` in the context creation flow) or passed through from the Python params.

## Root Cause

Tool definitions in the PyO3 params conversion are minimal placeholders — several fields are zeroed/emptied (implementation_hash: `[0u8; 32]`, test_vectors: empty, signature: empty). The focus was on tool name and schema, not the full definition.

## Suggested Fix

1. Pass the creator DID through to the tool definition's `operator_did`
2. Accept operator DID as a field in the Python tool params dict
3. Also populate `implementation_hash`, `signature`, and other fields from params if provided
