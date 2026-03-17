# Finding 016: NAPI missing UCAN delegation and context discovery

## Severity: moderate

## Summary

The NAPI bridge is missing UCAN delegation chain creation and context discovery/address resolution.

## Evidence

**UCAN:** `crates/scp-ffi/napi/src/ucan.rs`
- Has: `ucan_validate`, `ucan_mint`, `ucan_revoke`
- Missing: `ucan_delegate` — cannot create delegation chains

**Discovery:** `crates/scp-ffi/napi/src/discovery.rs`
- Has: address parsing, petname set/remove, handle register/lookup/deregister
- Missing: `context_discover()` — discover contexts from DIDs/addresses
- Missing: `address_resolve()` — multi-path address resolution
- Missing: `petname_get_for_did` / `petname_get_for_context` — petname resolution

## Impact

- UCAN delegation chains cannot be created in TypeScript SDK (blocks capability sharing)
- Context discovery from DIDs/addresses unavailable in TypeScript SDK

## Suggested Fix

Port `ucan_delegate` from PyO3 UCAN module and `context_discover`/`address_resolve` from PyO3 discovery module to NAPI bridge.
