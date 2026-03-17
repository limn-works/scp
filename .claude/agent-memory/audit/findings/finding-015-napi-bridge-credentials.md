# Finding 015: NAPI bridge credential lifecycle entirely missing

## Severity: moderate

## Summary

The NAPI bridge only exports 3 of 12+ bridge connector functions. The entire credential lifecycle and OAuth PKCE flow are missing.

## Evidence

**File:** `crates/scp-ffi/napi/src/bridge_connector.rs`

NAPI exports only:
- `bridge_evaluate_trust`
- `bridge_register`
- `bridge_create_shadow`

Missing (present in PyO3 `crates/scp-ffi/src/bridge_connector.rs`):
- `bridge_claim_shadow` — claim a shadow identity
- `bridge_seal_shadow_envelope` — encrypt credential data for shadow
- `bridge_open_shadow_envelope` — decrypt sealed shadow credentials
- `bridge_credential_provision` — provision credentials for bridge flows
- `bridge_credential_rotate` — rotate bridge credentials
- `bridge_credential_revoke` — revoke issued credentials
- `bridge_oauth_generate_pkce` — generate PKCE challenge
- `bridge_oauth_build_auth_url` — build OAuth authorization URL
- `bridge_oauth_scopes_for_mode` — get OAuth scopes for bridge mode

## Impact

TypeScript SDK users cannot configure bridge connectors, manage credentials, or use OAuth PKCE flows.

## Suggested Fix

Port the 9 missing bridge connector functions from PyO3 to NAPI bridge.
