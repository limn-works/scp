# Changelog

All notable changes to SCP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2026-03-16

### Security

- PCS break fixed (#1250) — `recovery_advance_epoch` now performs real MLS epoch advance
- Relay swap attack fixed (#1222) — leaf hash verification in `RelayBlobColdProvider`
- Kotlin JSON injection fixed (#1203) — `buildJsonObject` replaces string concatenation
- PSK nonce hardened (#1246) — random nonce replaces deterministic SHA-256
- Checkpoint signature verification (#623) — Ed25519 verification before comparison
- JCS compliance (#1252) — RFC 8785 canonical JSON for all hashing paths
- UCAN capability URI format (#1293) — fixed resource/action split mismatch across all 5 bridges
- MLS crypto snapshot Debug redaction (#706) — prevent key material exposure in logs
- Mutex poison partial state prevention (#712) — MLS `restore_crypto_state` atomicity
- Webhook replay protection and error code collision fixes (#1237)
- Decryption failures return 404 to prevent oracle (#1291)
- X-Forwarded-For trusted-proxy SHOULD upgraded to MUST (#1292)

### Added

- **WASM MLS encryption** (#602) — browser clients can now participate in encrypted contexts
- **Provenance event log recording** (#586) — `ProvenanceAttached`/`ProvenanceReceived` events across all 4 FFI bridges
- **Broadcast content delivery** — `BroadcastContent`, `ContentMetadata`, `ContentPath`, `MimeType` types (SCP-287)
- **Path-indexed projection endpoint** with atomic deploys (SCP-288, SCP-289)
- **Trust aggregation** exposed across all 4 bridges and SDKs (#596)
- **Economic governance** exposed across all 4 bridges (#613)
- **Media subsystem** exposed through FFI bridges (#597)
- **Bidirectional consent protocol** across all 4 bridges and SDKs (#579)
- **Invitation evaluation pipeline** with WASM security checks (#614)
- **Provenance privacy functions** across all 4 bridges (#585)
- **Bridge subsystem operations** through PyO3 bridge (#616)
- **MCP operations** exposed through UniFFI bridge for Swift/Kotlin (#591)
- **Tool session and cross-context invocation** wrappers for TypeScript and Kotlin (#526)
- **SCPID auth wrappers** for all 4 SDKs (#1058, #1059)
- **Identity advanced operation** test coverage across all SDKs (#428)
- **Governance pipeline and context lifecycle** methods exposed through FFI (#559)
- **MetadataRecord and ContextTemplate inspection** exposed through FFI (#615)
- **DegradedMode** with graceful degradation behavior (#606)
- **Participation types** added to TypeScript SDK with WASM bridge (#426)
- **Broadcast unblock** implemented across all layers (#617)
- **Min protocol version** added to `ContextParams` per spec section 13 (#607)
- **MLS group state and sender key persistence** across restarts (#645)
- **Encryption at rest** via sealed `EncryptedStorage` trait (#695)
- **Economic policy** set/get exposed across all FFI bridges and SDKs (#713)
- `cargo deny` configuration for dependency auditing

### Fixed

- **NAPI backend**: 82 tests passing (from 33), identity registry fallback, `MemberRole` case, DID resolver seeding (#1144, #1236)
- **Python SDK**: all 4 examples updated to match post-refactor API (#1297)
- **UCAN spec documentation**: two-tier validation design clarified (#1281)
- UCAN revocation pipeline wired with authorization and event logging (#499)
- `ToolCost` aligned with spec section 5.4.1 — renamed fields, added currency (#934)
- Error code harmonization across PyO3/UniFFI/NAPI/WASM bridges (#537)
- WASM sequence field harmonized to f64 matching NAPI (#1022)
- Swift `Context.lastError` stored instead of discarded (#541)
- Swift concrete `ContextHandle` in bridge function typealiases (#1018)
- Kotlin `toolVerifyResult` changed from Boolean to String (#1010)
- Kotlin `identityHandle` added to `ScpContextHolder` and `rememberScpContext` (#1009)
- TypeScript broadcast state preserved in mock `contextImport` (#1007)
- TypeScript `ucanToken` made required in `Context.invokeTool` (#745)
- TypeScript JSON.parse calls wrapped with safe error handling (#681)
- NAPI `PascalCase` `ParsedAddress` variant tags per spec (#737)
- WASM `DID` validation added to `context_leave` (#740)
- WASM `ucan_token` passed through `tool_invoke` bridge (#554)
- Governance timeout task with deadlock detection (#581)
- Sync TOCTOU race eliminated in reset request nonce tracking (#572)
- Sync mutual removal check in governance conflict resolution (#576)
- Context version check moved before crypto ops in `join_context` (#715)
- Context TTL expiry errors propagated with retry and observability (#612)
- Event log accepts pruned logs on restore (#705)
- Forward-compatible deserialization and FFI timestamp guards (#593, #538)
- Outbound queue ordering and bound enforcement (#709)
- Provenance rejects empty context IDs in discovery method parsing (#741)
- `SnapshotCodecFailed` renamed, `reconcile_epoch` returns Failed for unknown epoch (#1179, #1180)
- `Retry-After` field added to `InterfaceRateLimited` error (#1110)
- Typed `Capability` enum in `check_media_capability` replaces string comparison (#1042)
- Persistent `SenderKeyStore` in `bridge_create_shadow` (#539)
- NAPI `HANDLE_COUNT` underflow prevention (#1263)
- Envelope `deny_unknown_fields` removed from wire types per spec (#723)
- Event log per-entry keys for O(1) append persistence (#710)
- `ContextSnapshot` clone eliminated in persist (#711)

### SDK Validation

- **Kotlin**: 227 tests pass, detekt clean
- **Swift**: 437 tests pass, SwiftLint/SwiftFormat clean
- **Python**: 488 tests pass, ruff clean
- **TypeScript**: NAPI backend 82 tests pass, type checks clean

## [0.1.0] - 2026-03-11

Initial release of the Shared Context Protocol SDK.

### Added

- **Identity**: DID-based cryptographic identity with `did:dht` and `did:web` methods
- **Contexts**: Bounded, encrypted interaction spaces with MLS group encryption
- **Governance**: 4-engine governance system with 28 action types
- **Trust**: Behavioral fact statements, contextual trust scoring, content access control
- **UCAN**: Capability-based authorization with delegation chains
- **Transport**: Native relay protocol with 17 adapter targets across 3 tiers
- **Provenance**: Merkle event log with cryptographic audit trail
- **Discovery**: Context discovery, search, and federation
- **Media**: Media key derivation and signaling
- **MCP Bridge**: Model Context Protocol integration for AI agent connectivity

### SDK Packages

- **Rust**: `scp-core`, `scp-transport`, `scp-platform`, `scp-mcp` on crates.io
- **Python**: `scp-python` on PyPI
- **TypeScript**: `@limn-works/scp-ts` on npm (WASM + native NAPI addon)
- **Kotlin**: `works.limn:scp-kt` and `works.limn:scp-kt-android` on Maven Central
- **Swift**: `SCP` via SwiftPM (GitHub Releases)
