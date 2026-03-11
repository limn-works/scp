# Changelog

All notable changes to SCP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
