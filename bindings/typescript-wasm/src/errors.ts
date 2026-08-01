/**
 * Error surface for `@limn-works/scp-ts-wasm`.
 *
 * Single-sources the cross-SDK `ScpError` hierarchy and the prefix-dispatch
 * `mapBridgeError` from the shared core (`@limn-works/scp-ts`, imported via the
 * `@scp-core/errors` workspace-source path and BUNDLED into this package at
 * build — ADR-057 Amendment 2026-07-15 D1). There is no drift: one definition,
 * bundled into both tiers.
 *
 * The wasm surface throws JS exceptions whose message carries a stable
 * `[SCP-{CATEGORY}-{NUMBER}]` prefix (`crates/scp-client-wasm/src/error.rs`).
 * The client maps those through {@link mapBridgeError} — the SAME string-prefix
 * dispatch the NAPI tier uses — so a wasm `SCP-CTX-2005` classifies to
 * `ContextError` exactly as a native one does. Classification is by code prefix,
 * never by cross-package object identity (the bounded dual-package `instanceof`
 * residual D1 accepts). `mapBridgeError` is re-exported for cross-tier API
 * symmetry (the error surface is identical across the `-ts` / `-ts-wasm` tiers).
 */

export {
  AttestationError,
  ContextError,
  CryptoError,
  EconomyError,
  GovernanceError,
  IdentityError,
  McpError,
  mapBridgeError,
  OutletError,
  ScpError,
  StorageError,
  TransportError,
  UcanPermissionError,
  ValidationError,
} from "@scp-core/errors";
