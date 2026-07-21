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
 * {@link mapWasmError} routes that prefix through the SAME string-prefix
 * dispatch the NAPI tier uses, so a wasm `SCP-CTX-2005` classifies to
 * `ContextError` exactly as a native one does — classification is by code
 * prefix, never by cross-package object identity (the bounded dual-package
 * `instanceof` residual D1 accepts).
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

import { mapBridgeError, type ScpError } from "@scp-core/errors";

/**
 * Maps an exception thrown across the wasm boundary to a typed {@link ScpError}
 * subclass.
 *
 * wasm-bindgen throws the driver's code-prefixed string
 * (`"[SCP-CRYPTO-4010] …"`) as a JS exception. This delegates to the shared
 * {@link mapBridgeError}, which extracts the bracketed code and dispatches on
 * its category prefix (`code.startsWith(...)`). An already-typed `ScpError`
 * (e.g. one this SDK's own guards threw) passes through untouched.
 *
 * @param error - The raw value caught from a wasm call (string, Error, or unknown).
 * @returns A typed `ScpError` subclass instance.
 */
export function mapWasmError(error: unknown): ScpError {
  return mapBridgeError(error);
}
