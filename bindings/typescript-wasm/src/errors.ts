/**
 * Error surface for `@limn-works/scp-ts-wasm`.
 *
 * Single-sources the cross-SDK `ScpError` hierarchy and the prefix-dispatch
 * `mapBridgeError` from the sibling package's shared core
 * (`../typescript/src/errors`), reached via the `@scp-core/errors` **tsconfig
 * path alias** (a relative-path alias resolved by tsc + esbuild — NOT a
 * node_modules package dependency), and BUNDLED into this package at build so the
 * published package is self-contained (ADR-057 Amendment 2026-07-15 D1). One
 * definition, bundled into both tiers — no drift.
 *
 * The wasm surface throws JS exceptions whose message carries a stable
 * `[SCP-{CATEGORY}-{NUMBER}]` prefix (`crates/scp-client-wasm/src/error.rs`).
 * The client maps those through {@link mapBridgeError} — the SAME string-prefix
 * dispatch the NAPI tier uses — so a wasm `SCP-CTX-2086` classifies to
 * `ContextError` exactly as a native one does. Classification is by code prefix,
 * never by cross-package object identity (the bounded dual-package `instanceof`
 * residual D1 accepts). `mapBridgeError` is re-exported for cross-tier API
 * symmetry (the error surface is identical across the `-ts` / `-ts-wasm` tiers).
 */

// `@scp-core/errors` is a tsconfig path alias to the SIBLING package's internal
// `../typescript/src/errors` (see tsconfig.json `paths`). Reaching into a
// sibling's `src/` is a deliberate, bounded coupling seam — CI-guarded: the
// `typescript-wasm-check` path filter includes `bindings/typescript/src/errors.ts`,
// so a change to the shared error core re-runs this tier's gate.
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
