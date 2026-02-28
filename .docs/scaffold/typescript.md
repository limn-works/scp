# TypeScript SDK Scaffold

> Source of truth: .docs/specs/, .docs/sketch.md, .docs/adrs/. This file is downstream of those documents.

Build blueprint for the SCP TypeScript SDK: package structure, dual-target architecture, build configuration, and type definitions. See `.docs/standards/typescript.md` for coding standards (Biome config, style rules, testing, CI).

## Package Layout

```
bindings/typescript/
  package.json
  tsconfig.json
  biome.json
  tsup.config.ts
  src/
    index.ts                  # Re-exports: Identity, Context, ScpError, etc.
    identity.ts               # Identity class, DIDDocument
    context.ts                # Context class, Membership, resource management
    tools.ts                  # ToolDefinition, TestVector interfaces
    trust.ts                  # evaluateTrust(), TrustEvaluation
    event-log.ts              # EventLog class, Event, Proof, Checkpoint
    errors.ts                 # Error hierarchy (ScpError -> subtypes)
    transport.ts              # TransportConfig, relay connection helpers
    types.ts                  # Shared types: Message, Provenance, Capability
    ucan.ts                   # UCAN validate(), mint(), revoke(), delegate()
    mcp.ts                    # serveMcp(), McpClient
    internal/
      native.ts              # napi-rs native addon binding (Bun/Node)
      wasm.ts                 # wasm-bindgen WASM binding (browser)
      bridge.ts               # Unified bridge — selects native or WASM at runtime
  tests/
    identity.test.ts
    context.test.ts
    tools.test.ts
    ucan.test.ts
    transport.test.ts
    event-log.test.ts
    mcp.test.ts
    conformance/
      conformance.test.ts     # Cross-language conformance test runner
  dist/                       # Build output (gitignored)
    index.js                  # ESM bundle
    index.cjs                 # CJS bundle
    index.d.ts                # Type declarations
```

## Dual Target Architecture

The TypeScript SDK supports two runtime environments via different FFI bridges:

| Target | FFI bridge | Runtime | Use case |
|--------|-----------|---------|----------|
| **Browser** | wasm-bindgen (WASM) | Any browser | Web apps, browser extensions |
| **Bun/Node** | napi-rs (native addon) | Bun, Node.js | Server-side agents, CLI tools, MCP servers |

### Bridge selection

Bridge selection logic determines runtime at import time. Implementation must avoid top-level await for CJS compatibility.

The public API is identical regardless of bridge. Application code never imports from `internal/`.

### napi-rs binding (Bun/Node)

```
crates/scp-ffi/napi/
  Cargo.toml
  src/lib.rs                # #[napi] annotated functions + structs
  package.json              # napi-rs build output metadata
```

Produces a `.node` native addon loaded at runtime. Zero WASM overhead, direct memory access.

### wasm-bindgen binding (browser)

```
crates/scp-ffi/wasm/
  Cargo.toml
  src/lib.rs                # #[wasm_bindgen] annotated functions + structs
```

Built via `wasm-pack build --target bundler`. Produces `.wasm` + JS glue code. Async operations use `wasm-bindgen-futures` to bridge Rust futures to JS Promises.

## package.json

```json
{
  "name": "@scp/sdk",
  "version": "0.1.0",
  "type": "module",
  "main": "./dist/index.cjs",
  "module": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "import": "./dist/index.js",
      "require": "./dist/index.cjs",
      "types": "./dist/index.d.ts"
    }
  },
  "files": ["dist/", "README.md", "LICENSE"],
  "scripts": {
    "build": "tsup",
    "check": "tsc --noEmit",
    "lint": "biome check src/ tests/",
    "format": "biome format --write src/ tests/",
    "test": "bun test"
  },
  "engines": {
    "node": ">=22",
    "bun": ">=1.0"
  },
  "devDependencies": {
    "typescript": "^5.7.0",
    "@biomejs/biome": "latest",
    "tsup": "latest"
  }
}
```

## tsconfig.json

```json
{
  "compilerOptions": {
    "target": "ESNext",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "isolatedModules": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "outDir": "dist",
    "rootDir": "src"
  },
  "include": ["src/**/*.ts"],
  "exclude": ["node_modules", "dist"]
}
```

## tsup Configuration

```typescript
// tsup.config.ts
import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  target: "esnext",
  splitting: false,
});
```

## Error Handling

```typescript
export class ScpError extends Error {
  constructor(
    message: string,
    readonly code: string,  // e.g., "SCP-CTX-2001"
  ) {
    super(message);
    this.name = "ScpError";
  }
}

export class IdentityError extends ScpError { name = "IdentityError" as const; }
export class ContextError extends ScpError { name = "ContextError" as const; }
export class PermissionError extends ScpError { name = "PermissionError" as const; }
export class CryptoError extends ScpError { name = "CryptoError" as const; }
export class TransportError extends ScpError { name = "TransportError" as const; }
export class ToolError extends ScpError { name = "ToolError" as const; }
export class ValidationError extends ScpError { name = "ValidationError" as const; }
```

## Interfaces

```typescript
interface ContextParams {
  ceiling: string[];
  tools?: ToolDefinition[];
  roles?: Record<string, string[]>;
  ttl?: number;           // seconds
  memoryScope?: "ephemeral" | "summary" | "full";
  governance?: "single_admin";
}

interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;   // JSON Schema
  outputSchema: Record<string, unknown>;  // JSON Schema
  operator: Identity | string;
  testVectors?: TestVector[];
  implementationHash?: Uint8Array;
}

interface Message {
  senderDid: string;
  content: string | Uint8Array;
  timestamp: number;
  sequence: number;
  contextId: string;
  provenance?: Provenance;
}
```

## npm Publishing

Published as `@scp/sdk` on npm. Package includes:
- ESM + CJS bundles (via tsup)
- Type declarations (`.d.ts`)
- Pre-built native addon for Bun/Node (platform-specific optionalDependencies)
- WASM bundle for browser (included in main package)
