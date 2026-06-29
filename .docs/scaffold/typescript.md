# TypeScript SDK Scaffold

> Source of truth: .docs/specs/, .docs/sketch.md, .docs/adrs/. This file is downstream of those documents.

Build blueprint for the SCP TypeScript SDK: package structure, the napi-rs in-process bridge, build configuration, and type definitions. See `.docs/standards/typescript.md` for coding standards (Biome config, style rules, testing, CI).

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
      bridge.ts               # Bridge module exposing the napi-rs backend
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

## In-Process Architecture

The TypeScript SDK runs the protocol engine in-process via a single FFI bridge:

| Target | FFI bridge | Runtime | Use case |
|--------|-----------|---------|----------|
| **Bun/Node** | napi-rs (native addon) | Bun, Node.js | Server-side agents, CLI tools, MCP servers |

Browser clients do **not** run the protocol engine in-process. Per ADR-055 (which supersedes ADR-034), a browser client is a remote thin client: it connects to a server-side `scp-node` over RPC/WebSocket and issues protocol operations remotely. The node holds MLS group state, the actor/supervisor runtime, custody, and the event log. There is no in-browser MLS or protocol execution and no second in-process engine.

### Bridge module

The public API is identical for application code; application code never imports from `internal/`.

### napi-rs binding (Bun/Node)

```
crates/scp-ffi/napi/
  Cargo.toml
  src/lib.rs                # #[napi] annotated functions + structs
  package.json              # napi-rs build output metadata
```

Produces a `.node` native addon loaded at runtime, with direct memory access.

## package.json

```json
{
  "name": "@limn-works/scp-ts",
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
export class UcanPermissionError extends ScpError { name = "UcanPermissionError" as const; }
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

Published as `@limn-works/scp-ts` on npm. Package includes:
- ESM + CJS bundles (via tsup)
- Type declarations (`.d.ts`)
- Pre-built native addon for Bun/Node (platform-specific optionalDependencies)
