# TypeScript Standards

TypeScript coding standards, toolchain, and CI for the SCP TypeScript SDK. References `sdk-common.md` for cross-language invariants and `conventions.md` for git/branch conventions. See `.docs/scaffold/typescript.md` for package structure, build configuration, and type definitions.

## Toolchain

| Tool | Version | Purpose |
|------|---------|---------|
| TypeScript | 5.7+ | Language |
| Bun | latest | Primary runtime (development, testing, scripting) |
| Node.js | 22 LTS | Secondary runtime (compatibility target) |
| tsc | (bundled) | Type checker |
| Biome | latest | Linter + formatter (replaces ESLint + Prettier) |
| bun:test | (built-in) | Test framework (Bun's built-in runner) |
| tsup | latest | Bundler (ESM + CJS output) |

## Biome Configuration

```json
{
  "$schema": "https://biomejs.dev/schemas/latest/schema.json",
  "linter": {
    "enabled": true,
    "rules": {
      "recommended": true,
      "complexity": { "noExcessiveCognitiveComplexity": { "level": "error", "options": { "maxAllowedComplexity": 25 } } },
      "suspicious": { "noExplicitAny": "error" },
      "style": { "useConst": "error", "noNonNullAssertion": "error" }
    }
  },
  "formatter": {
    "indentStyle": "space",
    "indentWidth": 2,
    "lineWidth": 100
  }
}
```

## Code Style

### Strict types

- `strict: true` in tsconfig — no implicit `any`, strict null checks, strict property initialization
- `noExplicitAny` in Biome — `any` is a lint error, use `unknown` and narrow
- `exactOptionalPropertyTypes` — distinguish `undefined` from missing
- `noUncheckedIndexedAccess` — array/object indexing returns `T | undefined`

### Resource management

Use ECMAScript Explicit Resource Management (`Symbol.dispose` / `Symbol.asyncDispose`). Note: `await using` requires `--experimental-explicit-resource-management` flag on Node.js < 24. Bun supports it natively.

```typescript
class Context implements AsyncDisposable {
  async [Symbol.asyncDispose](): Promise<void> {
    if (this.state === "active") {
      await this.leave();
    }
  }
}

// Usage
await using ctx = await Context.create({ ... });
// ctx is automatically disposed when scope exits
```

### Async patterns

All I/O operations return `Promise<T>`. Streaming uses `AsyncIterable<T>`:

```typescript
// I/O operations return promises
async send(message: string | Uint8Array): Promise<void>;

// Streaming results use async iterables
async *receive(): AsyncIterable<Message>;
```

### Naming

- Types/interfaces/classes: `PascalCase`
- Functions/methods/properties: `camelCase`
- Constants: `SCREAMING_SNAKE_CASE`
- Files: `kebab-case.ts`
- Test files: `kebab-case.test.ts`

## Testing

### bun:test

```typescript
// tests/identity.test.ts
import { describe, expect, it } from "bun:test";
import { Identity } from "../src/index.js";

describe("Identity", () => {
  it("creates identity with valid DID", async () => {
    const identity = await Identity.create({ custody: "in_memory" });
    expect(identity.did).toMatch(/^did:dht:/);
  });

  it("rejects invalid custody type", async () => {
    await expect(Identity.create({ custody: "invalid" }))
      .rejects.toThrow(IdentityError);
  });
});
```

### Test naming

Format: `{action} {condition or expected result}` in natural English.

### Conformance tests

```typescript
// tests/conformance/conformance.test.ts
import { describe, it, expect } from "bun:test";
import fixtures from "../../../tests/conformance/identity.json";

describe("conformance", () => {
  for (const fixture of fixtures) {
    it(fixture.description, async () => {
      const result = await runOperation(fixture.operation, fixture.input);
      assertMatches(result, fixture.expected);
    });
  }
});
```

## CI Commands

```bash
# Type check
bunx tsc --noEmit

# Lint + format check
bunx biome check src/ tests/

# Format (write)
bunx biome format --write src/ tests/

# Test
bun test

# Build
bun run build

# Build napi (Bun/Node target)
cd crates/scp-ffi/napi && napi build --release
```

## CI Matrix

| Job | Runs on | Runtime | Trigger |
|-----|---------|---------|---------|
| tsc | ubuntu-latest | Bun | Every PR |
| biome | ubuntu-latest | Bun | Every PR |
| npm audit | ubuntu-latest | Bun | Every PR |
| test (Bun) | ubuntu-latest, macos-latest | Bun latest | Every PR |
| test (Node) | ubuntu-latest | Node 22 LTS | Every PR |
| build-esm | ubuntu-latest | Bun | Every PR |
| build-napi | ubuntu-latest, macos-latest, windows-latest | napi-rs | Every PR |
| conformance | ubuntu-latest | Bun | Every PR |
| publish (npm) | ubuntu-latest | Bun | Tagged release |
