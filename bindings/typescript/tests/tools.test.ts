/**
 * Tests for the tools module.
 *
 * See ADR-010 (Tool Registry) and `.docs/scaffold/typescript.md`.
 */

import { describe, expect, it } from "bun:test";
import { ValidationError } from "../src/errors.js";
import { defineToolDefinition } from "../src/tools.js";

describe("defineToolDefinition", () => {
  it("creates a valid tool definition", () => {
    const def = defineToolDefinition({
      name: "test-tool",
      description: "A test tool",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: "did:dht:z6MkTest",
    });

    expect(def.name).toBe("test-tool");
    expect(def.description).toBe("A test tool");
    expect(def.operator).toBe("did:dht:z6MkTest");
  });

  it("includes optional fields when provided", () => {
    const testVectors = [{ input: { x: 1 }, expectedOutput: { y: 2 } }];
    const hash = new Uint8Array(32);

    const def = defineToolDefinition({
      name: "test-tool",
      description: "A test tool",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: "did:dht:z6MkTest",
      testVectors,
      implementationHash: hash,
    });

    expect(def.testVectors).toEqual(testVectors);
    expect(def.implementationHash).toBe(hash);
  });

  it("rejects empty tool name", () => {
    expect(() =>
      defineToolDefinition({
        name: "",
        description: "A test tool",
        inputSchema: { type: "object" },
        outputSchema: { type: "object" },
        operator: "did:dht:z6MkTest",
      }),
    ).toThrow(ValidationError);
  });

  it("rejects empty tool description", () => {
    expect(() =>
      defineToolDefinition({
        name: "test-tool",
        description: "",
        inputSchema: { type: "object" },
        outputSchema: { type: "object" },
        operator: "did:dht:z6MkTest",
      }),
    ).toThrow(ValidationError);
  });

  it("rejects empty operator DID", () => {
    expect(() =>
      defineToolDefinition({
        name: "test-tool",
        description: "A test tool",
        inputSchema: { type: "object" },
        outputSchema: { type: "object" },
        operator: "",
      }),
    ).toThrow(ValidationError);
  });
});
