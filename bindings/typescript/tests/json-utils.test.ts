/**
 * Tests for the shared safeJsonParse utility.
 *
 * Verifies that malformed JSON produces a ValidationError with the correct
 * error code (SCP-VALID-7001), that the error message includes the function
 * name for debuggability, and that valid JSON still parses correctly.
 */

import { describe, expect, it } from "bun:test";
import { ValidationError } from "../src/errors";
import { safeJsonParse } from "../src/internal/json-utils";

describe("safeJsonParse", () => {
  it("parses valid JSON correctly", () => {
    const result = safeJsonParse('{"key":"value"}', "testFunction");
    expect(result).toEqual({ key: "value" });
  });

  it("parses valid JSON arrays", () => {
    const result = safeJsonParse("[1, 2, 3]", "testFunction");
    expect(result).toEqual([1, 2, 3]);
  });

  it("parses valid JSON primitives", () => {
    expect(safeJsonParse("42", "testFunction")).toBe(42);
    expect(safeJsonParse('"hello"', "testFunction")).toBe("hello");
    expect(safeJsonParse("true", "testFunction")).toBe(true);
    expect(safeJsonParse("null", "testFunction")).toBeNull();
  });

  it("throws ValidationError for malformed JSON", () => {
    expect(() => safeJsonParse("{not valid json}", "testFunction")).toThrow(ValidationError);
  });

  it("throws with error code SCP-VALID-7001", () => {
    try {
      safeJsonParse("{not valid json}", "testFunction");
      // Should not reach here
      expect(true).toBe(false);
    } catch (err) {
      expect(err).toBeInstanceOf(ValidationError);
      expect((err as ValidationError).code).toBe("SCP-VALID-7001");
    }
  });

  it("includes the function name in the error message", () => {
    try {
      safeJsonParse("{bad}", "identity_resolve");
      expect(true).toBe(false);
    } catch (err) {
      expect(err).toBeInstanceOf(ValidationError);
      expect((err as ValidationError).message).toContain("identity_resolve");
    }
  });

  it("includes the function name for different bridge functions", () => {
    const functionNames = [
      "eventLogQuery",
      "eventLogVerify",
      "discoveryParseAddress",
      "contextDiscover",
      "toolInvoke",
      "mcpClientListTools",
      "mcpClientInvoke",
      "provenanceAttach",
    ];

    for (const name of functionNames) {
      try {
        safeJsonParse("<<<invalid>>>", name);
        expect(true).toBe(false);
      } catch (err) {
        expect(err).toBeInstanceOf(ValidationError);
        expect((err as ValidationError).message).toContain(name);
        expect((err as ValidationError).code).toBe("SCP-VALID-7001");
      }
    }
  });

  it("includes the underlying parse error details in the message", () => {
    try {
      safeJsonParse("{bad}", "testFunction");
      expect(true).toBe(false);
    } catch (err) {
      expect(err).toBeInstanceOf(ValidationError);
      // The message should contain something from the original SyntaxError
      const message = (err as ValidationError).message;
      expect(message).toContain("malformed JSON");
      expect(message).toContain("Bridge testFunction");
    }
  });

  it("handles empty string input", () => {
    expect(() => safeJsonParse("", "testFunction")).toThrow(ValidationError);
  });
});
