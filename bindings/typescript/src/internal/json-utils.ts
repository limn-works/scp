/**
 * Shared JSON parsing utilities for the SCP TypeScript SDK bridge layer.
 *
 * The native (napi-rs) bridge returns JSON strings that need parsing. This
 * module provides a safe wrapper around `JSON.parse` that converts raw
 * `SyntaxError` into a descriptive `ValidationError` with error code
 * `SCP-VALID-7001`.
 */

import { ValidationError } from "../errors";

/**
 * Safely parses a JSON string returned from a bridge layer.
 *
 * Wraps `JSON.parse` in a try/catch so that malformed JSON from the bridge
 * layer produces a descriptive `ValidationError` instead of a raw
 * `SyntaxError`.
 *
 * @param json - The JSON string to parse.
 * @param functionName - The bridge function that produced the JSON
 *   (used in the error message for debuggability).
 * @returns The parsed value.
 */
export function safeJsonParse(json: string, functionName: string): unknown {
  try {
    return JSON.parse(json);
  } catch (err) {
    throw new ValidationError(
      `Bridge ${functionName} returned malformed JSON: ${err instanceof Error ? err.message : String(err)}`,
      "SCP-VALID-7001",
    );
  }
}
