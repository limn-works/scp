/**
 * Tests for the economy amount display helper (`formatAmount`) and the
 * bigint economy amount boundary (ADR-060).
 *
 * The protocol wire form for a monetary value is a smallest-unit integer
 * (decimal string in JSON, native integer in MessagePack). SDK amounts are
 * exposed as `bigint` to round-trip a full `u64` exactly; `formatAmount`
 * renders the human decimal for display using an SDK-side per-currency
 * decimals table.
 */

import { describe, expect, it } from "bun:test";
import { EconomyError } from "../src/errors";
import { formatAmount } from "../src/index";

describe("formatAmount", () => {
  it("formats a USD amount (2 decimals)", () => {
    expect(formatAmount(150n, "USD")).toBe("1.50");
    expect(formatAmount(0n, "USD")).toBe("0.00");
    expect(formatAmount(5n, "USD")).toBe("0.05");
    expect(formatAmount(1234567n, "USD")).toBe("12345.67");
  });

  it("formats a BTC amount (8 decimals)", () => {
    expect(formatAmount(100_000_000n, "BTC")).toBe("1.00000000");
    expect(formatAmount(1n, "BTC")).toBe("0.00000001");
  });

  it("formats zero-decimal currencies as the bare integer", () => {
    expect(formatAmount(150n, "SAT")).toBe("150");
    expect(formatAmount(0n, "SAT")).toBe("0");
  });

  it("covers the full known-currency decimals table", () => {
    expect(formatAmount(100n, "EUR")).toBe("1.00");
    expect(formatAmount(100n, "GBP")).toBe("1.00");
    expect(formatAmount(1_000_000_000n, "SOL")).toBe("1.000000000");
    expect(formatAmount(1_000_000n, "USDC")).toBe("1.000000");
    expect(formatAmount(10n ** 18n, "ETH")).toBe("1.000000000000000000");
  });

  it("matches currency codes case-insensitively", () => {
    expect(formatAmount(150n, "usd")).toBe("1.50");
    expect(formatAmount(150n, "Usd")).toBe("1.50");
  });

  it("formats amounts larger than 2^53 exactly (no float rounding)", () => {
    // 2^53 + 1 — the first integer JS `number` cannot represent exactly.
    const amount = 9_007_199_254_740_993n;
    expect(formatAmount(amount, "USD")).toBe("90071992547409.93");
    // A full-width u64 near the maximum.
    expect(formatAmount(18_446_744_073_709_551_615n, "USD")).toBe("184467440737095516.15");
  });

  it("accepts an explicit decimals override for unknown currencies", () => {
    expect(formatAmount(1500n, { decimals: 3 })).toBe("1.500");
    expect(formatAmount(42n, { decimals: 0 })).toBe("42");
    expect(formatAmount(123_456n, { decimals: 4 })).toBe("12.3456");
  });

  it("throws EconomyError on an unknown currency with no override", () => {
    expect(() => formatAmount(100n, "XYZ")).toThrow(EconomyError);
    try {
      formatAmount(100n, "XYZ");
    } catch (err) {
      expect((err as EconomyError).code).toBe("SCP-ECON-12070");
    }
  });

  it("throws on a negative amount", () => {
    expect(() => formatAmount(-1n, "USD")).toThrow(EconomyError);
  });

  it("throws on invalid decimals overrides", () => {
    expect(() => formatAmount(1n, { decimals: -1 })).toThrow(EconomyError);
    expect(() => formatAmount(1n, { decimals: 1.5 })).toThrow(EconomyError);
  });
});
