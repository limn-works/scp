/**
 * The branded, validating {@link Credit} stream-credit grant (§5.4.5) for the
 * browser-invoker streaming surface (SCP-OUT-048).
 *
 * This is a faithful MIRROR of the native `Credit` in the sibling NAPI tier
 * (`bindings/typescript/src/outlets.ts`) — same brand, same `[1, 2**32)`
 * validation, same `.value` accessor, same uniform {@link InvalidGrant} on a
 * bad value. It is re-implemented here (not imported) DELIBERATELY: the native
 * `Credit` lives in a module that also imports the NAPI addon surface, so
 * importing it into the wasm tier would drag node-only code into the browser
 * bundle and break the `node:`-free guard (`guard:node-free`). The two
 * definitions are kept byte-for-byte behaviorally identical so the developer
 * API shape is canonical across both `-ts` and `-ts-wasm` tiers.
 */

import { InvalidGrant } from "./errors";

/** Exclusive upper bound of the `u32` credit-grant range: `1 <= grant < 2**32`. */
const U32_CEIL = 2 ** 32;

/**
 * A validated, non-zero `u32` stream-credit grant (§5.4.5).
 *
 * Construct with `new Credit(n)`. `n` MUST be an integer in the half-open
 * interval `[1, 2**32)`. Any other value — `0`, a negative, `>= 2**32`, or a
 * non-integer / non-number — throws {@link InvalidGrant} at construction (the
 * SCP-OUT-031 round-6 uniform rule; never a bare `RangeError` / `TypeError`).
 *
 * {@link import("./outlet-stream-session").BrowserInvokerStreamSession.grantCredit}
 * consumes a `Credit`, never a raw `number` — the private brand makes
 * `session.grantCredit(10)` a `tsc` type error (there is no implicit
 * `number` → `Credit` coercion), forcing the caller through the validating
 * constructor. The canonical accessor field is `.value` in every SDK.
 *
 * @example
 * ```ts
 * await session.grantCredit(new Credit(4));
 * ```
 */
export class Credit {
  /**
   * Nominal brand: a `private` member makes `Credit` structurally unforgeable,
   * so neither a raw `number` nor a bare `{ value: n }` object satisfies the
   * type — only an instance minted by this validating constructor.
   */
  private readonly __creditBrand = true;

  /** The validated grant magnitude (a non-zero `u32`). */
  readonly value: number;

  constructor(value: number) {
    if (typeof value !== "number" || !Number.isInteger(value)) {
      throw new InvalidGrant(`Credit must be an integer in [1, 2**32), got ${String(value)}`);
    }
    if (value < 1 || value >= U32_CEIL) {
      throw new InvalidGrant(`Credit must be a non-zero u32 in [1, 2**32), got ${value}`);
    }
    // Touch the brand so it is not reported as an unused private member.
    void this.__creditBrand;
    this.value = value;
  }
}
