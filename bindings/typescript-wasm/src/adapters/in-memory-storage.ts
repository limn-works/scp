/**
 * {@link InMemoryStorage} — an ephemeral, process-lifetime {@link JsStorage}.
 *
 * This is a LEGITIMATE production choice (ADR-057 T2), NOT a dev/test stand-in
 * masking a missing durable backend: the embedder KNOWINGLY selects ephemeral
 * storage (a throwaway tab, a stateless Worker, a "lose-device-lose-history"
 * session). Nothing is masked — persistence is honestly absent, and the client's
 * cold-presence restore simply finds an empty store on the next construction.
 * Durability, when wanted, is the explicit opt-in {@link IndexedDbStorage}.
 *
 * It is already synchronous, so it satisfies the driver's synchronous `Storage`
 * contract directly — no write-behind mirror is needed.
 */

import type { JsStorage } from "./types";

export class InMemoryStorage implements JsStorage {
  readonly #map = new Map<string, Uint8Array>();

  /** Returns the value under `key`, or `undefined` if absent. Never throws. */
  get(key: string): Uint8Array | undefined {
    return this.#map.get(key);
  }

  /**
   * Stores `value` under `key`. The wasm boundary already hands over an owned
   * `Uint8Array` copy detached from wasm memory, so it is retained directly.
   */
  set(key: string, value: Uint8Array): void {
    this.#map.set(key, value);
  }

  /** Removes the value under `key`. Idempotent. */
  delete(key: string): void {
    this.#map.delete(key);
  }

  /** Every key starting with `prefix`, in insertion order. */
  listKeys(prefix: string): string[] {
    const out: string[] = [];
    for (const key of this.#map.keys()) {
      if (key.startsWith(prefix)) {
        out.push(key);
      }
    }
    return out;
  }
}
