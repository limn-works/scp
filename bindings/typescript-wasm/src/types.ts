/**
 * Flat, plain-object result types for the {@link ScpBrowserClient} surface.
 *
 * The wasm-bindgen surface returns opaque `Wasm*` handle classes (getters over
 * wasm linear memory). The wrapper marshals each into a flat, frozen TS
 * interface so callers get idiomatic plain objects with no manual `.free()`
 * lifecycle — the same shape idiom the NAPI `@limn-works/scp-ts` tier uses.
 */

/**
 * A single HPKE-sealed sender-key distribution to deliver (§9.16.1/§9.16.2).
 *
 * The caller routes `ciphertext` — an MLS-encrypted management frame — to
 * `targetDid`'s {@link ScpBrowserClient.receiveMessage}, which installs the key.
 */
export interface SenderKeyDistribution {
  /** The DID this distribution is sealed for (the in-tab delivery hint). */
  readonly targetDid: string;
  /** The MLS-encrypted management frame carrying the HPKE-sealed sender key. */
  readonly ciphertext: Uint8Array;
}

/**
 * The wire output of {@link ScpBrowserClient.addMember}: the bytes to distribute
 * plus the join-replay material the new member needs.
 */
export interface AddMemberOutput {
  /** The TLS-serialized MLS Commit for existing members. */
  readonly commit: Uint8Array;
  /** The TLS-serialized MLS Welcome for the new member. */
  readonly welcome: Uint8Array;
  /** The adder's serialized event-log stream after the add (the joiner replays it). */
  readonly eventLog: Uint8Array;
  /** The adder's serialized member-wrapping-key directory after the add. */
  readonly wrappingKeys: Uint8Array;
  /** The adder's own §9.16 sender key, HPKE-sealed to the new joiner. */
  readonly senderKeyDistributions: SenderKeyDistribution[];
}

/**
 * The outcome of {@link ScpBrowserClient.receiveMessage}: whether an application
 * message was produced, plus any sender-key distributions the receive triggered
 * (the bystander re-distribution trigger — ADR-057 INVARIANT 2).
 */
export interface ReceiveOutput {
  /** `true` if an application message was decrypted (a `MessageReceived` event is buffered). */
  readonly application: boolean;
  /** Sender-key distributions this receive triggered (empty except on an add-Commit as an existing member). */
  readonly senderKeyDistributions: SenderKeyDistribution[];
}

/**
 * A drained context event (`MessageReceived` / `MessageSent` /
 * `PseudonymAnnounced` / other), in JS-friendly form. `kind` discriminates the
 * variant so the surface stays forward-safe if the driver buffers more.
 */
export interface ReceivedEvent {
  /** The event variant name (e.g. `"MessageReceived"`). */
  readonly kind: string;
  /** The sender's DID (empty for a variant that carries none). */
  readonly senderDid: string;
  /** The decrypted plaintext payload (or the 32-byte routing id for `PseudonymAnnounced`). */
  readonly payload: Uint8Array;
}

/**
 * A §5.4.5 `OutletStreamCredit` — the invoker-authored credit grant, as it
 * appears ON THE JSON WIRE that {@link import("./client").outletStreamSignCredit}
 * produces. The browser signs it in-tab and routes it to the node coordinator
 * (SCP-OUT-048); the node's saga validates and applies it.
 *
 * These field names and shapes are BYTE-ACCURATE to the shared `scp-protocol`
 * `serde_json` wire, so `JSON.parse(new TextDecoder().decode(signed)) as
 * OutletStreamCredit` is correct: keys are `snake_case`, the fixed-width byte
 * fields (`request_id`, `sig`) serialize as JSON `number[]` (not `Uint8Array`),
 * and the `u64` `monotonic_seq` serializes as a JSON `number` (a `u64` rendered
 * as a JSON number — exact only up to `Number.MAX_SAFE_INTEGER`).
 */
export interface OutletStreamCredit {
  /** Stream identifier (16 bytes, JSON `number[]`). */
  readonly request_id: number[];
  /** Additional billable chunks the executor may send (`u32`). */
  readonly grant: number;
  /** Per-stream monotonic grant counter (`u64`; rejected as `CreditReplay` on regress). */
  readonly monotonic_seq: number;
  /** The invoker's Ed25519 signature over the §5.4.5 credit-grant preimage (64 bytes, JSON `number[]`). */
  readonly sig: number[];
}

/**
 * The lifecycle status of a held context — the non-throwing predicate form of
 * the poison guard.
 *
 * - `"live"` — held and usable.
 * - `"poisoned"` — a storage write failed after in-memory state advanced
 *   irreversibly; reconstruct the client to recover.
 * - `"absent"` — not held.
 */
export type ContextStatus = "live" | "poisoned" | "absent";
