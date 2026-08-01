/**
 * scaffolds/typescript-web — a single-tab in-browser SCP participant over
 * `@limn-works/scp-ts-wasm` (ADR-057).
 *
 * Structural scaffold only (spec §21.12: scaffolds are *structural* —
 * placeholder identity + context creation, no application logic; templates are
 * *functional*). It wires the real package API end to end: on-device WebCrypto
 * custody, IndexedDB storage, the managed WebSocket relay transport, a context,
 * a `sendMessage` path, and a `drainEvents` render loop. Where relay-mediated
 * cross-party invitation-join would go there is a clearly-marked seam deferred to
 * #2187 (its §9.7.1 DID-VM KeyPackage binding is not yet in the wasm tier).
 *
 * The wasm tier does NOT mint DIDs in-tab: `did` is pre-provisioned by your
 * identity flow and pasted into the form. Keys are held on-device (see the
 * package caveats — the MLS signing key is still extractable pre-#1980).
 */

import {
  IndexedDbStorage,
  ScpBrowserClient,
  ScpError,
  WebCryptoCustody,
} from "@limn-works/scp-ts-wasm";

/** Looks up a required element by id, throwing a clear error if the markup drifted. */
function required<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (el === null) {
    throw new Error(`scaffold markup is missing #${id}`);
  }
  return el as T;
}

const connectForm = required<HTMLFormElement>("connect-form");
const sendForm = required<HTMLFormElement>("send-form");
const didInput = required<HTMLInputElement>("did");
const relayInput = required<HTMLInputElement>("relay");
const contextInput = required<HTMLInputElement>("context");
const messageInput = required<HTMLInputElement>("message");
const connectButton = required<HTMLButtonElement>("connect");
const sendButton = required<HTMLButtonElement>("send");
const log = required<HTMLElement>("log");

/** Appends one line to the activity log (an `aria-live` region). */
function append(line: string): void {
  const entry = document.createElement("div");
  entry.textContent = line;
  log.append(entry);
}

let client: ScpBrowserClient | undefined;
let contextId = "";
let pump: ReturnType<typeof setInterval> | undefined;

/** Tears down the render loop + managed transport before any reconnect (idempotent). */
function teardown(): void {
  if (pump !== undefined) {
    clearInterval(pump);
    pump = undefined;
  }
  client?.disconnect();
  client = undefined;
}

/** Connects a fully-wired in-browser client and opens a sole-member context. */
async function connect(params: { did: string; url: string; contextId: string }): Promise<void> {
  // Defensive: clear any prior client/pump before reassigning, so a repeat
  // connect never leaks a still-reconnecting WebSocket or a live interval.
  teardown();

  // On-device key custody (WebCrypto) + durable storage (IndexedDB) are explicit,
  // injected ports — the SDK never reaches for a hidden default. `did` is
  // pre-provisioned; the browser tier does not mint DIDs in-tab (ADR-057).
  const custody = WebCryptoCustody.create({ did: params.did });
  const storage = await IndexedDbStorage.open();

  // The managed transport wires the inbound pump + reconnect for you: on every
  // (re)open it re-drives SUBSCRIBEs; on every relay frame it feeds the driver.
  // `onError` covers the ONGOING relay pump only — init failures propagate out of
  // this async function to the submit handler's `.catch` and reach the same log.
  client = await ScpBrowserClient.connect({
    custody,
    storage,
    url: params.url,
    onError: (err) => append(`relay pump error [${err.code}]: ${err.message}`),
  });

  // Sole-member context (this tab). Cross-party membership is the #2187 seam below.
  contextId = params.contextId;
  client.createContext(contextId);
  append(`Connected as ${client.did}; created context "${contextId}".`);
  sendButton.disabled = false;

  // ── drainEvents render loop ────────────────────────────────────────────────
  // Poll the driver's buffered events and render inbound application messages.
  // The managed transport feeds handleRelayFrame; we drain what it produces.
  pump = setInterval(() => {
    if (client === undefined) {
      return;
    }
    for (const event of client.drainEvents(contextId)) {
      if (event.kind === "MessageReceived") {
        append(`${event.senderDid}: ${new TextDecoder().decode(event.payload)}`);
      }
    }
  }, 500);

  // ── PLACEHOLDER seam: relay-mediated cross-party invitation-join (#2187) ─────
  // In a REAL two-party flow the ADDER and the JOINER are DIFFERENT clients, and
  // the roles do not run on one `client`:
  //   • ADDER (an existing member): `createContext` then, given the joiner's key
  //     package, `addMember(contextId, joinerKeyPackage)` → { welcome, eventLog,
  //     wrappingKeys, … }.
  //   • JOINER (the newcomer): `generateKeyPackageForJoin(contextId)` to hand to
  //     the adder, then `joinContextEncrypted(contextId, welcome, eventLog,
  //     wrappingKeys)` with the adder's returned material.
  // Those artifacts are exchanged out-of-band today; relay-mediated exchange (and
  // the §9.7.1 DID-VM KeyPackage binding it needs) is deferred to #2187, so this
  // scaffold stays single-tab and implements NEITHER role's cross-party half.
  // See bindings/typescript-wasm/examples/browser-roundtrip.ts for the full flow.
}

/** Encrypts one message and fans it out over the relay to announced peers (§9.10.4). */
function send(): void {
  if (client === undefined || contextId === "") {
    return;
  }
  const text = messageInput.value;
  if (text === "") {
    return;
  }
  try {
    client.sendMessage(contextId, new TextEncoder().encode(text));
    append(`you: ${text}`);
    messageInput.value = "";
  } catch (error) {
    // SCP-CTX-2040 (no peer pseudonym announced yet) is the expected single-tab
    // outcome — there is no second participant until the #2187 join seam lands.
    const code = error instanceof ScpError ? error.code : "unknown";
    append(`send unavailable [${code}] — no peer has joined yet (cross-party join is #2187).`);
  }
}

connectForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const did = didInput.value.trim();
  const url = relayInput.value.trim();
  const context = contextInput.value.trim();
  if (did === "" || url === "" || context === "") {
    append("Provide a pre-provisioned DID, a relay URL, and a context id first.");
    return;
  }
  // Teach secure transport mechanically: relays are untrusted, so a plaintext
  // ws:// link (which leaks transport metadata) is refused — wss:// only.
  if (!url.startsWith("wss://")) {
    append("Relay URL must use wss:// — relays are untrusted; ws:// leaks transport metadata.");
    return;
  }
  // Guard re-entry: disable Connect while a connect is in flight (and while
  // connected). A failed connect re-enables it so the user can retry.
  connectButton.disabled = true;
  void connect({ did, url, contextId: context }).catch((error: unknown) => {
    const code = error instanceof ScpError ? error.code : "unknown";
    const message = error instanceof Error ? error.message : String(error);
    append(`connect failed [${code}]: ${message}`);
    teardown();
    sendButton.disabled = true;
    connectButton.disabled = false;
  });
});

sendForm.addEventListener("submit", (event) => {
  event.preventDefault();
  send();
});

// Best-effort cleanup of the render loop + managed transport on unload.
window.addEventListener("beforeunload", () => {
  teardown();
});
