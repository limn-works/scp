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

/** Connects a fully-wired in-browser client and opens a sole-member context. */
async function connect(): Promise<void> {
  const did = didInput.value.trim();
  const url = relayInput.value.trim();
  contextId = contextInput.value.trim();
  if (did === "" || url === "" || contextId === "") {
    append("Provide a pre-provisioned DID, a relay URL, and a context id first.");
    return;
  }

  // On-device key custody (WebCrypto) + durable storage (IndexedDB) are explicit,
  // injected ports — the SDK never reaches for a hidden default. `did` is
  // pre-provisioned; the browser tier does not mint DIDs in-tab (ADR-057).
  const custody = WebCryptoCustody.create({ did });
  const storage = await IndexedDbStorage.open();

  // The managed transport wires the inbound pump + reconnect for you: on every
  // (re)open it re-drives SUBSCRIBEs; on every relay frame it feeds the driver.
  client = await ScpBrowserClient.connect({
    custody,
    storage,
    url,
    onError: (err) => append(`relay pump error [${err.code}]: ${err.message}`),
  });

  // Sole-member context (this tab). Cross-party membership is the #2187 seam below.
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
  // A second participant joins here. Native↔browser invitation-join / HPKE-open
  // custody and the §9.7.1 DID-VM KeyPackage binding are deferred to #2187, so
  // this scaffold stays single-tab. When #2187 lands the join wires through the
  // real API the package already exports (illustrative — intentionally NOT run):
  //   const keyPackage = client.generateKeyPackageForJoin(contextId);
  //   const add = client.addMember(contextId, peerKeyPackage);
  //   client.joinContextEncrypted(contextId, add.welcome, add.eventLog, add.wrappingKeys);
  // No cross-party membership is implemented in this slice.
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
  void connect();
});

sendForm.addEventListener("submit", (event) => {
  event.preventDefault();
  send();
});

// Best-effort cleanup of the render loop + managed transport on unload.
window.addEventListener("beforeunload", () => {
  if (pump !== undefined) {
    clearInterval(pump);
  }
  client?.disconnect();
});
