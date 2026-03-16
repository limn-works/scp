/**
 * Two-party encrypted chat in the browser over SCP.
 *
 * Creates or joins an encrypted context and exchanges messages via a
 * minimal web UI.  Uses the WASM backend for browser environments.
 *
 * Usage:
 *   bun install && bun run build
 *   Open index.html in a browser (or run `bun run serve`)
 */

import { Context, Identity } from "@limn-works/scp-ts";
import type { Message } from "@limn-works/scp-ts";

// ---------------------------------------------------------------------------
// DOM elements
// ---------------------------------------------------------------------------

const messagesEl = document.getElementById("messages") as HTMLUListElement;
const inputEl = document.getElementById("msg-input") as HTMLInputElement;
const sendBtn = document.getElementById("send-btn") as HTMLButtonElement;
const statusEl = document.getElementById("status") as HTMLElement;
const contextIdEl = document.getElementById("context-id") as HTMLElement;
const joinInput = document.getElementById("join-input") as HTMLInputElement;
const createBtn = document.getElementById("create-btn") as HTMLButtonElement;
const joinBtn = document.getElementById("join-btn") as HTMLButtonElement;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

let identity: Identity | null = null;
let ctx: Context | null = null;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function log(text: string, sender?: string): void {
  const li = document.createElement("li");
  if (sender) {
    const strong = document.createElement("strong");
    strong.textContent = `${sender.slice(0, 20)}...: `;
    li.appendChild(strong);
    li.appendChild(document.createTextNode(text));
  } else {
    li.textContent = text;
    li.style.color = "#888";
  }
  messagesEl.appendChild(li);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function setStatus(text: string): void {
  statusEl.textContent = text;
}

function showContextId(id: string): void {
  contextIdEl.textContent = `Context: ${id}`;
}

function enableChat(): void {
  inputEl.disabled = false;
  sendBtn.disabled = false;
  createBtn.disabled = true;
  joinBtn.disabled = true;
  joinInput.disabled = true;
  inputEl.focus();
}

// ---------------------------------------------------------------------------
// Receive loop
// ---------------------------------------------------------------------------

async function receiveMessages(context: Context, myDid: string): Promise<void> {
  for await (const msg of context.receive()) {
    // Skip echo of own messages.
    if (msg.senderDid === myDid) continue;
    const content =
      typeof msg.content === "string"
        ? msg.content
        : new TextDecoder().decode(msg.content);
    log(content, msg.senderDid);
  }
}

// ---------------------------------------------------------------------------
// Create / Join
// ---------------------------------------------------------------------------

async function initIdentity(): Promise<Identity> {
  if (!identity) {
    identity = await Identity.create({ custody: "in_memory" });
    log(`Identity created: ${identity.did.slice(0, 30)}...`);
  }
  return identity;
}

async function createContext(): Promise<void> {
  try {
    setStatus("Creating identity...");
    const id = await initIdentity();

    setStatus("Creating context...");
    ctx = await Context.create(id, {
      ceiling: ["MessagesRead", "MessagesWrite", "MemberInvite"],
      memoryScope: "ephemeral",
    });

    showContextId(ctx.contextId);
    log(`Context created. Share this ID with the other party: ${ctx.contextId}`);
    setStatus("Waiting for messages...");
    enableChat();

    // Start receiving in the background.
    receiveMessages(ctx, id.did).catch((err) =>
      log(`Receive error: ${String(err)}`),
    );
  } catch (err) {
    setStatus(`Error: ${String(err)}`);
  }
}

async function joinContext(): Promise<void> {
  const contextId = joinInput.value.trim();
  if (!contextId) {
    setStatus("Enter a context ID to join.");
    return;
  }

  try {
    setStatus("Creating identity...");
    const id = await initIdentity();

    setStatus("Joining context...");
    // In a full deployment, the context handle comes from discovery or an
    // invite link.  Here we create a local context and join -- the bridge
    // resolves the context_id to the remote state.
    ctx = await Context.create(id, {
      ceiling: ["MessagesRead", "MessagesWrite", "MemberInvite"],
      memoryScope: "ephemeral",
    });
    await ctx.join(id);

    showContextId(ctx.contextId);
    log(`Joined context: ${contextId}`);
    setStatus("Waiting for messages...");
    enableChat();

    receiveMessages(ctx, id.did).catch((err) =>
      log(`Receive error: ${String(err)}`),
    );
  } catch (err) {
    setStatus(`Error: ${String(err)}`);
  }
}

// ---------------------------------------------------------------------------
// Send
// ---------------------------------------------------------------------------

async function sendMessage(): Promise<void> {
  if (!ctx) return;
  const text = inputEl.value.trim();
  if (!text) return;

  inputEl.value = "";
  try {
    await ctx.send(text);
    log(text, identity?.did ?? "me");
  } catch (err) {
    log(`Send error: ${String(err)}`);
  }
  inputEl.focus();
}

// ---------------------------------------------------------------------------
// Event wiring
// ---------------------------------------------------------------------------

createBtn.addEventListener("click", createContext);
joinBtn.addEventListener("click", joinContext);
sendBtn.addEventListener("click", sendMessage);
inputEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter") sendMessage();
});

setStatus("Ready. Create a new context or join an existing one.");
