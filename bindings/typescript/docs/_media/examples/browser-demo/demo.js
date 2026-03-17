/**
 * SCP Browser Demo — demonstrates core protocol operations via the WASM module.
 *
 * Operations demonstrated:
 *   1. Initialize WASM module
 *   2. Create a DID identity
 *   3. Create a governed context
 *   4. Register a tool in the context
 *   5. Send a message to the context
 *   6. Attach provenance metadata (cross-context data flow)
 *   7. Query the event log (Merkle-backed)
 *   8. Evaluate provenance quality tier
 *
 * Prerequisites:
 *   wasm-pack build crates/scp-ffi/wasm --target web --out-dir bindings/typescript/examples/browser-demo/pkg
 *
 * Serve:
 *   cd bindings/typescript/examples/browser-demo && python3 -m http.server 8080
 *   Open http://localhost:8080
 */

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------

const QUALITY_TIERS = {
  0: "NoProvenance",
  1: "EphemeralKnownParties",
  2: "SummaryVerified",
  3: "PersistentVerifiable",
};

function setStatus(step, status, label) {
  const el = document.getElementById(`status-${step}`);
  el.className = `step-status status-${status}`;
  el.textContent = label || status;
}

function setOutput(step, html) {
  const el = document.getElementById(`output-${step}`);
  el.innerHTML = html;
  el.classList.add("visible");
}

function showError(msg) {
  const el = document.getElementById("error-banner");
  el.textContent = msg;
  el.classList.add("visible");
}

function kv(key, value) {
  return `<span class="key">${esc(key)}</span>: <span class="val">${esc(String(value))}</span>`;
}

function esc(s) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function addSummaryItem(label, value) {
  const li = document.createElement("li");
  li.innerHTML = `<span class="label">${esc(label)}:</span> ${esc(String(value))}`;
  document.getElementById("summary-list").appendChild(li);
}

// ---------------------------------------------------------------------------
// Demo runner
// ---------------------------------------------------------------------------

/** @type {() => Promise<void>} */
async function runDemo() {
  const btn = document.getElementById("run-btn");
  btn.disabled = true;

  // Reset UI state.
  document.getElementById("error-banner").classList.remove("visible");
  document.getElementById("summary").classList.remove("visible");
  document.getElementById("summary-list").innerHTML = "";
  for (let i = 1; i <= 8; i++) {
    setStatus(i, "pending", "pending");
    const out = document.getElementById(`output-${i}`);
    out.innerHTML = "";
    out.classList.remove("visible");
  }

  try {
    await runDemoSteps();
  } catch (err) {
    showError(`Fatal error: ${err.message || err}`);
    console.error(err);
  } finally {
    btn.disabled = false;
  }
}

async function runDemoSteps() {
  // -----------------------------------------------------------------------
  // Step 1: Initialize WASM module
  // -----------------------------------------------------------------------
  setStatus(1, "running", "loading...");

  let wasm;
  try {
    wasm = await import("./pkg/scp_ffi_wasm.js");
    await wasm.default(); // load + instantiate the .wasm binary
    wasm.scp_init();      // set up panic hook
  } catch (err) {
    setStatus(1, "error", "failed");
    setOutput(1, `<span class="dimmed">Failed to load WASM module.\n\nHave you built it?\n  wasm-pack build crates/scp-ffi/wasm --target web \\\n    --out-dir bindings/typescript/examples/browser-demo/pkg\n\n${esc(err.message || String(err))}</span>`);
    throw err;
  }

  const version = wasm.scp_version();
  setStatus(1, "done", "ready");
  setOutput(1, [
    kv("scp-ffi-wasm version", version),
    kv("wasm-bindgen target", "web"),
    `<span class="dimmed">Panic hook installed, console errors enabled.</span>`,
  ].join("\n"));
  addSummaryItem("WASM version", version);

  // -----------------------------------------------------------------------
  // Step 2: Create identity
  // -----------------------------------------------------------------------
  setStatus(2, "running", "generating...");

  const identity = await wasm.identity_create("in_memory");
  const did = identity.did;
  const custodyType = identity.custodyType;

  setStatus(2, "done", "created");
  setOutput(2, [
    kv("DID", did),
    kv("custody", custodyType),
    `<span class="dimmed">Ed25519 keypair generated via crypto.getRandomValues.</span>`,
  ].join("\n"));
  addSummaryItem("Identity DID", did);

  // -----------------------------------------------------------------------
  // Step 3: Create context
  // -----------------------------------------------------------------------
  setStatus(3, "running", "creating...");

  const contextParams = {
    mode: "broadcast",
    governance: "creator_admin",
    ceiling: ["scp:ctx:*/*"],
  };

  const ctx = await wasm.context_create(did, JSON.stringify(contextParams));
  const contextId = ctx.contextId;
  const contextState = ctx.state;
  const contextMode = ctx.mode;
  const memberCount = ctx.memberCount;
  const governance = ctx.governance;

  setStatus(3, "done", "active");
  setOutput(3, [
    kv("context ID", contextId),
    kv("state", contextState),
    kv("mode", contextMode),
    kv("governance", governance),
    kv("members", memberCount),
    kv("creator", ctx.creatorDid),
  ].join("\n"));
  addSummaryItem("Context ID", contextId);

  // -----------------------------------------------------------------------
  // Step 4: Register tool
  // -----------------------------------------------------------------------
  setStatus(4, "running", "registering...");

  const toolDef = {
    name: "text-summarizer",
    description: "Summarizes text content using extractive methods",
    operatorDid: did,
    schema: {
      type: "object",
      properties: {
        text: { type: "string", description: "Input text to summarize" },
        maxLength: { type: "number", description: "Maximum summary length" },
      },
      required: ["text"],
    },
    outputSchema: {
      type: "object",
      properties: {
        summary: { type: "string" },
        wordCount: { type: "number" },
      },
      required: ["summary"],
    },
  };

  const toolId = await wasm.tool_register(ctx, JSON.stringify(toolDef));

  setStatus(4, "done", "registered");
  setOutput(4, [
    kv("tool ID", toolId),
    kv("name", toolDef.name),
    kv("description", toolDef.description),
    kv("input schema", JSON.stringify(toolDef.schema, null, 2)),
  ].join("\n"));
  addSummaryItem("Tool registered", `${toolDef.name} (${toolId})`);

  // -----------------------------------------------------------------------
  // Step 5: Send message
  // -----------------------------------------------------------------------
  setStatus(5, "running", "sending...");

  const message = { type: "chat", text: "Hello from the browser WASM demo!" };
  const payloadBytes = new TextEncoder().encode(JSON.stringify(message));
  const payloadBase64 = btoa(String.fromCharCode(...payloadBytes));

  await wasm.context_send(ctx, did, payloadBase64);

  setStatus(5, "done", "sent");
  setOutput(5, [
    kv("payload (decoded)", JSON.stringify(message)),
    kv("payload (base64)", payloadBase64),
    kv("sender", did),
    kv("context", contextId),
    `<span class="dimmed">Message recorded in context event log.</span>`,
  ].join("\n"));
  addSummaryItem("Message sent", message.text);

  // -----------------------------------------------------------------------
  // Step 6: Attach provenance
  // -----------------------------------------------------------------------
  setStatus(6, "running", "attaching...");

  // Simulate cross-context data flow: data from this context is being
  // shared into a hypothetical target context.
  const targetContextId = `ctx-${crypto.randomUUID()}`;
  const provenanceJson = wasm.provenance_attach(
    contextId,          // source_context_id
    "persistent",       // source_type
    "full",             // memory_scope
    JSON.stringify([did]), // counterparties
    targetContextId,    // target_context_id
    did,                // actor_did
    undefined,          // existing_chain_depth (first hop)
    "[]",               // existing_chain_path_json
    "direct",           // discovery_method
    "demo",             // purpose
  );

  const provenance = JSON.parse(provenanceJson);

  setStatus(6, "done", "attached");
  setOutput(6, [
    kv("source context", provenance.source_context),
    kv("source type", provenance.source_type),
    kv("memory scope", provenance.memory_scope),
    kv("chain depth", provenance.chain_depth),
    kv("discovery method", provenance.discovery_method),
    kv("purpose", provenance.purpose),
    kv("content hash", provenance.content_hash),
    kv("counterparties", JSON.stringify(provenance.counterparties)),
    `<span class="dimmed">Provenance metadata for cross-context data flow.</span>`,
  ].join("\n"));
  addSummaryItem("Provenance chain depth", provenance.chain_depth);

  // -----------------------------------------------------------------------
  // Step 7: Query event log
  // -----------------------------------------------------------------------
  setStatus(7, "running", "querying...");

  const eventsJson = await wasm.event_log_query(ctx, null);
  const events = JSON.parse(eventsJson);

  setStatus(7, "done", `${events.length} event(s)`);

  if (events.length > 0) {
    const logSummary = events[0];
    const payload = JSON.parse(logSummary.payloadJson);
    setOutput(7, [
      kv("event type", logSummary.eventType),
      kv("event count", payload.event_count),
      kv("merkle root", payload.merkle_root),
      kv("sequence", logSummary.sequence),
      `<span class="dimmed">Merkle tree provides cryptographic integrity guarantees.</span>`,
    ].join("\n"));
    addSummaryItem("Events in log", payload.event_count);
    addSummaryItem("Merkle root", payload.merkle_root.substring(0, 16) + "...");
  } else {
    setOutput(7, `<span class="dimmed">No events in log.</span>`);
    addSummaryItem("Events in log", 0);
  }

  // -----------------------------------------------------------------------
  // Step 8: Evaluate provenance quality
  // -----------------------------------------------------------------------
  setStatus(8, "running", "evaluating...");

  const qualityTier = wasm.evaluate_provenance_quality(
    contextId,             // source_context
    "persistent",          // source_type
    "active",              // context_state
    JSON.stringify([did]),  // counterparties_json
  );

  const tierName = QUALITY_TIERS[qualityTier] || `Unknown (${qualityTier})`;

  setStatus(8, "done", tierName);
  setOutput(8, [
    kv("quality tier", qualityTier),
    kv("tier name", tierName),
    kv("source type", "persistent"),
    kv("context state", "active"),
    `<span class="dimmed">Tier 3 = PersistentVerifiable (highest). Active context + persistent source.</span>`,
  ].join("\n"));
  addSummaryItem("Provenance quality", `${qualityTier} (${tierName})`);

  // -----------------------------------------------------------------------
  // Done
  // -----------------------------------------------------------------------
  document.getElementById("summary").classList.add("visible");
}

// Expose to HTML onclick.
window.runDemo = runDemo;
