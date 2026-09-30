//! `PyO3` bridge functions for MCP (Model Context Protocol) server and client.
//!
//! Exposes SCP MCP operations to Python:
//!
//! - `py_mcp_serve` -- Start an MCP server exposing SCP context outlets.
//! - `py_mcp_server_stop` -- Stop a running MCP server.
//! - `py_mcp_server_wait` -- Block until the MCP server exits.
//! - `py_mcp_server_info` -- Return metadata about a running MCP server.
//! - `py_mcp_client_connect_stdio` -- Connect to an external MCP server via
//!   stdio.
//! - `py_mcp_client_connect_sse` -- Connect to an external MCP server via
//!   SSE.
//! - `py_mcp_client_disconnect` -- Disconnect from an external MCP server.
//! - `py_mcp_client_info` -- Return metadata about an active MCP client.
//! - `py_mcp_client_list_tools` -- List outlets from an external MCP server.
//! - `py_mcp_client_invoke` -- Invoke an external MCP outlet with provenance.
//! - `py_mcp_load_contexts` -- Load active contexts for a DID from a relay.
//!
//! The MCP bridge uses opaque string handles to track server and client
//! instances. Handles are stored in a global registry (similar to the
//! context runtime registry pattern).
//!
//! ## Architecture
//!
//! The bridge delegates to real `scp-mcp` implementations:
//!
//! - **Server side**: `FfiBridgeProvider` implements
//!   [`scp_mcp::server::ContextProvider`], reading outlet registrations and
//!   context state from the scp-ffi runtime registry. The MCP server is run
//!   on the tokio runtime via [`scp_mcp::stdio::run_stdio`] or
//!   [`scp_mcp::sse::run_sse`].
//!
//! - **Client side**: `StdioClientTransport` implements
//!   [`scp_mcp::client::McpTransport`] by spawning a subprocess and
//!   communicating via line-delimited JSON-RPC over stdin/stdout. SSE
//!   client transport is managed via `SseClientTransport`.
//!
//! See ADR-015 in `.docs/adrs/phase-3.md` for the full MCP adapter design.

use scp_ffi_common::error_codes as codes;
use std::io::{BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use scp_mcp::allowlist;
use scp_mcp::client::{McpClient, McpTransport, SystemTimestamp};
use scp_mcp::protocol::{JsonRpcNotification, JsonRpcRequest, JsonRpcResponse};
use scp_mcp::server::{ContextOutletInfo, ContextProvider, McpServer, MemberInfo};
use scp_mcp::sse_client::{SseClientTransport, SseCloser};
use scp_mcp::stdio::read_response;
use scp_platform::traits::Storage;

use crate::error::ScpPyError;
use crate::types::{json_to_py_dict, py_dict_to_json};
use crate::validate;

// ---------------------------------------------------------------------------
// Stdio client transport
// ---------------------------------------------------------------------------

/// MCP client transport that communicates with a subprocess via stdin/stdout.
///
/// Spawns the given command, pipes stdin/stdout, and exchanges line-delimited
/// JSON-RPC messages synchronously. The subprocess's stderr is inherited by
/// the parent process for debugging.
struct StdioClientTransport {
    /// The spawned subprocess, kept apart from the pipes an in-flight call
    /// holds so a disconnect can stop it while a call waits on its stdout.
    /// On Unix it leads its own process group. Dropping the handle's
    /// [`McpClientState`] or, at the latest, this transport's [`Drop`] kills
    /// that group and reaps the subprocess
    /// through [`stop_stdio_server`], which empties the slot.
    child: Arc<Mutex<Option<Child>>>,
    /// The subprocess's stdin writer and stdout reader.
    inner: Mutex<StdioTransportInner>,
}

/// Interior state for [`StdioClientTransport`], protected by a mutex.
struct StdioTransportInner {
    /// Buffered writer to the subprocess's stdin.
    writer: std::io::BufWriter<std::process::ChildStdin>,
    /// Buffered reader from the subprocess's stdout.
    reader: BufReader<std::process::ChildStdout>,
}

impl StdioClientTransport {
    /// Spawns the given command and establishes JSON-RPC communication.
    ///
    /// # Errors
    ///
    /// Returns an error message if the subprocess fails to start.
    fn spawn(
        allowlist: &Mutex<allowlist::StdioAllowlist>,
        command: &[String],
    ) -> Result<Self, String> {
        let (cmd, args) = command.split_first().ok_or("command list is empty")?;

        // Validate the command against the per-instance stdio allowlist
        // (defense-in-depth). Uses the validated basename for Command::new
        // to prevent path bypass. Hold the lock only across `validate_command`,
        // then drop before spawning the subprocess.
        let basename = {
            let guard = allowlist
                .lock()
                .map_err(|_| "stdio allowlist lock poisoned".to_owned())?;
            guard.validate_command(cmd).map_err(|e| e.to_string())?
        };

        let mut server = Command::new(&basename);
        server
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        // A launcher such as `npx` or `uvx` runs the real server as its own
        // child, which inherits the stdout pipe. The subprocess leads a new
        // process group so `stop_server_process` can kill that descendant
        // too; killing the launcher alone would leave the pipe open. That
        // group is not the terminal's foreground group, so a Ctrl-C or hangup
        // reaches the host and not the server. A host killed that way runs no
        // destructor; the server then sees EOF on stdin, which the MCP stdio
        // transport names as its shutdown signal, and a server that ignores
        // that EOF outlives the host.
        #[cfg(unix)]
        std::os::unix::process::CommandExt::process_group(&mut server, 0);
        let mut child = server
            .spawn()
            .map_err(|e| format!("failed to spawn '{basename}': {e}"))?;

        let stdin = child
            .stdin
            .take()
            .ok_or("failed to capture subprocess stdin")?;
        let stdout = child
            .stdout
            .take()
            .ok_or("failed to capture subprocess stdout")?;

        let writer = std::io::BufWriter::new(stdin);
        let reader = BufReader::new(stdout);

        Ok(Self {
            child: Arc::new(Mutex::new(Some(child))),
            inner: Mutex::new(StdioTransportInner { writer, reader }),
        })
    }

    /// The subprocess, for [`ClientServer::Stdio`].
    fn server_process(&self) -> Arc<Mutex<Option<Child>>> {
        Arc::clone(&self.child)
    }
}

/// Kills a stdio server's process group and reaps the server, once.
///
/// The server leaves its slot under the slot's lock, and
/// `stop_server_process` consumes the `Child`, so a later call (the
/// transport's [`Drop`] after the [`McpClientState`] drop) finds the slot
/// empty and signals nothing. A second stop of the same reaped server would
/// not be safe: the stop decides whether to signal the group from a `waitid`
/// on the raw pid, and once the server is reaped that pid can belong to
/// another child of this process, such as a second stdio server leading its
/// own group. The lock is held until the server is reaped, so a disconnect
/// returns only after the server is gone even when the drop runs
/// concurrently.
fn stop_stdio_server(slot: &Mutex<Option<Child>>) {
    let mut slot = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(child) = slot.take() {
        scp_mcp::stdio::stop_server_process(child);
    }
}

/// Kills the subprocess and, on Unix, its process group, and waits for the
/// subprocess to exit on drop.
///
/// `std::process::Child::drop` does NOT kill the subprocess — it only closes
/// handles. Without this impl, dropped transports leak running subprocesses.
impl Drop for StdioClientTransport {
    fn drop(&mut self) {
        stop_stdio_server(&self.child);
    }
}

impl McpTransport for StdioClientTransport {
    fn send_request(&self, request: &JsonRpcRequest) -> Result<JsonRpcResponse, String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| format!("transport lock poisoned: {e}"))?;

        // Serialize and write the request as a single line.
        let json = serde_json::to_string(request)
            .map_err(|e| format!("failed to serialize request: {e}"))?;
        inner
            .writer
            .write_all(json.as_bytes())
            .map_err(|e| format!("failed to write to subprocess stdin: {e}"))?;
        inner
            .writer
            .write_all(b"\n")
            .map_err(|e| format!("failed to write newline: {e}"))?;
        inner
            .writer
            .flush()
            .map_err(|e| format!("failed to flush subprocess stdin: {e}"))?;

        // Read until this request's response: the server interleaves
        // notifications on the same stream.
        let response = read_response(&mut inner.reader, &request.id)
            .map_err(|e| format!("failed to read from subprocess stdout: {e}"));
        drop(inner);
        response
    }

    fn send_notification(&self, notification: &JsonRpcNotification) -> Result<(), String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| format!("transport lock poisoned: {e}"))?;

        let json = serde_json::to_string(notification)
            .map_err(|e| format!("failed to serialize notification: {e}"))?;
        inner
            .writer
            .write_all(json.as_bytes())
            .map_err(|e| format!("failed to write notification: {e}"))?;
        inner
            .writer
            .write_all(b"\n")
            .map_err(|e| format!("failed to write newline: {e}"))?;
        inner
            .writer
            .flush()
            .map_err(|e| format!("failed to flush notification: {e}"))?;
        drop(inner);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Client transport enum (for type-safe storage without trait objects)
// ---------------------------------------------------------------------------

/// Enum-based transport to avoid orphan rule issues with `Box<dyn McpTransport>`.
///
/// [`StdioClientTransport`] is defined in this module, [`SseClientTransport`]
/// comes from `scp_mcp::sse_client` (the one SSE client every bridge shares),
/// and [`McpTransport`] is from `scp-mcp`, so we cannot implement
/// `McpTransport` for `Box<dyn McpTransport>` due to orphan rules. This enum
/// dispatch avoids that problem.
enum ClientTransport {
    /// Stdio transport: subprocess with piped stdin/stdout.
    Stdio(StdioClientTransport),
    /// SSE transport: HTTP with Server-Sent Events.
    Sse(SseClientTransport),
}

impl McpTransport for ClientTransport {
    fn send_request(&self, request: &JsonRpcRequest) -> Result<JsonRpcResponse, String> {
        match self {
            Self::Stdio(t) => t.send_request(request),
            // Each variant dispatches to its own McpTransport impl with distinct
            // I/O behavior (subprocess stdio vs. HTTP SSE). Arms look identical
            // syntactically but resolve to different concrete implementations.
            #[allow(clippy::match_same_arms)]
            Self::Sse(t) => t.send_request(request),
        }
    }

    fn send_notification(&self, notification: &JsonRpcNotification) -> Result<(), String> {
        match self {
            Self::Stdio(t) => t.send_notification(notification),
            #[allow(clippy::match_same_arms)]
            Self::Sse(t) => t.send_notification(notification),
        }
    }
}

// ---------------------------------------------------------------------------
// FFI bridge context provider
// ---------------------------------------------------------------------------

/// Default outlet handler execution timeout in milliseconds (30 seconds).
///
/// Matches [`scp_core::context::outlets::DEFAULT_TIMEOUT_MS`]. If a registered
/// handler does not return within this duration, the invocation is aborted
/// with a timeout error. Configurable per-provider via
/// [`FfiBridgeProvider::outlet_timeout_ms`].
const FFI_OUTLET_TIMEOUT_MS: u64 = scp_core::context::outlets::DEFAULT_TIMEOUT_MS as u64;

/// Implements [`ContextProvider`] by reading from the scp-ffi runtime registry.
///
/// Bridges the MCP server's context/outlet queries to the live runtime state
/// managed by `crates/scp-ffi/src/runtime.rs`.
struct FfiBridgeProvider {
    /// Weak reference to the bridge instance whose runtime registry this
    /// provider reads.
    ///
    /// # Why `Weak` and not `Arc` (#1549 round-2 bug-catcher)
    ///
    /// The provider is installed in an [`McpServer`] that lives inside a
    /// background task spawned on the shared tokio runtime
    /// (`RUNTIME.spawn(...)`). That task is NOT enrolled in the per-instance
    /// [`JoinSet`](scp_ffi_common::bridge_instance::CoreFields::task_handle)
    /// aborted by `emergency_cancel_tasks`, so it survives
    /// [`crate::runtime::PyBridgeInstance::drop`] unless the caller
    /// explicitly sends a shutdown via
    /// [`crate::scp::PyScp::py_mcp_server_stop`].
    ///
    /// If this field were `Arc<PyBridgeInstance>`, the server task would
    /// keep the instance alive forever when the caller forgets to
    /// `shutdown`. With `Weak`, callers that drop their last strong
    /// reference release `ContextManager`, identity registry, relay
    /// connection, and the rest of `BridgeInstance`'s state. Provider
    /// methods upgrade per call; once `None` is returned, they emit a
    /// stable error so the MCP server can propagate it to the peer.
    bi: std::sync::Weak<crate::runtime::PyBridgeInstance>,
    /// The agent's DID.
    agent_did: String,
    /// The context IDs this provider serves.
    context_ids: Vec<String>,
    /// Maximum time (in milliseconds) to wait for an outlet handler to complete.
    ///
    /// Defaults to [`FFI_OUTLET_TIMEOUT_MS`] (30 seconds). If a registered
    /// handler blocks longer than this, the invocation returns an error
    /// instead of blocking indefinitely. See issue #123.
    outlet_timeout_ms: u64,
    /// JWT-encoded UCAN token for outlet invocation authorization.
    ///
    /// When present, `validate_capability` runs the full 11-step ADR-016
    /// validation pipeline to verify the token grants `outlet_call:{outlet_name}`
    /// or `outlet_call:*` for the context. When absent, `validate_capability`
    /// rejects immediately (UCAN is required for outlet invocation).
    ///
    /// See spec §6.2, §8, ADR-016, and issue #319.
    agent_ucan_token: Option<String>,
    /// Optional proof tokens for UCAN delegation chain verification.
    ///
    /// When the `agent_ucan_token` is a delegated UCAN (non-empty `prf` field),
    /// the parent tokens must be provided here so the proof resolver can
    /// verify the delegation chain. Without these, delegated UCANs always fail.
    agent_proof_tokens: Option<Vec<String>>,
}

impl FfiBridgeProvider {
    /// Upgrades the stored [`Weak`](std::sync::Weak) to a live [`Arc<PyBridgeInstance>`].
    ///
    /// Returns an error string if the bridge instance has been dropped.
    /// Callers MUST drop the returned `Arc` before the next `.await` so
    /// they do not pin the instance alive across suspension points.
    fn upgrade_bi(&self) -> Result<std::sync::Arc<crate::runtime::PyBridgeInstance>, String> {
        self.bi.upgrade().ok_or_else(|| {
            "bridge instance has been dropped — MCP provider cannot service request".to_owned()
        })
    }

    /// Reads `context_id`'s current role state for an MCP authorization.
    ///
    /// With a supervisor attached, the answer is the actor's role state, never
    /// this bridge's copy (`FfiBridgeState.role_state`). Only the bridge's own
    /// join, leave and governance calls resync that copy. A change the actor
    /// applies from an inbound commit, such as another admin revoking this
    /// agent's `messages:read` or removing it, never reaches the copy by itself,
    /// so a gate reading the copy keeps authorizing the agent after the
    /// revocation. The `UniFFI` provider asks the actor on every read for the
    /// same reason.
    ///
    /// The function writes nothing back to the copy. The MCP transport task
    /// and the notification pump call it concurrently with the bridge's own
    /// calls, so a write-back could replace a newer copy with the older
    /// snapshot this call read.
    ///
    /// With no supervisor attached there is no actor and no inbound path, so
    /// the copy is the context's only role state and is read as it stands.
    ///
    /// # Errors
    ///
    /// Fails when the actor does not hold the context or cannot be asked, and,
    /// with no supervisor attached, when the bridge holds no copy of the
    /// context. The message for an absent context names whichever of the two
    /// held nothing. [`Self::gate_role_state`] keeps those two failures apart
    /// for the access gates.
    fn live_role_state(
        bi: &crate::runtime::PyBridgeInstance,
        context_id: &str,
    ) -> Result<scp_core::context::roles::ContextRoleState, String> {
        Self::held_role_state(bi, context_id)?
            .ok_or_else(|| Self::absent_context_message(bi, context_id))
    }

    /// Reads `context_id`'s role state as [`Self::live_role_state`] does, for
    /// an access gate.
    ///
    /// # Errors
    ///
    /// Returns [`AccessRefusal::Denied`](scp_mcp::server::AccessRefusal::Denied)
    /// when the actor (with no supervisor, the bridge) holds no such context:
    /// the agent holds no grant in a context this instance does not hold, so
    /// `tools/list` and `resources/list` omit it. Returns
    /// [`AccessRefusal::Unreadable`](scp_mcp::server::AccessRefusal::Unreadable)
    /// when the read itself failed, so a failed read never reaches the client
    /// as a shorter list.
    fn gate_role_state(
        bi: &crate::runtime::PyBridgeInstance,
        context_id: &str,
    ) -> Result<scp_core::context::roles::ContextRoleState, scp_mcp::server::AccessRefusal> {
        use scp_mcp::server::AccessRefusal;
        match Self::held_role_state(bi, context_id) {
            Ok(Some(role_state)) => Ok(role_state),
            Ok(None) => Err(AccessRefusal::Denied(Self::absent_context_message(
                bi, context_id,
            ))),
            Err(e) => Err(AccessRefusal::Unreadable(e)),
        }
    }

    /// Names the holder that has no `context_id`: the supervisor when one is
    /// attached, otherwise this bridge.
    fn absent_context_message(bi: &crate::runtime::PyBridgeInstance, context_id: &str) -> String {
        if bi.core.try_supervisor().is_some() {
            format!("context '{context_id}' is not held by the supervisor")
        } else {
            format!(
                "context '{context_id}' is not held by this bridge, and no supervisor is attached"
            )
        }
    }

    /// Reads `context_id`'s current role state from the source
    /// [`Self::live_role_state`] names, and separates the two outcomes that
    /// function merges: `Ok(None)` when the actor holds no such context (with
    /// no supervisor, when the bridge holds no copy), and `Err` when the read
    /// itself failed.
    ///
    /// # Errors
    ///
    /// Fails when the actor cannot be asked or does not answer: from a
    /// current-thread runtime, when the bridge runtime cannot start, or when
    /// `Supervisor::get_role_state_checked`
    /// fails, which it does for a busy actor and for a context the crash
    /// watchdog poisoned or is respawning, so none of those reads as `Ok(None)`.
    fn held_role_state(
        bi: &crate::runtime::PyBridgeInstance,
        context_id: &str,
    ) -> Result<Option<scp_core::context::roles::ContextRoleState>, String> {
        let Some(supervisor) = bi.core.try_supervisor() else {
            // The closure cannot fail, so an error from `with_context` means
            // the bridge holds no copy of the context.
            return Ok(crate::runtime::with_context(bi, context_id, |rt| {
                Ok(rt.role_state.clone())
            })
            .ok());
        };
        let supervisor = Arc::clone(supervisor);
        let id = context_id.to_owned();
        let query = async move {
            supervisor
                .get_role_state_checked(&id)
                .await
                .map_err(|e| format!("role state of context '{id}' could not be read: {e}"))
        };
        match tokio::runtime::Handle::try_current() {
            // Inside the MCP transport task: the actor runs on this runtime's
            // other workers while this one blocks.
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(query))
            }
            // A current-thread runtime would have to run the actor on the
            // thread this call blocks.
            Ok(_) => Err(format!(
                "cannot read the role state of context '{context_id}' from a \
                 current-thread runtime"
            )),
            Err(_) => crate::runtime()
                .map_err(|e| format!("{e}"))?
                .block_on(query),
        }
    }

    /// Decides whether the agent may invoke `outlet_name` in `context_id`,
    /// given the context's current role state: the role-state capability
    /// check, then the UCAN check. The role-state check runs first because
    /// an Invoke check's UCAN step records the token's nonce, and a refusal
    /// after that record would spend the agent's token without running an
    /// outlet.
    ///
    /// # Errors
    ///
    /// Returns [`AccessRefusal::Denied`](scp_mcp::server::AccessRefusal::Denied)
    /// naming the check that refused the invocation, and
    /// [`AccessRefusal::Unreadable`](scp_mcp::server::AccessRefusal::Unreadable)
    /// when the agent's proof tokens cannot be read, so a failed read never
    /// reaches the client as a denial.
    fn outlet_grant(
        &self,
        bi: &crate::runtime::PyBridgeInstance,
        role_state: &scp_core::context::roles::ContextRoleState,
        context_id: &str,
        outlet_name: &str,
        check: scp_mcp::server::CapabilityCheck,
    ) -> Result<(), scp_mcp::server::AccessRefusal> {
        use scp_mcp::server::AccessRefusal;
        let Some(token) = self.agent_ucan_token.as_ref() else {
            tracing::warn!(
                agent = %self.agent_did,
                outlet = %outlet_name,
                context = %context_id,
                "no UCAN token provided for outlet invocation — authorization bypass risk"
            );
            return Err(AccessRefusal::Denied(
                "UCAN token required for outlet invocation — no token provided".to_owned(),
            ));
        };
        // Defense-in-depth: check role-state capabilities in addition to the
        // UCAN layer. See §7.2 and ADR-010 for the dual-check design.
        //
        // SCP-OUT-014: select the kind-appropriate split stem from the
        // outlet's registered kind — OutletQuery for Query outlets,
        // OutletCall for Action outlets (§5.4.2). The two stems are
        // independent, so a Query grant never authorizes an Action call and
        // vice versa. An outlet absent from the registry defaults to the
        // Action stem (the UCAN step below requires registration). The closure
        // cannot fail, so an `Err` from `with_context` means the bridge holds
        // no copy of a context the actor holds: only this bridge's create and
        // join paths register a copy, so a context the actor holds by any
        // other path has none. The bridge then holds no registration of the
        // outlet, and the same default applies, as it does in `context_tools`.
        let outlet_kind = crate::runtime::with_context(bi, context_id, |rt| {
            Ok(rt.outlet_registry.get(outlet_name).map(|r| r.kind))
        })
        .ok()
        .flatten()
        .unwrap_or(scp_core::context::outlets::OutletKind::Action);
        if !scp_core::context::outlets::invoke::has_outlet_invocation_capability(
            role_state,
            &self.agent_did,
            outlet_name,
            outlet_kind,
        ) {
            // Generic message for the wire — detailed info stays server-side.
            tracing::warn!(
                agent = %self.agent_did,
                outlet = %outlet_name,
                context = %context_id,
                "capability check failed: agent lacks the required outlet invocation capability"
            );
            return Err(AccessRefusal::Denied(
                "insufficient permissions to invoke outlet".to_owned(),
            ));
        }
        // With no bridge copy, the context has no outlet registered through
        // this bridge (see `context_tools`), so the outlet is unregistered:
        // the denial the copy's own registry gives below, not a failed read.
        if !crate::runtime::ffi_state_registry(bi).contains_key(context_id) {
            return Err(AccessRefusal::Denied(format!(
                "outlet '{outlet_name}' not registered in context '{context_id}'"
            )));
        }

        // Primary check: UCAN token validation via the full 11-step ADR-016
        // pipeline. Verifies the token grants the outlet's kind-appropriate stem
        // — outlet_query:{outlet_name}/outlet_query:* for Query outlets,
        // outlet_call:{outlet_name}/outlet_call:* for Action outlets
        // (SCP-OUT-014, §5.4.2) — for this context.
        // See spec §6.2, §8, ADR-016, and issue #319.
        // Build proof resolver from optional proof tokens (supports delegated UCANs).
        let proof_resolver =
            crate::ucan::build_proof_resolver_from_tokens(self.agent_proof_tokens.as_deref())
                .map_err(|e| {
                    AccessRefusal::Unreadable(format!("failed to build proof resolver: {e}"))
                })?;

        // The closure's `Ok` carries the UCAN decision, so an `Err` from
        // `with_context` is a failed read of the bridge's context copy.
        let decision = crate::runtime::with_context(bi, context_id, |rt| {
            // SCP-OUT-014: select the split capability stem from the
            // outlet's registered kind — `outlet_query:{id}` for Query
            // outlets, `outlet_call:{id}` for Action outlets.
            let Some(outlet_kind_for_ucan) = rt.outlet_registry.get(outlet_name).map(|r| r.kind)
            else {
                return Ok(Err(format!(
                    "outlet '{outlet_name}' not registered in context '{context_id}'"
                )));
            };

            let production_resolver = crate::runtime::did_resolver(bi);
            let did_resolver = crate::bridge_adapters::DispatchDidResolver::new(
                production_resolver.map(std::convert::AsRef::as_ref),
            );
            let revocation_checker = crate::bridge_adapters::BridgeRevocationChecker {
                revocation_list: &rt.revocation_list,
            };
            // Only the Invoke check made just before a `tools/call` runs
            // its outlet records the nonce; a probe records nothing.
            let mut nonce_adapter =
                crate::bridge_adapters::OutletGrantNonceTracker::new(&mut rt.nonce_tracker, check);

            let mut ctx = scp_core::crypto::ucan::validate::ValidationContext {
                did_resolver: &did_resolver,
                nonce_tracker: &mut nonce_adapter,
                revocation_checker: &revocation_checker,
                proof_resolver: &proof_resolver,
                ceiling: &rt.ceiling_strings,
                context_creator_did: &rt.creator_did,
                presenting_agent_did: &self.agent_did,
                clock_skew_tolerance_secs:
                    scp_core::crypto::ucan::validate::DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
                clock: &scp_clock::SystemClock,
                // §5.4.5 HIGH-3 — outlet-invocation site resolves effective
                // caveats from each token's `nb` field so §7.3.8 Step 7b
                // (per-edge narrow) and Step 11b (time-box) run over the
                // proof chain's VALIDATED-NARROWED caveat set. Generic
                // validate/evaluate sites (ucan.rs) stay on `NoCaveatResolver`.
                caveat_resolver: &scp_core::crypto::ucan::validate::TokenNbCaveatResolver,
            };

            Ok(scp_core::context::outlets::validate_outlet_invocation_ucan(
                token,
                context_id,
                outlet_name,
                outlet_kind_for_ucan,
                &mut ctx,
            )
            .map_err(|e| {
                tracing::warn!(
                    agent = %self.agent_did,
                    outlet = %outlet_name,
                    context = %context_id,
                    error = %e,
                    "UCAN validation failed for outlet invocation"
                );
                format!("UCAN authorization failed for outlet '{outlet_name}': {e}")
            }))
        })
        .map_err(|e| AccessRefusal::Unreadable(format!("{e}")))?;
        decision.map_err(AccessRefusal::Denied)?;
        Ok(())
    }
}

impl ContextProvider for FfiBridgeProvider {
    fn active_context_ids(&self) -> Result<Vec<String>, String> {
        // Configured ∩ live: a context the agent has left is no longer served,
        // so its tools and resources drop out of `tools/list` and
        // `resources/list` without restarting the server (ADR-015 AC7). A
        // context no actor holds is not served; a failed read is an error, not
        // a departure.
        let bi = self.upgrade_bi()?;
        let mut served = Vec::new();
        for id in &self.context_ids {
            if Self::held_role_state(&bi, id)?
                .is_some_and(|role_state| role_state.members.contains(&self.agent_did))
            {
                served.push(id.clone());
            }
        }
        Ok(served)
    }

    fn agent_role(&self, context_id: &str) -> Result<Option<String>, String> {
        // Look up the agent's role assignment in the context's role state. A
        // context nobody holds has no role for the agent; a dropped bridge or
        // a failed read is an error, never `None`.
        let bi = self.upgrade_bi()?;
        Ok(
            Self::held_role_state(&bi, context_id)?.and_then(|role_state| {
                role_state
                    .assignments
                    .get(&self.agent_did)
                    .map(|assignment| assignment.role_name.clone())
            }),
        )
    }

    fn agent_did(&self) -> &str {
        &self.agent_did
    }

    fn context_tools(&self, context_id: &str) -> Result<Vec<ContextOutletInfo>, String> {
        // A dropped bridge or an unreadable context is an error, never an
        // empty outlet registry.
        let bi = self.upgrade_bi()?;
        // Outlets register only on the bridge copy, and only this bridge's
        // create and join paths register a copy, so a context the actor holds
        // by any other path has no copy here and no outlet registered through
        // this bridge: its registry is empty. With no supervisor the copy is
        // the context's only state, so `held_role_state` finds no context.
        if !crate::runtime::ffi_state_registry(&bi).contains_key(context_id) {
            return match Self::held_role_state(&bi, context_id)? {
                Some(_) => Ok(Vec::new()),
                None => Err(format!(
                    "context '{context_id}' is held neither by the supervisor nor by \
                     this bridge"
                )),
            };
        }
        crate::runtime::with_context(&bi, context_id, |rt| {
            let outlets = rt
                .outlet_registry
                .registrations()
                .map(|t| ContextOutletInfo {
                    name: t.name.clone(),
                    description: Some(t.description.clone()),
                    input_schema: t.schema.input_schema.clone(),
                    output_schema: Some(t.schema.output_schema.clone()),
                    admin_only: false,
                    // Carry the registry's authoritative §5.4.2 kind so the
                    // translator surfaces the correct `query.` / `call.` MCP
                    // tool-name prefix. `ContextOutletInfo.kind` is the canonical
                    // `scp_core::context::outlets::OutletKind` (re-exported by
                    // scp-mcp), so this is a direct move — never hardcode Action.
                    kind: t.kind,
                })
                .collect();
            Ok(outlets)
        })
        .map_err(|e| format!("{e}"))
    }

    fn validate_capability(
        &self,
        context_id: &str,
        outlet_name: &str,
        check: scp_mcp::server::CapabilityCheck,
    ) -> Result<(), scp_mcp::server::AccessRefusal> {
        use scp_mcp::server::AccessRefusal;
        // A dropped bridge instance, an unreadable role state, or a failed
        // read inside `outlet_grant` is a failed read, which `tools/list`
        // reports as an error instead of omitting the context's tools. A
        // context the actor does not hold is a denial. The role state comes
        // from the actor, not the bridge copy.
        let bi = self.upgrade_bi().map_err(AccessRefusal::Unreadable)?;
        let role_state = Self::gate_role_state(&bi, context_id)?;
        self.outlet_grant(&bi, &role_state, context_id, outlet_name, check)
    }

    fn invoke_outlet(
        &self,
        context_id: &str,
        outlet_name: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, scp_mcp::server::OutletInvokeError> {
        self.run_outlet(context_id, outlet_name, arguments, || {
            self.validate_capability(
                context_id,
                outlet_name,
                scp_mcp::server::CapabilityCheck::Invoke,
            )
        })
    }

    fn validate_resource_access(
        &self,
        context_id: &str,
        resource: scp_mcp::server::ResourceKind,
    ) -> Result<(), scp_mcp::server::AccessRefusal> {
        use scp_mcp::server::AccessRefusal;
        // A dropped bridge instance or an unreadable role state is a failed
        // read, which `resources/list` reports as an error instead of
        // omitting the context's resources. A context the actor does not hold
        // is a denial, which `resources/list` omits.
        let bi = self.upgrade_bi().map_err(AccessRefusal::Unreadable)?;
        let role_state = Self::gate_role_state(&bi, context_id)?;
        let access = resource.check_access(&role_state, &self.agent_did, context_id);
        access.map_err(AccessRefusal::Denied)
    }

    fn context_members(&self, context_id: &str) -> Result<Vec<MemberInfo>, String> {
        // A dropped bridge or an unreadable context is an error, never an
        // empty roster.
        let bi = self.upgrade_bi()?;
        let role_state = Self::live_role_state(&bi, context_id)?;
        Ok(role_state
            .members
            .iter()
            .map(|did| MemberInfo {
                did: did.clone(),
                role: role_state
                    .assignments
                    .get(did)
                    .map_or_else(|| "member".to_owned(), |a| a.role_name.clone()),
            })
            .collect())
    }

    fn context_events(&self, context_id: &str) -> Result<serde_json::Value, String> {
        // The event log stores Merkle tree hashes, not event payloads, so the
        // resource reports entry counts and Merkle roots. A dropped bridge or
        // an unreadable log is an error, never an empty log.
        let bi = self.upgrade_bi()?;
        // `bridge_event_log` summarizes the bridge's local tree, to which
        // `invoke_outlet` appends the OutletInvokedEvent of every MCP
        // `tools/call`. The actor's log never receives that record, so without
        // `bridge_event_log` a `tools/call` would leave this resource
        // unchanged.
        let bridge_log = crate::runtime::with_context(&bi, context_id, |rt| {
            Ok((
                rt.event_log.leaves().len(),
                scp_event_log::tree::root(&rt.event_log),
            ))
        })
        .map_err(|e| format!("{e}"));
        // With a supervisor attached, the top level reports the actor's log,
        // whose events drive the pump's `resources/updated` notices, and
        // `bridge_event_log` is `null` when the bridge holds no local tree for
        // the context. Without a supervisor the bridge's tree is the context's
        // only log, so an unreadable tree is an error.
        let ((event_count, root), bridge_log) = if let Some(supervisor) = bi.core.try_supervisor() {
            let actor_log = supervisor
                .event_log_summary(&scp_core::context::state::context_id_to_bytes(context_id))
                .map_err(|e| format!("cannot read the event log of context '{context_id}': {e}"))?;
            (actor_log, bridge_log.ok())
        } else {
            let bridge_log = bridge_log?;
            (bridge_log, Some(bridge_log))
        };
        let bridge_event_log = bridge_log.map(|(count, root)| {
            serde_json::json!({
                "event_count": count,
                "merkle_root": crate::types::encode_hex(&root),
            })
        });
        Ok(serde_json::json!({
            "event_count": event_count,
            "merkle_root": crate::types::encode_hex(&root),
            "bridge_event_log": bridge_event_log,
        }))
    }
}

impl FfiBridgeProvider {
    /// Runs `outlet_name` for [`ContextProvider::invoke_outlet`], which
    /// passes the Invoke check as `authorize`. `authorize` runs after every
    /// refusal that runs no outlet (the supervisor lookup, the hard rate
    /// limit, the registry lookup, the input schema and the handler lookup)
    /// and just before the handler dispatch, because a passing Invoke check
    /// spends the agent token. A refused `authorize` refunds the rate-limit
    /// token and runs no outlet. An outlet with no registered handler is
    /// refused: nothing would run, so a success result for it would report
    /// work that was not done.
    #[allow(clippy::too_many_lines)] // Three-phase dispatch: validate + execute + emit event.
    fn run_outlet(
        &self,
        context_id: &str,
        outlet_name: &str,
        arguments: serde_json::Value,
        authorize: impl FnOnce() -> Result<(), scp_mcp::server::AccessRefusal>,
    ) -> Result<serde_json::Value, scp_mcp::server::OutletInvokeError> {
        // Validates outlet existence, input schema and handler registration,
        // then dispatches to the registered handler.
        //
        // After successful invocation, appends a OutletInvokedEvent to the
        // context's event log per ADR-010 acceptance criterion 3.
        //
        // The handler dispatch is sync because ContextProvider::invoke_outlet is
        // sync and Python handlers are GIL-bound (inherently sync). The async
        // invoke_outlet in scp-core is for contexts where Rust itself executes
        // outlets. See SCP-212, ADR-010, ADR-015.
        //
        // IMPORTANT: The handler Arc and output schema are extracted inside the
        // DashMap shard lock (via with_context), then the lock is released
        // BEFORE calling the handler. This prevents holding the shard lock
        // during Python GIL acquisition, which would block concurrent
        // same-context operations for the duration of the handler. See #122.
        //
        // Handler execution is bounded by `outlet_timeout_ms` to prevent a
        // misbehaving handler from blocking the tokio runtime indefinitely.
        // Uses std::thread::spawn + mpsc::recv_timeout (sync timeout) because
        // ContextProvider::invoke_outlet is a sync trait method. See issue #123.
        //
        // KNOWN LIMITATION — thread leak on timeout: When `recv_timeout`
        // expires, the spawned `std::thread` continues running in the
        // background until the handler returns naturally. Rust threads
        // cannot be forcibly cancelled — there is no `pthread_cancel`
        // equivalent and `JoinHandle` has no `abort()`. The leaked thread
        // holds an `Arc<dyn Fn>` (the handler closure) and, for Python
        // handlers, will hold the GIL until the handler completes. However:
        //
        //   1. No DashMap shard locks are held during handler execution
        //      (two-phase design from #122), so the leaked thread does not
        //      block other context operations.
        //   2. The only contended resource is the Python GIL, which is
        //      released when the handler eventually returns.
        //   3. Cooperative cancellation (e.g., polling a CancellationToken)
        //      would require handler authors to interleave cancellation
        //      checks into their logic — an unreasonable API burden for an
        //      exceptional case.
        //   4. Timeouts are exceptional in well-behaved systems; the default
        //      `outlet_timeout_ms` is generous. Repeated timeouts indicate a
        //      broken handler, not a protocol issue.
        //
        // If this becomes a problem in practice, the mitigation path is
        // process-level isolation (subprocess handlers), not in-process
        // thread cancellation. See PR #170 review discussion.
        let start = std::time::Instant::now();
        let agent_did = self.agent_did.clone();
        let timeout = std::time::Duration::from_millis(self.outlet_timeout_ms);

        // Upgrade the bridge instance handle up-front. `invoke_outlet` is a
        // sync trait method, so the `Arc` we hold here has a well-defined
        // lifetime bounded by this function's return — it cannot survive
        // across an `await` and pin the instance alive (#1549 round-2).
        let bi = self.upgrade_bi()?;

        // Consume a hard-rate-limit token BEFORE dispatching the MCP
        // outlet invocation. This path — reachable from external MCP
        // clients — does not go through
        // `ContextManager::invoke_outlet_with_economy`; it dispatches
        // directly against the bridge-side outlet registry, so without
        // this hook an external client could burn relay capacity
        // regardless of the per-context rate limit.
        //
        // This trait method is sync but its callers vary:
        //   (a) `py_mcp_serve` stdio loop → `rt.spawn(async move …)`
        //       on the multi-thread bridge runtime: `py_mcp_serve` refuses
        //       a current-thread runtime while a supervisor is attached
        //       (`check_serve_runtime`), and without one this call fails at
        //       `supervisor` below.
        //   (b) SSE async handler → multi-thread runtime.
        //   (c) Sync `#[test]` tests → no runtime.
        //
        // `try_consume_hard_rate_limit_from_any_context` dispatches
        // internally between `blocking_lock`, `block_in_place +
        // block_on`, or a dedicated `std::thread` with its own tiny
        // runtime depending on which regime the caller is in.
        let invoker_did_typed: scp_did::DID = agent_did.clone().into();
        let now_secs = scp_clock::Clock::now_secs(&scp_clock::SystemClock);
        let supervisor = crate::runtime::supervisor(&bi).map_err(|e| format!("{e}"))?;
        if !supervisor.try_consume_hard_rate_limit_from_any_context(
            context_id,
            &invoker_did_typed,
            now_secs,
        ) {
            return Err("SCP-ECON-12090: rate limit exceeded on outlet_invoke: \
                        hard rate limit exceeded for invoker"
                .to_owned()
                .into());
        }
        // Helper that refunds the token on any failure path. Used by
        // every `return Err` below. Same runtime-agnostic dispatch
        // as the consume call above.
        let ctx_id_for_refund = context_id.to_owned();
        let refund = |e: String| -> String {
            supervisor
                .refund_hard_rate_limit_from_any_context(&ctx_id_for_refund, &invoker_did_typed);
            e
        };

        // Phase 1: Validate input and extract handler + output schema under
        // the DashMap shard lock. The lock is released when with_context
        // returns. Also compute input hash before dispatch (arguments may
        // be consumed by the handler).
        let (dispatch, input_hash) = crate::runtime::with_context(&bi, context_id, |rt| {
            let registration = rt.outlet_registry.get(outlet_name).ok_or_else(|| {
                ScpPyError::context(format!(
                    "outlet '{outlet_name}' not found in context '{context_id}'"
                ))
            })?;

            // Validate input against the outlet's input schema.
            scp_core::context::outlets::schema::validate_value_against_schema(
                &arguments,
                &registration.schema.input_schema,
            )
            .map_err(|msg| {
                ScpPyError::validation(format!(
                    "input validation failed for outlet '{outlet_name}': {msg}"
                ))
            })?;

            // Clone handler Arc and output schema so we can release the lock.
            // Compute input hash before dispatch (arguments may be consumed).
            let input_hash = scp_core::context::outlets::sha256_json(&arguments);

            let dispatch = rt
                .outlet_handlers
                .get(outlet_name)
                .map(|handler| (handler.clone(), registration.schema.output_schema.clone()))
                .ok_or_else(|| {
                    ScpPyError::context(format!(
                        "outlet '{outlet_name}' in context '{context_id}' has no registered handler"
                    ))
                })?;

            Ok((dispatch, input_hash))
        })
        .map_err(|e| refund(format!("{e}")))?;

        // The Invoke check records the agent token's nonce, so it runs after
        // every refusal above and just before the dispatch below.
        if let Err(refusal) = authorize() {
            supervisor.refund_hard_rate_limit_from_any_context(context_id, &invoker_did_typed);
            return Err(scp_mcp::server::OutletInvokeError::Refused(refusal));
        }

        // Phase 2: Execute handler OUTSIDE the DashMap shard lock so that
        // concurrent same-context operations are not blocked during Python
        // GIL acquisition and handler execution. Handler execution is
        // bounded by `outlet_timeout_ms` (issue #123).
        let output = {
            let (handler, output_schema) = dispatch;
            // Run the handler on a dedicated thread with a timeout to
            // prevent indefinite blocking. The handler is Send + Sync
            // (Arc<dyn Fn>), so it is safe to move across threads.
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let result = handler(arguments);
                // If the receiver has been dropped (timeout elapsed), the
                // send will fail silently -- that is intentional.
                let _ = tx.send(result);
            });

            let handler_result = rx.recv_timeout(timeout).map_err(|_| {
                refund(format!(
                    "outlet handler for '{outlet_name}' timed out after {}ms",
                    timeout.as_millis()
                ))
            })?;

            let output = handler_result
                .map_err(|e| refund(format!("outlet handler for '{outlet_name}' failed: {e}")))?;

            // Validate output against the outlet's output schema (defense-in-depth).
            scp_core::context::outlets::schema::validate_value_against_schema(
                &output,
                &output_schema,
            )
            .map_err(|msg| {
                refund(format!(
                    "output validation failed for outlet '{outlet_name}': {msg}"
                ))
            })?;

            output
        };

        // Phase 3: Append OutletInvokedEvent to the event log (ADR-010
        // criterion 3).
        //
        // SECURITY: unsigned event — uses `append_unsigned_event` because
        // `KeyCustody::sign()` is async and we are inside the tokio runtime
        // (block_on would panic). The event is chain-validated and Merkle-
        // committed but carries an empty signature. A compromised in-process
        // caller could inject fake OutletInvokedEvent entries. Migrate to signed
        // events via `append` once async FFI signing lands (SCP-214).
        // See: crates/scp-core/src/event_log/tree.rs::append_unsigned_event
        // See: .docs/lessons/unsigned-event-mcp-bridge.md
        #[allow(clippy::cast_possible_truncation)]
        let elapsed_ms = {
            let millis = start.elapsed().as_millis();
            if millis > u128::from(u64::MAX) {
                u64::MAX
            } else {
                millis as u64
            }
        };

        let output_hash = scp_core::context::outlets::sha256_json(&output);

        let outlet_event = scp_core::context::outlets::OutletInvokedEvent {
            request_id: uuid::Uuid::new_v4().to_string(),
            outlet_id: outlet_name.to_owned(),
            invoker_did: agent_did.clone().into(),
            status: scp_core::context::outlets::OutletStatus::Success,
            execution_time_ms: elapsed_ms,
            input_hash,
            output_hash: Some(output_hash),
            cost: None,
            // Non-streaming bridge invocation: degenerate/no-manifest
            // streaming-field defaults matching the lifecycle serde defaults.
            stream_chunk_count: 0,
            chunks_billed: 0,
            stream_manifest_hash: [0u8; 32],
            stream_terminal_status: scp_core::context::outlets::stream::StreamTerminalStatus::Ok,
            cancel_ack_seq: None,
            audit_anomaly: None,
        };

        let payload_data = serde_json::to_vec(&outlet_event).unwrap_or_default();

        let timestamp = scp_clock::Clock::now_secs(&scp_clock::SystemClock);

        // Re-acquire the DashMap lock briefly to append the event.
        // Returns (sequence, serialized_event_bytes) on success for
        // ProtocolRepository persistence (GitHub issue #303).
        let append_result = crate::runtime::with_context(&bi, context_id, |rt| {
            let sequence = scp_event_log::tree::event_count(&rt.event_log);
            let prev_hash = if rt.event_log.leaves().is_empty() {
                scp_event_log::tree::GENESIS_PREV_HASH
            } else {
                rt.event_log.leaves()[rt.event_log.leaves().len() - 1]
            };

            let event = scp_event_log::Event {
                event_type: scp_event_log::EventType::OutletInvoked,
                actor_did: agent_did.into(),
                timestamp,
                sequence,
                payload: scp_event_log::EventPayload {
                    data: payload_data.clone(),
                },
                prev_hash,
                signature: Vec::new(),
            };

            // Serialize the event for ProtocolRepository persistence.
            let event_bytes = rmp_serde::to_vec(&event)
                .map_err(|e| ScpPyError::context(format!("event serialization failed: {e}")))?;

            scp_event_log::tree::append_unsigned_event(&mut rt.event_log, &event)
                .map_err(|e| ScpPyError::context(e.to_string()))?;

            // Return the leaf hash (last appended leaf) for ProtocolRepository.
            let leaf_hash: [u8; 32] = rt.event_log.leaves()[rt.event_log.leaves().len() - 1];

            Ok((sequence, event_bytes, leaf_hash))
        });

        match append_result {
            Ok((sequence, event_bytes, _leaf_hash)) => {
                // Persist the event payload to storage (best-effort).
                // This enables py_event_log_query to return real events
                // instead of just a LogSummary (GitHub issue #303).
                //
                // Uses the Storage trait directly because the global storage
                // is Arc<EncryptingAdapter<InMemoryStorage>> and ProtocolRepository
                // requires an owned Storage impl. The key convention matches
                // ProtocolRepository's event_data_key format.
                if let Ok(storage) = crate::runtime::get_storage(&bi)
                    && let Ok(rt) = crate::runtime()
                {
                    let key = format!("context/{context_id}/event_data/{sequence:020}");
                    if let Err(e) = rt.block_on(storage.store(&key, &event_bytes)) {
                        tracing::warn!(
                            outlet = %outlet_name,
                            context = %context_id,
                            error = %e,
                            "failed to persist event payload to storage"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    outlet = %outlet_name,
                    context = %context_id,
                    error = %e,
                    "failed to append OutletInvokedEvent to event log"
                );
            }
        }

        Ok(output)
    }
}

// ---------------------------------------------------------------------------
// MCP handle registries
// ---------------------------------------------------------------------------

/// State for an active MCP server instance.
pub(crate) struct McpServerState {
    /// The identity DID running this server.
    identity_did: String,
    /// The context IDs being served.
    context_ids: Vec<String>,
    /// The transport mode (stdio or sse).
    transport: String,
    /// Whether the server has been stopped.
    stopped: bool,
    /// Shutdown signal sender. Dropping this signals the transport task to stop.
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// Handle to the tokio task running the transport. Used by `server_wait`.
    task_handle: Option<tokio::task::JoinHandle<()>>,
}

/// State for an active MCP client connection.
pub(crate) struct McpClientState {
    /// The transport mode (stdio or sse).
    transport: String,
    /// For stdio, the command used to spawn the subprocess.
    command: Option<Vec<String>>,
    /// For sse, the URL of the SSE endpoint.
    url: Option<String>,
    /// The real MCP client, connected and initialized.
    client: Arc<Mutex<McpClient<ClientTransport, SystemTimestamp>>>,
    /// The server end this state's [`Drop`] stops directly, whether
    /// `py_mcp_client_disconnect` removes the state or instance shutdown
    /// clears the registry: an in-flight call's clone of `client`, the
    /// connect's handshake included, would otherwise keep the transport open,
    /// and a thread parked on it, for as long as the server stays silent.
    server: ClientServer,
    /// Set by the state's [`Drop`]. A call reads it after it takes the
    /// client's lock, so a call queued behind an in-flight one fails as
    /// disconnected and sends nothing.
    closed: Arc<AtomicBool>,
}

/// The server end an [`McpClientState`]'s [`Drop`] stops.
enum ClientServer {
    /// A stdio client's subprocess, killed with its process group; a call
    /// waiting on its stdout then fails on EOF.
    Stdio(Arc<Mutex<Option<Child>>>),
    /// An SSE client's closer, which shuts down the `GET` stream and every
    /// POST a call waits on; that call then fails as closed.
    Sse(SseCloser),
}

impl McpClientState {
    fn new(
        transport: &str,
        command: Option<Vec<String>>,
        url: Option<String>,
        client: McpClient<ClientTransport, SystemTimestamp>,
        server: ClientServer,
    ) -> Self {
        Self {
            transport: transport.to_owned(),
            command,
            url,
            client: Arc::new(Mutex::new(client)),
            server,
            closed: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// A client cloned out of the registry, with its state's closed flag.
struct LiveMcpClient {
    client: Arc<Mutex<McpClient<ClientTransport, SystemTimestamp>>>,
    closed: Arc<AtomicBool>,
}

impl LiveMcpClient {
    /// Clones the handle's client out of the registry, so the shard guard
    /// drops before the call blocks. A missing handle fails with `code`, the
    /// operation's not-registered code (`TRANS_5020` or `TRANS_5023`).
    fn checkout(
        bi: &crate::runtime::PyBridgeInstance,
        handle: &str,
        code: &str,
    ) -> Result<Self, ScpPyError> {
        client_registry_of(bi)
            .get(handle)
            .map(|entry| Self {
                client: Arc::clone(&entry.client),
                closed: Arc::clone(&entry.closed),
            })
            .ok_or_else(|| {
                mcp_client_error(code, format!("MCP client handle '{handle}' not found"))
            })
    }

    /// Takes the client's lock, and refuses the call when the handle was
    /// disconnected while it waited. The refusal carries `disconnected_code`
    /// (`TRANS_5021` or `TRANS_5024`); a poisoned lock, left by a call that
    /// panicked, carries `failed_code` (`TRANS_5022` or `TRANS_5025`). The
    /// connect's `initialize` handshake passes `TRANS_5001` for both.
    fn lock(
        &self,
        handle: &str,
        disconnected_code: &str,
        failed_code: &str,
    ) -> Result<std::sync::MutexGuard<'_, McpClient<ClientTransport, SystemTimestamp>>, ScpPyError>
    {
        let guard = self
            .client
            .lock()
            .map_err(|e| mcp_client_error(failed_code, format!("client lock poisoned: {e}")))?;
        if self.closed.load(Ordering::Acquire) {
            return Err(mcp_client_error(
                disconnected_code,
                format!("MCP client handle '{handle}' was disconnected"),
            ));
        }
        Ok(guard)
    }
}

/// A `TransportError` carrying one of the MCP client codes
/// `TRANS_5020`..`TRANS_5025`.
fn mcp_client_error(code: &str, message: String) -> ScpPyError {
    ScpPyError::TransportError {
        message,
        code: code.to_owned(),
    }
}

/// Registers `state` under `handle` unless the instance has shut down.
///
/// Shutdown sets the core flag before it clears the registries, so the flag
/// read after the insert catches an insert that the clear missed; the state
/// is then removed and dropped, which stops a client's server end or ends a
/// server's transport task. A serve holds the GIL throughout, so for it the
/// check refuses a registration on an instance already shut down. A connect
/// registers before its handshake and releases the GIL for it (see
/// [`initialize_registered`]), so a Python-thread `SCP.shutdown` can also
/// clear the registry while the handshake waits.
fn register_unless_shut_down<S>(
    bi: &crate::runtime::PyBridgeInstance,
    registry: &DashMap<String, S>,
    handle: String,
    state: S,
) -> Result<String, ScpPyError> {
    registry.insert(handle.clone(), state);
    if bi.core.is_shutdown() {
        drop(registry.remove(&handle));
        return Err(ScpPyError::transport(
            "the SCP instance has shut down".to_owned(),
        ));
    }
    Ok(handle)
}

/// Registers a connected client and runs its `initialize` handshake with the
/// GIL released, returning the handle.
///
/// The state is registered before the handshake, so `SCP.shutdown` drops it
/// while the handshake waits on a silent server: the drop stops the server
/// end, the handshake fails on the closed transport, and the connect fails as
/// shut down. A handshake that fails for any other reason removes the state,
/// which stops the server end too. The handle is returned only after the
/// handshake, so no other call reaches the client while it runs.
fn initialize_registered(
    py: Python<'_>,
    bi: &crate::runtime::PyBridgeInstance,
    state: McpClientState,
) -> Result<String, ScpPyError> {
    let live = LiveMcpClient {
        client: Arc::clone(&state.client),
        closed: Arc::clone(&state.closed),
    };
    let handle = register_unless_shut_down(
        bi,
        client_registry_of(bi),
        generate_handle_id("mcp-client"),
        state,
    )?;
    // A connect is neither `tools/list` nor `tools/call`, so it keeps the
    // generic transport code.
    let result = py.allow_threads(|| {
        live.lock(&handle, codes::TRANS_5001, codes::TRANS_5001)?
            .initialize()
            .map(|_| ())
            .map_err(|e| ScpPyError::transport(format!("MCP initialize handshake failed: {e}")))
    });
    // A shutdown that began before this read fails the connect: its clear
    // dropped the state, or the remove here drops it. Shutdown sets the flag
    // before it clears, so a state its clear dropped is always seen here.
    if bi.core.is_shutdown() {
        drop(client_registry_of(bi).remove(&handle));
        return Err(ScpPyError::transport(
            "the SCP instance has shut down".to_owned(),
        ));
    }
    if let Err(e) = result {
        drop(client_registry_of(bi).remove(&handle));
        return Err(e);
    }
    Ok(handle)
}

impl Drop for McpClientState {
    fn drop(&mut self) {
        // A call queued on the handle's lock fails once it gets the lock.
        self.closed.store(true, Ordering::Release);
        // The transport is closed once the state drops, even while a call on
        // the handle is in flight: a stdio server dies with every process in
        // its process group, and an SSE client's sockets are shut down.
        match &self.server {
            ClientServer::Stdio(server) => stop_stdio_server(server),
            ClientServer::Sse(closer) => closer.close(),
        }
    }
}

// Phase D (#1695): `server_registry()` / `client_registry()` default-bridge
// shims and their `EMPTY_*_REGISTRY` fallback statics have been deleted.
// Callers must use the per-instance `server_registry_of(bi)` /
// `client_registry_of(bi)` accessors.

/// Builds the one server `py_mcp_serve` hands to its transport, paired with
/// the supervisor's context event receiver when there is one.
///
/// `subscribe_events()` returns `None` only for a supervisor built without the
/// channel; production supervisors always enable it (see
/// `crate::runtime::build_supervisor`). The bundle is unwired in three cases:
/// no supervisor is attached, the supervisor has no channel, or the instance
/// is suspended when the server is created, because
/// `crate::runtime::supervisor` refuses a suspended instance. Each case lasts
/// the server's life, because this function runs once per serve call: neither
/// a supervisor attached later nor a `resume()` rewires the server, so the
/// host creates the server again once the instance has a supervisor and is
/// not suspended to get subscriptions. An unwired server advertises every capability the event pump
/// backs as false (`resources.subscribe`, `resources.listChanged`,
/// `tools.listChanged`), rejects `resources/subscribe`, and sends no
/// `notifications/*/list_changed`, so those capabilities are honestly absent
/// rather than accepted-and-never-delivered. Serving is not failed outright,
/// because that would deny working functionality over an optional feature:
/// the server still serves `tools/list` and `resources/list|read`. It runs a
/// `tools/call` only with a supervisor attached; with none, it refuses every
/// `tools/call` (`ContextManager not yet attached`).
///
/// One call decides both halves: the server that advertises
/// `resources.subscribe` and the pump that honours it, folded into one
/// `McpServerForTransport` value. There is no setter that could desynchronize
/// them, and only one server is built per serve call: two servers over one
/// event source would each advertise subscriptions while only one had the
/// pump.
fn mcp_server_bundle(
    bi: &crate::runtime::PyBridgeInstance,
    provider: FfiBridgeProvider,
) -> scp_mcp::server::McpServerForTransport<FfiBridgeProvider> {
    let context_events = match crate::runtime::supervisor(bi) {
        Ok(supervisor) => supervisor.subscribe_events(),
        Err(e) => {
            tracing::warn!("MCP server: no supervisor event source ({e})");
            None
        }
    };
    if context_events.is_none() {
        tracing::warn!(
            "MCP server: no context event source — resource subscriptions \
             will be advertised as unsupported and rejected if requested"
        );
    }
    McpServer::with_optional_event_source(provider, context_events)
}

/// Refuses to serve from a current-thread bridge runtime while a supervisor is
/// attached.
///
/// With a supervisor attached, every provider gate reads the actor's role
/// state (`FfiBridgeProvider::held_role_state`), which blocks the transport
/// task's thread until the actor answers. On a current-thread runtime that
/// thread is the only one that could run the actor, so every gated request
/// would fail; `py_mcp_serve` fails instead of returning a handle to a server
/// that answers none of them. The bridge runtime falls back to current-thread
/// only when the multi-thread build fails (`crate::init_runtime`).
fn check_serve_runtime(
    flavor: tokio::runtime::RuntimeFlavor,
    has_supervisor: bool,
) -> Result<(), ScpPyError> {
    if has_supervisor && flavor != tokio::runtime::RuntimeFlavor::MultiThread {
        return Err(ScpPyError::transport(
            "cannot serve MCP from a current-thread bridge runtime while a supervisor \
             is attached: every gate reads the actor's role state, which that runtime \
             cannot run while the gate blocks its only thread"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Returns a reference to the given bridge instance's MCP server registry.
fn server_registry_of(bi: &crate::runtime::PyBridgeInstance) -> &DashMap<String, McpServerState> {
    bi.mcp_server_registry().as_ref()
}

/// Returns a reference to the given bridge instance's MCP client registry.
fn client_registry_of(bi: &crate::runtime::PyBridgeInstance) -> &DashMap<String, McpClientState> {
    bi.mcp_client_registry().as_ref()
}

/// Generates a unique, unpredictable handle ID.
///
/// Delegates to [`crate::types::generate_random_id`] for the shared CSPRNG
/// pattern. MCP handles use prefixed IDs (e.g., `mcp-server-{hex}`) since
/// they are internal-only and never appear in `scp://` URIs.
fn generate_handle_id(prefix: &str) -> String {
    crate::types::generate_random_id(prefix)
}

// ---------------------------------------------------------------------------
// MCP server bridge functions
// ---------------------------------------------------------------------------

/// Starts an MCP server that exposes SCP context outlets.
///
/// Creates an MCP server backed by a `FfiBridgeProvider` that reads outlets
/// and context state from the scp-ffi runtime registry. For `"stdio"`
/// transport, the server processes JSON-RPC messages via a tokio task. For
/// `"sse"` transport, the server binds a loopback HTTP server on an ephemeral
/// port behind a per-server bearer token. This function returns neither the
/// port nor the token, so no client can reach an SSE server it starts.
///
/// A server started while no supervisor is attached, or while the instance
/// is suspended, has no resource subscriptions for its whole life: it
/// advertises `resources.subscribe`, `resources.listChanged` and
/// `tools.listChanged` as false, rejects `resources/subscribe`, and sends no
/// `list_changed` notification. With no supervisor attached it also refuses
/// every `tools/call`. Attaching a supervisor or calling `resume()` later
/// does not change a running server; stop it and serve again.
///
/// # Arguments
///
/// * `identity_did` -- The DID of the identity running the server.
/// * `context_ids` -- List of context IDs to expose.
/// * `transport` -- Transport mode: `"stdio"` or `"sse"`.
///
/// # Returns
///
/// An opaque server handle string for use with `py_mcp_server_stop` and
/// `py_mcp_server_wait`.
///
/// # Errors
///
/// Raises `TransportError` if the server fails to start, if the bridge
/// runtime is current-thread while a supervisor is attached (see
/// `check_serve_runtime`), or if the instance shuts down before the server
/// is registered.
///
/// See ADR-015: MCP server with context namespace mapping.
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_mcp_serve", signature = (identity_did, context_ids, transport, ucan_token=None))]
    #[allow(clippy::needless_pass_by_value)] // PyO3 requires owned Vec for method arguments.
    #[allow(clippy::too_many_lines)] // MCP server startup with stdio/SSE transport dispatch is inherently verbose.
    pub fn py_mcp_serve(
        &self,
        identity_did: &str,
        context_ids: Vec<String>,
        transport: &str,
        ucan_token: Option<String>,
    ) -> PyResult<String> {
        let bi = &*self.inner;
        let bi_arc = Arc::clone(&self.inner);
        validate::validate_did(identity_did)?;
        validate::validate_transport_mode(transport)?;
        for ctx_id in &context_ids {
            validate::validate_context_id(ctx_id)?;
        }

        // Validate that all context IDs are registered in the runtime.
        for ctx_id in &context_ids {
            crate::runtime::with_context(bi, ctx_id, |_rt| Ok(())).map_err(|e| {
                ScpPyError::transport(format!("cannot serve context '{ctx_id}': {e}"))
            })?;
        }

        // Create the FfiBridgeProvider and McpServer.
        //
        // #1549 round-2: hold the bridge instance as a `Weak`, not an
        // `Arc`. The MCP server task is spawned on the shared tokio
        // runtime (`rt.spawn(...)`) and is NOT enrolled in the
        // per-instance `JoinSet`, so an `Arc` would leak the
        // `PyBridgeInstance` (and with it `ContextManager`, identity
        // registry, relay connection) for the remainder of the process
        // when the caller drops `PyScp` without calling
        // `py_mcp_server_stop`. The task body additionally selects on
        // the instance's `cancel_token` so `emergency_cancel_tasks()`
        // from `Drop` can wake it between requests.
        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi_arc),
            agent_did: identity_did.to_owned(),
            context_ids: context_ids.clone(),
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: ucan_token,

            agent_proof_tokens: None,
        };

        // Create a shutdown channel.
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        // Start the transport task on the tokio runtime.
        let rt = crate::runtime()?;
        check_serve_runtime(
            rt.handle().runtime_flavor(),
            bi.core.try_supervisor().is_some(),
        )?;
        let transport_mode = transport.to_owned();
        // Capture the cancel token so the server task exits when the
        // instance is dropped, even if the caller never calls
        // `py_mcp_server_stop`. Cloning a `CancellationToken` does not
        // extend the instance's lifetime.
        let cancel_token = bi_arc.core.cancel_token();

        // Subscribe to the supervisor's events *before* spawning, so no event
        // emitted between here and the transport loop starting is missed.
        let server = mcp_server_bundle(bi, provider);

        let task_handle = rt.spawn(async move {
            match transport_mode.as_str() {
                "stdio" => {
                    // Run the MCP server over stdio via the shared
                    // `scp_mcp::stdio::run_stdio` loop. It owns stdout so the
                    // response writer and the resource-subscription event pump
                    // interleave as whole lines, and it parses JSON-RPC
                    // notifications correctly (a bare `JsonRpcRequest` decode
                    // rejects them — they carry no `id`). The server and its pump
                    // travel as the single `server` bundle, so the loop cannot be
                    // handed one without the other.
                    //
                    // We also listen for the shutdown signal AND the bridge
                    // instance's cancel token so `emergency_cancel_tasks()`
                    // from the instance's `Drop` impl can terminate this task
                    // even when the caller never invoked `py_mcp_server_stop`.
                    tokio::select! {
                        _ = shutdown_rx => {
                            // Shutdown signal received -- exit cleanly.
                        }
                        () = cancel_token.cancelled() => {
                            tracing::debug!(
                                "MCP stdio server task exiting — bridge instance cancelled"
                            );
                        }
                        result = scp_mcp::stdio::run_stdio(server) => {
                            if let Err(e) = result {
                                tracing::error!("MCP stdio server error: {e}");
                            }
                        }
                    }
                }
                "sse" => {
                    // `run_sse` takes ownership of the `McpServerForTransport`
                    // bundle: the server and, when it advertises
                    // subscriptions, the event pump that delivers them. No
                    // mutex wrapper, since the SSE transport owns the bundle.
                    // `SseConfig::new` draws a fresh bearer token, and the transport rejects
                    // every request that does not present it. This bridge returns neither that
                    // token nor the bound port to its caller, so no client can reach this
                    // server.
                    let config = scp_mcp::sse::SseConfig::new(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        0,
                    )));

                    // Create a ShutdownHandle for the SSE server. Wire both
                    // the oneshot shutdown_rx (py_mcp_server_stop) AND the
                    // bridge instance's cancel_token (emergency_cancel_tasks
                    // from Drop) so either signal tears down the SSE server.
                    // Without the cancel_token branch, a caller that drops
                    // `PyScp` without calling `py_mcp_server_stop` would
                    // leave this task running indefinitely and pin
                    // `PyBridgeInstance` state alive via the
                    // `McpServer`-held resources (#1549 round-2).
                    let sse_shutdown = scp_mcp::sse::ShutdownHandle::new();
                    let sse_shutdown_trigger = sse_shutdown.clone();
                    tokio::spawn(async move {
                        tokio::select! {
                            _ = shutdown_rx => {}
                            () = cancel_token.cancelled() => {}
                        }
                        sse_shutdown_trigger.shutdown();
                    });

                    let result = scp_mcp::sse::run_sse(server, config, sse_shutdown).await;
                    if let Err(e) = result {
                        tracing::error!("MCP SSE server error: {e}");
                    }
                }
                _ => {} // Already validated above.
            }
        });

        // Create the server state and register it.
        let handle = generate_handle_id("mcp-server");
        let state = McpServerState {
            identity_did: identity_did.to_owned(),
            context_ids,
            transport: transport.to_owned(),
            stopped: false,
            shutdown_tx: Some(shutdown_tx),
            task_handle: Some(task_handle),
        };

        Ok(register_unless_shut_down(
            bi,
            server_registry_of(bi),
            handle,
            state,
        )?)
    }
}

/// Stops a running MCP server.
///
/// Sends a shutdown signal to the transport task and marks the server as
/// stopped. The transport task will exit after processing any in-flight
/// requests.
///
/// # Arguments
///
/// * `handle` -- The server handle returned by `py_mcp_serve`.
///
/// # Errors
///
/// Raises `TransportError` if the server is not found or already stopped.
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_mcp_server_stop")]
    pub fn py_mcp_server_stop(&self, handle: &str) -> PyResult<()> {
        let bi = &*self.inner;
        validate::validate_mcp_handle(handle)?;
        let mut entry = server_registry_of(bi).get_mut(handle).ok_or_else(|| {
            ScpPyError::transport(format!("MCP server handle '{handle}' not found"))
        })?;

        if entry.stopped {
            return Err(
                ScpPyError::transport(format!("MCP server '{handle}' is already stopped")).into(),
            );
        }

        entry.stopped = true;

        // Send the shutdown signal. Dropping the sender signals the receiver.
        if let Some(tx) = entry.shutdown_tx.take() {
            let _ = tx.send(());
        }
        drop(entry);

        Ok(())
    }
}

/// Blocks until the MCP server exits.
///
/// For stdio transport, waits until stdin is closed (EOF) or the server is
/// stopped via `py_mcp_server_stop`. For SSE transport, waits until the
/// HTTP server is terminated.
///
/// # Arguments
///
/// * `handle` -- The server handle returned by `py_mcp_serve`.
///
/// # Errors
///
/// Raises `TransportError` if the server handle is not found.
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_mcp_server_wait")]
    pub fn py_mcp_server_wait(&self, py: Python<'_>, handle: &str) -> PyResult<()> {
        let bi = &*self.inner;
        validate::validate_mcp_handle(handle)?;
        // Extract the task handle if available.
        let task_handle = {
            let mut entry = server_registry_of(bi).get_mut(handle).ok_or_else(|| {
                ScpPyError::transport(format!("MCP server handle '{handle}' not found"))
            })?;

            if entry.stopped && entry.task_handle.is_none() {
                return Ok(());
            }

            entry.task_handle.take()
        };

        // Block on the task handle if we have one.
        if let Some(task) = task_handle {
            let rt = crate::runtime()?;
            py.allow_threads(|| {
                rt.block_on(async {
                    let _ = task.await;
                });
            });
        }

        Ok(())
    }
}

/// Returns metadata about a running MCP server.
///
/// # Arguments
///
/// * `handle` -- The server handle returned by `py_mcp_serve`.
///
/// # Returns
///
/// A dict with keys: `identity_did`, `context_ids`, `transport`, `stopped`.
///
/// # Errors
///
/// Raises `TransportError` if the server handle is not found.
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_mcp_server_info")]
    pub fn py_mcp_server_info(&self, py: Python<'_>, handle: &str) -> PyResult<PyObject> {
        let bi = &*self.inner;
        validate::validate_mcp_handle(handle)?;
        let entry = server_registry_of(bi).get(handle).ok_or_else(|| {
            ScpPyError::transport(format!("MCP server handle '{handle}' not found"))
        })?;

        let dict = PyDict::new(py);
        dict.set_item("identity_did", &entry.identity_did)?;
        dict.set_item("context_ids", &entry.context_ids)?;
        dict.set_item("transport", &entry.transport)?;
        dict.set_item("stopped", entry.stopped)?;
        drop(entry);
        Ok(dict.into())
    }
}

/// Returns metadata about an active MCP client connection.
///
/// # Arguments
///
/// * `handle` -- The client handle returned by `py_mcp_client_connect_*`.
///
/// # Returns
///
/// A dict with keys: `transport`, `command` (nullable), `url` (nullable).
///
/// # Errors
///
/// Raises `TransportError` if the client handle is not found.
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_mcp_client_info")]
    pub fn py_mcp_client_info(&self, py: Python<'_>, handle: &str) -> PyResult<PyObject> {
        let bi = &*self.inner;
        validate::validate_mcp_handle(handle)?;
        let entry = client_registry_of(bi).get(handle).ok_or_else(|| {
            ScpPyError::transport(format!("MCP client handle '{handle}' not found"))
        })?;

        let dict = PyDict::new(py);
        dict.set_item("transport", &entry.transport)?;
        dict.set_item("command", &entry.command)?;
        dict.set_item("url", &entry.url)?;
        drop(entry);
        Ok(dict.into())
    }
}

// ---------------------------------------------------------------------------
// MCP client bridge functions
// ---------------------------------------------------------------------------

/// Connects to an external MCP server via stdio transport.
///
/// Spawns the given command as a subprocess and communicates via
/// line-delimited JSON over stdin/stdout. Performs the MCP initialize
/// handshake before returning.
///
/// # Arguments
///
/// * `command` -- The command and arguments to spawn (e.g.,
///   `["uvx", "some-mcp-server"]`).
///
/// # Returns
///
/// An opaque client handle string.
///
/// # Errors
///
/// Raises `TransportError` if the subprocess fails to start, the MCP
/// initialize handshake fails, or the instance shuts down before the connect
/// returns; in both of the last two cases the subprocess is killed, and a
/// shutdown during the handshake ends it.
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_mcp_client_connect_stdio")]
    #[allow(clippy::needless_pass_by_value)] // PyO3 requires owned Vec for method arguments.
    pub fn py_mcp_client_connect_stdio(
        &self,
        py: Python<'_>,
        command: Vec<String>,
    ) -> PyResult<String> {
        let bi = &*self.inner;
        if command.is_empty() {
            return Err(
                ScpPyError::validation("command must be a non-empty list".to_owned()).into(),
            );
        }

        // Spawn the subprocess and create the transport. Allowlist is
        // per-instance (lives on `CoreFields::mcp_allowlist`). The GIL is
        // released for the spawn and the blocking handshake, so a silent
        // server stalls only this thread.
        let transport = py
            .allow_threads(|| StdioClientTransport::spawn(bi.core.mcp_allowlist(), &command))
            .map_err(|e| ScpPyError::transport(format!("failed to connect stdio client: {e}")))?;
        let server = ClientServer::Stdio(transport.server_process());
        let client = McpClient::new(ClientTransport::Stdio(transport));
        let state = McpClientState::new("stdio", Some(command), None, client, server);
        Ok(initialize_registered(py, bi, state)?)
    }
}

/// Connects to an external MCP server via SSE transport.
///
/// Connects to the given URL using HTTP with Server-Sent Events for
/// server-to-client messages and POST for client-to-server messages.
/// Performs the MCP initialize handshake before returning.
///
/// # Arguments
///
/// * `url` -- The URL of the SSE endpoint.
/// * `auth_token` -- The bearer token sent in an `Authorization` header on
///   every request, or `None` for a server that runs no bearer check. An SCP
///   SSE server always runs one (ADR-015). The transport has no TLS, so a
///   token is sent only to a loopback host.
///
/// # Returns
///
/// An opaque client handle string.
///
/// # Errors
///
/// Raises `TransportError` if the token is malformed, or if the connection
/// or MCP handshake fails, including when the server refuses the token, or
/// if the instance shuts down before the connect returns; a shutdown during
/// the handshake closes the connection and ends it.
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_mcp_client_connect_sse", signature = (url, auth_token))]
    pub fn py_mcp_client_connect_sse(
        &self,
        py: Python<'_>,
        url: &str,
        auth_token: Option<&str>,
    ) -> PyResult<String> {
        let bi = &*self.inner;
        validate::validate_relay_url(url)?;

        // Connect to the SSE endpoint and perform the initialize handshake
        // with the GIL released, so a silent server stalls only this thread.
        let transport = py
            .allow_threads(|| SseClientTransport::connect(url, auth_token))
            .map_err(|e| ScpPyError::transport(format!("failed to connect SSE client: {e}")))?;
        let server = ClientServer::Sse(transport.closer());
        let client = McpClient::new(ClientTransport::Sse(transport));
        let state = McpClientState::new("sse", None, Some(url.to_owned()), client, server);
        Ok(initialize_registered(py, bi, state)?)
    }
}

/// Disconnects from an external MCP server.
///
/// Removes the client from the registry. For stdio clients, the subprocess and,
/// on Unix, every process in its process group (such as the server an `npx`
/// launcher started) are killed before this returns, and the subprocess is
/// reaped, even while a call on the handle is in flight; that call then fails
/// on the closed stdout. For SSE clients, the `GET` stream's socket and the
/// socket of every POST a call waits on are shut down before this returns,
/// so an in-flight call fails as closed. A call queued behind an in-flight
/// one, on either transport, fails as disconnected once it gets the client
/// and sends nothing.
///
/// # Arguments
///
/// * `handle` -- The client handle returned by `py_mcp_client_connect_*`.
///
/// # Errors
///
/// Raises `TransportError` if the client handle is not found (e.g. already
/// disconnected or never connected).
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_mcp_client_disconnect")]
    pub fn py_mcp_client_disconnect(&self, handle: &str) -> PyResult<()> {
        let bi = &*self.inner;
        validate::validate_mcp_handle(handle)?;
        let (_, state) = client_registry_of(bi).remove(handle).ok_or_else(|| {
            ScpPyError::transport(format!("MCP client handle '{handle}' not found"))
        })?;

        // A call in flight on this handle holds its own clone of
        // `state.client`, so dropping `state` does not drop the transport.
        // The state's `Drop` kills the stdio subprocess's process group or
        // shuts down the SSE sockets here; the in-flight call then fails on
        // the closed transport and drops the last clone.
        drop(state);

        Ok(())
    }
}

/// Lists available outlets from an external MCP server.
///
/// Sends a `tools/list` JSON-RPC request to the connected MCP server and
/// returns the outlet definitions as a list of Python dicts.
///
/// # Arguments
///
/// * `handle` -- The client handle returned by `py_mcp_client_connect_*`.
///
/// # Returns
///
/// A list of Python dicts, each with `name`, `description`, and
/// `inputSchema` keys.
///
/// # Errors
///
/// Raises `TransportError` with `SCP-TRANS-5020` when no client is
/// registered under `handle`, `SCP-TRANS-5021` when the handle was
/// disconnected while the call waited for the client's lock, and
/// `SCP-TRANS-5022` when the request fails on the transport, the server
/// answers with an error, or an earlier call panicked holding the lock.
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_mcp_client_list_tools")]
    pub fn py_mcp_client_list_tools(&self, py: Python<'_>, handle: &str) -> PyResult<PyObject> {
        let bi = &*self.inner;
        validate::validate_mcp_handle(handle)?;
        // Send the real tools/list request via the MCP client.
        let client = LiveMcpClient::checkout(bi, handle, codes::TRANS_5020)?;

        // The GIL is released for the blocking request, so another Python
        // thread can run, including a `py_mcp_client_disconnect` that ends
        // this call against a silent stdio or SSE server.
        let outlets = py.allow_threads(|| {
            let client_guard = client.lock(handle, codes::TRANS_5021, codes::TRANS_5022)?;
            client_guard
                .list_tools()
                .map_err(|e| mcp_client_error(codes::TRANS_5022, format!("tools/list failed: {e}")))
        })?;

        // Convert outlet definitions to JSON array for Python.
        let outlets_json: Vec<serde_json::Value> = outlets
            .iter()
            .map(|t| {
                serde_json::json!({
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.input_schema,
                })
            })
            .collect();

        json_to_py_dict(py, &serde_json::Value::Array(outlets_json))
    }
}

/// Invokes an external MCP outlet with SCP provenance wrapping.
///
/// Sends a `tools/call` JSON-RPC request to the external MCP server and
/// wraps the result with provenance metadata recording the source outlet,
/// invoking agent, context, and timestamp.
///
/// # Arguments
///
/// * `handle` -- The client handle returned by `py_mcp_client_connect_*`.
/// * `outlet_name` -- The name of the external outlet to invoke.
/// * `input` -- A Python dict of input parameters.
/// * `context_id` -- The SCP context ID for provenance tracking.
/// * `identity_did` -- The DID of the invoking identity.
///
/// # Returns
///
/// A Python dict with `content`, `is_error`, and `provenance` keys.
///
/// # Errors
///
/// Raises `TransportError` with `SCP-TRANS-5023` when no client is
/// registered under `handle`, `SCP-TRANS-5024` when the handle was
/// disconnected while the call waited for the client's lock, and
/// `SCP-TRANS-5025` when the request fails on the transport, the server
/// answers with an error, or an earlier call panicked holding the lock.
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_mcp_client_invoke")]
    pub fn py_mcp_client_invoke(
        &self,
        py: Python<'_>,
        handle: &str,
        outlet_name: &str,
        input: &Bound<'_, PyDict>,
        context_id: &str,
        identity_did: &str,
    ) -> PyResult<PyObject> {
        let bi = &*self.inner;
        validate::validate_mcp_handle(handle)?;
        validate::validate_outlet_name(outlet_name)?;
        validate::validate_context_id(context_id)?;
        validate::validate_did(identity_did)?;
        let client = LiveMcpClient::checkout(bi, handle, codes::TRANS_5023)?;

        // Convert input to JSON.
        let input_json = py_dict_to_json(input)?;

        // Send the real tools/call request via the MCP client.
        // The GIL is released for the blocking request, as in
        // `py_mcp_client_list_tools`.
        let result = py.allow_threads(|| {
            let client_guard = client.lock(handle, codes::TRANS_5024, codes::TRANS_5025)?;
            client_guard
                .invoke(outlet_name, input_json, context_id, identity_did)
                .map_err(|e| mcp_client_error(codes::TRANS_5025, format!("tools/call failed: {e}")))
        })?;

        // Convert the McpToolResult to a Python dict.
        let content_json: Vec<serde_json::Value> = result
            .content
            .iter()
            .map(|c| serde_json::to_value(c).unwrap_or(serde_json::Value::Null))
            .collect();

        let result_json = serde_json::json!({
            "content": content_json,
            "is_error": result.is_error,
            "provenance": {
                "source": result.provenance.source,
                "invoked_by": result.provenance.invoked_by,
                "context": result.provenance.context,
                "timestamp": result.provenance.timestamp,
            },
        });

        json_to_py_dict(py, &result_json)
    }
}

/// Loads active contexts for a DID, combining local registry and relay discovery.
///
/// Context discovery is **client-side** because the SCP relay is a dumb blob
/// store with no identity-to-context mapping. This function:
///
/// 1. Collects contexts from the local runtime registry (always available).
/// 2. Collects contexts from the known-contexts registry (SCP-213).
/// 3. If a relay connection is active, probes known routing IDs via QUERY
///    to determine which contexts have recent activity on the relay.
/// 4. Falls back gracefully to local-only when the relay is unreachable.
///
/// Results are deduplicated by context ID. Each result dict contains:
/// - `context_id` -- The context identifier.
/// - `source` -- `"local"`, `"relay"`, or `"local+relay"`.
/// - `creator_did` -- The context creator's DID (if available from runtime).
/// - `member_count` -- Number of members (if available from runtime).
/// - `outlet_count` -- Number of registered outlets (if available from runtime).
/// - `relay_active` -- `True` if the relay returned blobs for this context.
///
/// # Arguments
///
/// * `identity_did` -- The DID to look up contexts for.
/// * `relay_url` -- The relay URL to query (used as a hint; the active
///   transport connection is preferred if available).
///
/// # Returns
///
/// A list of context dicts. Returns an empty list if no contexts are found.
///
/// # Errors
///
/// Raises `TransportError` if the relay query fails fatally (transient
/// failures are handled by falling back to local-only).
///
/// See SCP-213, ADR-015 in `.docs/adrs/phase-3.md`.
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_mcp_load_contexts")]
    pub fn py_mcp_load_contexts(
        &self,
        py: Python<'_>,
        identity_did: &str,
        _relay_url: &str,
    ) -> PyResult<Vec<PyObject>> {
        let bi = &*self.inner;
        validate::validate_did(identity_did)?;
        // Step 1: Collect contexts from the local runtime registry.
        let local_context_ids = crate::runtime::context_ids_for_member(bi, identity_did);

        // Step 2: Collect contexts from the known-contexts registry.
        let known = crate::runtime::known_contexts_for_member_on(bi, identity_did);

        // Step 3: Probe relay for known routing IDs (if connected).
        let relay_active_set = probe_relay_for_known_contexts(bi, &known);

        // Step 4: Build deduplicated result set.
        let mut seen = std::collections::HashSet::new();
        let mut results = Vec::new();

        // Add local contexts first.
        for ctx_id in &local_context_ids {
            seen.insert(ctx_id.clone());
            let dict = PyDict::new(py);
            dict.set_item("context_id", ctx_id)?;

            let relay_active = relay_active_set.contains(ctx_id);
            if relay_active {
                dict.set_item("source", "local+relay")?;
            } else {
                dict.set_item("source", "local")?;
            }
            dict.set_item("relay_active", relay_active)?;

            // Enrich with creator DID and member count from runtime state.
            if let Ok(info) = crate::runtime::with_context(bi, ctx_id, |rt| {
                Ok((
                    rt.creator_did.clone(),
                    rt.role_state.members.len(),
                    rt.outlet_registry.len(),
                ))
            }) {
                dict.set_item("creator_did", info.0)?;
                dict.set_item("member_count", info.1)?;
                dict.set_item("outlet_count", info.2)?;
            }

            results.push(dict.into());
        }

        // Add relay-only contexts (known but not in local registry).
        for (ctx_id, known_ctx) in &known {
            if seen.contains(ctx_id) {
                continue;
            }
            seen.insert(ctx_id.clone());
            let dict = PyDict::new(py);
            dict.set_item("context_id", ctx_id)?;

            let relay_active = relay_active_set.contains(ctx_id);
            dict.set_item("source", "relay")?;
            dict.set_item("relay_active", relay_active)?;
            dict.set_item("relay_url", &known_ctx.relay_url)?;

            results.push(dict.into());
        }

        Ok(results)
    }
}

/// Probes the relay for activity on known context routing IDs.
///
/// For each known context, sends a QUERY with `limit=1` to check if any
/// blobs exist for that routing ID. Returns the set of context IDs that
/// have activity on the relay.
///
/// Falls back to an empty set if no relay connection is available or if
/// queries fail (graceful degradation).
fn probe_relay_for_known_contexts(
    bi: &crate::runtime::PyBridgeInstance,
    known: &[(String, crate::runtime::KnownContext)],
) -> std::collections::HashSet<String> {
    use scp_transport::traits::RoutingId;

    let mut active = std::collections::HashSet::new();

    if known.is_empty() {
        return active;
    }

    // Check if a transport manager is available. If not, return empty set.
    if !crate::runtime::has_transport_manager(bi) {
        return active;
    }

    // Get the tokio runtime for blocking on async queries.
    let Ok(rt) = crate::runtime() else {
        return active;
    };

    // Probe each known context's routing ID on the relay via the
    // TransportManager. Uses manager.query() which delegates to the
    // first adapter (Phase 1 single-adapter mode).
    for (ctx_id, known_ctx) in known {
        let routing_id = RoutingId::new(known_ctx.routing_id);
        let query_result = crate::runtime::with_transport_manager(bi, |manager| {
            rt.block_on(manager.query(&routing_id, None)).map_err(|e| {
                crate::error::ScpPyError::transport(format!("relay probe failed: {e}"))
            })
        });

        match query_result {
            Ok(envelopes) if !envelopes.is_empty() => {
                active.insert(ctx_id.clone());
            }
            // Empty result (no activity) or query failure (relay error,
            // timeout, etc.) — skip gracefully; other contexts may succeed.
            _ => {}
        }
    }

    active
}

// ---------------------------------------------------------------------------
// Stdio allowlist error mapping
// ---------------------------------------------------------------------------

/// Maps [`AllowlistError`](scp_mcp::allowlist::AllowlistError) to the appropriate [`ScpPyError`] variant.
///
/// Input-validation errors map to `ValidationError`. Runtime/policy errors
/// map to `TransportError`. Exhaustive match ensures new variants produce
/// a compile error instead of silently falling through.
///
/// Mutex poisoning is NOT modelled by `AllowlistError` — the allowlist
/// type is now per-instance and the mutex lives on `CoreFields`. Each call
/// site maps `PoisonError` to its own typed transport error before calling
/// into the allowlist.
// `clippy::match_same_arms` — the explicit wildcard arm at the end is intentional:
// `AllowlistError` is `#[non_exhaustive]`, so future variants must compile, and
// classifying them as a validation error fails closed. Folding the wildcard into
// the named OR-chain would erase that documentation.
#[allow(clippy::needless_pass_by_value, clippy::match_same_arms)]
fn allowlist_err(e: allowlist::AllowlistError) -> ScpPyError {
    use scp_mcp::allowlist::AllowlistError;
    let msg = e.to_string();
    match e {
        AllowlistError::EmptyEntry
        | AllowlistError::PathInEntry(_)
        | AllowlistError::NulInEntry(_)
        | AllowlistError::ControlCharInEntry(_)
        | AllowlistError::PathInCommand(_)
        | AllowlistError::InvalidCommand(_) => ScpPyError::ValidationError {
            message: msg,
            code: codes::VALID_7033.to_owned(),
        },
        AllowlistError::NotAllowed { .. } => ScpPyError::TransportError {
            message: msg,
            code: codes::TRANS_5030.to_owned(),
        },
        // `AllowlistError` is `#[non_exhaustive]` — fail closed for any
        // future variant by classifying as a validation error so an unknown
        // policy decision can never silently turn into a permissive
        // transport-success path.
        _ => ScpPyError::ValidationError {
            message: msg,
            code: codes::VALID_7033.to_owned(),
        },
    }
}

// ---------------------------------------------------------------------------
// Stdio allowlist configuration (PyO3, per-instance)
// ---------------------------------------------------------------------------

/// Maps a `PoisonError` from the per-instance allowlist mutex to a
/// transport-level [`ScpPyError`]. Uses `SCP-TRANS-5030` for cross-bridge
/// parity with NAPI / `UniFFI` — same code, same semantics, regardless of SDK.
fn allowlist_lock_poisoned() -> ScpPyError {
    ScpPyError::TransportError {
        message: "stdio allowlist lock poisoned".to_owned(),
        code: codes::TRANS_5030.to_owned(),
    }
}

/// Per-instance MCP stdio allowlist methods on [`PyScp`](crate::scp::PyScp).
///
/// The allowlist is owned by `CoreFields::mcp_allowlist` (one per bridge
/// instance) — disabling enforcement on one `SCP` does not leak into another.
#[pymethods]
impl crate::scp::PyScp {
    /// Configures this instance's MCP stdio subprocess allowlist.
    ///
    /// By default, only well-known MCP server launchers are permitted (e.g.
    /// `uvx`, `npx`, `node`, `python3`). Call this method to extend the
    /// per-instance allow set.
    ///
    /// # Arguments
    ///
    /// * `additional_binaries` -- Binary basenames to add to the allowlist.
    ///
    /// # Errors
    ///
    /// Raises `ValidationError` if any entry is invalid (path, NUL, empty).
    /// Raises `TransportError` if the allowlist lock is poisoned.
    #[pyo3(name = "mcp_configure_stdio_allowlist", signature = (additional_binaries=vec![]))]
    #[allow(clippy::needless_pass_by_value)] // PyO3 requires owned Vec for method arguments.
    pub fn mcp_configure_stdio_allowlist(&self, additional_binaries: Vec<String>) -> PyResult<()> {
        let instance_id = self.inner.core.instance_id();
        self.inner
            .core
            .with_mcp_allowlist(|a| a.configure(&additional_binaries))
            .map_err(|_| allowlist_lock_poisoned())?
            .map_err(allowlist_err)?;
        tracing::info!(
            instance_id,
            added = ?additional_binaries,
            "MCP stdio allowlist extended"
        );
        Ok(())
    }

    /// Disable this instance's stdio allowlist entirely (unrestricted mode).
    ///
    /// # Safety
    ///
    /// This allows **any** binary to be spawned as a subprocess by THIS
    /// instance. Other `SCP` instances are unaffected. Only use when the
    /// command source is fully trusted.
    ///
    /// # Errors
    ///
    /// Raises `TransportError` if the allowlist lock is poisoned.
    #[pyo3(name = "mcp_disable_stdio_allowlist")]
    pub fn mcp_disable_stdio_allowlist(&self) -> PyResult<()> {
        let instance_id = self.inner.core.instance_id();
        self.inner
            .core
            .with_mcp_allowlist(|a| a.disable_enforcement(instance_id))
            .map_err(|_| allowlist_lock_poisoned())?;
        Ok(())
    }

    /// Reset this instance's stdio allowlist to its default state.
    ///
    /// Restores the default binaries and re-enables allowlist enforcement
    /// (clears unrestricted mode) for THIS instance only.
    ///
    /// # Errors
    ///
    /// Raises `TransportError` if the allowlist lock is poisoned.
    #[pyo3(name = "mcp_reset_stdio_allowlist")]
    pub fn mcp_reset_stdio_allowlist(&self) -> PyResult<()> {
        let instance_id = self.inner.core.instance_id();
        self.inner
            .core
            .with_mcp_allowlist(scp_mcp::allowlist::StdioAllowlist::reset)
            .map_err(|_| allowlist_lock_poisoned())?;
        tracing::info!(instance_id, "MCP stdio allowlist reset to defaults");
        Ok(())
    }

    /// Return the current stdio allowlist state for this instance.
    ///
    /// Returns a Python dict with keys:
    /// - `"allowed"`: sorted list of allowed binary names
    /// - `"unrestricted"`: bool indicating whether the allowlist is bypassed
    ///
    /// # Errors
    ///
    /// Raises `TransportError` if the allowlist lock is poisoned.
    #[pyo3(name = "mcp_get_stdio_allowlist")]
    pub fn mcp_get_stdio_allowlist(&self, py: Python<'_>) -> PyResult<PyObject> {
        let state = self
            .inner
            .core
            .with_mcp_allowlist(|a| a.snapshot())
            .map_err(|_| allowlist_lock_poisoned())?;

        let dict = PyDict::new(py);
        dict.set_item("allowed", state.allowed)?;
        dict.set_item("unrestricted", state.unrestricted)?;
        Ok(dict.into())
    }
}

// ---------------------------------------------------------------------------
// Outlet handler registration
// ---------------------------------------------------------------------------

/// Registers a Python callable as the handler for an outlet in a context.
///
/// The handler is called when the outlet is invoked via MCP
/// (`FfiBridgeProvider::invoke_outlet`). It receives the outlet's validated
/// JSON input as a Python dict and must return a Python dict representing
/// the JSON output.
///
/// The outlet must already be registered in the context's outlet registry
/// (via `py_outlet_register`) before a handler can be attached.
///
/// # Arguments
///
/// * `context_id` -- The context containing the outlet.
/// * `outlet_name` -- The outlet ID to attach the handler to.
/// * `handler` -- A Python callable `(dict) -> dict`.
///
/// # Errors
///
/// Raises `ContextError` if the context or outlet is not found.
///
/// See SCP-212 and ADR-010 for the handler registration design.
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "mcp_register_outlet_handler")]
    #[allow(clippy::needless_pass_by_value)] // PyObject must be owned to clone_ref into the closure.
    pub fn py_register_outlet_handler(
        &self,
        py: Python<'_>,
        context_id: &str,
        outlet_name: &str,
        handler: PyObject,
    ) -> PyResult<()> {
        let bi = &*self.inner;
        validate::validate_context_id(context_id)?;
        validate::validate_outlet_name(outlet_name)?;
        // Verify the handler is callable before storing it.
        if !handler.bind(py).is_callable() {
            return Err(ScpPyError::validation("handler must be callable".to_owned()).into());
        }

        // Wrap the Python callable in a Rust closure that acquires the GIL,
        // converts JSON -> Python dict, calls the handler, and converts back.
        let handler_ref = handler.clone_ref(py);
        let rust_handler: crate::runtime::OutletHandler =
            std::sync::Arc::new(move |input: serde_json::Value| {
                Python::with_gil(|py| {
                    // Convert serde_json::Value -> Python dict.
                    let py_input = crate::types::json_to_py_dict(py, &input)
                        .map_err(|e| format!("failed to convert input to Python dict: {e}"))?;

                    // Call the Python handler.
                    let py_result = handler_ref
                        .call1(py, (py_input,))
                        .map_err(|e| format!("Python handler raised an exception: {e}"))?;

                    // Convert Python result back to serde_json::Value.
                    let result_dict = py_result
                        .downcast_bound::<PyDict>(py)
                        .map_err(|_| "outlet handler must return a dict".to_owned())?;
                    crate::types::py_dict_to_json(result_dict)
                        .map_err(|e| format!("failed to convert handler output to JSON: {e}"))
                })
            });

        crate::runtime::register_outlet_handler(bi, context_id, outlet_name, rust_handler)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Registry statistics and cleanup (issue #108)
// ---------------------------------------------------------------------------

/// MCP-specific registry entry counts.
///
/// Returned by [`registry_stats`](crate::runtime::registry_stats) alongside the core registry stats
/// for monitoring and debugging in long-running processes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct McpRegistryStats {
    /// Number of entries in the MCP server registry.
    servers: usize,
    /// Number of stopped servers still in the registry.
    stopped_servers: usize,
    /// Number of entries in the MCP client registry.
    clients: usize,
}

/// Returns MCP registry entry counts for the given bridge instance
/// (Phase 4 PR 4 sub-slice D).
fn mcp_registry_stats_for(bi: &crate::runtime::PyBridgeInstance) -> McpRegistryStats {
    let registry = server_registry_of(bi);
    let servers = registry.len();
    let stopped_servers = registry
        .iter()
        .filter(|entry| entry.value().stopped)
        .count();
    let clients = client_registry_of(bi).len();
    McpRegistryStats {
        servers,
        stopped_servers,
        clients,
    }
}

/// Removes stopped MCP server entries from the given bridge instance's
/// registry.
fn cleanup_stopped_servers_for(bi: &crate::runtime::PyBridgeInstance) -> usize {
    let registry = server_registry_of(bi);
    let mut removed = 0;
    let keys_to_remove: Vec<String> = registry
        .iter()
        .filter(|entry| entry.value().stopped)
        .map(|entry| entry.key().clone())
        .collect();

    for key in keys_to_remove {
        if registry.remove(&key).is_some() {
            removed += 1;
        }
    }
    removed
}

/// Returns registry entry counts for all FFI registries.
///
/// Exposes the current entry counts for the context registry, identity
/// registry, known-contexts registry, MCP server registry, and MCP
/// client registry. Intended for monitoring and debugging in
/// long-running processes.
///
/// # Returns
///
/// A Python dict with keys: `contexts`, `known_contexts`, `identities`,
/// `relay_connected`, `mcp_servers`, `mcp_servers_stopped`, `mcp_clients`.
///
/// # Errors
///
/// Raises `PyErr` if building the result dict fails.
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_registry_stats")]
    pub fn py_registry_stats(&self, py: Python<'_>) -> PyResult<PyObject> {
        let bi = &*self.inner;
        let core_stats = crate::runtime::registry_stats(bi);
        let mcp_stats = mcp_registry_stats_for(bi);

        let dict = PyDict::new(py);
        dict.set_item("contexts", core_stats.contexts)?;
        dict.set_item("known_contexts", core_stats.known_contexts)?;
        dict.set_item("identities", core_stats.identities)?;
        dict.set_item("relay_connected", core_stats.relay_connected)?;
        dict.set_item("mcp_servers", mcp_stats.servers)?;
        dict.set_item("mcp_servers_stopped", mcp_stats.stopped_servers)?;
        dict.set_item("mcp_clients", mcp_stats.clients)?;
        Ok(dict.into())
    }
}

/// Removes stale entries from all FFI registries.
///
/// Currently cleans up:
/// - Stopped MCP server entries (where `py_mcp_server_stop` was called but
///   the entry was never removed from the registry)
///
/// # Returns
///
/// A Python dict with keys: `mcp_servers_removed` (number of stopped
/// server entries cleaned up).
///
/// # Errors
///
/// Raises `TransportError` on internal errors.
#[pymethods]
impl crate::scp::PyScp {
    #[pyo3(name = "py_registry_cleanup")]
    pub fn py_registry_cleanup(&self, py: Python<'_>) -> PyResult<PyObject> {
        let bi = &*self.inner;
        let servers_removed = cleanup_stopped_servers_for(bi);

        let dict = PyDict::new(py);
        dict.set_item("mcp_servers_removed", servers_removed)?;
        Ok(dict.into())
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers MCP bridge functions on the `_scp_core` module.
///
/// Called from [`crate::_scp_core`] during module initialization.
///
/// # Errors
///
/// Returns `PyErr` if registration of functions fails.
pub const fn register_mcp(_m: &Bound<'_, PyModule>) -> PyResult<()> {
    // All MCP operations — including the stdio allowlist — are
    // now methods on `SCP`. PyO3 registers `#[pymethods]` automatically with
    // the class, so this function has nothing to wire up here.
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Test helper: constructs a fresh bridge instance.
    /// Phase D (#1695) deleted the process-global default.
    fn __bi() -> std::sync::Arc<crate::runtime::PyBridgeInstance> {
        std::sync::Arc::new(crate::runtime::PyBridgeInstance::new_py())
    }

    // -----------------------------------------------------------------------
    // ClientTransport enum dispatch
    // -----------------------------------------------------------------------

    // Note: These tests verify the enum dispatch compiles and routes
    // correctly. Full integration tests require a running MCP server
    // subprocess, which is tested via pytest with maturin develop.

    // -----------------------------------------------------------------------
    // FfiBridgeProvider
    // -----------------------------------------------------------------------

    #[test]
    fn ffi_bridge_provider_active_context_ids() {
        // Hold the Arc alive for the duration of the test so the Weak
        // inside the provider upgrades successfully (#1549 round-2).
        let bi = __bi();
        let creator = "did:dht:z6MkTest";
        let live_a = setup_unsupervised_context(&bi, creator, false);
        let live_b = setup_unsupervised_context(&bi, creator, false);

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            // A third id the agent does not participate in: configuring a
            // context is not the same as being a member of it.
            context_ids: vec![live_a.clone(), live_b.clone(), "ctx-not-joined".to_owned()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        // ADR-015 AC7: the served set is configured ∩ live participation, so a
        // context the agent is not (or is no longer) a member of drops out
        // without restarting the server. A static snapshot of the configured
        // list could never satisfy that.
        assert_eq!(provider.active_context_ids().unwrap(), vec![live_a, live_b]);
    }

    #[test]
    fn ffi_bridge_provider_agent_did() {
        let bi = __bi();
        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: "did:dht:z6MkTest".to_owned(),
            context_ids: vec![],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };
        assert_eq!(provider.agent_did(), "did:dht:z6MkTest");
    }

    #[test]
    fn ffi_bridge_provider_context_outlets_error_for_unknown_context() {
        let bi = __bi();
        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: "did:dht:z6MkTest".to_owned(),
            context_ids: vec!["nonexistent".to_owned()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };
        // An unknown context is an unreadable registry: an error, never an
        // empty outlet list that reads as "no outlets registered".
        assert!(
            provider.context_tools("nonexistent").is_err(),
            "context_tools must fail for a context the bridge cannot read"
        );
    }

    // -----------------------------------------------------------------------
    // Helper: register a context with an outlet for FfiBridgeProvider tests.
    // -----------------------------------------------------------------------

    /// Registers a context in the runtime registry and optionally adds an outlet.
    /// Returns a unique context ID to avoid collisions with parallel tests.
    ///
    /// Attaches a supervisor, as `register_context` does, and the supervisor
    /// does not hold the context, so the provider's role-state gates deny it
    /// (see `provider_gates_follow_the_actor_not_the_bridge_copy_pyo3`). Tests
    /// of those gates use [`setup_unsupervised_context`].
    ///
    /// Callers must pass the same `bi` they use for subsequent registry lookups;
    /// each `PyBridgeInstance` has its own `instance_id` and context registry.
    fn setup_test_context(
        bi: &crate::runtime::PyBridgeInstance,
        creator_did: &str,
        with_outlet: bool,
    ) -> String {
        crate::runtime::init_context_manager_for_test(bi);
        setup_unsupervised_context(bi, creator_did, with_outlet)
    }

    /// [`setup_test_context`] without the supervisor: with no actor, the FFI
    /// copy of the role state is the context's only role state, so the
    /// provider's gates read it as it stands.
    fn setup_unsupervised_context(
        bi: &crate::runtime::PyBridgeInstance,
        creator_did: &str,
        with_outlet: bool,
    ) -> String {
        // Use a unique context ID to avoid collisions across parallel tests.
        let ctx_id = crate::types::generate_random_id("test-mcp");
        crate::runtime::register_ffi_state(bi, &ctx_id, creator_did, &[]).unwrap();

        if with_outlet {
            crate::runtime::with_context(bi, &ctx_id, |rt| {
                let registration = scp_core::context::outlets::OutletRegistration {
                    outlet_id: "calculator".to_owned(),
                    kind: scp_core::context::outlets::OutletKind::default(),
                    name: "Calculator".to_owned(),
                    description: "A simple calculator".to_owned(),
                    schema: scp_core::context::outlets::OutletSchema {
                        input_schema: serde_json::json!({
                            "type": "object",
                            "properties": {
                                "a": {"type": "number"},
                                "b": {"type": "number"}
                            },
                            "required": ["a", "b"]
                        }),
                        output_schema: serde_json::json!({
                            "type": "object",
                            "properties": {
                                "result": {"type": "number"}
                            }
                        }),
                        aggregate_schema: None,
                    },
                    implementation_hash: [0xAA; 32],
                    test_vectors: vec![],
                    operator_did: "did:dht:z6MkOperator".into(),
                    cost: None,
                    message_catalog: Vec::new(),
                    registered_at: 0,
                    signature: Vec::new(),
                };
                scp_core::context::outlets::register_outlet(
                    &mut rt.outlet_registry,
                    &rt.role_state,
                    registration,
                    creator_did,
                )
                .map_err(|e| crate::error::ScpPyError::context(format!("{e}")))?;
                Ok(())
            })
            .unwrap();
        }

        ctx_id
    }

    // -----------------------------------------------------------------------
    // FfiBridgeProvider::validate_capability — rejects missing UCAN (#319)
    // -----------------------------------------------------------------------

    #[test]
    fn ffi_bridge_provider_validate_capability_rejects_missing_ucan() {
        let creator = "did:dht:z6MkCreatorValCap";
        let bi = __bi();
        let ctx_id = setup_unsupervised_context(&bi, creator, true);

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };
        // Even the creator is rejected without a UCAN token.
        let result = provider.validate_capability(
            &ctx_id,
            "calculator",
            scp_mcp::server::CapabilityCheck::Probe,
        );
        assert!(
            result.is_err(),
            "should reject when no UCAN token is provided"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(&err, scp_mcp::server::AccessRefusal::Denied(msg) if msg.contains("UCAN token required")),
            "error should mention UCAN requirement: {err}"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    /// A proof token `outlet_grant` cannot parse is a failed read, so
    /// `tools/list` reports it as an error. A token that parses and fails
    /// validation is a denial, so `tools/list` omits the tool.
    #[test]
    fn ffi_bridge_provider_outlet_grant_read_failure_is_unreadable_not_denied() {
        let creator = "did:dht:z6MkCreatorGrantRead";
        let bi = __bi();
        let ctx_id = setup_unsupervised_context(&bi, creator, true);
        let provider = |proofs: Option<Vec<String>>| FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: Some("not-a-ucan".to_owned()),
            agent_proof_tokens: proofs,
        };

        let err = provider(Some(vec!["not-a-ucan".to_owned()]))
            .validate_capability(
                &ctx_id,
                "calculator",
                scp_mcp::server::CapabilityCheck::Probe,
            )
            .unwrap_err();
        assert!(
            matches!(&err, scp_mcp::server::AccessRefusal::Unreadable(msg) if msg.contains("proof resolver")),
            "an unparseable proof token must be a failed read: {err}"
        );

        let err = provider(None)
            .validate_capability(
                &ctx_id,
                "calculator",
                scp_mcp::server::CapabilityCheck::Probe,
            )
            .unwrap_err();
        assert!(
            matches!(&err, scp_mcp::server::AccessRefusal::Denied(msg) if msg.contains("UCAN authorization failed")),
            "a UCAN that fails validation must be a denial: {err}"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // FfiBridgeProvider::validate_capability — rejects unauthorized member
    // without UCAN token (#319)
    // -----------------------------------------------------------------------

    #[test]
    fn ffi_bridge_provider_validate_capability_rejects_unauthorized() {
        let creator = "did:dht:z6MkCreatorValCapReject";
        let bi = __bi();
        let ctx_id = setup_unsupervised_context(&bi, creator, true);

        // Add a member with no OutletCall capability.
        let member = "did:dht:z6MkMemberNoInvoke";
        crate::runtime::with_context(&bi, &ctx_id, |rt| {
            rt.role_state.members.insert(member.to_owned());
            let mut caps = std::collections::HashSet::new();
            caps.insert(scp_core::context::roles::Capability::MessagesRead);
            rt.role_state
                .member_capabilities
                .insert(member.to_owned(), caps);
            Ok(())
        })
        .unwrap();

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: member.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };
        let result = provider.validate_capability(
            &ctx_id,
            "calculator",
            scp_mcp::server::CapabilityCheck::Probe,
        );
        assert!(
            result.is_err(),
            "member without UCAN token should be rejected"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(&err, scp_mcp::server::AccessRefusal::Denied(msg) if msg.contains("UCAN token required")),
            "error should mention UCAN requirement: {err}"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    /// An Invoke check records the agent token's nonce in its UCAN step, so
    /// `outlet_grant` must run the role-state check first: a refusal after the
    /// UCAN step would spend the token without running an outlet. The token
    /// here is unparseable, so a UCAN step that ran first would refuse with
    /// "UCAN authorization failed" instead of the role-state refusal.
    #[test]
    fn ffi_bridge_provider_invoke_role_refusal_precedes_ucan_step() {
        let creator = "did:dht:z6MkCreatorInvokeOrder";
        let bi = __bi();
        let ctx_id = setup_unsupervised_context(&bi, creator, true);
        let member = "did:dht:z6MkMemberInvokeOrder";
        crate::runtime::with_context(&bi, &ctx_id, |rt| {
            rt.role_state.members.insert(member.to_owned());
            let mut caps = std::collections::HashSet::new();
            caps.insert(scp_core::context::roles::Capability::MessagesRead);
            rt.role_state
                .member_capabilities
                .insert(member.to_owned(), caps);
            Ok(())
        })
        .unwrap();

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: member.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: Some("not-a-ucan".to_owned()),
            agent_proof_tokens: None,
        };
        let err = provider
            .validate_capability(
                &ctx_id,
                "calculator",
                scp_mcp::server::CapabilityCheck::Invoke,
            )
            .unwrap_err();
        assert!(
            matches!(&err, scp_mcp::server::AccessRefusal::Denied(msg) if msg == "insufficient permissions to invoke outlet"),
            "the role-state check must refuse before the UCAN step: {err}"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // FfiBridgeProvider::validate_capability — kind-aware defense-in-depth gate
    // (SCP-OUT-014, §5.4.2). Proves the MCP bridge's role-state check reads the
    // outlet's registered kind from the runtime registry and dispatches to the
    // matching split stem: a Query outlet is DENIED to an OutletCall-only member
    // and ALLOWED to an OutletQuery-only member. This exercises the exact
    // registry-kind read + `has_outlet_invocation_capability` dispatch the fixed
    // gate at mcp.rs performs against real bridge state (registered outlet +
    // role_state). The full through-`validate_capability` path additionally
    // requires a valid 11-step UCAN token; that primary layer is covered by the
    // #319 UCAN tests, and the shared gate is covered end-to-end by the runtime
    // `invoke_query_session_*` test.
    #[test]
    #[allow(clippy::too_many_lines)] // End-to-end query-gate test: register + role-state + two-member gate assertions.
    fn ffi_bridge_provider_validate_capability_query_kind_selects_query_stem() {
        use scp_core::context::roles::Capability;

        let creator = "did:dht:z6MkCreatorQueryStem";
        let member = "did:dht:z6MkMemberQueryStem";
        let bi = __bi();
        // Register the context WITHOUT the default calculator outlet — we add a
        // Query-kind one explicitly below.
        let ctx_id = setup_unsupervised_context(&bi, creator, false);

        // Register a QUERY-kind outlet and add a member holding ONLY the
        // Action-class OutletCall grant.
        crate::runtime::with_context(&bi, &ctx_id, |rt| {
            let registration = scp_core::context::outlets::OutletRegistration {
                outlet_id: "lookup".to_owned(),
                kind: scp_core::context::outlets::OutletKind::Query,
                name: "Lookup".to_owned(),
                description: "A read-only lookup".to_owned(),
                schema: scp_core::context::outlets::OutletSchema {
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                            "limit": {"type": "number"}
                        }
                    }),
                    output_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "results": {"type": "array"}
                        }
                    }),
                    aggregate_schema: None,
                },
                implementation_hash: [0xAA; 32],
                test_vectors: vec![],
                operator_did: "did:dht:z6MkOperator".into(),
                cost: None,
                message_catalog: Vec::new(),
                registered_at: 0,
                signature: Vec::new(),
            };
            scp_core::context::outlets::register_outlet(
                &mut rt.outlet_registry,
                &rt.role_state,
                registration,
                creator,
            )
            .map_err(|e| crate::error::ScpPyError::context(format!("{e}")))?;

            rt.role_state.members.insert(member.to_owned());
            rt.role_state.member_capabilities.insert(
                member.to_owned(),
                std::iter::once(Capability::OutletCall("lookup".to_owned())).collect(),
            );
            Ok(())
        })
        .unwrap();

        // The MCP defense-in-depth gate reads the registered kind and dispatches
        // via `has_outlet_invocation_capability`. An OutletCall-only member is
        // DENIED on a Query outlet because the two stems are independent.
        let denied = crate::runtime::with_context(&bi, &ctx_id, |rt| {
            let kind = rt
                .outlet_registry
                .get("lookup")
                .map_or(scp_core::context::outlets::OutletKind::Action, |r| r.kind);
            assert_eq!(
                kind,
                scp_core::context::outlets::OutletKind::Query,
                "outlet must round-trip as Query through the bridge registry"
            );
            Ok(
                scp_core::context::outlets::invoke::has_outlet_invocation_capability(
                    &rt.role_state,
                    member,
                    "lookup",
                    kind,
                ),
            )
        })
        .unwrap();
        assert!(
            !denied,
            "Query outlet must be denied to a member holding only OutletCall"
        );

        // Grant the Query-class capability → ALLOWED.
        crate::runtime::with_context(&bi, &ctx_id, |rt| {
            rt.role_state
                .member_capabilities
                .get_mut(member)
                .unwrap()
                .insert(Capability::OutletQuery("lookup".to_owned()));
            Ok(())
        })
        .unwrap();
        let allowed = crate::runtime::with_context(&bi, &ctx_id, |rt| {
            let kind = rt
                .outlet_registry
                .get("lookup")
                .map_or(scp_core::context::outlets::OutletKind::Action, |r| r.kind);
            Ok(
                scp_core::context::outlets::invoke::has_outlet_invocation_capability(
                    &rt.role_state,
                    member,
                    "lookup",
                    kind,
                ),
            )
        })
        .unwrap();
        assert!(
            allowed,
            "Query outlet must be allowed once the member holds OutletQuery"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // FfiBridgeProvider::invoke_outlet — refuses an outlet with no handler
    // -----------------------------------------------------------------------

    /// Registers a `calculator` handler that sums `a` and `b`.
    fn register_sum_handler(bi: &crate::runtime::PyBridgeInstance, ctx_id: &str) {
        let handler: crate::runtime::OutletHandler =
            std::sync::Arc::new(|input: serde_json::Value| {
                let a = input["a"].as_f64().unwrap_or(0.0);
                let b = input["b"].as_f64().unwrap_or(0.0);
                Ok(serde_json::json!({"result": a + b}))
            });
        crate::runtime::register_outlet_handler(bi, ctx_id, "calculator", handler).unwrap();
    }

    /// A registered outlet with no handler runs nothing, so the call is
    /// refused before the Invoke check and appends no event: a success result
    /// would report work that was not done.
    #[test]
    fn ffi_bridge_provider_invoke_outlet_refuses_an_outlet_without_handler() {
        let creator = "did:dht:z6MkCreatorInvokeOutlet";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        let asked = std::cell::Cell::new(0_u32);
        let result = provider.run_outlet(
            &ctx_id,
            "calculator",
            serde_json::json!({"a": 3, "b": 4}),
            || {
                asked.set(asked.get() + 1);
                Ok(())
            },
        );
        let err = result.expect_err("an outlet without a handler must be refused");
        assert!(
            err.to_string().contains("has no registered handler"),
            "the refusal must name the missing handler: {err}"
        );
        assert_eq!(asked.get(), 0, "the refusal must not spend the token");
        assert_eq!(event_count(&bi, &ctx_id), 0, "no outlet may have run");

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // FfiBridgeProvider::invoke_outlet — appends OutletInvokedEvent to event log
    // (ADR-010 acceptance criterion 3, issue #120)
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_outlet_appends_one_outlet_invoked_event_per_call() {
        let creator = "did:dht:z6MkCreatorEventLog";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);
        register_sum_handler(&bi, &ctx_id);

        // Verify the event log is initially empty.
        let initial_count = crate::runtime::with_context(&bi, &ctx_id, |rt| {
            Ok(scp_event_log::tree::event_count(&rt.event_log))
        })
        .unwrap();
        assert_eq!(initial_count, 0, "event log should start empty");

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        let result = invoke_granted(
            &provider,
            &ctx_id,
            "calculator",
            serde_json::json!({"a": 1, "b": 2}),
        );
        assert!(result.is_ok(), "invoke_outlet should succeed: {result:?}");

        // Verify the event log now has one event.
        let after_count = crate::runtime::with_context(&bi, &ctx_id, |rt| {
            Ok(scp_event_log::tree::event_count(&rt.event_log))
        })
        .unwrap();
        assert_eq!(
            after_count, 1,
            "event log should have 1 event after invocation"
        );
        // Invoke again to verify sequential appending.
        let result2 = invoke_granted(
            &provider,
            &ctx_id,
            "calculator",
            serde_json::json!({"a": 5, "b": 6}),
        );
        assert!(result2.is_ok());

        let final_count = crate::runtime::with_context(&bi, &ctx_id, |rt| {
            Ok(scp_event_log::tree::event_count(&rt.event_log))
        })
        .unwrap();
        assert_eq!(
            final_count, 2,
            "event log should have 2 events after two invocations"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    #[test]
    fn invoke_outlet_with_handler_appends_outlet_invoked_event() {
        let creator = "did:dht:z6MkCreatorHandlerEventLog";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);

        // Register a handler.
        let handler: crate::runtime::OutletHandler =
            std::sync::Arc::new(|input: serde_json::Value| {
                let a = input["a"].as_f64().unwrap_or(0.0);
                let b = input["b"].as_f64().unwrap_or(0.0);
                Ok(serde_json::json!({"result": a + b}))
            });
        crate::runtime::register_outlet_handler(&bi, &ctx_id, "calculator", handler).unwrap();

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        let result = invoke_granted(
            &provider,
            &ctx_id,
            "calculator",
            serde_json::json!({"a": 10, "b": 20}),
        );
        assert!(result.is_ok(), "invoke_outlet should succeed: {result:?}");
        assert_eq!(result.unwrap(), serde_json::json!({"result": 30.0}));

        // Verify event was logged.
        let count = crate::runtime::with_context(&bi, &ctx_id, |rt| {
            Ok(scp_event_log::tree::event_count(&rt.event_log))
        })
        .unwrap();
        assert_eq!(count, 1, "handler path should also append to event log");

        // Verify the merkle root is non-zero (tree was actually built).
        let root = crate::runtime::with_context(&bi, &ctx_id, |rt| {
            Ok(scp_event_log::tree::root(&rt.event_log))
        })
        .unwrap();
        assert_ne!(
            root, [0u8; 32],
            "merkle root should be non-zero after appending an event"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    /// Runs an outlet through `run_outlet` with an Invoke check that passes,
    /// so a test of the dispatch needs no UCAN token.
    fn invoke_granted(
        provider: &FfiBridgeProvider,
        context_id: &str,
        outlet_name: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        provider
            .run_outlet(context_id, outlet_name, arguments, || Ok(()))
            .map_err(|e| e.to_string())
    }

    fn event_count(bi: &crate::runtime::PyBridgeInstance, ctx_id: &str) -> u64 {
        crate::runtime::with_context(bi, ctx_id, |rt| {
            Ok(scp_event_log::tree::event_count(&rt.event_log))
        })
        .unwrap()
    }

    /// `run_outlet` asks for the Invoke check, which spends the agent token,
    /// only after every refusal that runs no outlet: a missing supervisor, an
    /// unknown outlet, an input the schema rejects, and an outlet with no
    /// registered handler each refuse the call without asking.
    #[test]
    fn run_outlet_authorizes_after_every_refusal_that_runs_no_outlet() {
        let creator = "did:dht:z6MkCreatorAuthorizeLast";
        let bi = __bi();
        let provider_for = |ctx_id: &str| FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.to_owned()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,
            agent_proof_tokens: None,
        };
        let asked = std::cell::Cell::new(0_u32);
        let authorize = || {
            asked.set(asked.get() + 1);
            Ok(())
        };

        // The outlet and its handler are registered, so only the missing
        // supervisor can refuse this call.
        let unsupervised = setup_unsupervised_context(&bi, creator, true);
        register_sum_handler(&bi, &unsupervised);
        let provider = provider_for(&unsupervised);
        let args = serde_json::json!({"a": 1, "b": 2});
        let refusal = provider
            .run_outlet(&unsupervised, "calculator", args.clone(), authorize)
            .expect_err("no supervisor must refuse the call")
            .to_string();
        assert!(
            refusal.contains("ContextManager not yet attached"),
            "the refusal must name the missing supervisor, got: {refusal}"
        );
        assert_eq!(asked.get(), 0, "no supervisor: the token must stay unspent");
        crate::runtime::remove_context(&bi, &unsupervised);

        let ctx_id = setup_test_context(&bi, creator, true);
        let provider = provider_for(&ctx_id);
        assert!(
            provider
                .run_outlet(&ctx_id, "nonexistent", args.clone(), authorize)
                .is_err()
        );
        assert!(
            provider
                .run_outlet(&ctx_id, "calculator", args.clone(), authorize)
                .is_err(),
            "no handler is registered yet"
        );
        assert_eq!(asked.get(), 0, "a refused call must not spend the token");

        register_sum_handler(&bi, &ctx_id);
        // The handler is registered, so only the schema check can refuse
        // this input before the token is spent.
        assert!(
            provider
                .run_outlet(&ctx_id, "calculator", serde_json::json!("bad"), authorize)
                .is_err()
        );
        assert_eq!(
            asked.get(),
            0,
            "an input the schema rejects must not spend the token"
        );
        assert!(
            provider
                .run_outlet(&ctx_id, "calculator", args, authorize)
                .is_ok()
        );
        assert_eq!(asked.get(), 1, "the dispatched call asks once");
        crate::runtime::remove_context(&bi, &ctx_id);
    }

    /// A refused capability check runs no outlet and appends no event, and the
    /// trait's `invoke_outlet` passes its capability check as `authorize`: with
    /// no UCAN token, `outlet_grant` refuses before any other step. The check
    /// kind never matters on this path;
    /// `invoke_outlet_records_the_token_nonce_and_refuses_its_replay` proves
    /// that `invoke_outlet` passes the Invoke check.
    #[test]
    fn refused_invoke_check_runs_no_outlet() {
        let creator = "did:dht:z6MkCreatorRefusedInvoke";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);
        hold_on_actor(&bi, &ctx_id, creator, &["messages:read", "outlet:call:*"]);
        register_sum_handler(&bi, &ctx_id);
        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,
            agent_proof_tokens: None,
        };
        let args = serde_json::json!({"a": 1, "b": 2});
        let refused = provider.run_outlet(&ctx_id, "calculator", args.clone(), || {
            Err(scp_mcp::server::AccessRefusal::Denied("replay".to_owned()))
        });
        assert!(matches!(
            refused,
            Err(scp_mcp::server::OutletInvokeError::Refused(_))
        ));
        let refused = provider.invoke_outlet(&ctx_id, "calculator", args);
        assert!(
            matches!(
                &refused,
                Err(scp_mcp::server::OutletInvokeError::Refused(
                    scp_mcp::server::AccessRefusal::Denied(msg)
                )) if msg.contains("UCAN token required")
            ),
            "the Invoke check must refuse for the missing token: {refused:?}"
        );
        assert_eq!(event_count(&bi, &ctx_id), 0, "no outlet may have run");
        crate::runtime::remove_context(&bi, &ctx_id);
    }

    /// `invoke_outlet` passes the Invoke check, which records the agent
    /// token's nonce, so the same token cannot run a second `tools/call`. A
    /// Probe records nothing, so probing first leaves the token unspent. Had
    /// `invoke_outlet` passed the Probe check, the second call would run.
    ///
    /// The bridge copy names the token's issuer as the context's creator, so
    /// the UCAN step accepts the root token; the actor names the agent as the
    /// creator holding `outlet:call:*`, so the role-state check passes.
    #[test]
    fn invoke_outlet_records_the_token_nonce_and_refuses_its_replay() {
        use scp_platform::traits::KeyCustody as _;
        crate::init_runtime().ok();
        let runtime = crate::runtime().unwrap();
        let custody = scp_platform::testing::InMemoryKeyCustody::new();
        let key = runtime
            .block_on(custody.generate_keypair(scp_platform::traits::KeyType::Ed25519))
            .unwrap();
        let mut public_key = [0_u8; 32];
        public_key.copy_from_slice(
            runtime
                .block_on(custody.public_key(&key))
                .unwrap()
                .as_bytes(),
        );
        let issuer = scp_did::did_dht_from_public_key(&public_key).0;
        let agent = "did:dht:z6MkAgentReplayedToken";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, &issuer, true);
        hold_on_actor(&bi, &ctx_id, agent, &["messages:read", "outlet:call:*"]);
        register_sum_handler(&bi, &ctx_id);
        let capabilities = vec!["outlet:call:*".to_owned()];
        let params = scp_core::crypto::ucan::mint::MintParams {
            issuer_did: &issuer,
            issuer_key: &key,
            audience_did: agent,
            context_id: &ctx_id,
            capabilities: &capabilities,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };
        let token = runtime
            .block_on(scp_core::crypto::ucan::mint::mint_ucan(
                &params,
                &custody,
                &scp_clock::SystemClock,
            ))
            .unwrap();
        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: agent.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: Some(token.encoded),
            agent_proof_tokens: None,
        };
        for _ in 0..2 {
            provider
                .validate_capability(
                    &ctx_id,
                    "calculator",
                    scp_mcp::server::CapabilityCheck::Probe,
                )
                .expect("a probe records no nonce, so it passes every time");
        }
        let args = serde_json::json!({"a": 1, "b": 2});
        let output = provider
            .invoke_outlet(&ctx_id, "calculator", args.clone())
            .expect("the first call with a fresh token runs the outlet");
        assert_eq!(output, serde_json::json!({"result": 3.0}));
        let replayed = provider.invoke_outlet(&ctx_id, "calculator", args);
        assert!(
            matches!(
                &replayed,
                Err(scp_mcp::server::OutletInvokeError::Refused(
                    scp_mcp::server::AccessRefusal::Denied(msg)
                )) if msg.contains("UCAN authorization failed")
            ),
            "a replayed token must be refused by the UCAN step: {replayed:?}"
        );
        crate::runtime::remove_context(&bi, &ctx_id);
    }

    /// `py_mcp_client_connect_sse` sends the caller's token on its `GET`, so a
    /// Python client passes the bearer check an SCP SSE server always runs.
    /// The listener reads the request head and then closes the connection, so
    /// the connect fails after the header has gone out. The test waits for
    /// the head for at most 10 seconds, so a connect that refuses before it
    /// dials fails the test with the connect's own result, not a hang.
    #[test]
    fn py_mcp_client_connect_sse_sends_the_bearer_token() {
        use std::io::BufRead;
        let scp = crate::scp::PyScp { inner: __bi() };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (head_tx, head_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let Ok((conn, _)) = listener.accept() else {
                return;
            };
            let mut reader = std::io::BufReader::new(conn);
            let mut head = String::new();
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(n) if n > 0 && line != "\r\n" => head.push_str(&line),
                    _ => break,
                }
            }
            drop(reader);
            let _ = head_tx.send(head);
        });
        pyo3::prepare_freethreaded_python();
        let result = Python::with_gil(|py| {
            scp.py_mcp_client_connect_sse(
                py,
                &format!("http://127.0.0.1:{port}/sse"),
                Some("tok-1"),
            )
        });
        let head = head_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap_or_else(|_| {
                panic!(
                    "the connect never sent its GET; it returned: {:?}",
                    result.as_ref().map(|_| ()).map_err(ToString::to_string)
                )
            });
        assert!(
            head.contains("\r\nAuthorization: Bearer tok-1\r\n"),
            "the GET must carry the caller's bearer token, got: {head:?}"
        );
        assert!(
            result.is_err(),
            "the listener closed the stream, so the connect must fail"
        );
    }

    #[test]
    fn invoke_outlet_error_does_not_append_event() {
        let creator = "did:dht:z6MkCreatorNoEventOnErr";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        // Invoke with invalid input (schema validation fails).
        let result = invoke_granted(
            &provider,
            &ctx_id,
            "calculator",
            serde_json::json!("not an object"),
        );
        assert!(result.is_err(), "invalid input should be rejected");

        // Event log should still be empty (no event appended on error).
        let count = crate::runtime::with_context(&bi, &ctx_id, |rt| {
            Ok(scp_event_log::tree::event_count(&rt.event_log))
        })
        .unwrap();
        assert_eq!(
            count, 0,
            "event log should remain empty when invocation fails"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // FfiBridgeProvider::invoke_outlet — rejects invalid schema input
    // -----------------------------------------------------------------------

    #[test]
    fn ffi_bridge_provider_invoke_outlet_validates_schema() {
        let creator = "did:dht:z6MkCreatorSchemaVal";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);
        register_sum_handler(&bi, &ctx_id);

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        // Input schema requires an object with "a" and "b" as required fields.
        // Pass a string instead.
        let result = invoke_granted(
            &provider,
            &ctx_id,
            "calculator",
            serde_json::json!("not an object"),
        );
        assert!(result.is_err(), "invalid input should be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("validation"),
            "error should mention validation: {err}"
        );

        // Pass an object missing required fields.
        let result = invoke_granted(
            &provider,
            &ctx_id,
            "calculator",
            serde_json::json!({"a": 1}),
        );
        assert!(
            result.is_err(),
            "input missing required field 'b' should be rejected"
        );

        // Pass valid input — should succeed.
        let result = invoke_granted(
            &provider,
            &ctx_id,
            "calculator",
            serde_json::json!({"a": 1, "b": 2}),
        );
        assert!(result.is_ok(), "valid input should succeed: {result:?}");

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // FfiBridgeProvider::invoke_outlet — outlet not found
    // -----------------------------------------------------------------------

    #[test]
    fn ffi_bridge_provider_invoke_outlet_rejects_unknown_outlet() {
        let creator = "did:dht:z6MkCreatorUnknownOutlet";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, false);

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        let result = invoke_granted(&provider, &ctx_id, "nonexistent", serde_json::json!({}));
        assert!(result.is_err(), "unknown outlet should be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("not found"),
            "error should mention outlet not found: {err}"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // py_mcp_load_contexts — returns contexts from local runtime registry
    // -----------------------------------------------------------------------

    #[test]
    fn load_contexts_returns_local_contexts() {
        let creator = "did:dht:z6MkCreatorLoadCtx";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);

        // Since py_mcp_load_contexts requires Python, we test the underlying
        // runtime function directly.
        let ids = crate::runtime::context_ids_for_member(&bi, creator);
        assert!(
            ids.contains(&ctx_id),
            "creator should be a member of the context"
        );

        // Non-member should not see the context.
        let other_ids = crate::runtime::context_ids_for_member(&bi, "did:dht:z6MkNobody");
        assert!(
            !other_ids.contains(&ctx_id),
            "non-member should not see the context"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // Known context registry (SCP-213)
    // -----------------------------------------------------------------------

    #[test]
    fn known_context_registration_and_lookup() {
        // BridgeInstance must exist for known-context registration.
        crate::runtime::init_context_manager_for_test(&__bi());

        let creator = "did:dht:z6MkCreatorKnownCtx";
        let ctx_id = crate::types::generate_random_id("known-ctx");
        let routing_id = [0xAA; 32];

        let known = crate::runtime::KnownContext {
            routing_id,
            relay_url: Some("ws://127.0.0.1:9000/scp/v1".to_owned()),
            member_did: creator.to_owned(),
            last_seen: 1_700_000_000,
        };

        let bi = __bi();
        crate::runtime::register_known_context_on(&bi, &ctx_id, known);

        // Should be discoverable by member DID.
        let found = crate::runtime::known_contexts_for_member_on(&bi, creator);
        assert!(
            found.iter().any(|(id, _)| id == &ctx_id),
            "known context should be found by member DID"
        );

        // Should not be found for a different DID.
        let not_found =
            crate::runtime::known_contexts_for_member_on(&bi, "did:dht:z6MkSomeoneElse");
        assert!(
            !not_found.iter().any(|(id, _)| id == &ctx_id),
            "known context should not be found for a different DID"
        );

        // Cleanup: remove_context also removes from known-contexts.
        crate::runtime::remove_context(&bi, &ctx_id);
        let after_remove = crate::runtime::known_contexts_for_member_on(&bi, creator);
        assert!(
            !after_remove.iter().any(|(id, _)| id == &ctx_id),
            "known context should be removed after remove_context"
        );
    }

    #[test]
    fn probe_relay_with_no_connection_returns_empty() {
        // When no relay connection is active, probing should return an empty set.
        let known = vec![(
            "test-ctx".to_owned(),
            crate::runtime::KnownContext {
                routing_id: [0xBB; 32],
                relay_url: Some("ws://127.0.0.1:9000/scp/v1".to_owned()),
                member_did: "did:dht:z6MkTest".to_owned(),
                last_seen: 1_700_000_000,
            },
        )];

        let active = probe_relay_for_known_contexts(&__bi(), &known);
        assert!(
            active.is_empty(),
            "should return empty set when no relay is connected"
        );
    }

    #[test]
    fn probe_relay_with_empty_known_returns_empty() {
        let known: Vec<(String, crate::runtime::KnownContext)> = vec![];
        let active = probe_relay_for_known_contexts(&__bi(), &known);
        assert!(active.is_empty(), "should return empty set for empty input");
    }

    // -----------------------------------------------------------------------
    // Outlet handler registration and dispatch (SCP-212)
    // -----------------------------------------------------------------------

    #[test]
    fn register_outlet_handler_and_invoke_dispatches_through_handler() {
        let creator = "did:dht:z6MkCreatorHandler";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);

        // Register a Rust handler that adds two numbers (simulates a Python handler).
        let handler: crate::runtime::OutletHandler =
            std::sync::Arc::new(|input: serde_json::Value| {
                let a = input
                    .get("a")
                    .and_then(serde_json::Value::as_f64)
                    .ok_or_else(|| "missing 'a'".to_owned())?;
                let b = input
                    .get("b")
                    .and_then(serde_json::Value::as_f64)
                    .ok_or_else(|| "missing 'b'".to_owned())?;
                Ok(serde_json::json!({"result": a + b}))
            });

        crate::runtime::register_outlet_handler(&bi, &ctx_id, "calculator", handler).unwrap();

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        let input = serde_json::json!({"a": 3, "b": 4});
        let result = invoke_granted(&provider, &ctx_id, "calculator", input);
        assert!(result.is_ok(), "invoke_outlet should succeed: {result:?}");

        let output = result.unwrap();
        // Handler returns computed output, not echoed input.
        assert_eq!(
            output,
            serde_json::json!({"result": 7.0}),
            "handler should compute a + b = 7"
        );
        // Should NOT have the echo-mode "status" field.
        assert!(
            output.get("status").is_none(),
            "handler output should not contain echo-mode 'status' field"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    #[test]
    fn register_outlet_handler_rejects_unregistered_outlet() {
        let creator = "did:dht:z6MkCreatorHandlerReject";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, false); // No outlet registered.

        let handler: crate::runtime::OutletHandler =
            std::sync::Arc::new(|_input| Ok(serde_json::json!({})));

        let result = crate::runtime::register_outlet_handler(&bi, &ctx_id, "nonexistent", handler);
        assert!(
            result.is_err(),
            "should reject handler for unregistered outlet"
        );
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("not found"),
            "error should mention outlet not found: {err}"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    #[test]
    fn invoke_outlet_with_handler_validates_output_schema() {
        let creator = "did:dht:z6MkCreatorOutVal";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);

        // Register a handler that returns a string instead of an object
        // (violates the output schema which requires an object).
        let bad_handler: crate::runtime::OutletHandler =
            std::sync::Arc::new(|_input| Ok(serde_json::json!("not an object")));

        crate::runtime::register_outlet_handler(&bi, &ctx_id, "calculator", bad_handler).unwrap();

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        let result = invoke_granted(
            &provider,
            &ctx_id,
            "calculator",
            serde_json::json!({"a": 1, "b": 2}),
        );
        assert!(
            result.is_err(),
            "handler returning invalid output should be rejected"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("output validation"),
            "error should mention output validation: {err}"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    #[test]
    fn invoke_outlet_handler_error_is_propagated() {
        let creator = "did:dht:z6MkCreatorHandlerErr";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);

        // Register a handler that always fails.
        let failing_handler: crate::runtime::OutletHandler =
            std::sync::Arc::new(|_input| Err("computation exploded".to_owned()));

        crate::runtime::register_outlet_handler(&bi, &ctx_id, "calculator", failing_handler)
            .unwrap();

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        let result = invoke_granted(
            &provider,
            &ctx_id,
            "calculator",
            serde_json::json!({"a": 1, "b": 2}),
        );
        assert!(result.is_err(), "failing handler should propagate error");
        let err = result.unwrap_err();
        assert!(
            err.contains("computation exploded"),
            "error should contain handler error message: {err}"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // Outlet handler execution timeout (issue #123)
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_outlet_handler_timeout_produces_clear_error() {
        let creator = "did:dht:z6MkCreatorTimeout";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);

        // Register a handler that blocks for 5 seconds (will be timed out).
        let blocking_handler: crate::runtime::OutletHandler = std::sync::Arc::new(|_input| {
            std::thread::sleep(std::time::Duration::from_secs(5));
            Ok(serde_json::json!({"result": 42}))
        });

        crate::runtime::register_outlet_handler(&bi, &ctx_id, "calculator", blocking_handler)
            .unwrap();

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: 50, // 50ms — will expire before the 5s sleep.
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        let result = invoke_granted(
            &provider,
            &ctx_id,
            "calculator",
            serde_json::json!({"a": 1, "b": 2}),
        );
        assert!(result.is_err(), "blocking handler should be timed out");
        let err = result.unwrap_err();
        assert!(
            err.contains("timed out"),
            "error should mention timeout: {err}"
        );
        assert!(
            err.contains("50ms"),
            "error should include the timeout duration: {err}"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    #[test]
    fn invoke_outlet_handler_completes_within_timeout_succeeds() {
        let creator = "did:dht:z6MkCreatorTimeoutOk";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, true);

        // Register a fast handler.
        let fast_handler: crate::runtime::OutletHandler =
            std::sync::Arc::new(|input: serde_json::Value| {
                let a = input
                    .get("a")
                    .and_then(serde_json::Value::as_f64)
                    .unwrap_or(0.0);
                let b = input
                    .get("b")
                    .and_then(serde_json::Value::as_f64)
                    .unwrap_or(0.0);
                Ok(serde_json::json!({"result": a + b}))
            });

        crate::runtime::register_outlet_handler(&bi, &ctx_id, "calculator", fast_handler).unwrap();

        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: creator.to_owned(),
            context_ids: vec![ctx_id.clone()],
            outlet_timeout_ms: 5_000, // 5 seconds — plenty for an instant handler.
            agent_ucan_token: None,

            agent_proof_tokens: None,
        };

        let result = invoke_granted(
            &provider,
            &ctx_id,
            "calculator",
            serde_json::json!({"a": 3, "b": 4}),
        );
        assert!(
            result.is_ok(),
            "fast handler should complete within timeout: {result:?}"
        );
        let output = result.unwrap();
        assert_eq!(
            output,
            serde_json::json!({"result": 7.0}),
            "handler output should be correct"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    #[test]
    fn invoke_outlet_handler_default_timeout_is_30s() {
        // Verify the default timeout constant matches scp-core.
        assert_eq!(
            FFI_OUTLET_TIMEOUT_MS,
            u64::from(scp_core::context::outlets::DEFAULT_TIMEOUT_MS),
            "FFI default timeout should match scp-core default"
        );
    }

    // -----------------------------------------------------------------------
    // StdioClientTransport
    // -----------------------------------------------------------------------

    #[test]
    fn stdio_client_transport_spawn_rejects_unlisted_command() {
        let allowlist = Mutex::new(allowlist::StdioAllowlist::new_with_defaults());
        let result = StdioClientTransport::spawn(
            &allowlist,
            &["nonexistent_command_that_does_not_exist_12345".to_owned()],
        );
        match result {
            Err(msg) => assert!(
                msg.contains("allowlist"),
                "error should mention allowlist: {msg}"
            ),
            Ok(_) => panic!("expected rejection for unlisted command"),
        }
    }

    #[test]
    fn stdio_client_transport_empty_command() {
        let allowlist = Mutex::new(allowlist::StdioAllowlist::new_with_defaults());
        let result = StdioClientTransport::spawn(&allowlist, &[]);
        assert!(result.is_err());
    }

    /// Yields an in-flight call's error message once it ends, or `None` if
    /// it succeeded.
    #[cfg(unix)]
    type CallOutcome = std::sync::mpsc::Receiver<Option<String>>;

    /// Connects `scp` through `py_mcp_client_connect_stdio` to a stub server
    /// that answers `initialize` and then falls silent, and starts a
    /// `py_mcp_client_list_tools` on it from a Python thread. The stub runs
    /// `sleep` as its own child, the way `npx` runs the real server: `sh`
    /// starts it in the background and `wait`s, so `sh` never execs it. The
    /// stub forks `sleep` before it answers `initialize`, so the grandchild
    /// exists before connect returns, and a teardown that starts right after
    /// connect cannot race the fork and leave `sleep` alive. That grandchild
    /// holds the stdout pipe, so the in-flight call ends only when its whole
    /// process group is killed. Returns only once the call holds the client's lock,
    /// which it takes after cloning `client` out of the registry and keeps
    /// through the blocking read, so the caller's teardown always meets a
    /// call in flight. Returns the handle, the server's slot, and a receiver
    /// that yields the in-flight call's error message, or `None` if it
    /// succeeded.
    #[cfg(unix)]
    fn start_call_on_a_silent_stdio_server(
        scp: &crate::scp::PyScp,
    ) -> (String, Arc<Mutex<Option<Child>>>, CallOutcome) {
        pyo3::prepare_freethreaded_python();
        scp.inner
            .core
            .mcp_allowlist()
            .lock()
            .expect("allowlist lock")
            .configure(&["sh"])
            .expect("allow sh");
        let script = "read l; sleep 600 & \
            echo '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\
            \"capabilities\":{},\"serverInfo\":{\"name\":\"stub\"}}}'; \
            wait";
        let handle = Python::with_gil(|py| {
            scp.py_mcp_client_connect_stdio(
                py,
                vec!["sh".to_owned(), "-c".to_owned(), script.to_owned()],
            )
        })
        .expect("connect to the stub server");
        let (server, probe) = {
            let entry = client_registry_of(&scp.inner)
                .get(&handle)
                .expect("registered handle");
            let ClientServer::Stdio(server) = &entry.server else {
                panic!("a stdio client records its server");
            };
            (Arc::clone(server), Arc::clone(&entry.client))
        };

        let caller = crate::scp::PyScp {
            inner: Arc::clone(&scp.inner),
        };
        let call_handle = handle.clone();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let error = Python::with_gil(|py| {
                caller
                    .py_mcp_client_list_tools(py, &call_handle)
                    .err()
                    .map(|e| e.to_string())
            });
            let _ = done_tx.send(error);
        });
        // Nothing but the call locks the client once connect has returned,
        // so a failed `try_lock` means the call is inside `list_tools`.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while probe.try_lock().is_ok() {
            assert!(
                std::time::Instant::now() < deadline,
                "the tools/list call never took the client's lock"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        drop(probe);
        (handle, server, done_rx)
    }

    /// Asserts that the in-flight call failed on its `tools/list` request,
    /// which only a call that reached the transport can do; a call that lost
    /// the race to the teardown fails on the missing handle instead.
    #[cfg(unix)]
    fn assert_failed_in_tools_list(error: Option<String>) {
        let error = error.expect("the killed stub server sent no tools/list response");
        assert!(
            error.contains("tools/list failed") && error.contains(codes::TRANS_5022),
            "the call must fail on its in-flight request with TRANS-5022, not on the handle lookup: {error}"
        );
    }

    /// Runs `stop` on a Python thread of its own and waits for it to return.
    /// The in-flight call releases the GIL, so `stop` gets it; a call that
    /// held the GIL through its blocking read would leave `stop` waiting
    /// here until the timeout.
    #[cfg(unix)]
    fn run_on_a_second_python_thread(stop: impl FnOnce(Python<'_>) + Send + 'static) {
        let (stopped_tx, stopped_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            Python::with_gil(stop);
            let _ = stopped_tx.send(());
        });
        stopped_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect(
                "the in-flight call must release the GIL so a second Python thread can stop it",
            );
    }

    /// A `tools/list` in flight against a silent stdio server holds its own
    /// clone of the client, so dropping the registry's copy does not drop the
    /// transport. `py_mcp_client_disconnect`, called from a second Python
    /// thread, kills the server's process group, and the in-flight call then
    /// ends on the closed stdout.
    #[cfg(unix)]
    #[test]
    fn disconnect_kills_the_stdio_servers_process_group_under_an_in_flight_call() {
        let scp = crate::scp::PyScp::new_in_memory_for_test();
        let (handle, server, done_rx) = start_call_on_a_silent_stdio_server(&scp);

        let disconnector = crate::scp::PyScp {
            inner: Arc::clone(&scp.inner),
        };
        run_on_a_second_python_thread(move |_py| {
            disconnector
                .py_mcp_client_disconnect(&handle)
                .expect("disconnect a known handle");
        });

        assert!(
            server.lock().expect("server lock").is_none(),
            "disconnect must kill and reap the stdio server process"
        );
        let error = done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the in-flight call must end once disconnect kills the server's grandchild");
        assert_failed_in_tools_list(error);
    }

    /// Instance shutdown clears the client registry while a `tools/list` is
    /// in flight against a silent stdio server. Dropping the client state
    /// kills the server's process group, as a disconnect does, and the
    /// in-flight call then ends on the closed stdout.
    #[cfg(unix)]
    #[test]
    fn shutdown_kills_the_stdio_servers_process_group_under_an_in_flight_call() {
        crate::init_runtime().expect("tokio runtime for SCP.shutdown");
        let scp = crate::scp::PyScp::new_in_memory_for_test();
        let (_handle, server, done_rx) = start_call_on_a_silent_stdio_server(&scp);

        let owner = crate::scp::PyScp {
            inner: Arc::clone(&scp.inner),
        };
        run_on_a_second_python_thread(move |py| {
            owner.shutdown(py, 1_000).expect("shut the instance down");
        });

        assert!(
            server.lock().expect("server lock").is_none(),
            "shutdown must kill and reap the stdio server process"
        );
        let error = done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the in-flight call must end once shutdown kills the server's grandchild");
        assert_failed_in_tools_list(error);
    }

    /// `stop_stdio_server` reaps the server and empties its slot, so the
    /// second stop that a disconnect followed by the transport's drop makes
    /// finds no `Child` and never runs `stop_server_process` on a reaped one,
    /// whose raw pid may by then name another group-leading child. Pid reuse
    /// cannot be forced in a test, so the test checks the empty slot, which
    /// is what keeps the second stop from signalling.
    #[cfg(unix)]
    #[test]
    fn stop_stdio_server_reaps_the_server_and_empties_its_slot() {
        let mut command = Command::new("sleep");
        command.arg("600");
        std::os::unix::process::CommandExt::process_group(&mut command, 0);
        let slot = Mutex::new(Some(command.spawn().expect("spawn group leader")));
        stop_stdio_server(&slot);
        assert!(
            slot.lock().expect("slot lock").is_none(),
            "the first stop must reap the server and empty its slot"
        );
        stop_stdio_server(&slot);
        assert!(slot.lock().expect("slot lock").is_none());
    }

    /// A call that checked the handle out before a disconnect, and takes the
    /// client's lock after it, fails as disconnected and sends nothing. The
    /// helper's `tools/list` holds the lock when the queued call checks the
    /// handle out, so the queued call gets the lock only after the disconnect
    /// has set the closed flag, whichever of its lock attempt and the
    /// disconnect runs first.
    #[cfg(unix)]
    #[test]
    fn a_call_queued_at_disconnect_sends_no_request() {
        let scp = crate::scp::PyScp::new_in_memory_for_test();
        let (handle, server, done_rx) = start_call_on_a_silent_stdio_server(&scp);
        let queued = LiveMcpClient::checkout(&scp.inner, &handle, codes::TRANS_5020)
            .expect("check out the live handle");
        let queued_handle = handle.clone();
        let (queued_tx, queued_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let outcome = queued
                .lock(&queued_handle, codes::TRANS_5021, codes::TRANS_5022)
                .map(drop)
                .map_err(|e| e.to_string());
            let _ = queued_tx.send(outcome);
        });

        scp.py_mcp_client_disconnect(&handle)
            .expect("disconnect a known handle");

        let timeout = std::time::Duration::from_secs(10);
        let queued = queued_rx
            .recv_timeout(timeout)
            .expect("the queued call must end");
        assert_failed_in_tools_list(
            done_rx
                .recv_timeout(timeout)
                .expect("the in-flight call must end"),
        );
        stop_stdio_server(&server);
        let error = queued.expect_err("the queued call took the client after the disconnect");
        assert!(
            error.contains("was disconnected") && error.contains(codes::TRANS_5021),
            "the queued call must fail as disconnected with TRANS-5021, got: {error}"
        );
    }

    /// Connects a stdio client to a stub server that answers `initialize`
    /// and then answers every request with a JSON-RPC error carrying the
    /// request's id.
    #[cfg(unix)]
    fn connect_to_an_erroring_stdio_server(scp: &crate::scp::PyScp) -> String {
        pyo3::prepare_freethreaded_python();
        scp.inner
            .core
            .mcp_allowlist()
            .lock()
            .expect("allowlist lock")
            .configure(&["sh"])
            .expect("allow sh");
        let script = "read l; \
            echo '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\
            \"capabilities\":{},\"serverInfo\":{\"name\":\"stub\"}}}'; \
            while read l; do \
            id=$(printf '%s' \"$l\" | sed -n 's/.*\"id\":\\([0-9][0-9]*\\).*/\\1/p'); \
            if [ -n \"$id\" ]; then \
            echo \"{\\\"jsonrpc\\\":\\\"2.0\\\",\\\"id\\\":$id,\\\"error\\\":{\\\"code\\\":-32601,\\\"message\\\":\\\"refused\\\"}}\"; \
            fi; done";
        Python::with_gil(|py| {
            scp.py_mcp_client_connect_stdio(
                py,
                vec!["sh".to_owned(), "-c".to_owned(), script.to_owned()],
            )
        })
        .expect("connect to the stub server")
    }

    /// Calls `tools/list` and `tools/call` on `handle` and returns both
    /// error strings.
    #[cfg(unix)]
    fn list_and_invoke_errors(scp: &crate::scp::PyScp, handle: &str) -> (String, String) {
        Python::with_gil(|py| {
            let list = scp
                .py_mcp_client_list_tools(py, handle)
                .expect_err("tools/list must fail")
                .to_string();
            let invoke = scp
                .py_mcp_client_invoke(
                    py,
                    handle,
                    "test-outlet",
                    &PyDict::new(py),
                    "ctx-test",
                    "did:dht:z6MkTestUser",
                )
                .expect_err("tools/call must fail")
                .to_string();
            (list, invoke)
        })
    }

    /// Asserts that `error` carries `code` and none of the other MCP client
    /// codes, nor the generic transport code.
    #[cfg(unix)]
    fn assert_mcp_client_code(error: &str, code: &str) {
        for other in [
            codes::TRANS_5001,
            codes::TRANS_5020,
            codes::TRANS_5021,
            codes::TRANS_5022,
            codes::TRANS_5023,
            codes::TRANS_5024,
            codes::TRANS_5025,
        ] {
            assert_eq!(
                error.contains(other),
                other == code,
                "expected {code} alone, got: {error}"
            );
        }
    }

    /// The `PyO3` MCP client returns the documented code for each condition:
    /// a server error on `tools/list` and `tools/call` is TRANS-5022 and
    /// TRANS-5025, a poisoned client lock is the same failure codes, and an
    /// unregistered handle is TRANS-5020 and TRANS-5023. A disconnect cannot
    /// be raced into a call deterministically, so
    /// `a_call_queued_at_disconnect_sends_no_request` checks the
    /// disconnected-while-waiting refusal through `LiveMcpClient::lock`.
    #[cfg(unix)]
    #[test]
    fn mcp_client_calls_return_the_documented_codes() {
        let scp = crate::scp::PyScp::new_in_memory_for_test();
        let handle = connect_to_an_erroring_stdio_server(&scp);

        let (list, invoke) = list_and_invoke_errors(&scp, &handle);
        assert!(list.contains("tools/list failed"), "got: {list}");
        assert_mcp_client_code(&list, codes::TRANS_5022);
        assert!(invoke.contains("tools/call failed"), "got: {invoke}");
        assert_mcp_client_code(&invoke, codes::TRANS_5025);

        let client = LiveMcpClient::checkout(&scp.inner, &handle, codes::TRANS_5020)
            .expect("check out the live handle");
        let poisoner = Arc::clone(&client.client);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.lock().expect("client lock");
            panic!("poison the client lock");
        })
        .join();
        let (list, invoke) = list_and_invoke_errors(&scp, &handle);
        assert!(list.contains("client lock poisoned"), "got: {list}");
        assert_mcp_client_code(&list, codes::TRANS_5022);
        assert!(invoke.contains("client lock poisoned"), "got: {invoke}");
        assert_mcp_client_code(&invoke, codes::TRANS_5025);
        drop(client);

        scp.py_mcp_client_disconnect(&handle)
            .expect("disconnect a known handle");
        let (list, invoke) = list_and_invoke_errors(&scp, &handle);
        assert!(list.contains("not found"), "got: {list}");
        assert_mcp_client_code(&list, codes::TRANS_5020);
        assert!(invoke.contains("not found"), "got: {invoke}");
        assert_mcp_client_code(&invoke, codes::TRANS_5023);
    }

    /// Polls `condition` every 5 ms for up to 10 seconds.
    #[cfg(unix)]
    fn wait_for(what: &str, condition: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !condition() {
            assert!(std::time::Instant::now() < deadline, "timed out: {what}");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// `SCP.shutdown` ends a stdio connect whose server never answers
    /// `initialize`. The connect registers its client before the handshake,
    /// so the shutdown's registry clear kills the server; the handshake fails
    /// on the closed stdout and the connect fails as shut down.
    #[cfg(unix)]
    #[test]
    fn shutdown_ends_a_stdio_connect_waiting_on_initialize_and_kills_its_server() {
        crate::init_runtime().expect("tokio runtime for SCP.shutdown");
        pyo3::prepare_freethreaded_python();
        let scp = crate::scp::PyScp::new_in_memory_for_test();
        scp.inner
            .core
            .mcp_allowlist()
            .lock()
            .expect("allowlist lock")
            .configure(&["sh"])
            .expect("allow sh");
        let pid_file = std::env::temp_dir().join(format!(
            "{}.pid",
            generate_handle_id("mcp-silent-handshake")
        ));
        let script = format!("echo $$ > '{}'; sleep 600 & wait", pid_file.display());
        let connector = crate::scp::PyScp {
            inner: Arc::clone(&scp.inner),
        };
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = Python::with_gil(|py| {
                connector
                    .py_mcp_client_connect_stdio(py, vec!["sh".to_owned(), "-c".to_owned(), script])
                    .map_err(|e| e.to_string())
            });
            let _ = done_tx.send(result);
        });
        wait_for(
            "the connect registers its client before the handshake",
            || client_registry_of(&scp.inner).len() == 1,
        );
        wait_for("the stub server writes its pid", || {
            std::fs::read_to_string(&pid_file).is_ok_and(|pid| pid.ends_with('\n'))
        });

        let owner = crate::scp::PyScp {
            inner: Arc::clone(&scp.inner),
        };
        run_on_a_second_python_thread(move |py| {
            owner.shutdown(py, 1_000).expect("shut the instance down");
        });

        let result = done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("shutdown must end the connect's handshake");
        let pid = std::fs::read_to_string(&pid_file).expect("the stub server wrote its pid");
        let _ = std::fs::remove_file(&pid_file);
        let error = result.expect_err("a connect that shutdown ended must fail");
        assert!(error.contains("shut down"), "unexpected error: {error}");
        assert!(
            client_registry_of(&scp.inner).is_empty(),
            "the ended connect must leave the registry empty"
        );
        let alive = Command::new("kill")
            .args(["-0", pid.trim()])
            .stderr(Stdio::null())
            .status()
            .expect("run kill -0");
        assert!(
            !alive.success(),
            "the spawned server must be killed and reaped"
        );
    }

    /// `SCP.shutdown` ends an SSE handshake whose server accepts the
    /// `initialize` POST and never answers it: the registered state's drop
    /// shuts down the POST's socket, and the handshake fails as shut down.
    #[cfg(unix)]
    #[test]
    fn shutdown_ends_an_sse_handshake_waiting_on_a_silent_server() {
        use std::io::BufRead as _;
        crate::init_runtime().expect("tokio runtime for SCP.shutdown");
        pyo3::prepare_freethreaded_python();
        let scp = crate::scp::PyScp::new_in_memory_for_test();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the stub");
        let port = listener.local_addr().expect("stub address").port();
        let (posted_tx, posted_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            let mut get = listener.accept().expect("accept the GET").0;
            let mut request = BufReader::new(get.try_clone().expect("clone the GET"));
            let mut line = String::new();
            while request.read_line(&mut line).is_ok_and(|n| n > 0) && !line.trim().is_empty() {
                line.clear();
            }
            get.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n\
                  event: endpoint\ndata: /message\n\n",
            )
            .expect("answer the GET");
            let initialize_post = listener.accept().expect("accept the POST").0;
            let _ = posted_tx.send(());
            let _ = stop_rx.recv();
            drop((get, initialize_post));
        });
        let url = format!("http://127.0.0.1:{port}/sse");
        let transport = SseClientTransport::connect(&url, None).expect("connect to the stub");
        let server = ClientServer::Sse(transport.closer());
        let client = McpClient::new(ClientTransport::Sse(transport));
        let state = McpClientState::new("sse", None, Some(url), client, server);
        let bridge = Arc::clone(&scp.inner);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = Python::with_gil(|py| {
                initialize_registered(py, &bridge, state).map_err(|e| e.to_string())
            });
            let _ = done_tx.send(result);
        });
        posted_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the handshake must send its initialize POST");

        let owner = crate::scp::PyScp {
            inner: Arc::clone(&scp.inner),
        };
        run_on_a_second_python_thread(move |py| {
            owner.shutdown(py, 1_000).expect("shut the instance down");
        });

        let result = done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("shutdown must end the SSE handshake");
        drop(stop_tx);
        let error = result.expect_err("a handshake that shutdown ended must fail");
        assert!(error.contains("shut down"), "unexpected error: {error}");
        assert!(
            client_registry_of(&scp.inner).is_empty(),
            "the ended connect must leave the registry empty"
        );
    }

    /// Reads one HTTP request from `conn`, head and `Content-Length` body, and
    /// returns the JSON-RPC `id` of its body, or `None` for a request without
    /// a body or without an `id` (a `GET`, or a notification).
    #[cfg(unix)]
    fn read_request_id(conn: &std::net::TcpStream) -> Option<serde_json::Value> {
        use std::io::{BufRead as _, Read as _};
        let mut reader = BufReader::new(conn);
        let mut length = 0usize;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).ok()? == 0 || line.trim().is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                length = value.trim().parse().ok()?;
            }
        }
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body).ok()?;
        serde_json::from_slice::<serde_json::Value>(&body)
            .ok()?
            .get("id")
            .cloned()
    }

    /// Answers a POST with `202 Accepted` and writes `result` under `id` on
    /// the SSE stream, the way an SCP SSE server answers a request.
    #[cfg(unix)]
    fn answer_on_the_stream(
        post: &mut std::net::TcpStream,
        sse: &mut std::net::TcpStream,
        id: &serde_json::Value,
        result: &serde_json::Value,
    ) -> Option<()> {
        post.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n")
            .ok()?;
        let response = serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result});
        sse.write_all(format!("event: message\ndata: {response}\n\n").as_bytes())
            .ok()
    }

    /// Connects `scp` through `py_mcp_client_connect_sse` to a stub server
    /// that answers the handshake and one `tools/list`, which must succeed,
    /// and then starts a second `tools/list` from a Python thread whose POST
    /// the stub accepts and never answers. The stub holds every connection
    /// open until the returned sender drops, so only closing the transport
    /// ends that call. Returns once the stub has accepted the silent POST,
    /// with the handle, a receiver that yields the call's error message (or
    /// `None` if it succeeded), and the sender that releases the stub.
    #[cfg(unix)]
    fn start_call_on_a_silent_sse_server(
        scp: &crate::scp::PyScp,
    ) -> (String, CallOutcome, std::sync::mpsc::Sender<()>) {
        pyo3::prepare_freethreaded_python();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the stub");
        let port = listener.local_addr().expect("stub address").port();
        let (silent_tx, silent_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || -> Option<()> {
            let mut sse = listener.accept().ok()?.0;
            read_request_id(&sse);
            sse.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n\
                  event: endpoint\ndata: /message\n\n",
            )
            .ok()?;
            let mut initialize = listener.accept().ok()?.0;
            let id = read_request_id(&initialize)?;
            let info = serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "stub"},
            });
            answer_on_the_stream(&mut initialize, &mut sse, &id, &info)?;
            let mut initialized = listener.accept().ok()?.0;
            read_request_id(&initialized);
            initialized
                .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n")
                .ok()?;
            let mut answered = listener.accept().ok()?.0;
            let id = read_request_id(&answered)?;
            let tools = serde_json::json!({"tools": [{
                "name": "echo",
                "description": "echoes",
                "inputSchema": {"type": "object"},
            }]});
            answer_on_the_stream(&mut answered, &mut sse, &id, &tools)?;
            let silent = listener.accept().ok()?.0;
            read_request_id(&silent)?;
            let _ = silent_tx.send(());
            let _ = release_rx.recv();
            drop((sse, initialize, initialized, answered, silent));
            Some(())
        });
        let handle = Python::with_gil(|py| {
            scp.py_mcp_client_connect_sse(py, &format!("http://127.0.0.1:{port}/sse"), None)
        })
        .expect("connect to the stub server");
        let listed = Python::with_gil(|py| {
            scp.py_mcp_client_list_tools(py, &handle)
                .map(|tools| tools.bind(py).to_string())
        })
        .expect("a tools/list the server answers must succeed");
        assert!(listed.contains("echo"), "unexpected tools: {listed}");

        let caller = crate::scp::PyScp {
            inner: Arc::clone(&scp.inner),
        };
        let call_handle = handle.clone();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let error = Python::with_gil(|py| {
                caller
                    .py_mcp_client_list_tools(py, &call_handle)
                    .err()
                    .map(|e| e.to_string())
            });
            let _ = done_tx.send(error);
        });
        silent_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the second tools/list must reach the stub");
        (handle, done_rx, release_tx)
    }

    /// Asserts that the in-flight SSE call ended within two seconds of
    /// `stopped_at` and failed because its transport was closed.
    #[cfg(unix)]
    fn assert_closed_in_flight(done_rx: &CallOutcome, stopped_at: std::time::Instant) {
        let error = done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("closing the transport must end the SSE call in flight")
            .expect("the silent stub sent no tools/list response");
        assert!(
            stopped_at.elapsed() < std::time::Duration::from_secs(2),
            "the call must end at once, not on a read timeout"
        );
        assert!(
            error.contains("tools/list failed") && error.contains("SSE connection is closed"),
            "the call must fail on its closed transport, got: {error}"
        );
    }

    /// `py_mcp_client_disconnect`, called from a second Python thread, ends
    /// a `tools/list` in flight on an SSE client whose server accepted the
    /// POST and never answers: the state's drop shuts the POST's socket down.
    /// The handle then fails as not found.
    #[cfg(unix)]
    #[test]
    fn disconnect_ends_an_sse_call_in_flight() {
        let scp = crate::scp::PyScp::new_in_memory_for_test();
        let (handle, done_rx, release) = start_call_on_a_silent_sse_server(&scp);

        let disconnector = crate::scp::PyScp {
            inner: Arc::clone(&scp.inner),
        };
        let disconnected = handle.clone();
        let stopped_at = std::time::Instant::now();
        run_on_a_second_python_thread(move |_py| {
            disconnector
                .py_mcp_client_disconnect(&disconnected)
                .expect("disconnect a known handle");
        });

        assert_closed_in_flight(&done_rx, stopped_at);
        drop(release);
        let after = Python::with_gil(|py| scp.py_mcp_client_list_tools(py, &handle))
            .expect_err("a disconnected handle must refuse a call")
            .to_string();
        assert!(
            after.contains("not found") && after.contains(codes::TRANS_5020),
            "got: {after}"
        );
    }

    /// Instance shutdown clears the client registry while a `tools/list` is
    /// in flight on an SSE client whose server never answers; the state's
    /// drop closes the transport, as a disconnect does, and the call ends.
    #[cfg(unix)]
    #[test]
    fn shutdown_ends_an_sse_call_in_flight() {
        crate::init_runtime().expect("tokio runtime for SCP.shutdown");
        let scp = crate::scp::PyScp::new_in_memory_for_test();
        let (_handle, done_rx, release) = start_call_on_a_silent_sse_server(&scp);

        let owner = crate::scp::PyScp {
            inner: Arc::clone(&scp.inner),
        };
        let stopped_at = std::time::Instant::now();
        run_on_a_second_python_thread(move |py| {
            owner.shutdown(py, 1_000).expect("shut the instance down");
        });

        assert_closed_in_flight(&done_rx, stopped_at);
        drop(release);
        assert!(
            client_registry_of(&scp.inner).is_empty(),
            "shutdown must clear the client registry"
        );
    }

    /// A stdio client whose state reaches the registry after `SCP.shutdown`
    /// cleared it registers nothing: the connect fails, and dropping its state
    /// kills the server it spawned. The shutdown runs after the spawn and
    /// before the registration here, so the check after the insert is the one
    /// that refuses it.
    #[cfg(unix)]
    #[test]
    fn a_stdio_connect_after_shutdown_registers_nothing_and_kills_its_server() {
        crate::init_runtime().expect("tokio runtime for SCP.shutdown");
        pyo3::prepare_freethreaded_python();
        let scp = crate::scp::PyScp::new_in_memory_for_test();
        scp.inner
            .core
            .mcp_allowlist()
            .lock()
            .expect("allowlist lock")
            .configure(&["sh"])
            .expect("allow sh");
        let pid_file = std::env::temp_dir().join(format!(
            "{}.pid",
            generate_handle_id("mcp-shutdown-connect")
        ));
        let script = format!("echo $$ > '{}'; sleep 600 & wait", pid_file.display());
        let transport = StdioClientTransport::spawn(
            scp.inner.core.mcp_allowlist(),
            &["sh".to_owned(), "-c".to_owned(), script],
        )
        .expect("spawn stub server");
        let server = ClientServer::Stdio(transport.server_process());
        let client = McpClient::new(ClientTransport::Stdio(transport));
        let state = McpClientState::new("stdio", None, None, client, server);
        wait_for("the stub server writes its pid", || {
            std::fs::read_to_string(&pid_file).is_ok_and(|pid| pid.ends_with('\n'))
        });
        let result = Python::with_gil(|py| {
            scp.shutdown(py, 1_000).expect("shut the instance down");
            initialize_registered(py, &scp.inner, state)
        });
        let pid = std::fs::read_to_string(&pid_file).expect("the stub server wrote its pid");
        let _ = std::fs::remove_file(&pid_file);

        let error = result
            .expect_err("a connect after shutdown must fail")
            .to_string();
        assert!(error.contains("shut down"), "unexpected error: {error}");
        assert!(
            client_registry_of(&scp.inner).is_empty(),
            "a connect after shutdown must leave the registry empty"
        );
        let alive = Command::new("kill")
            .args(["-0", pid.trim()])
            .stderr(Stdio::null())
            .status()
            .expect("run kill -0");
        assert!(
            !alive.success(),
            "the spawned server must be killed and reaped"
        );
    }

    /// WU6: Two-instance regression test — disabling enforcement via the
    /// public `PyScp::mcp_disable_stdio_allowlist` method on one instance
    /// MUST NOT leak into another. Drives the public surface (not the
    /// internal `core.mcp_allowlist()` accessor) so the test catches a
    /// regression where the method silently locks the wrong mutex.
    #[test]
    fn allowlist_disable_does_not_leak_across_instances_pyo3() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let a = crate::scp::PyScp::new_in_memory_for_test();
            let b = crate::scp::PyScp::new_in_memory_for_test();

            a.mcp_disable_stdio_allowlist()
                .expect("disable on a should succeed");

            // `b` snapshot remains restricted (default allowlist, enforcement on).
            let b_dict_obj = b.mcp_get_stdio_allowlist(py).expect("snapshot b");
            let b_dict: &Bound<'_, PyDict> = b_dict_obj.bind(py).downcast().unwrap();
            let b_unrestricted: bool = b_dict
                .get_item("unrestricted")
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();
            assert!(!b_unrestricted, "instance b must remain restricted");

            // Sanity: `a` is unrestricted via its own snapshot.
            let a_dict_obj = a.mcp_get_stdio_allowlist(py).expect("snapshot a");
            let a_dict: &Bound<'_, PyDict> = a_dict_obj.bind(py).downcast().unwrap();
            let a_unrestricted: bool = a_dict
                .get_item("unrestricted")
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();
            assert!(a_unrestricted, "instance a must be unrestricted");
        });
    }

    /// WU6 supplement: `configure` on one instance must not bleed into
    /// another's allow set, exercised through the public `PyScp` method.
    #[test]
    fn allowlist_configure_does_not_leak_across_instances_pyo3() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let a = crate::scp::PyScp::new_in_memory_for_test();
            let b = crate::scp::PyScp::new_in_memory_for_test();

            a.mcp_configure_stdio_allowlist(vec!["custom-a".to_owned()])
                .expect("configure on a");

            let a_dict_obj = a.mcp_get_stdio_allowlist(py).expect("snapshot a");
            let a_dict: &Bound<'_, PyDict> = a_dict_obj.bind(py).downcast().unwrap();
            let a_allowed: Vec<String> = a_dict
                .get_item("allowed")
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();
            assert!(a_allowed.contains(&"custom-a".to_owned()));

            let b_dict_obj = b.mcp_get_stdio_allowlist(py).expect("snapshot b");
            let b_dict: &Bound<'_, PyDict> = b_dict_obj.bind(py).downcast().unwrap();
            let b_allowed: Vec<String> = b_dict
                .get_item("allowed")
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();
            assert!(
                !b_allowed.contains(&"custom-a".to_owned()),
                "instance b must not see a's custom binary",
            );
        });
    }

    // -----------------------------------------------------------------------
    // Registry statistics and cleanup (issue #108)
    // -----------------------------------------------------------------------

    #[test]
    fn mcp_registry_stats_returns_consistent_counts() {
        crate::runtime::init_context_manager_for_test(&__bi());
        let stats = mcp_registry_stats_for(&__bi());
        // Cannot assert exact values due to parallel tests, but structural
        // invariants must hold: stopped_servers can never exceed total servers.
        assert!(
            stats.stopped_servers <= stats.servers,
            "stopped_servers ({}) must be <= servers ({})",
            stats.stopped_servers,
            stats.servers
        );
        // Verify the struct is constructable and all fields are accessible.
        let _ = stats.clients;
    }

    #[test]
    fn cleanup_stopped_servers_removes_stopped_entries() {
        let creator = "did:dht:z6MkCreatorCleanup";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, false);

        // Create a minimal server entry directly in the registry.
        let handle = generate_handle_id("mcp-server");

        server_registry_of(&bi).insert(
            handle.clone(),
            McpServerState {
                identity_did: creator.to_owned(),
                context_ids: vec![ctx_id.clone()],
                transport: "stdio".to_owned(),
                stopped: true, // Already stopped.
                shutdown_tx: None,
                task_handle: None,
            },
        );

        // Verify our entry is present before cleanup.
        assert!(
            server_registry_of(&bi).contains_key(&handle),
            "stopped server handle should be present before cleanup"
        );

        cleanup_stopped_servers_for(&bi);

        // The specific handle should be gone. We check by key rather than
        // by count because parallel tests may insert/remove other entries.
        assert!(
            !server_registry_of(&bi).contains_key(&handle),
            "stopped server handle should be removed after cleanup"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    #[test]
    fn cleanup_stopped_servers_leaves_running_entries() {
        let creator = "did:dht:z6MkCreatorCleanupRunning";
        let bi = __bi();
        let ctx_id = setup_test_context(&bi, creator, false);

        let handle = generate_handle_id("mcp-server");

        server_registry_of(&bi).insert(
            handle.clone(),
            McpServerState {
                identity_did: creator.to_owned(),
                context_ids: vec![ctx_id.clone()],
                transport: "stdio".to_owned(),
                stopped: false, // Still running.
                shutdown_tx: None,
                task_handle: None,
            },
        );

        cleanup_stopped_servers_for(&bi);

        // Running server should still be present.
        assert!(
            server_registry_of(&bi).contains_key(&handle),
            "running server handle should NOT be removed"
        );

        // Cleanup: remove manually.
        server_registry_of(&bi).remove(&handle);
        crate::runtime::remove_context(&bi, &ctx_id);
    }

    #[test]
    fn core_registry_stats_includes_all_fields() {
        crate::runtime::init_context_manager_for_test(&__bi());
        let stats = crate::runtime::registry_stats(&__bi());
        // Destructure without `..`, so adding a field to `RegistryStats`
        // stops this test compiling. Reading each field through `let _ =`,
        // as an earlier version did, caught a removed field but admitted a
        // new one, which is what "includes all fields" denies.
        let crate::runtime::RegistryStats {
            contexts,
            known_contexts,
            identities,
            relay_connected,
        } = stats;
        let _: usize = contexts;
        let _: usize = known_contexts;
        let _: usize = identities;
        let _: bool = relay_connected;
    }

    // -----------------------------------------------------------------------
    // FfiBridgeProvider::validate_resource_access — answered from real role
    // state, as the NAPI and UniFFI providers answer it
    // -----------------------------------------------------------------------

    /// Builds an [`FfiBridgeProvider`] over `bi` serving `context_id` on
    /// behalf of `agent_did`, with no UCAN material.
    fn pyo3_mcp_provider(
        bi: &std::sync::Arc<crate::runtime::PyBridgeInstance>,
        context_id: &str,
        agent_did: &str,
    ) -> FfiBridgeProvider {
        FfiBridgeProvider {
            bi: Arc::downgrade(bi),
            agent_did: agent_did.to_owned(),
            context_ids: vec![context_id.to_owned()],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,
            agent_proof_tokens: None,
        }
    }

    fn mcp_request(method: &str, params: serde_json::Value) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: scp_mcp::protocol::JSONRPC_VERSION.to_owned(),
            method: method.to_owned(),
            params: Some(params),
            id: scp_mcp::protocol::RequestId::Number(1),
        }
    }

    /// Completes the MCP handshake and returns the advertised
    /// `capabilities.resources.subscribe` flag.
    fn initialize_and_read_subscribe_flag(server: &mut McpServer<FfiBridgeProvider>) -> bool {
        let response = server
            .handle_request(&mcp_request(
                scp_mcp::protocol::METHOD_INITIALIZE,
                serde_json::json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": { "name": "pyo3-test" },
                }),
            ))
            .expect("initialize must produce a response");
        let result = response.result.expect("initialize must succeed");
        result["capabilities"]["resources"]["subscribe"]
            .as_bool()
            .expect("resources.subscribe must be advertised as a bool")
    }

    /// `validate_resource_access` answers from the context's REAL role state:
    /// the creator (an admin holding `messages:read` under the default
    /// ceiling) reads every resource; a non-member is denied — the gate is
    /// real, not a blanket allow.
    #[test]
    fn ffi_bridge_provider_validates_resource_access_from_role_state() {
        use scp_mcp::server::ResourceKind;

        let creator = "did:dht:z6MkCreatorResAccess";
        let bi = __bi();
        let ctx_id = setup_unsupervised_context(&bi, creator, false);

        let provider = pyo3_mcp_provider(&bi, &ctx_id, creator);
        for kind in [
            ResourceKind::Events,
            ResourceKind::Members,
            ResourceKind::Tools,
        ] {
            assert!(
                provider.validate_resource_access(&ctx_id, kind).is_ok(),
                "the context creator must be able to read scp://{ctx_id}/{}",
                kind.uri_suffix()
            );
        }

        // Negative control: a DID that is not a member of the context is
        // denied every resource — `Events`/`Members` for lack of
        // `messages:read`, `Tools` for lack of membership.
        let outsider = pyo3_mcp_provider(&bi, &ctx_id, "did:dht:z6MkNotAMember");
        for kind in [
            ResourceKind::Events,
            ResourceKind::Members,
            ResourceKind::Tools,
        ] {
            let denial = outsider
                .validate_resource_access(&ctx_id, kind)
                .expect_err("a non-member must not be able to read the resource");
            // The denial names the requirement this kind checks.
            let expected = match kind {
                ResourceKind::Tools => "lacks membership",
                ResourceKind::Events | ResourceKind::Members => "lacks messages:read",
            };
            assert!(
                matches!(&denial, scp_mcp::server::AccessRefusal::Denied(msg) if msg.contains(expected)),
                "the denial for scp://{ctx_id}/{} must say {expected:?}, got: {denial}",
                kind.uri_suffix()
            );
        }

        // Unknown context: fails closed rather than defaulting open.
        assert!(
            provider
                .validate_resource_access("ctx-does-not-exist", ResourceKind::Events)
                .is_err(),
            "an unknown context must be denied"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // Resource subscriptions: honest advertisement + delivery.
    // Mirrors the NAPI (`mcp_subscribe_*_napi`) and UniFFI test pairs — PyO3
    // is the reference bridge, so it carries the same pair.
    // -----------------------------------------------------------------------

    /// Negative half: with no event receiver wired — what
    /// `py_mcp_serve` produces when `Supervisor::subscribe_events()` yields
    /// `None` — the server must advertise `resources.subscribe: false` AND
    /// reject `resources/subscribe` with a typed `METHOD_NOT_FOUND`, never
    /// accept-and-drop.
    #[test]
    fn mcp_subscribe_rejected_when_no_event_source_wired_pyo3() {
        let creator = "did:dht:z6MkSubUnwired";
        let bi = __bi();
        let ctx_id = setup_unsupervised_context(&bi, creator, false);
        let uri = format!("scp://{ctx_id}/events");

        let mut server = McpServer::new(pyo3_mcp_provider(&bi, &ctx_id, creator));
        assert!(
            !server.event_source_wired(),
            "a server built by McpServer::new must fail closed on subscriptions"
        );
        assert!(
            !initialize_and_read_subscribe_flag(&mut server),
            "an unwired server must advertise resources.subscribe: false"
        );

        let response = server
            .handle_request(&mcp_request(
                scp_mcp::protocol::METHOD_RESOURCES_SUBSCRIBE,
                serde_json::json!({ "uri": uri }),
            ))
            .expect("resources/subscribe must produce a response");
        let error = response
            .error
            .expect("resources/subscribe must be rejected when no event source is wired");
        assert_eq!(
            error.code,
            scp_mcp::protocol::METHOD_NOT_FOUND,
            "rejection must be a typed method-not-found, got: {error:?}"
        );
        assert!(
            !server.is_subscribed(&uri),
            "a rejected subscribe must not register a subscription"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    /// Positive half: built with a `ContextEvent` receiver from a
    /// detached channel, not the supervisor's, the server advertises the
    /// capability, accepts the subscription, and `notifications_for_event`
    /// (the function the transport pump drives per received event) produces a
    /// real `notifications/resources/updated`. This test does not run the pump
    /// and does not read the receiver `py_mcp_serve` passes;
    /// `supervisor_yields_context_event_receiver_for_mcp_pyo3` and the
    /// `pipeline_wiring` event-source gate cover that wiring.
    #[test]
    fn mcp_subscribe_produces_notifications_when_event_source_wired_pyo3() {
        let creator = "did:dht:z6MkSubWired";
        let bi = __bi();
        let ctx_id = setup_unsupervised_context(&bi, creator, false);
        let uri = format!("scp://{ctx_id}/events");

        // A channel of the supervisor's event type stands in for its receiver;
        // `supervisor_yields_context_event_receiver_for_mcp_pyo3` pins that the
        // supervisor yields one.
        let (_event_tx, receiver) = tokio::sync::broadcast::channel::<(
            String,
            scp_core::context::membership::ContextEvent,
        )>(16);
        // `with_event_source` builds the same server-and-pump pair that
        // `with_optional_event_source(Some(rx))` seals into its opaque bundle;
        // it is public only under `scp-mcp/testing`, which this crate enables
        // from `[dev-dependencies]`.
        let (mut server, _pump) =
            McpServer::with_event_source(pyo3_mcp_provider(&bi, &ctx_id, creator), receiver);

        assert!(
            initialize_and_read_subscribe_flag(&mut server),
            "a wired server must advertise resources.subscribe: true"
        );

        let response = server
            .handle_request(&mcp_request(
                scp_mcp::protocol::METHOD_RESOURCES_SUBSCRIBE,
                serde_json::json!({ "uri": uri }),
            ))
            .expect("resources/subscribe must produce a response");
        assert!(
            response.error.is_none(),
            "subscribe must succeed on a wired server, got: {:?}",
            response.error
        );
        assert!(server.is_subscribed(&uri));

        // `ContextEvent::Expired` invalidates the events/members/tools
        // resources, so the pump must push an update for the subscribed URI.
        let notifications = server.notifications_for_event(
            &ctx_id,
            &scp_core::context::membership::ContextEvent::Expired,
        );
        assert!(
            notifications.iter().any(|n| {
                n.method == scp_mcp::protocol::METHOD_RESOURCES_UPDATED
                    && n.params
                        .as_ref()
                        .and_then(|p| p.get("uri"))
                        .and_then(serde_json::Value::as_str)
                        == Some(uri.as_str())
            }),
            "a subscribed resource must receive notifications/resources/updated, \
             got: {notifications:?}"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // #1549 round-2 regression: FfiBridgeProvider must hold a `Weak`, not
    // an `Arc`, so the MCP server task cannot pin `PyBridgeInstance` alive
    // past the caller's last `Arc` drop.
    //
    // A direct unit assertion: the field type itself is `Weak`. When the
    // only strong reference is dropped, the provider's methods must not
    // panic, and every state read, `agent_role` included, must fail with an
    // error that names the dropped bridge.
    // -----------------------------------------------------------------------

    /// Struct-level proof: the `bi` field is `Weak<PyBridgeInstance>`.
    /// If someone reverts the type to `Arc`, this test stops compiling.
    #[test]
    fn ffi_bridge_provider_field_is_weak_not_arc() {
        let bi = __bi();
        let provider = FfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: "did:dht:z6MkTypeProof".to_owned(),
            context_ids: vec![],
            outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
            agent_ucan_token: None,
            agent_proof_tokens: None,
        };
        // Compile-time assertion: the field is a `Weak`, so upgrade()
        // returns `Option`. If the field regresses to `Arc`, this line
        // fails to type-check.
        let _opt: Option<Arc<crate::runtime::PyBridgeInstance>> = provider.bi.upgrade();
    }

    /// Every provider read fails when the bridge instance has been dropped,
    /// so no read reports an empty result for state it could not see.
    /// `agent_role` fails too, so a dropped bridge never reads as "no role";
    /// only `agent_did`, which is provider-local, still answers.
    #[test]
    fn ffi_bridge_provider_reads_fail_when_bridge_dropped() {
        let provider = {
            // Construct the provider against a short-lived Arc, then drop
            // the Arc so the provider's `Weak` can no longer upgrade.
            let bi = __bi();
            let p = FfiBridgeProvider {
                bi: Arc::downgrade(&bi),
                agent_did: "did:dht:z6MkDropped".to_owned(),
                context_ids: vec!["ctx-dropped".to_owned()],
                outlet_timeout_ms: FFI_OUTLET_TIMEOUT_MS,
                agent_ucan_token: None,
                agent_proof_tokens: None,
            };
            drop(bi);
            p
        };

        // upgrade_bi itself returns Err.
        assert!(
            provider.upgrade_bi().is_err(),
            "upgrade_bi must fail when the bridge has been dropped"
        );

        // agent_role: fails, so a dropped bridge never reads as "no role".
        assert!(provider.agent_role("ctx-dropped").is_err());

        // context_tools / context_members / context_events: each fails, so
        // no read of a dropped bridge reports an empty registry, roster or log.
        assert!(provider.context_tools("ctx-dropped").is_err());
        assert!(provider.context_members("ctx-dropped").is_err());
        assert!(
            provider.context_events("ctx-dropped").is_err(),
            "context_events must fail, not report a zero-event log"
        );

        // validate_capability: returns Err.
        let vc = provider.validate_capability(
            "ctx-dropped",
            "anyoutlet",
            scp_mcp::server::CapabilityCheck::Probe,
        );
        assert!(
            vc.is_err(),
            "validate_capability must reject when bridge is dropped"
        );
        assert!(
            matches!(
                vc.unwrap_err(),
                scp_mcp::server::AccessRefusal::Unreadable(msg) if msg.contains("bridge instance has been dropped")
            ),
            "a dropped bridge is a failed read that names the dropped bridge"
        );

        // validate_resource_access: fails closed for every resource kind —
        // a resource whose role state can no longer be read must be denied,
        // never silently admitted.
        for kind in [
            scp_mcp::server::ResourceKind::Events,
            scp_mcp::server::ResourceKind::Members,
            scp_mcp::server::ResourceKind::Tools,
        ] {
            let vra = provider.validate_resource_access("ctx-dropped", kind);
            assert!(
                vra.is_err(),
                "validate_resource_access must reject {kind:?} when bridge is dropped"
            );
            assert!(
                matches!(
                    vra.unwrap_err(),
                    scp_mcp::server::AccessRefusal::Unreadable(msg) if msg.contains("bridge instance has been dropped")
                ),
                "a dropped bridge is a failed read that names the dropped bridge"
            );
        }

        // active_context_ids: an error. It resolves live participation
        // through the bridge, so a dropped instance cannot answer, and an empty
        // list would report the agent as a participant in nothing.
        assert!(
            provider.active_context_ids().is_err(),
            "a dropped bridge must fail the participation read, not serve an empty list"
        );

        // agent_did is provider-local and does not touch the weak at all.
        assert_eq!(provider.agent_did(), "did:dht:z6MkDropped");
    }

    /// With a supervisor attached, every MCP gate answers from the actor's
    /// role state, not from the bridge's copy. The copy is resynced only by the
    /// bridge's own join, leave and governance calls, so a revocation or
    /// removal the actor applies from an inbound commit leaves the copy still
    /// granting. Here the copy names the agent as a member and the actor holds
    /// no such context — the state after the actor drops a context the agent
    /// was removed from — so every gate must deny.
    #[test]
    fn provider_gates_follow_the_actor_not_the_bridge_copy_pyo3() {
        use scp_mcp::server::ResourceKind;

        crate::init_runtime().ok();
        let agent = "did:dht:z6MkActorBackedAgent";
        let bi = __bi();
        let ctx_id = setup_unsupervised_context(&bi, agent, false);
        let provider = pyo3_mcp_provider(&bi, &ctx_id, agent);

        // No supervisor: the copy is the context's only role state, and a
        // context the bridge holds no copy of is reported as such, not as one
        // a supervisor lacks.
        assert_eq!(provider.active_context_ids().unwrap(), vec![ctx_id.clone()]);
        let denial = provider
            .validate_resource_access("ctx-the-bridge-never-held", ResourceKind::Events)
            .expect_err("a context the bridge holds no copy of must not be readable");
        assert!(
            matches!(
                &denial,
                scp_mcp::server::AccessRefusal::Denied(msg)
                    if msg.contains("not held by this bridge, and no supervisor is attached")
            ),
            "with no supervisor an absent context is a denial naming the bridge, not a \
             failed read, got: {denial}"
        );
        assert!(provider.context_members(&ctx_id).is_ok());
        assert!(
            provider
                .agent_role(&ctx_id)
                .expect("the role state reads")
                .is_some()
        );
        assert!(
            provider
                .validate_resource_access(&ctx_id, ResourceKind::Events)
                .is_ok()
        );

        // The actor now exists and does not hold the context; the copy still
        // names the agent as a member.
        crate::runtime::init_context_manager_for_test(&bi);
        assert!(crate::runtime::supervisor(&bi).is_ok());

        assert!(
            provider.active_context_ids().unwrap().is_empty(),
            "a context the actor does not hold must drop out of the served set"
        );
        for kind in [
            ResourceKind::Events,
            ResourceKind::Members,
            ResourceKind::Tools,
        ] {
            let denial = provider
                .validate_resource_access(&ctx_id, kind)
                .expect_err("the bridge copy must not grant what the actor does not");
            assert!(
                matches!(
                    &denial,
                    scp_mcp::server::AccessRefusal::Denied(msg) if msg.contains("not held by the supervisor")
                ),
                "the {kind:?} refusal must be a denial from the actor query, so \
                 `resources/list` omits the context instead of failing, got: {denial}"
            );
        }
        for check in [
            scp_mcp::server::CapabilityCheck::Probe,
            scp_mcp::server::CapabilityCheck::Invoke,
        ] {
            let denial = provider
                .validate_capability(&ctx_id, "any-outlet", check)
                .expect_err("the bridge copy must not grant a tool the actor does not");
            assert!(
                matches!(
                    &denial,
                    scp_mcp::server::AccessRefusal::Denied(msg) if msg.contains("not held by the supervisor")
                ),
                "the {check:?} refusal must be a denial from the actor query, so \
                 `tools/list` omits the context instead of failing, got: {denial}"
            );
        }
        assert!(provider.context_members(&ctx_id).is_err());
        assert!(
            provider
                .agent_role(&ctx_id)
                .expect("the role state reads")
                .is_none()
        );

        // The production shape: the MCP transport task on the multi-thread
        // runtime, where the query blocks one worker while the actor runs.
        let spawned = pyo3_mcp_provider(&bi, &ctx_id, agent);
        let rt = crate::runtime().unwrap();
        let served = rt
            .block_on(rt.spawn(async move { spawned.active_context_ids().unwrap() }))
            .unwrap();
        assert!(
            served.is_empty(),
            "the transport task must see the actor's role state too"
        );

        // A read the provider cannot make is an error, never "not served": a
        // current-thread runtime cannot run the actor while this call blocks
        // its only thread.
        let current_thread = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        assert!(
            current_thread
                .block_on(async { provider.active_context_ids() })
                .is_err(),
            "a failed participation read must not be reported as an empty served set"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    /// Registers `ctx_id` on the bridge with `copy_creator` as the copy's sole
    /// member, and creates it on the actor with `actor_creator` as its creator,
    /// so the bridge copy and the actor disagree about who is a member.
    fn setup_diverged_context(
        bi: &crate::runtime::PyBridgeInstance,
        ctx_id: &str,
        copy_creator: &str,
        actor_creator: &str,
    ) {
        setup_diverged_context_with_ceiling(
            bi,
            ctx_id,
            copy_creator,
            actor_creator,
            &["messages:read"],
        );
    }

    /// [`setup_diverged_context`] with `ceiling` as the actor context's
    /// ceiling, which its creator holds as admin.
    fn setup_diverged_context_with_ceiling(
        bi: &crate::runtime::PyBridgeInstance,
        ctx_id: &str,
        copy_creator: &str,
        actor_creator: &str,
        ceiling: &[&str],
    ) {
        crate::runtime::register_context(bi, ctx_id, copy_creator, &[]).unwrap();
        hold_on_actor(bi, ctx_id, actor_creator, ceiling);
    }

    /// Creates `ctx_id` on the bridge's supervisor with `creator` as its
    /// creator and `ceiling` as its ceiling, which the creator holds as admin.
    fn hold_on_actor(
        bi: &crate::runtime::PyBridgeInstance,
        ctx_id: &str,
        creator: &str,
        ceiling: &[&str],
    ) {
        crate::init_runtime().ok();
        let supervisor = Arc::clone(crate::runtime::supervisor(bi).unwrap());
        let params = scp_core::context::ContextParams {
            ceiling: ceiling
                .iter()
                .map(|c| scp_core::context::params::Capability::new(c).expect("known capability"))
                .collect(),
            ..scp_core::context::ContextParams::default()
        };
        crate::runtime()
            .unwrap()
            .block_on(supervisor.create_context(
                ctx_id.to_owned(),
                params,
                scp_did::DID(creator.to_owned()),
                None,
            ))
            .unwrap();
    }

    /// Every MCP gate answers from the actor's role state while the actor holds
    /// the context, and the gates write nothing back to the bridge copy.
    ///
    /// `revoked` is the state after an inbound commit removed the agent: the
    /// actor holds the context without the agent while the bridge copy still
    /// names the agent as its member. `granted` is the reverse. A gate that read
    /// the copy, or that let the copy decide, fails one of the two halves; a
    /// gate that wrote the actor's snapshot back into the copy fails the final
    /// assertions.
    #[test]
    fn provider_gates_read_the_actor_role_state_without_writing_the_copy_pyo3() {
        use scp_mcp::server::ResourceKind;

        crate::init_runtime().ok();
        let agent = "did:dht:z6MkLiveRoleAgent";
        let other = "did:dht:z6MkLiveRoleOther";
        let bi = __bi();
        let revoked = crate::types::generate_random_id("test-mcp-revoked");
        let granted = crate::types::generate_random_id("test-mcp-granted");
        setup_diverged_context(&bi, &revoked, agent, other);
        setup_diverged_context(&bi, &granted, other, agent);
        let copy_has_agent = |ctx: &str| {
            crate::runtime::with_context(&bi, ctx, |rt| Ok(rt.role_state.members.contains(agent)))
                .unwrap()
        };
        assert!(copy_has_agent(&revoked) && !copy_has_agent(&granted));

        let provider = pyo3_mcp_provider(&bi, &revoked, agent);
        assert!(provider.active_context_ids().unwrap().is_empty());
        for (kind, requirement) in [
            (ResourceKind::Events, "lacks messages:read"),
            (ResourceKind::Members, "lacks messages:read"),
            (ResourceKind::Tools, "lacks membership"),
        ] {
            let denial = provider
                .validate_resource_access(&revoked, kind)
                .expect_err("the copy's grant must not outlive the actor's revocation");
            assert!(
                matches!(&denial, scp_mcp::server::AccessRefusal::Denied(msg) if msg.contains(requirement)),
                "{kind:?}: {denial}"
            );
        }
        assert!(
            provider
                .agent_role(&revoked)
                .expect("the role state reads")
                .is_none()
        );
        let members = provider.context_members(&revoked).unwrap();
        assert!(members.iter().all(|m| m.did != agent));

        let provider = pyo3_mcp_provider(&bi, &granted, agent);
        assert_eq!(
            provider.active_context_ids().unwrap(),
            vec![granted.clone()]
        );
        for kind in [
            ResourceKind::Events,
            ResourceKind::Members,
            ResourceKind::Tools,
        ] {
            provider
                .validate_resource_access(&granted, kind)
                .unwrap_or_else(|e| panic!("the actor grants {kind:?}: {e}"));
        }
        assert!(
            provider
                .agent_role(&granted)
                .expect("the role state reads")
                .is_some()
        );

        // The served shape: `py_mcp_serve` runs the gates inside a task it
        // spawns on the multi-thread bridge runtime, where each read blocks
        // one worker (`block_in_place`) while the actor answers on another.
        let served = pyo3_mcp_provider(&bi, &granted, agent);
        let served_ctx = granted.clone();
        let rt = crate::runtime().unwrap();
        let (ids, role, access, members) = rt
            .block_on(rt.spawn(async move {
                (
                    served.active_context_ids(),
                    served.agent_role(&served_ctx),
                    served.validate_resource_access(&served_ctx, ResourceKind::Members),
                    served.context_members(&served_ctx),
                )
            }))
            .expect("the transport task must not panic");
        assert_eq!(
            ids.expect("participation reads in the task"),
            vec![granted.clone()]
        );
        assert!(role.expect("the role state reads in the task").is_some());
        access.unwrap_or_else(|e| panic!("the actor grants Members in the task: {e}"));
        assert!(
            members
                .expect("members read in the task")
                .iter()
                .any(|m| m.did == agent)
        );
        let served = pyo3_mcp_provider(&bi, &revoked, agent);
        let served_ctx = revoked.clone();
        let denial = rt
            .block_on(rt.spawn(async move {
                served.validate_resource_access(&served_ctx, ResourceKind::Members)
            }))
            .expect("the transport task must not panic")
            .expect_err("the actor's revocation holds in the task");
        assert!(
            matches!(&denial, scp_mcp::server::AccessRefusal::Denied(msg) if msg.contains("lacks messages:read")),
            "{denial}"
        );

        // No write-back: each copy still holds what the bridge wrote into it.
        assert!(copy_has_agent(&revoked) && !copy_has_agent(&granted));

        crate::runtime::remove_context(&bi, &revoked);
        crate::runtime::remove_context(&bi, &granted);
    }

    /// `py_mcp_serve` refuses a current-thread bridge runtime only while a
    /// supervisor is attached, the one case where every gate would fail.
    #[test]
    fn serve_refuses_a_current_thread_runtime_only_with_a_supervisor() {
        use tokio::runtime::RuntimeFlavor;
        let error = check_serve_runtime(RuntimeFlavor::CurrentThread, true)
            .expect_err("a current-thread runtime cannot run the actor a gate waits on")
            .to_string();
        assert!(error.contains("current-thread"), "{error}");
        check_serve_runtime(RuntimeFlavor::MultiThread, true)
            .expect("a multi-thread runtime serves with a supervisor");
        check_serve_runtime(RuntimeFlavor::CurrentThread, false)
            .expect("without a supervisor the gates read the bridge copy");
        check_serve_runtime(RuntimeFlavor::MultiThread, false)
            .expect("a multi-thread runtime serves without a supervisor");
    }

    /// A context the actor holds while the bridge holds no copy of it has no
    /// outlet registered through this bridge: `context_tools` reports an empty
    /// registry, and `validate_capability`, for an agent whose role grants
    /// `outlet:call:*`, passes the role-state check and denies the outlet as
    /// unregistered, instead of failing the read and, through it, `tools/list`
    /// for every served context.
    #[test]
    fn actor_held_context_without_a_bridge_copy_has_no_outlets_pyo3() {
        crate::init_runtime().ok();
        let agent = "did:dht:z6MkNoCopyAgent";
        let bi = __bi();
        let ctx_id = crate::types::generate_random_id("test-mcp-no-copy");
        setup_diverged_context_with_ceiling(
            &bi,
            &ctx_id,
            agent,
            agent,
            &["messages:read", "outlet:call:*"],
        );
        crate::runtime::remove_context(&bi, &ctx_id);
        assert!(crate::runtime::with_context(&bi, &ctx_id, |_| Ok(())).is_err());

        let mut provider = pyo3_mcp_provider(&bi, &ctx_id, agent);
        assert_eq!(provider.active_context_ids().unwrap(), vec![ctx_id.clone()]);
        assert!(provider.context_tools(&ctx_id).unwrap().is_empty());

        provider.agent_ucan_token = Some("not-a-ucan".to_owned());
        let refusal = provider
            .validate_capability(
                &ctx_id,
                "calculator",
                scp_mcp::server::CapabilityCheck::Probe,
            )
            .unwrap_err();
        assert!(
            matches!(&refusal, scp_mcp::server::AccessRefusal::Denied(msg) if msg.contains("not registered")),
            "a missing bridge copy is no registration, not a failed read: {refusal}"
        );

        // A context held by neither is still an error.
        assert!(provider.context_tools("ctx-held-by-no-one").is_err());
    }

    /// With a supervisor attached, `scp://{ctx}/events` reports the actor's
    /// event log, whose events drive the `resources/updated` notices, at the
    /// top level, and reports the bridge's local tree, where `invoke_outlet`
    /// appends each MCP `tools/call` record, under `bridge_event_log`.
    #[test]
    fn events_resource_reports_the_actor_log_and_the_bridge_log_pyo3() {
        crate::init_runtime().ok();
        let agent = "did:dht:z6MkEventsResourceAgent";
        let bi = __bi();
        let ctx_id = crate::types::generate_random_id("test-mcp-events");
        setup_diverged_context(&bi, &ctx_id, agent, agent);
        // Make the bridge's local tree diverge from the actor's log.
        crate::runtime::with_context(&bi, &ctx_id, |rt| {
            rt.event_log.push_leaf_raw([0x5A; 32]);
            rt.event_log.push_leaf_raw([0xA5; 32]);
            Ok(())
        })
        .unwrap();

        let supervisor = crate::runtime::supervisor(&bi).unwrap();
        let ctx_bytes = scp_core::context::state::context_id_to_bytes(&ctx_id);
        let (count, root) = supervisor.event_log_summary(&ctx_bytes).unwrap();
        // The summary matches a tree rebuilt from the actor's entries.
        let entries = supervisor
            .event_log_entries(&ctx_bytes)
            .unwrap()
            .unwrap_or_default();
        let mut rebuilt = scp_event_log::EventLog::new(String::new());
        for entry in &entries {
            rebuilt.push_leaf_raw(scp_event_log::tree::leaf_hash(entry).unwrap());
        }
        assert_eq!(
            (count, root),
            (entries.len(), scp_event_log::tree::root(&rebuilt))
        );
        let resource = pyo3_mcp_provider(&bi, &ctx_id, agent)
            .context_events(&ctx_id)
            .unwrap();
        let (copy_count, copy_root) = crate::runtime::with_context(&bi, &ctx_id, |rt| {
            Ok((
                rt.event_log.leaves().len(),
                scp_event_log::tree::root(&rt.event_log),
            ))
        })
        .unwrap();
        assert_ne!(root, copy_root, "the two logs must differ for this test");
        assert_eq!(
            resource,
            serde_json::json!({
                "event_count": count,
                "merkle_root": crate::types::encode_hex(&root),
                "bridge_event_log": {
                    "event_count": copy_count,
                    "merkle_root": crate::types::encode_hex(&copy_root),
                },
            })
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    /// Wiring guard, mirroring the NAPI and `UniFFI` tests:
    /// `py_mcp_serve` sources its receiver from `Supervisor::subscribe_events()`,
    /// and `crate::runtime::build_supervisor` enables the broadcast channel, so
    /// that call must yield `Some`, and `mcp_server_bundle`, the function
    /// `py_mcp_serve` builds its server with, must return the wired bundle.
    /// Were either to regress, every `PyO3` MCP server would silently advertise
    /// `resources.subscribe: false`.
    #[test]
    fn supervisor_yields_context_event_receiver_for_mcp_pyo3() {
        crate::init_runtime().ok();
        let bi = __bi();
        crate::runtime::init_context_manager_for_test(&bi);

        let supervisor =
            crate::runtime::supervisor(&bi).expect("supervisor must be attached after init");
        assert!(
            supervisor.subscribe_events().is_some(),
            "the PyO3 supervisor must expose a context event receiver so MCP \
             resource subscriptions are wired rather than advertised-and-dropped"
        );
        let bundle = mcp_server_bundle(
            &bi,
            pyo3_mcp_provider(&bi, "ctx-wired", "did:dht:z6MkWiredBundle"),
        );
        assert_eq!(format!("{bundle:?}"), "McpServerForTransport::Wired");
    }

    /// A server created while the instance is suspended is unwired even with
    /// a supervisor attached, as the `mcp_server_bundle` doc states, because
    /// `crate::runtime::supervisor` refuses a suspended instance. The same
    /// instance, resumed, builds the wired bundle again.
    #[test]
    fn suspended_instance_builds_the_unwired_bundle_pyo3() {
        use scp_ffi_common::bridge_instance::BridgeInstanceCore as _;
        crate::init_runtime().ok();
        let bi = __bi();
        crate::runtime::init_context_manager_for_test(&bi);

        bi.core.suspend().expect("suspend");
        assert!(
            bi.core.try_supervisor().is_some(),
            "precondition: suspension keeps the supervisor attached"
        );
        assert_eq!(
            format!(
                "{:?}",
                mcp_server_bundle(
                    &bi,
                    pyo3_mcp_provider(&bi, "ctx-suspended", "did:dht:z6MkSuspendedBundle"),
                )
            ),
            "McpServerForTransport::Unwired"
        );

        crate::runtime()
            .expect("runtime")
            .block_on(bi.resume())
            .expect("resume");
        assert_eq!(
            format!(
                "{:?}",
                mcp_server_bundle(
                    &bi,
                    pyo3_mcp_provider(&bi, "ctx-suspended", "did:dht:z6MkSuspendedBundle"),
                )
            ),
            "McpServerForTransport::Wired"
        );
    }

    /// A missing `Supervisor` removes only the pump-backed capabilities
    /// (`resources.subscribe`, `resources.listChanged`, `tools.listChanged`)
    /// — it must not fail MCP serving outright. Drives the production entry point:
    /// were `py_mcp_serve` to propagate the missing-supervisor error
    /// (`supervisor(bi)?`), the serve call would return `Err`. Then checks that
    /// `mcp_server_bundle`, the function `py_mcp_serve` builds its server with,
    /// returns the unwired bundle, whose server advertises
    /// `resources.subscribe: false`, and reads `resources/list` through the
    /// provider type that entry point builds over the same instance, so a
    /// provider that served nothing without a supervisor fails here.
    #[test]
    fn missing_supervisor_degrades_subscriptions_not_the_whole_server_pyo3() {
        crate::init_runtime().ok();
        let agent = "did:dht:z6MkNoSupervisorAgent";
        let bi = __bi();
        let ctx_id = setup_unsupervised_context(&bi, agent, false);
        assert!(
            crate::runtime::supervisor(&bi).is_err(),
            "precondition: this instance has no supervisor attached"
        );

        let scp = crate::scp::PyScp {
            inner: Arc::clone(&bi),
        };
        let handle = scp
            .py_mcp_serve(agent, vec![ctx_id.clone()], "sse", None)
            .expect("a missing supervisor must degrade subscriptions, not fail MCP serving");
        scp.py_mcp_server_stop(&handle)
            .expect("the server created without a supervisor must stop cleanly");

        let bundle = mcp_server_bundle(&bi, pyo3_mcp_provider(&bi, &ctx_id, agent));
        assert_eq!(
            format!("{bundle:?}"),
            "McpServerForTransport::Unwired",
            "without a supervisor the served server must not advertise resources.subscribe"
        );
        // Initialize this server only so it answers `resources/list`. Its flag
        // says nothing about the served server: `McpServer::new` never
        // advertises subscriptions.
        let mut server = McpServer::new(pyo3_mcp_provider(&bi, &ctx_id, agent));
        let _ = initialize_and_read_subscribe_flag(&mut server);
        let listed = server
            .handle_request(&mcp_request("resources/list", serde_json::json!({})))
            .expect("resources/list must produce a response")
            .result
            .expect("resources/list must succeed without a supervisor");
        let uris: Vec<&str> = listed["resources"]
            .as_array()
            .expect("resources must be an array")
            .iter()
            .filter_map(|r| r["uri"].as_str())
            .collect();
        let expected: Vec<String> = ["events", "members", "tools"]
            .iter()
            .map(|kind| format!("scp://{ctx_id}/{kind}"))
            .collect();
        assert_eq!(
            uris, expected,
            "a missing supervisor must leave resources/list serving the context"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }
}
