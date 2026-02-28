//! `PyO3` bridge functions for MCP (Model Context Protocol) server and client.
//!
//! Exposes SCP MCP operations to Python:
//!
//! - [`py_mcp_serve`] -- Start an MCP server exposing SCP context tools.
//! - [`py_mcp_server_stop`] -- Stop a running MCP server.
//! - [`py_mcp_server_wait`] -- Block until the MCP server exits.
//! - [`py_mcp_client_connect_stdio`] -- Connect to an external MCP server via
//!   stdio.
//! - [`py_mcp_client_connect_sse`] -- Connect to an external MCP server via
//!   SSE.
//! - [`py_mcp_client_disconnect`] -- Disconnect from an external MCP server.
//! - [`py_mcp_client_list_tools`] -- List tools from an external MCP server.
//! - [`py_mcp_client_invoke`] -- Invoke an external MCP tool with provenance.
//! - [`py_mcp_load_contexts`] -- Load active contexts for a DID from a relay.
//!
//! The MCP bridge uses opaque string handles to track server and client
//! instances. Handles are stored in a global registry (similar to the
//! context runtime registry pattern).
//!
//! See ADR-015 in `.docs/adrs/phase-3.md` for the full MCP adapter design.

use std::sync::OnceLock;

use dashmap::DashMap;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::error::ScpPyError;
use crate::types::{json_to_py_dict, py_dict_to_json};

// ---------------------------------------------------------------------------
// MCP handle registries
// ---------------------------------------------------------------------------

/// State for an active MCP server instance.
#[allow(dead_code)] // Fields are stored for future transport integration.
struct McpServerState {
    /// The identity DID running this server.
    identity_did: String,
    /// The context IDs being served.
    context_ids: Vec<String>,
    /// The transport mode (stdio or sse).
    transport: String,
    /// Whether the server has been stopped.
    stopped: bool,
}

/// State for an active MCP client connection.
#[allow(dead_code)] // Fields are stored for future transport integration.
struct McpClientState {
    /// The transport mode (stdio or sse).
    transport: String,
    /// For stdio, the command used to spawn the subprocess.
    command: Option<Vec<String>>,
    /// For sse, the URL of the SSE endpoint.
    url: Option<String>,
    /// Whether the client has been disconnected.
    disconnected: bool,
    /// Cached tool definitions from list_tools.
    cached_tools: Vec<serde_json::Value>,
}

/// Global registry of MCP server instances.
static SERVER_REGISTRY: OnceLock<DashMap<String, McpServerState>> = OnceLock::new();

/// Global registry of MCP client instances.
static CLIENT_REGISTRY: OnceLock<DashMap<String, McpClientState>> = OnceLock::new();

fn server_registry() -> &'static DashMap<String, McpServerState> {
    SERVER_REGISTRY.get_or_init(DashMap::new)
}

fn client_registry() -> &'static DashMap<String, McpClientState> {
    CLIENT_REGISTRY.get_or_init(DashMap::new)
}

/// Generates a unique, unpredictable handle ID.
fn generate_handle_id(prefix: &str) -> String {
    use rand::Rng;
    let mut random_bytes = [0u8; 16];
    rand::thread_rng().fill(&mut random_bytes);
    let hex = crate::types::encode_hex(&random_bytes);
    format!("{prefix}-{hex}")
}

// ---------------------------------------------------------------------------
// MCP server bridge functions
// ---------------------------------------------------------------------------

/// Starts an MCP server that exposes SCP context tools.
///
/// Creates an MCP server that dynamically exposes tools from the agent's
/// active SCP contexts, namespaced by context ID. Tools are capability-
/// filtered: only tools the agent's role permits are listed.
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
/// Raises `TransportError` if the server fails to start.
///
/// See ADR-015: MCP server with context namespace mapping.
#[pyfunction]
#[pyo3(name = "py_mcp_serve")]
pub fn py_mcp_serve(
    identity_did: &str,
    context_ids: Vec<String>,
    transport: &str,
) -> PyResult<String> {
    // Validate transport mode.
    if transport != "stdio" && transport != "sse" {
        return Err(ScpPyError::ValidationError(format!(
            "transport must be 'stdio' or 'sse', got '{transport}'"
        ))
        .into());
    }

    // Validate that all context IDs are registered in the runtime.
    for ctx_id in &context_ids {
        crate::runtime::with_context(ctx_id, |_rt| Ok(())).map_err(|e| {
            ScpPyError::TransportError(format!("cannot serve context '{ctx_id}': {e}"))
        })?;
    }

    // Create the server state and register it.
    let handle = generate_handle_id("mcp-server");
    let state = McpServerState {
        identity_did: identity_did.to_owned(),
        context_ids,
        transport: transport.to_owned(),
        stopped: false,
    };

    server_registry().insert(handle.clone(), state);

    Ok(handle)
}

/// Stops a running MCP server.
///
/// # Arguments
///
/// * `handle` -- The server handle returned by `py_mcp_serve`.
///
/// # Errors
///
/// Raises `TransportError` if the server is not found or already stopped.
#[pyfunction]
#[pyo3(name = "py_mcp_server_stop")]
pub fn py_mcp_server_stop(handle: &str) -> PyResult<()> {
    let mut entry = server_registry().get_mut(handle).ok_or_else(|| {
        ScpPyError::TransportError(format!("MCP server handle '{handle}' not found"))
    })?;

    if entry.stopped {
        return Err(ScpPyError::TransportError(format!(
            "MCP server '{handle}' is already stopped"
        ))
        .into());
    }

    entry.stopped = true;
    Ok(())
}

/// Blocks until the MCP server exits.
///
/// For stdio transport, waits until stdin is closed (EOF). For SSE
/// transport, waits until a termination signal is received.
///
/// In the bridge layer, this returns immediately since the MCP server is
/// not yet connected to real transport I/O. The full implementation will
/// block on the server's event loop.
///
/// # Arguments
///
/// * `handle` -- The server handle returned by `py_mcp_serve`.
///
/// # Errors
///
/// Raises `TransportError` if the server handle is not found.
#[pyfunction]
#[pyo3(name = "py_mcp_server_wait")]
pub fn py_mcp_server_wait(handle: &str) -> PyResult<()> {
    let entry = server_registry().get(handle).ok_or_else(|| {
        ScpPyError::TransportError(format!("MCP server handle '{handle}' not found"))
    })?;

    // In the full implementation, this would block on the server's event loop.
    // For now, if the server is stopped, return immediately.
    // See #106 for the story to complete this with real transport blocking.
    if entry.stopped {
        return Ok(());
    }

    // Server is running -- in the bridge layer, return immediately.
    // The full implementation will block here until the server exits.
    Ok(())
}

// ---------------------------------------------------------------------------
// MCP client bridge functions
// ---------------------------------------------------------------------------

/// Connects to an external MCP server via stdio transport.
///
/// Spawns the given command as a subprocess and communicates via
/// line-delimited JSON over stdin/stdout.
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
/// Raises `TransportError` if the connection fails.
#[pyfunction]
#[pyo3(name = "py_mcp_client_connect_stdio")]
pub fn py_mcp_client_connect_stdio(command: Vec<String>) -> PyResult<String> {
    if command.is_empty() {
        return Err(ScpPyError::ValidationError(
            "command must be a non-empty list".to_owned(),
        )
        .into());
    }

    let handle = generate_handle_id("mcp-client");
    let state = McpClientState {
        transport: "stdio".to_owned(),
        command: Some(command),
        url: None,
        disconnected: false,
        cached_tools: Vec::new(),
    };

    client_registry().insert(handle.clone(), state);

    Ok(handle)
}

/// Connects to an external MCP server via SSE transport.
///
/// Connects to the given URL using HTTP with Server-Sent Events for
/// server-to-client messages and POST for client-to-server messages.
///
/// # Arguments
///
/// * `url` -- The URL of the SSE endpoint.
///
/// # Returns
///
/// An opaque client handle string.
///
/// # Errors
///
/// Raises `TransportError` if the connection fails.
#[pyfunction]
#[pyo3(name = "py_mcp_client_connect_sse")]
pub fn py_mcp_client_connect_sse(url: &str) -> PyResult<String> {
    if url.is_empty() {
        return Err(ScpPyError::ValidationError(
            "url must be a non-empty string".to_owned(),
        )
        .into());
    }

    let handle = generate_handle_id("mcp-client");
    let state = McpClientState {
        transport: "sse".to_owned(),
        command: None,
        url: Some(url.to_owned()),
        disconnected: false,
        cached_tools: Vec::new(),
    };

    client_registry().insert(handle.clone(), state);

    Ok(handle)
}

/// Disconnects from an external MCP server.
///
/// # Arguments
///
/// * `handle` -- The client handle returned by `py_mcp_client_connect_*`.
///
/// # Errors
///
/// Raises `TransportError` if the client is not found or already
/// disconnected.
#[pyfunction]
#[pyo3(name = "py_mcp_client_disconnect")]
pub fn py_mcp_client_disconnect(handle: &str) -> PyResult<()> {
    let mut entry = client_registry().get_mut(handle).ok_or_else(|| {
        ScpPyError::TransportError(format!("MCP client handle '{handle}' not found"))
    })?;

    if entry.disconnected {
        return Err(ScpPyError::TransportError(format!(
            "MCP client '{handle}' is already disconnected"
        ))
        .into());
    }

    entry.disconnected = true;
    Ok(())
}

/// Lists available tools from an external MCP server.
///
/// Sends a `tools/list` request to the connected MCP server and returns
/// the tool definitions as a list of Python dicts.
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
/// Raises `TransportError` if the client is not connected or the request
/// fails.
#[pyfunction]
#[pyo3(name = "py_mcp_client_list_tools")]
pub fn py_mcp_client_list_tools(py: Python<'_>, handle: &str) -> PyResult<PyObject> {
    let entry = client_registry().get(handle).ok_or_else(|| {
        ScpPyError::TransportError(format!("MCP client handle '{handle}' not found"))
    })?;

    if entry.disconnected {
        return Err(ScpPyError::TransportError(format!(
            "MCP client '{handle}' is disconnected"
        ))
        .into());
    }

    // In the bridge layer without a real transport connection, return the
    // cached tools (initially empty). The full implementation will send a
    // tools/list JSON-RPC request via the transport.
    let tools_json = serde_json::Value::Array(entry.cached_tools.clone());
    json_to_py_dict(py, &tools_json)
}

/// Invokes an external MCP tool with SCP provenance wrapping.
///
/// Calls the external MCP tool and wraps the result with provenance
/// metadata recording the source tool, invoking agent, context, and
/// timestamp.
///
/// # Arguments
///
/// * `handle` -- The client handle returned by `py_mcp_client_connect_*`.
/// * `tool_name` -- The name of the external tool to invoke.
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
/// Raises `TransportError` if the client is not connected or the
/// invocation fails.
#[pyfunction]
#[pyo3(name = "py_mcp_client_invoke")]
pub fn py_mcp_client_invoke(
    py: Python<'_>,
    handle: &str,
    tool_name: &str,
    input: &Bound<'_, PyDict>,
    context_id: &str,
    identity_did: &str,
) -> PyResult<PyObject> {
    let entry = client_registry().get(handle).ok_or_else(|| {
        ScpPyError::TransportError(format!("MCP client handle '{handle}' not found"))
    })?;

    if entry.disconnected {
        return Err(ScpPyError::TransportError(format!(
            "MCP client '{handle}' is disconnected"
        ))
        .into());
    }

    // Drop the DashMap guard before calling py_dict_to_json (which may
    // acquire the GIL for Python object access).
    drop(entry);

    // Convert input to JSON for provenance computation.
    let _input_json = py_dict_to_json(input)?;

    // Build provenance metadata using scp-mcp's ExternalToolProvenance.
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let provenance = scp_mcp::client::ExternalToolProvenance::new(
        tool_name,
        identity_did,
        context_id,
        timestamp,
    );

    // In the bridge layer, return a result with empty content and the
    // provenance metadata. The full implementation will send a tools/call
    // JSON-RPC request via the transport and return the actual result.
    let result_json = serde_json::json!({
        "content": [],
        "is_error": false,
        "provenance": {
            "source": provenance.source,
            "invoked_by": provenance.invoked_by,
            "context": provenance.context,
            "timestamp": provenance.timestamp,
        },
    });

    json_to_py_dict(py, &result_json)
}

/// Loads active contexts for a DID from a relay.
///
/// Discovers the contexts that the given identity is a member of by
/// querying the relay. Used during CLI startup to populate the MCP
/// server with the agent's active contexts.
///
/// # Arguments
///
/// * `identity_did` -- The DID to look up contexts for.
/// * `relay_url` -- The relay URL to query.
///
/// # Returns
///
/// A list of context handle objects (currently empty in the bridge layer).
///
/// # Errors
///
/// Raises `TransportError` if the relay query fails.
#[pyfunction]
#[pyo3(name = "py_mcp_load_contexts")]
pub fn py_mcp_load_contexts(
    _identity_did: &str,
    _relay_url: &str,
) -> PyResult<Vec<PyObject>> {
    // In the bridge layer, context discovery requires a live relay connection
    // which is wired via the transport layer. Return an empty list; the full
    // implementation will query the relay for the identity's active contexts.
    Ok(Vec::new())
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
pub fn register_mcp(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_mcp_serve, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_server_stop, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_server_wait, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_client_connect_stdio, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_client_connect_sse, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_client_disconnect, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_client_list_tools, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_client_invoke, m)?)?;
    m.add_function(wrap_pyfunction!(py_mcp_load_contexts, m)?)?;
    Ok(())
}
