//! Stdio command allowlist for MCP subprocess transport.
//!
//! Per MCP Security Best Practices, stdio transport must validate commands
//! before execution. This module provides a configurable allowlist that
//! restricts subprocess spawning to known MCP server runtimes.
//!
//! The allowlist is a process-global singleton. All FFI layers (`PyO3`, `UniFFI`,
//! wasm-bindgen) delegate to these functions.
//!
//! # Default allowed binaries
//!
//! Package runners: `uvx`, `npx`, `bunx`, `pipx`
//! Interpreters: `python`, `python3`, `node`, `bun`, `deno`
//! Containers: `docker`, `podman`
//! SCP CLI: `scp-mcp`
//!
//! # Usage
//!
//! ```
//! use scp_mcp::allowlist;
//!
//! // Validate a command before spawning
//! let basename = allowlist::validate_command("node").unwrap();
//!
//! // Add custom binaries (accepts &str or String slices)
//! allowlist::configure(&["my-server"]).unwrap();
//!
//! // Query current state
//! let state = allowlist::get_state().unwrap();
//! assert!(state.allowed.contains(&"my-server".to_owned()));
//!
//! // Reset to defaults
//! allowlist::reset().unwrap();
//! ```

use std::collections::BTreeSet;
use std::sync::{Mutex, MutexGuard, OnceLock};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from allowlist operations.
#[derive(Debug, thiserror::Error)]
pub enum AllowlistError {
    /// Entry is empty.
    #[error("allowlist entry cannot be empty")]
    EmptyEntry,

    /// Entry contains path separators (must be a bare binary name).
    #[error("allowlist entry must be a bare binary name, not a path: '{0}'")]
    PathInEntry(String),

    /// Entry contains a NUL byte.
    #[error("allowlist entry contains NUL byte: '{0}'")]
    NulInEntry(String),

    /// Entry contains ASCII control characters.
    #[error("allowlist entry contains control characters: '{0}'")]
    ControlCharInEntry(String),

    /// Command contains path separators (must be a bare binary name).
    #[error(
        "command must be a bare binary name, not a path: '{0}'. \
         The OS will resolve it via PATH."
    )]
    PathInCommand(String),

    /// Command could not be parsed (e.g. empty, `.`, `..`).
    #[error("invalid command: '{0}'")]
    InvalidCommand(String),

    /// Command basename is not in the allowlist.
    #[error(
        "command '{command}' is not in the MCP stdio allowlist. \
         Allowed: {allowed:?}. Configure the allowlist before connecting."
    )]
    NotAllowed {
        /// The rejected command basename.
        command: String,
        /// Currently allowed binaries (sorted).
        allowed: Vec<String>,
    },

    /// The internal mutex is poisoned (a previous holder panicked).
    #[error("stdio allowlist lock poisoned")]
    LockPoisoned,
}

// ---------------------------------------------------------------------------
// State types
// ---------------------------------------------------------------------------

/// Snapshot of the current allowlist state.
#[derive(Debug, Clone)]
pub struct AllowlistState {
    /// Sorted list of allowed binary basenames.
    pub allowed: Vec<String>,
    /// Whether the allowlist is bypassed entirely.
    pub unrestricted: bool,
}

/// Well-known MCP server launchers allowed by default.
pub const DEFAULT_ALLOWLIST: &[&str] = &[
    // Package runners
    "uvx",  // Python (uv tool runner)
    "npx",  // Node.js (npm package runner)
    "bunx", // Bun (JavaScript runtime)
    "pipx", // Python (pip package runner)
    // Direct interpreters
    "python", "python3", "node", "bun", "deno", // Containerized execution
    "docker", "podman", // SCP's own CLI
    "scp-mcp",
];

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------

/// Runtime-configurable allowlist for stdio subprocess commands.
///
/// Uses [`BTreeSet`] so entries are always sorted — no per-query sorting
/// needed for error messages or state snapshots.
struct StdioAllowlist {
    /// Allowed binary basenames (sorted by `BTreeSet` invariant).
    allowed: BTreeSet<String>,
    /// If true, bypass the allowlist entirely.
    unrestricted: bool,
}

impl StdioAllowlist {
    fn default_list() -> Self {
        Self {
            allowed: DEFAULT_ALLOWLIST.iter().map(|s| (*s).to_owned()).collect(),
            unrestricted: false,
        }
    }
}

/// Global singleton for the stdio allowlist.
fn instance() -> &'static Mutex<StdioAllowlist> {
    static INSTANCE: OnceLock<Mutex<StdioAllowlist>> = OnceLock::new();
    INSTANCE.get_or_init(|| Mutex::new(StdioAllowlist::default_list()))
}

/// Acquire the allowlist lock, mapping poisoned-lock to [`AllowlistError`].
fn lock() -> Result<MutexGuard<'static, StdioAllowlist>, AllowlistError> {
    instance().lock().map_err(|_| AllowlistError::LockPoisoned)
}

// ---------------------------------------------------------------------------
// Entry validation (internal)
// ---------------------------------------------------------------------------

/// Validates a binary name for insertion into the allowlist.
///
/// Rejects names containing path separators, NUL bytes, ASCII control
/// characters (0x00-0x1F, 0x7F), or empty strings.
fn validate_entry(name: &str) -> Result<(), AllowlistError> {
    if name.is_empty() {
        return Err(AllowlistError::EmptyEntry);
    }
    if name.contains('/') || name.contains('\\') {
        return Err(AllowlistError::PathInEntry(name.to_owned()));
    }
    // NUL is a control character but gets its own variant for clarity.
    if name.contains('\0') {
        return Err(AllowlistError::NulInEntry(name.to_owned()));
    }
    if name.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err(AllowlistError::ControlCharInEntry(name.to_owned()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Command validation
// ---------------------------------------------------------------------------

/// Validates a command against the stdio allowlist.
///
/// Only bare binary names are accepted (no paths). The OS resolves the
/// binary via `PATH`.
///
/// Returns `Ok(basename)` on success — **always use the returned value
/// for `Command::new`**, not the original input, as a defense-in-depth
/// measure against path bypass attacks.
///
/// # Errors
///
/// Returns [`AllowlistError`] if:
/// - The command is an invalid path (e.g. empty, `.`, `..`)
/// - The command contains path separators
/// - The command basename is not in the allowlist (and unrestricted is false)
pub fn validate_command(cmd: &str) -> Result<String, AllowlistError> {
    // Use Path::file_name() to reject ".", "..", empty, and trailing separators.
    let basename = std::path::Path::new(cmd)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| AllowlistError::InvalidCommand(cmd.to_owned()))?
        .to_owned();

    // Reject commands with path separators — force PATH resolution.
    // Allowing absolute/relative paths defeats the allowlist because
    // /tmp/evil/node has basename "node" but may not be the real binary.
    // `cmd != basename` catches forward-slash paths (Path::file_name strips them).
    // Explicit backslash check needed because backslash is a valid filename char
    // on Unix, so Path::file_name() won't strip it — "..\bin\sh" has basename
    // "..\bin\sh" on Unix.
    if cmd != basename || cmd.contains('\\') {
        return Err(AllowlistError::PathInCommand(cmd.to_owned()));
    }

    let guard = lock()?;

    if guard.unrestricted {
        return Ok(basename);
    }

    if guard.allowed.contains(&basename) {
        Ok(basename)
    } else {
        // BTreeSet is always sorted — no sort needed.
        Err(AllowlistError::NotAllowed {
            command: basename,
            allowed: guard.allowed.iter().cloned().collect(),
        })
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Add binary names to the allowlist.
///
/// Entries are validated before insertion (rejects paths, NUL, empty).
/// This is additive — previously added binaries are retained.
/// All entries are validated atomically before any are inserted.
///
/// # Errors
///
/// Returns [`AllowlistError`] if any entry fails validation or the lock
/// is poisoned.
pub fn configure(additional_binaries: &[impl AsRef<str>]) -> Result<(), AllowlistError> {
    // Validate all entries before acquiring the lock.
    for name in additional_binaries {
        validate_entry(name.as_ref())?;
    }

    {
        let mut guard = lock()?;
        for name in additional_binaries {
            guard.allowed.insert(name.as_ref().to_owned());
        }
    }

    Ok(())
}

/// Disable the allowlist entirely (unrestricted mode).
///
/// After calling this, **any** binary name passes [`validate_command`].
/// Only use when the command source is fully trusted.
///
/// # Errors
///
/// Returns [`AllowlistError::LockPoisoned`] if the lock is poisoned.
pub fn disable_enforcement() -> Result<(), AllowlistError> {
    lock()?.unrestricted = true;
    Ok(())
}

/// Reset the allowlist to its default state.
///
/// Restores the default binaries, removes any additions, and re-enables
/// enforcement (clears unrestricted mode).
///
/// # Errors
///
/// Returns [`AllowlistError::LockPoisoned`] if the lock is poisoned.
pub fn reset() -> Result<(), AllowlistError> {
    *lock()? = StdioAllowlist::default_list();
    Ok(())
}

/// Return a snapshot of the current allowlist state.
///
/// # Errors
///
/// Returns [`AllowlistError::LockPoisoned`] if the lock is poisoned.
pub fn get_state() -> Result<AllowlistState, AllowlistError> {
    let guard = lock()?;

    // BTreeSet is always sorted — collect directly.
    Ok(AllowlistState {
        allowed: guard.allowed.iter().cloned().collect(),
        unrestricted: guard.unrestricted,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // The allowlist is a process-global singleton. Tests that mutate it
    // (configure, disable, reset) must not run in parallel. This mutex
    // serializes those tests without adding a crate dependency.
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    fn lock_allowlist() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset().unwrap();
        guard
    }

    #[test]
    fn default_allowlist_contains_expected_binaries() {
        assert!(DEFAULT_ALLOWLIST.contains(&"uvx"));
        assert!(DEFAULT_ALLOWLIST.contains(&"npx"));
        assert!(DEFAULT_ALLOWLIST.contains(&"node"));
        assert!(DEFAULT_ALLOWLIST.contains(&"python3"));
        assert!(DEFAULT_ALLOWLIST.contains(&"docker"));
        assert!(DEFAULT_ALLOWLIST.contains(&"scp-mcp"));
    }

    #[test]
    fn default_allowlist_excludes_shells() {
        for shell in &["sh", "bash", "zsh", "fish", "cmd", "powershell"] {
            assert!(
                !DEFAULT_ALLOWLIST.contains(shell),
                "shell '{shell}' should NOT be in the default allowlist"
            );
        }
    }

    #[test]
    fn validate_command_allows_default_binaries() {
        let _guard = lock_allowlist();
        for bin in DEFAULT_ALLOWLIST {
            assert!(
                validate_command(bin).is_ok(),
                "default binary '{bin}' should be allowed"
            );
        }
    }

    #[test]
    fn validate_command_rejects_absolute_path_to_allowed_binary() {
        let _guard = lock_allowlist();
        let result = validate_command("/usr/bin/node");
        assert!(result.is_err());
        assert!(
            matches!(result, Err(AllowlistError::PathInCommand(_))),
            "should be PathInCommand variant"
        );
    }

    #[test]
    fn validate_command_rejects_relative_path() {
        let _guard = lock_allowlist();
        let result = validate_command("../../bin/sh");
        assert!(result.is_err());
        assert!(
            matches!(result, Err(AllowlistError::PathInCommand(_))),
            "should be PathInCommand variant"
        );
    }

    #[test]
    fn validate_command_rejects_relative_path_to_allowed_binary() {
        let _guard = lock_allowlist();
        let result = validate_command("./node");
        assert!(matches!(result, Err(AllowlistError::PathInCommand(_))));
    }

    #[test]
    fn validate_command_rejects_backslash_path() {
        let _guard = lock_allowlist();
        // On Unix, backslash is a valid filename char, so Path::file_name()
        // would not catch this. The explicit backslash check does.
        let result = validate_command("..\\..\\bin\\sh");
        assert!(matches!(result, Err(AllowlistError::PathInCommand(_))));
    }

    #[test]
    fn validate_command_rejects_unknown_binary() {
        let _guard = lock_allowlist();
        match validate_command("curl") {
            Err(AllowlistError::NotAllowed { command, allowed }) => {
                assert_eq!(command, "curl");
                assert!(!allowed.is_empty());
            }
            other => panic!("expected NotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn validate_command_rejects_shells() {
        let _guard = lock_allowlist();
        for shell in &["sh", "bash", "zsh", "fish", "cmd", "powershell"] {
            assert!(
                validate_command(shell).is_err(),
                "shell '{shell}' should NOT be in the allowlist"
            );
        }
    }

    #[test]
    fn validate_command_rejects_empty() {
        let _guard = lock_allowlist();
        assert!(matches!(
            validate_command(""),
            Err(AllowlistError::InvalidCommand(_))
        ));
    }

    #[test]
    fn validate_command_rejects_dot() {
        let _guard = lock_allowlist();
        assert!(matches!(
            validate_command("."),
            Err(AllowlistError::InvalidCommand(_))
        ));
    }

    #[test]
    fn validate_command_rejects_dotdot() {
        let _guard = lock_allowlist();
        assert!(matches!(
            validate_command(".."),
            Err(AllowlistError::InvalidCommand(_))
        ));
    }

    // -----------------------------------------------------------------------
    // Entry validation (pure — no global state)
    // -----------------------------------------------------------------------

    #[test]
    fn validate_entry_rejects_paths() {
        assert!(matches!(
            validate_entry("/usr/bin/node"),
            Err(AllowlistError::PathInEntry(_))
        ));
        assert!(matches!(
            validate_entry("..\\evil"),
            Err(AllowlistError::PathInEntry(_))
        ));
        assert!(matches!(
            validate_entry("sub/dir"),
            Err(AllowlistError::PathInEntry(_))
        ));
    }

    #[test]
    fn validate_entry_rejects_empty() {
        assert!(matches!(
            validate_entry(""),
            Err(AllowlistError::EmptyEntry)
        ));
    }

    #[test]
    fn validate_entry_rejects_nul() {
        assert!(matches!(
            validate_entry("bad\0name"),
            Err(AllowlistError::NulInEntry(_))
        ));
    }

    #[test]
    fn validate_entry_rejects_control_characters() {
        assert!(matches!(
            validate_entry("bad\tname"),
            Err(AllowlistError::ControlCharInEntry(_))
        ));
        assert!(matches!(
            validate_entry("bad\nname"),
            Err(AllowlistError::ControlCharInEntry(_))
        ));
        assert!(matches!(
            validate_entry("bad\x7fname"),
            Err(AllowlistError::ControlCharInEntry(_))
        ));
    }

    #[test]
    fn validate_entry_accepts_valid_names() {
        assert!(validate_entry("good-binary").is_ok());
        assert!(validate_entry("my_server").is_ok());
        assert!(validate_entry("scp-mcp").is_ok());
    }

    // -----------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------

    #[test]
    fn configure_adds_binaries() {
        let _guard = lock_allowlist();
        configure(&["my-server"]).unwrap();
        assert!(validate_command("my-server").is_ok());
    }

    #[test]
    fn configure_accepts_owned_strings() {
        let _guard = lock_allowlist();
        let names = vec!["server-x".to_owned()];
        configure(&names).unwrap();
        assert!(validate_command("server-x").is_ok());
    }

    #[test]
    fn configure_rejects_invalid_entries() {
        let _guard = lock_allowlist();
        let result = configure(&["/usr/bin/bad"]);
        assert!(result.is_err());
        // Ensure the valid default state is unchanged after a failed configure.
        assert!(validate_command("node").is_ok());
    }

    #[test]
    fn configure_is_additive() {
        let _guard = lock_allowlist();
        configure(&["server-a"]).unwrap();
        configure(&["server-b"]).unwrap();
        assert!(validate_command("server-a").is_ok());
        assert!(validate_command("server-b").is_ok());
    }

    // -----------------------------------------------------------------------
    // Disable / Reset
    // -----------------------------------------------------------------------

    #[test]
    fn disable_enforcement_allows_any_binary() {
        let _guard = lock_allowlist();
        disable_enforcement().unwrap();
        assert!(validate_command("curl").is_ok());
        assert!(validate_command("totally-unknown").is_ok());
    }

    #[test]
    fn reset_restores_defaults() {
        let _guard = lock_allowlist();
        configure(&["custom-server"]).unwrap();
        disable_enforcement().unwrap();
        reset().unwrap();

        // Custom addition gone.
        assert!(validate_command("custom-server").is_err());
        // Unrestricted mode gone.
        assert!(validate_command("curl").is_err());
        // Defaults still work.
        assert!(validate_command("node").is_ok());
    }

    // -----------------------------------------------------------------------
    // get_state
    // -----------------------------------------------------------------------

    #[test]
    fn get_state_returns_defaults() {
        let _guard = lock_allowlist();
        let state = get_state().unwrap();
        assert!(!state.unrestricted);
        assert!(state.allowed.contains(&"node".to_owned()));
        assert!(state.allowed.contains(&"scp-mcp".to_owned()));
        // Verify sorted.
        let mut sorted = state.allowed.clone();
        sorted.sort_unstable();
        assert_eq!(state.allowed, sorted);
    }

    #[test]
    fn get_state_reflects_additions() {
        let _guard = lock_allowlist();
        configure(&["zzz-server"]).unwrap();
        let state = get_state().unwrap();
        assert!(state.allowed.contains(&"zzz-server".to_owned()));
    }

    #[test]
    fn get_state_reflects_unrestricted() {
        let _guard = lock_allowlist();
        disable_enforcement().unwrap();
        let state = get_state().unwrap();
        assert!(state.unrestricted);
    }
}
