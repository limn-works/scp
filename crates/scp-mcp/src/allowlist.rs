//! Per-instance allowlist for stdio command validation.
//!
//! Each bridge instance owns its own allowlist via `CoreFields::mcp_allowlist`
//! (see `scp-ffi-common::bridge_instance::CoreFields`). The allowlist
//! restricts subprocess spawning to known MCP server runtimes, per the MCP
//! Security Best Practices.
//!
//! The type is a plain owned struct — the surrounding `Mutex` (held inside
//! `CoreFields`) is the caller's concern, and lock-poisoning is mapped to
//! the bridge-specific transport-error variant by each FFI layer.
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
//! use scp_mcp::allowlist::StdioAllowlist;
//!
//! let mut allowlist = StdioAllowlist::new_with_defaults();
//!
//! // Validate a command before spawning.
//! let basename = allowlist.validate_command("node").unwrap();
//!
//! // Add custom binaries (accepts &str or String slices).
//! allowlist.configure(&["my-server"]).unwrap();
//!
//! // Query current state.
//! let state = allowlist.snapshot();
//! assert!(state.allowed.contains(&"my-server".to_owned()));
//!
//! // Reset to defaults.
//! allowlist.reset();
//! ```

use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from allowlist operations.
///
/// Each variant either describes an input-validation failure (rejected
/// entry / command shape) or a policy decision (`NotAllowed`). Mutex
/// poisoning is **not** modelled here — each FFI bridge that wraps an
/// allowlist in a `Mutex` maps `PoisonError` to its own transport-error
/// type.
///
/// Marked `#[non_exhaustive]` so future variants (e.g. a richer
/// rate-limit error class) can be added without breaking match arms in
/// out-of-tree consumers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
// Per-instance allowlist
// ---------------------------------------------------------------------------

/// Runtime-configurable allowlist for stdio subprocess commands.
///
/// Owned per-bridge-instance: each `CoreFields` holds one in a `Mutex`.
/// Construction (via [`StdioAllowlist::new_with_defaults`] or
/// [`StdioAllowlist::default`]) seeds the allowlist with [`DEFAULT_ALLOWLIST`]
/// and disables unrestricted mode.
///
/// Uses [`BTreeSet`] so entries are always sorted — no per-query sorting
/// needed for error messages or state snapshots.
///
/// # Threat model
///
/// The allowlist defends against **binary-name spoofing** at subprocess
/// spawn: it gates which `basename` (e.g. `node`, `npx`, `uvx`) may reach
/// `Command::new`, and rejects path-shaped inputs (`/usr/bin/sh`,
/// `..\bin\sh`, `./node`) regardless of unrestricted mode. The OS still
/// resolves the binary via `PATH`, so a malicious `PATH` entry that
/// shadows an allowed name (`/tmp/evil/node`) is **not** caught here —
/// hosts must keep `PATH` clean of attacker-writable directories.
///
/// The allowlist does **not** defend against malicious *arguments* to a
/// permitted binary. `python3 -c '<code>'`, `node -e '...'`, `npx -y
/// attacker-package`, and `docker run -v /:/host alpine sh` all pass
/// validation because the binary basename is in [`DEFAULT_ALLOWLIST`].
/// Hosts that need argument-level restrictions must add a separate
/// argument-validation layer above this one. Disabling the allowlist
/// (or extending it) on a `BridgeInstance` is realm-local — see
/// `.docs/lessons/process-global-policy-state-is-realm-local-rce.md`.
#[derive(Debug)]
pub struct StdioAllowlist {
    /// Allowed binary basenames (sorted by `BTreeSet` invariant).
    allowed: BTreeSet<String>,
    /// If true, bypass the allowlist entirely.
    unrestricted: bool,
}

impl StdioAllowlist {
    /// Constructs a new allowlist seeded with [`DEFAULT_ALLOWLIST`] and
    /// enforcement enabled.
    #[must_use]
    pub fn new_with_defaults() -> Self {
        Self {
            allowed: DEFAULT_ALLOWLIST.iter().map(|s| (*s).to_owned()).collect(),
            unrestricted: false,
        }
    }

    /// Validates a command against this allowlist.
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
    pub fn validate_command(&self, cmd: &str) -> Result<String, AllowlistError> {
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

        // Defense-in-depth: reject NUL and ASCII control characters even in
        // unrestricted mode. `Command::new` would also reject NUL at the
        // libc boundary, but the validator must not depend on the OS as the
        // last line of content-safety. Symmetric with `validate_entry`.
        if cmd.contains('\0') {
            return Err(AllowlistError::NulInEntry(cmd.to_owned()));
        }
        if cmd.bytes().any(|b| b < 0x20 || b == 0x7F) {
            return Err(AllowlistError::ControlCharInEntry(cmd.to_owned()));
        }

        if self.unrestricted {
            return Ok(basename);
        }

        if self.allowed.contains(&basename) {
            Ok(basename)
        } else {
            // BTreeSet is always sorted — no sort needed.
            Err(AllowlistError::NotAllowed {
                command: basename,
                allowed: self.allowed.iter().cloned().collect(),
            })
        }
    }

    /// Add binary names to the allowlist.
    ///
    /// Entries are validated before insertion (rejects paths, NUL, empty).
    /// This is additive — previously added binaries are retained. All
    /// entries are validated atomically before any are inserted.
    ///
    /// # Errors
    ///
    /// Returns [`AllowlistError`] if any entry fails validation. The
    /// allowlist is unchanged on error.
    pub fn configure<S: AsRef<str>>(
        &mut self,
        additional_binaries: &[S],
    ) -> Result<(), AllowlistError> {
        // Validate all entries before mutating self.
        for name in additional_binaries {
            validate_entry(name.as_ref())?;
        }

        for name in additional_binaries {
            self.allowed.insert(name.as_ref().to_owned());
        }

        Ok(())
    }

    /// Disable the allowlist entirely (unrestricted mode).
    ///
    /// After calling this, **any** binary name passes
    /// [`validate_command`](Self::validate_command). Only use when the
    /// command source is fully trusted.
    ///
    /// Emits a `tracing::warn!` audit event with the supplied
    /// `instance_id` so multi-tenant operators can identify which bridge
    /// instance unrestricted before subprocess spawning starts. Pass
    /// the result of `CoreFields::instance_id()` from the calling bridge;
    /// in unit tests for the standalone type, any sentinel value (e.g.
    /// `0`) is fine.
    pub fn disable_enforcement(&mut self, instance_id: u64) {
        tracing::warn!(
            instance_id,
            "MCP stdio allowlist enforcement disabled — \
             arbitrary subprocess spawning is now permitted on this bridge instance"
        );
        self.unrestricted = true;
    }

    /// Reset the allowlist to its default state.
    ///
    /// Restores the default binaries, removes any additions, and re-enables
    /// enforcement (clears unrestricted mode).
    pub fn reset(&mut self) {
        *self = Self::new_with_defaults();
    }

    /// Return a snapshot of the current allowlist state.
    #[must_use]
    pub fn snapshot(&self) -> AllowlistState {
        // BTreeSet is always sorted — collect directly.
        AllowlistState {
            allowed: self.allowed.iter().cloned().collect(),
            unrestricted: self.unrestricted,
        }
    }
}

impl Default for StdioAllowlist {
    fn default() -> Self {
        Self::new_with_defaults()
    }
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // Each test owns a fresh `StdioAllowlist`, so tests run in parallel safely.

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
        let allowlist = StdioAllowlist::new_with_defaults();
        for bin in DEFAULT_ALLOWLIST {
            assert!(
                allowlist.validate_command(bin).is_ok(),
                "default binary '{bin}' should be allowed"
            );
        }
    }

    #[test]
    fn validate_command_rejects_absolute_path_to_allowed_binary() {
        let allowlist = StdioAllowlist::new_with_defaults();
        let result = allowlist.validate_command("/usr/bin/node");
        assert!(result.is_err());
        assert!(
            matches!(result, Err(AllowlistError::PathInCommand(_))),
            "should be PathInCommand variant"
        );
    }

    #[test]
    fn validate_command_rejects_relative_path() {
        let allowlist = StdioAllowlist::new_with_defaults();
        let result = allowlist.validate_command("../../bin/sh");
        assert!(result.is_err());
        assert!(
            matches!(result, Err(AllowlistError::PathInCommand(_))),
            "should be PathInCommand variant"
        );
    }

    #[test]
    fn validate_command_rejects_relative_path_to_allowed_binary() {
        let allowlist = StdioAllowlist::new_with_defaults();
        let result = allowlist.validate_command("./node");
        assert!(matches!(result, Err(AllowlistError::PathInCommand(_))));
    }

    #[test]
    fn validate_command_rejects_backslash_path() {
        let allowlist = StdioAllowlist::new_with_defaults();
        // On Unix, backslash is a valid filename char, so Path::file_name()
        // would not catch this. The explicit backslash check does.
        let result = allowlist.validate_command("..\\..\\bin\\sh");
        assert!(matches!(result, Err(AllowlistError::PathInCommand(_))));
    }

    #[test]
    fn validate_command_rejects_unknown_binary() {
        let allowlist = StdioAllowlist::new_with_defaults();
        match allowlist.validate_command("curl") {
            Err(AllowlistError::NotAllowed { command, allowed }) => {
                assert_eq!(command, "curl");
                assert!(!allowed.is_empty());
            }
            other => panic!("expected NotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn validate_command_rejects_shells() {
        let allowlist = StdioAllowlist::new_with_defaults();
        for shell in &["sh", "bash", "zsh", "fish", "cmd", "powershell"] {
            assert!(
                allowlist.validate_command(shell).is_err(),
                "shell '{shell}' should NOT be in the allowlist"
            );
        }
    }

    #[test]
    fn validate_command_rejects_empty() {
        let allowlist = StdioAllowlist::new_with_defaults();
        assert!(matches!(
            allowlist.validate_command(""),
            Err(AllowlistError::InvalidCommand(_))
        ));
    }

    #[test]
    fn validate_command_rejects_dot() {
        let allowlist = StdioAllowlist::new_with_defaults();
        assert!(matches!(
            allowlist.validate_command("."),
            Err(AllowlistError::InvalidCommand(_))
        ));
    }

    #[test]
    fn validate_command_rejects_dotdot() {
        let allowlist = StdioAllowlist::new_with_defaults();
        assert!(matches!(
            allowlist.validate_command(".."),
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
        let mut allowlist = StdioAllowlist::new_with_defaults();
        allowlist.configure(&["my-server"]).unwrap();
        assert!(allowlist.validate_command("my-server").is_ok());
    }

    #[test]
    fn configure_accepts_owned_strings() {
        let mut allowlist = StdioAllowlist::new_with_defaults();
        let names = vec!["server-x".to_owned()];
        allowlist.configure(&names).unwrap();
        assert!(allowlist.validate_command("server-x").is_ok());
    }

    #[test]
    fn configure_rejects_invalid_entries() {
        let mut allowlist = StdioAllowlist::new_with_defaults();
        let result = allowlist.configure(&["/usr/bin/bad"]);
        assert!(result.is_err());
        // Ensure the valid default state is unchanged after a failed configure.
        assert!(allowlist.validate_command("node").is_ok());
    }

    #[test]
    fn configure_is_additive() {
        let mut allowlist = StdioAllowlist::new_with_defaults();
        allowlist.configure(&["server-a"]).unwrap();
        allowlist.configure(&["server-b"]).unwrap();
        assert!(allowlist.validate_command("server-a").is_ok());
        assert!(allowlist.validate_command("server-b").is_ok());
    }

    // -----------------------------------------------------------------------
    // Disable / Reset
    // -----------------------------------------------------------------------

    #[test]
    fn disable_enforcement_allows_any_binary() {
        let mut allowlist = StdioAllowlist::new_with_defaults();
        allowlist.disable_enforcement(0);
        assert!(allowlist.validate_command("curl").is_ok());
        assert!(allowlist.validate_command("totally-unknown").is_ok());
    }

    #[test]
    fn reset_restores_defaults() {
        let mut allowlist = StdioAllowlist::new_with_defaults();
        allowlist.configure(&["custom-server"]).unwrap();
        allowlist.disable_enforcement(0);
        allowlist.reset();

        // Custom addition gone.
        assert!(allowlist.validate_command("custom-server").is_err());
        // Unrestricted mode gone.
        assert!(allowlist.validate_command("curl").is_err());
        // Defaults still work.
        assert!(allowlist.validate_command("node").is_ok());
    }

    // -----------------------------------------------------------------------
    // snapshot
    // -----------------------------------------------------------------------

    #[test]
    fn snapshot_returns_defaults() {
        let allowlist = StdioAllowlist::new_with_defaults();
        let state = allowlist.snapshot();
        assert!(!state.unrestricted);
        assert!(state.allowed.contains(&"node".to_owned()));
        assert!(state.allowed.contains(&"scp-mcp".to_owned()));
        // Verify sorted.
        let mut sorted = state.allowed.clone();
        sorted.sort_unstable();
        assert_eq!(state.allowed, sorted);
    }

    #[test]
    fn snapshot_reflects_additions() {
        let mut allowlist = StdioAllowlist::new_with_defaults();
        allowlist.configure(&["zzz-server"]).unwrap();
        let state = allowlist.snapshot();
        assert!(state.allowed.contains(&"zzz-server".to_owned()));
    }

    #[test]
    fn snapshot_reflects_unrestricted() {
        let mut allowlist = StdioAllowlist::new_with_defaults();
        allowlist.disable_enforcement(0);
        let state = allowlist.snapshot();
        assert!(state.unrestricted);
    }

    #[test]
    fn default_impl_matches_new_with_defaults() {
        let a = StdioAllowlist::default().snapshot();
        let b = StdioAllowlist::new_with_defaults().snapshot();
        assert_eq!(a.unrestricted, b.unrestricted);
        assert_eq!(a.allowed, b.allowed);
    }

    #[test]
    fn unrestricted_still_rejects_paths() {
        // INV-5: even in unrestricted mode, path-shaped commands are rejected.
        // Path-rejection is a pre-allowlist defense — it must run regardless of
        // whether the allowlist is bypassed.
        let mut allowlist = StdioAllowlist::new_with_defaults();
        allowlist.disable_enforcement(0);
        assert!(matches!(
            allowlist.validate_command("/usr/bin/sh"),
            Err(AllowlistError::PathInCommand(_))
        ));
        assert!(matches!(
            allowlist.validate_command("./node"),
            Err(AllowlistError::PathInCommand(_))
        ));
        assert!(matches!(
            allowlist.validate_command("..\\bin\\sh"),
            Err(AllowlistError::PathInCommand(_))
        ));
        // Empty + dot-paths still rejected as InvalidCommand (Path::file_name fails).
        assert!(matches!(
            allowlist.validate_command(""),
            Err(AllowlistError::InvalidCommand(_))
        ));
    }

    #[test]
    fn unrestricted_still_rejects_nul_and_control_chars() {
        // Defense-in-depth: even in unrestricted mode, NUL and ASCII control
        // characters in commands must be rejected — the validator must not
        // depend on `Command::new` to catch them at the libc boundary.
        let mut allowlist = StdioAllowlist::new_with_defaults();
        allowlist.disable_enforcement(0);
        assert!(matches!(
            allowlist.validate_command("node\0evil"),
            Err(AllowlistError::NulInEntry(_))
        ));
        assert!(matches!(
            allowlist.validate_command("node\tevil"),
            Err(AllowlistError::ControlCharInEntry(_))
        ));
        assert!(matches!(
            allowlist.validate_command("node\nevil"),
            Err(AllowlistError::ControlCharInEntry(_))
        ));
        assert!(matches!(
            allowlist.validate_command("node\x7fevil"),
            Err(AllowlistError::ControlCharInEntry(_))
        ));
    }

    #[test]
    fn configure_atomicity_no_partial_inserts() {
        // INV-6: a multi-entry configure call where one entry fails validation
        // must NOT insert any of the entries (validate-all-then-insert).
        let mut allowlist = StdioAllowlist::new_with_defaults();
        let result = allowlist.configure(&["valid-name", "/invalid/path"]);
        assert!(result.is_err(), "expected configure to fail");
        // The valid entry must NOT have been inserted before the invalid one
        // tripped the validation.
        assert!(
            allowlist.validate_command("valid-name").is_err(),
            "valid-name must NOT be inserted on partial failure"
        );
        // Defaults still intact.
        assert!(allowlist.validate_command("node").is_ok());
    }

    #[test]
    fn allowlists_are_independent() {
        // Two instances must not share state.
        let mut a = StdioAllowlist::new_with_defaults();
        let b = StdioAllowlist::new_with_defaults();

        a.disable_enforcement(0);
        a.configure(&["custom-a"]).unwrap();

        // `b` is unaffected.
        let b_state = b.snapshot();
        assert!(!b_state.unrestricted);
        assert!(!b_state.allowed.contains(&"custom-a".to_owned()));
        assert!(b.validate_command("custom-a").is_err());
    }
}
