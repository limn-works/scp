//! Spending capability UCAN extension for SCP economic governance.
//!
//! Implements the `SpendingCapability` UCAN type specified in section 19.5 of
//! `.docs/specs/19-economic-governance.md`. Spending UCANs authorize agents to
//! spend on behalf of their human principal within SCP contexts.
//!
//! # Key concepts
//!
//! - **AND-composition**: Paid actions require BOTH an action UCAN (e.g.,
//!   `messages:write`) AND a `SpendingCapability` UCAN. Neither alone suffices.
//! - **Attenuation**: Sub-delegated spending capabilities must narrow (lower
//!   `max_per_action`, `max_total`, `time_window`; subset `allowed_adapters`).
//! - **24-hour maximum expiry**: Spending UCANs follow the existing UCAN expiry
//!   rules (spec section 9.5). Short-lived by design to limit blast radius.
//! - **Independent revocation**: Spending UCANs are revoked via the standard
//!   revocation mechanism (spec section 7.4.4) without affecting other UCANs.
//! - **Budget tracking**: Rolling window tracking of cumulative spending against
//!   `max_total`.
//!
//! # Resource URI format
//!
//! ```text
//! scp:spending:{context_id}   — scoped to a specific context
//! scp:spending:*              — global spending (any context)
//! ```
//!
//! See ADR-033 acceptance criteria 5, 6 in `.docs/adrs/phase-3.md` and
//! spec section 19.5 in `.docs/specs/19-economic-governance.md`.

use std::collections::VecDeque;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use scp_clock::Clock;

use super::{Attenuation, UcanError, UcanPayload, UcanToken};

// ---------------------------------------------------------------------------
// Economic types (defined here pending economy module — spec section 19.1.1)
// ---------------------------------------------------------------------------

/// Amount in smallest currency unit. USD: cents. BTC: satoshis.
///
/// Always integer — no floating-point in economic calculations. Cross-party
/// determinism guaranteed. See spec section 19.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Amount(pub u64);

impl Amount {
    /// Zero amount.
    pub const ZERO: Self = Self(0);
}

impl std::fmt::Display for Amount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// ISO 4217 currency code (USD, EUR) or protocol-defined code (BTC, SAT, SOL).
///
/// 3-4 character code, null-padded to 4 bytes. See spec section 19.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CurrencyCode(pub [u8; 4]);

impl CurrencyCode {
    /// Creates a `CurrencyCode` from a string slice (max 4 ASCII bytes).
    ///
    /// # Errors
    ///
    /// Returns `None` if the input is empty, longer than 4 bytes, or contains
    /// non-ASCII characters.
    #[must_use]
    pub fn from_code(s: &str) -> Option<Self> {
        if s.is_empty() || s.len() > 4 || !s.is_ascii() {
            return None;
        }
        let mut buf = [0u8; 4];
        buf[..s.len()].copy_from_slice(s.as_bytes());
        Some(Self(buf))
    }

    /// Returns the code as a string, trimming trailing null bytes.
    #[must_use]
    pub fn as_str(&self) -> &str {
        let len = self.0.iter().position(|&b| b == 0).unwrap_or(4);
        // SAFETY: we only construct from ASCII in `from_str`, and serde
        // deserialization maintains this invariant via the 4-byte array.
        std::str::from_utf8(&self.0[..len]).unwrap_or("")
    }
}

impl std::fmt::Display for CurrencyCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SpendingCapability
// ---------------------------------------------------------------------------

/// UCAN capability for spending authorization (spec section 19.5).
///
/// Resource URI: `scp:spending:{context_id}` or `scp:spending:*` for global.
///
/// AND-composed with action UCANs: agent needs both the action capability
/// (e.g., `messages:write`) AND a valid `SpendingCapability` to perform paid
/// actions. Free actions in paid contexts do not require this capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendingCapability {
    /// Maximum amount for a single action.
    pub max_per_action: Amount,
    /// Maximum total spend within `time_window`.
    pub max_total: Amount,
    /// Currency for all amounts in this capability.
    pub currency: CurrencyCode,
    /// Rolling window for `max_total` enforcement.
    pub time_window: Duration,
    /// Allowed payment adapters. Empty means any configured adapter.
    pub allowed_adapters: Vec<String>,
}

// ---------------------------------------------------------------------------
// Spending URI parsing
// ---------------------------------------------------------------------------

/// Prefix for spending capability resource URIs.
const SPENDING_URI_PREFIX: &str = "scp:spending:";

/// The action string used in spending capability attestations.
const SPENDING_ACTION: &str = "spend";

/// Maximum UCAN token lifetime: 24 hours in seconds (spec section 9.5).
const MAX_EXPIRY_SECS: u64 = 24 * 60 * 60;

/// Parsed spending resource URI.
///
/// Either scoped to a specific context or wildcard (global spending).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendingScope {
    /// Scoped to a specific context.
    Context(String),
    /// Global spending — any context.
    Global,
}

impl SpendingScope {
    /// Parses a spending resource URI string.
    ///
    /// # Errors
    ///
    /// Returns [`SpendingError::InvalidResourceUri`] if the URI does not match
    /// the expected format.
    pub fn parse(uri: &str) -> Result<Self, SpendingError> {
        let suffix = uri
            .strip_prefix(SPENDING_URI_PREFIX)
            .ok_or_else(|| SpendingError::InvalidResourceUri(uri.to_owned()))?;

        if suffix.is_empty() {
            return Err(SpendingError::InvalidResourceUri(uri.to_owned()));
        }

        if suffix == "*" {
            Ok(Self::Global)
        } else {
            Ok(Self::Context(suffix.to_owned()))
        }
    }

    /// Returns the resource URI string for this scope.
    #[must_use]
    pub fn to_uri(&self) -> String {
        match self {
            Self::Context(id) => format!("{SPENDING_URI_PREFIX}{id}"),
            Self::Global => format!("{SPENDING_URI_PREFIX}*"),
        }
    }

    /// Checks whether this scope covers the given context ID.
    ///
    /// Global scope covers any context. Context scope covers only the
    /// matching context.
    #[must_use]
    pub fn covers_context(&self, context_id: &str) -> bool {
        match self {
            Self::Global => true,
            Self::Context(id) => id == context_id,
        }
    }
}

// ---------------------------------------------------------------------------
// SpendingError
// ---------------------------------------------------------------------------

/// Errors specific to spending capability operations.
///
/// Distinct from [`UcanError`] to avoid coupling the core UCAN error type
/// to economic governance concerns. Functions that need both use
/// `Result<T, SpendingError>` and consumers can convert via `From`.
#[derive(Debug, thiserror::Error)]
pub enum SpendingError {
    /// A paid action was attempted without a spending UCAN.
    #[error("spending capability required: {0}")]
    SpendingCapabilityRequired(String),

    /// The spending UCAN's resource URI is malformed.
    #[error("invalid spending resource URI: {0}")]
    InvalidResourceUri(String),

    /// A single action's cost exceeds `max_per_action`.
    #[error("action cost {cost} exceeds max_per_action {max} (currency: {currency})")]
    PerActionLimitExceeded {
        /// The action's cost.
        cost: Amount,
        /// The spending capability's `max_per_action`.
        max: Amount,
        /// The currency code.
        currency: CurrencyCode,
    },

    /// Cumulative spending within the time window would exceed `max_total`.
    #[error(
        "total spending {total} + action cost {cost} exceeds max_total {max} (currency: {currency})"
    )]
    TotalLimitExceeded {
        /// The current total within the window.
        total: Amount,
        /// The action's cost.
        cost: Amount,
        /// The spending capability's `max_total`.
        max: Amount,
        /// The currency code.
        currency: CurrencyCode,
    },

    /// The spending UCAN's expiry exceeds 24 hours.
    #[error("spending UCAN expiry {actual_secs}s exceeds 24h maximum ({max_secs}s)")]
    ExpiryTooLong {
        /// Actual lifetime in seconds.
        actual_secs: u64,
        /// Maximum allowed lifetime (86400s).
        max_secs: u64,
    },

    /// The spending capability's currency does not match the required currency.
    #[error("currency mismatch: expected {expected}, got {actual}")]
    CurrencyMismatch {
        /// The expected currency.
        expected: CurrencyCode,
        /// The actual currency in the capability.
        actual: CurrencyCode,
    },

    /// Attenuation violation: child capability widens parent.
    #[error("spending attenuation violation: {0}")]
    AttenuationViolation(String),

    /// The adapter is not in the allowed adapters list.
    #[error("adapter {adapter} not in allowed adapters: {allowed:?}")]
    AdapterNotAllowed {
        /// The adapter that was used.
        adapter: String,
        /// The list of allowed adapters.
        allowed: Vec<String>,
    },

    /// The spending UCAN scope does not cover the target context.
    #[error("spending UCAN scope {scope} does not cover context {context_id}")]
    ScopeNotCovered {
        /// The spending UCAN's scope URI.
        scope: String,
        /// The target context ID.
        context_id: String,
    },

    /// A UCAN-level error occurred during spending validation.
    #[error("UCAN error: {0}")]
    Ucan(#[from] UcanError),
}

// ---------------------------------------------------------------------------
// SpendingCapability extraction from UCAN facts
// ---------------------------------------------------------------------------

/// Fact key under which [`SpendingCapability`] is stored in UCAN `fct`.
const SPENDING_CAPABILITY_FACT_KEY: &str = "spending_capability";

impl SpendingCapability {
    /// Extracts a [`SpendingCapability`] from a UCAN token's `fct` field.
    ///
    /// The capability is expected under the JSON key `"spending_capability"`
    /// in the token's facts.
    ///
    /// # Errors
    ///
    /// Returns [`SpendingError::SpendingCapabilityRequired`] if the token has
    /// no facts or the fact key is missing.
    pub fn from_ucan_token(token: &UcanToken) -> Result<Self, SpendingError> {
        let fct = token.payload.fct.as_ref().ok_or_else(|| {
            SpendingError::SpendingCapabilityRequired("UCAN token has no facts field".to_owned())
        })?;

        let cap_value = fct.get(SPENDING_CAPABILITY_FACT_KEY).ok_or_else(|| {
            SpendingError::SpendingCapabilityRequired(
                "UCAN facts missing 'spending_capability' key".to_owned(),
            )
        })?;

        serde_json::from_value(cap_value.clone()).map_err(|e| {
            SpendingError::SpendingCapabilityRequired(format!(
                "failed to deserialize spending capability from UCAN facts: {e}"
            ))
        })
    }

    /// Serializes this capability as a JSON value suitable for embedding in
    /// a UCAN `fct` field.
    ///
    /// # Errors
    ///
    /// Returns `None` if serialization fails (should not happen for valid
    /// capabilities).
    #[must_use]
    pub fn to_fact_value(&self) -> Option<serde_json::Value> {
        serde_json::to_value(self).ok()
    }

    /// Returns the spending capability attestation for a given scope.
    #[must_use]
    pub fn to_attenuation(scope: &SpendingScope) -> Attenuation {
        Attenuation {
            with: scope.to_uri(),
            can: SPENDING_ACTION.to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// Spending capability check — the spending side of AND-composition
// ---------------------------------------------------------------------------

/// Validates the spending side of the AND-composition required by spec §19.5.
///
/// Per spec §19.5, a paid action requires BOTH (a) an action capability
/// (e.g., `messages:write`, `outlet:call:*`, or a context-defined custom
/// capability) AND (b) a valid `SpendingCapability`. The check is split
/// across two layers of the runtime on purpose:
///
/// 1. **Action capability** — verified UPSTREAM at the capability gate via
///    `ContextRoleState::member_has_capability`. See the `MessagesWrite`
///    check in `scp-runtime/src/context/manager/messaging.rs` (send path),
///    and the `OutletCall` / `OutletCallAll` check in
///    `scp-runtime/src/context/outlets/invoke.rs` (outlet path). A member whose
///    role does not grant the required capability is rejected at the gate,
///    before this function is ever called.
///
/// 2. **Spending capability** — verified HERE. When a spending UCAN is
///    present, this function extracts the `SpendingCapability` from its
///    `fct` field and validates:
///    - `action_cost <= max_per_action`
///    - The `SpendingCapability` structure is well-formed
///    - Currency matches `context_currency` (via
///      [`check_spending_capability_with_currency`])
///
/// This function deliberately does not accept an action UCAN. Delegated
/// action UCANs are not currently wired end-to-end through the runtime;
/// if added in the future, their validation belongs at the gate layer
/// alongside the existing role-based capability checks, not here.
///
/// Cumulative `max_total` enforcement within the `time_window` is the
/// responsibility of the caller's `BudgetTracker`, which maintains rolling
/// spend records. This function validates the per-action structural limit
/// only.
///
/// # Arguments
///
/// * `spending_ucan` — The spending UCAN. `None` if the agent has no
///   spending capability. MUST be `Some` for paid actions (`action_cost > 0`).
/// * `action_cost` — The cost of the action. `Amount::ZERO` for free actions.
/// * `action_description` — Human-readable description for error messages.
///
/// # Errors
///
/// Returns [`SpendingError::SpendingCapabilityRequired`] if the action has a
/// non-zero cost and no spending UCAN is provided.
/// Returns [`SpendingError::PerActionLimitExceeded`] if `action_cost`
/// exceeds `max_per_action` from the spending capability.
pub fn check_spending_capability(
    spending_ucan: Option<&UcanToken>,
    action_cost: Amount,
    action_description: &str,
) -> Result<(), SpendingError> {
    // Spending UCAN is required only for paid actions (cost > 0).
    if action_cost.0 > 0 && spending_ucan.is_none() {
        return Err(SpendingError::SpendingCapabilityRequired(format!(
            "paid action '{action_description}' costs {action_cost} but no spending UCAN provided"
        )));
    }

    // Free actions pass through without spending validation.
    if action_cost.0 == 0 {
        return Ok(());
    }

    // Validate spending capability fields from the UCAN's fct.
    if let Some(spending) = spending_ucan {
        let cap = SpendingCapability::from_ucan_token(spending)?;

        // Per-action limit: action_cost must not exceed max_per_action.
        if action_cost.0 > cap.max_per_action.0 {
            return Err(SpendingError::PerActionLimitExceeded {
                cost: action_cost,
                max: cap.max_per_action,
                currency: cap.currency,
            });
        }

        // Note: max_total within time_window is enforced by the caller's
        // BudgetTracker (rolling window tracking). This function validates
        // the per-action structural limit only.
    }

    Ok(())
}

/// Extended spending-capability check with currency validation.
///
/// Like [`check_spending_capability`] but also verifies that the spending
/// capability's currency matches the context's economic policy currency.
///
/// # Arguments
///
/// * `context_currency` — The currency from the context's economic policy.
///   When `Some`, the spending UCAN's currency must match.
///
/// # Errors
///
/// Returns [`SpendingError`] if the spending-capability check fails or
/// if the spending UCAN's currency does not match the context currency.
///
/// See [`check_spending_capability`] for other arguments and errors, and
/// for the layer-split rationale (action-capability verification is the
/// caller's responsibility at the gate layer).
pub fn check_spending_capability_with_currency(
    spending_ucan: Option<&UcanToken>,
    action_cost: Amount,
    action_description: &str,
    context_currency: Option<CurrencyCode>,
) -> Result<(), SpendingError> {
    check_spending_capability(spending_ucan, action_cost, action_description)?;

    // Currency validation: when the context has a currency, the spending
    // UCAN must use the same currency.
    if let (Some(expected), Some(spending)) = (context_currency, spending_ucan)
        && action_cost.0 > 0
    {
        let cap = SpendingCapability::from_ucan_token(spending)?;
        if cap.currency != expected {
            return Err(SpendingError::CurrencyMismatch {
                expected,
                actual: cap.currency,
            });
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Attenuation validation
// ---------------------------------------------------------------------------

/// Validates that a child `SpendingCapability` is a valid attenuation of
/// a parent capability.
///
/// Per spec section 7.2 and 19.5: sub-delegation must narrow, never widen.
/// Specifically:
///
/// - `max_per_action` must be <= parent's
/// - `max_total` must be <= parent's
/// - `time_window` must be <= parent's
/// - `allowed_adapters` must be a subset of parent's (empty parent = any,
///   so child can be anything; non-empty parent restricts child)
/// - `currency` must match exactly
///
/// # Errors
///
/// Returns [`SpendingError::AttenuationViolation`] with a description of the
/// first violation found.
pub fn validate_spending_attenuation(
    parent: &SpendingCapability,
    child: &SpendingCapability,
) -> Result<(), SpendingError> {
    // Currency must match exactly.
    if parent.currency != child.currency {
        return Err(SpendingError::AttenuationViolation(format!(
            "currency mismatch: parent={}, child={}",
            parent.currency, child.currency,
        )));
    }

    // max_per_action must narrow or equal.
    if child.max_per_action.0 > parent.max_per_action.0 {
        return Err(SpendingError::AttenuationViolation(format!(
            "max_per_action widened: parent={}, child={}",
            parent.max_per_action, child.max_per_action,
        )));
    }

    // max_total must narrow or equal.
    if child.max_total.0 > parent.max_total.0 {
        return Err(SpendingError::AttenuationViolation(format!(
            "max_total widened: parent={}, child={}",
            parent.max_total, child.max_total,
        )));
    }

    // time_window must narrow or equal.
    if child.time_window > parent.time_window {
        return Err(SpendingError::AttenuationViolation(format!(
            "time_window widened: parent={}s, child={}s",
            parent.time_window.as_secs(),
            child.time_window.as_secs(),
        )));
    }

    // allowed_adapters must be a subset of parent's.
    // Empty parent means "any adapter" — child can be anything.
    // Non-empty parent means child must be a non-empty subset.
    // A child with empty allowed_adapters (meaning "any") under a parent
    // with restricted adapters would widen the permission — that's a violation.
    if !parent.allowed_adapters.is_empty() {
        if child.allowed_adapters.is_empty() {
            return Err(SpendingError::AttenuationViolation(format!(
                "child has unrestricted adapters but parent restricts to: {:?}",
                parent.allowed_adapters,
            )));
        }
        for adapter in &child.allowed_adapters {
            if !parent.allowed_adapters.contains(adapter) {
                return Err(SpendingError::AttenuationViolation(format!(
                    "adapter '{adapter}' not in parent's allowed_adapters: {:?}",
                    parent.allowed_adapters,
                )));
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Budget tracking
// ---------------------------------------------------------------------------

/// A record of a single spend event within a budget window.
#[derive(Debug, Clone)]
struct SpendRecord {
    /// Amount spent.
    amount: Amount,
    /// Unix timestamp (seconds) when the spend occurred.
    timestamp_secs: u64,
}

/// Tracks cumulative spending within a rolling time window.
///
/// Used to enforce `max_total` from a [`SpendingCapability`]. Each
/// `BudgetTracker` is scoped to a single spending capability (one currency,
/// one time window).
///
/// Records are pruned lazily: expired records are removed when
/// [`check_and_record`](BudgetTracker::check_and_record) is called.
#[derive(Debug, Clone)]
pub struct BudgetTracker {
    /// The spending capability this tracker enforces.
    capability: SpendingCapability,
    /// Chronologically ordered spend records within the current window.
    records: VecDeque<SpendRecord>,
}

impl BudgetTracker {
    /// Creates a new budget tracker for the given spending capability.
    #[must_use]
    pub const fn new(capability: SpendingCapability) -> Self {
        Self {
            capability,
            records: VecDeque::new(),
        }
    }

    /// Returns the spending capability this tracker enforces.
    #[must_use]
    pub const fn capability(&self) -> &SpendingCapability {
        &self.capability
    }

    /// Returns the current total spend within the active time window.
    ///
    /// Prunes expired records before summing.
    #[must_use]
    pub fn current_total(&self, now_secs: u64) -> Amount {
        let window_start = now_secs.saturating_sub(self.capability.time_window.as_secs());
        let total: u64 = self
            .records
            .iter()
            .filter(|r| r.timestamp_secs >= window_start)
            .map(|r| r.amount.0)
            .sum();
        Amount(total)
    }

    /// Checks whether a new spend of the given amount is permitted, and if
    /// so, records it.
    ///
    /// Performs three checks:
    /// 1. Per-action limit: `amount <= max_per_action`
    /// 2. Adapter restriction: `adapter_id` in `allowed_adapters` (if non-empty)
    /// 3. Total limit: `current_total + amount <= max_total`
    ///
    /// # Arguments
    ///
    /// * `amount` — The cost of the action.
    /// * `currency` — The currency of the action (must match the capability).
    /// * `now_secs` — Current Unix timestamp in seconds.
    /// * `adapter_id` — The payment adapter being used for this spend.
    ///
    /// # Errors
    ///
    /// Returns [`SpendingError::CurrencyMismatch`] if currencies differ.
    /// Returns [`SpendingError::AdapterNotAllowed`] if the adapter is not in
    /// the allowed list.
    /// Returns [`SpendingError::PerActionLimitExceeded`] if `amount > max_per_action`.
    /// Returns [`SpendingError::TotalLimitExceeded`] if cumulative total would
    /// exceed `max_total`.
    pub fn check_and_record(
        &mut self,
        amount: Amount,
        currency: CurrencyCode,
        now_secs: u64,
        adapter_id: &str,
    ) -> Result<(), SpendingError> {
        // Currency must match.
        if currency != self.capability.currency {
            return Err(SpendingError::CurrencyMismatch {
                expected: self.capability.currency,
                actual: currency,
            });
        }

        // Adapter restriction check.
        if !self.capability.allowed_adapters.is_empty()
            && !self
                .capability
                .allowed_adapters
                .iter()
                .any(|a| a == adapter_id)
        {
            return Err(SpendingError::AdapterNotAllowed {
                adapter: adapter_id.to_owned(),
                allowed: self.capability.allowed_adapters.clone(),
            });
        }

        // Per-action check.
        if amount.0 > self.capability.max_per_action.0 {
            return Err(SpendingError::PerActionLimitExceeded {
                cost: amount,
                max: self.capability.max_per_action,
                currency,
            });
        }

        // Prune expired records.
        self.prune(now_secs);

        // Total check.
        let current = self.current_total(now_secs);
        if current.0.saturating_add(amount.0) > self.capability.max_total.0 {
            return Err(SpendingError::TotalLimitExceeded {
                total: current,
                cost: amount,
                max: self.capability.max_total,
                currency,
            });
        }

        // Record the spend.
        self.records.push_back(SpendRecord {
            amount,
            timestamp_secs: now_secs,
        });

        Ok(())
    }

    /// Removes records older than the time window from the front of the deque.
    fn prune(&mut self, now_secs: u64) {
        let window_start = now_secs.saturating_sub(self.capability.time_window.as_secs());
        while self
            .records
            .front()
            .is_some_and(|r| r.timestamp_secs < window_start)
        {
            self.records.pop_front();
        }
    }
}

// ---------------------------------------------------------------------------
// Mint spending UCAN
// ---------------------------------------------------------------------------

/// Default key scope for spending UCANs (agent verification method).
///
/// Per ADR-039, the shared-DID model uses `#agent` as the default key scope
/// for agent-issued spending UCANs (self-delegation).
pub const DEFAULT_SPENDING_KEY_SCOPE: &str = "#agent";

/// Parameters for minting a spending UCAN.
///
/// Under the shared-DID model (ADR-039), human and agent share one DID with
/// distinct verification methods (`#active` for human, `#agent` for agent).
/// The spending UCAN is a self-delegation (`iss == aud == did`) with
/// `fct.scp_key_scope` indicating which key signs.
pub struct MintSpendingParams<'a> {
    /// The shared DID (used as both issuer and audience for self-delegation).
    pub did: &'a str,
    /// The key scope identifying the signing verification method (e.g., `"#agent"`).
    /// Defaults to [`DEFAULT_SPENDING_KEY_SCOPE`] (`"#agent"`).
    pub key_scope: &'a str,
    /// The spending scope (context-specific or global).
    pub scope: &'a SpendingScope,
    /// The spending capability to grant.
    pub capability: &'a SpendingCapability,
    /// Token lifetime in seconds (must not exceed 24 hours).
    pub lifetime_secs: u64,
    /// Optional not-before timestamp.
    pub not_before: Option<u64>,
}

/// Creates a spending UCAN payload as a self-delegation under the shared-DID
/// model (ADR-039).
///
/// The spending UCAN uses `iss == aud == did` (self-delegation) with
/// `fct.scp_key_scope` set to the agent's key scope. This builds a
/// [`UcanPayload`] with the spending capability encoded in the `fct` field
/// and a spending attestation in `att`. The caller is responsible for signing
/// the payload and constructing the full [`UcanToken`].
///
/// # Errors
///
/// Returns [`SpendingError::ExpiryTooLong`] if `lifetime_secs` exceeds 24
/// hours.
///
/// See spec section 19.5, ADR-039, and SDK surface `SCP.Identity.grantSpending`.
pub fn mint_spending_ucan_payload(
    params: &MintSpendingParams<'_>,
    clock: &dyn Clock,
) -> Result<UcanPayload, SpendingError> {
    // Enforce 24-hour maximum expiry.
    if params.lifetime_secs > MAX_EXPIRY_SECS {
        return Err(SpendingError::ExpiryTooLong {
            actual_secs: params.lifetime_secs,
            max_secs: MAX_EXPIRY_SECS,
        });
    }

    let now = clock.now_secs();

    let exp = now + params.lifetime_secs;

    // Build the spending attestation.
    let att = vec![SpendingCapability::to_attenuation(params.scope)];

    // Encode the spending capability and key scope as UCAN facts.
    // The key scope enables self-delegation validation (AB-012/AB-013).
    let fct = {
        let mut facts = serde_json::Map::new();
        let cap_value = params.capability.to_fact_value().ok_or_else(|| {
            SpendingError::SpendingCapabilityRequired(
                "failed to serialize spending capability to UCAN facts".to_owned(),
            )
        })?;
        facts.insert(SPENDING_CAPABILITY_FACT_KEY.to_owned(), cap_value);
        facts.insert(
            "scp_key_scope".to_owned(),
            serde_json::Value::String(params.key_scope.to_owned()),
        );
        Some(serde_json::Value::Object(facts))
    };

    // Generate a nonce.
    let nonce = generate_spending_nonce(clock);

    Ok(UcanPayload {
        iss: params.did.to_owned(),
        aud: params.did.to_owned(),
        exp,
        nbf: params.not_before,
        nnc: nonce,
        att,
        prf: vec![],
        fct,
    })
}

/// Generates a nonce in the format `{unix_millis}-{16_random_bytes_hex}`.
fn generate_spending_nonce(clock: &dyn Clock) -> String {
    let now_millis = clock.now_millis();

    let mut random_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut random_bytes);

    let hex_suffix = random_bytes
        .iter()
        .fold(String::with_capacity(32), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        });

    format!("{now_millis}-{hex_suffix}")
}

// ---------------------------------------------------------------------------
// Validate spending UCAN
// ---------------------------------------------------------------------------

/// Validates the spending-specific surface of a spending UCAN token (scope,
/// 24-hour lifetime cap, capability extraction, attenuation against an
/// optional parent).
///
/// **DO NOT CALL THIS DIRECTLY for enforcement.** It performs none of the
/// cryptographic checks that make a UCAN trustworthy: no signature
/// verification, no chain walk, no revocation lookup, no nonce replay
/// guard, no expiry check, no key-scope check, no `iss == actor_did`
/// binding. A token can satisfy every assertion this function makes while
/// being entirely fabricated by an attacker.
///
/// The combined entry point [`validate_spending_ucan_signed`] runs the full
/// 11-step UCAN validation pipeline (via `validate.rs` helpers) **before**
/// delegating here. That is the only public way to validate a spending UCAN.
/// This function is restricted to `pub(crate)` so the misuse-prone partial
/// API cannot escape the crate.
///
/// # Steps performed by this function
///
/// 1. Verifies the token contains a spending attestation (`scp:spending:...`).
/// 2. Extracts the [`SpendingCapability`] from the token's facts.
/// 3. Verifies the spending scope covers the target context.
/// 4. Verifies the token expiry does not exceed 24 hours.
/// 5. If `parent_capability` is provided, validates attenuation.
///
/// # Key scope validation
///
/// This function does **not** validate `scp_key_scope` from the token's facts.
/// Key scope validation (verifying that the `kid` header matches the signing
/// key and that `scp_key_scope` is consistent) is handled by
/// [`validate_spending_ucan_signed`] via the shared `validate.rs` helpers
/// (SCP-AB-012/SCP-AB-013 steps 5a/5b). Duplicating key scope checks here
/// would violate the single-responsibility split between spending validation
/// and general UCAN validation.
///
/// # Arguments
///
/// * `token` — The spending UCAN token.
/// * `context_id` — The target context for the paid action.
/// * `parent_capability` — If this is a delegated spending UCAN, the parent's
///   capability for attenuation validation.
///
/// # Errors
///
/// Returns [`SpendingError`] variants for each validation failure.
pub(crate) fn validate_spending_ucan(
    token: &UcanToken,
    context_id: &str,
    parent_capability: Option<&SpendingCapability>,
    clock: &dyn Clock,
) -> Result<SpendingCapability, SpendingError> {
    // 1. Verify the token has a spending attestation.
    let spending_att = token
        .payload
        .att
        .iter()
        .find(|att| att.with.starts_with(SPENDING_URI_PREFIX) && att.can == SPENDING_ACTION)
        .ok_or_else(|| {
            SpendingError::SpendingCapabilityRequired(
                "UCAN token has no spending attestation".to_owned(),
            )
        })?;

    // 2. Parse the spending scope and verify it covers the context.
    let scope = SpendingScope::parse(&spending_att.with)?;
    if !scope.covers_context(context_id) {
        return Err(SpendingError::ScopeNotCovered {
            scope: spending_att.with.clone(),
            context_id: context_id.to_owned(),
        });
    }

    // 3. Extract the spending capability from facts.
    let capability = SpendingCapability::from_ucan_token(token)?;

    // 4. Verify 24-hour maximum expiry.
    let now = clock.now_secs();

    let lifetime = token.payload.exp.saturating_sub(now);
    if lifetime > MAX_EXPIRY_SECS {
        // Check against the token's own nbf or creation time for a more
        // accurate lifetime check.
        let start = token.payload.nbf.unwrap_or(now);
        let actual_lifetime = token.payload.exp.saturating_sub(start);
        if actual_lifetime > MAX_EXPIRY_SECS {
            return Err(SpendingError::ExpiryTooLong {
                actual_secs: actual_lifetime,
                max_secs: MAX_EXPIRY_SECS,
            });
        }
    }

    // 5. If parent capability provided, validate attenuation.
    if let Some(parent) = parent_capability {
        validate_spending_attenuation(parent, &capability)?;
    }

    Ok(capability)
}

// ---------------------------------------------------------------------------
// validate_spending_ucan_signed — combined cryptographic + spending validation
// ---------------------------------------------------------------------------

/// Inputs that bind a spending UCAN to its presenting actor and the
/// runtime state needed to verify it cryptographically.
///
/// Grouped into a struct so the public entry point keeps a single positional
/// argument and survives future additions (key-scope override, attestation
/// witness, etc.) without churn at every call site. All fields are
/// references so the struct is `Copy`-cheap; passing it by value at the
/// call site avoids a needless borrow ceremony.
#[derive(Clone, Copy)]
pub struct SpendingUcanCheck<'a> {
    /// The spending UCAN token to validate.
    pub token: &'a UcanToken,
    /// The target context the paid action runs in.
    pub context_id: &'a str,
    /// The DID the runtime is about to charge. The token's `iss` and `aud`
    /// MUST equal this string — that is the binding that prevents an
    /// attacker from replaying or fabricating someone else's spending UCAN.
    pub actor_did: &'a str,
    /// Optional parent spending capability for sub-delegated spending UCANs.
    /// `None` for the (overwhelmingly common) root spending UCAN case.
    pub parent_capability: Option<&'a SpendingCapability>,
}

/// Validates a spending UCAN end-to-end: signature, expiry, key scope,
/// revocation, nonce, scope, and the spending-specific facts.
///
/// This is the **only** entry point that exists for runtime enforcement of
/// spending UCANs. The partial helper [`validate_spending_ucan`] is now
/// `pub(crate)` and unreachable from outside the crate; bridges and SDKs
/// must call this function (or a wrapper around it) instead.
///
/// # Validation pipeline
///
/// In order:
///
/// 1. **Actor binding** — `token.payload.iss == token.payload.aud == actor_did`.
///    Spending UCANs are self-delegations under the shared-DID model
///    (ADR-039), so both `iss` and `aud` must equal the actor whose budget
///    will be debited. This check rejects forged-signer attacks where an
///    attacker presents `iss == "did:victim"` to drain a victim's budget.
/// 2. **Key scope** — Steps 5a/5b from `validate_ucan`: self-delegation
///    requires `fct.scp_key_scope` and the `kid` header must match. This is
///    what guarantees the token was signed by the agent verification method
///    that the actor explicitly authorized (typically `#agent`).
/// 3. **Delegation chain** — If `prf` is non-empty, walks every parent
///    UCAN, verifying signatures, expiry, revocation, key-scope, and
///    `aud`/`iss` linkage. The root issuer must be the actor (spending
///    UCANs cannot be delegated from elsewhere into an actor's budget).
/// 4. **Signature** — Verifies the Ed25519 signature with kid-aware DID
///    resolution (`resolve_public_key_by_kid` for `#agent`).
/// 5. **Expiry** — `nbf <= now < exp`, with the configured clock-skew
///    tolerance. Rejects tokens whose `exp` is more than 24 hours away.
/// 6. **Revocation** — Computes the SHA-256 revocation CID over the
///    encoded JWT and consults the revocation checker.
/// 7. **Nonce** — Reserves the nonce in the per-context tracker so a
///    replay of the same UCAN is rejected on the second presentation.
/// 8. **Spending facts** — Delegates to [`validate_spending_ucan`] for
///    scope coverage, lifetime cap, capability extraction, and parent
///    attenuation.
///
/// # Why a combined function instead of `validate_ucan`
///
/// The general `validate_ucan` pipeline parses every attestation as a
/// `scp:ctx:{id}/{resource}:{action}` capability URI. Spending UCANs carry
/// `scp:spending:{id}` URIs, which are not parseable as `CapabilityUri`,
/// so calling `validate_ucan` directly fails fail-closed at step 6 with
/// `MalformedToken`. This function reuses the same `validate.rs` helpers
/// for the cryptographic checks (signature, chain, expiry, key scope) and
/// then runs the spending-specific scope/cap/attenuation logic instead.
///
/// # Errors
///
/// Returns [`SpendingError`] variants for each validation failure. UCAN-level
/// failures (signature, key scope, expiry, nonce, revocation, delegation
/// chain) are surfaced via the [`SpendingError::Ucan`] variant.
///
/// # Closes
///
/// PR #1606 finding C1: spending UCANs were never cryptographically
/// validated on the `send_message`/`join_context` paths.
pub fn validate_spending_ucan_signed<D, N, R, P>(
    check: SpendingUcanCheck<'_>,
    did_resolver: &D,
    nonce_tracker: &mut N,
    revocation_checker: &R,
    proof_resolver: &P,
    clock_skew_tolerance_secs: u64,
    clock: &dyn Clock,
) -> Result<SpendingCapability, SpendingError>
where
    D: super::validate::DidResolver,
    N: super::validate::NonceTracker,
    R: super::validate::RevocationChecker,
    P: super::validate::ProofResolver,
{
    let SpendingUcanCheck {
        token,
        context_id,
        actor_did,
        parent_capability,
    } = check;

    // Validate the token's parsed JWT header (alg/typ/ucv).
    token.header.validate()?;

    // Step A: Actor binding. Spending UCANs are self-delegations: the
    // issuer and audience MUST both equal the actor whose budget the
    // runtime is about to debit. This is the single most important check
    // for closing C1 — without it an attacker can present `iss == victim`
    // and forge a spending UCAN signed by the attacker's own key.
    if token.payload.iss != actor_did {
        return Err(SpendingError::Ucan(UcanError::InvalidIssuer {
            expected: actor_did.to_owned(),
            actual: token.payload.iss.clone(),
        }));
    }
    if token.payload.aud != actor_did {
        return Err(SpendingError::Ucan(UcanError::AudienceMismatch {
            expected: actor_did.to_owned(),
            actual: token.payload.aud.clone(),
        }));
    }

    // Step B: Key scope. Rejects self-delegation without `scp_key_scope`
    // and rejects `kid`/`scp_key_scope` mismatches (ADR-039 SCP-AB-012/013).
    super::validate::validate_key_scope(token)?;

    // Step C: Delegation chain. For root spending UCANs (`prf` empty)
    // this returns `iss` immediately. For sub-delegated spending UCANs
    // it walks the chain, verifying every parent's signature, expiry,
    // revocation, key scope, and aud/iss linkage. The returned root
    // issuer is then bound to the actor — sub-delegation cannot smuggle
    // in a different root.
    let root_issuer = super::validate::verify_delegation_chain(
        token,
        did_resolver,
        proof_resolver,
        revocation_checker,
        clock_skew_tolerance_secs,
        clock,
    )?;
    if root_issuer != actor_did {
        return Err(SpendingError::Ucan(UcanError::InvalidIssuer {
            expected: actor_did.to_owned(),
            actual: root_issuer,
        }));
    }

    // Step D: Signature. kid-aware Ed25519 verification — when the header
    // includes `kid: "#agent"` (the standard for spending UCANs) the
    // verifier consults the agent verification method on the issuer's
    // DID document.
    super::validate::verify_signature(token, did_resolver)?;

    // Step E: Expiry / not-before / 24-hour ceiling, with clock skew
    // tolerance for NTP drift.
    super::validate::verify_expiry(token, clock_skew_tolerance_secs, clock)?;

    // Step F: Revocation. Computes the SHA-256 CID of the encoded JWT
    // (matching the format produced by `revoke_ucan`) and consults the
    // revocation checker.
    let revocation_cid = super::revoke::compute_revocation_cid(&token.encoded);
    if revocation_checker.is_revoked(&revocation_cid) {
        return Err(SpendingError::Ucan(UcanError::TokenRevoked(revocation_cid)));
    }

    // Step G: Nonce probe (read-only). Rejects format/freshness violations and
    // replays WITHOUT recording the nonce. The nonce is committed only after
    // all downstream gates — including the budget check — pass, via a
    // separate `commit_spending_ucan_nonce` call (H11 split-phase). This
    // prevents nonce-burn DoS: a budget-rejected request must not exhaust
    // tracker capacity.
    nonce_tracker.check_replay(&token.payload.nnc, token.payload.exp)?;

    // Step H: Spending-specific validation. Delegates to the partial
    // helper, which is now `pub(crate)` and unreachable from outside the
    // crate. Validates the spending attestation scope, lifetime cap,
    // capability extraction, and (if a parent is supplied) attenuation.
    validate_spending_ucan(token, context_id, parent_capability, clock)
}

/// Commits the nonce from a previously validated spending UCAN into the
/// nonce tracker.
///
/// This is the second phase of the H11 split-phase nonce protocol.
/// [`validate_spending_ucan_signed`] calls
/// [`check_replay`](super::validate::NonceTracker::check_replay) — a
/// read-only probe that rejects replays and format/freshness violations but
/// does NOT record the nonce. After all downstream gates pass (including the
/// budget check), the caller MUST invoke `commit_spending_ucan_nonce` to
/// durably record the nonce and prevent future replays.
///
/// Splitting the phases prevents nonce-burn denial-of-service: a valid UCAN
/// that fails the budget gate cannot exhaust tracker capacity by consuming a
/// nonce slot.
///
/// # Errors
///
/// Returns [`SpendingError`] if the defensive re-check inside `record` fails
/// (e.g., a concurrent caller raced to record the same nonce).
pub fn commit_spending_ucan_nonce<N>(
    token: &UcanToken,
    nonce_tracker: &mut N,
) -> Result<(), SpendingError>
where
    N: super::validate::NonceTracker,
{
    nonce_tracker
        .record(&token.payload.nnc, token.payload.exp)
        .map_err(SpendingError::Ucan)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreadable_literal
)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Amount
    // -----------------------------------------------------------------------

    #[test]
    fn amount_zero_is_zero() {
        assert_eq!(Amount::ZERO.0, 0);
    }

    #[test]
    fn amount_display() {
        assert_eq!(Amount(100).to_string(), "100");
        assert_eq!(Amount(0).to_string(), "0");
    }

    #[test]
    fn amount_ordering() {
        assert!(Amount(100) > Amount(50));
        assert!(Amount(50) < Amount(100));
        assert_eq!(Amount(42), Amount(42));
    }

    #[test]
    fn amount_serialization_roundtrip() {
        let amount = Amount(12345);
        let json = serde_json::to_string(&amount).unwrap();
        let deserialized: Amount = serde_json::from_str(&json).unwrap();
        assert_eq!(amount, deserialized);
    }

    // -----------------------------------------------------------------------
    // CurrencyCode
    // -----------------------------------------------------------------------

    #[test]
    fn currency_code_from_str_valid() {
        let usd = CurrencyCode::from_code("USD").unwrap();
        assert_eq!(usd.as_str(), "USD");

        let btc = CurrencyCode::from_code("BTC").unwrap();
        assert_eq!(btc.as_str(), "BTC");

        let usdc = CurrencyCode::from_code("USDC").unwrap();
        assert_eq!(usdc.as_str(), "USDC");
    }

    #[test]
    fn currency_code_from_str_rejects_empty() {
        assert!(CurrencyCode::from_code("").is_none());
    }

    #[test]
    fn currency_code_from_str_rejects_too_long() {
        assert!(CurrencyCode::from_code("ABCDE").is_none());
    }

    #[test]
    fn currency_code_from_str_rejects_non_ascii() {
        assert!(CurrencyCode::from_code("\u{00e9}UR").is_none());
    }

    #[test]
    fn currency_code_display() {
        let usd = CurrencyCode::from_code("USD").unwrap();
        assert_eq!(usd.to_string(), "USD");
    }

    #[test]
    fn currency_code_serialization_roundtrip() {
        let code = CurrencyCode::from_code("USD").unwrap();
        let json = serde_json::to_string(&code).unwrap();
        let deserialized: CurrencyCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, deserialized);
    }

    // -----------------------------------------------------------------------
    // SpendingCapability
    // -----------------------------------------------------------------------

    fn usd() -> CurrencyCode {
        CurrencyCode::from_code("USD").unwrap()
    }

    fn sample_capability() -> SpendingCapability {
        SpendingCapability {
            max_per_action: Amount(1000),
            max_total: Amount(10000),
            currency: usd(),
            time_window: Duration::from_hours(24),
            allowed_adapters: vec!["x402".to_owned(), "lightning".to_owned()],
        }
    }

    #[test]
    fn spending_capability_serialization_roundtrip() {
        let cap = sample_capability();
        let json = serde_json::to_string(&cap).unwrap();
        let deserialized: SpendingCapability = serde_json::from_str(&json).unwrap();
        assert_eq!(cap, deserialized);
    }

    #[test]
    fn spending_capability_to_fact_value_roundtrip() {
        let cap = sample_capability();
        let fact = cap.to_fact_value().unwrap();
        let restored: SpendingCapability = serde_json::from_value(fact).unwrap();
        assert_eq!(cap, restored);
    }

    #[test]
    fn spending_capability_from_ucan_token_success() {
        let cap = sample_capability();
        let token = make_spending_token(&cap, "scp:spending:ctx123");
        let extracted = SpendingCapability::from_ucan_token(&token).unwrap();
        assert_eq!(cap, extracted);
    }

    #[test]
    fn spending_capability_from_ucan_token_no_facts() {
        let token = UcanToken {
            header: super::super::UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkHuman".to_owned(),
                aud: "did:dht:z6MkAgent".to_owned(),
                exp: 1_700_000_000,
                nbf: None,
                nnc: "1699999000000-aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        };
        let err = SpendingCapability::from_ucan_token(&token).unwrap_err();
        assert!(matches!(err, SpendingError::SpendingCapabilityRequired(_)));
    }

    #[test]
    fn spending_capability_from_ucan_token_missing_key() {
        let token = UcanToken {
            header: super::super::UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkHuman".to_owned(),
                aud: "did:dht:z6MkAgent".to_owned(),
                exp: 1_700_000_000,
                nbf: None,
                nnc: "1699999000000-aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: Some(serde_json::json!({"other_key": "value"})),
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        };
        let err = SpendingCapability::from_ucan_token(&token).unwrap_err();
        assert!(matches!(err, SpendingError::SpendingCapabilityRequired(_)));
    }

    // -----------------------------------------------------------------------
    // SpendingScope
    // -----------------------------------------------------------------------

    #[test]
    fn spending_scope_parse_context() {
        let scope = SpendingScope::parse("scp:spending:ctx123").unwrap();
        assert_eq!(scope, SpendingScope::Context("ctx123".to_owned()));
    }

    #[test]
    fn spending_scope_parse_global() {
        let scope = SpendingScope::parse("scp:spending:*").unwrap();
        assert_eq!(scope, SpendingScope::Global);
    }

    #[test]
    fn spending_scope_parse_invalid_prefix() {
        let err = SpendingScope::parse("scp:ctx:abc123/messages:write").unwrap_err();
        assert!(matches!(err, SpendingError::InvalidResourceUri(_)));
    }

    #[test]
    fn spending_scope_parse_empty_suffix() {
        let err = SpendingScope::parse("scp:spending:").unwrap_err();
        assert!(matches!(err, SpendingError::InvalidResourceUri(_)));
    }

    #[test]
    fn spending_scope_to_uri_roundtrip() {
        let scope = SpendingScope::Context("ctx123".to_owned());
        assert_eq!(scope.to_uri(), "scp:spending:ctx123");

        let global = SpendingScope::Global;
        assert_eq!(global.to_uri(), "scp:spending:*");
    }

    #[test]
    fn spending_scope_covers_context() {
        let ctx_scope = SpendingScope::Context("ctx123".to_owned());
        assert!(ctx_scope.covers_context("ctx123"));
        assert!(!ctx_scope.covers_context("ctx456"));

        let global = SpendingScope::Global;
        assert!(global.covers_context("ctx123"));
        assert!(global.covers_context("any-context"));
    }

    // -----------------------------------------------------------------------
    // Spending capability check
    // -----------------------------------------------------------------------

    /// Dummy token with a valid `SpendingCapability` in the fct field.
    fn dummy_spending_token() -> UcanToken {
        let cap = sample_capability();
        let mut fct = serde_json::Map::new();
        fct.insert(
            SPENDING_CAPABILITY_FACT_KEY.to_owned(),
            cap.to_fact_value().unwrap(),
        );
        UcanToken {
            header: super::super::UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkHuman".to_owned(),
                aud: "did:dht:z6MkAgent".to_owned(),
                exp: 1_700_000_000,
                nbf: None,
                nnc: "1699999000000-aabbccdd11223344".to_owned(),
                att: vec![],
                prf: vec![],
                fct: Some(serde_json::Value::Object(fct)),
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        }
    }

    #[test]
    fn check_spending_capability_paid_action_with_spending_succeeds() {
        // Action capability is assumed verified at the gate layer per §19.5
        // (see docstring). With a valid spending UCAN and cost within
        // max_per_action, the check succeeds.
        let spending = dummy_spending_token();
        let result = check_spending_capability(Some(&spending), Amount(100), "send message");
        assert!(result.is_ok());
    }

    #[test]
    fn check_spending_capability_free_action_no_spending_succeeds() {
        // Free actions (cost == 0) pass without any spending UCAN.
        let result = check_spending_capability(None, Amount::ZERO, "send free message");
        assert!(result.is_ok());
    }

    #[test]
    fn check_spending_capability_paid_action_no_spending_rejected() {
        // Paid action (cost > 0) with no spending UCAN must be rejected.
        let result = check_spending_capability(None, Amount(100), "send message");
        let err = result.unwrap_err();
        assert!(matches!(err, SpendingError::SpendingCapabilityRequired(_)));
    }

    // -----------------------------------------------------------------------
    // Attenuation validation
    // -----------------------------------------------------------------------

    #[test]
    fn attenuation_valid_narrowing() {
        let parent = sample_capability();
        let child = SpendingCapability {
            max_per_action: Amount(500),
            max_total: Amount(5000),
            currency: usd(),
            time_window: Duration::from_hours(12), // 12 hours
            allowed_adapters: vec!["x402".to_owned()],
        };
        assert!(validate_spending_attenuation(&parent, &child).is_ok());
    }

    #[test]
    fn attenuation_equal_is_valid() {
        let parent = sample_capability();
        let child = parent.clone();
        assert!(validate_spending_attenuation(&parent, &child).is_ok());
    }

    #[test]
    fn attenuation_widens_max_per_action() {
        let parent = sample_capability();
        let child = SpendingCapability {
            max_per_action: Amount(2000), // wider
            ..parent.clone()
        };
        let err = validate_spending_attenuation(&parent, &child).unwrap_err();
        assert!(matches!(err, SpendingError::AttenuationViolation(_)));
    }

    #[test]
    fn attenuation_widens_max_total() {
        let parent = sample_capability();
        let child = SpendingCapability {
            max_total: Amount(20000), // wider
            ..parent.clone()
        };
        let err = validate_spending_attenuation(&parent, &child).unwrap_err();
        assert!(matches!(err, SpendingError::AttenuationViolation(_)));
    }

    #[test]
    fn attenuation_widens_time_window() {
        let parent = sample_capability();
        let child = SpendingCapability {
            time_window: Duration::from_hours(48), // wider (2 days)
            ..parent.clone()
        };
        let err = validate_spending_attenuation(&parent, &child).unwrap_err();
        assert!(matches!(err, SpendingError::AttenuationViolation(_)));
    }

    #[test]
    fn attenuation_currency_mismatch() {
        let parent = sample_capability();
        let child = SpendingCapability {
            currency: CurrencyCode::from_code("BTC").unwrap(),
            ..parent.clone()
        };
        let err = validate_spending_attenuation(&parent, &child).unwrap_err();
        assert!(matches!(err, SpendingError::AttenuationViolation(_)));
    }

    #[test]
    fn attenuation_adapter_not_in_parent() {
        let parent = sample_capability();
        let child = SpendingCapability {
            allowed_adapters: vec!["stripe".to_owned()], // not in parent
            ..parent
        };
        let err = validate_spending_attenuation(&parent, &child).unwrap_err();
        assert!(matches!(err, SpendingError::AttenuationViolation(_)));
    }

    #[test]
    fn attenuation_rejects_unrestricted_child_under_restricted_parent() {
        let parent = sample_capability(); // has ["x402", "lightning"]
        let child = SpendingCapability {
            allowed_adapters: vec![], // unrestricted — would widen parent
            ..parent
        };
        let err = validate_spending_attenuation(&parent, &child).unwrap_err();
        assert!(matches!(err, SpendingError::AttenuationViolation(_)));
    }

    #[test]
    fn attenuation_empty_parent_adapters_allows_any_child() {
        let parent = SpendingCapability {
            allowed_adapters: vec![], // any adapter
            ..sample_capability()
        };
        let child = SpendingCapability {
            allowed_adapters: vec!["stripe".to_owned(), "x402".to_owned()],
            ..parent
        };
        assert!(validate_spending_attenuation(&parent, &child).is_ok());
    }

    // -----------------------------------------------------------------------
    // Budget tracking
    // -----------------------------------------------------------------------

    #[test]
    fn budget_tracker_allows_within_limits() {
        let cap = sample_capability();
        let mut tracker = BudgetTracker::new(cap);
        let now = 1_700_000_000;
        assert!(
            tracker
                .check_and_record(Amount(500), usd(), now, "x402")
                .is_ok()
        );
    }

    #[test]
    fn budget_tracker_rejects_per_action_exceeded() {
        let cap = sample_capability(); // max_per_action = 1000
        let mut tracker = BudgetTracker::new(cap);
        let now = 1_700_000_000;
        let err = tracker
            .check_and_record(Amount(1500), usd(), now, "x402")
            .unwrap_err();
        assert!(matches!(err, SpendingError::PerActionLimitExceeded { .. }));
    }

    #[test]
    fn budget_tracker_rejects_total_exceeded() {
        let cap = SpendingCapability {
            max_per_action: Amount(5000),
            max_total: Amount(10000),
            currency: usd(),
            time_window: Duration::from_hours(1),
            allowed_adapters: vec![],
        };
        let mut tracker = BudgetTracker::new(cap);
        let now = 1_700_000_000;

        // Spend 6000, then try 5000 more (total would be 11000 > 10000).
        assert!(
            tracker
                .check_and_record(Amount(4000), usd(), now, "test")
                .is_ok()
        );
        assert!(
            tracker
                .check_and_record(Amount(4000), usd(), now, "test")
                .is_ok()
        );
        let err = tracker
            .check_and_record(Amount(3000), usd(), now, "test")
            .unwrap_err();
        assert!(matches!(err, SpendingError::TotalLimitExceeded { .. }));
    }

    #[test]
    fn budget_tracker_prunes_expired_records() {
        let cap = SpendingCapability {
            max_per_action: Amount(5000),
            max_total: Amount(5000),
            currency: usd(),
            time_window: Duration::from_hours(1), // 1 hour
            allowed_adapters: vec![],
        };
        let mut tracker = BudgetTracker::new(cap);

        // Spend 4000 at t=1000.
        let t1 = 1000;
        assert!(
            tracker
                .check_and_record(Amount(4000), usd(), t1, "test")
                .is_ok()
        );

        // At t=5000 (4000 seconds later, well past the 1-hour window),
        // the old record should be pruned.
        let t2 = 5000;
        assert!(
            tracker
                .check_and_record(Amount(4000), usd(), t2, "test")
                .is_ok()
        );
    }

    #[test]
    fn budget_tracker_currency_mismatch() {
        let cap = sample_capability(); // USD
        let mut tracker = BudgetTracker::new(cap);
        let btc = CurrencyCode::from_code("BTC").unwrap();
        let err = tracker
            .check_and_record(Amount(100), btc, 1_700_000_000, "test")
            .unwrap_err();
        assert!(matches!(err, SpendingError::CurrencyMismatch { .. }));
    }

    #[test]
    fn budget_tracker_current_total_excludes_expired() {
        let cap = SpendingCapability {
            max_per_action: Amount(5000),
            max_total: Amount(10000),
            currency: usd(),
            time_window: Duration::from_secs(100),
            allowed_adapters: vec![],
        };
        let mut tracker = BudgetTracker::new(cap);

        // Record at t=100
        assert!(
            tracker
                .check_and_record(Amount(3000), usd(), 100, "test")
                .is_ok()
        );
        // Record at t=150
        assert!(
            tracker
                .check_and_record(Amount(2000), usd(), 150, "test")
                .is_ok()
        );

        // At t=250, the first record (t=100) is expired (250-100=150 > window 100).
        assert_eq!(tracker.current_total(250), Amount(2000));
    }

    // -----------------------------------------------------------------------
    // Mint spending UCAN payload
    // -----------------------------------------------------------------------

    #[test]
    fn mint_spending_ucan_payload_success() {
        let cap = sample_capability();
        let scope = SpendingScope::Context("ctx123".to_owned());
        let params = MintSpendingParams {
            did: "did:dht:z6MkShared",
            key_scope: DEFAULT_SPENDING_KEY_SCOPE,
            scope: &scope,
            capability: &cap,
            lifetime_secs: 3600,
            not_before: None,
        };
        let payload = mint_spending_ucan_payload(&params, &scp_clock::SystemClock).unwrap();

        // Self-delegation: iss == aud
        assert_eq!(payload.iss, "did:dht:z6MkShared");
        assert_eq!(payload.aud, "did:dht:z6MkShared");
        assert_eq!(payload.att.len(), 1);
        assert_eq!(payload.att[0].with, "scp:spending:ctx123");
        assert_eq!(payload.att[0].can, "spend");
        assert!(payload.fct.is_some());

        // Verify the capability can be extracted from the facts.
        let fct = payload.fct.as_ref().unwrap();
        let extracted: SpendingCapability =
            serde_json::from_value(fct["spending_capability"].clone()).unwrap();
        assert_eq!(extracted, cap);

        // Verify scp_key_scope is present for self-delegation validation.
        assert_eq!(
            fct.get("scp_key_scope").and_then(|v| v.as_str()),
            Some("#agent")
        );
    }

    #[test]
    fn mint_spending_ucan_payload_global_scope() {
        let cap = sample_capability();
        let scope = SpendingScope::Global;
        let params = MintSpendingParams {
            did: "did:dht:z6MkShared",
            key_scope: DEFAULT_SPENDING_KEY_SCOPE,
            scope: &scope,
            capability: &cap,
            lifetime_secs: 3600,
            not_before: None,
        };
        let payload = mint_spending_ucan_payload(&params, &scp_clock::SystemClock).unwrap();
        assert_eq!(payload.att[0].with, "scp:spending:*");
        assert_eq!(payload.iss, payload.aud); // self-delegation
    }

    #[test]
    fn mint_spending_ucan_payload_rejects_long_expiry() {
        let cap = sample_capability();
        let scope = SpendingScope::Context("ctx123".to_owned());
        let params = MintSpendingParams {
            did: "did:dht:z6MkShared",
            key_scope: DEFAULT_SPENDING_KEY_SCOPE,
            scope: &scope,
            capability: &cap,
            lifetime_secs: MAX_EXPIRY_SECS + 1,
            not_before: None,
        };
        let err = mint_spending_ucan_payload(&params, &scp_clock::SystemClock).unwrap_err();
        assert!(matches!(err, SpendingError::ExpiryTooLong { .. }));
    }

    #[test]
    fn mint_spending_ucan_payload_with_not_before() {
        let cap = sample_capability();
        let scope = SpendingScope::Context("ctx123".to_owned());
        let params = MintSpendingParams {
            did: "did:dht:z6MkShared",
            key_scope: DEFAULT_SPENDING_KEY_SCOPE,
            scope: &scope,
            capability: &cap,
            lifetime_secs: 3600,
            not_before: Some(1_700_000_000),
        };
        let payload = mint_spending_ucan_payload(&params, &scp_clock::SystemClock).unwrap();
        assert_eq!(payload.nbf, Some(1_700_000_000));
    }

    // -----------------------------------------------------------------------
    // Validate spending UCAN
    // -----------------------------------------------------------------------

    /// Helper to build a spending UCAN token for testing.
    ///
    /// Uses the shared-DID model: `iss == aud` (self-delegation) with
    /// `fct.scp_key_scope: "#agent"`.
    fn make_spending_token(cap: &SpendingCapability, scope_uri: &str) -> UcanToken {
        let now = scp_clock::SystemClock.now_secs();

        UcanToken {
            header: super::super::UcanHeader::with_kid("#agent".to_owned()),
            payload: UcanPayload {
                iss: "did:dht:z6MkShared".to_owned(),
                aud: "did:dht:z6MkShared".to_owned(),
                exp: now + 3600,
                nbf: Some(now),
                nnc: "1699999000000-aabbccdd11223344".to_owned(),
                att: vec![Attenuation {
                    with: scope_uri.to_owned(),
                    can: "spend".to_owned(),
                }],
                prf: vec![],
                fct: Some(serde_json::json!({
                    "spending_capability": serde_json::to_value(cap).unwrap(),
                    "scp_key_scope": "#agent"
                })),
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        }
    }

    #[test]
    fn validate_spending_ucan_context_scoped() {
        let cap = sample_capability();
        let token = make_spending_token(&cap, "scp:spending:ctx123");
        let result = validate_spending_ucan(&token, "ctx123", None, &scp_clock::SystemClock);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), cap);
    }

    #[test]
    fn validate_spending_ucan_global_scope() {
        let cap = sample_capability();
        let token = make_spending_token(&cap, "scp:spending:*");
        let result = validate_spending_ucan(&token, "any-context", None, &scp_clock::SystemClock);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_spending_ucan_scope_mismatch() {
        let cap = sample_capability();
        let token = make_spending_token(&cap, "scp:spending:ctx123");
        let err =
            validate_spending_ucan(&token, "ctx456", None, &scp_clock::SystemClock).unwrap_err();
        assert!(matches!(err, SpendingError::ScopeNotCovered { .. }));
    }

    #[test]
    fn validate_spending_ucan_no_spending_att() {
        let token = UcanToken {
            header: super::super::UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:dht:z6MkHuman".to_owned(),
                aud: "did:dht:z6MkAgent".to_owned(),
                exp: 1_700_000_000,
                nbf: None,
                nnc: "1699999000000-aabbccdd11223344".to_owned(),
                att: vec![Attenuation {
                    with: "scp:ctx:ctx123/messages:write".to_owned(),
                    can: "write".to_owned(),
                }],
                prf: vec![],
                fct: None,
            },
            signature: vec![0u8; 64],
            encoded: String::new(),
        };
        let err =
            validate_spending_ucan(&token, "ctx123", None, &scp_clock::SystemClock).unwrap_err();
        assert!(matches!(err, SpendingError::SpendingCapabilityRequired(_)));
    }

    #[test]
    fn validate_spending_ucan_with_attenuation() {
        let parent_cap = sample_capability();
        let child_cap = SpendingCapability {
            max_per_action: Amount(500),
            max_total: Amount(5000),
            currency: usd(),
            time_window: Duration::from_hours(12),
            allowed_adapters: vec!["x402".to_owned()],
        };
        let token = make_spending_token(&child_cap, "scp:spending:ctx123");
        let result =
            validate_spending_ucan(&token, "ctx123", Some(&parent_cap), &scp_clock::SystemClock);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_spending_ucan_attenuation_violation() {
        let parent_cap = SpendingCapability {
            max_per_action: Amount(500),
            max_total: Amount(5000),
            currency: usd(),
            time_window: Duration::from_hours(12),
            allowed_adapters: vec!["x402".to_owned()],
        };
        let child_cap = sample_capability(); // wider than parent
        let token = make_spending_token(&child_cap, "scp:spending:ctx123");
        let err =
            validate_spending_ucan(&token, "ctx123", Some(&parent_cap), &scp_clock::SystemClock)
                .unwrap_err();
        assert!(matches!(err, SpendingError::AttenuationViolation(_)));
    }

    // -----------------------------------------------------------------------
    // SpendingError display
    // -----------------------------------------------------------------------

    #[test]
    fn spending_error_display_messages() {
        let err = SpendingError::SpendingCapabilityRequired("test".to_owned());
        assert_eq!(err.to_string(), "spending capability required: test");

        let err = SpendingError::PerActionLimitExceeded {
            cost: Amount(200),
            max: Amount(100),
            currency: usd(),
        };
        assert!(err.to_string().contains("200"));
        assert!(err.to_string().contains("100"));

        let err = SpendingError::TotalLimitExceeded {
            total: Amount(9000),
            cost: Amount(2000),
            max: Amount(10000),
            currency: usd(),
        };
        assert!(err.to_string().contains("9000"));
        assert!(err.to_string().contains("2000"));
        assert!(err.to_string().contains("10000"));

        let err = SpendingError::ExpiryTooLong {
            actual_secs: 100000,
            max_secs: 86400,
        };
        assert!(err.to_string().contains("100000"));
        assert!(err.to_string().contains("86400"));

        let err = SpendingError::ScopeNotCovered {
            scope: "scp:spending:ctx123".to_owned(),
            context_id: "ctx456".to_owned(),
        };
        assert!(err.to_string().contains("ctx123"));
        assert!(err.to_string().contains("ctx456"));
    }

    // -----------------------------------------------------------------------
    // Integration: mint + validate + budget
    // -----------------------------------------------------------------------

    #[test]
    fn end_to_end_mint_validate_budget() {
        let cap = SpendingCapability {
            max_per_action: Amount(1000),
            max_total: Amount(3000),
            currency: usd(),
            time_window: Duration::from_hours(1),
            allowed_adapters: vec!["x402".to_owned()],
        };

        // Mint a spending UCAN payload.
        let scope = SpendingScope::Context("ctx123".to_owned());
        let params = MintSpendingParams {
            did: "did:dht:z6MkShared",
            key_scope: DEFAULT_SPENDING_KEY_SCOPE,
            scope: &scope,
            capability: &cap,
            lifetime_secs: 3600,
            not_before: None,
        };
        let payload = mint_spending_ucan_payload(&params, &scp_clock::SystemClock).unwrap();

        // Build a token from the payload (skip actual signing for unit test).
        let token = UcanToken {
            header: super::super::UcanHeader::new(),
            payload,
            signature: vec![0u8; 64],
            encoded: String::new(),
        };

        // Validate the spending UCAN.
        let validated_cap =
            validate_spending_ucan(&token, "ctx123", None, &scp_clock::SystemClock).unwrap();
        assert_eq!(validated_cap, cap);

        // Use budget tracker to enforce limits.
        let mut tracker = BudgetTracker::new(validated_cap);
        let now = scp_clock::SystemClock.now_secs();

        // Spend 1000 three times (total 3000 = max_total).
        assert!(
            tracker
                .check_and_record(Amount(1000), usd(), now, "x402")
                .is_ok()
        );
        assert!(
            tracker
                .check_and_record(Amount(1000), usd(), now, "x402")
                .is_ok()
        );
        assert!(
            tracker
                .check_and_record(Amount(1000), usd(), now, "x402")
                .is_ok()
        );

        // Fourth spend should fail (total would exceed max_total).
        let err = tracker
            .check_and_record(Amount(1000), usd(), now, "x402")
            .unwrap_err();
        assert!(matches!(err, SpendingError::TotalLimitExceeded { .. }));
    }

    #[test]
    fn attenuation_to_attenuation_struct() {
        let scope = SpendingScope::Context("ctx123".to_owned());
        let att = SpendingCapability::to_attenuation(&scope);
        assert_eq!(att.with, "scp:spending:ctx123");
        assert_eq!(att.can, "spend");
    }

    // -----------------------------------------------------------------------
    // Adapter restriction enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn check_and_record_rejects_disallowed_adapter() {
        let cap = SpendingCapability {
            max_per_action: Amount(1000),
            max_total: Amount(10000),
            currency: CurrencyCode::from_code("USD").unwrap(),
            time_window: Duration::from_hours(1),
            allowed_adapters: vec!["stripe".to_owned()],
        };
        let mut tracker = BudgetTracker::new(cap);

        // Allowed adapter succeeds
        assert!(
            tracker
                .check_and_record(
                    Amount(100),
                    CurrencyCode::from_code("USD").unwrap(),
                    1000,
                    "stripe"
                )
                .is_ok()
        );

        // Disallowed adapter fails
        let result = tracker.check_and_record(
            Amount(100),
            CurrencyCode::from_code("USD").unwrap(),
            1001,
            "lightning",
        );
        assert!(matches!(
            result,
            Err(SpendingError::AdapterNotAllowed { .. })
        ));
    }

    #[test]
    fn check_and_record_allows_any_adapter_when_list_empty() {
        let cap = SpendingCapability {
            max_per_action: Amount(1000),
            max_total: Amount(10000),
            currency: CurrencyCode::from_code("USD").unwrap(),
            time_window: Duration::from_hours(1),
            allowed_adapters: vec![],
        };
        let mut tracker = BudgetTracker::new(cap);

        // Any adapter should succeed when list is empty
        assert!(
            tracker
                .check_and_record(
                    Amount(100),
                    CurrencyCode::from_code("USD").unwrap(),
                    1000,
                    "anything"
                )
                .is_ok()
        );
    }

    // -----------------------------------------------------------------------
    // Shared-DID model tests (ADR-039, SCP-AB-014)
    // -----------------------------------------------------------------------

    #[test]
    fn mint_spending_self_delegation_iss_equals_aud() {
        let cap = sample_capability();
        let scope = SpendingScope::Context("ctx-self".to_owned());
        let params = MintSpendingParams {
            did: "did:dht:z6MkSharedIdentity",
            key_scope: "#agent",
            scope: &scope,
            capability: &cap,
            lifetime_secs: 1800,
            not_before: None,
        };
        let payload = mint_spending_ucan_payload(&params, &scp_clock::SystemClock).unwrap();

        // Core invariant: self-delegation means iss == aud
        assert_eq!(payload.iss, "did:dht:z6MkSharedIdentity");
        assert_eq!(payload.aud, "did:dht:z6MkSharedIdentity");
        assert_eq!(payload.iss, payload.aud);
    }

    #[test]
    fn mint_spending_includes_key_scope_in_facts() {
        let cap = sample_capability();
        let scope = SpendingScope::Global;
        let params = MintSpendingParams {
            did: "did:dht:z6MkTest",
            key_scope: "#agent",
            scope: &scope,
            capability: &cap,
            lifetime_secs: 3600,
            not_before: None,
        };
        let payload = mint_spending_ucan_payload(&params, &scp_clock::SystemClock).unwrap();

        let fct = payload.fct.as_ref().expect("facts must be present");
        assert_eq!(
            fct.get("scp_key_scope").and_then(|v| v.as_str()),
            Some("#agent"),
            "scp_key_scope must be set to the key_scope parameter"
        );
    }

    #[test]
    fn mint_spending_custom_key_scope() {
        let cap = sample_capability();
        let scope = SpendingScope::Context("ctx-custom".to_owned());
        let params = MintSpendingParams {
            did: "did:dht:z6MkCustom",
            key_scope: "#active",
            scope: &scope,
            capability: &cap,
            lifetime_secs: 3600,
            not_before: None,
        };
        let payload = mint_spending_ucan_payload(&params, &scp_clock::SystemClock).unwrap();

        // Custom key scope should be respected
        let fct = payload.fct.as_ref().unwrap();
        assert_eq!(
            fct.get("scp_key_scope").and_then(|v| v.as_str()),
            Some("#active"),
        );
        // Self-delegation still holds with custom scope
        assert_eq!(payload.iss, payload.aud);
    }

    #[test]
    fn mint_spending_facts_contain_both_capability_and_key_scope() {
        let cap = sample_capability();
        let scope = SpendingScope::Context("ctx-both".to_owned());
        let params = MintSpendingParams {
            did: "did:dht:z6MkBoth",
            key_scope: DEFAULT_SPENDING_KEY_SCOPE,
            scope: &scope,
            capability: &cap,
            lifetime_secs: 3600,
            not_before: None,
        };
        let payload = mint_spending_ucan_payload(&params, &scp_clock::SystemClock).unwrap();

        let fct = payload.fct.as_ref().expect("facts must be present");

        // Both spending_capability and scp_key_scope must coexist in facts
        assert!(
            fct.get("spending_capability").is_some(),
            "spending_capability must be present in facts"
        );
        assert!(
            fct.get("scp_key_scope").is_some(),
            "scp_key_scope must be present in facts"
        );

        // spending_capability must round-trip correctly
        let extracted: SpendingCapability =
            serde_json::from_value(fct["spending_capability"].clone()).unwrap();
        assert_eq!(extracted, cap);
    }

    #[test]
    fn default_spending_key_scope_is_agent() {
        assert_eq!(DEFAULT_SPENDING_KEY_SCOPE, "#agent");
    }

    #[test]
    fn end_to_end_shared_did_mint_and_validate() {
        // Full round-trip: mint with shared-DID model, validate, use budget tracker.
        let cap = SpendingCapability {
            max_per_action: Amount(500),
            max_total: Amount(1500),
            currency: usd(),
            time_window: Duration::from_hours(1),
            allowed_adapters: vec!["x402".to_owned()],
        };

        let scope = SpendingScope::Context("ctx-e2e".to_owned());
        let params = MintSpendingParams {
            did: "did:dht:z6MkE2E",
            key_scope: DEFAULT_SPENDING_KEY_SCOPE,
            scope: &scope,
            capability: &cap,
            lifetime_secs: 3600,
            not_before: None,
        };
        let payload = mint_spending_ucan_payload(&params, &scp_clock::SystemClock).unwrap();

        // Verify self-delegation structure
        assert_eq!(payload.iss, payload.aud);
        let fct = payload.fct.as_ref().unwrap();
        assert_eq!(
            fct.get("scp_key_scope").and_then(|v| v.as_str()),
            Some("#agent")
        );

        // Build token and validate
        let token = UcanToken {
            header: super::super::UcanHeader::new(),
            payload,
            signature: vec![0u8; 64],
            encoded: String::new(),
        };
        let validated_cap =
            validate_spending_ucan(&token, "ctx-e2e", None, &scp_clock::SystemClock).unwrap();
        assert_eq!(validated_cap, cap);

        // Budget tracker works with the validated capability
        let mut tracker = BudgetTracker::new(validated_cap);
        let now = scp_clock::SystemClock.now_secs();

        assert!(
            tracker
                .check_and_record(Amount(500), usd(), now, "x402")
                .is_ok()
        );
        assert!(
            tracker
                .check_and_record(Amount(500), usd(), now, "x402")
                .is_ok()
        );
        assert!(
            tracker
                .check_and_record(Amount(500), usd(), now, "x402")
                .is_ok()
        );
        // Fourth spend exceeds max_total
        assert!(
            tracker
                .check_and_record(Amount(500), usd(), now, "x402")
                .is_err()
        );
    }
}
