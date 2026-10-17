//! `ChallengerLedgerActor`: one actor per challenger identity. It owns the
//! attempt ledger of every challenge that identity issued (spec 07 §7.3.4
//! steps 1, 3 and 4; spec 09 §9.18.C).
//!
//! # What the ledger decides
//!
//! - **Create** refuses while the latest challenge to the same subject (by
//!   canonical key) for the same capability is inside its window, closed or
//!   not (RULING 14), and beyond [`MAX_OPEN_CHALLENGES_PER_CHALLENGER`] open
//!   challenges. It then signs the request digest `D`, persists the index
//!   and the entry holding the signed request, and only then inserts the
//!   entry in memory.
//! - **Lookup** is read-only. The grading path runs it before any DID
//!   resolution, so a response naming an unknown challenge, another request
//!   digest, another subject, or a closed challenge it did not already
//!   answer costs no resolution.
//! - **Begin** returns the stored record for a resubmitted `(attempt, D_r)`,
//!   else checks the entry, runs [`check_attempt`] and takes the grading
//!   lease.
//! - **Commit** checks the lease, reads `t = now` once, re-runs
//!   [`check_attempt`] at `t`, signs `D_v`, and persists the signed attempt
//!   and any closure in one write.
//! - **`RecordFault`** records a challenger fault, which uses no attempt and
//!   closes nothing: it sets `last_fault_at`, so the cooldown runs from the
//!   later of the last attempt and the last fault.
//!
//! # Crash safety (ADR-049 §9, Class S)
//!
//! Every write is fail-closed: a turn replies with an error and leaves its
//! in-memory state unchanged when a write it depends on fails. Both
//! signatures are made before the write that records them, and leave the
//! actor only after it succeeds, so a failed write or a crash leaves no
//! signed request or record that the ledger does not hold. A sign failure
//! writes nothing, so the subject's attempt is not used.
//!
//! The grading lease lives in memory only. A restart drops it, which is
//! safe: no Commit can match a lease that no longer exists. Lease ids come
//! from a counter on the handle that a respawn keeps, so a lease taken
//! before a respawn never matches one taken after it.
//!
//! # ADR-049 7a
//!
//! Both signatures are made inside the turn through
//! [`CommandSigner::sign_bounded_ed25519`], carried in the command, so a
//! custody wait is bounded by the signer and the turn never blocks a thread.
//! The ledger never calls the trust store; the FFI layer stores the record
//! after the reply.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use scp_clock::Clock;
use scp_protocol::context::ContextError;
use scp_protocol::trust::{
    AnswerKey, AttemptLedgerView, CHALLENGE_CLOCK_SKEW_SECS, CHALLENGE_GRADING_BUDGET_SECS,
    CHALLENGE_LEASE_MARGIN_SECS, CanonicalIdentifier, CaseResult, ChallengeClosure,
    ChallengeRequest, ChallengeVerification, GradeOutcome, OwnedAuthenticatedResponse, TrustError,
    UnsignedChallengeRequest, challenge_verification_unsigned, check_attempt,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Semaphore, mpsc, oneshot};

use crate::context::actor::signer::CommandSigner;
use crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Mailbox capacity of a `ChallengerLedgerActor`.
pub const CHALLENGER_LEDGER_MAILBOX_CAPACITY: usize = 32;

/// How long a caller waits to enqueue a command before
/// [`ContextError::ActorBusy`].
pub const CHALLENGER_LEDGER_SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a caller waits for a reply after enqueue before
/// [`ContextError::ActorBusy`]. A turn signs at most once, bounded by the
/// signer's own timeout.
pub const CHALLENGER_LEDGER_REPLY_TIMEOUT: Duration = Duration::from_mins(1);

/// The most open challenges one challenger's ledger holds at once (spec 09
/// §9.18.C).
///
/// An open entry is neither closed nor past its prune point. Create
/// refuses beyond it with [`TrustError::ChallengeNotOpen`]. Closed entries do
/// not count; RULING 14 bounds them at one live entry per subject and
/// capability.
pub const MAX_OPEN_CHALLENGES_PER_CHALLENGER: usize = 1024;

/// The most gradings one challenger runs at once (spec 09 §9.18.C). A grading
/// holds one permit until its future and every blocking closure it started
/// have finished.
pub const MAX_CONCURRENT_GRADINGS_PER_CHALLENGER: usize = 8;

/// Seconds a grading lease lives after Begin.
const LEASE_SECS: u64 = CHALLENGE_GRADING_BUDGET_SECS + CHALLENGE_LEASE_MARGIN_SECS;

/// Storage key prefix of one ledger entry.
const ENTRY_PREFIX: &str = "scp-challenger";
/// Storage key prefix of a challenger's index of entry ids.
const INDEX_PREFIX: &str = "scp-challenger-ids";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A ledger refusal: a protocol refusal ([`TrustError`]) or a runtime
/// failure ([`ContextError`]: persistence, custody, a busy actor).
#[derive(Debug, thiserror::Error)]
pub enum ChallengeLedgerError {
    /// The protocol refused the operation.
    #[error(transparent)]
    Trust(#[from] TrustError),
    /// The runtime could not complete it.
    #[error(transparent)]
    Context(#[from] ContextError),
}

type Reply<T> = oneshot::Sender<Result<T, ChallengeLedgerError>>;

// ---------------------------------------------------------------------------
// Ledger records
// ---------------------------------------------------------------------------

/// One graded attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Attempt {
    /// The attempt number.
    n: u32,
    /// `D_r` of the response graded.
    #[serde(with = "hex_32")]
    response_digest: [u8; 32],
    /// Per-case results, returned to the caller and never signed.
    reasons: Vec<CaseResult>,
    /// The signed record. Its `timestamp` is when the attempt was graded.
    record: ChallengeVerification,
}

/// One challenge in the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LedgerEntry {
    /// The signed request. Every check keys on `request_digest`.
    request: ChallengeRequest,
    /// `D` of the request.
    #[serde(with = "hex_32")]
    request_digest: [u8; 32],
    /// The subject's canonical key.
    #[serde(with = "hex_32")]
    subject_key: [u8; 32],
    /// The answer key.
    answer_key: AnswerKey,
    /// The context of the `CustomEval` evaluators, if any case has one.
    evaluator_context_id: Option<String>,
    /// Graded attempts, in order.
    attempts: Vec<Attempt>,
    /// When the last grading fault was recorded.
    last_fault_at: Option<u64>,
    /// Set once the challenge closes.
    closed: Option<ChallengeClosure>,
}

impl LedgerEntry {
    fn view(&self) -> AttemptLedgerView {
        let last = self.attempts.last();
        AttemptLedgerView {
            challenge_id: self.request.challenge_id,
            created_at: self.request.created_at,
            expires_at: self.request.expires_at,
            max_retries: self.request.max_retries,
            cooldown_secs: self.request.cooldown_secs,
            last_attempt: last.map_or(0, |a| a.n),
            last_timestamp: last.map(|a| a.record.timestamp),
            last_fault_at: self.last_fault_at,
            closed: self.closed,
        }
    }

    /// Whether the entry counts against
    /// [`MAX_OPEN_CHALLENGES_PER_CHALLENGER`] at `now`.
    const fn is_open(&self, now: u64) -> bool {
        self.closed.is_none() && !self.is_prunable(now)
    }

    /// Whether `now` is past the point the entry can matter to anyone.
    const fn is_prunable(&self, now: u64) -> bool {
        now > self
            .request
            .expires_at
            .saturating_add(CHALLENGE_CLOCK_SKEW_SECS)
    }
}

mod hex_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        let raw = hex::decode(&text).map_err(serde::de::Error::custom)?;
        raw.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

/// The in-memory grading lease of one challenge.
#[derive(Debug, Clone, Copy)]
struct Lease {
    id: u64,
    deadline: u64,
    attempt: u32,
    response_digest: [u8; 32],
}

// ---------------------------------------------------------------------------
// Command payloads
// ---------------------------------------------------------------------------

/// What a grading needs after Begin took its lease.
#[derive(Debug, Clone)]
pub struct GradingLease {
    /// Names the lease in Commit and `RecordFault`.
    pub lease_id: u64,
    /// The expected outputs to grade against.
    pub answer_key: AnswerKey,
    /// The context of the `CustomEval` evaluators.
    pub evaluator_context_id: Option<String>,
}

/// A signed record with the per-case results it was graded from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GradedAttempt {
    /// The signed record.
    pub record: ChallengeVerification,
    /// Per-case results, never signed.
    pub reasons: Vec<CaseResult>,
}

/// The result of Begin.
#[derive(Debug, Clone)]
pub enum BeginOutcome {
    /// This `(attempt, D_r)` was graded already; nothing is graded again.
    Stored(Box<GradedAttempt>),
    /// The caller holds the lease and grades.
    Lease(GradingLease),
}

/// A command to a [`ChallengerLedgerActor`].
pub enum ChallengerLedgerCommand {
    /// Persist a new challenge and sign its request.
    Create {
        /// The request to sign; its verifier is this ledger's identity.
        unsigned: Box<UnsignedChallengeRequest>,
        /// The expected outputs the challenger keeps.
        answer_key: AnswerKey,
        /// The `CustomEval` evaluator context, if any.
        evaluator_context_id: Option<String>,
        /// The verifier's `#active` signer.
        signer: CommandSigner,
        /// The signed request.
        reply: Reply<ChallengeRequest>,
    },
    /// Read-only: does a live entry with this id, request digest and subject
    /// exist, and, once it is closed, does it hold an attempt for this
    /// response?
    Lookup {
        /// The challenge.
        challenge_id: [u8; 32],
        /// `D` computed from the caller's request.
        request_digest: [u8; 32],
        /// The request's subject.
        subject: CanonicalIdentifier,
        /// `D_r` computed from the caller's response.
        response_digest: [u8; 32],
        /// `Ok(())` when it exists.
        reply: Reply<()>,
    },
    /// Begin grading an authenticated response.
    BeginGrade {
        /// The authenticated response.
        auth: Arc<OwnedAuthenticatedResponse>,
        /// The stored record or the lease.
        reply: Reply<BeginOutcome>,
    },
    /// Record a graded attempt.
    Commit {
        /// The authenticated response graded.
        auth: Arc<OwnedAuthenticatedResponse>,
        /// The lease Begin returned.
        lease_id: u64,
        /// The grading result.
        outcome: GradeOutcome,
        /// The verifier's `#active` signer.
        signer: CommandSigner,
        /// The signed record.
        reply: Reply<GradedAttempt>,
    },
    /// Record a challenger fault.
    RecordFault {
        /// The authenticated response whose grading faulted.
        auth: Arc<OwnedAuthenticatedResponse>,
        /// The lease Begin returned.
        lease_id: u64,
        /// The fault: `SchemaRejected` or `EvaluatorUnavailable`.
        fault: TrustError,
        /// `Ok(())` once the fault is persisted.
        reply: Reply<()>,
    },
    /// Stop the actor.
    Shutdown,
}

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

/// The state of one challenger that outlives a respawn of its actor.
///
/// It holds the grading semaphore, so permits held by unfinished gradings still count,
/// and the lease counter, so a lease id taken before a respawn is never
/// issued again after it. Cheap to clone; clones share both.
#[derive(Clone)]
pub struct ChallengerLedgerShared {
    gradings: Arc<Semaphore>,
    next_lease: Arc<AtomicU64>,
}

impl ChallengerLedgerShared {
    /// A fresh semaphore of [`MAX_CONCURRENT_GRADINGS_PER_CHALLENGER`]
    /// permits and a lease counter at zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            gradings: Arc::new(Semaphore::new(MAX_CONCURRENT_GRADINGS_PER_CHALLENGER)),
            next_lease: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl Default for ChallengerLedgerShared {
    fn default() -> Self {
        Self::new()
    }
}

/// Caller-side handle of a [`ChallengerLedgerActor`]. Cheap to clone.
///
/// It carries the challenger's [`ChallengerLedgerShared`] state; the
/// supervisor hands it from a stopped handle to its replacement.
#[derive(Clone)]
pub struct ChallengerLedgerHandle {
    inbox: mpsc::Sender<ChallengerLedgerCommand>,
    shared: ChallengerLedgerShared,
}

impl ChallengerLedgerHandle {
    /// Whether the actor behind this handle has stopped.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inbox.is_closed()
    }

    /// The challenger's grading semaphore.
    #[must_use]
    pub fn grading_semaphore(&self) -> Arc<Semaphore> {
        Arc::clone(&self.shared.gradings)
    }

    /// The state a replacement actor must keep.
    #[must_use]
    pub fn shared(&self) -> ChallengerLedgerShared {
        self.shared.clone()
    }

    /// Submits a command and awaits its reply.
    ///
    /// # Errors
    ///
    /// [`ContextError::ActorBusy`] when the mailbox stays full for
    /// [`CHALLENGER_LEDGER_SEND_TIMEOUT`], the inbox is closed, the actor
    /// drops the reply, or no reply arrives within
    /// [`CHALLENGER_LEDGER_REPLY_TIMEOUT`]; otherwise the turn's error.
    pub async fn send<T, F>(&self, cmd_factory: F) -> Result<T, ChallengeLedgerError>
    where
        F: FnOnce(Reply<T>) -> ChallengerLedgerCommand,
    {
        let (tx, rx) = oneshot::channel();
        let cmd = cmd_factory(tx);
        match tokio::time::timeout(CHALLENGER_LEDGER_SEND_TIMEOUT, self.inbox.send(cmd)).await {
            Ok(Ok(())) => match tokio::time::timeout(CHALLENGER_LEDGER_REPLY_TIMEOUT, rx).await {
                Ok(Ok(reply)) => reply,
                Ok(Err(_dropped)) => Err(ContextError::ActorBusy(
                    "challenger-ledger actor dropped the reply channel".to_owned(),
                )
                .into()),
                Err(_elapsed) => Err(ContextError::ActorBusy(format!(
                    "challenger-ledger actor did not reply within {} seconds",
                    CHALLENGER_LEDGER_REPLY_TIMEOUT.as_secs()
                ))
                .into()),
            },
            Ok(Err(_closed)) => Err(ContextError::ActorBusy(
                "challenger-ledger actor inbox is closed".to_owned(),
            )
            .into()),
            Err(_elapsed) => Err(ContextError::ActorBusy(format!(
                "challenger-ledger actor mailbox full for {} seconds",
                CHALLENGER_LEDGER_SEND_TIMEOUT.as_secs()
            ))
            .into()),
        }
    }

    /// Asks the actor to stop.
    ///
    /// # Errors
    ///
    /// [`ContextError::ActorBusy`] when the mailbox stays full or is closed.
    pub async fn send_shutdown(&self) -> Result<(), ContextError> {
        match tokio::time::timeout(
            CHALLENGER_LEDGER_SEND_TIMEOUT,
            self.inbox.send(ChallengerLedgerCommand::Shutdown),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_closed)) => Err(ContextError::ActorBusy(
                "challenger-ledger actor inbox is closed".to_owned(),
            )),
            Err(_elapsed) => Err(ContextError::ActorBusy(
                "challenger-ledger actor mailbox full on shutdown".to_owned(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Actor
// ---------------------------------------------------------------------------

/// The collaborators a [`ChallengerLedgerActor`] needs, from the supervisor's
/// provider slots.
pub(in crate::context) struct ChallengerLedgerDeps {
    /// Durable KV of the ledger.
    pub mls_storage: Arc<dyn OpenMlsStorageAdapter>,
    /// The challenger's clock.
    pub clock: Arc<dyn Clock>,
}

/// One per challenger identity. Owns that identity's attempt ledger.
pub struct ChallengerLedgerActor {
    /// The challenger, canonical.
    identity: CanonicalIdentifier,
    mls_storage: Arc<dyn OpenMlsStorageAdapter>,
    clock: Arc<dyn Clock>,
    /// `None` until the durable ledger loads; every command is refused
    /// until then, so the actor never serves from an empty ledger.
    entries: Option<HashMap<[u8; 32], LedgerEntry>>,
    leases: HashMap<[u8; 32], Lease>,
    /// Shared with the handle, so it survives a respawn.
    next_lease: Arc<AtomicU64>,
    inbox: mpsc::Receiver<ChallengerLedgerCommand>,
}

impl ChallengerLedgerActor {
    /// Spawns on the ambient runtime. Test-only: production spawns through
    /// [`Self::spawn_through`].
    #[cfg(test)]
    pub(in crate::context) fn spawn(
        identity: CanonicalIdentifier,
        deps: ChallengerLedgerDeps,
        shared: ChallengerLedgerShared,
    ) -> (ChallengerLedgerHandle, tokio::task::JoinHandle<()>) {
        let (handle, actor) = Self::new(identity, deps, shared);
        (handle, tokio::spawn(actor.run()))
    }

    /// Spawns through `permit` onto the supervisor's task tracker (ADR-049
    /// Decision 16).
    pub(in crate::context) fn spawn_through(
        permit: &super::supervisor::SpawnPermit<'_>,
        identity: CanonicalIdentifier,
        deps: ChallengerLedgerDeps,
        shared: ChallengerLedgerShared,
    ) -> (ChallengerLedgerHandle, tokio::task::JoinHandle<()>) {
        let (handle, actor) = Self::new(identity, deps, shared);
        (handle, permit.spawn(actor.run()))
    }

    fn new(
        identity: CanonicalIdentifier,
        deps: ChallengerLedgerDeps,
        shared: ChallengerLedgerShared,
    ) -> (ChallengerLedgerHandle, Self) {
        let (tx, rx) = mpsc::channel(CHALLENGER_LEDGER_MAILBOX_CAPACITY);
        let actor = Self {
            identity,
            mls_storage: deps.mls_storage,
            clock: deps.clock,
            entries: None,
            leases: HashMap::new(),
            next_lease: Arc::clone(&shared.next_lease),
            inbox: rx,
        };
        (ChallengerLedgerHandle { inbox: tx, shared }, actor)
    }

    async fn run(mut self) {
        if let Err(e) = self.ensure_loaded().await {
            tracing::error!(
                actor_kind = "challenger_ledger",
                identity = %self.identity.as_str(),
                error = %e,
                "challenger ledger failed to load; every command is refused until a load succeeds"
            );
        }
        while let Some(cmd) = self.inbox.recv().await {
            if matches!(cmd, ChallengerLedgerCommand::Shutdown) {
                break;
            }
            self.dispatch(cmd).await;
        }
    }

    async fn dispatch(&mut self, cmd: ChallengerLedgerCommand) {
        match cmd {
            ChallengerLedgerCommand::Create {
                unsigned,
                answer_key,
                evaluator_context_id,
                signer,
                reply,
            } => {
                let result = self
                    .handle_create(*unsigned, answer_key, evaluator_context_id, &signer)
                    .await;
                let _ = reply.send(result);
            }
            ChallengerLedgerCommand::Lookup {
                challenge_id,
                request_digest,
                subject,
                response_digest,
                reply,
            } => {
                let result = self
                    .handle_lookup(&challenge_id, &request_digest, &subject, &response_digest)
                    .await;
                let _ = reply.send(result);
            }
            ChallengerLedgerCommand::BeginGrade { auth, reply } => {
                let result = self.handle_begin(&auth).await;
                let _ = reply.send(result);
            }
            ChallengerLedgerCommand::Commit {
                auth,
                lease_id,
                outcome,
                signer,
                reply,
            } => {
                let result = self.handle_commit(&auth, lease_id, &outcome, &signer).await;
                let _ = reply.send(result);
            }
            ChallengerLedgerCommand::RecordFault {
                auth,
                lease_id,
                fault,
                reply,
            } => {
                let result = self.handle_fault(&auth, lease_id, &fault).await;
                let _ = reply.send(result);
            }
            ChallengerLedgerCommand::Shutdown => {}
        }
    }

    // -----------------------------------------------------------------
    // Turns
    // -----------------------------------------------------------------

    async fn handle_create(
        &mut self,
        unsigned: UnsignedChallengeRequest,
        answer_key: AnswerKey,
        evaluator_context_id: Option<String>,
        signer: &CommandSigner,
    ) -> Result<ChallengeRequest, ChallengeLedgerError> {
        self.begin_turn().await?;
        let request = unsigned.request();
        if CanonicalIdentifier::parse(&request.verifier)? != self.identity {
            return Err(TrustError::ChallengeVerifierMismatch {
                expected: self.identity.as_str().to_owned(),
                got: request.verifier.to_string(),
            }
            .into());
        }
        if answer_key.expected().len() != request.test_cases.len() {
            return Err(ContextError::InvalidState(
                "challenge create: the answer key does not belong to the request".to_owned(),
            )
            .into());
        }
        let subject_key = *CanonicalIdentifier::parse(&request.subject)?.key();
        let challenge_id = request.challenge_id;
        let now = self.clock.now_secs();

        // RULING 14: the latest challenge to this subject for this
        // capability, closed or not, blocks Create until its window ends.
        if let Some(latest) = self
            .entries()?
            .values()
            .filter(|e| {
                e.subject_key == subject_key && e.request.capability_uri == request.capability_uri
            })
            .max_by_key(|e| (e.request.created_at, e.request.expires_at))
            && now < latest.request.expires_at
        {
            return Err(TrustError::ChallengeWindowOpen {
                challenge_id: hex::encode(latest.request.challenge_id),
                expires_at: latest.request.expires_at,
            }
            .into());
        }
        let open = self.entries()?.values().filter(|e| e.is_open(now)).count();
        if open >= MAX_OPEN_CHALLENGES_PER_CHALLENGER {
            return Err(TrustError::ChallengeNotOpen {
                challenger: self.identity.as_str().to_owned(),
                open,
            }
            .into());
        }
        if self.entries()?.contains_key(&challenge_id) {
            return Err(ContextError::InvalidState(format!(
                "challenge {} is already in the ledger",
                hex::encode(challenge_id)
            ))
            .into());
        }

        // Sign first; the signed request leaves the actor only once both
        // writes hold it.
        let digest = unsigned.signing_digest();
        let signature = signer.sign_bounded_ed25519(&digest).await?;
        let issued = unsigned.with_verifier_signature(signature.to_vec());
        let entry = LedgerEntry {
            request: issued.clone(),
            request_digest: digest,
            subject_key,
            answer_key,
            evaluator_context_id,
            attempts: Vec::new(),
            last_fault_at: None,
            closed: None,
        };
        let mut ids: BTreeSet<[u8; 32]> = self.entries()?.keys().copied().collect();
        ids.insert(challenge_id);
        self.persist_index(&ids).await?;
        self.persist_entry(&entry).await?;
        self.entries_mut()?.insert(challenge_id, entry);
        Ok(issued)
    }

    async fn handle_lookup(
        &mut self,
        challenge_id: &[u8; 32],
        request_digest: &[u8; 32],
        subject: &CanonicalIdentifier,
        response_digest: &[u8; 32],
    ) -> Result<(), ChallengeLedgerError> {
        self.ensure_loaded().await?;
        let now = self.clock.now_secs();
        let entry = self
            .entries()?
            .get(challenge_id)
            .filter(|entry| {
                !entry.is_prunable(now)
                    && entry.request_digest == *request_digest
                    && entry.subject_key == *subject.key()
            })
            .ok_or_else(|| unknown(challenge_id))?;
        // A closed entry serves only a resubmit of a response it graded.
        if entry.closed.is_some()
            && !entry
                .attempts
                .iter()
                .any(|x| x.response_digest == *response_digest)
        {
            return Err(TrustError::ChallengeClosed {
                challenge_id: hex::encode(challenge_id),
            }
            .into());
        }
        Ok(())
    }

    async fn handle_begin(
        &mut self,
        auth: &OwnedAuthenticatedResponse,
    ) -> Result<BeginOutcome, ChallengeLedgerError> {
        self.begin_turn().await?;
        let a = auth.as_authenticated();
        let challenge_id = a.request().challenge_id;
        let attempt = a.response().attempt;
        let response_digest = a.response_digest();
        let entry = self
            .entries()?
            .get(&challenge_id)
            .ok_or_else(|| unknown(&challenge_id))?;

        // 1. Resubmit: the same (attempt, D_r) returns its stored record.
        if let Some(stored) = entry
            .attempts
            .iter()
            .find(|x| x.n == attempt && x.response_digest == response_digest)
        {
            return Ok(BeginOutcome::Stored(Box::new(GradedAttempt {
                record: stored.record.clone(),
                reasons: stored.reasons.clone(),
            })));
        }

        // 2. The entry must be the one the response answers.
        if entry.request_digest != a.request_digest()
            || entry.subject_key != *CanonicalIdentifier::parse(&a.request().subject)?.key()
        {
            return Err(unknown(&challenge_id).into());
        }

        // 3. The attempt must be gradable now.
        let now = self.clock.now_secs();
        check_attempt(&entry.view(), attempt, now)?;
        let grading = GradingLease {
            lease_id: 0,
            answer_key: entry.answer_key.clone(),
            evaluator_context_id: entry.evaluator_context_id.clone(),
        };

        // 4. The lease.
        if let Some(lease) = self.leases.get(&challenge_id)
            && now <= lease.deadline
        {
            return Err(TrustError::GradingInProgress {
                challenge_id: hex::encode(challenge_id),
            }
            .into());
        }
        let lease = Lease {
            id: self
                .next_lease
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1),
            deadline: now.saturating_add(LEASE_SECS),
            attempt,
            response_digest,
        };
        self.leases.insert(challenge_id, lease);
        Ok(BeginOutcome::Lease(GradingLease {
            lease_id: lease.id,
            ..grading
        }))
    }

    async fn handle_commit(
        &mut self,
        auth: &OwnedAuthenticatedResponse,
        lease_id: u64,
        outcome: &GradeOutcome,
        signer: &CommandSigner,
    ) -> Result<GradedAttempt, ChallengeLedgerError> {
        self.begin_turn().await?;
        let a = auth.as_authenticated();
        let challenge_id = a.request().challenge_id;
        let attempt = a.response().attempt;
        let response_digest = a.response_digest();
        let mut entry = self
            .entries()?
            .get(&challenge_id)
            .cloned()
            .ok_or_else(|| unknown(&challenge_id))?;

        // 1. The lease must be ours, live, and for this response.
        let t = self.clock.now_secs();
        self.require_lease(&challenge_id, lease_id, t, attempt, response_digest)?;
        if entry.request_digest != a.request_digest() {
            return Err(unknown(&challenge_id).into());
        }

        // 2-7. Every failure from here releases the lease and writes
        // nothing, so the attempt is not used.
        let result = async {
            // 2-3. One `t`, and the attempt checked again at `t`.
            check_attempt(&entry.view(), attempt, t)?;
            // 4-5. Sign the record, then write it and any closure in one
            // write.
            let unsigned = challenge_verification_unsigned(&a, outcome, t)?;
            let signature = signer
                .sign_bounded_ed25519(&unsigned.signing_digest())
                .await?;
            let record = unsigned.with_verifier_signature(signature.to_vec());
            entry.closed = if outcome.passed {
                Some(ChallengeClosure::Passed)
            } else if attempt >= entry.request.max_retries.saturating_add(1) {
                Some(ChallengeClosure::Exhausted)
            } else {
                None
            };
            entry.attempts.push(Attempt {
                n: attempt,
                response_digest,
                reasons: outcome.per_case.clone(),
                record: record.clone(),
            });
            self.persist_entry(&entry).await?;
            Ok::<_, ChallengeLedgerError>(GradedAttempt {
                record,
                reasons: outcome.per_case.clone(),
            })
        }
        .await;
        self.leases.remove(&challenge_id);
        let graded = result?;
        self.entries_mut()?.insert(challenge_id, entry);
        Ok(graded)
    }

    async fn handle_fault(
        &mut self,
        auth: &OwnedAuthenticatedResponse,
        lease_id: u64,
        fault: &TrustError,
    ) -> Result<(), ChallengeLedgerError> {
        self.begin_turn().await?;
        let a = auth.as_authenticated();
        let challenge_id = a.request().challenge_id;
        let mut entry = self
            .entries()?
            .get(&challenge_id)
            .cloned()
            .ok_or_else(|| unknown(&challenge_id))?;
        let now = self.clock.now_secs();
        self.require_lease(
            &challenge_id,
            lease_id,
            now,
            a.response().attempt,
            a.response_digest(),
        )?;
        entry.last_fault_at = Some(now);
        self.persist_entry(&entry).await?;
        self.leases.remove(&challenge_id);
        tracing::warn!(
            actor_kind = "challenger_ledger",
            challenge_id = %hex::encode(challenge_id),
            fault = %fault,
            "challenger grading fault recorded; no attempt used, cooldown restarts"
        );
        self.entries_mut()?.insert(challenge_id, entry);
        Ok(())
    }

    // -----------------------------------------------------------------
    // Turn helpers
    // -----------------------------------------------------------------

    /// Loads the ledger if it has not loaded, then prunes.
    async fn begin_turn(&mut self) -> Result<(), ContextError> {
        self.ensure_loaded().await?;
        self.prune().await;
        Ok(())
    }

    /// Requires the held lease of `challenge_id` to be `lease_id`, live at
    /// `now`, and for `(attempt, D_r)`.
    fn require_lease(
        &self,
        challenge_id: &[u8; 32],
        lease_id: u64,
        now: u64,
        attempt: u32,
        response_digest: [u8; 32],
    ) -> Result<(), TrustError> {
        let held = self.leases.get(challenge_id).is_some_and(|lease| {
            lease.id == lease_id
                && now <= lease.deadline
                && lease.attempt == attempt
                && lease.response_digest == response_digest
        });
        if held {
            Ok(())
        } else {
            Err(TrustError::GradingLeaseLost {
                challenge_id: hex::encode(challenge_id),
            })
        }
    }

    fn entries(&self) -> Result<&HashMap<[u8; 32], LedgerEntry>, ContextError> {
        self.entries.as_ref().ok_or_else(not_loaded)
    }

    fn entries_mut(&mut self) -> Result<&mut HashMap<[u8; 32], LedgerEntry>, ContextError> {
        self.entries.as_mut().ok_or_else(not_loaded)
    }

    // -----------------------------------------------------------------
    // Durable ledger
    // -----------------------------------------------------------------

    fn index_key(&self) -> String {
        format!("{INDEX_PREFIX}/{}", self.identity.as_str())
    }

    fn entry_key(&self, challenge_id: &[u8; 32]) -> String {
        format!(
            "{ENTRY_PREFIX}/{}/{}",
            self.identity.as_str(),
            hex::encode(challenge_id)
        )
    }

    /// Loads the index and every entry it names. An id whose entry is
    /// missing is a Create whose entry write failed after its index write.
    /// It is skipped, so it is absent from memory, and the next index write
    /// drops it. Any read or decode failure leaves the ledger unloaded.
    async fn ensure_loaded(&mut self) -> Result<(), ContextError> {
        if self.entries.is_some() {
            return Ok(());
        }
        let ids: Vec<String> = match self
            .mls_storage
            .retrieve(&self.index_key())
            .await
            .map_err(|e| ContextError::PersistenceFailed(format!("challenger index read: {e}")))?
        {
            Some(bytes) => rmp_serde::from_slice(&bytes).map_err(|e| {
                ContextError::PersistenceFailed(format!("challenger index decode: {e}"))
            })?,
            None => Vec::new(),
        };
        let mut entries = HashMap::with_capacity(ids.len());
        for id in ids {
            let challenge_id: [u8; 32] = hex::decode(&id)
                .ok()
                .and_then(|raw| raw.try_into().ok())
                .ok_or_else(|| {
                    ContextError::PersistenceFailed(format!("challenger index holds {id:?}"))
                })?;
            let Some(bytes) = self
                .mls_storage
                .retrieve(&self.entry_key(&challenge_id))
                .await
                .map_err(|e| {
                    ContextError::PersistenceFailed(format!("challenger entry read: {e}"))
                })?
            else {
                continue;
            };
            let entry: LedgerEntry = rmp_serde::from_slice(&bytes).map_err(|e| {
                ContextError::PersistenceFailed(format!("challenger entry decode: {e}"))
            })?;
            entries.insert(challenge_id, entry);
        }
        self.entries = Some(entries);
        Ok(())
    }

    /// Drops every entry past `expires_at + CHALLENGE_CLOCK_SKEW_SECS`.
    /// Best-effort: no turn depends on it, so a failure is logged and never
    /// refuses the turn. An entry whose delete fails stays in memory and in
    /// the index, prunable, and the next turn retries it; it no longer counts
    /// as open, and its window has ended, so it blocks nothing. The entries
    /// are deleted first and the index rewritten after, so a failed index
    /// write leaves the index a superset of the stored entries, which a load
    /// tolerates.
    async fn prune(&mut self) {
        let now = self.clock.now_secs();
        let Some(entries) = self.entries.as_ref() else {
            return;
        };
        let expired: Vec<[u8; 32]> = entries
            .iter()
            .filter(|(_, entry)| entry.is_prunable(now))
            .map(|(id, _)| *id)
            .collect();
        if expired.is_empty() {
            return;
        }
        let mut removed = 0_usize;
        for id in &expired {
            if let Err(e) = self.mls_storage.delete(&self.entry_key(id)).await {
                tracing::warn!(
                    actor_kind = "challenger_ledger",
                    challenge_id = %hex::encode(id),
                    error = %e,
                    "expired challenge entry not deleted; retried on the next turn"
                );
                continue;
            }
            if let Some(entries) = self.entries.as_mut() {
                entries.remove(id);
            }
            self.leases.remove(id);
            removed += 1;
        }
        if removed == 0 {
            return;
        }
        let Some(entries) = self.entries.as_ref() else {
            return;
        };
        let ids: BTreeSet<[u8; 32]> = entries.keys().copied().collect();
        if let Err(e) = self.persist_index(&ids).await {
            tracing::warn!(
                actor_kind = "challenger_ledger",
                identity = %self.identity.as_str(),
                error = %e,
                "challenger index not rewritten after prune; it names deleted entries until the next write"
            );
        }
    }

    async fn persist_index(&self, ids: &BTreeSet<[u8; 32]>) -> Result<(), ContextError> {
        let ids: Vec<String> = ids.iter().map(hex::encode).collect();
        let bytes = rmp_serde::to_vec_named(&ids).map_err(|e| {
            ContextError::PersistenceFailed(format!("challenger index encode: {e}"))
        })?;
        self.mls_storage
            .store(&self.index_key(), &bytes)
            .await
            .map_err(|e| ContextError::PersistenceFailed(format!("challenger index write: {e}")))
    }

    async fn persist_entry(&self, entry: &LedgerEntry) -> Result<(), ContextError> {
        let bytes = rmp_serde::to_vec_named(entry).map_err(|e| {
            ContextError::PersistenceFailed(format!("challenger entry encode: {e}"))
        })?;
        self.mls_storage
            .store(&self.entry_key(&entry.request.challenge_id), &bytes)
            .await
            .map_err(|e| ContextError::PersistenceFailed(format!("challenger entry write: {e}")))
    }
}

fn unknown(challenge_id: &[u8; 32]) -> TrustError {
    TrustError::UnknownChallenge {
        challenge_id: hex::encode(challenge_id),
    }
}

fn not_loaded() -> ContextError {
    ContextError::PersistenceFailed("challenger ledger is not loaded".to_owned())
}

#[cfg(test)]
#[path = "challenger_ledger_actor_tests.rs"]
mod tests;
