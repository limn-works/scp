//! `ChallengerLedgerActor`: one actor per challenger identity. It owns the
//! attempt ledger of every challenge that identity issued (spec 07 §7.3.4
//! steps 1, 3 and 4; spec 09 §9.18.C).
//!
//! # What the ledger decides
//!
//! - **Create** persists the open entry (index first, then entry) and signs
//!   the request digest `D` in the same turn, so no signed request exists
//!   for a challenge the ledger does not hold.
//! - **Lookup** is read-only. The grading path runs it before any DID
//!   resolution, so a response naming an unknown challenge, another request
//!   digest or another subject costs no resolution.
//! - **Begin** returns a stored record for a resubmitted `(attempt, D_r)`
//!   (re-signing a Pending one), else checks the entry, runs
//!   [`check_attempt`] and takes the grading lease.
//! - **Commit** checks the lease, reads `t = now` once, re-runs
//!   [`check_attempt`] at `t`, writes the Pending attempt and any closure in
//!   one write, signs `D_v` and writes the Signed attempt.
//! - **`RecordFault`** counts a challenger fault, which uses no attempt, and
//!   closes the challenge as `Faulted` at [`MAX_GRADING_FAULTS`].
//!
//! # Crash safety (ADR-049 §9, Class S)
//!
//! Every write is fail-closed: a turn replies with an error and leaves its
//! in-memory state unchanged when a write it depends on fails. The record
//! is persisted as Pending before it is signed, so a crash between the two
//! leaves a Pending attempt that the next touching turn re-signs: `D_v` is
//! the same, because the record's `timestamp` was persisted.
//!
//! The grading lease lives in memory only. A restart drops it, which is
//! safe: no Commit can match a lease that no longer exists.
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
use std::time::Duration;

use scp_clock::Clock;
use scp_protocol::context::ContextError;
use scp_protocol::trust::capability_definition::CapabilityDefinition;
use scp_protocol::trust::{
    AnswerKey, AttemptLedgerView, CHALLENGE_CLOCK_SKEW_SECS, CHALLENGE_GRADING_BUDGET_SECS,
    CHALLENGE_LEASE_MARGIN_SECS, CanonicalIdentifier, CaseResult, ChallengeClosure,
    ChallengeRequest, ChallengeVerification, GradeError, GradeOutcome, MAX_GRADING_FAULTS,
    OwnedAuthenticatedResponse, TrustError, UnsignedChallengeRequest,
    challenge_verification_signing_digest, challenge_verification_unsigned, check_attempt,
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
/// [`ContextError::ActorBusy`]. A turn signs at most twice, each bounded by
/// the signer's own timeout.
pub const CHALLENGER_LEDGER_REPLY_TIMEOUT: Duration = Duration::from_mins(1);

/// The most challenges one challenger's ledger holds at once (spec 09
/// §9.18.C). Create refuses beyond it with [`TrustError::ChallengeNotOpen`].
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

/// The state of one graded attempt's record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum AttemptState {
    /// Persisted, not yet signed. Its `verifier_signature` is empty.
    Pending(ChallengeVerification),
    /// Signed.
    Signed(ChallengeVerification),
}

/// One graded attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Attempt {
    /// The attempt number.
    n: u32,
    /// When it was graded (the record's `timestamp`).
    graded_at: u64,
    /// `D_r` of the response graded.
    #[serde(with = "hex_32")]
    response_digest: [u8; 32],
    /// Per-case results, returned to the caller and never signed.
    reasons: Vec<CaseResult>,
    /// The record.
    state: AttemptState,
}

/// One challenge in the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LedgerEntry {
    /// The request, without its signature: the ledger persists it before
    /// signing, and keys every check on `request_digest`.
    request: ChallengeRequest,
    /// `D` of the request.
    #[serde(with = "hex_32")]
    request_digest: [u8; 32],
    /// The subject's canonical key.
    #[serde(with = "hex_32")]
    subject_key: [u8; 32],
    /// The answer key.
    answer_key: AnswerKey,
    /// The definition the request follows.
    definition: CapabilityDefinition,
    /// The context of the `CustomEval` evaluators, if any case has one.
    evaluator_context_id: Option<String>,
    /// Graded attempts, in order.
    attempts: Vec<Attempt>,
    /// Grading faults so far.
    faults: u32,
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
            last_timestamp: last.map(|a| a.graded_at),
            closed: self.closed,
            faults: self.faults,
        }
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

/// A challenger fault: it depends only on the challenger, so it uses no
/// attempt (spec 07 §7.3.4 step 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GradingFault {
    /// An opening does not open its commitment.
    AnswerKeyMismatch(GradeError),
    /// A `SchemaMatch` schema the answer key opens no longer passes the
    /// schema gate, so the challenger cannot grade the case.
    SchemaRejected {
        /// The case.
        test_id: String,
        /// The gate's refusal.
        reason: String,
    },
    /// An evaluator could not run, or its settlement failed after a verdict.
    EvaluatorUnavailable {
        /// The evaluator context.
        context_id: String,
        /// The evaluator outlet.
        outlet_id: String,
        /// Why.
        reason: String,
    },
}

impl From<GradingFault> for TrustError {
    fn from(fault: GradingFault) -> Self {
        match fault {
            GradingFault::AnswerKeyMismatch(error) => error.into(),
            GradingFault::SchemaRejected { test_id, reason } => {
                Self::SchemaRejected { test_id, reason }
            }
            GradingFault::EvaluatorUnavailable {
                context_id,
                outlet_id,
                reason,
            } => Self::EvaluatorUnavailable {
                context_id,
                outlet_id,
                reason,
            },
        }
    }
}

/// What a grading needs after Begin took its lease.
#[derive(Debug, Clone)]
pub struct GradingLease {
    /// Names the lease in Commit and `RecordFault`.
    pub lease_id: u64,
    /// The openings to grade against.
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

/// The result of `RecordFault`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultRecorded {
    /// Faults so far.
    pub faults: u32,
    /// `Some(Faulted)` once the challenge closed.
    pub closed: Option<ChallengeClosure>,
}

/// A command to a [`ChallengerLedgerActor`].
pub enum ChallengerLedgerCommand {
    /// Persist a new challenge and sign its request.
    Create {
        /// The request to sign; its verifier is this ledger's identity.
        unsigned: Box<UnsignedChallengeRequest>,
        /// The openings the challenger keeps.
        answer_key: AnswerKey,
        /// The definition the request follows.
        definition: Box<CapabilityDefinition>,
        /// The `CustomEval` evaluator context, if any.
        evaluator_context_id: Option<String>,
        /// The verifier's `#active` signer.
        signer: CommandSigner,
        /// The signed request.
        reply: Reply<ChallengeRequest>,
    },
    /// Read-only: does a live entry with this id, request digest and subject
    /// exist?
    Lookup {
        /// The challenge.
        challenge_id: [u8; 32],
        /// `D` computed from the caller's request.
        request_digest: [u8; 32],
        /// The request's subject.
        subject: CanonicalIdentifier,
        /// `Ok(())` when it exists.
        reply: Reply<()>,
    },
    /// Begin grading an authenticated response.
    BeginGrade {
        /// The authenticated response.
        auth: Arc<OwnedAuthenticatedResponse>,
        /// Re-signs a Pending record found on resubmit.
        signer: CommandSigner,
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
        /// The challenge.
        challenge_id: [u8; 32],
        /// The lease Begin returned.
        lease_id: u64,
        /// The fault.
        fault: GradingFault,
        /// The fault count and closure.
        reply: Reply<FaultRecorded>,
    },
    /// Stop the actor.
    Shutdown,
}

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

/// Caller-side handle of a [`ChallengerLedgerActor`]. Cheap to clone.
///
/// It also owns the challenger's grading semaphore, so the permit count
/// survives a respawn of the actor: the supervisor hands the old semaphore to
/// the new handle.
#[derive(Clone)]
pub struct ChallengerLedgerHandle {
    inbox: mpsc::Sender<ChallengerLedgerCommand>,
    gradings: Arc<Semaphore>,
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
        Arc::clone(&self.gradings)
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
    next_lease: u64,
    inbox: mpsc::Receiver<ChallengerLedgerCommand>,
}

impl ChallengerLedgerActor {
    /// Spawns on the ambient runtime. Test-only: production spawns through
    /// [`Self::spawn_through`].
    #[cfg(test)]
    pub(in crate::context) fn spawn(
        identity: CanonicalIdentifier,
        deps: ChallengerLedgerDeps,
        gradings: Arc<Semaphore>,
    ) -> (ChallengerLedgerHandle, tokio::task::JoinHandle<()>) {
        let (handle, actor) = Self::new(identity, deps, gradings);
        (handle, tokio::spawn(actor.run()))
    }

    /// Spawns through `permit` onto the supervisor's task tracker (ADR-049
    /// Decision 16).
    pub(in crate::context) fn spawn_through(
        permit: &super::supervisor::SpawnPermit<'_>,
        identity: CanonicalIdentifier,
        deps: ChallengerLedgerDeps,
        gradings: Arc<Semaphore>,
    ) -> (ChallengerLedgerHandle, tokio::task::JoinHandle<()>) {
        let (handle, actor) = Self::new(identity, deps, gradings);
        (handle, permit.spawn(actor.run()))
    }

    fn new(
        identity: CanonicalIdentifier,
        deps: ChallengerLedgerDeps,
        gradings: Arc<Semaphore>,
    ) -> (ChallengerLedgerHandle, Self) {
        let (tx, rx) = mpsc::channel(CHALLENGER_LEDGER_MAILBOX_CAPACITY);
        let actor = Self {
            identity,
            mls_storage: deps.mls_storage,
            clock: deps.clock,
            entries: None,
            leases: HashMap::new(),
            next_lease: 0,
            inbox: rx,
        };
        (
            ChallengerLedgerHandle {
                inbox: tx,
                gradings,
            },
            actor,
        )
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
                definition,
                evaluator_context_id,
                signer,
                reply,
            } => {
                let result = self
                    .handle_create(
                        *unsigned,
                        answer_key,
                        *definition,
                        evaluator_context_id,
                        &signer,
                    )
                    .await;
                let _ = reply.send(result);
            }
            ChallengerLedgerCommand::Lookup {
                challenge_id,
                request_digest,
                subject,
                reply,
            } => {
                let result = self
                    .handle_lookup(&challenge_id, &request_digest, &subject)
                    .await;
                let _ = reply.send(result);
            }
            ChallengerLedgerCommand::BeginGrade {
                auth,
                signer,
                reply,
            } => {
                let result = self.handle_begin(&auth, &signer).await;
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
                challenge_id,
                lease_id,
                fault,
                reply,
            } => {
                let result = self.handle_fault(&challenge_id, lease_id, fault).await;
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
        definition: CapabilityDefinition,
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
        let openings = answer_key.openings().len();
        if openings != request.test_cases.len()
            || definition.capability_uri != request.capability_uri
        {
            return Err(ContextError::InvalidState(
                "challenge create: the answer key or definition does not belong to the request"
                    .to_owned(),
            )
            .into());
        }
        let subject_key = *CanonicalIdentifier::parse(&request.subject)?.key();
        let challenge_id = request.challenge_id;
        let open = self.entries()?.len();
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
        let digest = unsigned.signing_digest();
        let entry = LedgerEntry {
            request: request.clone(),
            request_digest: digest,
            subject_key,
            answer_key,
            definition,
            evaluator_context_id,
            attempts: Vec::new(),
            faults: 0,
            closed: None,
        };
        let mut ids: BTreeSet<[u8; 32]> = self.entries()?.keys().copied().collect();
        ids.insert(challenge_id);
        self.persist_index(&ids).await?;
        self.persist_entry(&entry).await?;
        let signature = match signer.sign_bounded_ed25519(&digest).await {
            Ok(signature) => signature,
            Err(e) => {
                // No signed request exists, so the entry can never be graded;
                // removing it keeps it from counting against the bound.
                self.remove_durable(&challenge_id).await;
                return Err(e.into());
            }
        };
        self.entries_mut()?.insert(challenge_id, entry);
        Ok(unsigned.with_verifier_signature(signature.to_vec()))
    }

    async fn handle_lookup(
        &mut self,
        challenge_id: &[u8; 32],
        request_digest: &[u8; 32],
        subject: &CanonicalIdentifier,
    ) -> Result<(), ChallengeLedgerError> {
        self.ensure_loaded().await?;
        let now = self.clock.now_secs();
        let found = self.entries()?.get(challenge_id).is_some_and(|entry| {
            !entry.is_prunable(now)
                && entry.request_digest == *request_digest
                && entry.subject_key == *subject.key()
        });
        if found {
            Ok(())
        } else {
            Err(unknown(challenge_id).into())
        }
    }

    async fn handle_begin(
        &mut self,
        auth: &OwnedAuthenticatedResponse,
        signer: &CommandSigner,
    ) -> Result<BeginOutcome, ChallengeLedgerError> {
        self.begin_turn().await?;
        let a = auth.as_authenticated();
        let challenge_id = a.request().challenge_id;
        let attempt = a.response().attempt;
        let response_digest = a.response_digest();
        let entry = self
            .entries()?
            .get(&challenge_id)
            .cloned()
            .ok_or_else(|| unknown(&challenge_id))?;

        // 1. Resubmit: the same (attempt, D_r) returns its stored record.
        if let Some(index) = entry
            .attempts
            .iter()
            .position(|x| x.n == attempt && x.response_digest == response_digest)
        {
            let graded = self.signed_attempt(entry, index, signer).await?;
            return Ok(BeginOutcome::Stored(Box::new(graded)));
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

        // 4. The lease.
        if let Some(lease) = self.leases.get(&challenge_id)
            && now <= lease.deadline
        {
            return Err(TrustError::GradingInProgress {
                challenge_id: hex::encode(challenge_id),
            }
            .into());
        }
        self.next_lease = self.next_lease.wrapping_add(1);
        let lease = Lease {
            id: self.next_lease,
            deadline: now.saturating_add(LEASE_SECS),
            attempt,
            response_digest,
        };
        self.leases.insert(challenge_id, lease);
        Ok(BeginOutcome::Lease(GradingLease {
            lease_id: lease.id,
            answer_key: entry.answer_key,
            evaluator_context_id: entry.evaluator_context_id,
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
        self.require_lease(&challenge_id, lease_id, t, Some((attempt, response_digest)))?;
        if entry.request_digest != a.request_digest() {
            return Err(unknown(&challenge_id).into());
        }

        // 2-3. One `t`, and the attempt checked again at `t`.
        if let Err(e) = check_attempt(&entry.view(), attempt, t) {
            self.leases.remove(&challenge_id);
            return Err(e.into());
        }

        // 4-5. The unsigned record and any closure, in one write.
        let unsigned = challenge_verification_unsigned(&a, outcome, t)?;
        let record = unsigned.record().clone();
        let closure = if outcome.passed {
            Some(ChallengeClosure::Passed)
        } else if attempt >= entry.request.max_retries.saturating_add(1) {
            Some(ChallengeClosure::Exhausted)
        } else {
            None
        };
        entry.attempts.push(Attempt {
            n: attempt,
            graded_at: t,
            response_digest,
            reasons: outcome.per_case.clone(),
            state: AttemptState::Pending(record),
        });
        entry.closed = closure;
        self.persist_entry(&entry).await?;
        self.leases.remove(&challenge_id);
        let index = entry.attempts.len() - 1;
        self.entries_mut()?.insert(challenge_id, entry.clone());

        // 6-7. Sign and write the Signed attempt.
        self.signed_attempt(entry, index, signer)
            .await
            .map_err(Into::into)
    }

    async fn handle_fault(
        &mut self,
        challenge_id: &[u8; 32],
        lease_id: u64,
        fault: GradingFault,
    ) -> Result<FaultRecorded, ChallengeLedgerError> {
        self.begin_turn().await?;
        let mut entry = self
            .entries()?
            .get(challenge_id)
            .cloned()
            .ok_or_else(|| unknown(challenge_id))?;
        let now = self.clock.now_secs();
        self.require_lease(challenge_id, lease_id, now, None)?;
        entry.faults = entry.faults.saturating_add(1);
        if entry.faults >= MAX_GRADING_FAULTS {
            entry.closed = Some(ChallengeClosure::Faulted);
        }
        self.persist_entry(&entry).await?;
        self.leases.remove(challenge_id);
        let recorded = FaultRecorded {
            faults: entry.faults,
            closed: entry.closed,
        };
        tracing::warn!(
            actor_kind = "challenger_ledger",
            challenge_id = %hex::encode(challenge_id),
            faults = recorded.faults,
            fault = %TrustError::from(fault),
            "challenger grading fault recorded; no attempt used"
        );
        self.entries_mut()?.insert(*challenge_id, entry);
        Ok(recorded)
    }

    // -----------------------------------------------------------------
    // Turn helpers
    // -----------------------------------------------------------------

    /// Loads the ledger if it has not loaded, then prunes.
    async fn begin_turn(&mut self) -> Result<(), ContextError> {
        self.ensure_loaded().await?;
        self.prune().await
    }

    /// Requires the held lease of `challenge_id` to be `lease_id`, live at
    /// `now`, and, when given, for `(attempt, D_r)`.
    fn require_lease(
        &self,
        challenge_id: &[u8; 32],
        lease_id: u64,
        now: u64,
        response: Option<(u32, [u8; 32])>,
    ) -> Result<(), TrustError> {
        let held = self.leases.get(challenge_id).is_some_and(|lease| {
            lease.id == lease_id
                && now <= lease.deadline
                && response.is_none_or(|(n, d)| lease.attempt == n && lease.response_digest == d)
        });
        if held {
            Ok(())
        } else {
            Err(TrustError::GradingLeaseLost {
                challenge_id: hex::encode(challenge_id),
            })
        }
    }

    /// The signed record of attempt `index`, signing and persisting a
    /// Pending one first.
    async fn signed_attempt(
        &mut self,
        mut entry: LedgerEntry,
        index: usize,
        signer: &CommandSigner,
    ) -> Result<GradedAttempt, ContextError> {
        let challenge_id = entry.request.challenge_id;
        let Some(attempt) = entry.attempts.get_mut(index) else {
            return Err(ContextError::InvalidState(
                "challenger ledger: attempt index out of range".to_owned(),
            ));
        };
        let reasons = attempt.reasons.clone();
        let record = match &attempt.state {
            AttemptState::Signed(record) => {
                return Ok(GradedAttempt {
                    record: record.clone(),
                    reasons,
                });
            }
            AttemptState::Pending(record) => record.clone(),
        };
        let digest = challenge_verification_signing_digest(&record)
            .map_err(|e| ContextError::CryptoFailed(format!("record digest: {e}")))?;
        let signature = signer.sign_bounded_ed25519(&digest).await?;
        let signed_record = ChallengeVerification {
            verifier_signature: signature.to_vec(),
            ..record
        };
        attempt.state = AttemptState::Signed(signed_record.clone());
        self.persist_entry(&entry).await?;
        self.entries_mut()?.insert(challenge_id, entry);
        Ok(GradedAttempt {
            record: signed_record,
            reasons,
        })
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
    /// missing is a Create that failed between the two writes, and is
    /// skipped. Any read or decode failure leaves the ledger unloaded.
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

    /// Drops every entry past `expires_at + CHALLENGE_CLOCK_SKEW_SECS`. The
    /// entries are deleted first and the index rewritten after, so a failed
    /// write leaves the index a superset of the stored entries, which a load
    /// tolerates.
    async fn prune(&mut self) -> Result<(), ContextError> {
        let now = self.clock.now_secs();
        let expired: Vec<[u8; 32]> = self
            .entries()?
            .iter()
            .filter(|(_, entry)| entry.is_prunable(now))
            .map(|(id, _)| *id)
            .collect();
        if expired.is_empty() {
            return Ok(());
        }
        for id in &expired {
            self.mls_storage
                .delete(&self.entry_key(id))
                .await
                .map_err(|e| {
                    ContextError::PersistenceFailed(format!("challenger entry delete: {e}"))
                })?;
            self.entries_mut()?.remove(id);
            self.leases.remove(id);
        }
        let ids: BTreeSet<[u8; 32]> = self.entries()?.keys().copied().collect();
        self.persist_index(&ids).await
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

    /// Removes an entry that was persisted but never signed. A failure is
    /// logged: the entry holds no signed request, so it cannot be graded,
    /// and it is pruned at its expiry.
    async fn remove_durable(&self, challenge_id: &[u8; 32]) {
        if let Err(e) = self.mls_storage.delete(&self.entry_key(challenge_id)).await {
            tracing::warn!(
                actor_kind = "challenger_ledger",
                challenge_id = %hex::encode(challenge_id),
                error = %e,
                "unsigned challenge entry not deleted; it is pruned at expiry"
            );
        }
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
