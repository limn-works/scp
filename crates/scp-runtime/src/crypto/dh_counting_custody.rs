//! Test custody that counts its calls, `dh_agree` and `generate_keypair` calls
//! separately, so a
//! round-trip test can prove the access-key open path performs exactly one key
//! agreement, and a restart test can prove a wrapping key is generated once.
//! It records every handle it generates and can be told to refuse
//! `public_key`, to report a substitute public key, or never to answer
//! `public_key` or `dh_agree`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use tokio::sync::Notify;

use scp_platform::PlatformError;
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::{
    CustodyType, KeyCustody, KeyHandle, KeyType, Pseudonym, PublicKey, SharedSecret, Signature,
};

/// [`InMemoryKeyCustody`] that counts [`KeyCustody::dh_agree`] and
/// [`KeyCustody::generate_keypair`] calls and otherwise delegates every call
/// unchanged.
pub struct DhCountingCustody {
    pub inner: InMemoryKeyCustody,
    calls: AtomicUsize,
    dh_calls: AtomicUsize,
    generate_calls: AtomicUsize,
    generate_gate: Option<GenerateGate>,
    generated: RwLock<Vec<KeyHandle>>,
    public_key_fault: RwLock<Option<PublicKeyFault>>,
    dh_hang: AtomicBool,
    hang_entered: Arc<Notify>,
}

/// What `public_key` answers instead of the key's public key.
#[derive(Clone)]
pub enum PublicKeyFault {
    /// Refuses with `PlatformError::CustodyError` carrying this text.
    Refuse(String),
    /// Reports these bytes as the public key.
    Bytes(Vec<u8>),
    /// Never answers, after signalling [`DhCountingCustody::hang_entered`].
    Hang,
}

/// Holds `generate_keypair` open: the call signals `entered`, then waits for
/// `release` before generating.
#[derive(Clone, Default)]
pub struct GenerateGate {
    pub entered: Arc<Notify>,
    pub release: Arc<Notify>,
}

impl DhCountingCustody {
    pub fn new() -> Self {
        Self {
            inner: InMemoryKeyCustody::new(),
            calls: AtomicUsize::new(0),
            dh_calls: AtomicUsize::new(0),
            generate_calls: AtomicUsize::new(0),
            generate_gate: None,
            generated: RwLock::new(Vec::new()),
            public_key_fault: RwLock::new(None),
            dh_hang: AtomicBool::new(false),
            hang_entered: Arc::new(Notify::new()),
        }
    }

    /// A custody whose every `generate_keypair` waits on the returned gate.
    pub fn with_generate_gate() -> (Self, GenerateGate) {
        let gate = GenerateGate::default();
        let custody = Self {
            generate_gate: Some(gate.clone()),
            ..Self::new()
        };
        (custody, gate)
    }

    /// The number of calls of every [`KeyCustody`] method so far, whatever
    /// their outcome.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// The number of `dh_agree` calls so far, whatever their outcome.
    pub fn dh_calls(&self) -> usize {
        self.dh_calls.load(Ordering::SeqCst)
    }

    /// The number of `generate_keypair` calls so far, whatever their outcome.
    pub fn generate_calls(&self) -> usize {
        self.generate_calls.load(Ordering::SeqCst)
    }

    /// Every handle `generate_keypair` returned, oldest first.
    pub fn generated_handles(&self) -> Vec<KeyHandle> {
        self.generated
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Makes every later `public_key` call answer `fault`; `None` restores
    /// the real answer.
    pub fn set_public_key_fault(&self, fault: Option<PublicKeyFault>) {
        *self
            .public_key_fault
            .write()
            .unwrap_or_else(PoisonError::into_inner) = fault;
    }

    /// Makes every later `dh_agree` call never answer (`true`), or answer
    /// again (`false`).
    pub fn set_dh_hang(&self, hang: bool) {
        self.dh_hang.store(hang, Ordering::SeqCst);
    }

    /// Notified each time a hanging `public_key` or `dh_agree` call starts.
    pub fn hang_entered(&self) -> Arc<Notify> {
        Arc::clone(&self.hang_entered)
    }
}

impl KeyCustody for DhCountingCustody {
    async fn generate_keypair(&self, key_type: KeyType) -> Result<KeyHandle, PlatformError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.generate_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = &self.generate_gate {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
        let handle = self.inner.generate_keypair(key_type).await?;
        self.generated
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push(handle);
        Ok(handle)
    }

    async fn generate_identity_keypair(&self) -> Result<KeyHandle, PlatformError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.generate_identity_keypair().await
    }

    async fn sign(&self, key: &KeyHandle, data: &[u8]) -> Result<Signature, PlatformError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sign(key, data).await
    }

    async fn public_key(&self, key: &KeyHandle) -> Result<PublicKey, PlatformError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let fault = self
            .public_key_fault
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        match fault {
            None => self.inner.public_key(key).await,
            Some(PublicKeyFault::Refuse(detail)) => Err(PlatformError::CustodyError(detail)),
            Some(PublicKeyFault::Bytes(bytes)) => Ok(PublicKey::new(bytes)),
            Some(PublicKeyFault::Hang) => {
                self.hang_entered.notify_one();
                std::future::pending().await
            }
        }
    }

    async fn destroy_key(&self, key: &KeyHandle) -> Result<(), PlatformError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.destroy_key(key).await
    }

    async fn dh_agree(
        &self,
        key: &KeyHandle,
        peer_public: &[u8],
    ) -> Result<SharedSecret, PlatformError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.dh_calls.fetch_add(1, Ordering::SeqCst);
        if self.dh_hang.load(Ordering::SeqCst) {
            self.hang_entered.notify_one();
            return std::future::pending().await;
        }
        self.inner.dh_agree(key, peer_public).await
    }

    async fn derive_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
    ) -> Result<Pseudonym, PlatformError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.derive_pseudonym(key, context_id).await
    }

    async fn derive_rotatable_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
        pseudonym_epoch: u64,
    ) -> Result<Pseudonym, PlatformError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .derive_rotatable_pseudonym(key, context_id, pseudonym_epoch)
            .await
    }

    fn custody_type(&self, key: &KeyHandle) -> CustodyType {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.custody_type(key)
    }
}
