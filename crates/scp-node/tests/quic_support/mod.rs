//! Shared harness for the QUIC listener integration tests: a domain-mode node
//! whose public listeners bind port 0, served in the background with the
//! addresses [`ApplicationNode::bind`] reports, and clients that skip
//! certificate verification for the node's self-signed certificate.
//!
//! The node binds port 0 itself and reports what it bound, so no test learns a
//! port before the code under test binds it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Endpoint};
use scp_transport::native::storage::BlobStorageBackend;
use scp_transport::quic::listener::SCP_ALPN;

use scp_clock::SystemClock;
use scp_dht::InMemoryDhtClient;
use scp_identity::DidCache;
use scp_identity::dht::DidDht;
use scp_node::{ApplicationNode, DhtMode, IdentitySource, Node, NodeConfig, NodeError, Reach};
use scp_platform::in_memory::InMemoryStorage;
use scp_platform::testing::InMemoryKeyCustody;

type TestDidDht = DidDht<InMemoryDhtClient, SystemClock>;

/// A rustls server-certificate verifier that accepts any certificate.
///
/// Test-only: the node generates its self-signed certificate internally, so the
/// QUIC and WebSocket clients have no way to pin it. Skipping verification is acceptable here
/// because the test only exercises transport plumbing, not TLS trust.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Installs the process-wide rustls crypto provider exactly once.
///
/// Both the node's TLS stack and the client config builders require a default
/// [`rustls::crypto::CryptoProvider`]; installing it is idempotent (a second
/// call returns `Err`, which we ignore).
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Builds a rustls client config that trusts any server certificate and offers
/// the given ALPN protocols.
pub fn insecure_rustls_client_config(alpn_protocols: Vec<Vec<u8>>) -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification(Arc::clone(&provider))))
        .with_no_client_auth();
    tls_config.alpn_protocols = alpn_protocols;
    tls_config
}

/// Builds a QUIC client config that trusts any server certificate and
/// negotiates the SCP ALPN.
fn insecure_quic_client_config() -> ClientConfig {
    let tls_config = insecure_rustls_client_config(vec![SCP_ALPN.to_vec()]);
    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).unwrap();
    ClientConfig::new(Arc::new(quic_client_config))
}

/// Builds a domain-mode node with a self-signed certificate (so a QUIC server
/// config is provisioned) whose public HTTP/TLS listener asks the OS for a
/// port: [`ApplicationNode::bind`] reports the bound TCP and QUIC addresses, so
/// no port is learned before the node binds it.
pub async fn build_tls_node() -> ApplicationNode<InMemoryStorage> {
    let custody = Arc::new(InMemoryKeyCustody::new());
    let dht_client = Arc::new(InMemoryDhtClient::new());
    let cache = Arc::new(DidCache::new());
    let sign_fn = TestDidDht::make_sign_fn(Arc::clone(&custody));
    let did_method = Arc::new(TestDidDht::with_client_and_signer(
        dht_client, cache, sign_fn,
    ));

    // Default `TlsMode::SelfSigned` reproduces the dropped explicit
    // `SelfSignedTlsProvider::new("localhost")` (so a QUIC server config is
    // provisioned). The node opts into `DhtMode::Production` (M2 accepts
    // `Disabled` for every `Reach`, `Domain` included), which makes the start
    // publish through `did_method` and fail if that publish fails.
    Node::start_for_testing(NodeConfig {
        http_bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        dht: DhtMode::Production,
        ..NodeConfig::defaults(
            Reach::Domain {
                domain: "localhost".to_owned(),
            },
            IdentitySource::Generate {
                custody,
                did_method,
            },
            InMemoryStorage::new(),
            BlobStorageBackend::in_memory(),
        )
    })
    .await
    .expect("node build should succeed")
}

/// A node serving in a background task, with the addresses its listeners bound.
pub struct Serving {
    pub http_addr: SocketAddr,
    pub quic_addr: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<(), NodeError>>,
}

impl Serving {
    /// Stops the node and fails the test if `serve()` returned an error.
    pub async fn stop(self) {
        let _ = self.shutdown.send(());
        self.task
            .await
            .expect("serve task must not panic")
            .expect("serve() must shut down without error");
    }
}

/// Binds `node`, asserts its QUIC listener is running, and serves it in the
/// background until [`Serving::stop`].
pub async fn serve_in_background(node: ApplicationNode<InMemoryStorage>) -> Serving {
    let bound = node
        .bind()
        .await
        .expect("bind() must bind the public listeners");
    let http_addr = bound.http_addr();
    let quic_addr = bound
        .quic_addr()
        .expect("the QUIC listener must be running on the bound port");
    assert_eq!(
        quic_addr.port(),
        http_addr.port(),
        "QUIC must share the TCP listener's port (spec §10.14.3 item 1)"
    );
    let (shutdown, rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(bound.serve(axum::Router::new(), async move {
        let _ = rx.await;
    }));
    Serving {
        http_addr,
        quic_addr,
        shutdown,
        task,
    }
}

/// Total time [`connect_quic`] spends before failing the test.
pub const CONNECT_DEADLINE: Duration = Duration::from_secs(10);

/// Connects a QUIC client to the serving node's QUIC listener, retrying until
/// it accepts or [`CONNECT_DEADLINE`] elapses. Each attempt is bounded by the
/// remaining time, so the test fails at the deadline with the last error; it
/// also fails at once with the serve error if `serve()` exits first.
pub async fn connect_quic(serving: &mut Serving) -> quinn::Connection {
    let addr = serving.quic_addr;
    let mut endpoint = Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    endpoint.set_default_client_config(insecure_quic_client_config());

    let deadline = tokio::time::Instant::now() + CONNECT_DEADLINE;
    let mut last_error = String::from("no attempt completed");
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "QUIC connection to {addr} never succeeded within {CONNECT_DEADLINE:?}: {last_error}"
        );
        let attempt = tokio::time::timeout(remaining, endpoint.connect(addr, "localhost").unwrap());
        tokio::select! {
            result = &mut serving.task => {
                panic!("serve() exited before the QUIC connection was made: {result:?}");
            }
            outcome = attempt => match outcome {
                Ok(Ok(conn)) => return conn,
                Ok(Err(e)) => last_error = e.to_string(),
                Err(_) => last_error = String::from("attempt timed out at the deadline"),
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
