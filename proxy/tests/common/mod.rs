//! What the end-to-end tests share: a test CA, the real `harbor-proxy`
//! binary, and a mock of the Harbor internal API it syncs from.

#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use futures::StreamExt;
use serde_json::{Value, json};
use tokio::sync::broadcast;

// ---------------------------------------------------------------- certificates

pub struct Pki {
    pub ca_pem: String,
    pub ca_cert: rcgen::Certificate,
    ca_key: rcgen::KeyPair,
}

pub struct Leaf {
    pub chain_pem: String,
    pub key_pem: String,
    pub der: Vec<u8>,
}

impl Pki {
    pub fn new() -> Self {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "harbor test CA");
        let ca_cert = params.self_signed(&ca_key).unwrap();
        Self {
            ca_pem: ca_cert.pem(),
            ca_cert,
            ca_key,
        }
    }

    pub fn leaf(&self, host: &str) -> Leaf {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec![host.to_string()]).unwrap();
        let cert = params.signed_by(&key, &self.ca_cert, &self.ca_key).unwrap();
        Leaf {
            chain_pem: format!("{}{}", cert.pem(), self.ca_pem),
            key_pem: key.serialize_pem(),
            der: cert.der().to_vec(),
        }
    }

    pub fn root_store(&self) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        let der = rustls::pki_types::CertificateDer::from(self.ca_cert.der().to_vec());
        roots.add(der).unwrap();
        roots
    }

    /// A TLS 1.3 client config trusting only this CA, with the given ALPN.
    pub fn client_config(&self, alpn: &[u8]) -> rustls::ClientConfig {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(self.root_store())
            .with_no_client_auth();
        tls.alpn_protocols = vec![alpn.to_vec()];
        tls
    }
}

/// A route table / cert list entry for the mock.
pub fn cert_entry(host: &str, leaf: &Leaf) -> Value {
    json!({ "domain": host, "chain_pem": leaf.chain_pem, "key_pem": leaf.key_pem })
}

// --------------------------------------------------------- mock Harbor server

/// The internal API the proxy syncs from: routes, certificates, and the SSE
/// stream that tells it to reload.
#[derive(Clone)]
pub struct MockHarbor {
    pub routes: Arc<Mutex<Vec<Value>>>,
    pub certs: Arc<Mutex<Vec<Value>>>,
    pub reload: broadcast::Sender<()>,
}

impl MockHarbor {
    pub fn new(routes: Vec<Value>, certs: Vec<Value>) -> Self {
        Self {
            routes: Arc::new(Mutex::new(routes)),
            certs: Arc::new(Mutex::new(certs)),
            reload: broadcast::channel(4).0,
        }
    }

    pub async fn serve(&self) -> SocketAddr {
        serve(
            Router::new()
                .route("/api/internal/routes", get(routes))
                .route("/api/internal/certs", get(certs))
                .route("/api/internal/certs/{host}", post(|| async { "" }))
                .route("/api/internal/events", get(events))
                .with_state(self.clone()),
        )
        .await
    }
}

async fn routes(State(m): State<MockHarbor>) -> impl IntoResponse {
    axum::Json(json!({
        "routes": m.routes.lock().unwrap().clone(),
        "token_lifetime_secs": 3600,
    }))
}

async fn certs(State(m): State<MockHarbor>) -> impl IntoResponse {
    axum::Json(Value::Array(m.certs.lock().unwrap().clone()))
}

async fn events(State(m): State<MockHarbor>) -> impl IntoResponse {
    let rx = tokio_stream::wrappers::BroadcastStream::new(m.reload.subscribe());
    let stream = rx.map(|_| Ok::<_, std::io::Error>(Bytes::from("event: reload\ndata: {}\n\n")));
    // A comment first so the proxy's SSE client sees the stream open.
    let hello = futures::stream::once(async { Ok(Bytes::from(": hi\n\n")) });
    (
        [("content-type", "text/event-stream")],
        Body::from_stream(hello.chain(stream)),
    )
}

pub async fn serve(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    addr
}

// ---------------------------------------------------------------------- proxy

pub struct ProxyProcess {
    child: Child,
    _dir: TempDir,
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A port free on both TCP and UDP (the HTTPS and QUIC listeners share it).
pub fn free_port() -> u16 {
    loop {
        let tcp = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = tcp.local_addr().unwrap().port();
        if std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return port;
        }
    }
}

/// Start the binary on 127.0.0.1 against the mock at `server`.
pub fn start_proxy(server: SocketAddr, https: u16, quic: bool) -> ProxyProcess {
    let dir = tempdir();
    let http = free_port();
    let token = dir.path().join("internal.token");
    std::fs::write(&token, "test-token").unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            "[proxy]\n\
             domain = \"harbor.test\"\n\
             http_addr = \"127.0.0.1:{http}\"\n\
             https_addr = \"127.0.0.1:{https}\"\n\
             quic = {quic}\n\
             internal_token_path = \"{}\"\n\
             server_url = \"http://{server}\"\n",
            token.display()
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_harbor-proxy"))
        .env("CONFIG_PATH", &config)
        .env(
            "RUST_LOG",
            std::env::var("HARBOR_PROXY_TEST_RUST_LOG").unwrap_or_else(|_| "info".into()),
        )
        // The proxy logs to stdout; HARBOR_PROXY_TEST_LOG=1 shows it.
        .stdout(if std::env::var_os("HARBOR_PROXY_TEST_LOG").is_some() {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    ProxyProcess { child, _dir: dir }
}

/// An HTTPS (HTTP/2) client trusting the test CA, with `hosts` resolved to
/// the proxy.
pub fn h2_client(pki: &Pki, https: u16, hosts: &[&str]) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .tls_certs_only([reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).unwrap()])
        .tls_info(true)
        .timeout(Duration::from_secs(10));
    for host in hosts {
        builder = builder.resolve(host, SocketAddr::from((Ipv4Addr::LOCALHOST, https)));
    }
    builder.build().unwrap()
}

/// Wait until the proxy has its routes and certificate for `host`.
pub async fn wait_until_served(client: &reqwest::Client, host: &str, https: u16) {
    eventually(&format!("the proxy to serve {host}"), || async {
        client
            .get(format!("https://{host}:{https}/ready"))
            .send()
            .await
            .is_ok_and(|r| r.status() == 200)
    })
    .await;
}

pub async fn eventually<F, Fut>(what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("timed out waiting for {what}");
}

pub fn tempdir() -> TempDir {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("harbor-proxy-test-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    TempDir(path)
}

pub struct TempDir(std::path::PathBuf);

impl TempDir {
    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
