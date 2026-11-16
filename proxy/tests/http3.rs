//! End-to-end: the real `harbor-proxy` binary, fed routes and certificates by
//! a mock Harbor server, in front of an echo upstream. The same requests go
//! over HTTP/2 (TCP + BoringSSL) and HTTP/3 (QUIC + rustls) and must come out
//! of the proxy the same way.

use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Method, Uri};
use axum::response::IntoResponse;
use axum::routing::{any, get, post};
use bytes::Buf;
use futures::StreamExt;
use serde_json::{Value, json};
use tokio::sync::broadcast;

const APP_HOST: &str = "app.test";

// ---------------------------------------------------------------- certificates

struct Pki {
    ca_pem: String,
    ca_cert: rcgen::Certificate,
    ca_key: rcgen::KeyPair,
}

struct Leaf {
    chain_pem: String,
    key_pem: String,
    der: Vec<u8>,
}

impl Pki {
    fn new() -> Self {
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

    fn leaf(&self, host: &str) -> Leaf {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec![host.to_string()]).unwrap();
        let cert = params.signed_by(&key, &self.ca_cert, &self.ca_key).unwrap();
        Leaf {
            chain_pem: format!("{}{}", cert.pem(), self.ca_pem),
            key_pem: key.serialize_pem(),
            der: cert.der().to_vec(),
        }
    }
}

// ------------------------------------------------------------------- upstream

/// Answers with what it received, plus headers the edge is meant to replace.
async fn echo(method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    let headers: serde_json::Map<String, Value> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), json!(v.to_str().unwrap_or(""))))
        .collect();
    let body = json!({
        "method": method.as_str(),
        "path": uri.path_and_query().map(|p| p.as_str()).unwrap_or(""),
        "headers": headers,
        "body_len": body.len(),
        "body_sha": format!("{:x}", fingerprint(&body)),
    });
    (
        [
            ("alt-svc", "h3=\":9\"; ma=1"),
            ("server", "nginx/1.0 (upstream)"),
            ("content-type", "application/json"),
        ],
        body.to_string(),
    )
}

fn fingerprint(data: &[u8]) -> u64 {
    // Cheap content fingerprint (FNV-1a); enough to tell bodies apart.
    data.iter().fold(0xcbf29ce484222325u64, |h, b| {
        (h ^ *b as u64).wrapping_mul(0x100000001b3)
    })
}

// --------------------------------------------------------- mock Harbor server

#[derive(Clone)]
struct Mock {
    upstream: String,
    certs: Arc<Mutex<Vec<Value>>>,
    reload: broadcast::Sender<()>,
}

async fn routes(State(m): State<Mock>) -> impl IntoResponse {
    axum::Json(json!({
        "routes": [{ "host": APP_HOST, "path_prefix": "/", "upstream": m.upstream }],
        "token_lifetime_secs": 3600,
    }))
}

async fn certs(State(m): State<Mock>) -> impl IntoResponse {
    axum::Json(Value::Array(m.certs.lock().unwrap().clone()))
}

async fn events(State(m): State<Mock>) -> impl IntoResponse {
    let rx = tokio_stream::wrappers::BroadcastStream::new(m.reload.subscribe());
    let stream = rx.map(|_| Ok::<_, std::io::Error>(Bytes::from("event: reload\ndata: {}\n\n")));
    // A comment first so the proxy's SSE client sees the stream open.
    let hello = futures::stream::once(async { Ok(Bytes::from(": hi\n\n")) });
    (
        [("content-type", "text/event-stream")],
        Body::from_stream(hello.chain(stream)),
    )
}

async fn serve(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    addr
}

// ---------------------------------------------------------------------- proxy

struct ProxyProcess(Child);

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A port free on both TCP and UDP (the HTTPS and QUIC listeners share it).
fn free_port() -> u16 {
    loop {
        let tcp = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = tcp.local_addr().unwrap().port();
        if std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return port;
        }
    }
}

fn start_proxy(
    dir: &std::path::Path,
    server: SocketAddr,
    http: u16,
    https: u16,
    quic: bool,
) -> ProxyProcess {
    let token = dir.join("internal.token");
    std::fs::write(&token, "test-token").unwrap();
    let config = dir.join("config.toml");
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
        .env("RUST_LOG", "info")
        // The proxy logs to stdout; HARBOR_PROXY_TEST_LOG=1 shows it.
        .stdout(if std::env::var_os("HARBOR_PROXY_TEST_LOG").is_some() {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    ProxyProcess(child)
}

// -------------------------------------------------------------------- clients

fn root_store(pki: &Pki) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    let der = rustls::pki_types::CertificateDer::from(pki.ca_cert.der().to_vec());
    roots.add(der).unwrap();
    roots
}

fn h2_client(pki: &Pki, https: u16) -> reqwest::Client {
    reqwest::Client::builder()
        .tls_certs_only([reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).unwrap()])
        .resolve(APP_HOST, SocketAddr::from((Ipv4Addr::LOCALHOST, https)))
        .resolve(
            "unknown.test",
            SocketAddr::from((Ipv4Addr::LOCALHOST, https)),
        )
        .tls_info(true)
        .http2_adaptive_window(true)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

struct H3Response {
    status: u16,
    headers: http::HeaderMap,
    body: Vec<u8>,
    peer_cert: Vec<u8>,
}

/// One HTTP/3 request on a fresh QUIC connection.
async fn h3_request(
    pki: &Pki,
    https: u16,
    host: &str,
    method: &str,
    path: &str,
    body: Option<Vec<u8>>,
) -> anyhow::Result<H3Response> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(root_store(pki))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut endpoint = quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into())?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));

    let conn = endpoint
        .connect((Ipv4Addr::LOCALHOST, https).into(), host)?
        .await?;
    let peer_cert = conn
        .peer_identity()
        .and_then(|id| {
            id.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                .ok()
        })
        .and_then(|certs| certs.first().map(|c| c.to_vec()))
        .unwrap_or_default();

    let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn)).await?;
    let drive = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let req = http::Request::builder()
        .method(method)
        .uri(format!("https://{host}:{https}{path}"))
        .body(())?;
    let mut stream = send.send_request(req).await?;
    if let Some(body) = body {
        for chunk in body.chunks(16 * 1024) {
            stream.send_data(Bytes::copy_from_slice(chunk)).await?;
        }
    }
    stream.finish().await?;

    let resp = stream.recv_response().await?;
    let mut out = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        out.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    drop(send);
    drive.abort();
    endpoint.close(0u32.into(), b"");
    Ok(H3Response {
        status: resp.status().as_u16(),
        headers: resp.headers().clone(),
        body: out,
        peer_cert,
    })
}

fn tls_peer_cert(resp: &reqwest::Response) -> Vec<u8> {
    resp.extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|i| i.peer_certificate())
        .map(|c| c.to_vec())
        .unwrap_or_default()
}

async fn eventually<F, Fut>(what: &str, mut f: F)
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

/// The upstream-facing parts the edge sets: these must not depend on the
/// visitor's HTTP version.
fn edge_view(echo: &Value) -> Value {
    let h = &echo["headers"];
    json!({
        "method": echo["method"],
        "path": echo["path"],
        "host": h["host"],
        "x-forwarded-for": h["x-forwarded-for"],
        "x-forwarded-proto": h["x-forwarded-proto"],
        "x-forwarded-host": h["x-forwarded-host"],
        "transfer-encoding": h["transfer-encoding"],
        "content-length": h["content-length"],
        "body_len": echo["body_len"],
        "body_sha": echo["body_sha"],
    })
}

/// The edge's own response headers, which both transports must carry alike.
fn edge_headers(h: &http::HeaderMap) -> Value {
    let get = |n: &str| h.get(n).and_then(|v| v.to_str().ok()).map(str::to_string);
    json!({
        "strict-transport-security": get("strict-transport-security"),
        "x-content-type-options": get("x-content-type-options"),
        "x-frame-options": get("x-frame-options"),
        "server": get("server"),
        "alt-svc": get("alt-svc"),
    })
}

// ---------------------------------------------------------------------- tests

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http3_is_routed_like_http2_and_advertised() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pki = Pki::new();
    let leaf_a = pki.leaf(APP_HOST);
    let leaf_b = pki.leaf(APP_HOST);

    let upstream = serve(Router::new().fallback(any(echo))).await;
    let (reload, _) = broadcast::channel(4);
    let mock = Mock {
        upstream: upstream.to_string(),
        certs: Arc::new(Mutex::new(vec![json!({
            "domain": APP_HOST, "chain_pem": leaf_a.chain_pem, "key_pem": leaf_a.key_pem,
        })])),
        reload: reload.clone(),
    };
    let server = serve(
        Router::new()
            .route("/api/internal/routes", get(routes))
            .route("/api/internal/certs", get(certs))
            .route("/api/internal/certs/{host}", post(|| async { "" }))
            .route("/api/internal/events", get(events))
            .with_state(mock.clone()),
    )
    .await;

    let dir = tempdir();
    let https = free_port();
    let _proxy = start_proxy(dir.path(), server, free_port(), https, true);
    let h2 = h2_client(&pki, https);

    // Routes and certificate A loaded: an HTTP/2 request verifies against the CA.
    eventually("the proxy to serve app.test over HTTP/2", || async {
        h2.get(format!("https://{APP_HOST}:{https}/ready"))
            .send()
            .await
            .is_ok_and(|r| r.status() == 200)
    })
    .await;

    // --- GET, both ways
    let r2 = h2
        .get(format!("https://{APP_HOST}:{https}/echo?x=1"))
        .send()
        .await
        .unwrap();
    assert_eq!(r2.version(), http::Version::HTTP_2);
    let h2_headers = r2.headers().clone();
    let h2_echo: Value = r2.json().await.unwrap();

    let r3 = h3_request(&pki, https, APP_HOST, "GET", "/echo?x=1", None)
        .await
        .unwrap();
    assert_eq!(r3.status, 200);
    let h3_echo: Value = serde_json::from_slice(&r3.body).unwrap();

    assert_eq!(edge_view(&h2_echo), edge_view(&h3_echo));
    assert_eq!(h3_echo["headers"]["host"], format!("{APP_HOST}:{https}"));
    assert_eq!(h3_echo["headers"]["x-forwarded-proto"], "https");
    assert_eq!(h3_echo["headers"]["x-forwarded-for"], "127.0.0.1");
    assert!(
        h3_echo["headers"]["transfer-encoding"].is_null(),
        "bodiless GET went upstream chunked"
    );

    // Edge headers: identical on both, Alt-Svc names the UDP port, and the
    // upstream's own Alt-Svc / Server never reach the visitor.
    let expected_alt_svc = format!("h3=\":{https}\"; ma=86400");
    assert_eq!(edge_headers(&h2_headers), edge_headers(&r3.headers));
    assert_eq!(h2_headers["alt-svc"], expected_alt_svc.as_str());
    assert!(h2_headers.get("server").is_none());
    assert_eq!(
        h2_headers["strict-transport-security"],
        "max-age=63072000; includeSubDomains"
    );

    // --- POST with a body larger than one flow-control window
    let body: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let r2 = h2
        .post(format!("https://{APP_HOST}:{https}/upload"))
        .body(body.clone())
        .send()
        .await
        .unwrap();
    let h2_echo: Value = r2.json().await.unwrap();
    let r3 = h3_request(&pki, https, APP_HOST, "POST", "/upload", Some(body.clone()))
        .await
        .unwrap();
    let h3_echo: Value = serde_json::from_slice(&r3.body).unwrap();
    assert_eq!(h3_echo["body_len"], body.len());
    assert_eq!(h2_echo["body_sha"], h3_echo["body_sha"]);
    assert_eq!(h3_echo["method"], "POST");

    // --- a host without a route gets the same edge page on both
    let r2 = h2
        .get(format!("https://unknown.test:{https}/"))
        .send()
        .await;
    // No certificate for unknown.test (self-signed fallback): TCP refuses it,
    // and so does QUIC, through the same lookup.
    assert!(r2.is_err());
    assert!(
        h3_request(&pki, https, "unknown.test", "GET", "/", None)
            .await
            .is_err()
    );

    // --- certificate rotation reaches both listeners
    assert_eq!(r3.peer_cert, leaf_a.der);
    *mock.certs.lock().unwrap() = vec![json!({
        "domain": APP_HOST, "chain_pem": leaf_b.chain_pem, "key_pem": leaf_b.key_pem,
    })];
    let _ = reload.send(());
    eventually("QUIC to present the rotated certificate", || async {
        h3_request(&pki, https, APP_HOST, "GET", "/", None)
            .await
            .is_ok_and(|r| r.peer_cert == leaf_b.der)
    })
    .await;
    let fresh = h2_client(&pki, https);
    let r2 = fresh
        .get(format!("https://{APP_HOST}:{https}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(tls_peer_cert(&r2), leaf_b.der);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_off_means_no_udp_and_no_advertisement() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pki = Pki::new();
    let leaf = pki.leaf(APP_HOST);
    let upstream = serve(Router::new().fallback(any(echo))).await;
    let (reload, _) = broadcast::channel(4);
    let mock = Mock {
        upstream: upstream.to_string(),
        certs: Arc::new(Mutex::new(vec![json!({
            "domain": APP_HOST, "chain_pem": leaf.chain_pem, "key_pem": leaf.key_pem,
        })])),
        reload,
    };
    let server = serve(
        Router::new()
            .route("/api/internal/routes", get(routes))
            .route("/api/internal/certs", get(certs))
            .route("/api/internal/certs/{host}", post(|| async { "" }))
            .route("/api/internal/events", get(events))
            .with_state(mock),
    )
    .await;

    let dir = tempdir();
    let https = free_port();
    let _proxy = start_proxy(dir.path(), server, free_port(), https, false);
    let h2 = h2_client(&pki, https);
    eventually("the proxy to serve app.test over HTTP/2", || async {
        h2.get(format!("https://{APP_HOST}:{https}/ready"))
            .send()
            .await
            .is_ok_and(|r| r.status() == 200)
    })
    .await;
    let r = h2
        .get(format!("https://{APP_HOST}:{https}/"))
        .send()
        .await
        .unwrap();
    assert!(r.headers().get("alt-svc").is_none());

    let attempt = tokio::time::timeout(
        Duration::from_secs(3),
        h3_request(&pki, https, APP_HOST, "GET", "/", None),
    )
    .await;
    assert!(
        !matches!(attempt, Ok(Ok(_))),
        "HTTP/3 answered with quic = false"
    );
}

fn tempdir() -> TempDir {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("harbor-proxy-h3-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    TempDir(path)
}

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
