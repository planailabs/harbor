//! End-to-end: the real `harbor-proxy` binary, fed routes and certificates by
//! a mock Harbor server, in front of an echo upstream. The same requests go
//! over HTTP/2 (TCP + BoringSSL) and HTTP/3 (QUIC + rustls) and must come out
//! of the proxy the same way.

mod common;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::http::{HeaderMap, Method, Uri};
use axum::response::IntoResponse;
use axum::routing::any;
use bytes::Buf;
use serde_json::{Value, json};

use common::{
    MockHarbor, Pki, cert_entry, free_port, h2_client, serve, start_proxy, wait_until_served,
};

const APP_HOST: &str = "app.test";

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

// -------------------------------------------------------------------- clients

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
    let tls = pki.client_config(b"h3");
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
    let mock = MockHarbor::new(
        vec![json!({ "host": APP_HOST, "path_prefix": "/", "upstream": upstream.to_string() })],
        vec![cert_entry(APP_HOST, &leaf_a)],
    );
    let server = mock.serve().await;
    let https = free_port();
    let _proxy = start_proxy(server, https, true);
    let h2 = h2_client(&pki, https, &[APP_HOST, "unknown.test"]);

    // Routes and certificate A loaded: an HTTP/2 request verifies against the CA.
    wait_until_served(&h2, APP_HOST, https).await;

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
    *mock.certs.lock().unwrap() = vec![cert_entry(APP_HOST, &leaf_b)];
    let _ = mock.reload.send(());
    common::eventually("QUIC to present the rotated certificate", || async {
        h3_request(&pki, https, APP_HOST, "GET", "/", None)
            .await
            .is_ok_and(|r| r.peer_cert == leaf_b.der)
    })
    .await;
    let fresh = h2_client(&pki, https, &[APP_HOST]);
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
    let mock = MockHarbor::new(
        vec![json!({ "host": APP_HOST, "path_prefix": "/", "upstream": upstream.to_string() })],
        vec![cert_entry(APP_HOST, &leaf)],
    );
    let server = mock.serve().await;
    let https = free_port();
    let _proxy = start_proxy(server, https, false);
    let h2 = h2_client(&pki, https, &[APP_HOST]);
    wait_until_served(&h2, APP_HOST, https).await;
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
