//! End-to-end WebTransport: a client → the real `harbor-proxy` binary → a
//! WebTransport echo server upstream with a self-signed certificate that is
//! trusted only through its pinned public key.

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::routing::any;
use bytes::Bytes;
use serde_json::json;
use sha2::Digest as _;
use web_transport_quinn::{ClientError, ConnectError, ReadError, Session, SessionError};

use common::{
    MockHarbor, Pki, cert_entry, free_port, h2_client, serve, start_proxy, wait_until_served,
};

const WT_HOST: &str = "wt.test";
const BAD_PIN_HOST: &str = "badpin.test";
const NO_QUIC_HOST: &str = "noquic.test";

// ------------------------------------------------------------- upstream echo

/// What the upstream saw, for the assertions that look from its side.
#[derive(Default)]
struct Seen {
    /// The CONNECT's path and query.
    paths: Vec<String>,
    x_forwarded_for: Option<String>,
    /// The close the client sent through the edge.
    closed: Option<(u32, String)>,
}

/// A WebTransport echo server with a fresh self-signed certificate. Returns
/// its address and the hex SHA-256 of its SubjectPublicKeyInfo.
async fn upstream_echo(seen: Arc<Mutex<Seen>>) -> (SocketAddr, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["instance".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let spki_sha256 = hex::encode(sha2::Sha256::digest(key.public_key_der()));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        (Ipv4Addr::LOCALHOST, 0).into(),
    )
    .unwrap();
    let addr = endpoint.local_addr().unwrap();

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let Ok(request) = web_transport_quinn::Request::accept(conn).await else {
                    return;
                };
                {
                    let mut s = seen.lock().unwrap();
                    let url = &request.url;
                    s.paths.push(format!(
                        "{}{}",
                        url.path(),
                        url.query().map(|q| format!("?{q}")).unwrap_or_default()
                    ));
                    s.x_forwarded_for = request
                        .headers
                        .get("x-forwarded-for")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string);
                }
                // The instance's own authorization: a ticket in the query.
                if request.url.query() != Some("ticket=good") {
                    let conn = request.conn().clone();
                    let _ = request.reject(http::StatusCode::FORBIDDEN).await;
                    // Let the answer arrive before the connection goes.
                    let _ = tokio::time::timeout(Duration::from_secs(2), conn.closed()).await;
                    return;
                }
                let Ok(session) = request.ok().await else {
                    return;
                };
                echo_session(session, seen).await;
            });
        }
    });
    (addr, spki_sha256)
}

async fn echo_session(session: Session, seen: Arc<Mutex<Seen>>) {
    // uni in → uni out with "uni:" prefixed; a reset uni in is reported on a
    // uni out as "reset:<code>".
    let s = session.clone();
    tokio::spawn(async move {
        while let Ok(mut recv) = s.accept_uni().await {
            let s = s.clone();
            tokio::spawn(async move {
                let reply = match recv.read_to_end(1 << 20).await {
                    Ok(data) => [b"uni:".as_slice(), &data].concat(),
                    Err(web_transport_quinn::ReadToEndError::ReadError(ReadError::Reset(c))) => {
                        format!("reset:{c}").into_bytes()
                    }
                    Err(_) => return,
                };
                let mut send = s.open_uni().await.unwrap();
                send.write_all(&reply).await.unwrap();
                send.finish().unwrap();
            });
        }
    });

    // bi: echo with "bi:" prefixed, plus two commands.
    let s = session.clone();
    tokio::spawn(async move {
        while let Ok((mut send, mut recv)) = s.accept_bi().await {
            let s = s.clone();
            tokio::spawn(async move {
                let data = recv.read_to_end(1 << 20).await.unwrap();
                match data.as_slice() {
                    // Open a stream toward the client, start it, then reset it.
                    b"reset please" => {
                        let mut uni = s.open_uni().await.unwrap();
                        uni.write_all(b"partial").await.unwrap();
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        uni.reset(42).unwrap();
                        send.write_all(b"done").await.unwrap();
                        send.finish().unwrap();
                    }
                    b"close please" => s.close(4242, b"bye"),
                    _ => {
                        send.write_all(&[b"bi:".as_slice(), &data].concat())
                            .await
                            .unwrap();
                        send.finish().unwrap();
                    }
                }
            });
        }
    });

    // datagrams: echo with "dgram:" prefixed.
    let s = session.clone();
    tokio::spawn(async move {
        while let Ok(d) = s.read_datagram().await {
            let _ = s.send_datagram(Bytes::from([b"dgram:".as_slice(), &d].concat()));
        }
    });

    if let SessionError::WebTransportError(web_transport_quinn::WebTransportError::Closed(
        code,
        reason,
    )) = session.closed().await
    {
        seen.lock().unwrap().closed = Some((code, reason));
    }
}

// --------------------------------------------------------------------- client

/// A WebTransport session to `host` through the proxy (resolved to
/// 127.0.0.1), trusting the test CA.
async fn connect(
    pki: &Pki,
    https: u16,
    host: &str,
    path: &str,
) -> Result<(quinn::Endpoint, Session), ClientError> {
    let tls = pki.client_config(b"h3");
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let config = quinn::ClientConfig::new(Arc::new(crypto));
    let endpoint = quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let conn = endpoint
        .connect_with(config, (Ipv4Addr::LOCALHOST, https).into(), host)?
        .await?;
    let url = url::Url::parse(&format!("https://{host}:{https}{path}")).unwrap();
    let session = Session::connect(conn, url).await?;
    Ok((endpoint, session))
}

fn refused_with(result: Result<(quinn::Endpoint, Session), ClientError>) -> Option<u16> {
    match result {
        Err(ClientError::HttpError(ConnectError::ErrorStatus(s)))
        | Err(ClientError::HttpError(ConnectError::ProtoError(
            web_transport_quinn::proto::ConnectError::WrongStatus(Some(s)),
        ))) => Some(s.as_u16()),
        _ => None,
    }
}

async fn read_uni(session: &Session) -> Result<Vec<u8>, web_transport_quinn::ReadToEndError> {
    let mut recv = tokio::time::timeout(Duration::from_secs(5), session.accept_uni())
        .await
        .expect("no uni stream from upstream")
        .unwrap();
    recv.read_to_end(1 << 20).await
}

// ---------------------------------------------------------------------- test

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webtransport_is_relayed_end_to_end() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pki = Pki::new();

    let seen = Arc::new(Mutex::new(Seen::default()));
    let (wt_addr, pin) = upstream_echo(seen.clone()).await;
    let other_pin = hex::encode(sha2::Sha256::digest(b"some other key"));
    let http = serve(Router::new().fallback(any(|| async { "ok" }))).await;

    let route = |host: &str, quic: Option<(u16, &str)>| {
        let mut r = json!({ "host": host, "path_prefix": "/", "upstream": http.to_string() });
        if let Some((port, pin)) = quic {
            r["quic_upstream"] = json!({ "port": port, "spki_sha256": pin });
        }
        r
    };
    let mock = MockHarbor::new(
        vec![
            route(WT_HOST, Some((wt_addr.port(), &pin))),
            route(BAD_PIN_HOST, Some((wt_addr.port(), &other_pin))),
            route(NO_QUIC_HOST, None),
        ],
        [WT_HOST, BAD_PIN_HOST, NO_QUIC_HOST]
            .iter()
            .map(|h| cert_entry(h, &pki.leaf(h)))
            .collect(),
    );
    let server = mock.serve().await;
    let https = free_port();
    let _proxy = start_proxy(server, https, true);
    let h2 = h2_client(&pki, https, &[WT_HOST]);
    wait_until_served(&h2, WT_HOST, https).await;

    // --- refusals: the upstream's own, a wrong pin, no QUIC upstream at all
    assert_eq!(
        refused_with(connect(&pki, https, WT_HOST, "/session?ticket=bad").await),
        Some(403),
        "the upstream's refusal reaches the client"
    );
    assert_eq!(
        refused_with(connect(&pki, https, BAD_PIN_HOST, "/session?ticket=good").await),
        Some(502),
        "an upstream whose key does not match the pin must not be reached"
    );
    assert_eq!(
        refused_with(connect(&pki, https, NO_QUIC_HOST, "/session?ticket=good").await),
        Some(501),
    );
    // The wrong-pin attempt never got to the upstream's CONNECT handling.
    assert_eq!(seen.lock().unwrap().paths, vec!["/session?ticket=bad"]);

    let (_endpoint, session) = connect(&pki, https, WT_HOST, "/session?ticket=good")
        .await
        .expect("session through the edge");
    {
        let s = seen.lock().unwrap();
        assert_eq!(s.paths.last().unwrap(), "/session?ticket=good");
        assert_eq!(s.x_forwarded_for.as_deref(), Some("127.0.0.1"));
    }

    // --- uni stream: client → upstream, answered on an upstream-opened uni
    let mut uni = session.open_uni().await.unwrap();
    uni.write_all(b"hello uni").await.unwrap();
    uni.finish().unwrap();
    assert_eq!(read_uni(&session).await.unwrap(), b"uni:hello uni");

    // --- bidi stream
    let (mut send, mut recv) = session.open_bi().await.unwrap();
    send.write_all(b"hello bi").await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(1 << 20).await.unwrap(), b"bi:hello bi");

    // --- datagram (lossy by nature; retry a few times on loopback)
    let mut echoed = None;
    for _ in 0..20 {
        session
            .send_datagram(Bytes::from_static(b"hello dgram"))
            .unwrap();
        if let Ok(Ok(d)) =
            tokio::time::timeout(Duration::from_millis(250), session.read_datagram()).await
        {
            echoed = Some(d);
            break;
        }
    }
    assert_eq!(echoed.as_deref(), Some(b"dgram:hello dgram".as_slice()));

    // --- reset, upstream → client: the upstream resets a stream it opened
    let (mut send, mut recv) = session.open_bi().await.unwrap();
    send.write_all(b"reset please").await.unwrap();
    send.finish().unwrap();
    let reset = read_uni(&session).await;
    assert!(
        matches!(
            reset,
            Err(web_transport_quinn::ReadToEndError::ReadError(
                ReadError::Reset(42)
            ))
        ),
        "expected the upstream's reset code 42, got {reset:?}"
    );
    assert_eq!(recv.read_to_end(64).await.unwrap(), b"done");

    // --- reset, client → upstream
    let mut uni = session.open_uni().await.unwrap();
    uni.write_all(b"never finished").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    uni.reset(7).unwrap();
    assert_eq!(read_uni(&session).await.unwrap(), b"reset:7");

    // --- close, upstream → client: code and reason arrive
    let (mut send, _recv) = session.open_bi().await.unwrap();
    send.write_all(b"close please").await.unwrap();
    send.finish().unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(5), session.closed())
        .await
        .expect("session not closed");
    assert!(
        matches!(
            &closed,
            SessionError::WebTransportError(web_transport_quinn::WebTransportError::Closed(4242, r))
                if r == "bye"
        ),
        "expected close 4242 \"bye\", got {closed:?}"
    );

    // --- close, client → upstream
    let (_endpoint2, session) = connect(&pki, https, WT_HOST, "/session?ticket=good")
        .await
        .unwrap();
    session.close(77, b"client bye");
    common::eventually("the upstream to see the client's close", || async {
        seen.lock().unwrap().closed == Some((77, "client bye".to_string()))
    })
    .await;
}
