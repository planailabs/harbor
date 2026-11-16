//! WebTransport through the edge: terminate the browser's session, re-open
//! one toward the upstream, relay everything 1:1.
//!
//! A browser opens a WebTransport session with an extended CONNECT
//! (`:protocol = webtransport`) on the HTTP/3 listener. That request goes
//! through `HarborProxy` like any other — host routing, redirect domains,
//! basic/OIDC gates — and when the folder may be reached, the proxy marks it
//! with a [`WebTransportTarget`] instead of proxying it (see
//! `HarborProxy::request_filter`). The QUIC listener then hands the
//! connection here (browsers give every WebTransport session a connection of
//! its own).
//!
//! The upstream session is opened first, so the browser gets the upstream's
//! answer: its status when it refuses (an expired ticket, say), 200 only when
//! it accepted. From then on every stream either side opens is mirrored and
//! piped both ways, with RESET_STREAM and STOP_SENDING carried across (so a
//! superseded stream can be reset end to end), datagrams are forwarded as
//! they come (dropped, never queued, when the other side cannot take them),
//! and the session's close code and reason are passed on. Nothing is buffered
//! beyond QUIC flow control and nothing is reordered.
//!
//! The upstream is not checked against a CA or a name: its certificate is
//! short-lived and self-signed, so the folder's host carries the SHA-256 of
//! the upstream's SubjectPublicKeyInfo and only a certificate for that key
//! is accepted.
//!
//! Libraries: the browser side is `h3`'s own extension crates
//! (h3-webtransport, h3-datagram) because it lives on the same connections
//! as ordinary HTTP/3; the upstream side is web-transport-quinn's client.
//! Error codes cross between the two through web-transport-proto's mapping
//! (h3-webtransport speaks raw HTTP/3 codes, web-transport-quinn WebTransport
//! application codes).

use std::future::poll_fn;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use h3::quic::{self, BidiStream as _, SendStreamUnframed};
use h3_webtransport::server::{AcceptedBi, WebTransportSession};
use pingora::http::RequestHeader;
use sha2::Digest as _;
use web_transport_proto::{Capsule, error_from_http3, error_to_http3};

/// A folder's QUIC upstream for WebTransport: where its sessions are
/// re-opened, and the only public key that upstream may present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicUpstream {
    /// The folder's upstream host (its HTTP upstream's address, without the
    /// port).
    pub host: String,
    pub port: u16,
    /// SHA-256 of the upstream certificate's DER SubjectPublicKeyInfo.
    pub spki_sha256: [u8; 32],
}

impl QuicUpstream {
    /// From the route table's `quic_upstream` and the folder's HTTP upstream
    /// (`host:port`, `[v6]:port`, or a bare host).
    pub fn new(http_upstream: &str, port: u16, spki_sha256_hex: &str) -> anyhow::Result<Self> {
        let hex = spki_sha256_hex.trim();
        let bytes = hex::decode(hex).map_err(|e| anyhow::anyhow!("spki_sha256: {e}"))?;
        let spki_sha256: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("spki_sha256 must be 32 bytes (64 hex digits)"))?;
        Ok(Self {
            host: upstream_host(http_upstream)?,
            port,
            spki_sha256,
        })
    }
}

/// The host part of an upstream address: `[2001:db8::1]:8080` →
/// `2001:db8::1`, `10.0.0.1:80` → `10.0.0.1`, `name:80` → `name`.
fn upstream_host(upstream: &str) -> anyhow::Result<String> {
    let s = upstream
        .strip_prefix("https://")
        .or_else(|| upstream.strip_prefix("http://"))
        .unwrap_or(upstream);
    let s = s.split('/').next().unwrap_or(s);
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr.ip().to_string());
    }
    if let Ok(ip) = s.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    let host = match s.rsplit_once(':') {
        Some((h, port)) if port.parse::<u16>().is_ok() => h,
        _ => s,
    };
    if host.is_empty() {
        anyhow::bail!("upstream {upstream:?} has no host");
    }
    Ok(host.to_string())
}

/// Set by `HarborProxy::request_filter` on a WebTransport CONNECT it lets
/// through: the session is to be relayed to `upstream` at `path`.
#[derive(Debug, Clone)]
pub struct WebTransportTarget {
    pub upstream: QuicUpstream,
    /// Path and query toward the upstream (the folder's mount prefix
    /// stripped, as for HTTP).
    pub path: String,
}

/// Whether a request is a WebTransport extended CONNECT.
pub fn is_webtransport_connect(req: &RequestHeader) -> bool {
    req.method == http::Method::CONNECT
        && req.extensions.get::<h3::ext::Protocol>() == Some(&h3::ext::Protocol::WEB_TRANSPORT)
}

type DownConnection = h3::server::Connection<h3_quinn::Connection, Bytes>;
type DownSession = WebTransportSession<h3_quinn::Connection, Bytes>;
type ConnectStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// Generous for a handshake to a nearby instance; a stuck one must not hold
/// the browser's CONNECT forever.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the browser gets to read our CLOSE capsule before the
/// connection is dropped.
const CLOSE_LINGER: Duration = Duration::from_secs(2);

/// `H3_CONNECT_ERROR`: the tunnel to the upstream broke.
const H3_CONNECT_ERROR: u32 = 0x10f;

/// Outgoing QUIC connections toward upstreams.
pub struct UpstreamClient {
    endpoint: quinn::Endpoint,
}

impl UpstreamClient {
    /// A client endpoint on an ephemeral port: dual-stack where the host
    /// has IPv6 (instances are reached over IPv6), IPv4 otherwise.
    pub fn new() -> anyhow::Result<Self> {
        let endpoint = quinn::Endpoint::client((std::net::Ipv6Addr::UNSPECIFIED, 0).into())
            .or_else(|_| quinn::Endpoint::client((std::net::Ipv4Addr::UNSPECIFIED, 0).into()))?;
        Ok(Self { endpoint })
    }

    fn config(spki_sha256: [u8; 32]) -> anyhow::Result<quinn::ClientConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedSpki {
                spki_sha256,
                provider,
            }))
            .with_no_client_auth();
        tls.alpn_protocols = vec![web_transport_quinn::ALPN.as_bytes().to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        // Keep an idle session (a paused stream, no datagrams) alive.
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        config.transport_config(Arc::new(transport));
        Ok(config)
    }

    async fn connect(
        &self,
        target: &WebTransportTarget,
        request: web_transport_quinn::proto::ConnectRequest,
        server_name: &str,
    ) -> Result<web_transport_quinn::Session, UpstreamError> {
        let up = &target.upstream;
        let addr = tokio::net::lookup_host((up.host.as_str(), up.port))
            .await
            .map_err(|e| UpstreamError::Unreachable(e.to_string()))?
            .next()
            .ok_or_else(|| UpstreamError::Unreachable(format!("{} has no address", up.host)))?;
        let config =
            Self::config(up.spki_sha256).map_err(|e| UpstreamError::Unreachable(e.to_string()))?;
        // The name is not verified (only the pin is); send the visitor's.
        let conn = self
            .endpoint
            .connect_with(config, addr, server_name)
            .map_err(|e| UpstreamError::Unreachable(e.to_string()))?
            .await
            .map_err(|e| UpstreamError::Unreachable(e.to_string()))?;
        web_transport_quinn::Session::connect(conn, request)
            .await
            .map_err(|e| match refused_status(&e) {
                Some(status) => UpstreamError::Refused(status),
                None => UpstreamError::Unreachable(e.to_string()),
            })
    }
}

/// The status an upstream answered a CONNECT with, when it said no.
/// web-transport-quinn reports it in two shapes depending on where it noticed.
fn refused_status(e: &web_transport_quinn::ClientError) -> Option<http::StatusCode> {
    use web_transport_quinn::{ClientError, ConnectError};
    match e {
        ClientError::HttpError(ConnectError::ErrorStatus(status))
        | ClientError::HttpError(ConnectError::ProtoError(
            web_transport_quinn::proto::ConnectError::WrongStatus(Some(status)),
        )) => Some(*status),
        _ => None,
    }
}

enum UpstreamError {
    /// The upstream answered the CONNECT with this status.
    Refused(http::StatusCode),
    Unreachable(String),
}

/// Accepts exactly the upstream certificate whose public key hashes to the
/// pin. No CA, no name, no validity period: the instance rotates a
/// self-signed certificate on the same key's terms, and the pin is the
/// trust.
#[derive(Debug)]
struct PinnedSpki {
    spki_sha256: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

/// SHA-256 of a DER certificate's SubjectPublicKeyInfo.
pub fn spki_sha256(cert_der: &[u8]) -> anyhow::Result<[u8; 32]> {
    let cert = pingora::tls::x509::X509::from_der(cert_der)?;
    let spki = cert.public_key()?.public_key_to_der()?;
    Ok(sha2::Sha256::digest(&spki).into())
}

impl rustls::client::danger::ServerCertVerifier for PinnedSpki {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        match spki_sha256(end_entity) {
            Ok(hash) if hash == self.spki_sha256 => {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            Ok(_) => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )),
            Err(_) => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            )),
        }
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
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // The handshake still proves possession of the pinned key.
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Headers of the browser's CONNECT the upstream gets, plus the edge's own
/// `X-Forwarded-*` (set, never passed through, as for HTTP).
fn upstream_request(
    req: &RequestHeader,
    target: &WebTransportTarget,
    client_ip: Option<IpAddr>,
) -> anyhow::Result<web_transport_quinn::proto::ConnectRequest> {
    let authority = req
        .uri
        .authority()
        .map(|a| a.as_str().to_string())
        .or_else(|| {
            req.headers
                .get(http::header::HOST)
                .and_then(|h| h.to_str().ok())
                .map(str::to_string)
        })
        .ok_or_else(|| anyhow::anyhow!("CONNECT without :authority"))?;
    let url = url::Url::parse(&format!("https://{authority}{}", target.path))?;
    let mut out = web_transport_quinn::proto::ConnectRequest::new(url);
    for name in [
        http::header::ORIGIN,
        http::header::USER_AGENT,
        http::header::COOKIE,
        http::header::AUTHORIZATION,
    ] {
        for v in req.headers.get_all(&name) {
            out.headers.append(name.clone(), v.clone());
        }
    }
    // Subprotocol negotiation (wt-available-protocols) passes through as is.
    if let Some(p) = req.headers.get("wt-available-protocols") {
        out.headers.insert("wt-available-protocols", p.clone());
    }
    if let Some(ip) = client_ip {
        out.headers.insert(
            "x-forwarded-for",
            http::HeaderValue::from_str(&ip.to_string())?,
        );
    }
    out.headers
        .insert("x-forwarded-proto", http::HeaderValue::from_static("https"));
    let host = authority
        .split(':')
        .next()
        .unwrap_or(&authority)
        .to_lowercase();
    out.headers
        .insert("x-forwarded-host", http::HeaderValue::from_str(&host)?);
    Ok(out)
}

/// Answer the browser's CONNECT with an error status and end the stream.
/// The connection was the session's, so it ends too, but only once the
/// browser has had the answer.
async fn refuse(
    mut stream: ConnectStream,
    quic_conn: &quinn::Connection,
    status: http::StatusCode,
) {
    let resp = http::Response::builder().status(status).body(()).unwrap();
    if stream.send_response(resp).await.is_ok() {
        let _ = stream.finish().await;
        let _ = tokio::time::timeout(CLOSE_LINGER, quic_conn.closed()).await;
    }
}

/// Relay one WebTransport session. `conn` is the browser's HTTP/3
/// connection, `stream` its CONNECT, `req` the request as HarborProxy saw
/// it.
pub async fn relay(
    client: Arc<UpstreamClient>,
    quic_conn: quinn::Connection,
    conn: DownConnection,
    req: RequestHeader,
    stream: ConnectStream,
    target: WebTransportTarget,
) {
    let client_ip = Some(quic_conn.remote_address().ip());
    let request = match upstream_request(&req, &target, client_ip) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("WebTransport CONNECT rejected: {e}");
            return refuse(stream, &quic_conn, http::StatusCode::BAD_REQUEST).await;
        }
    };
    let server_name = request.url.host_str().unwrap_or("upstream").to_string();
    let up = match tokio::time::timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        client.connect(&target, request, &server_name),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(UpstreamError::Refused(status))) => return refuse(stream, &quic_conn, status).await,
        Ok(Err(UpstreamError::Unreachable(e))) => {
            tracing::warn!(upstream = %target.upstream.host, port = target.upstream.port, "WebTransport upstream unreachable: {e}");
            return refuse(stream, &quic_conn, http::StatusCode::BAD_GATEWAY).await;
        }
        Err(_) => {
            tracing::warn!(upstream = %target.upstream.host, "WebTransport upstream timed out");
            return refuse(stream, &quic_conn, http::StatusCode::GATEWAY_TIMEOUT).await;
        }
    };

    let parts: http::request::Parts = req.into();
    let down = match DownSession::accept(http::Request::from_parts(parts, ()), stream, conn).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::debug!("WebTransport accept failed: {e}");
            up.close(0, b"");
            return;
        }
    };
    let Some(connect_stream) = down.take_connect_stream() else {
        up.close(0, b"");
        return;
    };

    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(down_accept(down.clone(), up.clone()));
    tasks.spawn(up_uni(down.clone(), up.clone()));
    tasks.spawn(up_bi(down.clone(), up.clone()));
    tasks.spawn(datagrams_down(down.clone(), up.clone()));
    tasks.spawn(datagrams_up(down.clone(), up.clone()));

    close_session(connect_stream, &up, &quic_conn).await;
    // Streams in flight end with their sessions.
    tasks.abort_all();
}

/// Watch both ends of the session and pass the first close on: the
/// browser's CLOSE capsule (or its CONNECT stream ending) closes the
/// upstream session with the same code and reason; the upstream's close is
/// written to the browser as a CLOSE capsule.
async fn close_session(
    mut connect: ConnectStream,
    up: &web_transport_quinn::Session,
    quic_conn: &quinn::Connection,
) {
    let mut buf = BytesMut::new();
    let upstream_closed = loop {
        tokio::select! {
            data = connect.recv_data() => match data {
                Ok(Some(mut chunk)) => {
                    buf.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
                    loop {
                        let mut peek = &buf[..];
                        match Capsule::decode(&mut peek) {
                            Ok(Capsule::CloseWebTransportSession { code, reason }) => {
                                up.close(code, reason.as_bytes());
                                return;
                            }
                            Ok(_) => {
                                let used = buf.len() - peek.len();
                                let _ = buf.split_to(used);
                            }
                            // Incomplete: wait for more.
                            Err(web_transport_proto::CapsuleError::UnexpectedEnd) => break,
                            // Malformed (or oversized): the session is broken.
                            Err(_) => {
                                up.close(0, b"");
                                return;
                            }
                        }
                    }
                }
                // FIN or the connection went: the browser is gone.
                Ok(None) | Err(_) => {
                    up.close(0, b"");
                    return;
                }
            },
            err = up.closed() => break err,
        }
    };

    match upstream_closed {
        web_transport_quinn::SessionError::WebTransportError(
            web_transport_quinn::WebTransportError::Closed(code, reason),
        ) => {
            let mut out = BytesMut::new();
            Capsule::CloseWebTransportSession { code, reason }.encode(&mut out);
            if connect.send_data(out.freeze()).await.is_ok() {
                let _ = connect.finish().await;
            }
            // The browser closes its (dedicated) connection once it has read
            // the capsule; don't cut it off before that.
            let _ = tokio::time::timeout(CLOSE_LINGER, quic_conn.closed()).await;
        }
        e => {
            tracing::debug!("WebTransport upstream session lost: {e}");
            quic_conn.close(H3_CONNECT_ERROR.into(), b"upstream session lost");
        }
    }
}

// ── stream mirroring ──────────────────────────────────────────────────

/// Streams the browser opens.
///
/// Both kinds are accepted in one task, from futures that live until they
/// complete. h3's bidi accept also sorts incoming uni streams into the
/// session's queue without waking whoever waits for them, so the uni accept
/// is polled right after it (`biased`) in the same round; and the bidi accept
/// may hold a stream it is still reading the header of, so it is never
/// dropped half-way.
async fn down_accept(down: Arc<DownSession>, up: web_transport_quinn::Session) {
    let mut bi = Box::pin(down.accept_bi());
    let mut uni = Box::pin(down.accept_uni());
    loop {
        tokio::select! {
            biased;
            accepted = &mut bi => {
                bi.set(down.accept_bi());
                match accepted {
                    Ok(Some(AcceptedBi::BidiStream(_, bidi))) => {
                        let up = up.clone();
                        tokio::spawn(async move {
                            let Ok((up_send, up_recv)) = up.open_bi().await else { return };
                            let (down_send, down_recv) = bidi.split();
                            tokio::spawn(pipe_up(down_recv, up_send));
                            pipe_down(up_recv, down_send).await;
                        });
                    }
                    // A plain request on the session's connection; browsers
                    // don't send these, and the connection is the session's.
                    Ok(Some(AcceptedBi::Request(_, mut stream))) => {
                        stream.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
                    }
                    Ok(None) | Err(_) => return,
                }
            }
            accepted = &mut uni => {
                uni = Box::pin(down.accept_uni());
                match accepted {
                    Ok(Some((_, recv))) => {
                        let up = up.clone();
                        tokio::spawn(async move {
                            let Ok(send) = up.open_uni().await else { return };
                            pipe_up(recv, send).await;
                        });
                    }
                    Ok(None) | Err(_) => return,
                }
            }
        }
    }
}

async fn up_uni(down: Arc<DownSession>, up: web_transport_quinn::Session) {
    let session_id = down.session_id();
    while let Ok(recv) = up.accept_uni().await {
        let Ok(send) = down.open_uni(session_id).await else {
            return;
        };
        tokio::spawn(pipe_down(recv, send));
    }
}

async fn up_bi(down: Arc<DownSession>, up: web_transport_quinn::Session) {
    let session_id = down.session_id();
    while let Ok((up_send, up_recv)) = up.accept_bi().await {
        let Ok(bidi) = down.open_bi(session_id).await else {
            return;
        };
        let (down_send, down_recv) = bidi.split();
        tokio::spawn(pipe_up(down_recv, up_send));
        tokio::spawn(pipe_down(up_recv, down_send));
    }
}

/// Browser → upstream. A RESET_STREAM from the browser resets the upstream
/// stream with the same application code; STOP_SENDING from the upstream is
/// passed back to the browser.
async fn pipe_up<R: quic::RecvStream>(mut from: R, mut to: web_transport_quinn::SendStream) {
    let stopped = to.stopped();
    tokio::pin!(stopped);
    loop {
        tokio::select! {
            data = poll_fn(|cx| from.poll_data(cx)) => match data {
                Ok(Some(mut buf)) => {
                    let chunk = buf.copy_to_bytes(buf.remaining());
                    if let Err(e) = to.write_chunk(chunk).await {
                        if let web_transport_quinn::WriteError::Stopped(code) = e {
                            from.stop_sending(error_to_http3(code));
                        }
                        return;
                    }
                }
                Ok(None) => {
                    let _ = to.finish();
                    return;
                }
                Err(quic::StreamErrorIncoming::StreamTerminated { error_code }) => {
                    let _ = to.reset(error_from_http3(error_code).unwrap_or(0));
                    return;
                }
                Err(_) => {
                    let _ = to.reset(0);
                    return;
                }
            },
            code = &mut stopped => {
                if let Ok(Some(code)) = code {
                    from.stop_sending(error_to_http3(code));
                }
                return;
            }
        }
    }
}

/// Upstream → browser, the mirror image of [`pipe_up`].
async fn pipe_down<S: SendStreamUnframed<Bytes>>(
    mut from: web_transport_quinn::RecvStream,
    mut to: S,
) {
    loop {
        match from.read_chunk(usize::MAX, true).await {
            Ok(Some(chunk)) => {
                let mut data: Bytes = chunk.bytes;
                while data.has_remaining() {
                    match poll_fn(|cx| to.poll_send(cx, &mut data)).await {
                        Ok(_) => {}
                        Err(quic::StreamErrorIncoming::StreamTerminated { error_code }) => {
                            let _ = from.stop(error_from_http3(error_code).unwrap_or(0));
                            return;
                        }
                        Err(_) => {
                            let _ = from.stop(0);
                            return;
                        }
                    }
                }
            }
            Ok(None) => {
                let _ = poll_fn(|cx| to.poll_finish(cx)).await;
                return;
            }
            Err(web_transport_quinn::ReadError::Reset(code)) => {
                to.reset(error_to_http3(code));
                return;
            }
            Err(_) => {
                to.reset(error_to_http3(0));
                return;
            }
        }
    }
}

// ── datagrams ─────────────────────────────────────────────────────────

async fn datagrams_down(down: Arc<DownSession>, up: web_transport_quinn::Session) {
    let mut reader = down.datagram_reader();
    while let Ok(datagram) = reader.read_datagram().await {
        let mut payload = datagram.into_payload();
        // Lossy by design: one the upstream can't take now is dropped.
        let _ = up.send_datagram(payload.copy_to_bytes(payload.remaining()));
    }
}

async fn datagrams_up(down: Arc<DownSession>, up: web_transport_quinn::Session) {
    let mut sender = down.datagram_sender();
    while let Ok(datagram) = up.read_datagram().await {
        let _ = sender.send_datagram(datagram);
    }
}

#[cfg(test)]
mod tests {
    use super::upstream_host;

    #[test]
    fn upstream_host_strips_the_port() {
        assert_eq!(upstream_host("[2001:db8::1]:8080").unwrap(), "2001:db8::1");
        assert_eq!(upstream_host("10.0.0.1:80").unwrap(), "10.0.0.1");
        assert_eq!(
            upstream_host("instance.internal:443").unwrap(),
            "instance.internal"
        );
        assert_eq!(upstream_host("2001:db8::2").unwrap(), "2001:db8::2");
        assert_eq!(
            upstream_host("http://[2001:db8::3]:4321/x").unwrap(),
            "2001:db8::3"
        );
    }

    #[test]
    fn pin_must_be_32_bytes() {
        assert!(super::QuicUpstream::new("[::1]:80", 4433, "ab").is_err());
        let ok = super::QuicUpstream::new("[::1]:80", 4433, &"ab".repeat(32)).unwrap();
        assert_eq!(ok.host, "::1");
        assert_eq!(ok.spki_sha256, [0xab; 32]);
    }
}
