//! HTTP/3 over QUIC on the HTTPS port (UDP).
//!
//! Pingora has no QUIC listener (not in 0.8, not in 0.9 — upstream plans one
//! on quiche, cloudflare/pingora#95). What it does have is the custom
//! downstream session: any type implementing
//! `pingora::protocols::http::custom::server::Session` can be handed to an
//! `HttpProxy` with `process_new_http`, and from there it runs through the
//! same `ProxyHttp` callbacks as an HTTP/1.1 or HTTP/2 request. So quinn does
//! QUIC, `h3` does the HTTP/3 framing, and each request stream becomes one
//! [`H3Session`] that drives the very `HarborProxy` the TCP listener uses —
//! routing, auth, headers and error pages exist once.
//!
//! TLS 1.3 inside QUIC is rustls (quinn's crypto), keyed from the same
//! [`CertStore`] as the BoringSSL listener: every loaded certificate carries
//! its rustls form, and the store's SNI lookup serves both listeners, so a
//! certificate the sync task swaps in is live on UDP and TCP at once.
//!
//! 0-RTT is off (rustls' default): early data can be replayed, and the edge
//! forwards POSTs to apps that do not expect that.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use futures::{FutureExt, Stream};
use http::{HeaderMap, HeaderName, Version, header};
use pingora::apps::HttpServerApp;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::protocols::Digest;
use pingora::protocols::http::body_buffer::FixedBuffer;
use pingora::protocols::http::custom::CustomMessageWrite;
use pingora::protocols::http::custom::server::Session as CustomSession;
use pingora::protocols::http::{HttpTask, ServerSession};
use pingora::protocols::l4::socket::SocketAddr;
use pingora::protocols::tls::SslDigest;
use pingora::proxy::HttpProxy;
use pingora::server::ShutdownWatch;
use pingora::{Error, ErrorType, OrErr, Result};

use crate::cert_store::CertStore;
use crate::proxy::HarborProxy;

/// How long a client may cache the HTTP/3 advertisement.
const ALT_SVC_MAX_AGE: u32 = 86400;

/// Request body bytes kept for an upstream retry, as Pingora's own sessions do.
const RETRY_BUFFER_LIMIT: usize = 64 * 1024;

/// How long a shutdown waits for in-flight HTTP/3 requests.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

static ALT_SVC: OnceLock<String> = OnceLock::new();

/// The `Alt-Svc` value HTTPS responses carry, once the QUIC listener is
/// actually bound. `None` while it is not (disabled, or the bind failed), so
/// no client is sent to a UDP port nobody answers.
pub fn alt_svc() -> Option<&'static str> {
    ALT_SVC.get().map(String::as_str)
}

fn alt_svc_value(port: u16) -> String {
    format!("h3=\":{port}\"; ma={ALT_SVC_MAX_AGE}")
}

type H3Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// The QUIC listener as a Pingora background service.
pub struct QuicService {
    addr: String,
    proxy: Arc<HttpProxy<HarborProxy>>,
    cert_store: Arc<CertStore>,
}

pub fn build_service(
    server_conf: &Arc<pingora::server::configuration::ServerConf>,
    addr: &str,
    proxy: HarborProxy,
    cert_store: Arc<CertStore>,
) -> pingora::services::background::GenBackgroundService<QuicService> {
    pingora::services::background::background_service(
        "quic",
        QuicService {
            addr: addr.to_string(),
            proxy: Arc::new(pingora::proxy::http_proxy(server_conf, proxy)),
            cert_store,
        },
    )
}

/// rustls + quinn configuration: TLS 1.3 only (QUIC has nothing else), ALPN
/// `h3`, certificates from the shared store.
fn server_config(cert_store: Arc<CertStore>) -> anyhow::Result<quinn::ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(cert_store);
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
}

fn bind(addr: &str, cert_store: Arc<CertStore>) -> anyhow::Result<quinn::Endpoint> {
    use std::net::ToSocketAddrs;
    let sock = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("{addr} resolves to no address"))?;
    Ok(quinn::Endpoint::server(server_config(cert_store)?, sock)?)
}

#[async_trait]
impl pingora::services::background::BackgroundService for QuicService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let endpoint = match bind(&self.addr, self.cert_store.clone()) {
            Ok(e) => e,
            Err(e) => {
                // TCP keeps serving; without the advertisement nobody tries UDP.
                tracing::error!(addr = %self.addr, "HTTP/3 disabled, cannot listen on UDP: {e}");
                return;
            }
        };
        let port = endpoint.local_addr().map(|a| a.port()).unwrap_or_default();
        let _ = ALT_SVC.set(alt_svc_value(port));
        tracing::info!(addr = %self.addr, "listening for HTTP/3 (QUIC)");

        loop {
            tokio::select! {
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else { break };
                    let proxy = self.proxy.clone();
                    let shutdown = shutdown.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve_connection(incoming, proxy, shutdown).await {
                            tracing::debug!("HTTP/3 connection ended: {e}");
                        }
                    });
                }
                _ = shutdown.changed() => break,
            }
        }

        // Connections were told to GOAWAY by the same watch; give their
        // in-flight requests a moment, then close what is left.
        let _ = tokio::time::timeout(DRAIN_TIMEOUT, endpoint.wait_idle()).await;
        endpoint.close(
            h3::error::Code::H3_NO_ERROR
                .value()
                .try_into()
                .unwrap_or_default(),
            b"",
        );
    }
}

async fn serve_connection(
    incoming: quinn::Incoming,
    proxy: Arc<HttpProxy<HarborProxy>>,
    mut shutdown: ShutdownWatch,
) -> anyhow::Result<()> {
    let conn = incoming.await?;
    let client_addr = SocketAddr::Inet(conn.remote_address());
    let digest = Arc::new(Digest {
        // Marks the request as arriving over TLS (HSTS, X-Forwarded-Proto,
        // no redirect to https). The cipher is not exposed by quinn and
        // nothing here reads it.
        ssl_digest: Some(Arc::new(SslDigest::new(
            "",
            "TLSv1.3",
            None,
            None,
            Vec::new(),
        ))),
        timing_digest: Vec::new(),
        proxy_digest: None,
        socket_digest: None,
    });

    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
        h3::server::Connection::new(h3_quinn::Connection::new(conn.clone())).await?;
    let mut draining = *shutdown.borrow();
    if draining {
        h3_conn.shutdown(0).await?;
    }

    loop {
        tokio::select! {
            accepted = h3_conn.accept() => match accepted {
                Ok(Some(resolver)) => {
                    let proxy = proxy.clone();
                    let shutdown = shutdown.clone();
                    let conn = conn.clone();
                    let digest = digest.clone();
                    let client_addr = client_addr.clone();
                    tokio::spawn(async move {
                        let (req, stream) = match resolver.resolve_request().await {
                            Ok(r) => r,
                            Err(e) => {
                                tracing::debug!("HTTP/3 request rejected: {e}");
                                return;
                            }
                        };
                        let session = H3Session::new(req, stream, conn, digest, client_addr);
                        let session = ServerSession::new_custom(Box::new(session));
                        proxy.process_new_http(session, &shutdown).await;
                    });
                }
                Ok(None) => break,
                Err(e) => {
                    if !e.is_h3_no_error() {
                        tracing::debug!("HTTP/3 connection error: {e}");
                    }
                    break;
                }
            },
            _ = shutdown.changed(), if !draining => {
                draining = true;
                h3_conn.shutdown(0).await?;
            }
        }
    }
    Ok(())
}

/// One HTTP/3 request stream, as a Pingora downstream session.
///
/// Modelled on Pingora's own HTTP/2 server session: the request header is
/// complete on arrival, the body is read as DATA frames, and the response is
/// written as HEADERS + DATA (+ trailers) frames.
pub struct H3Session {
    req: RequestHeader,
    /// `RequestStream` is `Send` but not `Sync` (quinn keeps boxed futures in
    /// it); Pingora wants `Sync`. Every access is through `&mut self`, so
    /// `Mutex::get_mut` hands it out without ever locking.
    stream: Mutex<H3Stream>,
    conn: quinn::Connection,
    digest: Arc<Digest>,
    client_addr: SocketAddr,
    /// A body chunk read early, to find out whether there is a body at all.
    pending: Option<Bytes>,
    body_done: bool,
    body_read: usize,
    body_sent: usize,
    retry_buffer: Option<FixedBuffer>,
    response_written: Option<Box<ResponseHeader>>,
    ended: bool,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    total_drain_timeout: Option<Duration>,
}

/// Connection-specific headers, forbidden in HTTP/3 (RFC 9114 §4.2) exactly
/// as in HTTP/2.
const HOP_HEADERS: [HeaderName; 5] = [
    header::CONNECTION,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
    HeaderName::from_static("keep-alive"),
    HeaderName::from_static("proxy-connection"),
];

impl H3Session {
    fn new(
        req: http::Request<()>,
        stream: H3Stream,
        conn: quinn::Connection,
        digest: Arc<Digest>,
        client_addr: SocketAddr,
    ) -> Self {
        let (parts, ()) = req.into_parts();
        let mut req: RequestHeader = parts.into();
        // HTTP/3 has HTTP/2's message shape — :authority instead of Host, a
        // framed body instead of Content-Length/chunked. Pingora converts a
        // request it knows as HTTP/2 for an HTTP/1.1 upstream (Host from the
        // authority, chunked for a body of unknown length) and passes it
        // through to an HTTP/2 one, which is exactly what HTTP/3 needs.
        req.set_version(Version::HTTP_2);
        for h in &HOP_HEADERS {
            req.remove_header(h);
        }
        let mut session = Self {
            req,
            stream: Mutex::new(stream),
            conn,
            digest,
            client_addr,
            pending: None,
            body_done: false,
            body_read: 0,
            body_sent: 0,
            retry_buffer: None,
            response_written: None,
            ended: false,
            read_timeout: None,
            write_timeout: None,
            total_drain_timeout: None,
        };
        session.peek_body();
        session
    }

    fn stream(&mut self) -> &mut H3Stream {
        self.stream.get_mut().unwrap_or_else(|e| e.into_inner())
    }

    /// Find out, without waiting, whether the request body already ended.
    /// HTTP/3 has no END_STREAM flag on HEADERS: a request without a body is
    /// one whose stream FIN arrived, usually in the same packet as the
    /// headers. Knowing it keeps a bodiless GET from going upstream chunked.
    fn peek_body(&mut self) {
        if self.body_done || self.pending.is_some() {
            return;
        }
        let polled = self.stream().recv_data().now_or_never();
        match polled {
            Some(Ok(Some(mut buf))) => {
                self.pending = Some(buf.copy_to_bytes(buf.remaining()));
            }
            Some(Ok(None)) => self.body_done = true,
            // An error will come back on the next real read; not yet known.
            Some(Err(_)) | None => {}
        }
    }

    async fn do_read_body(&mut self) -> Result<Option<Bytes>> {
        if let Some(data) = self.pending.take() {
            return Ok(Some(data));
        }
        if self.body_done {
            return Ok(None);
        }
        let data = self
            .stream()
            .recv_data()
            .await
            .or_err(ErrorType::ReadError, "while reading HTTP/3 request body")?;
        match data {
            Some(mut buf) => Ok(Some(buf.copy_to_bytes(buf.remaining()))),
            None => {
                self.body_done = true;
                Ok(None)
            }
        }
    }

    async fn do_write_response_header(
        &mut self,
        mut header: Box<ResponseHeader>,
        end: bool,
    ) -> Result<()> {
        if self.ended {
            return Ok(());
        }
        // 1xx can't be sent through h3's single send_response (same as h2).
        if header.status.is_informational() {
            return Ok(());
        }
        if self.response_written.is_some() {
            tracing::warn!("HTTP/3 response header already sent");
            return Ok(());
        }
        for h in &HOP_HEADERS {
            header.remove_header(h);
        }
        let resp = http::Response::from_parts(header.as_owned_parts(), ());
        self.stream().send_response(resp).await.or_err(
            ErrorType::WriteError,
            "while writing HTTP/3 response header",
        )?;
        self.response_written = Some(header);
        if end {
            self.finish_stream().await?;
        }
        Ok(())
    }

    async fn do_write_body(&mut self, data: Bytes, end: bool) -> Result<()> {
        if self.ended {
            tracing::warn!("HTTP/3 body written after end of stream, dropped");
            return Ok(());
        }
        if self.response_written.is_none() {
            return Error::e_explain(ErrorType::WriteError, "HTTP/3 body before response header");
        }
        let len = data.len();
        if len > 0 {
            self.stream()
                .send_data(data)
                .await
                .or_err(ErrorType::WriteError, "while writing HTTP/3 response body")?;
            self.body_sent += len;
        }
        if end {
            self.finish_stream().await?;
        }
        Ok(())
    }

    async fn finish_stream(&mut self) -> Result<()> {
        if self.ended {
            return Ok(());
        }
        self.ended = true;
        self.stream()
            .finish()
            .await
            .or_err(ErrorType::WriteError, "while finishing HTTP/3 response")
    }

    async fn with_write_timeout<T>(
        timeout: Option<Duration>,
        fut: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        match timeout {
            Some(t) => match tokio::time::timeout(t, fut).await {
                Ok(r) => r,
                Err(_) => Error::e_explain(
                    ErrorType::WriteTimedout,
                    format!("writing HTTP/3 response, timeout: {t:?}"),
                ),
            },
            None => fut.await,
        }
    }
}

#[async_trait]
impl CustomSession for H3Session {
    fn req_header(&self) -> &RequestHeader {
        &self.req
    }

    fn req_header_mut(&mut self) -> &mut RequestHeader {
        &mut self.req
    }

    async fn read_body_bytes(&mut self) -> Result<Option<Bytes>> {
        let data = match self.read_timeout {
            Some(t) => match tokio::time::timeout(t, self.do_read_body()).await {
                Ok(r) => r,
                Err(_) => Error::e_explain(
                    ErrorType::ReadTimedout,
                    format!("reading HTTP/3 request body, timeout: {t:?}"),
                ),
            },
            None => self.do_read_body().await,
        }
        .map_err(|e| e.into_down())?;
        if let Some(data) = data.as_ref() {
            self.body_read += data.len();
            if let Some(buffer) = self.retry_buffer.as_mut() {
                buffer.write_to_buffer(data);
            }
        }
        Ok(data)
    }

    async fn drain_request_body(&mut self) -> Result<()> {
        let total_drain_timeout = self.total_drain_timeout;
        let drain = async {
            while self.read_body_bytes().await?.is_some() {}
            Ok(())
        };
        match total_drain_timeout {
            Some(t) => match tokio::time::timeout(t, drain).await {
                Ok(r) => r,
                Err(_) => Error::e_explain(
                    ErrorType::ReadTimedout,
                    format!("draining HTTP/3 request body, timeout: {t:?}"),
                ),
            },
            None => drain.await,
        }
    }

    async fn write_response_header(&mut self, resp: Box<ResponseHeader>, end: bool) -> Result<()> {
        let timeout = self.write_timeout;
        Self::with_write_timeout(timeout, self.do_write_response_header(resp, end))
            .await
            .map_err(|e| e.into_down())
    }

    async fn write_response_header_ref(&mut self, resp: &ResponseHeader, end: bool) -> Result<()> {
        self.write_response_header(Box::new(resp.clone()), end)
            .await
    }

    async fn write_body(&mut self, data: Bytes, end: bool) -> Result<()> {
        let timeout = self.write_timeout;
        Self::with_write_timeout(timeout, self.do_write_body(data, end))
            .await
            .map_err(|e| e.into_down())
    }

    async fn write_trailers(&mut self, trailers: HeaderMap) -> Result<()> {
        if self.ended {
            tracing::warn!("HTTP/3 trailers written after end of stream, dropped");
            return Ok(());
        }
        self.stream()
            .send_trailers(trailers)
            .await
            .or_err(ErrorType::WriteError, "while writing HTTP/3 trailers")
            .map_err(|e| e.into_down())?;
        self.finish_stream().await.map_err(|e| e.into_down())
    }

    async fn response_duplex_vec(&mut self, tasks: Vec<HttpTask>) -> Result<bool> {
        let mut end_stream = false;
        for task in tasks {
            end_stream = match task {
                HttpTask::Header(header, end) => {
                    self.write_response_header(header, end).await?;
                    end
                }
                HttpTask::Body(data, end) => {
                    // An empty final chunk is finished below, via end_stream.
                    if let Some(d) = data
                        && !d.is_empty()
                    {
                        self.write_body(d, end).await?;
                    }
                    end
                }
                HttpTask::UpgradedBody(..) => {
                    return Error::e_explain(
                        ErrorType::InternalError,
                        "upgraded body on HTTP/3 server session",
                    );
                }
                HttpTask::Trailer(Some(trailers)) => {
                    self.write_trailers(*trailers).await?;
                    true
                }
                HttpTask::Trailer(None) | HttpTask::Done => true,
                HttpTask::Failed(e) => return Err(e),
            } || end_stream;
        }
        if end_stream && self.response_written.is_some() {
            self.finish_stream().await.map_err(|e| e.into_down())?;
        }
        Ok(end_stream)
    }

    fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout;
    }

    fn get_read_timeout(&self) -> Option<Duration> {
        self.read_timeout
    }

    fn set_write_timeout(&mut self, timeout: Option<Duration>) {
        self.write_timeout = timeout;
    }

    fn get_write_timeout(&self) -> Option<Duration> {
        self.write_timeout
    }

    fn set_total_drain_timeout(&mut self, timeout: Option<Duration>) {
        self.total_drain_timeout = timeout;
    }

    fn get_total_drain_timeout(&self) -> Option<Duration> {
        self.total_drain_timeout
    }

    fn request_summary(&self) -> String {
        format!(
            "{} {}, Host: {} (h3)",
            self.req.method,
            self.req
                .uri
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or_default(),
            self.req
                .uri
                .authority()
                .map(|a| a.as_str())
                .unwrap_or_default(),
        )
    }

    fn response_written(&self) -> Option<&ResponseHeader> {
        self.response_written.as_deref()
    }

    async fn shutdown(&mut self, _code: u32, _ctx: &str) {
        if !self.ended {
            self.ended = true;
            let stream = self.stream();
            stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
            stream.stop_sending(h3::error::Code::H3_INTERNAL_ERROR);
        }
    }

    fn is_body_done(&mut self) -> bool {
        self.peek_body();
        self.body_done && self.pending.is_none()
    }

    async fn finish(&mut self) -> Result<()> {
        if self.response_written.is_some() {
            self.finish_stream().await.map_err(|e| e.into_down())?;
        }
        // else: dropping the stream unfinished tells the client it failed.
        Ok(())
    }

    fn is_body_empty(&mut self) -> bool {
        if self
            .req
            .headers
            .get(header::CONTENT_LENGTH)
            .is_some_and(|cl| cl.as_bytes() == b"0")
        {
            return true;
        }
        self.peek_body();
        self.body_read == 0 && self.body_done && self.pending.is_none()
    }

    async fn read_body_or_idle(&mut self, no_body_expected: bool) -> Result<Option<Bytes>> {
        if no_body_expected || self.is_body_done() {
            // Nothing more to read: wait for the client to go away, which is
            // what lets Pingora cancel work for a vanished visitor.
            let reason = self.conn.closed().await;
            Error::e_explain(
                ErrorType::ConnectionClosed,
                format!("HTTP/3 client closed the connection: {reason}"),
            )
        } else {
            self.read_body_bytes().await
        }
    }

    fn body_bytes_sent(&self) -> usize {
        self.body_sent
    }

    fn body_bytes_read(&self) -> usize {
        self.body_read
    }

    fn digest(&self) -> Option<&Digest> {
        Some(&self.digest)
    }

    fn digest_mut(&mut self) -> Option<&mut Digest> {
        Arc::get_mut(&mut self.digest)
    }

    fn client_addr(&self) -> Option<&SocketAddr> {
        Some(&self.client_addr)
    }

    fn server_addr(&self) -> Option<&SocketAddr> {
        None
    }

    fn pseudo_raw_h1_request_header(&self) -> Bytes {
        // Only used by subrequests, which this proxy does not spawn.
        Bytes::new()
    }

    fn enable_retry_buffering(&mut self) {
        if self.retry_buffer.is_none() {
            self.retry_buffer = Some(FixedBuffer::new(RETRY_BUFFER_LIMIT));
        }
    }

    fn retry_buffer_truncated(&self) -> bool {
        self.retry_buffer.as_ref().is_some_and(|b| b.is_truncated())
    }

    fn get_retry_buffer(&self) -> Option<Bytes> {
        self.retry_buffer.as_ref().and_then(|b| {
            if b.is_truncated() {
                None
            } else {
                b.get_buffer()
            }
        })
    }

    async fn finish_custom(&mut self) -> Result<()> {
        Ok(())
    }

    fn take_custom_message_reader(
        &mut self,
    ) -> Option<Box<dyn Stream<Item = Result<Bytes>> + Unpin + Send + Sync + 'static>> {
        None
    }

    fn restore_custom_message_reader(
        &mut self,
        _reader: Box<dyn Stream<Item = Result<Bytes>> + Unpin + Send + Sync + 'static>,
    ) -> Result<()> {
        Ok(())
    }

    fn take_custom_message_writer(&mut self) -> Option<Box<dyn CustomMessageWrite>> {
        None
    }

    fn restore_custom_message_writer(
        &mut self,
        _writer: Box<dyn CustomMessageWrite>,
    ) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn alt_svc_names_the_port() {
        assert_eq!(super::alt_svc_value(443), "h3=\":443\"; ma=86400");
    }
}
