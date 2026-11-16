use arc_swap::ArcSwap;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::ssl::{NameType, SslRef};
use pingora::tls::x509::X509;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

use pingora::listeners::TlsAccept;

/// A parsed certificate + private key pair ready for TLS handshake.
#[derive(Clone)]
pub struct CertKey {
    pub cert: X509,
    pub chain: Vec<X509>,
    pub key: PKey<Private>,
    /// The same certificate and key for the QUIC listener, which does its
    /// TLS 1.3 with rustls rather than BoringSSL. Built once when the PEM is
    /// loaded so a handshake never converts anything. `None` when rustls
    /// cannot use the key; QUIC handshakes for that name then fail and the
    /// client stays on TCP.
    pub quic: Option<Arc<rustls::sign::CertifiedKey>>,
}

impl CertKey {
    pub fn from_pem(chain_pem: &str, key_pem: &str) -> anyhow::Result<Self> {
        let mut certs = X509::stack_from_pem(chain_pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("invalid cert PEM: {e}"))?;
        if certs.is_empty() {
            anyhow::bail!("cert PEM contained no certificates");
        }
        let cert = certs.remove(0);
        let key = PKey::private_key_from_pem(key_pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("invalid key PEM: {e}"))?;
        let quic = match rustls_certified_key(&cert, &certs, &key) {
            Ok(ck) => Some(Arc::new(ck)),
            Err(e) => {
                tracing::warn!("certificate not usable for QUIC: {e}");
                None
            }
        };
        Ok(Self {
            cert,
            chain: certs,
            key,
            quic,
        })
    }
}

/// The rustls form of a parsed certificate: the same DER the BoringSSL side
/// sends, and the same key.
fn rustls_certified_key(
    cert: &X509,
    chain: &[X509],
    key: &PKey<Private>,
) -> anyhow::Result<rustls::sign::CertifiedKey> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let certs = std::iter::once(cert)
        .chain(chain)
        .map(|c| c.to_der().map(CertificateDer::from))
        .collect::<Result<Vec<_>, _>>()?;
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.private_key_to_der_pkcs8()?));
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)?;
    Ok(rustls::sign::CertifiedKey::new(certs, signing_key))
}

/// Dynamic certificate store that resolves certs by SNI hostname
/// during the TLS handshake callback. Uses ArcSwap for lock-free reads.
pub struct CertStore {
    certs: ArcSwap<HashMap<String, Arc<CertKey>>>,
    fallback: Arc<CertKey>,
}

impl CertStore {
    pub fn new(fallback: Arc<CertKey>) -> Self {
        Self {
            certs: ArcSwap::from_pointee(HashMap::new()),
            fallback,
        }
    }

    /// Replace all certs at once (called on reload).
    pub fn replace_all(&self, map: HashMap<String, Arc<CertKey>>) {
        self.certs.store(Arc::new(map));
    }

    pub fn has_cert(&self, domain: &str) -> bool {
        self.certs.load().contains_key(domain)
    }

    /// Exact SNI match first, then the single-label wildcard cert
    /// ("foo.example.com" → "*.example.com"), then the self-signed fallback.
    fn lookup(&self, sni: &str) -> Arc<CertKey> {
        let certs = self.certs.load();
        if let Some(ck) = certs.get(sni) {
            return ck.clone();
        }
        if let Some((_, rest)) = sni.split_once('.') {
            if let Some(ck) = certs.get(&format!("*.{rest}")) {
                return ck.clone();
            }
        }
        self.fallback.clone()
    }
}

/// The QUIC listener's certificate selection: the same lookup, on the same
/// live map, as the TCP listener's BoringSSL callback below.
impl rustls::server::ResolvesServerCert for CertStore {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let sni = client_hello.server_name().unwrap_or("").to_lowercase();
        self.lookup(&sni).quic.clone()
    }
}

impl std::fmt::Debug for CertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertStore")
            .field("certs", &self.certs.load().len())
            .finish_non_exhaustive()
    }
}

/// Wrapper so we can put `Arc<CertStore>` into `Box<dyn TlsAccept>` while
/// still sharing the store with the sync task.
pub struct CertStoreCallback(pub Arc<CertStore>);

#[async_trait::async_trait]
impl TlsAccept for CertStoreCallback {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        let sni = ssl
            .servername(NameType::HOST_NAME)
            .unwrap_or("")
            .to_lowercase();

        let ck = self.0.lookup(&sni);

        if let Err(e) = ssl.set_certificate(&ck.cert) {
            tracing::error!(sni = %sni, "failed to set certificate: {e}");
            return;
        }
        for intermediate in &ck.chain {
            if let Err(e) = ssl.add_chain_cert(intermediate) {
                tracing::error!(sni = %sni, "failed to add chain cert: {e}");
                return;
            }
        }
        if let Err(e) = ssl.set_private_key(&ck.key) {
            tracing::error!(sni = %sni, "failed to set private key: {e}");
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CertEntry {
    pub domain: String,
    pub chain_pem: String,
    pub key_pem: String,
}
