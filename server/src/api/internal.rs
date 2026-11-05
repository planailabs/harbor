//! Internal API for the reverse proxy.
//!
//! Authenticated with a shared Bearer token from a state directory file.
//!
//! - `GET  /api/internal/routes`          — route table for the proxy
//! - `GET  /api/internal/certs`           — all valid certs (decrypted PEM)
//! - `POST /api/internal/certs/{domain}`  — trigger ACME cert issuance
//! - `GET  /api/internal/events`          — SSE stream (reload notifications)

use dioxus::fullstack::axum::{
    self as axum, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{
        Json,
        sse::{Event, Sse},
    },
    routing::{get, post},
};
use serde::Serialize;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::config;

/// Shared state for the internal API.
#[derive(Clone)]
pub struct InternalState {
    pub pool: PgPool,
    pub reload_tx: Arc<broadcast::Sender<()>>,
}

/// Global handle to the reload broadcast sender, set once during init.
static RELOAD_TX: std::sync::OnceLock<Arc<broadcast::Sender<()>>> = std::sync::OnceLock::new();

/// Store the reload sender globally so web components can trigger reloads.
pub fn set_reload_tx(tx: Arc<broadcast::Sender<()>>) {
    let _ = RELOAD_TX.set(tx);
}

/// Notify the proxy of route changes (callable from anywhere, e.g. web components).
pub fn notify_proxy_reload() {
    if let Some(tx) = RELOAD_TX.get() {
        let _ = tx.send(());
    }
}

pub fn router(state: InternalState) -> Router<()> {
    Router::new()
        .route("/api/internal/routes", get(get_routes))
        .route("/api/internal/certs", get(get_certs))
        .route("/api/internal/certs/{domain}", post(issue_cert))
        .route("/api/internal/events", get(sse_events))
        .with_state(state.clone())
        .merge(crate::api::basic_auth::internal_router(state.pool))
}

// ── Auth ──────────────────────────────────────────────────────────────

pub(crate) fn authenticate(headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    let cfg = config::config();
    let proxy_cfg = cfg.proxy.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "proxy not configured".into(),
    ))?;

    let expected_token = std::fs::read_to_string(&proxy_cfg.internal_token_path).map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "internal token not available".into(),
        )
    })?;
    let expected_token = expected_token.trim();

    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");

    if provided.is_empty() || !crate::api::basic_auth::constant_time_eq(provided, expected_token) {
        return Err((StatusCode::UNAUTHORIZED, "invalid token".into()));
    }

    Ok(())
}

// ── Routes ────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct RoutesResponse {
    routes: Vec<RouteEntry>,
    /// Seconds until the earliest relay proxy token expires.  The proxy
    /// should force a route re-fetch before this elapses.
    #[serde(skip_serializing_if = "Option::is_none")]
    token_lifetime_secs: Option<i64>,
}

#[derive(Serialize)]
struct RouteEntry {
    host: String,
    /// Mount path of this folder within the host (e.g. "/", "/api"). The proxy
    /// dispatches by host + longest-matching path_prefix.
    path_prefix: String,
    upstream: String,
    /// When set, this is a static folder served by the Harbor origin: the proxy
    /// proxies to `upstream` (the Harbor server), passes the Host through, and
    /// injects the internal token + this webspace id so the server serves the
    /// folder's files. Avoids the proxy needing filesystem access.
    #[serde(skip_serializing_if = "Option::is_none")]
    static_webspace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay: Option<RelayInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth: Option<AuthInfo>,
    /// The folder's edge headers, when they differ from the defaults.
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<HeadersInfo>,
}

/// How the edge's security headers apply to a folder (see the proxy's
/// `apply_security_headers`). Absent = all of them, framing denied.
#[derive(Serialize)]
struct HeadersInfo {
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    frame_ancestors: Option<String>,
}

fn headers_info(enabled: bool, frame_ancestors: Option<String>) -> Option<HeadersInfo> {
    (!enabled || frame_ancestors.is_some()).then_some(HeadersInfo {
        enabled,
        frame_ancestors,
    })
}

#[derive(Serialize)]
struct RelayInfo {
    /// Full relay URL to proxy to (e.g. https://abc123-ollama.relay.plan.ai)
    url: String,
    /// Minted proxy token for authenticating with the relay
    proxy_token: String,
    /// Pass the visitor's Host header through instead of rewriting it to the
    /// relay URL's hostname (tunnel folders only).
    passthrough_host: bool,
    /// Ready-to-send Authorization header value ("Basic ...") for the tunnel
    /// upstream (tunnel folders with a basic_auth credential).
    #[serde(skip_serializing_if = "Option::is_none")]
    basic_authorization: Option<String>,
    /// PEM client certificate chain + key presented to the tunnel upstream
    /// during the TLS handshake (tunnel folders with a client_cert credential).
    #[serde(skip_serializing_if = "Option::is_none")]
    client_cert_pem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_key_pem: Option<String>,
}

#[derive(Serialize, serde::Deserialize, Clone)]
struct AuthInfo {
    mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<uuid::Uuid>,
    /// For basic auth: the credential list the proxy gate verifies against. The
    /// proxy no longer receives the credentials themselves — validation happens
    /// on the Harbor login form (see `api::basic_auth`).
    #[serde(skip_serializing_if = "Option::is_none")]
    basic_list_id: Option<uuid::Uuid>,
}

/// In-memory cache for minted proxy tokens, keyed by credential ID.
static PROXY_TOKEN_CACHE: std::sync::LazyLock<
    std::sync::Mutex<
        std::collections::HashMap<uuid::Uuid, (String, chrono::DateTime<chrono::Utc>)>,
    >,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Get or mint a proxy token for the given mac-mgmt credential.
/// Returns `(token, expires_at)`.
async fn get_or_mint_proxy_token(
    pool: &PgPool,
    cred_id: uuid::Uuid,
) -> Result<(String, chrono::DateTime<chrono::Utc>), String> {
    // Check cache
    {
        let cache = PROXY_TOKEN_CACHE.lock().unwrap();
        if let Some((token, expires_at)) = cache.get(&cred_id) {
            if *expires_at > chrono::Utc::now() + chrono::Duration::minutes(5) {
                return Ok((token.clone(), *expires_at));
            }
        }
    }

    // Mint a new token
    let (server_url, admin_token) = crate::credentials::mac_mgmt_credential(pool, cred_id)
        .await
        .map_err(|e| format!("credential error: {e}"))?;

    // A short, bounded request: `get_routes` waits for these mints, and the
    // proxy gives up on `get_routes` after 30 s — one slow mac-mgmt must not
    // take every route down with it.
    static MINT_CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
        reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("reqwest client")
    });
    let resp = MINT_CLIENT
        .post(format!(
            "{}/api/proxy-token",
            server_url.trim_end_matches('/')
        ))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "scopes": ["tcp:*"],
        }))
        .send()
        .await
        .map_err(|e| format!("mint request to {server_url} failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let body: String = body.chars().take(300).collect();
        return Err(format!("mint at {server_url} failed ({status}): {body}"));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parse mint response: {e}"))?;
    let token = body["proxy_token"]
        .as_str()
        .ok_or("no proxy_token in mint response")?
        .to_string();
    let expires_at = body["expires_at"]
        .as_str()
        .and_then(|s| s.parse::<chrono::DateTime<chrono::Utc>>().ok())
        .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::hours(24));

    {
        let mut cache = PROXY_TOKEN_CACHE.lock().unwrap();
        cache.insert(cred_id, (token.clone(), expires_at));
    }

    Ok((token, expires_at))
}

/// A preview deployment of an unreleased build: a hostname with a
/// `dev-admin-<id>` label and a `cloud-test` label, and its wildcard bind.
///
/// Previews are the path by which unreleased builds reach the internet, so they
/// are gated even when nobody configured auth (see `build_auth_info`).
fn is_preview_host(host: &str) -> bool {
    let labels: Vec<&str> = host.trim_start_matches("*.").split('.').collect();
    labels.iter().any(|l| l.starts_with("dev-admin-")) && labels.contains(&"cloud-test")
}

/// Build an AuthInfo from webspace fields. Returns None for auth_mode = "none",
/// except on preview hosts, which default to org members only.
fn build_auth_info(
    host: &str,
    auth_mode: &str,
    org_id: uuid::Uuid,
    basic_list_id: Option<uuid::Uuid>,
) -> Option<AuthInfo> {
    match auth_mode {
        "oidc" => Some(AuthInfo {
            mode: "oidc".into(),
            org_id: Some(org_id),
            basic_list_id: None,
        }),
        "basic" => {
            let list_id = basic_list_id?;
            Some(AuthInfo {
                mode: "basic".into(),
                org_id: None,
                basic_list_id: Some(list_id),
            })
        }
        // Nothing explicit, but a preview host: org members (or admins, in the
        // gate) only. An explicit "oidc"/"basic" above still wins.
        _ if is_preview_host(host) => Some(AuthInfo {
            mode: "oidc".into(),
            org_id: Some(org_id),
            basic_list_id: None,
        }),
        _ => None,
    }
}

async fn get_routes(
    State(state): State<InternalState>,
    headers: HeaderMap,
) -> Result<Json<RoutesResponse>, (StatusCode, String)> {
    authenticate(&headers)?;

    let cfg = config::config();
    let proxy_cfg = cfg.proxy.as_ref().unwrap();

    let mut earliest_token_expiry: Option<chrono::DateTime<chrono::Utc>> = None;

    let mut routes = vec![RouteEntry {
        host: proxy_cfg.domain.clone(),
        path_prefix: "/".to_string(),
        upstream: proxy_cfg.upstream.clone(),
        static_webspace_id: None,
        relay: None,
        auth: None,
        headers: None,
    }];

    // Local folder routes. Static folders are served by the proxy directly from
    // their webroot directory; nodejs/docker folders are proxied to their local
    // port. The hostname comes from the host's domain bindings; the folder
    // supplies the mount path and auth. Only proxy-kind hosts are routed here.
    let rows = sqlx::query_as::<
        _,
        (
            String,
            Option<String>,
            String,
            Option<String>,
            Option<i32>,
            uuid::Uuid,
            uuid::Uuid,
            String,
            Option<uuid::Uuid>,
            bool,
            Option<String>,
        ),
    >(
        "SELECT d.name, s.name, w.path_prefix, w.runtime, w.local_port, w.id, w.organization_id, w.auth_mode, w.auth_basic_list_id, \
         w.security_headers, w.frame_ancestors \
         FROM webspace_host_domains whd \
         JOIN webspace_hosts h ON h.id = whd.webspace_host_id AND h.kind = 'proxy' \
         JOIN webspaces w ON w.webspace_host_id = h.id \
         JOIN domains d ON d.id = whd.domain_id \
         LEFT JOIN subdomains s ON s.id = whd.subdomain_id \
         WHERE w.hosting_type = 'local'",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    for (
        domain,
        subdomain,
        path_prefix,
        runtime,
        port,
        ws_id,
        org_id,
        auth_mode,
        basic_list_id,
        security_headers,
        frame_ancestors,
    ) in rows
    {
        let host = match subdomain.as_deref() {
            Some(sub) if sub != "@" => format!("{sub}.{domain}"),
            _ => domain,
        };
        let auth = build_auth_info(&host, &auth_mode, org_id, basic_list_id);
        if runtime.as_deref() == Some("static") {
            // Served by the Harbor origin (the server), not the proxy's disk.
            routes.push(RouteEntry {
                host,
                path_prefix,
                upstream: proxy_cfg.upstream.clone(),
                static_webspace_id: Some(ws_id.to_string()),
                relay: None,
                auth,
                headers: headers_info(security_headers, frame_ancestors),
            });
        } else if let Some(port) = port {
            routes.push(RouteEntry {
                host,
                path_prefix,
                upstream: format!("127.0.0.1:{port}"),
                static_webspace_id: None,
                relay: None,
                auth,
                headers: headers_info(security_headers, frame_ancestors),
            });
        }
        // nodejs/docker folders without a running port are not routed yet.
    }

    // Relay folder routes: (host hostname, folder path_prefix) → relay URL with proxy token
    let relay_rows = sqlx::query_as::<
        _,
        (
            String,
            Option<String>,
            String,
            String,
            uuid::Uuid,
            uuid::Uuid,
            String,
            Option<uuid::Uuid>,
            bool,
            Option<String>,
        ),
    >(
        "SELECT d.name, s.name, w.path_prefix, w.relay_url, w.relay_credential_id, w.organization_id, w.auth_mode, w.auth_basic_list_id, \
         w.security_headers, w.frame_ancestors \
         FROM webspace_host_domains whd \
         JOIN webspace_hosts h ON h.id = whd.webspace_host_id AND h.kind = 'proxy' \
         JOIN webspaces w ON w.webspace_host_id = h.id \
         JOIN domains d ON d.id = whd.domain_id \
         LEFT JOIN subdomains s ON s.id = whd.subdomain_id \
         WHERE w.hosting_type = 'relay' AND w.relay_url IS NOT NULL AND w.relay_credential_id IS NOT NULL",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Mint (or take from the cache) one proxy token per distinct credential,
    // all at once: a credential whose mint fails or times out only drops its
    // own relay routes, and the whole table is never held up by one server.
    let mut mints = tokio::task::JoinSet::new();
    let cred_ids: std::collections::HashSet<uuid::Uuid> =
        relay_rows.iter().map(|r| r.4).collect();
    for cred_id in cred_ids {
        let pool = state.pool.clone();
        mints.spawn(async move { (cred_id, get_or_mint_proxy_token(&pool, cred_id).await) });
    }
    let mut minted = std::collections::HashMap::new();
    while let Some(res) = mints.join_next().await {
        match res {
            Ok((cred_id, result)) => {
                if let Err(e) = &result {
                    tracing::error!(credential_id = %cred_id, "failed to mint proxy token: {e}");
                }
                minted.insert(cred_id, result);
            }
            Err(e) => tracing::error!("proxy token mint task failed: {e}"),
        }
    }

    for (
        domain,
        subdomain,
        path_prefix,
        relay_url,
        cred_id,
        org_id,
        auth_mode,
        basic_list_id,
        security_headers,
        frame_ancestors,
    ) in relay_rows
    {
        let host = match subdomain.as_deref() {
            Some(sub) if sub != "@" => format!("{sub}.{domain}"),
            _ => domain,
        };

        let upstream = parse_relay_upstream(&relay_url).ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("bad relay URL: {relay_url}"),
            )
        })?;

        let mint = minted
            .get(&cred_id)
            .cloned()
            .unwrap_or_else(|| Err("mint task failed".to_string()));
        let proxy_token = match mint {
            Ok((t, expires_at)) => {
                super::counters::COUNTERS
                    .relay_mint_success
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                {
                    let mut map = super::counters::RELAY_MINT_RESULTS.lock().unwrap();
                    map.insert(
                        host.clone(),
                        super::counters::MintResult {
                            org_id,
                            success: true,
                        },
                    );
                }
                earliest_token_expiry = Some(match earliest_token_expiry {
                    Some(prev) => prev.min(expires_at),
                    None => expires_at,
                });
                t
            }
            Err(e) => {
                tracing::error!(host = %host, credential_id = %cred_id, "relay route left out, no proxy token: {e}");
                super::counters::COUNTERS
                    .relay_mint_failed
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                {
                    let mut map = super::counters::RELAY_MINT_RESULTS.lock().unwrap();
                    map.insert(
                        host.clone(),
                        super::counters::MintResult {
                            org_id,
                            success: false,
                        },
                    );
                }
                continue;
            }
        };

        let auth = build_auth_info(&host, &auth_mode, org_id, basic_list_id);
        routes.push(RouteEntry {
            host,
            path_prefix,
            upstream,
            static_webspace_id: None,
            relay: Some(RelayInfo {
                url: relay_url,
                proxy_token,
                passthrough_host: false,
                basic_authorization: None,
                client_cert_pem: None,
                client_key_pem: None,
            }),
            auth,
            headers: headers_info(security_headers, frame_ancestors),
        });
    }

    // Tunnel folder routes: (host hostname, folder path_prefix) → upstream URL (no auth token)
    let tunnel_rows = sqlx::query_as::<
        _,
        (
            String,
            Option<String>,
            String,
            String,
            uuid::Uuid,
            String,
            Option<uuid::Uuid>,
            bool,
            Option<uuid::Uuid>,
            Option<uuid::Uuid>,
            bool,
            Option<String>,
        ),
    >(
        "SELECT d.name, s.name, w.path_prefix, w.relay_url, w.organization_id, w.auth_mode, w.auth_basic_list_id, \
         w.tunnel_passthrough_host, w.tunnel_client_cert_credential_id, w.tunnel_basic_auth_credential_id, \
         w.security_headers, w.frame_ancestors \
         FROM webspace_host_domains whd \
         JOIN webspace_hosts h ON h.id = whd.webspace_host_id AND h.kind = 'proxy' \
         JOIN webspaces w ON w.webspace_host_id = h.id \
         JOIN domains d ON d.id = whd.domain_id \
         LEFT JOIN subdomains s ON s.id = whd.subdomain_id \
         WHERE w.hosting_type = 'tunnel' AND w.relay_url IS NOT NULL",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    for (
        domain,
        subdomain,
        path_prefix,
        tunnel_url,
        org_id,
        auth_mode,
        basic_list_id,
        passthrough_host,
        client_cert_cred_id,
        basic_auth_cred_id,
        security_headers,
        frame_ancestors,
    ) in tunnel_rows
    {
        let host = match subdomain.as_deref() {
            Some(sub) if sub != "@" => format!("{sub}.{domain}"),
            _ => domain,
        };

        let upstream = parse_relay_upstream(&tunnel_url).ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("bad tunnel URL: {tunnel_url}"),
            )
        })?;

        let auth = build_auth_info(&host, &auth_mode, org_id, basic_list_id);

        // Best-effort credential resolution: a broken credential logs a
        // warning and the route still loads (the upstream will just 401 /
        // fail the handshake, same as before the credential existed).
        let basic_authorization = match basic_auth_cred_id {
            Some(cid) => match crate::credentials::basic_auth_credential(&state.pool, cid).await {
                Ok((user, pass)) => Some(format!(
                    "Basic {}",
                    base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        format!("{user}:{pass}"),
                    )
                )),
                Err(e) => {
                    tracing::warn!(host = %host, "tunnel basic_auth credential unusable: {e}");
                    None
                }
            },
            None => None,
        };
        let (client_cert_pem, client_key_pem) = match client_cert_cred_id {
            Some(cid) => match crate::credentials::client_cert_credential(&state.pool, cid).await {
                Ok((cert, key)) => (Some(cert), Some(key)),
                Err(e) => {
                    tracing::warn!(host = %host, "tunnel client_cert credential unusable: {e}");
                    (None, None)
                }
            },
            None => (None, None),
        };

        routes.push(RouteEntry {
            host,
            path_prefix,
            upstream,
            static_webspace_id: None,
            relay: Some(RelayInfo {
                url: tunnel_url,
                proxy_token: String::new(),
                passthrough_host,
                basic_authorization,
                client_cert_pem,
                client_key_pem,
            }),
            auth,
            headers: headers_info(security_headers, frame_ancestors),
        });
    }

    let token_lifetime_secs =
        earliest_token_expiry.map(|exp| (exp - chrono::Utc::now()).num_seconds().max(0));

    Ok(Json(RoutesResponse {
        routes,
        token_lifetime_secs,
    }))
}

/// Parse a relay URL like `https://host:port/...` into `host:port`.
fn parse_relay_upstream(url: &str) -> Option<String> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host_port = without_scheme.split('/').next()?;
    if host_port.contains(':') {
        Some(host_port.to_string())
    } else if url.starts_with("https://") {
        Some(format!("{host_port}:443"))
    } else {
        Some(format!("{host_port}:80"))
    }
}

// ── Certs ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct CertResponse {
    domain: String,
    chain_pem: String,
    key_pem: String,
}

async fn get_certs(
    State(state): State<InternalState>,
    headers: HeaderMap,
) -> Result<Json<Vec<CertResponse>>, (StatusCode, String)> {
    authenticate(&headers)?;

    let rows = sqlx::query_as::<_, (String, Vec<u8>, Vec<u8>)>(
        "SELECT domain, encrypted_chain, encrypted_key FROM certificates \
         WHERE not_after > now() AND acme_status IN ('valid', 'none') \
         ORDER BY domain",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut certs = Vec::new();
    for (domain, enc_chain, enc_key) in rows {
        let chain = crate::crypto::decrypt(&enc_chain).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("decrypt error: {e}"),
            )
        })?;
        let key = crate::crypto::decrypt(&enc_key).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("decrypt error: {e}"),
            )
        })?;
        certs.push(CertResponse {
            domain,
            chain_pem: String::from_utf8_lossy(&chain).into_owned(),
            key_pem: String::from_utf8_lossy(&key).into_owned(),
        });
    }

    Ok(Json(certs))
}

// ── Cert issuance ─────────────────────────────────────────────────────

#[derive(Serialize)]
struct IssueResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

async fn issue_cert(
    State(state): State<InternalState>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<IssueResponse>, (StatusCode, String)> {
    authenticate(&headers)?;

    // Check if already pending
    let existing =
        sqlx::query_scalar::<_, String>("SELECT acme_status FROM certificates WHERE domain = $1")
            .bind(&domain)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if existing.as_deref() == Some("pending") {
        return Ok(Json(IssueResponse {
            status: "pending".into(),
            message: None,
        }));
    }

    if existing.as_deref() == Some("valid") {
        // Check if still valid (not expiring soon)
        let not_expired = sqlx::query_scalar::<_, bool>(
            "SELECT not_after > now() + interval '7 days' FROM certificates WHERE domain = $1",
        )
        .bind(&domain)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        if not_expired == Some(true) {
            return Ok(Json(IssueResponse {
                status: "valid".into(),
                message: Some("cert still valid".into()),
            }));
        }
    }

    // Trigger issuance in background. If this domain belongs to a proxy host,
    // provision certs for all of the host's bound domains (each FQDN needs its
    // own cert), not just the requested one.
    let pool = state.pool.clone();
    let domain_clone = domain.clone();
    tokio::spawn(async move {
        let host_id: Option<uuid::Uuid> = sqlx::query_scalar(
            "SELECT whd.webspace_host_id \
             FROM webspace_host_domains whd \
             JOIN webspace_hosts h ON h.id = whd.webspace_host_id AND h.kind = 'proxy' \
             JOIN domains d ON d.id = whd.domain_id \
             LEFT JOIN subdomains s ON s.id = whd.subdomain_id \
             WHERE CASE WHEN s.name IS NOT NULL AND s.name != '@' \
                        THEN s.name || '.' || d.name ELSE d.name END = $1 \
             LIMIT 1",
        )
        .bind(&domain_clone)
        .fetch_optional(&pool)
        .await
        .ok()
        .flatten();

        let result = match host_id {
            Some(hid) => crate::api::acme::issue_host_certs(&pool, hid).await,
            None => crate::api::acme::issue_cert(&pool, &domain_clone).await,
        };
        match result {
            Ok(()) => {
                tracing::info!(domain = %domain_clone, "cert issuance complete");
            }
            Err(e) => {
                tracing::error!(domain = %domain_clone, "cert issuance failed: {e}");
            }
        }
    });

    Ok(Json(IssueResponse {
        status: "pending".into(),
        message: Some("issuance started".into()),
    }))
}

// ── Proxy gate (OIDC auth for webspaces) ─────────────────────────────

fn sign_proxy_gate(internal_token: &str, org_id: uuid::Uuid, expiry_ts: i64) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let msg = format!("proxy-gate:{org_id}:{expiry_ts}");
    let mut mac = Hmac::<Sha256>::new_from_slice(internal_token.as_bytes()).unwrap();
    mac.update(msg.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[derive(serde::Deserialize)]
pub struct ProxyGateParams {
    return_url: String,
}

/// OIDC proxy gate — mounted on the web router (behind OIDC auth middleware).
/// The proxy redirects unauthenticated users here. After the user logs in on the
/// Harbor domain, this endpoint validates org membership and redirects back to
/// the webspace with a signed token.
pub async fn proxy_gate(
    axum::extract::Query(params): axum::extract::Query<ProxyGateParams>,
    axum::extract::Extension(user): axum::extract::Extension<plan_ai_auth::WebUser>,
    headers: HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let lang = plan_ai_html::Lang::from_accept_language(
        headers
            .get("accept-language")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
    );
    // Browser-facing failures: render a localized HTML error page.
    let err = |code: StatusCode, tk: &str, bk: &str| -> axum::response::Response {
        (
            code,
            [("content-type", "text/html; charset=utf-8")],
            plan_ai_html::error_page(lang, tk, bk),
        )
            .into_response()
    };

    let Ok(pool) = crate::server_pool() else {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "error-title",
            "error-body",
        );
    };

    // Parse hostname from return_url
    let return_url = &params.return_url;
    let Some(hostname) = return_url
        .strip_prefix("https://")
        .or_else(|| return_url.strip_prefix("http://"))
        .and_then(|s| s.split('/').next())
        .and_then(|s| s.split(':').next())
    else {
        return err(StatusCode::BAD_REQUEST, "error-title", "error-body");
    };

    // Find which org owns the host bound to this hostname that has an
    // OIDC-protected folder — or a preview host, which is gated by default.
    // The wildcard bind ("*.cms.dev-admin-…") covers any single first label.
    let wildcard = match hostname.split_once('.') {
        Some((_, rest)) => format!("*.{rest}"),
        None => hostname.to_string(),
    };
    let org_id = match sqlx::query_as::<_, (uuid::Uuid, String)>(
        "SELECT h.organization_id, w.auth_mode FROM webspace_host_domains whd \
         JOIN webspace_hosts h ON h.id = whd.webspace_host_id \
         JOIN webspaces w ON w.webspace_host_id = h.id \
         JOIN domains d ON d.id = whd.domain_id \
         LEFT JOIN subdomains s ON s.id = whd.subdomain_id \
         WHERE (CASE WHEN s.name IS NOT NULL AND s.name != '@' \
                THEN s.name || '.' || d.name ELSE d.name END) = ANY($1) \
         AND w.auth_mode IN ('oidc', 'none')",
    )
    .bind(&[hostname.to_string(), wildcard][..])
    .fetch_all(&pool)
    .await
    {
        Ok(rows) => {
            // An explicitly OIDC-gated folder wins; otherwise a preview host's
            // default gate is the org that owns it.
            let hit = rows
                .iter()
                .find(|(_, mode)| mode == "oidc")
                .or_else(|| rows.first().filter(|_| is_preview_host(hostname)));
            match hit {
                Some((org_id, _)) => *org_id,
                None => {
                    return err(
                        StatusCode::NOT_FOUND,
                        "unknown-host-title",
                        "unknown-host-body",
                    );
                }
            }
        }
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "error-title",
                "error-body",
            );
        }
    };

    // Check user has org membership (any role) or is admin
    if !user.is_admin && !user.org_ids().contains(&org_id) {
        return err(StatusCode::FORBIDDEN, "forbidden-title", "forbidden-body");
    }

    // Sign a gate token (valid for 5 minutes — the proxy will exchange it for a 24h cookie)
    let cfg = config::config();
    let Some(proxy_cfg) = cfg.proxy.as_ref() else {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "error-title",
            "error-body",
        );
    };
    let Ok(internal_token) = std::fs::read_to_string(&proxy_cfg.internal_token_path) else {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "error-title",
            "error-body",
        );
    };
    let internal_token = internal_token.trim();

    let expiry_ts = chrono::Utc::now().timestamp() + 300; // 5 minutes
    let sig = sign_proxy_gate(internal_token, org_id, expiry_ts);

    // Append gate params to return_url
    let separator = if return_url.contains('?') { "&" } else { "?" };
    let redirect =
        format!("{return_url}{separator}__pg_token={sig}&__pg_oid={org_id}&__pg_exp={expiry_ts}");

    axum::response::Redirect::temporary(&redirect).into_response()
}

// ── SSE ───────────────────────────────────────────────────────────────

async fn sse_events(
    State(state): State<InternalState>,
    headers: HeaderMap,
) -> Result<
    Sse<impl futures_core::Stream<Item = Result<Event, std::convert::Infallible>>>,
    (StatusCode, String),
> {
    authenticate(&headers)?;

    let mut rx = state.reload_tx.subscribe();

    let stream = async_stream::stream! {
        let mut ping_interval = tokio::time::interval(std::time::Duration::from_secs(15));
        ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                result = rx.recv() => {
                    match result {
                        Ok(()) => {
                            yield Ok(Event::default().event("reload").data("{}"));
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::debug!("SSE subscriber lagged by {n} messages");
                            yield Ok(Event::default().event("reload").data("{}"));
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                _ = ping_interval.tick() => {
                    yield Ok(Event::default().event("ping").data("{}"));
                }
            }
        }
    };

    Ok(Sse::new(stream))
}

#[cfg(test)]
mod tests {
    use super::{build_auth_info, is_preview_host};

    #[test]
    fn preview_hosts_are_recognised() {
        for host in [
            "mv.dev-admin-f05ad5.cloud-test.plan.ai",
            "*.cms.dev-admin-f05ad5.cloud-test.plan.ai",
            "cms.dev-admin-f05ad5.cloud-test.plan.ai",
        ] {
            assert!(is_preview_host(host), "{host} is a preview host");
        }
        for host in [
            "cms.plan.ai",
            "agency.plan.ai",
            "dev-admin-f05ad5.plan.ai", // no cloud-test label
            "mv.cloud-test.plan.ai",
            "cms.dev-admin-f05ad5.example.com", // not a preview namespace
        ] {
            assert!(!is_preview_host(host), "{host} is not a preview host");
        }
    }

    #[test]
    fn preview_hosts_default_to_org_oidc() {
        let org = uuid::Uuid::nil();
        // No explicit mode: the preview default applies.
        let auth = build_auth_info("mv.dev-admin-1.cloud-test.plan.ai", "none", org, None)
            .expect("preview hosts are gated");
        assert_eq!(auth.mode, "oidc");
        assert_eq!(auth.org_id, Some(org));
        // A normal webspace with no mode stays open.
        assert!(build_auth_info("cms.plan.ai", "none", org, None).is_none());
        // An explicit mode still wins on a preview host.
        let list = uuid::Uuid::nil();
        let basic = build_auth_info(
            "mv.dev-admin-1.cloud-test.plan.ai",
            "basic",
            org,
            Some(list),
        )
        .unwrap();
        assert_eq!(basic.mode, "basic");
        assert_eq!(basic.basic_list_id, Some(list));
    }
}
