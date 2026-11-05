//! Shared credential helpers for building API clients.
//!
//! Consolidates the repeated "fetch encrypted credential → decrypt → parse JSON → build client"
//! pattern that was duplicated across domain_detail, webspace_detail, domain_list, domain_import,
//! domain_add, domain_register, credential_form, credential_edit, api/sync, and api/deploy.

use sqlx::PgPool;
use std::net::IpAddr;
use uuid::Uuid;

/// Reject outbound URLs that point at the loopback interface, private/link-local
/// ranges, or cloud metadata endpoints. Stored credential URLs are used verbatim
/// as request targets, so without this an operator who can create a credential
/// could turn a server-side fetch into an SSRF against internal services (e.g.
/// http://169.254.169.254/ or http://localhost:2375/). Call at credential
/// creation and again before each outbound request.
pub fn validate_outbound_url(url: &str) -> anyhow::Result<()> {
    // Test escape hatch: integration/NixOS tests point credentials at mock
    // APIs on loopback. Never set in production.
    let allow_private = std::env::var("WEB_AGENCY_ALLOW_PRIVATE_APIS").as_deref() == Ok("1");
    validate_outbound_url_impl(url, allow_private)
}

fn validate_outbound_url_impl(url: &str, allow_private: bool) -> anyhow::Result<()> {
    let parsed = reqwest::Url::parse(url).map_err(|e| anyhow::anyhow!("invalid url: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        anyhow::bail!("url scheme must be http or https");
    }
    if allow_private {
        return Ok(());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("url has no host"))?;
    // `host_str` keeps IPv6 literals bracketed; strip for parsing.
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        reject_private_ip(ip)?;
    } else {
        let d = host.trim_end_matches('.').to_ascii_lowercase();
        if d == "localhost" || d.ends_with(".localhost") || d == "metadata" {
            anyhow::bail!("url host is not permitted");
        }
    }
    Ok(())
}

fn reject_private_ip(ip: IpAddr) -> anyhow::Result<()> {
    let blocked = match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                // CGNAT 100.64.0.0/10
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // unique-local fc00::/7 and link-local fe80::/10
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // IPv4-mapped — re-check the embedded v4
                || v6.to_ipv4_mapped().is_some_and(|m| reject_private_ip(IpAddr::V4(m)).is_err())
        }
    };
    if blocked {
        anyhow::bail!("url resolves to a non-public address");
    }
    Ok(())
}

/// Fetch and decrypt a credential's JSON data from the database.
pub async fn credential_json(
    pool: &PgPool,
    cred_id: Uuid,
    cred_type: &str,
) -> anyhow::Result<serde_json::Value> {
    let encrypted = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT encrypted_data FROM credentials WHERE id = $1 AND credential_type = $2",
    )
    .bind(cred_id)
    .bind(cred_type)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow::anyhow!("{cred_type} credential {cred_id} not found"))?;
    let decrypted = crate::crypto::decrypt(&encrypted)?;
    Ok(serde_json::from_slice(&decrypted)?)
}

/// Optional per-credential API base URL override (`api_url` key). Used to
/// point clients at mock APIs in tests; validated like every stored URL.
fn credential_api_url(data: &serde_json::Value) -> anyhow::Result<Option<&str>> {
    match data["api_url"].as_str() {
        Some(url) if !url.is_empty() => {
            validate_outbound_url(url)?;
            Ok(Some(url))
        }
        _ => Ok(None),
    }
}

/// Build a Cloudflare API client from a stored credential.
pub async fn cf_client(
    pool: &PgPool,
    cred_id: Uuid,
) -> anyhow::Result<cloudflare_api::compat::SimpleClient> {
    let data = credential_json(pool, cred_id, "cloudflare").await?;
    let token = data["api_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing api_token"))?;
    Ok(match credential_api_url(&data)? {
        Some(url) => cloudflare_api::compat::SimpleClient::with_base_url(url, token),
        None => cloudflare_api::compat::SimpleClient::new(token),
    })
}

/// Build a Cloudflare API client and resolve the account ID.
/// If the credential has no account_id stored, resolves it via the API
/// and backfills it into the encrypted credential data so future calls are instant.
pub async fn cf_client_with_account(
    pool: &PgPool,
    cred_id: Uuid,
) -> anyhow::Result<(cloudflare_api::compat::SimpleClient, String)> {
    let data = credential_json(pool, cred_id, "cloudflare").await?;
    let token = data["api_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing api_token"))?;
    let configured = data["account_id"].as_str().unwrap_or("");
    let client = match credential_api_url(&data)? {
        Some(url) => cloudflare_api::compat::SimpleClient::with_base_url(url, token),
        None => cloudflare_api::compat::SimpleClient::new(token),
    };
    let account_id = client.resolve_account_id(configured).await?;

    // Backfill account_id if it was empty
    if configured.is_empty() && !account_id.is_empty() {
        let mut updated = data.clone();
        updated["account_id"] = serde_json::Value::String(account_id.clone());
        if let Ok(encrypted) =
            crate::crypto::encrypt(serde_json::to_vec(&updated).unwrap_or_default().as_slice())
        {
            let _ = sqlx::query(
                "UPDATE credentials SET encrypted_data = $1, updated_at = now() WHERE id = $2",
            )
            .bind(&encrypted)
            .bind(cred_id)
            .execute(pool)
            .await;
            tracing::info!(cred_id = %cred_id, account_id = %account_id, "backfilled account_id into credential");
        }
    }

    Ok((client, account_id))
}

/// Fetch the server URL and token from a mac-mgmt credential.
pub async fn mac_mgmt_credential(pool: &PgPool, cred_id: Uuid) -> anyhow::Result<(String, String)> {
    let data = credential_json(pool, cred_id, "mac-mgmt").await?;
    let server_url = data["server_url"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing server_url"))?
        .to_string();
    validate_outbound_url(&server_url)?;
    let token = data["token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing token"))?
        .to_string();
    Ok((server_url, token))
}

/// Build a ChangeDetection.io API client from a stored credential.
///
/// Returns the client (with `x-api-key` injected as a default header) and the
/// group name that watches should be organized under.
pub async fn changedetection_client(
    pool: &PgPool,
    cred_id: Uuid,
) -> anyhow::Result<(changedetection_api::Client, String)> {
    let data = credential_json(pool, cred_id, "changedetection").await?;
    let api_url = data["api_url"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing api_url"))?;
    validate_outbound_url(api_url)?;
    let api_key = data["api_key"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing api_key"))?;
    let group = data["group"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing group"))?
        .to_string();

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::HeaderName::from_static("x-api-key"),
        reqwest::header::HeaderValue::from_str(api_key)
            .map_err(|e| anyhow::anyhow!("invalid api_key header value: {e}"))?,
    );
    let http = reqwest::ClientBuilder::new()
        .default_headers(headers)
        .connect_timeout(std::time::Duration::from_secs(15))
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    Ok((
        changedetection_api::Client::new_with_client(api_url, http),
        group,
    ))
}

/// PEM certificate chain + private key from a `client_cert` credential
/// (presented to tunnel upstreams as a TLS client certificate).
pub async fn client_cert_credential(
    pool: &PgPool,
    cred_id: Uuid,
) -> anyhow::Result<(String, String)> {
    let data = credential_json(pool, cred_id, "client_cert").await?;
    let cert = data["cert_pem"]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing cert_pem"))?
        .to_string();
    let key = data["key_pem"]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing key_pem"))?
        .to_string();
    Ok((cert, key))
}

/// Username + password from a `basic_auth` credential (injected as an
/// Authorization header toward tunnel upstreams).
pub async fn basic_auth_credential(
    pool: &PgPool,
    cred_id: Uuid,
) -> anyhow::Result<(String, String)> {
    let data = credential_json(pool, cred_id, "basic_auth").await?;
    let username = data["username"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing username"))?
        .to_string();
    let password = data["password"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing password"))?
        .to_string();
    Ok((username, password))
}

/// Build a Spaceship API client from a stored credential.
pub async fn spaceship_client(
    pool: &PgPool,
    cred_id: Uuid,
) -> anyhow::Result<spaceship_api::compat::SimpleClient> {
    let data = credential_json(pool, cred_id, "spaceship").await?;
    let key = data["api_key"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing api_key"))?;
    let secret = data["api_secret"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing api_secret"))?;
    Ok(match credential_api_url(&data)? {
        Some(url) => spaceship_api::compat::SimpleClient::with_base_url(url, key, secret),
        None => spaceship_api::compat::SimpleClient::new(key, secret),
    })
}

#[cfg(all(test, feature = "server"))]
pub(crate) mod pg_tests {
    use sqlx::PgPool;
    use uuid::Uuid;

    /// Process-global test setup: rustls provider, config file + env vars.
    /// Everything env-related must happen here, before any config::load call.
    fn init_env() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            // Workspace feature unification builds reqwest with rustls-no-provider.
            let _ = rustls::crypto::ring::default_provider().install_default();

            let dir = std::env::temp_dir().join(format!("web-agency-test-{}", std::process::id()));
            let hosting = dir.join("hosting");
            std::fs::create_dir_all(&hosting).unwrap();

            use rand::Rng;
            let key_bytes: [u8; 32] = rand::rng().random();
            let key =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key_bytes);

            // The database URL is a placeholder: every test connects its own
            // pool straight to its pgtemp cluster; config is only consulted
            // for the encryption key.
            let config = format!(
                "[database]\nurl = \"postgres://placeholder/placeholder\"\n\n\
                 [local_hosting]\ndir = \"{}\"\n\n\
                 [secrets]\nencryption_key = \"{key}\"\n",
                hosting.display()
            );
            let config_path = dir.join("config.toml");
            std::fs::write(&config_path, config).unwrap();

            unsafe {
                std::env::set_var("CONFIG_PATH", &config_path);
                std::env::set_var("WEB_AGENCY_ALLOW_PRIVATE_APIS", "1");
            }
            crate::config::load();
        });
    }

    /// Base directory for the throwaway Postgres clusters `pgtemp` spins up.
    ///
    /// `pgtemp` creates its cluster inside `$TMPDIR`. When the test binary runs
    /// as root — which the CI `nix-image` job does — `pgtemp` `chown -R`s
    /// *only that cluster directory* to the `postgres` user and then execs
    /// `initdb`/`postgres` as `postgres`, so every parent of the cluster has to
    /// be traversable by that user as well. `nix develop` points `$TMPDIR` at a
    /// mode-0700 `nix-shell.XXXXXX` directory, which `postgres` cannot enter, and
    /// `initdb` then aborts with
    /// `could not open file ".../user_password.txt" for reading: Permission denied`.
    /// Anchor the clusters under the shared system temp root instead, which is
    /// world-traversable everywhere.
    fn pgtemp_data_dir_prefix() -> std::path::PathBuf {
        #[cfg(unix)]
        {
            std::path::PathBuf::from("/tmp")
        }
        #[cfg(not(unix))]
        {
            std::env::temp_dir()
        }
    }

    /// Boot a throwaway Postgres cluster and run the server migrations.
    /// The returned `PgTempDB` must stay alive for the duration of the test.
    pub(crate) async fn test_db() -> (pgtemp::PgTempDB, PgPool) {
        init_env();
        let db = pgtemp::PgTempDB::builder()
            .with_data_dir_prefix(pgtemp_data_dir_prefix())
            .start_async()
            .await;
        let pool = PgPool::connect(&db.connection_uri()).await.unwrap();
        sqlx::migrate!().run(&pool).await.unwrap();
        (db, pool)
    }

    async fn serve(router: axum::Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        format!("http://{addr}")
    }

    async fn insert_credential(
        pool: &PgPool,
        name: &str,
        cred_type: &str,
        data: &serde_json::Value,
    ) -> Uuid {
        let encrypted = crate::crypto::encrypt(&serde_json::to_vec(data).unwrap()).unwrap();
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO credentials (name, credential_type, encrypted_data) \
             VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(name)
        .bind(cred_type)
        .bind(&encrypted)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn cloudflare_resolves_and_backfills_account_id() {
        let (_db, pool) = test_db().await;
        let base = serve(mock_cloudflare::router()).await;
        let cred_id = insert_credential(
            &pool,
            "cf",
            "cloudflare",
            &serde_json::json!({ "api_token": "test-token", "api_url": base }),
        )
        .await;

        let (_client, account_id) = super::cf_client_with_account(&pool, cred_id).await.unwrap();
        assert_eq!(account_id.len(), 32);
        assert!(account_id.chars().all(|c| c.is_ascii_hexdigit()));

        // The resolved account_id must have been backfilled into the row.
        let data = super::credential_json(&pool, cred_id, "cloudflare")
            .await
            .unwrap();
        assert_eq!(data["account_id"].as_str(), Some(account_id.as_str()));
    }

    #[tokio::test]
    async fn spaceship_checks_availability() {
        let (_db, pool) = test_db().await;
        let base = serve(mock_spaceship::router()).await;
        let cred_id = insert_credential(
            &pool,
            "space",
            "spaceship",
            &serde_json::json!({
                "api_key": "test-key",
                "api_secret": "test-secret",
                "api_url": base,
            }),
        )
        .await;

        let client = super::spaceship_client(&pool, cred_id).await.unwrap();
        let avail = client.check_availability("free.example").await.unwrap();
        assert_eq!(avail.domain.as_deref(), Some("free.example"));
        assert_eq!(avail.status.as_deref(), Some("available"));
    }

    #[tokio::test]
    async fn changedetection_returns_client_and_group() {
        let (_db, pool) = test_db().await;
        let base = serve(mock_changedetection::router()).await;
        let cred_id = insert_credential(
            &pool,
            "cd",
            "changedetection",
            &serde_json::json!({
                "api_url": base,
                "api_key": "test-key",
                "group": "watch-group",
            }),
        )
        .await;

        let (client, group) = super::changedetection_client(&pool, cred_id).await.unwrap();
        assert_eq!(group, "watch-group");
        let info = client.get_system_info().await.unwrap().into_inner();
        assert!(info.version.is_some());
    }

    #[tokio::test]
    async fn missing_credential_is_not_found() {
        let (_db, pool) = test_db().await;
        let missing = Uuid::new_v4();
        let err = match super::cf_client(&pool, missing).await {
            Ok(_) => panic!("expected missing credential to error"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("not found"), "got: {err}");
    }
}

#[cfg(test)]
mod ssrf_tests {
    // The pg_tests above set WEB_AGENCY_ALLOW_PRIVATE_APIS=1 process-wide, so
    // exercise the check below the env escape hatch directly.
    fn validate_outbound_url(url: &str) -> anyhow::Result<()> {
        super::validate_outbound_url_impl(url, false)
    }

    #[test]
    fn blocks_metadata_and_loopback_and_private() {
        for bad in [
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:2375/",
            "http://127.0.0.1/",
            "http://[::1]/",
            "http://10.0.0.5/",
            "http://192.168.1.1/",
            "http://100.64.0.1/",
            "http://metadata/computeMetadata/v1/",
            "ftp://example.com/",
            "file:///etc/passwd",
        ] {
            assert!(
                validate_outbound_url(bad).is_err(),
                "{bad} should be blocked"
            );
        }
    }

    #[test]
    fn allows_public_hosts() {
        for ok in ["https://api.example.com/", "http://203.0.113.10:8080/x"] {
            assert!(validate_outbound_url(ok).is_ok(), "{ok} should be allowed");
        }
    }
}
