//! ACME certificate issuance via Let's Encrypt with Cloudflare DNS-01 challenges.

use sqlx::PgPool;
use uuid::Uuid;

/// Issue a TLS certificate for the given domain using ACME DNS-01 challenge.
///
/// Looks up the domain's Cloudflare credentials in the database, creates a
/// DNS-01 TXT record via the CF API, completes the ACME challenge, and stores
/// the resulting certificate (encrypted) in the `certificates` table.
pub async fn issue_cert(pool: &PgPool, domain: &str) -> anyhow::Result<()> {
    // 1. Look up CF credentials, walking up every parent suffix.
    // For "a.b.plan.ai" the zone is registered as "plan.ai", so try
    // "a.b.plan.ai", "b.plan.ai", "plan.ai", ... until one has credentials.
    let mut candidate = domain;
    let row = loop {
        let found = sqlx::query_as::<_, (Uuid, String)>(
            "SELECT cloudflare_credential_id, cloudflare_zone_id \
             FROM domains \
             WHERE name = $1 \
               AND cloudflare_credential_id IS NOT NULL \
               AND cloudflare_zone_id IS NOT NULL",
        )
        .bind(candidate)
        .fetch_optional(pool)
        .await?;
        if let Some(r) = found {
            break r;
        }
        match candidate.find('.') {
            Some(dot) => candidate = &candidate[dot + 1..],
            None => anyhow::bail!("domain {domain} has no Cloudflare credentials"),
        }
    };

    let (cred_id, zone_id) = row;

    // 2. Mark as pending
    sqlx::query(
        "INSERT INTO certificates (domain, encrypted_chain, encrypted_key, issuer, not_before, not_after, acme_status) \
         VALUES ($1, '\\x00', '\\x00', 'acme', now(), now(), 'pending') \
         ON CONFLICT (domain) DO UPDATE SET acme_status = 'pending', last_error = NULL, updated_at = now()",
    )
    .bind(domain)
    .execute(pool)
    .await?;

    // 3. Run ACME flow
    let result = run_acme_flow(pool, domain, cred_id, &zone_id).await;

    match &result {
        Ok((chain_pem, key_pem)) => {
            // Parse cert to get validity dates
            let not_before = chrono::Utc::now();
            let not_after = not_before + chrono::Duration::days(90);

            let enc_chain = crate::crypto::encrypt(chain_pem.as_bytes())
                .map_err(|e| anyhow::anyhow!("encrypt chain: {e}"))?;
            let enc_key = crate::crypto::encrypt(key_pem.as_bytes())
                .map_err(|e| anyhow::anyhow!("encrypt key: {e}"))?;

            sqlx::query(
                "UPDATE certificates SET \
                    encrypted_chain = $2, encrypted_key = $3, \
                    issuer = 'letsencrypt', not_before = $4, not_after = $5, \
                    acme_status = 'valid', last_error = NULL, updated_at = now() \
                 WHERE domain = $1",
            )
            .bind(domain)
            .bind(&enc_chain)
            .bind(&enc_key)
            .bind(not_before)
            .bind(not_after)
            .execute(pool)
            .await?;
            // Every caller (proxy request, MCP, renewal) needs the proxy to pick it up.
            crate::api::internal::notify_proxy_reload();
        }
        Err(e) => {
            sqlx::query(
                "UPDATE certificates SET acme_status = 'failed', last_error = $2, updated_at = now() WHERE domain = $1",
            )
            .bind(domain)
            .bind(e.to_string())
            .execute(pool)
            .await?;
        }
    }

    result.map(|_| ())
}

/// Singleton name of the shared ACME account credential row.
const ACME_CREDENTIAL_NAME: &str = "acme-account";

/// Load the single shared ACME account, creating and persisting it once if absent.
async fn acme_account(pool: &PgPool, contact_email: &str) -> anyhow::Result<instant_acme::Account> {
    use instant_acme::{Account, AccountCredentials, LetsEncrypt, NewAccount};

    if let Some(enc) = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT encrypted_data FROM credentials WHERE credential_type = 'acme-account' LIMIT 1",
    )
    .fetch_optional(pool)
    .await?
    {
        let json = crate::crypto::decrypt(&enc)
            .map_err(|e| anyhow::anyhow!("decrypt acme account: {e}"))?;
        let creds: AccountCredentials = serde_json::from_slice(&json)?;
        return Ok(Account::from_credentials(creds).await?);
    }

    let directory_url = crate::config::config()
        .proxy
        .as_ref()
        .and_then(|p| p.acme_directory_url.clone())
        .unwrap_or_else(|| LetsEncrypt::Production.url().to_string());
    let (account, creds) = Account::create(
        &NewAccount {
            contact: &[&format!("mailto:{contact_email}")],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        &directory_url,
        None,
    )
    .await?;

    let enc = crate::crypto::encrypt(&serde_json::to_vec(&creds)?)
        .map_err(|e| anyhow::anyhow!("encrypt acme account: {e}"))?;
    // The UNIQUE name makes this row a singleton; ON CONFLICT guards the race
    // where two issuances create an account at once.
    sqlx::query(
        "INSERT INTO credentials (name, credential_type, encrypted_data) \
         VALUES ($1, 'acme-account', $2) ON CONFLICT (name) DO NOTHING",
    )
    .bind(ACME_CREDENTIAL_NAME)
    .bind(&enc)
    .execute(pool)
    .await?;

    Ok(account)
}

/// Issue certs for every proxy-bound FQDN on a host that has no cert row yet,
/// or whose last attempt failed over an hour ago (backoff for LE rate limits).
///
/// Each domain/subdomain binding needs its own cert (the proxy resolves certs
/// by SNI, exact-first with a single-label wildcard fallback), so this checks
/// all bindings — not just the first. A "*" binding yields a wildcard cert.
pub async fn issue_host_certs(pool: &PgPool, host_id: Uuid) -> anyhow::Result<()> {
    let domains: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT CASE \
             WHEN s.name IS NOT NULL AND s.name != '@' THEN s.name || '.' || d.name \
             ELSE d.name \
         END AS hostname \
         FROM webspace_host_domains whd \
         JOIN webspace_hosts h ON h.id = whd.webspace_host_id AND h.kind = 'proxy' \
         JOIN domains d ON d.id = whd.domain_id \
         LEFT JOIN subdomains s ON s.id = whd.subdomain_id \
         WHERE whd.webspace_host_id = $1 \
           AND NOT EXISTS (SELECT 1 FROM certificates c WHERE c.domain = \
               CASE WHEN s.name IS NOT NULL AND s.name != '@' THEN s.name || '.' || d.name ELSE d.name END \
               AND NOT (c.acme_status = 'failed' AND c.updated_at < now() - interval '1 hour'))",
    )
    .bind(host_id)
    .fetch_all(pool)
    .await?;

    for domain in &domains {
        tracing::info!(domain, "issuing cert for host binding");
        if let Err(e) = issue_cert(pool, domain).await {
            tracing::error!(domain, "host cert issuance failed: {e}");
        }
    }
    Ok(())
}

/// One lock per DNS-01 TXT name.
fn challenge_lock(txt_name: &str) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    // ponytail: entries are never evicted; one per issued base domain is fine.
    static LOCKS: std::sync::LazyLock<
        std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>,
    > = std::sync::LazyLock::new(Default::default);
    LOCKS
        .lock()
        .unwrap()
        .entry(txt_name.to_string())
        .or_default()
        .clone()
}

async fn run_acme_flow(
    pool: &PgPool,
    domain: &str,
    cred_id: Uuid,
    zone_id: &str,
) -> anyhow::Result<(String, String)> {
    use instant_acme::{AuthorizationStatus, ChallengeType, Identifier, NewOrder, OrderStatus};

    // For a wildcard ("*.example.com") the DNS-01 TXT record and any derived
    // email live on the base domain — the "*." label never appears in DNS.
    let base_domain = domain.strip_prefix("*.").unwrap_or(domain);

    let cfg = crate::config::config();
    let contact_email = cfg
        .proxy
        .as_ref()
        .and_then(|p| p.acme_email.clone())
        .unwrap_or_else(|| format!("admin@{base_domain}"));

    // Reuse one ACME account across all domains. Creating a fresh account per
    // issuance trips Let's Encrypt's new-registration rate limit, so hosts with
    // several domain bindings would fail on the later domains.
    let account = acme_account(pool, &contact_email).await?;

    // Create order
    let mut order = account
        .new_order(&NewOrder {
            identifiers: &[Identifier::Dns(domain.to_string())],
        })
        .await?;

    // Get authorization and DNS-01 challenge
    let authorizations = order.authorizations().await?;
    let authz = authorizations
        .first()
        .ok_or_else(|| anyhow::anyhow!("no authorizations returned"))?;

    // The account is reused, so LE may hand back an authorization that is
    // already valid from a recent issuance — no challenge needed then.
    let cf_client = crate::credentials::cf_client(pool, cred_id).await?;
    let txt_name = format!("_acme-challenge.{base_domain}");
    // "x" and "*.x" share this TXT name, and we wipe existing records below:
    // concurrent flows for both would delete each other's challenge.
    let _challenge_guard = challenge_lock(&txt_name).lock_owned().await;
    let created_record_id = match authz.status {
        AuthorizationStatus::Valid => {
            tracing::info!(domain, "authorization already valid, skipping DNS-01");
            None
        }
        AuthorizationStatus::Pending => {
            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Dns01)
                .ok_or_else(|| anyhow::anyhow!("no DNS-01 challenge found"))?;

            let dns_value = order.key_authorization(challenge).dns_value();

            tracing::info!(domain, txt_name = %txt_name, "creating DNS-01 TXT record");

            // Delete any existing _acme-challenge records first
            let existing = cf_client.list_dns_records(zone_id).await?;
            for rec in &existing {
                if rec.name == txt_name && rec.record_type == "TXT" {
                    let _ = cf_client.delete_dns_record(zone_id, &rec.id).await;
                }
            }

            let record = cloudflare_api::compat::CreateDnsRecord {
                record_type: "TXT".to_string(),
                name: txt_name.clone(),
                content: Some(dns_value),
                ttl: Some(60),
                proxied: Some(false),
                priority: None,
                data: None,
                comment: Some("ACME DNS-01 challenge".to_string()),
            };
            let created_record = cf_client.create_dns_record(zone_id, &record).await?;

            // Wait for DNS propagation
            tracing::info!(domain, "waiting 15s for DNS propagation");
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;

            // Tell ACME server the challenge is ready
            order.set_challenge_ready(&challenge.url).await?;
            Some(created_record.id)
        }
        other => anyhow::bail!("authorization not usable: {other:?}"),
    };
    let cleanup = || async {
        if let Some(id) = &created_record_id {
            let _ = cf_client.delete_dns_record(zone_id, id).await;
        }
    };

    // Poll for order to become ready
    let mut tries = 0;
    loop {
        let state = order.refresh().await?;
        if matches!(state.status, OrderStatus::Ready | OrderStatus::Valid) {
            break;
        }
        if matches!(state.status, OrderStatus::Invalid) {
            cleanup().await;
            anyhow::bail!("ACME order became invalid");
        }
        tries += 1;
        if tries > 20 {
            cleanup().await;
            anyhow::bail!("ACME order timed out after 60s");
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }

    // Finalize: generate CSR and get certificate
    let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let key_pair = rcgen::KeyPair::generate()?;
    let csr = params.serialize_request(&key_pair)?;

    order.finalize(csr.der()).await?;

    // Poll for certificate
    let cert_chain_pem = loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let state = order.refresh().await?;
        if matches!(state.status, OrderStatus::Valid) {
            break order
                .certificate()
                .await?
                .ok_or_else(|| anyhow::anyhow!("no certificate returned"))?;
        }
        if matches!(state.status, OrderStatus::Invalid) {
            cleanup().await;
            anyhow::bail!("order became invalid during finalization");
        }
    };

    cleanup().await;

    tracing::info!(domain, "ACME cert issued successfully");

    Ok((cert_chain_pem, key_pair.serialize_pem()))
}
