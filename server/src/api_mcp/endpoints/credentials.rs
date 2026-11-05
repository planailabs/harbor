//! Credential endpoints.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use dioxus::prelude::*;
use plan_ai_api_mcp_macros::api_mcp_dioxus_server;

#[cfg(feature = "server")]
use crate::server_pool;
#[cfg(feature = "server")]
use crate::web::user::{current_user, principal_from, to_serverfn};
#[cfg(feature = "server")]
use plan_ai_api_mcp::{ApiError, Principal};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CredentialRow {
    pub id: Uuid,
    pub name: String,
    pub credential_type: String,
    pub organization_name: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CredentialListInput {}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CredentialInfo {
    pub id: Uuid,
    pub name: String,
    pub credential_type: String,
    pub organization_id: Option<Uuid>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CredentialGetInput {
    pub id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CredentialCreateInput {
    /// Owning organization; `None` makes a global credential (admin only).
    pub organization_id: Option<Uuid>,
    pub name: String,
    pub credential_type: String,
    /// Secret payload as a JSON document; encrypted at rest.
    pub data_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CredentialUpdateInput {
    pub id: Uuid,
    pub name: String,
    /// New owning organization; `None` makes it global (admin only).
    pub organization_id: Option<Uuid>,
    /// Replacement secret JSON; `None` or blank keeps the current data.
    pub new_data_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CredentialDeleteInput {
    pub id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CredentialTestInput {
    pub id: Uuid,
}

/// Require read access to the credential's organization: admins always pass;
/// global (NULL-org) credentials are admin-only; else org read membership.
/// Shared with sibling endpoint modules (e.g. domain availability checks).
#[cfg(feature = "server")]
pub(super) async fn require_credential_read(
    pool: &sqlx::PgPool,
    principal: &Principal,
    credential_id: Uuid,
) -> Result<(), ApiError> {
    if principal.admin {
        return Ok(());
    }
    // Non-admins: collapse missing / global / cross-org into a single generic
    // "access denied" so credential existence cannot be probed by comparing
    // 404 (bogus id) against 403 (real cross-org id) — an IDOR enumeration.
    match credential_org_opt(pool, credential_id).await? {
        Some(Some(oid)) => principal
            .require_read(&oid)
            .map_err(|_| ApiError::forbidden("access denied")),
        _ => Err(ApiError::forbidden("access denied")),
    }
}

/// Require write access to the credential's organization: admins always pass;
/// global (NULL-org) credentials are admin-only; else org write membership.
#[cfg(feature = "server")]
async fn require_credential_write(
    pool: &sqlx::PgPool,
    principal: &Principal,
    credential_id: Uuid,
) -> Result<(), ApiError> {
    if principal.admin {
        return Ok(());
    }
    match credential_org_opt(pool, credential_id).await? {
        Some(Some(oid)) => principal
            .require_write(&oid)
            .map_err(|_| ApiError::forbidden("access denied")),
        _ => Err(ApiError::forbidden("access denied")),
    }
}

/// Look up a credential's owning org without leaking existence via a 404:
///   `None`        → no such credential
///   `Some(None)`  → exists, global (no org)
///   `Some(Some())`→ exists, owned by that org
#[cfg(feature = "server")]
async fn credential_org_opt(
    pool: &sqlx::PgPool,
    credential_id: Uuid,
) -> Result<Option<Option<Uuid>>, ApiError> {
    sqlx::query_scalar::<_, Option<Uuid>>("SELECT organization_id FROM credentials WHERE id = $1")
        .bind(credential_id)
        .fetch_optional(pool)
        .await
        .map_err(super::internal)
}

// ── Global (plan.ai-wide, NULL-org) credentials for non-admins ─────────
//
// Non-admins never get a list of global credentials and only an admin can
// choose one. A global that is already attached to something in an org the
// caller can read may still be used by that caller (and shown as the current
// selection of a picker).

/// SQL predicate: credential `cred` is referenced by a domain, webspace,
/// webspace host or organization within the orgs in `orgs` (a `uuid[]`;
/// NULL = every org). Covers every column that references `credentials`.
#[cfg(feature = "server")]
fn attached_in_orgs_sql(cred: &str, orgs: &str) -> String {
    format!(
        "(EXISTS (SELECT 1 FROM domains WHERE ({orgs}::uuid[] IS NULL OR organization_id = ANY({orgs})) \
            AND {cred} IN (registrar_credential_id, cloudflare_credential_id)) \
         OR EXISTS (SELECT 1 FROM webspaces WHERE ({orgs}::uuid[] IS NULL OR organization_id = ANY({orgs})) \
            AND {cred} IN (cloudflare_credential_id, relay_credential_id, \
                           tunnel_client_cert_credential_id, tunnel_basic_auth_credential_id)) \
         OR EXISTS (SELECT 1 FROM webspace_hosts WHERE ({orgs}::uuid[] IS NULL OR organization_id = ANY({orgs})) \
            AND changedetection_credential_id = {cred}) \
         OR EXISTS (SELECT 1 FROM organizations WHERE ({orgs}::uuid[] IS NULL OR id = ANY({orgs})) \
            AND default_changedetection_credential_id = {cred}))"
    )
}

/// Whether `credential_id` is attached to something in an org the principal
/// can read.
#[cfg(feature = "server")]
async fn attached_in_readable_org(
    pool: &sqlx::PgPool,
    principal: &Principal,
    credential_id: Uuid,
) -> Result<bool, ApiError> {
    sqlx::query_scalar::<_, bool>(&format!("SELECT {}", attached_in_orgs_sql("$1", "$2")))
        .bind(credential_id)
        .bind(principal.read_filter())
        .fetch_one(pool)
        .await
        .map_err(super::internal)
}

/// Credentials of the given types a picker may offer, as `(id, name, type)`
/// sorted by name. Admins: all. Others: their orgs' credentials, plus a
/// global one only when it is in `selected` (the item's current value) *and*
/// attached to something in an org they can read — so the current selection
/// stays visible without a guessed id revealing a name.
#[cfg(feature = "server")]
pub async fn credential_options(
    pool: &sqlx::PgPool,
    principal: &Principal,
    types: &[&str],
    selected: &[Uuid],
) -> Result<Vec<(Uuid, String, String)>, ApiError> {
    let types: Vec<String> = types.iter().map(|t| t.to_string()).collect();
    let rows = if principal.admin {
        sqlx::query_as::<_, (Uuid, String, String)>(
            "SELECT id, name, credential_type FROM credentials \
             WHERE credential_type = ANY($1) ORDER BY name",
        )
        .bind(&types)
        .fetch_all(pool)
        .await
    } else {
        sqlx::query_as::<_, (Uuid, String, String)>(&format!(
            "SELECT c.id, c.name, c.credential_type FROM credentials c \
             WHERE c.credential_type = ANY($1) AND ( \
               (c.organization_id IS NOT NULL \
                AND ($2::uuid[] IS NULL OR c.organization_id = ANY($2))) \
               OR (c.organization_id IS NULL AND c.id = ANY($3) AND {}) \
             ) ORDER BY c.name",
            attached_in_orgs_sql("c.id", "$2")
        ))
        .bind(&types)
        .bind(principal.read_filter())
        .bind(selected)
        .fetch_all(pool)
        .await
    };
    rows.map_err(super::internal)
}

/// [`credential_options`] for a web session user, for `#[server]` pickers.
#[cfg(feature = "server")]
pub async fn credential_options_for_user(
    pool: &sqlx::PgPool,
    user: &crate::web::user::WebUser,
    types: &[&str],
    selected: &[Uuid],
) -> Result<Vec<(Uuid, String, String)>, ServerFnError> {
    credential_options(pool, &principal_from(user), types, selected)
        .await
        .map_err(to_serverfn)
}

/// Authorize assigning `credential_id` to an item (rule for every write of a
/// credential reference). Admins: always. Keeping the item's `current` value:
/// always. An org credential: the caller must read its org. A global
/// credential: admin only. Unknown ids get the generic "access denied".
#[cfg(feature = "server")]
pub(crate) async fn require_credential_use(
    pool: &sqlx::PgPool,
    principal: &Principal,
    credential_id: Uuid,
    current: Option<Uuid>,
) -> Result<(), ApiError> {
    if principal.admin || current == Some(credential_id) {
        return Ok(());
    }
    match credential_org_opt(pool, credential_id).await? {
        Some(Some(oid)) => principal
            .require_read(&oid)
            .map_err(|_| ApiError::forbidden("access denied")),
        Some(None) => Err(ApiError::forbidden(
            "only an admin can choose plan.ai's shared credentials",
        )),
        None => Err(ApiError::forbidden("access denied")),
    }
}

/// Authorize using `credential_id` without storing it (discovery, lookups).
/// Admins: always. An org credential: the caller must read its org. A global
/// credential: only if already attached to something in an org the caller
/// can read. Anything else is one generic "access denied" (no 404 vs 403).
#[cfg(feature = "server")]
pub(crate) async fn require_credential_access(
    pool: &sqlx::PgPool,
    principal: &Principal,
    credential_id: Uuid,
) -> Result<(), ApiError> {
    if principal.admin {
        return Ok(());
    }
    match credential_org_opt(pool, credential_id).await? {
        Some(Some(oid)) => principal
            .require_read(&oid)
            .map_err(|_| ApiError::forbidden("access denied")),
        Some(None) if attached_in_readable_org(pool, principal, credential_id).await? => Ok(()),
        _ => Err(ApiError::forbidden("access denied")),
    }
}

/// List credentials the caller may see (admins: all; else their orgs' only —
/// plan.ai's global credentials are never listed to non-admins).
#[api_mcp_dioxus_server(server = "list_credentials")]
pub async fn credential_list(
    pool: &sqlx::PgPool,
    principal: &Principal,
    _input: CredentialListInput,
) -> Result<Vec<CredentialRow>, ApiError> {
    type Row = (
        Uuid,
        String,
        String,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
    );
    let base = "SELECT c.id, c.name, c.credential_type, o.name, c.created_at \
                FROM credentials c LEFT JOIN organizations o ON o.id = c.organization_id";

    let rows = if principal.admin {
        sqlx::query_as::<_, Row>(&format!("{base} ORDER BY c.created_at DESC"))
            .fetch_all(pool)
            .await
    } else {
        // Non-admins: their orgs' credentials only, never global (NULL org) ones.
        sqlx::query_as::<_, Row>(&format!(
            "{base} WHERE c.organization_id IS NOT NULL \
             AND ($1::uuid[] IS NULL OR c.organization_id = ANY($1)) \
             ORDER BY c.created_at DESC"
        ))
        .bind(principal.read_filter())
        .fetch_all(pool)
        .await
    }
    .map_err(super::internal)?;

    Ok(rows
        .into_iter()
        .map(
            |(id, name, credential_type, organization_name, created_at)| CredentialRow {
                id,
                name,
                credential_type,
                organization_name,
                created_at: created_at.format("%Y-%m-%d %H:%M").to_string(),
            },
        )
        .collect())
}

/// Get a credential's metadata (admins, or members of the credential's org;
/// global credentials are admin-only). Never returns the secret data.
#[api_mcp_dioxus_server(server = "get_credential")]
pub async fn credential_get(
    pool: &sqlx::PgPool,
    principal: &Principal,
    input: CredentialGetInput,
) -> Result<CredentialInfo, ApiError> {
    // Authorize before disclosing existence: otherwise a caller can probe the
    // UUID namespace (403 for a real cross-org id vs 404 for a bogus one) to
    // enumerate credentials belonging to other organizations (IDOR).
    require_credential_read(pool, principal, input.id).await?;

    let row = sqlx::query_as::<_, (Uuid, String, String, Option<Uuid>, chrono::DateTime<chrono::Utc>)>(
        "SELECT id, name, credential_type, organization_id, created_at FROM credentials WHERE id = $1",
    )
    .bind(input.id)
    .fetch_optional(pool)
    .await
    .map_err(super::internal)?
    .ok_or_else(|| ApiError::not_found("credential not found"))?;

    let (id, name, credential_type, organization_id, created_at) = row;
    Ok(CredentialInfo {
        id,
        name,
        credential_type,
        organization_id,
        created_at: created_at.format("%Y-%m-%d %H:%M").to_string(),
    })
}

/// Create a credential. Global (no org) credentials require admin; org-owned
/// credentials require org write. The JSON payload is encrypted at rest.
/// Returns the new id.
#[api_mcp_dioxus_server(server = "create_credential")]
pub async fn credential_create(
    pool: &sqlx::PgPool,
    principal: &Principal,
    input: CredentialCreateInput,
) -> Result<Uuid, ApiError> {
    match input.organization_id {
        None => principal.require_admin()?,
        Some(oid) => principal.require_write(&oid)?,
    }

    let _: serde_json::Value = serde_json::from_str(&input.data_json)
        .map_err(|e| ApiError::bad_request(format!("invalid JSON: {e}")))?;

    let encrypted = crate::crypto::encrypt(input.data_json.as_bytes())
        .map_err(|e| ApiError::internal(format!("encryption failed: {e}")))?;

    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO credentials (organization_id, name, credential_type, encrypted_data) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(input.organization_id)
    .bind(&input.name)
    .bind(&input.credential_type)
    .bind(&encrypted)
    .fetch_one(pool)
    .await
    .map_err(|e| ApiError::internal(format!("failed to create credential: {e}")))
}

/// Update a credential's name/org and optionally replace its secret data
/// (requires credential write plus write on the target org; moving to global
/// requires admin).
#[api_mcp_dioxus_server(server = "update_credential")]
pub async fn credential_update(
    pool: &sqlx::PgPool,
    principal: &Principal,
    input: CredentialUpdateInput,
) -> Result<(), ApiError> {
    require_credential_write(pool, principal, input.id).await?;

    // Validate target org assignment.
    match input.organization_id {
        None => principal.require_admin()?,
        Some(oid) => principal.require_write(&oid)?,
    }

    sqlx::query(
        "UPDATE credentials SET name = $1, organization_id = $2, updated_at = now() WHERE id = $3",
    )
    .bind(&input.name)
    .bind(input.organization_id)
    .bind(input.id)
    .execute(pool)
    .await
    .map_err(super::internal)?;

    if let Some(json) = input.new_data_json {
        if !json.trim().is_empty() {
            let _: serde_json::Value = serde_json::from_str(&json)
                .map_err(|e| ApiError::bad_request(format!("invalid JSON: {e}")))?;
            let encrypted = crate::crypto::encrypt(json.as_bytes())
                .map_err(|e| ApiError::internal(format!("encryption failed: {e}")))?;
            sqlx::query(
                "UPDATE credentials SET encrypted_data = $1, updated_at = now() WHERE id = $2",
            )
            .bind(&encrypted)
            .bind(input.id)
            .execute(pool)
            .await
            .map_err(super::internal)?;
        }
    }

    Ok(())
}

/// Delete a credential (requires credential write).
#[api_mcp_dioxus_server(server = "delete_credential")]
pub async fn credential_delete(
    pool: &sqlx::PgPool,
    principal: &Principal,
    input: CredentialDeleteInput,
) -> Result<(), ApiError> {
    require_credential_write(pool, principal, input.id).await?;

    sqlx::query("DELETE FROM credentials WHERE id = $1")
        .bind(input.id)
        .execute(pool)
        .await
        .map_err(super::internal)?;
    Ok(())
}

/// Test a credential against its upstream API (requires credential read).
/// Returns a human-readable status string.
#[api_mcp_dioxus_server(server = "test_credential_conn")]
pub async fn credential_test(
    pool: &sqlx::PgPool,
    principal: &Principal,
    input: CredentialTestInput,
) -> Result<String, ApiError> {
    require_credential_read(pool, principal, input.id).await?;

    let cred_type =
        sqlx::query_scalar::<_, String>("SELECT credential_type FROM credentials WHERE id = $1")
            .bind(input.id)
            .fetch_optional(pool)
            .await
            .map_err(super::internal)?
            .ok_or_else(|| ApiError::not_found("credential not found"))?;

    match cred_type.as_str() {
        "cloudflare" => {
            let client = crate::credentials::cf_client(pool, input.id)
                .await
                .map_err(|e| ApiError::internal(format!("{e}")))?;
            let zones = client
                .list_zones(None)
                .await
                .map_err(|e| ApiError::internal(format!("Cloudflare API error: {e}")))?;
            Ok(format!("OK — {} zone(s) accessible", zones.len()))
        }
        "spaceship" => {
            let client = crate::credentials::spaceship_client(pool, input.id)
                .await
                .map_err(|e| ApiError::internal(format!("{e}")))?;
            let resp = client
                .list_domains(0, 1)
                .await
                .map_err(|e| ApiError::internal(format!("Spaceship API error: {e}")))?;
            Ok(format!(
                "OK — {} domain(s) in account",
                resp.total_count.unwrap_or(0)
            ))
        }
        "changedetection" => {
            let (client, _group) = crate::credentials::changedetection_client(pool, input.id)
                .await
                .map_err(|e| ApiError::internal(format!("{e}")))?;
            let info = client
                .get_system_info()
                .await
                .map_err(|e| ApiError::internal(format!("ChangeDetection API error: {e}")))?;
            let info = info.into_inner();
            Ok(format!(
                "OK — v{}, {} watch(es)",
                info.version.as_deref().unwrap_or("?"),
                info.watch_count.unwrap_or(0),
            ))
        }
        // No upstream to call for these; validate the stored payload shape.
        "client_cert" => {
            let (cert, key) = crate::credentials::client_cert_credential(pool, input.id)
                .await
                .map_err(|e| ApiError::internal(format!("{e}")))?;
            if !cert.contains("BEGIN CERTIFICATE") {
                return Err(ApiError::bad_request("cert_pem is not a PEM certificate"));
            }
            if !key.contains("PRIVATE KEY") {
                return Err(ApiError::bad_request("key_pem is not a PEM private key"));
            }
            Ok("OK — certificate and key PEM present".into())
        }
        "basic_auth" => {
            let (username, _) = crate::credentials::basic_auth_credential(pool, input.id)
                .await
                .map_err(|e| ApiError::internal(format!("{e}")))?;
            Ok(format!("OK — username '{username}' set"))
        }
        _ => Err(ApiError::bad_request("unknown credential type")),
    }
}

#[cfg(all(test, feature = "server"))]
mod global_credential_tests {
    use super::*;
    use std::collections::HashSet;

    async fn org(pool: &sqlx::PgPool, name: &str) -> Uuid {
        sqlx::query_scalar("INSERT INTO organizations (name) VALUES ($1) RETURNING id")
            .bind(name)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn cred(pool: &sqlx::PgPool, org: Option<Uuid>, name: &str) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO credentials (organization_id, name, credential_type, encrypted_data) \
             VALUES ($1, $2, 'cloudflare', '\\x00') RETURNING id",
        )
        .bind(org)
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn non_admins_only_see_and_choose_globals_already_attached() {
        let (_db, pool) = crate::credentials::pg_tests::test_db().await;
        let mine = org(&pool, "mine").await;
        let other = org(&pool, "other").await;
        let own = cred(&pool, Some(mine), "own").await;
        let foreign = cred(&pool, Some(other), "foreign").await;
        let attached = cred(&pool, None, "global-attached").await;
        let elsewhere = cred(&pool, None, "global-elsewhere").await;
        let unused = cred(&pool, None, "global-unused").await;
        // `attached` is on a domain in my org; `elsewhere` only in another org.
        sqlx::query(
            "INSERT INTO domains (organization_id, name, cloudflare_credential_id) \
             VALUES ($1, 'a.example', $2), ($3, 'b.example', $4)",
        )
        .bind(mine)
        .bind(attached)
        .bind(other)
        .bind(elsewhere)
        .execute(&pool)
        .await
        .unwrap();

        let user = Principal::scoped("u", HashSet::from([mine]), HashSet::from([mine]));
        let admin = Principal::admin("a");

        // Rule 1: the list never contains globals for non-admins.
        let names = |rows: Vec<CredentialRow>| -> HashSet<String> {
            rows.into_iter().map(|r| r.name).collect()
        };
        let listed = names(credential_list(&pool, &user, CredentialListInput {}).await.unwrap());
        assert_eq!(listed, HashSet::from(["own".to_string()]));
        let listed = names(credential_list(&pool, &admin, CredentialListInput {}).await.unwrap());
        assert_eq!(listed.len(), 5);

        // Rule 2: a global shows up in a picker only when selected + attached.
        let ids = |rows: Vec<(Uuid, String, String)>| -> Vec<Uuid> {
            rows.into_iter().map(|r| r.0).collect()
        };
        let opts = |selected: Vec<Uuid>| {
            let (pool, user) = (pool.clone(), user.clone());
            async move {
                ids(credential_options(&pool, &user, &["cloudflare"], &selected)
                    .await
                    .unwrap())
            }
        };
        assert_eq!(opts(vec![]).await, vec![own]);
        assert_eq!(opts(vec![attached]).await, vec![attached, own]);
        assert_eq!(opts(vec![elsewhere, unused, foreign]).await, vec![own]);
        assert_eq!(
            credential_options(&pool, &admin, &["cloudflare"], &[]).await.unwrap().len(),
            5
        );

        // Rule 3: choosing a new global is admin-only; keeping it is fine.
        let err = require_credential_use(&pool, &user, attached, None).await.unwrap_err();
        assert!(err.to_string().contains("only an admin"), "{err}");
        require_credential_use(&pool, &user, attached, Some(attached)).await.unwrap();
        require_credential_use(&pool, &user, unused, Some(own)).await.unwrap_err();
        require_credential_use(&pool, &admin, unused, None).await.unwrap();
        require_credential_use(&pool, &user, own, None).await.unwrap();
        let err = require_credential_use(&pool, &user, foreign, None).await.unwrap_err();
        assert_eq!(err.to_string(), "access denied");

        // ... and enforced by an endpoint before it touches Cloudflare.
        let err = super::super::domains::domain_create(
            &pool,
            &user,
            super::super::domains::DomainCreateInput {
                org_id: mine,
                domain_name: "new.example".into(),
                cf_credential_id: Some(attached),
                registrar_type: String::new(),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ApiError::Forbidden(_)), "{err}");

        // Rule 4: using without storing works for attached globals only, and
        // missing / unattached / foreign ids are indistinguishable.
        require_credential_access(&pool, &user, attached).await.unwrap();
        require_credential_access(&pool, &user, own).await.unwrap();
        require_credential_access(&pool, &admin, unused).await.unwrap();
        for id in [elsewhere, unused, foreign, Uuid::new_v4()] {
            let err = require_credential_access(&pool, &user, id).await.unwrap_err();
            assert_eq!(err.to_string(), "access denied");
        }
    }
}
