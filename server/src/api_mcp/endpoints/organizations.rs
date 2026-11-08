//! Organization endpoints.

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
pub struct OrgRow {
    pub id: Uuid,
    pub name: String,
    pub member_count: i64,
    pub created_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OrgListInput {}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OrgCreateInput {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OrgMemberRow {
    pub user_id: Uuid,
    pub email: String,
    pub name: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OrgInfo {
    pub id: Uuid,
    pub name: String,
    pub show_billing: bool,
    pub default_changedetection_credential_id: Option<Uuid>,
    pub members: Vec<OrgMemberRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OrgGetInput {
    pub id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OrgUpdateInput {
    pub id: Uuid,
    pub show_billing: Option<bool>,
    pub default_changedetection_credential_id: Option<Uuid>,
    pub clear_default_changedetection: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OrgMemberAddInput {
    pub organization_id: Uuid,
    pub user_id: Option<Uuid>,
    pub email: Option<String>,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OrgMemberRemoveInput {
    pub organization_id: Uuid,
    pub user_id: Uuid,
}

/// List all organizations (admin only).
#[api_mcp_dioxus_server(server = "list_organizations")]
pub async fn organization_list(
    pool: &sqlx::PgPool,
    principal: &Principal,
    _input: OrgListInput,
) -> Result<Vec<OrgRow>, ApiError> {
    principal.require_admin()?;
    let rows = sqlx::query_as::<_, (Uuid, String, i64, chrono::DateTime<chrono::Utc>)>(
        "SELECT o.id, o.name, \
         (SELECT count(*) FROM organization_members om WHERE om.organization_id = o.id), \
         o.created_at FROM organizations o ORDER BY o.name",
    )
    .fetch_all(pool)
    .await
    .map_err(super::internal)?;

    Ok(rows
        .into_iter()
        .map(|(id, name, member_count, created_at)| OrgRow {
            id,
            name,
            member_count,
            created_at: created_at.format("%Y-%m-%d").to_string(),
        })
        .collect())
}

/// Create an organization (admin only). Returns the new id.
#[api_mcp_dioxus_server(server = "create_organization")]
pub async fn organization_create(
    pool: &sqlx::PgPool,
    principal: &Principal,
    input: OrgCreateInput,
) -> Result<Uuid, ApiError> {
    principal.require_admin()?;
    sqlx::query_scalar::<_, Uuid>("INSERT INTO organizations (name) VALUES ($1) RETURNING id")
        .bind(&input.name)
        .fetch_one(pool)
        .await
        .map_err(|e| ApiError::internal(format!("failed to create organization: {e}")))
}

/// Get an organization by id, including its members (admin only).
#[api_mcp_dioxus_server(server = "get_org")]
pub async fn organization_get(
    pool: &sqlx::PgPool,
    principal: &Principal,
    input: OrgGetInput,
) -> Result<OrgInfo, ApiError> {
    principal.require_admin()?;

    let (name, show_billing, default_changedetection_credential_id) =
        sqlx::query_as::<_, (String, bool, Option<Uuid>)>(
            "SELECT name, show_billing, default_changedetection_credential_id \
             FROM organizations WHERE id = $1",
        )
        .bind(input.id)
        .fetch_optional(pool)
        .await
        .map_err(super::internal)?
        .ok_or_else(|| ApiError::not_found("organization not found"))?;

    let members = sqlx::query_as::<_, (Uuid, String, String, String)>(
        "SELECT u.id, u.email, u.name, om.role \
         FROM organization_members om JOIN users u ON u.id = om.user_id \
         WHERE om.organization_id = $1 ORDER BY u.email",
    )
    .bind(input.id)
    .fetch_all(pool)
    .await
    .map_err(super::internal)?
    .into_iter()
    .map(|(user_id, email, name, role)| OrgMemberRow {
        user_id,
        email,
        name,
        role,
    })
    .collect();

    Ok(OrgInfo {
        id: input.id,
        name,
        show_billing,
        default_changedetection_credential_id,
        members,
    })
}

/// Update an organization (admin only). Only the provided fields are applied;
/// `clear_default_changedetection` sets the default credential to NULL.
#[api_mcp_dioxus_server(server = "update_org")]
pub async fn organization_update(
    pool: &sqlx::PgPool,
    principal: &Principal,
    input: OrgUpdateInput,
) -> Result<(), ApiError> {
    principal.require_admin()?;

    if let Some(show_billing) = input.show_billing {
        sqlx::query("UPDATE organizations SET show_billing = $2 WHERE id = $1")
            .bind(input.id)
            .bind(show_billing)
            .execute(pool)
            .await
            .map_err(super::internal)?;
    }

    if input.clear_default_changedetection.unwrap_or(false) {
        sqlx::query(
            "UPDATE organizations SET default_changedetection_credential_id = NULL WHERE id = $1",
        )
        .bind(input.id)
        .execute(pool)
        .await
        .map_err(super::internal)?;
    } else if let Some(credential_id) = input.default_changedetection_credential_id {
        sqlx::query(
            "UPDATE organizations SET default_changedetection_credential_id = $2 WHERE id = $1",
        )
        .bind(input.id)
        .bind(credential_id)
        .execute(pool)
        .await
        .map_err(super::internal)?;
    }

    Ok(())
}

/// Add (or re-role) a member in an organization (admin only). Exactly one of
/// `user_id` / `email` selects the user.
#[api_mcp_dioxus_server(server = "add_org_member")]
pub async fn organization_member_add(
    pool: &sqlx::PgPool,
    principal: &Principal,
    input: OrgMemberAddInput,
) -> Result<(), ApiError> {
    principal.require_admin()?;

    if !["admin", "write", "read"].contains(&input.role.as_str()) {
        return Err(ApiError::bad_request("invalid role"));
    }

    let user_id = match (input.user_id, input.email) {
        (Some(user_id), None) => user_id,
        (None, Some(email)) => {
            sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE email = $1")
                .bind(&email)
                .fetch_optional(pool)
                .await
                .map_err(super::internal)?
                .ok_or_else(|| ApiError::not_found(format!("user {email} not found")))?
        }
        _ => {
            return Err(ApiError::bad_request(
                "exactly one of user_id or email must be set",
            ));
        }
    };

    sqlx::query(
        "INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1, $2, $3) \
         ON CONFLICT (organization_id, user_id) DO UPDATE SET role = EXCLUDED.role",
    )
    .bind(input.organization_id)
    .bind(user_id)
    .bind(&input.role)
    .execute(pool)
    .await
    .map_err(super::internal)?;

    Ok(())
}

/// Remove a member from an organization (admin only).
#[api_mcp_dioxus_server(server = "remove_org_member")]
pub async fn organization_member_remove(
    pool: &sqlx::PgPool,
    principal: &Principal,
    input: OrgMemberRemoveInput,
) -> Result<(), ApiError> {
    principal.require_admin()?;

    sqlx::query("DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2")
        .bind(input.organization_id)
        .bind(input.user_id)
        .execute(pool)
        .await
        .map_err(super::internal)?;

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OrgDeleteInput {
    pub id: Uuid,
}

/// What an organization took with it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OrgDeleted {
    pub webspace_hosts: i64,
    pub webspaces: i64,
    pub domains: i64,
}

/// Delete an organization and everything it holds (admin only).
///
/// Webspace hosts go first through `host_delete`, which takes down the CNAMEs
/// and Cloudflare custom domains they published; a host it can't remove stops
/// the delete, with nothing else touched, so it can be run again. Their
/// webspaces go with them. Then, in one transaction, the basic-auth lists
/// (they don't cascade) and the organization, whose rows do: domains,
/// credentials, contacts, tokens, members, billing. A domain is only forgotten — the zone at the registrar or
/// Cloudflare is the customer's and stays. Last, the static webspaces' files.
#[api_mcp_dioxus_server(server = "delete_organization")]
pub async fn organization_delete(
    pool: &sqlx::PgPool,
    principal: &Principal,
    input: OrgDeleteInput,
) -> Result<OrgDeleted, ApiError> {
    principal.require_admin()?;
    let exists =
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM organizations WHERE id = $1)")
            .bind(input.id)
            .fetch_one(pool)
            .await
            .map_err(super::internal)?;
    if !exists {
        return Err(ApiError::not_found("organization not found"));
    }

    // Before the hosts go: deleting one cascades to its webspaces, whose
    // files are removed at the end.
    let webspaces =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM webspaces WHERE organization_id = $1")
            .bind(input.id)
            .fetch_all(pool)
            .await
            .map_err(super::internal)?;
    let hosts =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM webspace_hosts WHERE organization_id = $1")
            .bind(input.id)
            .fetch_all(pool)
            .await
            .map_err(super::internal)?;
    for id in &hosts {
        super::webspace_hosts::host_delete(
            pool,
            principal,
            super::webspace_hosts::HostDeleteInput { id: *id },
        )
        .await
        .map_err(|e| ApiError::internal(format!("webspace host {id}: {e}")))?;
    }

    let mut tx = pool.begin().await.map_err(super::internal)?;
    let domains =
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM domains WHERE organization_id = $1")
            .bind(input.id)
            .fetch_one(&mut *tx)
            .await
            .map_err(super::internal)?;
    sqlx::query("DELETE FROM basic_auth_lists WHERE organization_id = $1")
        .bind(input.id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            ApiError::conflict(format!(
                "its basic-auth lists are still in use elsewhere: {e}"
            ))
        })?;
    sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(input.id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::conflict(format!("something outside it still refers to it: {e}")))?;
    tx.commit().await.map_err(super::internal)?;

    for id in &webspaces {
        let dir = crate::local_hosting::webspace_dir(*id);
        match tokio::fs::remove_dir_all(&dir).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(dir = %dir.display(), "files of a deleted webspace left behind: {e}")
            }
        }
    }
    crate::api::internal::notify_proxy_reload();
    tracing::info!(organization = %input.id, by = %principal.subject, "organization deleted");

    Ok(OrgDeleted {
        webspace_hosts: hosts.len() as i64,
        webspaces: webspaces.len() as i64,
        domains,
    })
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;

    /// Against a real schema: everything an organization holds goes, the
    /// basic-auth lists that don't cascade included; others are untouched.
    #[tokio::test]
    async fn deleting_an_organization_takes_what_it_holds() {
        let (_db, pool) = crate::credentials::pg_tests::test_db().await;
        let admin = Principal::admin("test");
        let org = |name: &'static str| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, Uuid>(
                    "INSERT INTO organizations (name) VALUES ($1) RETURNING id",
                )
                .bind(name)
                .fetch_one(&pool)
                .await
                .unwrap()
            }
        };
        let gone = org("gone").await;
        let kept = org("kept").await;
        for o in [gone, kept] {
            sqlx::query("INSERT INTO domains (organization_id, name) VALUES ($1, $2)")
                .bind(o)
                .bind(format!("{o}.example"))
                .execute(&pool)
                .await
                .unwrap();
        }
        let list = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO basic_auth_lists (organization_id, name) VALUES ($1, 'l') RETURNING id",
        )
        .bind(gone)
        .fetch_one(&pool)
        .await
        .unwrap();
        let host = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO webspace_hosts (organization_id, name, kind) VALUES ($1, 'h', 'proxy') RETURNING id",
        )
        .bind(gone)
        .fetch_one(&pool)
        .await
        .unwrap();
        // both behind the list, which doesn't cascade
        let mut dirs = Vec::new();
        for (name, path) in [("w1", "/"), ("w2", "/b")] {
            let id = sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO webspaces (organization_id, name, hosting_type, runtime, webspace_host_id, auth_mode, auth_basic_list_id, path_prefix) \
                 VALUES ($1, $4, 'local', 'static', $2, 'basic', $3, $5) RETURNING id",
            )
            .bind(gone)
            .bind(host)
            .bind(list)
            .bind(name)
            .bind(path)
            .fetch_one(&pool)
            .await
            .unwrap();
            let dir = crate::local_hosting::webspace_dir(id);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("index.html"), "hi").unwrap();
            dirs.push(dir);
        }

        let done = organization_delete(&pool, &admin, OrgDeleteInput { id: gone })
            .await
            .unwrap();
        assert_eq!(
            done,
            OrgDeleted {
                webspace_hosts: 1,
                webspaces: 2,
                domains: 1
            }
        );
        let left = |table: &'static str| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, i64>(&format!(
                    "SELECT count(*) FROM {table} WHERE organization_id = $1"
                ))
                .bind(gone)
                .fetch_one(&pool)
                .await
                .unwrap()
            }
        };
        for dir in &dirs {
            assert!(!dir.exists(), "{}", dir.display());
        }
        for table in ["domains", "webspaces", "webspace_hosts", "basic_auth_lists"] {
            assert_eq!(left(table).await, 0, "{table}");
        }
        let kept_domains =
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM domains WHERE organization_id = $1")
                .bind(kept)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(kept_domains, 1);

        assert!(matches!(
            organization_delete(&pool, &admin, OrgDeleteInput { id: gone }).await,
            Err(ApiError::NotFound(_))
        ));
        let nobody = Principal {
            admin: false,
            ..Principal::admin("x")
        };
        assert!(
            organization_delete(&pool, &nobody, OrgDeleteInput { id: kept })
                .await
                .is_err()
        );
    }
}
