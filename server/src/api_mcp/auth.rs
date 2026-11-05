//! Bearer-token `Authenticator` backed by the `tokens` table.
//!
//! Resolves a raw token to a framework `Principal`:
//! - `kind = 'admin'` → global admin (all orgs, read + write).
//! - `kind = 'api'` with an `organization_id` → scoped to that org; role comes
//!   from `scopes.role` (`"read"` | `"write"`, default `"write"`).
//! - `kind = 'api'` with `NULL` org → read-only across all orgs.
//! - any other kind → forbidden for this API surface.
//!
//! [`BearerAuthenticator`] tries that first and, when `[zitadel_bearer]` is
//! configured, falls back to Zitadel introspection: a signed-in user's Zitadel
//! access token acts as that user's web session ([`HarborUsers`]), the account
//! created on first use as a first web sign-in would.

use std::collections::HashSet;

use std::sync::Arc;

use async_trait::async_trait;
use plan_ai_api_mcp::zitadel::{ClientAuth, Identity, IdentityMapper, IntrospectionConfig, ZitadelAuthenticator};
use plan_ai_api_mcp::{ApiError, Authenticator, OrgSet, Principal};
use plan_ai_auth::{ProviderMeta, SignIn, SignInError, UserResolver, WebUser, groups_in_claims};
use sqlx::PgPool;
use uuid::Uuid;

pub struct TokenAuthenticator {
    pool: PgPool,
}

impl TokenAuthenticator {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl Authenticator for TokenAuthenticator {
    async fn authenticate(&self, bearer: &str) -> Result<Principal, ApiError> {
        self.lookup(bearer)
            .await?
            .ok_or_else(|| ApiError::unauthorized("invalid or expired token"))
    }
}

impl TokenAuthenticator {
    /// The principal of a live `tokens` row with this bearer; `None` when there is none.
    pub async fn lookup(&self, bearer: &str) -> Result<Option<Principal>, ApiError> {
        use sha2::{Digest, Sha256};
        let hash = hex::encode(Sha256::digest(bearer.as_bytes()));

        let row = sqlx::query_as::<_, (String, Option<Uuid>, Option<serde_json::Value>)>(
            "SELECT kind, organization_id, scopes FROM tokens \
             WHERE token_hash = $1 AND NOT revoked \
               AND (expires_at IS NULL OR expires_at > now())",
        )
        .bind(&hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
        let Some((kind, org, scopes)) = row else {
            return Ok(None);
        };
        match kind.as_str() {
            "admin" => Ok(Some(Principal::admin("token:admin"))),
            "api" => match org {
                Some(oid) => {
                    let role = scopes
                        .as_ref()
                        .and_then(|s| s.get("role"))
                        .and_then(|r| r.as_str())
                        .unwrap_or("write");
                    let read = HashSet::from([oid]);
                    let write = if role == "read" {
                        HashSet::new()
                    } else {
                        HashSet::from([oid])
                    };
                    Ok(Some(Principal {
                        admin: false,
                        read_orgs: OrgSet::Only(read),
                        write_orgs: OrgSet::Only(write),
                        scopes: scopes.unwrap_or(serde_json::Value::Null),
                        subject: format!("token:api:{oid}"),
                    }))
                }
                None => Ok(Some(Principal {
                    admin: false,
                    read_orgs: OrgSet::All,
                    write_orgs: OrgSet::Only(HashSet::new()),
                    scopes: serde_json::Value::Null,
                    subject: "token:api:global-ro".into(),
                })),
            },
            other => Err(ApiError::forbidden(format!(
                "token kind '{other}' is not permitted on this API"
            ))),
        }
    }
}

/// The API's authenticator: Harbor's own tokens first, then — when
/// configured — Zitadel access tokens of signed-in users.
pub struct BearerAuthenticator {
    tokens: TokenAuthenticator,
    zitadel: Option<ZitadelAuthenticator>,
}

impl BearerAuthenticator {
    pub fn new(pool: PgPool, cfg: Option<&crate::config::ZitadelBearerConfig>) -> Self {
        let zitadel = cfg.map(|z| {
            let introspection = IntrospectionConfig {
                issuer: z.issuer.clone(),
                introspection_endpoint: None,
                client: ClientAuth::Basic { client_id: z.client_id.clone(), client_secret: z.client_secret.clone() },
                project_id: z.project_id.clone(),
                cache_secs: 60,
            };
            let auth = crate::config::config().auth.as_ref();
            let users = Arc::new(HarborUsers {
                resolver: crate::web::auth::PgUserResolver::new(
                    pool.clone(),
                    auth.map(|a| a.admin_emails.clone()).unwrap_or_default(),
                ),
                pool: pool.clone(),
                sign_up: z.auto_create.then(|| provider_for(&z.issuer, auth)),
            });
            tracing::info!(issuer = %z.issuer, project_id = %z.project_id, auto_create = z.auto_create,
                "API accepts Zitadel bearer tokens");
            ZitadelAuthenticator::new(introspection, users).unwrap_or_else(|e| panic!("[zitadel_bearer]: {e}"))
        });
        Self { tokens: TokenAuthenticator::new(pool), zitadel }
    }
}

#[async_trait]
impl Authenticator for BearerAuthenticator {
    async fn authenticate(&self, bearer: &str) -> Result<Principal, ApiError> {
        if let Some(p) = self.tokens.lookup(bearer).await? {
            return Ok(p);
        }
        let Some(zitadel) = &self.zitadel else {
            return Err(ApiError::unauthorized("invalid or expired token"));
        };
        // Zitadel unreachable or refusing our credentials is, to the caller, a
        // bearer nobody could verify: 401, not a 500.
        zitadel.authenticate(bearer).await.map_err(|e| match e {
            ApiError::Internal(why) => {
                tracing::warn!(reason = %why, "zitadel bearer could not be verified");
                ApiError::unauthorized("invalid or expired token (not a Harbor token, and Zitadel could not verify it)")
            }
            other => other,
        })
    }
}

/// The `[[auth.providers]]` entry with `issuer`, or that issuer admitting
/// everybody the token check admits (as plan-ai-cloud's console does).
fn provider_for(issuer: &str, auth: Option<&plan_ai_auth::AuthConfig>) -> ProviderMeta {
    auth.and_then(|a| a.providers.iter().map(|p| ProviderMeta::from_config(p, a)).find(|p| p.has_issuer(issuer)))
        .unwrap_or_else(|| ProviderMeta {
            slug: "zitadel_bearer".into(),
            name: "Zitadel bearer".into(),
            issuer: Some(issuer.into()),
            allow_all: true,
            allowed_domains: vec![],
            allowed_emails: vec![],
            auto_join_orgs: vec![],
            admin_emails: auth.map(|a| a.admin_emails.clone()).unwrap_or_default(),
            groups_claim: None,
            liveliness_days: None,
            zitadel_org: None,
        })
}

/// Maps a Zitadel identity to the Harbor user with its email — their web
/// session's principal — creating it through the web sign-in when it has none.
pub struct HarborUsers {
    pool: PgPool,
    resolver: Arc<crate::web::auth::PgUserResolver>,
    sign_up: Option<ProviderMeta>,
}

impl HarborUsers {
    async fn sign_up(&self, email: &str, identity: &Identity) -> Result<WebUser, ApiError> {
        let Some(provider) = &self.sign_up else {
            return Err(ApiError::forbidden(format!("{email} has no Harbor account — sign in to it once first")));
        };
        if identity.email_verified != Some(true) {
            return Err(ApiError::forbidden(format!(
                "{email} has no Harbor account, and none is made for an address Zitadel does not call verified"
            )));
        }
        let claims = serde_json::Value::Object(identity.claims.clone());
        let sign_in = SignIn {
            email,
            name: identity.name.as_deref(),
            groups: provider.groups_claim.as_deref().map(|c| groups_in_claims(&claims, c)).unwrap_or_default(),
            zitadel_org: identity.org_id.as_deref(),
        };
        match provider.sign_in(self.resolver.as_ref(), &sign_in).await {
            Ok(user) => {
                tracing::info!(email, user_id = %user.id, zitadel_user_id = %identity.user_id,
                    "Harbor account created for a Zitadel bearer token");
                Ok(user)
            }
            Err(SignInError::Refused(why)) => Err(ApiError::forbidden(format!(
                "{email} has no Harbor account, and signing in would be refused: {why}"
            ))),
            Err(SignInError::Failed(e)) => Err(ApiError::internal(format!("could not create the account for {email}: {e:#}"))),
        }
    }
}

#[async_trait]
impl IdentityMapper for HarborUsers {
    async fn principal(&self, identity: &Identity) -> Result<Principal, ApiError> {
        let email = identity.email.as_deref().filter(|e| !e.is_empty()).ok_or_else(|| {
            ApiError::unauthorized("the token carries no email; request it with the `email` scope")
        })?;
        if identity.email_verified == Some(false) {
            return Err(ApiError::forbidden(format!("{email} is not verified in Zitadel")));
        }
        let internal = |e: anyhow::Error| ApiError::internal(format!("{e:#}"));
        let id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
        let user = match id {
            Some(id) => self
                .resolver
                .load_user_by_id(id)
                .await
                .map_err(internal)?
                .ok_or_else(|| ApiError::internal("the account vanished"))?,
            None => self.sign_up(email, identity).await?,
        };
        Ok(principal_for(&user, identity.actor.as_ref().map(|a| a.sub.as_str())))
    }
}

/// The user's web-session principal, saying who acts when the token came from
/// a token exchange.
fn principal_for(user: &WebUser, actor: Option<&str>) -> Principal {
    let mut p = crate::web::user::principal_from(user);
    if let Some(actor) = actor {
        p.subject = format!("{} (act: {actor})", user.email);
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bearer_acts_as_the_web_session() {
        let user = WebUser {
            id: Uuid::from_u128(1),
            email: "ada@plan.ai".into(),
            name: "Ada".into(),
            is_admin: false,
            org_memberships: vec![plan_ai_auth::OrgMembership::new(Uuid::from_u128(9), "write")],
            impersonating_from: None,
        };
        let session = crate::web::user::principal_from(&user);
        let p = principal_for(&user, Some("chat-connector"));
        assert_eq!(p.subject, "ada@plan.ai (act: chat-connector)");
        assert_eq!((p.admin, format!("{:?}", p.read_orgs), format!("{:?}", p.write_orgs)),
                   (session.admin, format!("{:?}", session.read_orgs), format!("{:?}", session.write_orgs)));
        assert_eq!(principal_for(&user, None).subject, "ada@plan.ai");
    }

    #[test]
    fn without_a_web_provider_the_issuer_admits_all() {
        assert!(provider_for("https://id.plan.ai", None).admits("x@y.z", None).is_ok());
    }
}
