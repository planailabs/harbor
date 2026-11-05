//! Prometheus metrics endpoint.
//!
//! `GET /api/metrics` — returns Prometheus text format metrics.
//!
//! The metrics themselves are OpenTelemetry instruments (see
//! [`super::counters`]); this endpoint only renders the Prometheus reader
//! attached to the same meter provider, so a collector scraping here and a
//! collector receiving OTLP see the same numbers.
//!
//! Auth: Bearer token with `kind = 'metrics'` in the `tokens` table.
//! - If the token has `organization_id` set → org-scoped (only that org's metrics).
//! - If `organization_id` is NULL → admin (all orgs + global counters).

use dioxus::fullstack::axum::{
    self as axum, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
};
use mac_mgmt_common::metrics::prom;
use sqlx::PgPool;
use uuid::Uuid;

use super::counters::{
    DB_SNAPSHOT, ORG_LABEL, ORG_SCOPED_METRICS, DbSnapshot, Reachability, WebspaceRunning,
};

#[derive(Clone)]
pub struct MetricsState {
    pub pool: PgPool,
}

pub fn router(state: MetricsState) -> Router<()> {
    Router::new()
        .route("/api/metrics", get(metrics_handler))
        .with_state(state)
}

struct MetricsAuth {
    organization_id: Option<Uuid>,
}

async fn authenticate_metrics(
    pool: &PgPool,
    headers: &HeaderMap,
) -> Result<MetricsAuth, (StatusCode, String)> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "missing Bearer token".into()))?;

    use sha2::{Digest, Sha256};
    let hash = hex::encode(Sha256::digest(token.as_bytes()));

    let row = sqlx::query_as::<_, (String, Option<Uuid>)>(
        "SELECT kind, organization_id FROM tokens \
         WHERE token_hash = $1 AND NOT revoked \
           AND (expires_at IS NULL OR expires_at > now())",
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::UNAUTHORIZED, "invalid token".into()))?;

    let (kind, organization_id) = row;
    if kind != "metrics" {
        return Err((StatusCode::FORBIDDEN, "token kind must be 'metrics'".into()));
    }

    Ok(MetricsAuth { organization_id })
}

async fn metrics_handler(
    State(state): State<MetricsState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let auth = authenticate_metrics(&state.pool, &headers).await?;

    // Database-derived series are pull-shaped: refresh them, then collect —
    // gathering runs the observable callbacks that read this snapshot.
    refresh_db_snapshot(&state.pool).await?;

    let mut families = prom::registry().gather();
    if let Some(org_id) = auth.organization_id {
        scope_to_org(&mut families, org_id);
    }

    let body = prom::encode_families(families)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("encode: {e}")))?;

    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    ))
}

/// Drop everything an org-scoped token may not see: admin-only metrics, and
/// other orgs' series within the per-org ones.
fn scope_to_org(families: &mut Vec<prom::prometheus::proto::MetricFamily>, org_id: Uuid) {
    let org_id = org_id.to_string();
    families.retain(|f| ORG_SCOPED_METRICS.contains(&f.name()));
    for family in families.iter_mut() {
        let metrics = std::mem::take(family.mut_metric());
        family.set_metric(
            metrics
                .into_iter()
                .filter(|m| {
                    m.get_label()
                        .iter()
                        .any(|l| l.name() == ORG_LABEL && l.value() == org_id)
                })
                .collect(),
        );
    }
    families.retain(|f| !f.get_metric().is_empty());
}

#[cfg(test)]
mod tests {
    use super::*;
    use prom::prometheus::proto::{LabelPair, Metric, MetricFamily};

    fn family(name: &str, org_ids: &[&str]) -> MetricFamily {
        let mut f = MetricFamily::default();
        f.set_name(name.to_owned());
        f.set_metric(
            org_ids
                .iter()
                .map(|id| {
                    let mut label = LabelPair::default();
                    label.set_name(ORG_LABEL.to_owned());
                    label.set_value((*id).to_owned());
                    let mut m = Metric::default();
                    m.set_label(vec![label]);
                    m
                })
                .collect(),
        );
        f
    }

    #[test]
    fn org_token_sees_only_its_own_series() {
        let mine = Uuid::new_v4();
        let theirs = Uuid::new_v4();
        let mut families = vec![
            family(
                "harbor_webspace_running",
                &[&mine.to_string(), &theirs.to_string()],
            ),
            // Per-org metric, but no series of ours → drops out entirely.
            family("harbor_relay_token_mint_ok", &[&theirs.to_string()]),
            // Admin-only.
            family("harbor_deployments_total", &[]),
        ];

        scope_to_org(&mut families, mine);

        assert_eq!(families.len(), 1);
        assert_eq!(families[0].name(), "harbor_webspace_running");
        assert_eq!(families[0].get_metric().len(), 1);
        assert_eq!(families[0].get_metric()[0].get_label()[0].value(), mine.to_string());
    }
}

/// Reload the webspace/reachability series the observable gauges report.
async fn refresh_db_snapshot(pool: &PgPool) -> Result<(), (StatusCode, String)> {
    let db_err = |e: sqlx::Error| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string());

    let webspaces = sqlx::query_as::<_, (String, String, Uuid, String)>(
        "SELECT w.name, o.name, o.id, w.local_status \
         FROM webspaces w \
         JOIN organizations o ON o.id = w.organization_id \
         WHERE w.hosting_type = 'local'",
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)?
    .into_iter()
    .map(|(webspace, org, org_id, status)| WebspaceRunning {
        org,
        org_id,
        webspace,
        running: status == "running",
    })
    .collect();

    let reachability = sqlx::query_as::<
        _,
        (String, String, Uuid, String, bool, bool, bool, Option<i32>, f64),
    >(
        "SELECT h.name, o.name, o.id, r.hostname, r.http_ok, r.ssl_ok, r.proxy_ok, r.latency_ms, \
                EXTRACT(EPOCH FROM r.checked_at)::float8 \
         FROM reachability_results r \
         JOIN webspace_hosts h ON h.id = r.webspace_host_id \
         JOIN organizations o ON o.id = r.organization_id",
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)?
    .into_iter()
    .map(
        |(webspace, org, org_id, hostname, http_ok, ssl_ok, proxy_ok, latency_ms, checked_at)| {
            Reachability {
                org,
                org_id,
                webspace,
                hostname,
                http_ok,
                ssl_ok,
                proxy_ok,
                latency_ms,
                checked_at,
            }
        },
    )
    .collect();

    *DB_SNAPSHOT.lock().unwrap() = DbSnapshot {
        webspaces,
        reachability,
    };
    Ok(())
}
