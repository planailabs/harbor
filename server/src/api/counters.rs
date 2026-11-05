//! Metric state and the OpenTelemetry instruments that export it.
//!
//! Instrumented code paths keep writing plain atomics (and, for pull-shaped
//! data, a snapshot refreshed at scrape time); [`register`] hangs OTel
//! observable instruments off them, read whenever a reader collects — the OTLP
//! push reader and the Prometheus scrape endpoint alike.
//!
//! Per-cycle gauges are reset at the start of each cycle (sync, cert tick).
//! Cumulative counters are monotonically increasing and never reset.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

use opentelemetry::{KeyValue, global};
use uuid::Uuid;

/// Metric scope for everything this server reports.
const SCOPE: &str = "harbor-server";

/// Metrics an org-scoped metrics token is allowed to see. Everything else is
/// admin-only. Kept next to the definitions so a new per-org metric can't be
/// added without deciding which side of the fence it falls on.
pub const ORG_SCOPED_METRICS: &[&str] = &[
    "harbor_webspace_running",
    "harbor_reachability_http_ok",
    "harbor_reachability_ssl_ok",
    "harbor_reachability_proxy_ok",
    "harbor_reachability_latency_ms",
    "harbor_reachability_checked_at",
    "harbor_relay_token_mint_ok",
];

/// Prometheus label carrying the owning organization, used to scope a scrape.
pub const ORG_LABEL: &str = "org_id";

/// Global counters, accessed from instrumented code paths.
pub static COUNTERS: LazyLock<GlobalCounters> = LazyLock::new(GlobalCounters::new);

/// Per-webspace relay token mint results, keyed by hostname.
pub static RELAY_MINT_RESULTS: LazyLock<Mutex<HashMap<String, MintResult>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Database-derived series, refreshed by the metrics endpoint immediately
/// before collection so a scrape still reflects live state.
pub static DB_SNAPSHOT: LazyLock<Mutex<DbSnapshot>> =
    LazyLock::new(|| Mutex::new(DbSnapshot::default()));

/// Result of the last relay token mint attempt for a webspace hostname.
pub struct MintResult {
    pub org_id: Uuid,
    pub success: bool,
}

#[derive(Default)]
pub struct DbSnapshot {
    pub webspaces: Vec<WebspaceRunning>,
    pub reachability: Vec<Reachability>,
}

pub struct WebspaceRunning {
    pub org: String,
    pub org_id: Uuid,
    pub webspace: String,
    pub running: bool,
}

pub struct Reachability {
    pub org: String,
    pub org_id: Uuid,
    pub webspace: String,
    pub hostname: String,
    pub http_ok: bool,
    pub ssl_ok: bool,
    pub proxy_ok: bool,
    pub latency_ms: Option<i32>,
    pub checked_at: f64,
}

pub struct GlobalCounters {
    // ── Per-cycle gauges (reset at start of each cycle) ──
    pub sync_dns_errors: AtomicU64,
    pub sync_expiry_errors: AtomicU64,
    pub sync_ns_errors: AtomicU64,
    pub sync_bot_errors: AtomicU64,
    pub sync_changedetection_errors: AtomicU64,
    pub cert_renewal_success: AtomicU64,
    pub cert_renewal_failed: AtomicU64,
    pub cert_issuance_success: AtomicU64,
    pub cert_issuance_failed: AtomicU64,

    // ── Cumulative counters (never reset) ──
    pub deploy_success: AtomicU64,
    pub deploy_failed: AtomicU64,
    pub relay_mint_success: AtomicU64,
    pub relay_mint_failed: AtomicU64,
}

impl GlobalCounters {
    fn new() -> Self {
        Self {
            sync_dns_errors: AtomicU64::new(0),
            sync_expiry_errors: AtomicU64::new(0),
            sync_ns_errors: AtomicU64::new(0),
            sync_bot_errors: AtomicU64::new(0),
            sync_changedetection_errors: AtomicU64::new(0),
            cert_renewal_success: AtomicU64::new(0),
            cert_renewal_failed: AtomicU64::new(0),
            cert_issuance_success: AtomicU64::new(0),
            cert_issuance_failed: AtomicU64::new(0),
            deploy_success: AtomicU64::new(0),
            deploy_failed: AtomicU64::new(0),
            relay_mint_success: AtomicU64::new(0),
            relay_mint_failed: AtomicU64::new(0),
        }
    }

    /// Reset all per-cycle sync gauges to 0.
    pub fn reset_sync_gauges(&self) {
        self.sync_dns_errors.store(0, Ordering::Relaxed);
        self.sync_expiry_errors.store(0, Ordering::Relaxed);
        self.sync_ns_errors.store(0, Ordering::Relaxed);
        self.sync_bot_errors.store(0, Ordering::Relaxed);
        self.sync_changedetection_errors.store(0, Ordering::Relaxed);
    }

    /// Reset all per-cycle cert gauges to 0.
    pub fn reset_cert_gauges(&self) {
        self.cert_renewal_success.store(0, Ordering::Relaxed);
        self.cert_renewal_failed.store(0, Ordering::Relaxed);
        self.cert_issuance_success.store(0, Ordering::Relaxed);
        self.cert_issuance_failed.store(0, Ordering::Relaxed);
    }
}

/// Register the observable instruments. Call once at startup, after
/// `otel::init` has installed a meter provider.
pub fn register() {
    let meter = global::meter(SCOPE);

    // ── Database-derived, refreshed at scrape time ──

    meter
        .i64_observable_gauge("harbor_webspace_running")
        .with_description("Whether the local webspace is running (1) or not (0)")
        .with_callback(|o| {
            for w in &DB_SNAPSHOT.lock().unwrap().webspaces {
                o.observe(
                    w.running as i64,
                    &[
                        KeyValue::new("org", w.org.clone()),
                        KeyValue::new(ORG_LABEL, w.org_id.to_string()),
                        KeyValue::new("webspace", w.webspace.clone()),
                    ],
                );
            }
        })
        .build();

    fn reachability_attrs(r: &Reachability) -> [KeyValue; 4] {
        [
            KeyValue::new("org", r.org.clone()),
            KeyValue::new(ORG_LABEL, r.org_id.to_string()),
            KeyValue::new("webspace", r.webspace.clone()),
            KeyValue::new("hostname", r.hostname.clone()),
        ]
    }

    for (name, description, pick) in [
        (
            "harbor_reachability_http_ok",
            "HTTP reachability (1=ok, 0=fail)",
            (|r: &Reachability| r.http_ok) as fn(&Reachability) -> bool,
        ),
        (
            "harbor_reachability_ssl_ok",
            "SSL validity (1=ok, 0=fail)",
            |r| r.ssl_ok,
        ),
        (
            "harbor_reachability_proxy_ok",
            "Proxy verification via .well-known (1=ok, 0=fail)",
            |r| r.proxy_ok,
        ),
    ] {
        meter
            .i64_observable_gauge(name)
            .with_description(description)
            .with_callback(move |o| {
                for r in &DB_SNAPSHOT.lock().unwrap().reachability {
                    o.observe(pick(r) as i64, &reachability_attrs(r));
                }
            })
            .build();
    }

    meter
        .f64_observable_gauge("harbor_reachability_latency_ms")
        .with_description("Reachability check latency in milliseconds")
        .with_callback(|o| {
            for r in &DB_SNAPSHOT.lock().unwrap().reachability {
                if let Some(ms) = r.latency_ms {
                    o.observe(ms as f64, &reachability_attrs(r));
                }
            }
        })
        .build();

    meter
        .f64_observable_gauge("harbor_reachability_checked_at")
        .with_description("Unix timestamp of last reachability check")
        .with_callback(|o| {
            for r in &DB_SNAPSHOT.lock().unwrap().reachability {
                o.observe(r.checked_at, &reachability_attrs(r));
            }
        })
        .build();

    meter
        .i64_observable_gauge("harbor_relay_token_mint_ok")
        .with_description("Whether the last relay token mint succeeded (1) or failed (0)")
        .with_callback(|o| {
            for (hostname, result) in RELAY_MINT_RESULTS.lock().unwrap().iter() {
                o.observe(
                    result.success as i64,
                    &[
                        KeyValue::new("hostname", hostname.clone()),
                        KeyValue::new(ORG_LABEL, result.org_id.to_string()),
                    ],
                );
            }
        })
        .build();

    // ── Per-cycle gauges ──

    meter
        .i64_observable_gauge("harbor_sync_last_errors")
        .with_description("Number of errors in the last sync cycle")
        .with_callback(|o| {
            let c = &COUNTERS;
            for (kind, value) in [
                ("dns", &c.sync_dns_errors),
                ("expiry", &c.sync_expiry_errors),
                ("nameserver", &c.sync_ns_errors),
                ("bot_protection", &c.sync_bot_errors),
                ("changedetection", &c.sync_changedetection_errors),
            ] {
                o.observe(
                    value.load(Ordering::Relaxed) as i64,
                    &[KeyValue::new("sync_type", kind)],
                );
            }
        })
        .build();

    meter
        .i64_observable_gauge("harbor_cert_renewal_last_results")
        .with_description("Results from the last cert renewal tick")
        .with_callback(|o| {
            observe_status_pair(
                o,
                &COUNTERS.cert_renewal_success,
                &COUNTERS.cert_renewal_failed,
            )
        })
        .build();

    meter
        .i64_observable_gauge("harbor_cert_issuance_last_results")
        .with_description("Results from the last cert issuance tick")
        .with_callback(|o| {
            observe_status_pair(
                o,
                &COUNTERS.cert_issuance_success,
                &COUNTERS.cert_issuance_failed,
            )
        })
        .build();

    // ── Cumulative counters (exported as `<name>_total`) ──

    meter
        .u64_observable_counter("harbor_deployments")
        .with_description("Total deployments since server start")
        .with_callback(|o| {
            o.observe(
                COUNTERS.deploy_success.load(Ordering::Relaxed),
                &[KeyValue::new("status", "success")],
            );
            o.observe(
                COUNTERS.deploy_failed.load(Ordering::Relaxed),
                &[KeyValue::new("status", "failed")],
            );
        })
        .build();

    meter
        .u64_observable_counter("harbor_relay_token_mint")
        .with_description("Total relay token mint attempts since server start")
        .with_callback(|o| {
            o.observe(
                COUNTERS.relay_mint_success.load(Ordering::Relaxed),
                &[KeyValue::new("status", "success")],
            );
            o.observe(
                COUNTERS.relay_mint_failed.load(Ordering::Relaxed),
                &[KeyValue::new("status", "failed")],
            );
        })
        .build();
}

fn observe_status_pair(
    o: &dyn opentelemetry::metrics::AsyncInstrument<i64>,
    success: &AtomicU64,
    failed: &AtomicU64,
) {
    o.observe(
        success.load(Ordering::Relaxed) as i64,
        &[KeyValue::new("status", "success")],
    );
    o.observe(
        failed.load(Ordering::Relaxed) as i64,
        &[KeyValue::new("status", "failed")],
    );
}
