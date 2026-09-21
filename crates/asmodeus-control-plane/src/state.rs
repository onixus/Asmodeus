//! Shared control-plane application state.
//!
//! Keeps runtime infrastructure and persistence handles out of the HTTP
//! transport module.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use asmodeus_common::{RunId, RunState};
use asmodeus_telemetry::{Aggregate, AuditTrail};

use crate::campaign::CampaignCatalog;
use crate::catalog::Catalog;
use crate::registry::RunnerRegistry;
use crate::scheduler::ScheduleCatalog;
use crate::webhook::WebhookDispatcher;

/// Shared, cheaply cloneable server state.
#[derive(Clone)]
pub struct AppState {
    pub catalog: Arc<Catalog>,
    pub runs: Arc<Mutex<HashMap<RunId, RunState>>>,
    pub metrics: Arc<Mutex<Aggregate>>,
    counter: Arc<AtomicU64>,
    /// When set, scenarios are dispatched to this live runner over gRPC;
    /// otherwise the in-process engine simulates the run.
    pub runner_endpoint: Option<String>,
    pub registry: RunnerRegistry,
    pub audit_trail: Arc<std::sync::RwLock<AuditTrail>>,
    pub campaigns: Arc<std::sync::RwLock<CampaignCatalog>>,
    pub schedules: Arc<std::sync::RwLock<ScheduleCatalog>>,
    pub webhook: Arc<WebhookDispatcher>,
    pub signing_key: [u8; 64],
    pub audit_file_path: Option<std::path::PathBuf>,
}

impl AppState {
    /// Reads `ASMODEUS_RUNNER_ENDPOINT` from the environment.
    pub fn new(catalog: Catalog) -> Self {
        let endpoint = std::env::var("ASMODEUS_RUNNER_ENDPOINT").ok();
        Self::with_runner(catalog, endpoint)
    }

    pub fn with_runner(catalog: Catalog, runner_endpoint: Option<String>) -> Self {
        let registry = if let Some(ref ep) = runner_endpoint {
            RunnerRegistry::with_default(
                "default-runner",
                ep,
                vec!["default".into(), "endpoint_agent".into()],
            )
        } else {
            RunnerRegistry::new()
        };
        Self::build(catalog, runner_endpoint, registry)
    }

    #[allow(dead_code)]
    pub fn with_registry(catalog: Catalog, registry: RunnerRegistry) -> Self {
        Self::build(catalog, None, registry)
    }

    /// Shared constructor: derives the audit signing key, restores the
    /// persistent audit trail from `ASMODEUS_AUDIT_LOG` (if set) and rebuilds
    /// the Prometheus aggregate from it, so `/metrics` and the resilience report
    /// survive a restart instead of resetting to zero.
    fn build(catalog: Catalog, runner_endpoint: Option<String>, registry: RunnerRegistry) -> Self {
        let signing_key = if let Some(sk_bytes) = catalog.secret_key() {
            let mut k = [0u8; 64];
            if sk_bytes.len() == 64 {
                k.copy_from_slice(sk_bytes);
                k
            } else {
                asmodeus_crypto::generate_keypair().1
            }
        } else {
            asmodeus_crypto::generate_keypair().1
        };
        let audit_file_path = std::env::var("ASMODEUS_AUDIT_LOG")
            .ok()
            .map(std::path::PathBuf::from);
        let audit_trail = if let Some(ref path) = audit_file_path {
            AuditTrail::load_from_file(path).unwrap_or_else(|_| AuditTrail::new())
        } else {
            AuditTrail::new()
        };
        // Rebuild rolling detection metrics from the persisted audit trail so
        // reports and /metrics survive a restart instead of resetting to zero.
        let metrics = Aggregate::from_records(audit_trail.records());
        AppState {
            catalog: Arc::new(catalog),
            runs: Arc::new(Mutex::new(HashMap::new())),
            metrics: Arc::new(Mutex::new(metrics)),
            counter: Arc::new(AtomicU64::new(1)),
            runner_endpoint,
            registry,
            audit_trail: Arc::new(std::sync::RwLock::new(audit_trail)),
            campaigns: Arc::new(std::sync::RwLock::new(CampaignCatalog::seeded())),
            schedules: Arc::new(std::sync::RwLock::new(ScheduleCatalog::seeded())),
            webhook: Arc::new(WebhookDispatcher::from_env()),
            signing_key,
            audit_file_path,
        }
    }

    pub(crate) fn next_run_id(&self) -> RunId {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        RunId::new(format!("run_{n:08x}"))
    }
}
