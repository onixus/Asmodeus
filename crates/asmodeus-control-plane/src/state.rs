//! Shared control-plane application state.
//!
//! Keeps runtime infrastructure and persistence handles out of the HTTP
//! transport module.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use asmodeus_common::RunId;
use ring::rand::{SecureRandom, SystemRandom};
use std::io;

use crate::audit_store::AuditStore;
use crate::campaign::CampaignCatalog;
use crate::catalog::Catalog;
use crate::registry::RunnerRegistry;
use crate::scheduler::ScheduleCatalog;
use crate::webhook::WebhookDispatcher;

/// Shared, cheaply cloneable server state.
#[derive(Clone)]
pub struct AppState {
    pub catalog: Arc<Catalog>,
    pub runs: Arc<Mutex<HashMap<RunId, crate::run_control::ActiveRun>>>,
    counter: Arc<AtomicU64>,
    run_namespace: String,
    pub audit_public_key: [u8; 32],
    /// When set, scenarios are dispatched to this live runner over gRPC;
    /// otherwise the in-process engine simulates the run.
    pub runner_endpoint: Option<String>,
    pub registry: RunnerRegistry,
    pub campaigns: crate::persistent::Persistent<CampaignCatalog>,
    pub schedules: crate::persistent::Persistent<ScheduleCatalog>,
    pub webhook: Arc<WebhookDispatcher>,
    pub signing_key: [u8; 64],
    pub audit: AuditStore,
}

impl AppState {
    /// Reads `ASMODEUS_RUNNER_ENDPOINT` from the environment.
    pub fn new(catalog: Catalog) -> io::Result<Self> {
        let endpoint = std::env::var("ASMODEUS_RUNNER_ENDPOINT").ok();
        Self::with_runner(catalog, endpoint)
    }

    pub fn with_runner(catalog: Catalog, runner_endpoint: Option<String>) -> io::Result<Self> {
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
    pub fn with_registry(catalog: Catalog, registry: RunnerRegistry) -> io::Result<Self> {
        Self::build(catalog, None, registry)
    }

    /// Shared constructor: derives the audit signing key, restores the
    /// persistent audit trail from `ASMODEUS_AUDIT_LOG` (if set) and rebuilds
    /// the Prometheus aggregate from it, so `/metrics` and the resilience report
    /// survive a restart instead of resetting to zero.
    fn build(
        catalog: Catalog,
        runner_endpoint: Option<String>,
        registry: RunnerRegistry,
    ) -> io::Result<Self> {
        let audit_path = std::env::var("ASMODEUS_AUDIT_LOG")
            .ok()
            .map(std::path::PathBuf::from);
        let key_path = std::env::var("ASMODEUS_AUDIT_SIGNING_KEY")
            .ok()
            .map(std::path::PathBuf::from);
        let signing_key = load_audit_key(key_path.as_deref(), audit_path.is_some())?;
        Self::with_storage(catalog, runner_endpoint, registry, audit_path, signing_key)
    }

    fn with_storage(
        catalog: Catalog,
        runner_endpoint: Option<String>,
        registry: RunnerRegistry,
        audit_path: Option<std::path::PathBuf>,
        signing_key: [u8; 64],
    ) -> io::Result<Self> {
        let state_dir = std::env::var("ASMODEUS_STATE_DIR")
            .ok()
            .map(std::path::PathBuf::from);
        let audit_public_key =
            asmodeus_crypto::public_key_from_secret_key(&signing_key).map_err(io::Error::other)?;
        let audit = AuditStore::load(audit_path)?;
        for record in audit.records() {
            if !record.verify_with_key(&audit_public_key) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("untrusted audit record: {}", record.run_id),
                ));
            }
        }
        audit.recover_incomplete(&signing_key)?;
        let mut namespace = [0u8; 16];
        SystemRandom::new()
            .fill(&mut namespace)
            .map_err(|_| io::Error::other("run ID entropy unavailable"))?;
        let run_namespace = namespace.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(AppState {
            catalog: Arc::new(catalog),
            runs: Arc::new(Mutex::new(HashMap::new())),
            counter: Arc::new(AtomicU64::new(1)),
            run_namespace,
            audit_public_key,
            runner_endpoint,
            registry,
            campaigns: crate::persistent::Persistent::load(
                state_dir.as_ref().map(|p| p.join("campaigns.json")),
                CampaignCatalog::seeded,
            )?,
            schedules: crate::persistent::Persistent::load(
                state_dir.as_ref().map(|p| p.join("schedules.json")),
                ScheduleCatalog::seeded,
            )?,
            webhook: Arc::new(WebhookDispatcher::from_env()),
            signing_key,
            audit,
        })
    }

    pub(crate) fn next_run_id(&self) -> RunId {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        RunId::new(format!("run_{}_{n:016x}", self.run_namespace))
    }
}

/// Persistent logs require an operator-managed key (the CLI keygen hex format).
/// A fresh demo key is allowed only when no persistent log is configured.
fn load_audit_key(path: Option<&std::path::Path>, persistent: bool) -> io::Result<[u8; 64]> {
    let Some(path) = path else {
        if persistent {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ASMODEUS_AUDIT_SIGNING_KEY is required with ASMODEUS_AUDIT_LOG",
            ));
        }
        return Ok(asmodeus_crypto::generate_keypair().1);
    };
    let text = std::fs::read_to_string(path)?;
    let hex = text.trim();
    if hex.len() != 128 || !hex.is_ascii() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "audit key must contain 64 hex-encoded bytes",
        ));
    }
    let mut key = [0u8; 64];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid audit key hex"))?;
    }
    let pk = asmodeus_crypto::public_key_from_secret_key(&key).map_err(io::Error::other)?;
    let proof = asmodeus_crypto::sign_message(b"asmodeus-audit-key-check", &key)
        .map_err(io::Error::other)?;
    if !asmodeus_crypto::is_valid(b"asmodeus-audit-key-check", &proof, &pk) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "inconsistent audit key",
        ));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asmodeus_common::Role;
    use asmodeus_testkit::Polygon;

    #[tokio::test]
    async fn restart_preserves_trusted_audit_metrics_and_unique_run_ids() {
        let poly = Polygon::new("restart-state");
        let path = poly.dir().join("audit.jsonl");
        let (_, key) = asmodeus_crypto::generate_keypair();
        let first = AppState::with_storage(
            Catalog::seeded(),
            None,
            RunnerRegistry::new(),
            Some(path.clone()),
            key,
        )
        .unwrap();
        let entry = first.catalog.get("RANSOMWARE_CANARY_SPIKE").unwrap();
        let (first_id, _, record) =
            crate::execution::execute_single_scenario(&first, entry, Role::Admin, None)
                .await
                .unwrap();
        assert!(record.verify_with_key(&first.audit_public_key));
        let restored = AppState::with_storage(
            Catalog::seeded(),
            None,
            RunnerRegistry::new(),
            Some(path.clone()),
            key,
        )
        .unwrap();
        assert_eq!(first.audit.records(), restored.audit.records());
        assert_eq!(
            first.audit.aggregate().prometheus_text(),
            restored.audit.aggregate().prometheus_text()
        );
        assert!(restored
            .audit
            .get(&first_id.to_string())
            .unwrap()
            .verify_with_key(&restored.audit_public_key));
        let entry = restored.catalog.get("RANSOMWARE_CANARY_SPIKE").unwrap();
        let (second_id, _, _) =
            crate::execution::execute_single_scenario(&restored, entry, Role::Admin, None)
                .await
                .unwrap();
        assert_ne!(first_id, second_id);
        assert_eq!(restored.audit.len(), 2);
        let (_, wrong_key) = asmodeus_crypto::generate_keypair();
        assert!(AppState::with_storage(
            Catalog::seeded(),
            None,
            RunnerRegistry::new(),
            Some(path),
            wrong_key
        )
        .is_err());
    }

    #[tokio::test]
    async fn failed_audit_write_returns_http_error_without_success_metrics() {
        use axum::{
            body::Body,
            http::{Request, StatusCode},
        };
        use tower::ServiceExt;
        let poly = Polygon::new("api-audit-failure");
        let path = poly.dir().join("audit.jsonl");
        let (_, key) = asmodeus_crypto::generate_keypair();
        let state = AppState::with_storage(
            Catalog::seeded(),
            None,
            RunnerRegistry::new(),
            Some(path.clone()),
            key,
        )
        .unwrap();
        std::fs::create_dir_all(path).unwrap();
        let response = crate::http::router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/asmodeus/scenarios/RANSOMWARE_CANARY_SPIKE/run")
                    .header("x-apex-role", "admin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(state.audit.len(), 0);
        assert_eq!(state.audit.aggregate().scenarios_executed, 0);
        assert!(state.runs.lock().unwrap().is_empty());
    }

    #[test]
    fn persistent_audit_requires_valid_operator_key() {
        assert!(load_audit_key(None, true).is_err());
        assert!(load_audit_key(None, false).is_ok());
        let poly = Polygon::new("audit-key");
        std::fs::create_dir_all(poly.dir()).unwrap();
        let path = poly.dir().join("audit.key");
        let (_, key) = asmodeus_crypto::generate_keypair();
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(&path, hex).unwrap();
        assert_eq!(load_audit_key(Some(&path), true).unwrap(), key);
        for bad in ["é".repeat(64), "zz".repeat(64), "abcd".into()] {
            std::fs::write(&path, bad).unwrap();
            assert!(load_audit_key(Some(&path), true).is_err());
        }
    }
}
