//! Integration-style tests for the control-plane HTTP transport.
//!
//! Kept outside `http.rs` so the production router remains small and easy to
//! review while preserving the same crate-private visibility.

use super::http::*;
use crate::catalog::Catalog;
use crate::registry::RunnerRegistry;
use crate::state::AppState;
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::Router;
use serde_json::Value;
use tower::ServiceExt;

use super::*;

fn app() -> Router {
    router(AppState::new(Catalog::seeded()))
}

async fn send(method: &str, uri: &str, role: Option<&str>) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(r) = role {
        req = req.header("x-apex-role", r);
    }
    let resp = app()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

#[tokio::test]
async fn healthz_is_open() {
    let (status, body) = send("GET", "/healthz", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn red_team_runs_red_team_scenario() {
    let (status, body) = send(
        "POST",
        "/api/v1/asmodeus/scenarios/RANSOMWARE_CANARY_SPIKE/run",
        Some("red_team"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "COMPLETED");
    assert_eq!(body["measurements"]["blue_team_detected"], true);
}

#[tokio::test]
async fn ciso_is_forbidden_from_running() {
    let (status, _) = send(
        "POST",
        "/api/v1/asmodeus/scenarios/RANSOMWARE_CANARY_SPIKE/run",
        Some("ciso"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn devsecops_cannot_launch_red_team() {
    let (status, _) = send(
        "POST",
        "/api/v1/asmodeus/scenarios/RANSOMWARE_CANARY_SPIKE/run",
        Some("devsecops"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn devsecops_can_inject_chaos() {
    let (status, body) = send(
        "POST",
        "/api/v1/asmodeus/scenarios/LATENCY_SPIKE_VM/run",
        Some("devsecops"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["tag"], asmodeus_common::EXERCISE_TAG_CHAOS);
}

#[tokio::test]
async fn missing_role_is_unauthorized() {
    let (status, _) = send(
        "POST",
        "/api/v1/asmodeus/scenarios/LATENCY_SPIKE_VM/run",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_scenario_is_not_found() {
    let (status, _) = send("POST", "/api/v1/asmodeus/scenarios/NOPE/run", Some("admin")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn metrics_reflect_a_run() {
    // Drive one run then scrape /metrics on the SAME app instance.
    let app = router(AppState::new(Catalog::seeded()));
    let run = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/scenarios/RANSOMWARE_CANARY_SPIKE/run")
        .header("x-apex-role", "red_team")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(run).await.unwrap().status(),
        StatusCode::OK
    );

    let scrape = Request::builder()
        .method("GET")
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(scrape).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(text.contains("asmodeus_scenarios_executed_total 1"));
    assert!(text.contains("asmodeus_mttd_seconds 0.142"));
}

#[tokio::test]
async fn auditor_can_view_but_not_abort() {
    let (view, _) = send("GET", "/api/v1/asmodeus/telemetry/mttd", Some("auditor")).await;
    assert_eq!(view, StatusCode::OK);
    let (abort, _) = send("POST", "/api/v1/asmodeus/scenarios/abort", Some("auditor")).await;
    assert_eq!(abort, StatusCode::FORBIDDEN);
}

// --- live dispatch: control-plane -> mock runner over gRPC ---------------

use asmodeus_proto::{
    EventKind as PbEvent, ExecuteRequest as PbExecute, HeartbeatReply as PbHbReply,
    HeartbeatRequest as PbHbReq, RunnerControl, RunnerControlServer,
    RunnerEvent as PbRunnerEvent,
};
use std::pin::Pin;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::Stream;

#[derive(Default)]
struct MockRunner;

#[tonic::async_trait]
impl RunnerControl for MockRunner {
    type ExecuteStream =
        Pin<Box<dyn Stream<Item = Result<PbRunnerEvent, tonic::Status>> + Send + 'static>>;

    async fn execute(
        &self,
        _req: tonic::Request<PbExecute>,
    ) -> Result<tonic::Response<Self::ExecuteStream>, tonic::Status> {
        let mut evs = Vec::new();
        for s in [
            "Validated",
            "Armed",
            "Injecting",
            "Detected",
            "Contained",
            "Cleanup",
        ] {
            evs.push(PbRunnerEvent {
                kind: PbEvent::StateChanged as i32,
                state: s.into(),
                ..Default::default()
            });
        }
        evs.push(PbRunnerEvent {
            kind: PbEvent::Completed as i32,
            state: "Completed".into(),
            files_created: 20,
            bytes_written: 40960,
            inject_ms: 7,
            detail: String::new(),
        });
        Ok(tonic::Response::new(Box::pin(tokio_stream::iter(
            evs.into_iter().map(Ok),
        ))))
    }

    async fn heartbeat(
        &self,
        _req: tonic::Request<PbHbReq>,
    ) -> Result<tonic::Response<PbHbReply>, tonic::Status> {
        Ok(tonic::Response::new(PbHbReply {
            state: "Idle".into(),
            healthy: true,
            cpu_usage_pct: 2,
            active_exercise_id: String::new(),
            version: "0.1.0".into(),
        }))
    }
}

async fn start_mock_runner() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(RunnerControlServer::new(MockRunner))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    format!("http://{addr}")
}

/// A runner whose Execute stream ends after Injecting, with no Completed
/// and no Rejected event — a partial/failed run.
#[derive(Default)]
struct PartialRunner;

#[tonic::async_trait]
impl RunnerControl for PartialRunner {
    type ExecuteStream =
        Pin<Box<dyn Stream<Item = Result<PbRunnerEvent, tonic::Status>> + Send + 'static>>;

    async fn execute(
        &self,
        _req: tonic::Request<PbExecute>,
    ) -> Result<tonic::Response<Self::ExecuteStream>, tonic::Status> {
        let evs = ["Validated", "Armed", "Injecting"].map(|s| PbRunnerEvent {
            kind: PbEvent::StateChanged as i32,
            state: s.into(),
            ..Default::default()
        });
        Ok(tonic::Response::new(Box::pin(tokio_stream::iter(
            evs.into_iter().map(Ok),
        ))))
    }

    async fn heartbeat(
        &self,
        _req: tonic::Request<PbHbReq>,
    ) -> Result<tonic::Response<PbHbReply>, tonic::Status> {
        Ok(tonic::Response::new(PbHbReply {
            state: "Injecting".into(),
            healthy: false,
            cpu_usage_pct: 88,
            active_exercise_id: "PARTIAL".into(),
            version: "0.1.0".into(),
        }))
    }
}

async fn start_partial_runner() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(RunnerControlServer::new(PartialRunner))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    format!("http://{addr}")
}

static DISPATCH_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const ALL_CLIENT_TLS_VARS: &[&str] = &[
    "ASMODEUS_CLIENT_TLS_CERT",
    "ASMODEUS_CLIENT_TLS_KEY",
    "ASMODEUS_CLIENT_TLS_CA",
    "ASMODEUS_CLIENT_TLS_DOMAIN",
    "ASMODEUS_TLS_CERT",
    "ASMODEUS_TLS_KEY",
    "ASMODEUS_TLS_CA",
    "ASMODEUS_TLS_DOMAIN",
];

#[tokio::test]
async fn dispatches_to_live_runner() {
    let _lock = DISPATCH_TEST_LOCK.lock().await;
    let _guard = EnvGuard::clear(ALL_CLIENT_TLS_VARS);

    let url = start_mock_runner().await;
    let app = router(AppState::with_runner(Catalog::seeded(), Some(url.clone())));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/scenarios/RANSOMWARE_CANARY_SPIKE/run")
        .header("x-apex-role", "red_team")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(body["status"], "COMPLETED");
    assert_eq!(body["execution"]["mode"], "dispatched");
    assert_eq!(body["execution"]["runner_final_state"], "Completed");
    assert_eq!(body["execution"]["files_created"], 20);
    assert_eq!(body["execution"]["runner_endpoint"], url);
}

#[tokio::test]
async fn partial_runner_is_not_reported_completed() {
    let _lock = DISPATCH_TEST_LOCK.lock().await;
    let _guard = EnvGuard::clear(ALL_CLIENT_TLS_VARS);

    let url = start_partial_runner().await;
    let app = router(AppState::with_runner(Catalog::seeded(), Some(url)));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/scenarios/RANSOMWARE_CANARY_SPIKE/run")
        .header("x-apex-role", "red_team")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // A run that never completed must not be a 200 success.
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

async fn start_mock_mtls_runner(tls: tonic::transport::ServerTlsConfig) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(RunnerControlServer::new(MockRunner))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    format!("https://{addr}")
}

struct EnvGuard {
    vars: Vec<(&'static str, Option<String>)>,
}

impl EnvGuard {
    fn set(vars: &[(&'static str, &str)]) -> Self {
        let mut saved = Vec::new();
        for &(k, v) in vars {
            saved.push((k, std::env::var(k).ok()));
            std::env::set_var(k, v);
        }
        EnvGuard { vars: saved }
    }

    fn clear(keys: &[&'static str]) -> Self {
        let mut saved = Vec::new();
        for &k in keys {
            saved.push((k, std::env::var(k).ok()));
            std::env::remove_var(k);
        }
        EnvGuard { vars: saved }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (k, v) in &self.vars {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}

#[tokio::test]
async fn dispatches_to_live_runner_over_mtls() {
    let _lock = DISPATCH_TEST_LOCK.lock().await;
    let mtls = asmodeus_testkit::TestMtls::generate();
    let temp_dir = std::env::temp_dir().join("asmodeus-cp-mtls-test");
    let paths = mtls.write_to_dir(&temp_dir).unwrap();

    let _guard = EnvGuard::set(&[
        (
            "ASMODEUS_CLIENT_TLS_CERT",
            paths.client_cert.to_str().unwrap(),
        ),
        (
            "ASMODEUS_CLIENT_TLS_KEY",
            paths.client_key.to_str().unwrap(),
        ),
        ("ASMODEUS_CLIENT_TLS_CA", paths.ca_cert.to_str().unwrap()),
        ("ASMODEUS_CLIENT_TLS_DOMAIN", "asmodeus-runner"),
    ]);

    let url = start_mock_mtls_runner(mtls.server_tls_config()).await;
    let app = router(AppState::with_runner(Catalog::seeded(), Some(url.clone())));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/scenarios/RANSOMWARE_CANARY_SPIKE/run")
        .header("x-apex-role", "red_team")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(body["status"], "COMPLETED");
    assert_eq!(body["execution"]["mode"], "dispatched");
    assert_eq!(body["execution"]["runner_final_state"], "Completed");
    assert_eq!(body["execution"]["files_created"], 20);
    assert_eq!(body["execution"]["runner_endpoint"], url);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn dispatch_over_mtls_rejects_untrusted_client() {
    let _lock = DISPATCH_TEST_LOCK.lock().await;
    let mtls = asmodeus_testkit::TestMtls::generate();
    let temp_dir = std::env::temp_dir().join("asmodeus-cp-mtls-rogue");
    let paths = mtls.write_to_dir(&temp_dir).unwrap();

    // Control plane uses rogue client cert (signed by untrusted CA)
    let _guard = EnvGuard::set(&[
        (
            "ASMODEUS_CLIENT_TLS_CERT",
            paths.rogue_client_cert.to_str().unwrap(),
        ),
        (
            "ASMODEUS_CLIENT_TLS_KEY",
            paths.rogue_client_key.to_str().unwrap(),
        ),
        ("ASMODEUS_CLIENT_TLS_CA", paths.ca_cert.to_str().unwrap()),
        ("ASMODEUS_CLIENT_TLS_DOMAIN", "asmodeus-runner"),
    ]);

    let url = start_mock_mtls_runner(mtls.server_tls_config()).await;
    let app = router(AppState::with_runner(Catalog::seeded(), Some(url)));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/scenarios/RANSOMWARE_CANARY_SPIKE/run")
        .header("x-apex-role", "red_team")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Handshake fails, run must not succeed
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn list_scenarios_returns_all_entries_with_mitre_metadata() {
    let app = router(AppState::new(Catalog::seeded()));
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/asmodeus/scenarios")
        .header("x-apex-role", "auditor")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    let list = body.as_array().expect("array of scenarios");
    assert_eq!(list.len(), 11);

    // Verify MITRE technique is present on Red Team scenarios
    let ransomware = list
        .iter()
        .find(|s| s["id"] == "RANSOMWARE_CANARY_SPIKE")
        .unwrap();
    assert_eq!(ransomware["mitre_technique"], "T1486");
    assert_eq!(ransomware["mitre_tactic"], "Impact");

    let beacon = list
        .iter()
        .find(|s| s["id"] == "C2_BEACONING_SIMULATION")
        .unwrap();
    assert_eq!(beacon["mitre_technique"], "T1071");
    assert_eq!(beacon["mitre_tactic"], "Command and Control");
}

#[tokio::test]
async fn get_scenario_returns_single_scenario_details() {
    let app = router(AppState::new(Catalog::seeded()));
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/asmodeus/scenarios/CREDENTIAL_ACCESS_CANARY")
        .header("x-apex-role", "devsecops")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["id"], "CREDENTIAL_ACCESS_CANARY");
    assert_eq!(body["mitre_technique"], "T1003");
    assert_eq!(body["mitre_tactic"], "Credential Access");
    assert_eq!(body["mitre_technique_name"], "OS Credential Dumping");
    assert_eq!(body["category"], "red_team");
}

#[tokio::test]
async fn mitre_matrix_returns_coverage_report() {
    let app = router(AppState::new(Catalog::seeded()));
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/asmodeus/scenarios/mitre")
        .header("x-apex-role", "ciso")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["framework"], "MITRE ATT&CK Enterprise Matrix");
    assert_eq!(body["total_scenarios"], 11);
    let covered_count = body["covered_techniques_count"].as_u64().unwrap();
    assert!(
        covered_count >= 7,
        "expected >= 7 covered techniques, got {covered_count}"
    );
    let tactics = body["tactics"].as_array().unwrap();
    assert!(
        tactics.len() >= 6,
        "expected >= 6 covered tactics, got {}",
        tactics.len()
    );
}

#[tokio::test]
async fn run_scenario_includes_mitre_and_scenario_name() {
    let app = router(AppState::new(Catalog::seeded()));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/scenarios/C2_BEACONING_SIMULATION/run")
        .header("x-apex-role", "red_team")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["status"], "COMPLETED");
    assert_eq!(body["scenario_id"], "C2_BEACONING_SIMULATION");
    assert_eq!(body["mitre_technique"], "T1071");
    assert_eq!(body["mitre_tactic"], "Command and Control");
    assert_eq!(
        body["scenario_name"],
        "C2 Beaconing & Dynamic Resolution Simulation"
    );
}

#[tokio::test]
async fn runners_lifecycle_and_rbac() {
    let app = router(AppState::new(Catalog::seeded()));

    // 1. CISO cannot register runner (403)
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/runners")
        .header("x-apex-role", "ciso")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "id": "probe-ciso",
                "endpoint": "http://127.0.0.1:8850"
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 2. Admin registers runner (201)
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/runners")
        .header("x-apex-role", "admin")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "id": "probe-k8s",
                "name": "K8s Worker Probe",
                "endpoint": "http://127.0.0.1:8850",
                "tags": ["k8s_workload", "prod"]
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["id"], "probe-k8s");
    assert_eq!(body["status"], "active");

    // 3. Auditor can list runners
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/asmodeus/runners")
        .header("x-apex-role", "auditor")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let list: Vec<Value> = serde_json::from_slice(&bytes).unwrap();
    assert!(list.iter().any(|r| r["id"] == "probe-k8s"));

    // 4. DevSecOps deregisters runner
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/asmodeus/runners/probe-k8s")
        .header("x-apex-role", "devsecops")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn dispatch_with_target_override_and_ping() {
    let _lock = DISPATCH_TEST_LOCK.lock().await;
    let _guard = EnvGuard::clear(ALL_CLIENT_TLS_VARS);

    let runner_url = start_mock_runner().await;
    let reg = RunnerRegistry::new();
    reg.register(RunnerRecord::new(
        "k8s-probe-01",
        "Targeted K8s Probe",
        &runner_url,
        vec!["k8s_workload".into()],
    ));

    let app = router(AppState::with_registry(Catalog::seeded(), reg));

    // 1. Ping runner over gRPC
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/asmodeus/runners/k8s-probe-01/ping")
        .header("x-apex-role", "auditor")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["healthy"], true);
    assert_eq!(body["state"], "Idle");

    // 2. Run with target_override matching tag
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/scenarios/RANSOMWARE_CANARY_SPIKE/run")
        .header("x-apex-role", "red_team")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "target_override": "k8s_workload"
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["status"], "COMPLETED");
    assert_eq!(body["execution"]["mode"], "dispatched");
    assert_eq!(body["execution"]["runner_id"], "k8s-probe-01");

    // 3. Run with unknown target returns 404
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/scenarios/RANSOMWARE_CANARY_SPIKE/run")
        .header("x-apex-role", "red_team")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "target_override": "unknown-node"
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn runs_history_and_crypto_verification() {
    let app = router(AppState::new(Catalog::seeded()));

    // 1. Initially no runs
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/asmodeus/runs")
        .header("x-apex-role", "auditor")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["total"], 0);

    // 2. Execute a scenario
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/scenarios/CREDENTIAL_ACCESS_CANARY/run")
        .header("x-apex-role", "red_team")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let run_body: Value = serde_json::from_slice(&bytes).unwrap();
    let run_id = run_body["run_id"].as_str().unwrap();
    assert!(!run_body["signature_hex"].as_str().unwrap().is_empty());

    // 3. Auditor fetches run list
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/asmodeus/runs")
        .header("x-apex-role", "auditor")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let list_body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(list_body["total"], 1);
    assert_eq!(list_body["runs"][0]["run_id"], run_id);

    // 4. Auditor fetches single run details
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/asmodeus/runs/{run_id}"))
        .header("x-apex-role", "auditor")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let single_body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(single_body["run_id"], run_id);
    assert_eq!(single_body["scenario_id"], "CREDENTIAL_ACCESS_CANARY");

    // 5. Verify cryptographic signature of the audit record
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/asmodeus/runs/{run_id}/verify"))
        .header("x-apex-role", "auditor")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let verify_body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(verify_body["run_id"], run_id);
    assert_eq!(verify_body["verified"], true);
}

#[tokio::test]
async fn campaigns_execution_and_rbac() {
    let app = router(AppState::new(Catalog::seeded()));

    // 1. List campaigns
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/asmodeus/campaigns")
        .header("x-apex-role", "auditor")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    let campaigns = body["campaigns"].as_array().unwrap();
    assert!(campaigns.len() >= 3);

    // 2. CISO and Auditor receive 403 on run campaign (SoD)
    for forbidden_role in &["ciso", "auditor", "secops"] {
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/asmodeus/campaigns/CAMP-RANSOMWARE-CHAIN/run")
            .header("x-apex-role", *forbidden_role)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // 3. Red Team launches ransomware campaign
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/campaigns/CAMP-RANSOMWARE-CHAIN/run")
        .header("x-apex-role", "red_team")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let res: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(res["campaign_id"], "CAMP-RANSOMWARE-CHAIN");
    assert_eq!(res["total_steps"], 4);
    assert_eq!(res["successful_steps"], 4);
    assert_eq!(res["step_results"].as_array().unwrap().len(), 4);
    assert!(res["resilience_score"].as_u64().unwrap() > 0);

    // 4. All 4 steps are recorded in audit trail
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/asmodeus/runs")
        .header("x-apex-role", "auditor")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["total"], 4);
}

#[tokio::test]
async fn explicit_target_never_falls_back_to_static_endpoint() {
    // A static default runner endpoint is configured, but the requested
    // target matches no registered runner. The request must be rejected
    // with 404 rather than silently dispatched to the default runner.
    let app = router(AppState::with_runner(
        Catalog::seeded(),
        Some("http://127.0.0.1:59999".to_string()),
    ));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/scenarios/RANSOMWARE_CANARY_SPIKE/run")
        .header("x-apex-role", "red_team")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "target_override": "no_such_tag" }).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // 404 (target not found) — crucially NOT a dispatch attempt to the
    // static endpoint (which would surface as 502 BadGateway).
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn validate_manifest_endpoint_checks_inv0() {
    let app = router(AppState::new(Catalog::seeded()));

    // 1. Valid YAML manifest
    let valid_yaml = r#"
apiVersion: asmodeus.io/v1alpha1
kind: AttackScenario
metadata:
  id: "CUSTOM-CANARY"
  name: "Custom Canary Probe"
  category: "red_team"
  mitre_technique: "T1486"
  severity: "high"
spec:
  target_scope:
type: "k8s_workload"
target_path: "/var/tmp/asmodeus-canary/canary.docx"
  safety:
max_duration_sec: 45
cpu_limit_percent: 20
canary_directory_only: "/var/tmp/asmodeus-canary"
  action:
nature: "synthetic"
type: "synthetic_canary_encrypt"
parameters:
  file_count: 20
  expected_outcome:
detector: "ferrum_ebpf"
"#;

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/scenarios/validate")
        .header("x-apex-role", "auditor")
        .body(Body::from(valid_yaml))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["valid"], true);
    assert_eq!(body["inv_0_compliant"], true);

    // 2. Operational action violating INV-0 -> 422
    let invalid_yaml = valid_yaml.replace("nature: \"synthetic\"", "nature: \"operational\"");
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/scenarios/validate")
        .header("x-apex-role", "red_team")
        .body(Body::from(invalid_yaml))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn closed_loop_feedback_updates_and_re_signs_audit_record() {
    let app = router(AppState::new(Catalog::seeded()));

    // 1. Run scenario as Red Team
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/scenarios/RANSOMWARE_CANARY_SPIKE/run")
        .header("x-apex-role", "red_team")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let run: Value = serde_json::from_slice(&bytes).unwrap();
    let run_id = run["run_id"].as_str().unwrap();

    // 2. Auditor / CISO is forbidden from submitting feedback (403)
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/asmodeus/runs/{run_id}/feedback"))
        .header("x-apex-role", "ciso")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "detected": true }).to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 3. SecOps (Blue Team) submits real detection and containment feedback
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/asmodeus/runs/{run_id}/feedback"))
        .header("x-apex-role", "secops")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "detected": true,
                "mttd_ms": 115,
                "detection_source": "ferrum_ebpf_kernel_probe",
                "contained": true,
                "mttr_ms": 210,
                "containment_action": "SIGKILL via Ferrum Policy"
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let feedback_resp: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(feedback_resp["status"], "UPDATED");
    assert_eq!(feedback_resp["run_status"], "CONTAINED");
    assert_eq!(feedback_resp["measurements"]["mttd_ms"], 115);
    assert_eq!(feedback_resp["measurements"]["mttr_ms"], 210);

    // 4. Verify updated record cryptographic signature
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/asmodeus/runs/{run_id}/verify"))
        .header("x-apex-role", "auditor")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let verify_res: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(verify_res["verified"], true);

    // 5. Check run report in JSON and Markdown formats
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/asmodeus/runs/{run_id}/report"))
        .header("x-apex-role", "auditor")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let req = Request::builder()
        .method("GET")
        .uri(format!(
            "/api/v1/asmodeus/runs/{run_id}/report?format=markdown"
        ))
        .header("x-apex-role", "auditor")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let md_report = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(md_report.contains("Отчёт по Прогону Учений"));
    assert!(md_report.contains("115 мс"));

    // 6. Check overall resilience report in JSON and Markdown
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/asmodeus/reports/resilience?format=markdown")
        .header("x-apex-role", "ciso")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let md_resilience = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(md_resilience.contains("ASMODEUS — Отчёт об Устойчивости Инфраструктуры"));
    assert!(md_resilience.contains("NIST CSF 2.0"));
}

#[tokio::test]
async fn openapi_endpoint_returns_valid_spec() {
    let app = router(AppState::new(Catalog::seeded()));
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/asmodeus/openapi.json")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let spec: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(spec["openapi"], "3.1.0");
    assert_eq!(spec["info"]["title"], "Asmodeus Control Plane API");
    assert!(spec["paths"]["/api/v1/asmodeus/campaigns"].is_object());
}

#[tokio::test]
async fn audit_export_json_and_jsonl() {
    let app = router(AppState::new(Catalog::seeded()));

    // 1. Run a scenario to generate audit record
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/scenarios/RANSOMWARE_CANARY_SPIKE/run")
        .header("x-apex-role", "red_team")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. Export JSONL as auditor
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/asmodeus/audit/export?format=jsonl")
        .header("x-apex-role", "auditor")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let jsonl = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(jsonl.lines().count() >= 1);
    assert!(jsonl.contains("RANSOMWARE_CANARY_SPIKE"));

    // 3. Export JSON as CISO
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/asmodeus/audit/export?format=json")
        .header("x-apex-role", "ciso")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let json_arr: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(!json_arr.as_array().unwrap().is_empty());

    // 4. Missing role -> 401
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/asmodeus/audit/export")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn campaigns_dynamic_crud_and_rbac() {
    let app = router(AppState::new(Catalog::seeded()));

    let custom_campaign = json!({
        "id": "CAMP-DYNAMIC-001",
        "name": "Dynamic APT Playbook",
        "description": "Dynamic testing campaign",
        "steps": [
            { "order": 1, "scenario_id": "CREDENTIAL_ACCESS_CANARY" }
        ]
    });

    // 1. Auditor cannot register campaign -> 403
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/campaigns")
        .header("x-apex-role", "auditor")
        .header("content-type", "application/json")
        .body(Body::from(custom_campaign.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 2. RedTeam registers campaign -> 201 Created
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/campaigns")
        .header("x-apex-role", "red_team")
        .header("content-type", "application/json")
        .body(Body::from(custom_campaign.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 3. List campaigns shows the new campaign
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/asmodeus/campaigns")
        .header("x-apex-role", "auditor")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let list: Value = serde_json::from_slice(&bytes).unwrap();
    let camps = list["campaigns"].as_array().unwrap();
    assert!(camps.iter().any(|c| c["id"] == "CAMP-DYNAMIC-001"));

    // 4. CISO cannot delete campaign -> 403
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/asmodeus/campaigns/CAMP-DYNAMIC-001")
        .header("x-apex-role", "ciso")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 5. Admin deletes campaign -> 200 OK
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/asmodeus/campaigns/CAMP-DYNAMIC-001")
        .header("x-apex-role", "admin")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 6. Delete again -> 404
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/asmodeus/campaigns/CAMP-DYNAMIC-001")
        .header("x-apex-role", "admin")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn audit_export_clickhouse_formats() {
    let app = router(AppState::new(Catalog::seeded()));

    // Run scenario to generate audit record
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/scenarios/RANSOMWARE_CANARY_SPIKE/run")
        .header("x-apex-role", "red_team")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Export ClickHouse SQL
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/asmodeus/audit/export?format=clickhouse_sql")
        .header("x-apex-role", "auditor")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/sql; charset=utf-8"
    );
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let sql = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(sql.contains("INSERT INTO apex.asmodeus_runs"));
    assert!(sql.contains("RANSOMWARE_CANARY_SPIKE"));

    // Export ClickHouse NDJSON
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/asmodeus/audit/export?format=clickhouse_ndjson")
        .header("x-apex-role", "auditor")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/x-ndjson; charset=utf-8"
    );
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let ndjson = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(ndjson.contains("RANSOMWARE_CANARY_SPIKE"));
}

#[tokio::test]
async fn compliance_report_json_and_markdown() {
    let app = router(AppState::new(Catalog::seeded()));

    // Run scenario to seed some audit data
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/scenarios/RANSOMWARE_CANARY_SPIKE/run")
        .header("x-apex-role", "red_team")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 1. JSON report
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/asmodeus/reports/compliance")
        .header("x-apex-role", "auditor")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let report: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(report["total_controls"].as_u64().unwrap() >= 6);
    assert!(report["controls"].as_array().unwrap().len() >= 6);

    // 2. Markdown report
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/asmodeus/reports/compliance?format=markdown")
        .header("x-apex-role", "ciso")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/markdown; charset=utf-8"
    );
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let md = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(md.contains("NIST CSF 2.0 / PCI-DSS v4.0"));
    assert!(md.contains("DE.CM-01"));

    // 3. Missing role -> 401
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/asmodeus/reports/compliance")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn schedules_crud_and_rbac() {
    let app = router(AppState::new(Catalog::seeded()));

    // 1. List seeded schedules as auditor
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/asmodeus/schedules")
        .header("x-apex-role", "auditor")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let list: Value = serde_json::from_slice(&bytes).unwrap();
    let scheds = list["schedules"].as_array().unwrap();
    assert!(scheds.iter().any(|s| s["id"] == "SCHED-BASE-RANSOMWARE"));

    // 2. SecOps forbidden from creating schedule -> 403
    let new_sched = json!({
        "id": "SCHED-TEST-001",
        "name": "Test Schedule",
        "scenario_id": "RANSOMWARE_CANARY_SPIKE",
        "interval_sec": 60
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/schedules")
        .header("x-apex-role", "secops")
        .header("content-type", "application/json")
        .body(Body::from(new_sched.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 3. RedTeam creates schedule -> 201 Created
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/asmodeus/schedules")
        .header("x-apex-role", "red_team")
        .header("content-type", "application/json")
        .body(Body::from(new_sched.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 4. Auditor deletes schedule -> 403
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/asmodeus/schedules/SCHED-TEST-001")
        .header("x-apex-role", "auditor")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 5. Admin deletes schedule -> 200 OK
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/asmodeus/schedules/SCHED-TEST-001")
        .header("x-apex-role", "admin")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 6. Delete again -> 404
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/asmodeus/schedules/SCHED-TEST-001")
        .header("x-apex-role", "admin")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn schedule_detail_toggle_and_alerts() {
    // Detail of a seeded schedule includes the (initially empty) history.
    let (status, body) = send(
        "GET",
        "/api/v1/asmodeus/schedules/SCHED-BASE-RANSOMWARE",
        Some("auditor"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["schedule"]["id"], "SCHED-BASE-RANSOMWARE");
    assert!(body["schedule"]["run_history"].is_array());

    // Unknown schedule -> 404.
    let (status, _) = send(
        "GET",
        "/api/v1/asmodeus/schedules/SCHED-NOPE",
        Some("auditor"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Alerts endpoint is readable by read-only roles and starts empty.
    let (status, body) = send("GET", "/api/v1/asmodeus/schedules/alerts", Some("ciso")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], 0);
    assert!(body["alerts"].as_array().unwrap().is_empty());

    // Toggle: read-only role is forbidden; admin succeeds.
    let app = router(AppState::new(Catalog::seeded()));
    let forbid = Request::builder()
        .method("PATCH")
        .uri("/api/v1/asmodeus/schedules/SCHED-BASE-RANSOMWARE")
        .header("x-apex-role", "auditor")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "enabled": false }).to_string()))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(forbid).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    let toggle = Request::builder()
        .method("PATCH")
        .uri("/api/v1/asmodeus/schedules/SCHED-BASE-RANSOMWARE")
        .header("x-apex-role", "admin")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "enabled": false }).to_string()))
        .unwrap();
    let resp = app.clone().oneshot(toggle).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["enabled"], false);

    // Toggling an unknown schedule -> 404.
    let missing = Request::builder()
        .method("PATCH")
        .uri("/api/v1/asmodeus/schedules/SCHED-NOPE")
        .header("x-apex-role", "admin")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "enabled": true }).to_string()))
        .unwrap();
    assert_eq!(
        app.oneshot(missing).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
}
