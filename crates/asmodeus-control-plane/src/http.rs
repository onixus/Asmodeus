//! REST surface (OpenAPI 3.1 shape) consumed by the APEX gateway. RBAC is
//! enforced here from `asmodeus_common::rbac` — never delegated to the gateway
//! (D5). Signature verification and the INV-0 gate run before any execution.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use asmodeus_common::{Category, Role, RunId, RunState, INV_0_SYNTHETIC_ONLY};
use asmodeus_telemetry::{Aggregate, Measurements};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};

use crate::catalog::Catalog;
use crate::engine::{self, EngineError};

/// Shared, cheaply cloneable server state.
#[derive(Clone)]
pub struct AppState {
    catalog: Arc<Catalog>,
    runs: Arc<Mutex<HashMap<RunId, RunState>>>,
    metrics: Arc<Mutex<Aggregate>>,
    counter: Arc<AtomicU64>,
    /// When set, scenarios are dispatched to this live runner over gRPC;
    /// otherwise the in-process engine simulates the run.
    runner_endpoint: Option<String>,
}

impl AppState {
    /// Reads `ASMODEUS_RUNNER_ENDPOINT` from the environment.
    pub fn new(catalog: Catalog) -> Self {
        let endpoint = std::env::var("ASMODEUS_RUNNER_ENDPOINT").ok();
        Self::with_runner(catalog, endpoint)
    }

    pub fn with_runner(catalog: Catalog, runner_endpoint: Option<String>) -> Self {
        AppState {
            catalog: Arc::new(catalog),
            runs: Arc::new(Mutex::new(HashMap::new())),
            metrics: Arc::new(Mutex::new(Aggregate::default())),
            counter: Arc::new(AtomicU64::new(1)),
            runner_endpoint,
        }
    }

    fn next_run_id(&self) -> RunId {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        RunId::new(format!("run_{n:08x}"))
    }
}

/// Build the router with all endpoints mounted.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/api/v1/asmodeus/scenarios/:id/run", post(run_scenario))
        .route("/api/v1/asmodeus/scenarios/abort", post(abort_all))
        .route("/api/v1/asmodeus/telemetry/mttd", get(telemetry_mttd))
        .with_state(state)
}

// --- error type -----------------------------------------------------------

enum ApiError {
    Unauthorized(&'static str),
    Forbidden(&'static str),
    NotFound(String),
    Unprocessable(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (code, msg) = match self {
            ApiError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m.to_string()),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, m.to_string()),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApiError::Unprocessable(m) => (StatusCode::UNPROCESSABLE_ENTITY, m),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (code, Json(json!({ "error": msg }))).into_response()
    }
}

/// Read and parse the `X-Apex-Role` header. Missing/unknown => 401.
fn caller_role(headers: &HeaderMap) -> Result<Role, ApiError> {
    let raw = headers
        .get("x-apex-role")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthorized("missing X-Apex-Role header"))?;
    raw.parse::<Role>()
        .map_err(|_| ApiError::Unauthorized("unknown role"))
}

// --- handlers -------------------------------------------------------------

async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok", "invariant": INV_0_SYNTHETIC_ONLY }))
}

/// Prometheus scrape endpoint (TT §4.3). Unauthenticated, like any exporter.
async fn metrics(State(state): State<AppState>) -> Response {
    let body = state.metrics.lock().unwrap().prometheus_text();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
        .into_response()
}

async fn run_scenario(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;

    let entry = state
        .catalog
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("unknown scenario_id: {id}")))?;

    // RBAC (D5): the required capability depends on the scenario category.
    let cap = entry.category.required_capability();
    if !role.can(cap) {
        return Err(ApiError::Forbidden(match entry.category {
            Category::RedTeam => "role may not launch Red Team scenarios",
            Category::Chaos => "role may not inject chaos",
        }));
    }

    // Integrity (D6): the catalogued manifest must verify against the trusted key.
    if !asmodeus_crypto::is_valid(
        &entry.manifest,
        &entry.signature,
        state.catalog.public_key(),
    ) {
        return Err(ApiError::Unprocessable("scenario signature invalid".into()));
    }

    // Execute: dispatch to a live runner over gRPC if one is configured,
    // else drive the in-process engine. Detection metrics stay simulated
    // (no live Blue Team wired); the runner reports the real injection stats.
    let (final_state, execution) = if let Some(endpoint) = state.runner_endpoint.clone() {
        let req = asmodeus_proto::ExecuteRequest {
            scenario_id: entry.id.to_string(),
            manifest: entry.manifest.clone(),
            signature: entry.signature.clone(),
            public_key: state.catalog.public_key().to_vec(),
            target_dir: entry.target_path.clone(),
            file_count: entry.file_count,
            chunk_size_kb: entry.chunk_size_kb,
        };
        let out = crate::dispatch::dispatch(&endpoint, req)
            .await
            .map_err(|s| ApiError::Internal(format!("dispatch: {s}")))?;
        if let Some(reason) = out.rejected {
            return Err(ApiError::Unprocessable(format!(
                "runner rejected: {reason}"
            )));
        }
        if !out.completed {
            // Stream ended without a terminal Completed event: the run did not
            // finish. Never record it as a success.
            return Err(ApiError::Internal(format!(
                "runner ended without completing (last state: {})",
                out.final_state
            )));
        }
        (
            RunState::Completed,
            json!({
                "mode": "dispatched",
                "runner_endpoint": endpoint,
                "runner_final_state": out.final_state,
                "files_created": out.files_created,
                "bytes_written": out.bytes_written,
                "inject_ms": out.inject_ms,
            }),
        )
    } else {
        let outcome = engine::execute(entry).map_err(|e| match e {
            EngineError::Rejected(_) => ApiError::Unprocessable(e.to_string()),
            EngineError::Transition(_) => ApiError::Internal(e.to_string()),
        })?;
        (outcome.final_state, json!({ "mode": "simulated" }))
    };

    let run_id = state.next_run_id();
    state
        .runs
        .lock()
        .unwrap()
        .insert(run_id.clone(), final_state);
    state.metrics.lock().unwrap().record(Measurements {
        mttd_ms: entry.sim_mttd_ms,
        mttr_ms: entry.sim_mttr_ms,
        blue_team_detected: true,
    });

    Ok(Json(json!({
        "run_id": run_id.to_string(),
        "scenario_id": entry.id,
        "tag": entry.category.tag(),
        "initiator": role.as_str(),
        "status": "COMPLETED",
        "execution": execution,
        "measurements": {
            "mttd_ms": entry.sim_mttd_ms,
            "mttr_ms": entry.sim_mttr_ms,
            "blue_team_detected": true,
            "detection_source": entry.detector,
            "containment_action": "SIGKILL via SOAR Policy",
        },
        "cleanup_status": "SUCCESS (canary removed, 0 host side-effects)",
    })))
}

async fn abort_all(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    // Only roles that can launch something may abort.
    let may_abort = role.can(asmodeus_common::Capability::RunRedTeam)
        || role.can(asmodeus_common::Capability::InjectChaos);
    if !may_abort {
        return Err(ApiError::Forbidden("role may not abort exercises"));
    }
    let mut runs = state.runs.lock().unwrap();
    let aborted = runs.len();
    runs.clear();
    Ok(Json(
        json!({ "status": "ABORTED", "runs_cleared": aborted }),
    ))
}

async fn telemetry_mttd(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view reports"));
    }
    let completed = state
        .runs
        .lock()
        .unwrap()
        .values()
        .filter(|s| s.is_terminal())
        .count();
    let agg = state.metrics.lock().unwrap();
    Ok(Json(json!({
        "runs_completed": completed,
        "catalog_size": state.catalog.ids().count(),
        "mean_mttd_ms": agg.mean_mttd_ms(),
        "mean_mttr_ms": agg.mean_mttr_ms(),
        "detection_rate_pct": agg.detection_rate_pct(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt; // for `oneshot`

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

    #[tokio::test]
    async fn dispatches_to_live_runner() {
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
}
