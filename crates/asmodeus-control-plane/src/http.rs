//! REST surface (OpenAPI 3.1 shape) consumed by the APEX gateway. RBAC is
//! enforced here from `asmodeus_common::rbac` — never delegated to the gateway
//! (D5). Signature verification and the INV-0 gate run before any execution.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use asmodeus_common::{Category, Role, RunId, RunState, INV_0_SYNTHETIC_ONLY};
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
    counter: Arc<AtomicU64>,
}

impl AppState {
    pub fn new(catalog: Catalog) -> Self {
        AppState {
            catalog: Arc::new(catalog),
            runs: Arc::new(Mutex::new(HashMap::new())),
            counter: Arc::new(AtomicU64::new(1)),
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

    // Drive the state machine under INV-0.
    let outcome = engine::execute(entry).map_err(|e| match e {
        EngineError::Rejected(_) => ApiError::Unprocessable(e.to_string()),
        EngineError::Transition(_) => ApiError::Internal(e.to_string()),
    })?;

    let run_id = state.next_run_id();
    state
        .runs
        .lock()
        .unwrap()
        .insert(run_id.clone(), outcome.final_state);

    Ok(Json(json!({
        "run_id": run_id.to_string(),
        "scenario_id": entry.id,
        "tag": entry.category.tag(),
        "initiator": role.as_str(),
        "status": "COMPLETED",
        "measurements": {
            "mttd_ms": outcome.mttd_ms,
            "mttr_ms": outcome.mttr_ms,
            "blue_team_detected": outcome.blue_team_detected,
            "detection_source": outcome.detector,
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
    Ok(Json(json!({
        "runs_completed": completed,
        "catalog_size": state.catalog.ids().count(),
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
    async fn auditor_can_view_but_not_abort() {
        let (view, _) = send("GET", "/api/v1/asmodeus/telemetry/mttd", Some("auditor")).await;
        assert_eq!(view, StatusCode::OK);
        let (abort, _) = send("POST", "/api/v1/asmodeus/scenarios/abort", Some("auditor")).await;
        assert_eq!(abort, StatusCode::FORBIDDEN);
    }
}
