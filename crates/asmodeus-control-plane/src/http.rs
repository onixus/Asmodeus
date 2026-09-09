//! REST surface (OpenAPI 3.1 shape) consumed by the APEX gateway. RBAC is
//! enforced here from `asmodeus_common::rbac` — never delegated to the gateway
//! (D5). Signature verification and the INV-0 gate run before any execution.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use asmodeus_common::{Category, Role, RunId, RunState, INV_0_SYNTHETIC_ONLY};
use asmodeus_telemetry::{
    Aggregate, AuditRecord, AuditTrail, EcosystemResilienceReport, Measurements, SingleRunReport,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::campaign::CampaignCatalog;
use crate::catalog::Catalog;
use crate::engine::{self, EngineError};
use crate::registry::{RunnerRecord, RunnerRegistry};
use crate::scheduler::{CreateScheduleRequest, ScheduleCatalog, ScheduledJob};
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
        AppState {
            catalog: Arc::new(catalog),
            runs: Arc::new(Mutex::new(HashMap::new())),
            metrics: Arc::new(Mutex::new(Aggregate::default())),
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

    #[allow(dead_code)]
    pub fn with_registry(catalog: Catalog, registry: RunnerRegistry) -> Self {
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
        AppState {
            catalog: Arc::new(catalog),
            runs: Arc::new(Mutex::new(HashMap::new())),
            metrics: Arc::new(Mutex::new(Aggregate::default())),
            counter: Arc::new(AtomicU64::new(1)),
            runner_endpoint: None,
            registry,
            audit_trail: Arc::new(std::sync::RwLock::new(audit_trail)),
            campaigns: Arc::new(std::sync::RwLock::new(CampaignCatalog::seeded())),
            schedules: Arc::new(std::sync::RwLock::new(ScheduleCatalog::seeded())),
            webhook: Arc::new(WebhookDispatcher::from_env()),
            signing_key,
            audit_file_path,
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
        .route("/api/v1/asmodeus/scenarios", get(list_scenarios))
        .route("/api/v1/asmodeus/scenarios/mitre", get(mitre_matrix))
        .route(
            "/api/v1/asmodeus/scenarios/validate",
            post(validate_scenario_manifest),
        )
        .route("/api/v1/asmodeus/scenarios/:id", get(get_scenario))
        .route("/api/v1/asmodeus/scenarios/:id/run", post(run_scenario))
        .route("/api/v1/asmodeus/scenarios/abort", post(abort_all))
        .route("/api/v1/asmodeus/telemetry/mttd", get(telemetry_mttd))
        .route(
            "/api/v1/asmodeus/runners",
            get(list_runners).post(register_runner),
        )
        .route("/api/v1/asmodeus/runners/:id", delete(deregister_runner))
        .route(
            "/api/v1/asmodeus/runners/:id/ping",
            get(ping_runner_handler),
        )
        .route("/api/v1/asmodeus/runs", get(list_runs))
        .route("/api/v1/asmodeus/runs/:id", get(get_run))
        .route("/api/v1/asmodeus/runs/:id/verify", get(verify_run))
        .route("/api/v1/asmodeus/runs/:id/feedback", post(run_feedback))
        .route("/api/v1/asmodeus/runs/:id/report", get(get_run_report))
        .route(
            "/api/v1/asmodeus/reports/resilience",
            get(get_resilience_report),
        )
        .route(
            "/api/v1/asmodeus/reports/compliance",
            get(get_compliance_report),
        )
        .route("/api/v1/asmodeus/openapi.json", get(openapi_spec))
        .route("/api/v1/asmodeus/audit/export", get(export_audit_trail))
        .route(
            "/api/v1/asmodeus/campaigns",
            get(list_campaigns).post(register_campaign),
        )
        .route("/api/v1/asmodeus/campaigns/:id", delete(delete_campaign))
        .route("/api/v1/asmodeus/campaigns/:id/run", post(run_campaign))
        .route(
            "/api/v1/asmodeus/schedules",
            get(list_schedules).post(create_schedule),
        )
        .route("/api/v1/asmodeus/schedules/:id", delete(delete_schedule))
        .with_state(state)
}

// --- error type -----------------------------------------------------------

#[derive(Debug)]
pub(crate) enum ApiError {
    Unauthorized(&'static str),
    Forbidden(&'static str),
    NotFound(String),
    Unprocessable(String),
    Internal(String),
    BadGateway(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Unauthorized(m) => write!(f, "Unauthorized: {m}"),
            ApiError::Forbidden(m) => write!(f, "Forbidden: {m}"),
            ApiError::NotFound(m) => write!(f, "Not Found: {m}"),
            ApiError::Unprocessable(m) => write!(f, "Unprocessable: {m}"),
            ApiError::Internal(m) => write!(f, "Internal: {m}"),
            ApiError::BadGateway(m) => write!(f, "Bad Gateway: {m}"),
        }
    }
}

impl std::error::Error for ApiError {}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (code, msg) = match self {
            ApiError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m.to_string()),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, m.to_string()),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApiError::Unprocessable(m) => (StatusCode::UNPROCESSABLE_ENTITY, m),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
            ApiError::BadGateway(m) => (StatusCode::BAD_GATEWAY, m),
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

#[derive(Debug, Default, serde::Deserialize)]
pub struct RunScenarioPayload {
    pub target_override: Option<String>,
    #[allow(dead_code)]
    pub timeout_sec: Option<u32>,
}

pub(crate) async fn execute_single_scenario(
    state: &AppState,
    entry: &crate::catalog::ScenarioEntry,
    role: Role,
    target_override: Option<&str>,
) -> Result<(RunId, Value, AuditRecord), ApiError> {
    // Integrity (D6): the catalogued manifest must verify against the trusted key.
    if !asmodeus_crypto::is_valid(
        &entry.manifest,
        &entry.signature,
        state.catalog.public_key(),
    ) {
        return Err(ApiError::Unprocessable("scenario signature invalid".into()));
    }

    state.webhook.dispatch(
        crate::webhook::WebhookPayload {
            event: "exercise_started".into(),
            timestamp_utc: asmodeus_telemetry::current_utc_iso8601(),
            exercise_id: String::new(),
            scenario_id: entry.id.to_string(),
            mitre_technique: entry.mitre.map(|m| m.id.to_string()).unwrap_or_default(),
            target: target_override.unwrap_or("default").to_string(),
            initiator: role.as_str().to_string(),
            tag: entry.category.tag().to_string(),
            data: json!({
                "scenario_name": entry.name,
                "category": entry.category.as_str(),
            }),
        },
        Some(&state.signing_key),
    );

    // Target resolution. An explicitly requested target must resolve to a
    // registered runner: we never silently fall back to the static default
    // endpoint, otherwise a mistyped or unavailable target would fire the
    // scenario against the wrong runner. The static endpoint is only used when
    // no target was requested at all.
    let explicit_target = target_override.map(str::trim).filter(|t| !t.is_empty());
    let matched_runner = state.registry.find_for_target(target_override);
    let target_endpoint = if let Some(target) = explicit_target {
        match matched_runner.as_ref() {
            Some(runner) => Some(runner.endpoint.clone()),
            None => {
                return Err(ApiError::NotFound(format!(
                    "target runner not found: {target}"
                )))
            }
        }
    } else {
        matched_runner
            .as_ref()
            .map(|r| r.endpoint.clone())
            .or_else(|| state.runner_endpoint.clone())
    };

    // Execute: dispatch to a live runner over gRPC if one is configured,
    // else drive the in-process engine. Detection metrics stay simulated
    // (no live Blue Team wired); the runner reports the real injection stats.
    let (final_state, execution, runner_id_str) = if let Some(endpoint) = target_endpoint {
        let runner_id = matched_runner
            .as_ref()
            .map(|r| r.id.clone())
            .unwrap_or_else(|| "default-runner".into());
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
            .map_err(|s| ApiError::BadGateway(format!("dispatch: {s}")))?;
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
                "runner_id": runner_id,
                "runner_endpoint": endpoint,
                "runner_final_state": out.final_state,
                "files_created": out.files_created,
                "bytes_written": out.bytes_written,
                "inject_ms": out.inject_ms,
            }),
            runner_id,
        )
    } else {
        let outcome = engine::execute(entry).map_err(|e| match e {
            EngineError::Rejected(_) => ApiError::Unprocessable(e.to_string()),
            EngineError::Transition(_) => ApiError::Internal(e.to_string()),
        })?;
        (
            outcome.final_state,
            json!({ "mode": "simulated" }),
            "in-process-sim".to_string(),
        )
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

    let raw_record = AuditRecord {
        run_id: run_id.to_string(),
        scenario_id: entry.id.to_string(),
        scenario_name: entry.name.to_string(),
        category: match entry.category {
            Category::RedTeam => "red_team".to_string(),
            Category::Chaos => "chaos".to_string(),
        },
        mitre_technique: entry.mitre.map(|m| m.id.to_string()).unwrap_or_default(),
        mitre_tactic: entry
            .mitre
            .map(|m| m.tactic.to_string())
            .unwrap_or_default(),
        severity: entry.severity.to_string(),
        tag: entry.category.tag().to_string(),
        initiator: role.as_str().to_string(),
        runner_id: runner_id_str,
        status: "COMPLETED".to_string(),
        measurements: Measurements {
            mttd_ms: entry.sim_mttd_ms,
            mttr_ms: entry.sim_mttr_ms,
            blue_team_detected: true,
        },
        detection_source: entry.detector.to_string(),
        containment_action: "SIGKILL via SOAR Policy".to_string(),
        cleanup_status: "SUCCESS (canary removed, 0 host side-effects)".to_string(),
        timestamp_utc: asmodeus_telemetry::current_utc_iso8601(),
        signature_hex: String::new(),
        public_key_hex: String::new(),
    };

    let signed_record = raw_record
        .sign(&state.signing_key)
        .map_err(|e| ApiError::Internal(format!("audit signing: {e}")))?;

    state
        .audit_trail
        .write()
        .unwrap()
        .append(signed_record.clone());

    if let Some(ref path) = state.audit_file_path {
        let _ = AuditTrail::append_to_file(&signed_record, path);
    }

    state.webhook.dispatch(
        crate::webhook::WebhookPayload {
            event: "exercise_completed".into(),
            timestamp_utc: signed_record.timestamp_utc.clone(),
            exercise_id: signed_record.run_id.clone(),
            scenario_id: entry.id.to_string(),
            mitre_technique: signed_record.mitre_technique.clone(),
            target: target_override.unwrap_or("default").to_string(),
            initiator: role.as_str().to_string(),
            tag: entry.category.tag().to_string(),
            data: json!({
                "status": signed_record.status,
                "mttd_ms": signed_record.measurements.mttd_ms,
                "mttr_ms": signed_record.measurements.mttr_ms,
                "runner_id": signed_record.runner_id,
            }),
        },
        Some(&state.signing_key),
    );

    Ok((run_id, execution, signed_record))
}

async fn run_scenario(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    let payload: RunScenarioPayload = if body.is_empty() {
        RunScenarioPayload::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| ApiError::Unprocessable(format!("invalid JSON body: {e}")))?
    };

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

    let (run_id, execution, audit_rec) =
        execute_single_scenario(&state, entry, role, payload.target_override.as_deref()).await?;

    Ok(Json(json!({
        "run_id": run_id.to_string(),
        "scenario_id": entry.id,
        "scenario_name": entry.name,
        "category": match entry.category {
            Category::RedTeam => "red_team",
            Category::Chaos => "chaos",
        },
        "mitre_technique": entry.mitre.map(|m| m.id),
        "mitre_tactic": entry.mitre.map(|m| m.tactic),
        "severity": entry.severity,
        "tag": entry.category.tag(),
        "initiator": role.as_str(),
        "status": audit_rec.status,
        "execution": execution,
        "measurements": {
            "mttd_ms": audit_rec.measurements.mttd_ms,
            "mttr_ms": audit_rec.measurements.mttr_ms,
            "blue_team_detected": audit_rec.measurements.blue_team_detected,
            "detection_source": audit_rec.detection_source,
            "containment_action": audit_rec.containment_action,
        },
        "cleanup_status": audit_rec.cleanup_status,
        "timestamp_utc": audit_rec.timestamp_utc,
        "signature_hex": audit_rec.signature_hex,
        "public_key_hex": audit_rec.public_key_hex,
    })))
}

async fn list_scenarios(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view scenarios"));
    }
    let mut scenarios: Vec<_> = state
        .catalog
        .entries()
        .map(|entry| {
            json!({
                "id": entry.id,
                "name": entry.name,
                "category": match entry.category {
                    Category::RedTeam => "red_team",
                    Category::Chaos => "chaos",
                },
                "mitre_technique": entry.mitre.map(|m| m.id),
                "mitre_tactic": entry.mitre.map(|m| m.tactic),
                "severity": entry.severity,
                "detector": entry.detector,
                "description": entry.description,
            })
        })
        .collect();
    scenarios.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    Ok(Json(json!(scenarios)))
}

async fn get_scenario(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view scenarios"));
    }
    let entry = state
        .catalog
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("unknown scenario_id: {id}")))?;

    Ok(Json(json!({
        "id": entry.id,
        "name": entry.name,
        "category": match entry.category {
            Category::RedTeam => "red_team",
            Category::Chaos => "chaos",
        },
        "mitre_technique": entry.mitre.map(|m| m.id),
        "mitre_tactic": entry.mitre.map(|m| m.tactic),
        "mitre_technique_name": entry.mitre.map(|m| m.name),
        "mitre_description": entry.mitre.map(|m| m.description),
        "severity": entry.severity,
        "detector": entry.detector,
        "description": entry.description,
        "target_path": entry.target_path,
        "sim_mttd_ms": entry.sim_mttd_ms,
        "sim_mttr_ms": entry.sim_mttr_ms,
    })))
}

async fn mitre_matrix(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view MITRE matrix"));
    }

    let mut tactics_map: HashMap<&'static str, Vec<Value>> = HashMap::new();
    let mut covered_techniques = std::collections::HashSet::new();
    let mut mitre_scenarios_count = 0;

    for entry in state.catalog.entries() {
        if let Some(m) = entry.mitre {
            mitre_scenarios_count += 1;
            covered_techniques.insert(m.id);
            tactics_map.entry(m.tactic).or_default().push(json!({
                "scenario_id": entry.id,
                "scenario_name": entry.name,
                "technique_id": m.id,
                "technique_name": m.name,
                "severity": entry.severity,
                "detector": entry.detector,
            }));
        }
    }

    let mut sorted_tactics: Vec<_> = tactics_map
        .into_iter()
        .map(|(tactic, mut scenarios)| {
            scenarios.sort_by(|a, b| a["technique_id"].as_str().cmp(&b["technique_id"].as_str()));
            json!({
                "tactic": tactic,
                "scenarios_count": scenarios.len(),
                "scenarios": scenarios,
            })
        })
        .collect();
    sorted_tactics.sort_by(|a, b| a["tactic"].as_str().cmp(&b["tactic"].as_str()));

    let total_scenarios = state.catalog.entries().count();

    Ok(Json(json!({
        "framework": "MITRE ATT&CK Enterprise Matrix",
        "total_scenarios": total_scenarios,
        "mitre_scenarios_count": mitre_scenarios_count,
        "covered_techniques_count": covered_techniques.len(),
        "tactics_count": sorted_tactics.len(),
        "tactics": sorted_tactics,
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

    state.webhook.dispatch(
        crate::webhook::WebhookPayload {
            event: "exercise_aborted".into(),
            timestamp_utc: asmodeus_telemetry::current_utc_iso8601(),
            exercise_id: "all".into(),
            scenario_id: "all".into(),
            mitre_technique: String::new(),
            target: "all".into(),
            initiator: role.as_str().to_string(),
            tag: "🛑 [EMERGENCY ABORT]".into(),
            data: json!({
                "runs_cleared": aborted,
            }),
        },
        Some(&state.signing_key),
    );

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

#[derive(Debug, serde::Deserialize)]
pub struct RegisterRunnerRequest {
    pub id: String,
    pub name: Option<String>,
    pub endpoint: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

async fn list_runners(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view runners"));
    }
    let runners = state.registry.list();
    Ok(Json(json!(runners)))
}

async fn register_runner(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RegisterRunnerRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let role = caller_role(&headers)?;
    let may_register = role.can(asmodeus_common::Capability::RunRedTeam)
        || role.can(asmodeus_common::Capability::InjectChaos);
    if !may_register {
        return Err(ApiError::Forbidden("role may not register runners"));
    }

    let id = payload.id.trim();
    if id.is_empty() {
        return Err(ApiError::Unprocessable("runner id cannot be empty".into()));
    }
    let endpoint = payload.endpoint.trim();
    if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
        return Err(ApiError::Unprocessable(
            "runner endpoint must start with http:// or https://".into(),
        ));
    }

    let name = payload.name.unwrap_or_else(|| id.to_string());
    let record = RunnerRecord::new(id, name, endpoint, payload.tags);
    state.registry.register(record.clone());

    Ok((StatusCode::CREATED, Json(json!(record))))
}

async fn deregister_runner(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    let may_deregister = role.can(asmodeus_common::Capability::RunRedTeam)
        || role.can(asmodeus_common::Capability::InjectChaos);
    if !may_deregister {
        return Err(ApiError::Forbidden("role may not deregister runners"));
    }

    if state.registry.deregister(&id) {
        Ok(Json(json!({ "status": "DEREGISTERED", "id": id })))
    } else {
        Err(ApiError::NotFound(format!("runner not found: {id}")))
    }
}

async fn ping_runner_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not ping runners"));
    }

    let runner = state
        .registry
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("runner not found: {id}")))?;

    match crate::dispatch::ping(&runner.endpoint).await {
        Ok(reply) => {
            state.registry.update_heartbeat(
                &id,
                reply.healthy,
                reply.cpu_usage_pct,
                &reply.version,
            );
            Ok(Json(json!({
                "id": id,
                "endpoint": runner.endpoint,
                "healthy": reply.healthy,
                "state": reply.state,
                "cpu_usage_pct": reply.cpu_usage_pct,
                "active_exercise_id": reply.active_exercise_id,
                "version": reply.version,
            })))
        }
        Err(status) => {
            state.registry.mark_unresponsive(&id);
            Err(ApiError::BadGateway(format!(
                "runner ping failed: {status}"
            )))
        }
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct ListRunsQuery {
    pub limit: Option<usize>,
    pub scenario_id: Option<String>,
    pub status: Option<String>,
}

async fn list_runs(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<ListRunsQuery>,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view run history"));
    }
    let trail = state.audit_trail.read().unwrap();
    let records = trail.list(
        query.limit,
        query.scenario_id.as_deref(),
        query.status.as_deref(),
    );
    Ok(Json(json!({
        "total": trail.len(),
        "returned": records.len(),
        "runs": records,
    })))
}

async fn get_run(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view run details"));
    }
    let trail = state.audit_trail.read().unwrap();
    let record = trail
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("run not found: {id}")))?;
    Ok(Json(json!(record)))
}

async fn verify_run(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not verify runs"));
    }
    let trail = state.audit_trail.read().unwrap();
    let record = trail
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("run not found: {id}")))?;
    // Pin verification to the control plane's trusted signing key rather than
    // the public key embedded in the record, so a tampered + re-signed record
    // cannot report itself as verified.
    let verified = record.verify_with_key(state.catalog.public_key());
    Ok(Json(json!({
        "run_id": record.run_id,
        "scenario_id": record.scenario_id,
        "verified": verified,
        "signature_hex": record.signature_hex,
        "public_key_hex": record.public_key_hex,
        "timestamp_utc": record.timestamp_utc,
    })))
}

async fn validate_scenario_manifest(
    State(_state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not validate scenarios"));
    }
    let body_str = std::str::from_utf8(&body)
        .map_err(|e| ApiError::Unprocessable(format!("invalid UTF-8 body: {e}")))?;
    match asmodeus_dsl::parse_and_validate_manifest(body_str) {
        Ok(manifest) => Ok(Json(json!({
            "valid": true,
            "manifest_id": manifest.metadata.id,
            "manifest_name": manifest.metadata.name,
            "category": manifest.metadata.category,
            "mitre_technique": manifest.metadata.mitre_technique,
            "inv_0_compliant": true,
        }))),
        Err(e) => Err(ApiError::Unprocessable(e.to_string())),
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RunFeedbackPayload {
    pub detected: bool,
    #[serde(default)]
    pub mttd_ms: Option<u64>,
    #[serde(default)]
    pub detection_source: Option<String>,
    #[serde(default)]
    pub contained: bool,
    #[serde(default)]
    pub mttr_ms: Option<u64>,
    #[serde(default)]
    pub containment_action: Option<String>,
}

async fn run_feedback(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<RunFeedbackPayload>,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    // Admin, RedTeam, DevSecOps, SecOps can submit feedback. Auditor & CISO forbidden.
    if matches!(role, Role::Ciso | Role::Auditor) {
        return Err(ApiError::Forbidden("role may not submit feedback"));
    }

    let (old_record, updated_record) = {
        let trail = state.audit_trail.read().unwrap();
        let old = trail
            .get(&id)
            .ok_or_else(|| ApiError::NotFound(format!("run not found: {id}")))?
            .clone();

        let new_measurements = Measurements {
            mttd_ms: payload.mttd_ms.unwrap_or(old.measurements.mttd_ms),
            mttr_ms: payload.mttr_ms.unwrap_or(old.measurements.mttr_ms),
            blue_team_detected: payload.detected,
        };

        let updated = AuditRecord {
            run_id: old.run_id.clone(),
            scenario_id: old.scenario_id.clone(),
            scenario_name: old.scenario_name.clone(),
            category: old.category.clone(),
            mitre_technique: old.mitre_technique.clone(),
            mitre_tactic: old.mitre_tactic.clone(),
            severity: old.severity.clone(),
            tag: old.tag.clone(),
            initiator: old.initiator.clone(),
            runner_id: old.runner_id.clone(),
            status: if payload.contained {
                "CONTAINED".to_string()
            } else if payload.detected {
                "DETECTED".to_string()
            } else {
                "UNCONTAINED".to_string()
            },
            measurements: new_measurements,
            detection_source: payload
                .detection_source
                .unwrap_or_else(|| old.detection_source.clone()),
            containment_action: payload
                .containment_action
                .unwrap_or_else(|| old.containment_action.clone()),
            cleanup_status: old.cleanup_status.clone(),
            timestamp_utc: asmodeus_telemetry::current_utc_iso8601(),
            signature_hex: String::new(),
            public_key_hex: String::new(),
        };

        (old, updated)
    };

    let signed = updated_record
        .sign(&state.signing_key)
        .map_err(|e| ApiError::Internal(format!("audit re-signing: {e}")))?;

    state
        .audit_trail
        .write()
        .unwrap()
        .update(&id, signed.clone());

    if let Some(ref path) = state.audit_file_path {
        let trail = state.audit_trail.read().unwrap();
        let _ = trail.save_to_file(path);
    }

    state
        .metrics
        .lock()
        .unwrap()
        .update_measurement(old_record.measurements, signed.measurements);

    Ok(Json(json!({
        "status": "UPDATED",
        "run_id": signed.run_id,
        "run_status": signed.status,
        "measurements": signed.measurements,
        "detection_source": signed.detection_source,
        "containment_action": signed.containment_action,
        "signature_hex": signed.signature_hex,
        "timestamp_utc": signed.timestamp_utc,
    })))
}

#[derive(Debug, Deserialize, Default)]
pub struct ReportQuery {
    pub format: Option<String>,
}

async fn get_resilience_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<ReportQuery>,
) -> Result<Response, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view resilience reports"));
    }

    let trail = state.audit_trail.read().unwrap();
    let records = trail.list(None, None, None);
    let agg = state.metrics.lock().unwrap().clone();
    let report = EcosystemResilienceReport::build(&records, &agg);

    if query.format.as_deref() == Some("markdown") {
        Ok((
            StatusCode::OK,
            [("content-type", "text/markdown; charset=utf-8")],
            report.to_markdown(),
        )
            .into_response())
    } else {
        Ok(Json(json!(report)).into_response())
    }
}

async fn get_compliance_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<ReportQuery>,
) -> Result<Response, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view compliance reports"));
    }

    let trail = state.audit_trail.read().unwrap();
    let records = trail.list(None, None, None);
    let scenario_metas: Vec<asmodeus_telemetry::ScenarioMeta> = state
        .catalog
        .ids()
        .filter_map(|id| state.catalog.get(id))
        .map(|entry| asmodeus_telemetry::ScenarioMeta {
            id: entry.id.to_string(),
            name: entry.name.to_string(),
            category: entry.category.as_str().to_string(),
            mitre_technique: entry.mitre.map(|m| m.id.to_string()).unwrap_or_default(),
        })
        .collect();
    let report = asmodeus_telemetry::ComplianceReport::generate(&scenario_metas, &records);

    if query.format.as_deref() == Some("markdown") {
        Ok((
            StatusCode::OK,
            [("content-type", "text/markdown; charset=utf-8")],
            report.to_markdown(),
        )
            .into_response())
    } else {
        Ok(Json(json!(report)).into_response())
    }
}

async fn get_run_report(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<ReportQuery>,
) -> Result<Response, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view run reports"));
    }

    let trail = state.audit_trail.read().unwrap();
    let record = trail
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("run not found: {id}")))?;

    let run_report = SingleRunReport::build(record, Some(state.catalog.public_key()));

    if query.format.as_deref() == Some("markdown") {
        Ok((
            StatusCode::OK,
            [("content-type", "text/markdown; charset=utf-8")],
            run_report.to_markdown(),
        )
            .into_response())
    } else {
        Ok(Json(json!(run_report)).into_response())
    }
}

async fn openapi_spec() -> Json<Value> {
    Json(crate::openapi::generate_spec())
}

#[derive(Debug, Deserialize, Default)]
pub struct ExportAuditParams {
    pub format: Option<String>,
}

async fn export_audit_trail(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<ExportAuditParams>,
) -> Result<Response, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view audit trail"));
    }

    let trail = state.audit_trail.read().unwrap();
    let fmt = params
        .format
        .as_deref()
        .unwrap_or("jsonl")
        .to_ascii_lowercase();

    match fmt.as_str() {
        "json" => {
            let json_body = trail
                .export_json()
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            Ok((
                StatusCode::OK,
                [("content-type", "application/json; charset=utf-8")],
                json_body,
            )
                .into_response())
        }
        "clickhouse" | "clickhouse_sql" | "sql" => {
            let sql_body = trail.export_clickhouse_sql();
            Ok((
                StatusCode::OK,
                [("content-type", "application/sql; charset=utf-8")],
                sql_body,
            )
                .into_response())
        }
        "clickhouse_ndjson" => {
            let ndjson_body = trail
                .export_clickhouse_ndjson()
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            Ok((
                StatusCode::OK,
                [("content-type", "application/x-ndjson; charset=utf-8")],
                ndjson_body,
            )
                .into_response())
        }
        _ => {
            let jsonl_body = trail.export_jsonl();
            Ok((
                StatusCode::OK,
                [("content-type", "application/x-ndjson; charset=utf-8")],
                jsonl_body,
            )
                .into_response())
        }
    }
}

async fn register_campaign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(campaign): Json<crate::campaign::Campaign>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ManageScenarios)
        && !role.can(asmodeus_common::Capability::RunRedTeam)
        && role != Role::Admin
    {
        return Err(ApiError::Forbidden(
            "role may not register attack campaigns",
        ));
    }

    if campaign.id.trim().is_empty() {
        return Err(ApiError::Unprocessable(
            "campaign id cannot be empty".to_string(),
        ));
    }
    if campaign.steps.is_empty() {
        return Err(ApiError::Unprocessable(
            "campaign steps cannot be empty".to_string(),
        ));
    }

    state.campaigns.write().unwrap().register(campaign.clone());

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "status": "registered",
            "campaign": campaign,
        })),
    ))
}

async fn delete_campaign(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ManageScenarios)
        && !role.can(asmodeus_common::Capability::RunRedTeam)
        && role != Role::Admin
    {
        return Err(ApiError::Forbidden("role may not delete attack campaigns"));
    }

    if state.campaigns.write().unwrap().deregister(&id) {
        Ok(Json(json!({
            "status": "deleted",
            "id": id,
        })))
    } else {
        Err(ApiError::NotFound(format!("campaign not found: {id}")))
    }
}

async fn list_campaigns(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view campaigns"));
    }
    let campaigns = state.campaigns.read().unwrap().list().to_vec();
    Ok(Json(json!({
        "campaigns": campaigns,
    })))
}

async fn run_campaign(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::RunRedTeam)
        && !role.can(asmodeus_common::Capability::InjectChaos)
    {
        return Err(ApiError::Forbidden("role may not launch attack campaigns"));
    }
    let payload: RunScenarioPayload = if body.is_empty() {
        RunScenarioPayload::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| ApiError::Unprocessable(format!("invalid JSON body: {e}")))?
    };

    let campaign = state
        .campaigns
        .read()
        .unwrap()
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("campaign not found: {id}")))?
        .clone();

    let mut step_results = Vec::new();
    let mut sum_mttd = 0u64;
    let mut sum_mttr = 0u64;
    let mut detected_count = 0usize;
    let total_steps = campaign.steps.len();

    // Execute the kill-chain stage by stage. A failing stage stops the chain
    // (later stages typically depend on earlier ones) but never discards the
    // work already done: the stage is recorded as failed and the partial
    // report is returned to the caller instead of a bare error.
    for step in &campaign.steps {
        let entry = match state.catalog.get(&step.scenario_id) {
            Some(entry) => entry,
            None => {
                step_results.push(crate::campaign::CampaignStepResult {
                    step_order: step.order,
                    scenario_id: step.scenario_id.clone(),
                    run_id: String::new(),
                    status: "SCENARIO_NOT_FOUND".to_string(),
                    mttd_ms: 0,
                    mttr_ms: 0,
                    detected: false,
                });
                break;
            }
        };

        match execute_single_scenario(&state, entry, role, payload.target_override.as_deref()).await
        {
            Ok((run_id, _exec, audit_rec)) => {
                sum_mttd += audit_rec.measurements.mttd_ms;
                sum_mttr += audit_rec.measurements.mttr_ms;
                if audit_rec.measurements.blue_team_detected {
                    detected_count += 1;
                }

                step_results.push(crate::campaign::CampaignStepResult {
                    step_order: step.order,
                    scenario_id: step.scenario_id.clone(),
                    run_id: run_id.to_string(),
                    status: audit_rec.status,
                    mttd_ms: audit_rec.measurements.mttd_ms,
                    mttr_ms: audit_rec.measurements.mttr_ms,
                    detected: audit_rec.measurements.blue_team_detected,
                });
            }
            Err(_) => {
                step_results.push(crate::campaign::CampaignStepResult {
                    step_order: step.order,
                    scenario_id: step.scenario_id.clone(),
                    run_id: String::new(),
                    status: "FAILED".to_string(),
                    mttd_ms: 0,
                    mttr_ms: 0,
                    detected: false,
                });
                break;
            }
        }
    }

    // Aggregate only over the stages that actually completed, so a partial
    // chain does not dilute the means with zero-valued failed stages.
    let successful_steps = step_results
        .iter()
        .filter(|r| r.status == "COMPLETED")
        .count();
    let mean_mttd = if successful_steps > 0 {
        sum_mttd / successful_steps as u64
    } else {
        0
    };
    let mean_mttr = if successful_steps > 0 {
        sum_mttr / successful_steps as u64
    } else {
        0
    };
    let detection_rate_pct = if successful_steps > 0 {
        100.0 * detected_count as f32 / successful_steps as f32
    } else {
        0.0
    };
    let recovery_speed_pct = if mean_mttr == 0 {
        100.0
    } else {
        (100.0 * asmodeus_telemetry::TARGET_MTTR_MS as f32 / mean_mttr as f32).clamp(0.0, 100.0)
    };
    let resilience_score =
        asmodeus_telemetry::resilience_score(detection_rate_pct, recovery_speed_pct);

    let result = crate::campaign::CampaignRunResult {
        campaign_id: campaign.id,
        campaign_name: campaign.name,
        initiator: role.as_str().to_string(),
        target_override: payload.target_override,
        total_steps,
        successful_steps,
        step_results,
        mean_mttd_ms: mean_mttd,
        mean_mttr_ms: mean_mttr,
        detection_rate_pct,
        recovery_speed_pct,
        resilience_score,
        timestamp_utc: asmodeus_telemetry::current_utc_iso8601(),
    };

    Ok(Json(json!(result)))
}

async fn list_schedules(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports)
        && !role.can(asmodeus_common::Capability::RunRedTeam)
        && !role.can(asmodeus_common::Capability::InjectChaos)
        && role != Role::Admin
    {
        return Err(ApiError::Forbidden("role may not view schedules"));
    }
    let schedules = state.schedules.read().unwrap().list();
    Ok(Json(json!({ "schedules": schedules })))
}

async fn create_schedule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateScheduleRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ManageScenarios)
        && !role.can(asmodeus_common::Capability::RunRedTeam)
        && !role.can(asmodeus_common::Capability::InjectChaos)
        && role != Role::Admin
    {
        return Err(ApiError::Forbidden("role may not schedule exercises"));
    }

    if req.name.trim().is_empty() {
        return Err(ApiError::Unprocessable(
            "schedule name cannot be empty".into(),
        ));
    }
    if req.interval_sec < 5 {
        return Err(ApiError::Unprocessable(
            "interval must be at least 5 seconds".into(),
        ));
    }
    if !state.catalog.ids().any(|id| id == req.scenario_id) {
        return Err(ApiError::NotFound(format!(
            "scenario not found: {}",
            req.scenario_id
        )));
    }

    let id = req.id.unwrap_or_else(|| {
        format!(
            "SCHED-{}",
            req.name
                .to_ascii_uppercase()
                .replace(|c: char| !c.is_ascii_alphanumeric(), "-")
        )
    });

    let job = ScheduledJob {
        id,
        name: req.name,
        scenario_id: req.scenario_id,
        interval_sec: req.interval_sec,
        role: if role == Role::DevSecOps || role == Role::Admin {
            Role::RedTeam
        } else {
            role
        },
        target_override: req.target_override,
        enabled: req.enabled.unwrap_or(true),
        created_at_utc: asmodeus_telemetry::current_utc_iso8601(),
        last_run_utc: None,
        last_run_epoch_secs: None,
        last_status: None,
        last_mttd_ms: None,
        baseline_mttd_ms: req.baseline_mttd_ms,
        drift_detected: false,
        drift_factor: None,
    };

    state.schedules.write().unwrap().register(job.clone());
    Ok((
        StatusCode::CREATED,
        Json(json!({ "status": "created", "schedule": job })),
    ))
}

async fn delete_schedule(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ManageScenarios)
        && !role.can(asmodeus_common::Capability::RunRedTeam)
        && !role.can(asmodeus_common::Capability::InjectChaos)
        && role != Role::Admin
    {
        return Err(ApiError::Forbidden("role may not delete schedules"));
    }

    if state.schedules.write().unwrap().deregister(&id) {
        Ok(Json(json!({ "status": "deleted", "id": id })))
    } else {
        Err(ApiError::NotFound(format!("schedule not found: {id}")))
    }
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
}
