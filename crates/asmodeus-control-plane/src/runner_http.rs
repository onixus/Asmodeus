//! HTTP handlers for runner registry and liveness operations.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::{json, Value};

use crate::api::{caller_role, ApiError};
use crate::registry::RunnerRecord;
use crate::state::AppState;

#[derive(Debug, serde::Deserialize)]
pub struct RegisterRunnerRequest {
    pub id: String,
    pub name: Option<String>,
    pub endpoint: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerMaintenanceRequest {
    pub draining: bool,
}

pub(crate) async fn set_runner_maintenance(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<RunnerMaintenanceRequest>,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::RunRedTeam)
        && !role.can(asmodeus_common::Capability::InjectChaos)
    {
        return Err(ApiError::Forbidden(
            "role may not change runner maintenance",
        ));
    }
    let record = state
        .registry
        .set_draining(&id, payload.draining)
        .await
        .map_err(registry_error)?
        .ok_or_else(|| ApiError::NotFound(format!("runner not found: {id}")))?;
    Ok(Json(json!(record)))
}

pub(crate) async fn list_runners(
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

pub(crate) async fn register_runner(
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
    let record = state
        .registry
        .register(record)
        .await
        .map_err(registry_error)?;

    Ok((StatusCode::CREATED, Json(json!(record))))
}

pub(crate) async fn deregister_runner(
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

    if state
        .registry
        .deregister(&id)
        .await
        .map_err(registry_error)?
    {
        Ok(Json(json!({ "status": "DEREGISTERED", "id": id })))
    } else {
        Err(ApiError::NotFound(format!("runner not found: {id}")))
    }
}

fn registry_error(error: std::io::Error) -> ApiError {
    if error.kind() == std::io::ErrorKind::InvalidInput {
        ApiError::Unprocessable(error.to_string())
    } else {
        ApiError::Internal(format!("runner registry persistence failed: {error}"))
    }
}

pub(crate) async fn ping_runner_handler(
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
        .begin_probe(&id)
        .ok_or_else(|| ApiError::NotFound(format!("runner not found: {id}")))?;

    match crate::dispatch::ping(&runner.record.endpoint).await {
        Ok(reply) => {
            let applied = state.registry.update_heartbeat(
                &runner,
                reply.healthy,
                reply.cpu_usage_pct,
                &reply.version,
            );
            Ok(Json(json!({
                "id": id,
                "endpoint": runner.record.endpoint,
                "registry_updated": applied,
                "healthy": reply.healthy,
                "state": reply.state,
                "cpu_usage_pct": reply.cpu_usage_pct,
                "active_exercise_id": reply.active_exercise_id,
                "version": reply.version,
            })))
        }
        Err(status) => {
            state.registry.mark_unresponsive(&runner);
            Err(ApiError::BadGateway(format!(
                "runner ping failed: {status}"
            )))
        }
    }
}
