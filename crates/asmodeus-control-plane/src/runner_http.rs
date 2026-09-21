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
    state.registry.register(record.clone());

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

    if state.registry.deregister(&id) {
        Ok(Json(json!({ "status": "DEREGISTERED", "id": id })))
    } else {
        Err(ApiError::NotFound(format!("runner not found: {id}")))
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
