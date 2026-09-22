//! HTTP handlers for Continuous BAS schedule management.

use asmodeus_common::Role;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::{caller_role, ApiError};
use crate::scheduler::{CreateScheduleRequest, ScheduledJob};
use crate::state::AppState;

pub(crate) async fn list_schedules(
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

pub(crate) async fn create_schedule(
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
    if req.baseline_mttd_ms == Some(0) {
        return Err(ApiError::Unprocessable(
            "baseline_mttd_ms must be greater than zero".into(),
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
        run_history: Default::default(),
    };

    state.schedules.write().unwrap().register(job.clone());
    Ok((
        StatusCode::CREATED,
        Json(json!({ "status": "created", "schedule": job })),
    ))
}

pub(crate) async fn delete_schedule(
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

/// Roles allowed to read schedules and their drift history: any read-only
/// role (CISO/SecOps/Auditor via `ViewReports`) plus operators. Mirrors the
/// gate on `list_schedules`.
fn may_view_schedules(role: Role) -> bool {
    role.can(asmodeus_common::Capability::ViewReports)
        || role.can(asmodeus_common::Capability::RunRedTeam)
        || role.can(asmodeus_common::Capability::InjectChaos)
        || role == Role::Admin
}

/// Schedule detail including the bounded run-history timeline (drift over time).
pub(crate) async fn get_schedule(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !may_view_schedules(role) {
        return Err(ApiError::Forbidden("role may not view schedules"));
    }
    let cat = state.schedules.read().unwrap();
    match cat.get(&id) {
        Some(job) => Ok(Json(json!({ "schedule": job }))),
        None => Err(ApiError::NotFound(format!("schedule not found: {id}"))),
    }
}

/// Persisted detection-drift alerts across all scheduled baselines, newest
/// first. This is the operator-facing surface for MTTD regression.
pub(crate) async fn list_drift_alerts(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !may_view_schedules(role) {
        return Err(ApiError::Forbidden("role may not view drift alerts"));
    }
    let alerts = state.schedules.read().unwrap().alerts();
    Ok(Json(json!({ "alerts": alerts, "count": alerts.len() })))
}

#[derive(Debug, Deserialize)]
pub(crate) struct ToggleSchedulePayload {
    enabled: bool,
}

/// Enable or disable a scheduled baseline without deleting it (pause a noisy
/// job, or resume a paused one).
pub(crate) async fn toggle_schedule(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<ToggleSchedulePayload>,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ManageScenarios)
        && !role.can(asmodeus_common::Capability::RunRedTeam)
        && !role.can(asmodeus_common::Capability::InjectChaos)
        && role != Role::Admin
    {
        return Err(ApiError::Forbidden("role may not modify schedules"));
    }
    match state
        .schedules
        .write()
        .unwrap()
        .set_enabled(&id, payload.enabled)
    {
        Some(enabled) => Ok(Json(
            json!({ "status": "updated", "id": id, "enabled": enabled }),
        )),
        None => Err(ApiError::NotFound(format!("schedule not found: {id}"))),
    }
}
