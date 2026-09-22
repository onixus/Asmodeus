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

    let entry = state
        .catalog
        .get(&req.scenario_id)
        .expect("catalog validated above");
    if !role.can(entry.category.required_capability()) {
        return Err(ApiError::Forbidden(
            "role may not schedule this scenario category",
        ));
    }

    let id = req.id.unwrap_or_else(|| {
        format!(
            "SCHED-{}",
            req.name
                .to_ascii_uppercase()
                .replace(|c: char| !c.is_ascii_alphanumeric(), "-")
        )
    });

    if id.trim().is_empty() {
        return Err(ApiError::Unprocessable(
            "schedule id cannot be empty".into(),
        ));
    }
    let job = ScheduledJob {
        generation: state.next_run_id().to_string(),
        id,
        name: req.name,
        scenario_id: req.scenario_id,
        interval_sec: req.interval_sec,
        role,
        target_override: req.target_override,
        enabled: req.enabled.unwrap_or(true),
        created_at_utc: asmodeus_telemetry::current_utc_iso8601(),
        last_run_utc: None,
        last_run_epoch_secs: None,
        last_status: None,
        last_run_id: None,
        last_mttd_ms: None,
        baseline_mttd_ms: req.baseline_mttd_ms,
        drift_detected: false,
        drift_factor: None,
        run_history: Default::default(),
    };

    let saved = job.clone();
    let created = state
        .schedules
        .update(move |catalog| {
            if catalog.get(&saved.id).is_some() {
                return Ok(false);
            }
            catalog.register(saved);
            Ok(true)
        })
        .await
        .map_err(|e| ApiError::Internal(format!("schedule persistence: {e}")))?;
    if !created {
        return Err(ApiError::Unprocessable(
            "schedule id already exists; delete it before replacement".into(),
        ));
    }
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

    let delete_id = id.clone();
    if state
        .schedules
        .update(move |catalog| Ok(catalog.deregister(&delete_id)))
        .await
        .map_err(|e| ApiError::Internal(format!("schedule persistence: {e}")))?
    {
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
    let catalog = state.catalog.clone();
    let update_id = id.clone();
    match state
        .schedules
        .update(move |schedules| {
            if let Some(job) = schedules.get(&update_id) {
                let allowed = catalog
                    .get(&job.scenario_id)
                    .is_some_and(|entry| role.can(entry.category.required_capability()));
                if !allowed {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "role may not enable this scenario category",
                    ));
                }
            }
            Ok(schedules.set_enabled(&update_id, payload.enabled))
        })
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                ApiError::Forbidden("role may not modify this scenario category")
            } else {
                ApiError::Internal(format!("schedule persistence: {e}"))
            }
        })? {
        Some(enabled) => Ok(Json(
            json!({ "status": "updated", "id": id, "enabled": enabled }),
        )),
        None => Err(ApiError::NotFound(format!("schedule not found: {id}"))),
    }
}
