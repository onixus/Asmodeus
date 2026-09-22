//! HTTP handlers for run history, verification and Blue Team feedback.

use asmodeus_common::Role;
use asmodeus_telemetry::{Measurements, RunEvidence};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::{caller_role, ApiError};
use crate::state::AppState;

#[derive(Debug, Default, Deserialize)]
pub struct ListRunsQuery {
    pub limit: Option<usize>,
    pub scenario_id: Option<String>,
    pub status: Option<String>,
}

pub(crate) async fn list_runs(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<ListRunsQuery>,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view run history"));
    }
    let records = state.audit.list(
        query.limit,
        query.scenario_id.as_deref(),
        query.status.as_deref(),
    );
    Ok(Json(json!({
        "total": state.audit.len(),
        "returned": records.len(),
        "runs": records,
    })))
}

pub(crate) async fn get_run(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view run details"));
    }
    let record = state
        .audit
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("run not found: {id}")))?;
    let mut value = json!(record);
    value["live_state"] = state
        .runs
        .lock()
        .unwrap()
        .get(&asmodeus_common::RunId::new(&id))
        .map(|active| json!(*active.status.lock().unwrap()))
        .unwrap_or(serde_json::Value::Null);
    Ok(Json(value))
}

pub(crate) async fn verify_run(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not verify runs"));
    }
    let record = state
        .audit
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("run not found: {id}")))?;
    // Pin verification to the control plane's trusted signing key rather than
    // the public key embedded in the record, so a tampered + re-signed record
    // cannot report itself as verified.
    let verified = record.verify_with_key(&state.audit_public_key);
    Ok(Json(json!({
        "run_id": record.run_id,
        "scenario_id": record.scenario_id,
        "verified": verified,
        "signature_hex": record.signature_hex,
        "public_key_hex": record.public_key_hex,
        "timestamp_utc": record.timestamp_utc,
    })))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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

pub(crate) async fn run_feedback(
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

    let old = state
        .audit
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("run not found: {id}")))?;
    if !old.is_terminal() {
        return Err(ApiError::Unprocessable(
            "feedback requires a terminal execution result".into(),
        ));
    }
    if payload.contained && !payload.detected {
        return Err(ApiError::Unprocessable(
            "contained requires detected=true".into(),
        ));
    }
    if payload.detected && payload.mttd_ms.is_none() {
        return Err(ApiError::Unprocessable(
            "detected feedback requires mttd_ms".into(),
        ));
    }
    if payload.contained && payload.mttr_ms.is_none() {
        return Err(ApiError::Unprocessable(
            "contained feedback requires mttr_ms".into(),
        ));
    }
    let signing_key = state.signing_key;
    let signed = state
        .audit
        .update(id.clone(), move |mut old| {
            old.measurements = Measurements {
                mttd_ms: if payload.detected {
                    payload.mttd_ms.unwrap_or(0)
                } else {
                    0
                },
                mttr_ms: if payload.contained {
                    payload.mttr_ms.unwrap_or(0)
                } else {
                    0
                },
                blue_team_detected: payload.detected,
            };
            let evidence = old.evidence.get_or_insert_with(|| RunEvidence {
                execution_mode: "legacy_unverified".into(),
                ..Default::default()
            });
            evidence.feedback_received = true;
            evidence.contained = payload.contained;
            old.detection_source = payload
                .detection_source
                .unwrap_or_else(|| "operator_feedback".into());
            old.containment_action = if payload.contained {
                payload
                    .containment_action
                    .unwrap_or_else(|| "operator_confirmed".into())
            } else {
                "UNCONFIRMED".into()
            };
            old.timestamp_utc = asmodeus_telemetry::current_utc_iso8601();
            old.sign(&signing_key).map_err(std::io::Error::other)
        })
        .await
        .map_err(|e| ApiError::Internal(format!("audit feedback: {e}")))?
        .ok_or_else(|| ApiError::NotFound(format!("run not found: {id}")))?;

    let feedback = signed.clone();
    state
        .schedules
        .update(move |catalog| {
            catalog.record_feedback(&feedback);
            Ok(())
        })
        .await
        .map_err(|e| {
            ApiError::Internal(format!("feedback saved but schedule update failed: {e}"))
        })?;

    Ok(Json(json!({
        "status": "UPDATED",
        "run_id": signed.run_id,
        "run_status": signed.status,
        "measurements": signed.measurements,
        "evidence": signed.evidence,
        "detection_status": if signed.measurements.blue_team_detected { "DETECTED" } else { "NOT_DETECTED" },
        "detection_source": signed.detection_source,
        "containment_action": signed.containment_action,
        "signature_hex": signed.signature_hex,
        "timestamp_utc": signed.timestamp_utc,
    })))
}

pub(crate) async fn cancel_run(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<(axum::http::StatusCode, Json<Value>), ApiError> {
    let role = caller_role(&headers)?;
    let record = state
        .audit
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("run not found: {id}")))?;
    let category: asmodeus_common::Category = record
        .category
        .parse()
        .map_err(|_| ApiError::Unprocessable("unknown run category".into()))?;
    if !role.can(category.required_capability()) {
        return Err(ApiError::Forbidden(
            "role may not cancel this scenario category",
        ));
    }
    if record.is_terminal() {
        return Ok((
            axum::http::StatusCode::OK,
            Json(json!({"run_id":id,"status":record.status,"evidence":record.evidence})),
        ));
    }
    if let Some(active) = state
        .runs
        .lock()
        .unwrap()
        .get(&asmodeus_common::RunId::new(&id))
    {
        active.cancel();
        return Ok((
            axum::http::StatusCode::ACCEPTED,
            Json(json!({"run_id":id,"status":"CANCELLATION_REQUESTED","cleanup_confirmed":false})),
        ));
    }
    Ok((
        axum::http::StatusCode::OK,
        Json(json!({"run_id":id,"status":record.status,"evidence":record.evidence})),
    ))
}
