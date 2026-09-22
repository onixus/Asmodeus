//! HTTP handlers for run history, verification and Blue Team feedback.

use asmodeus_common::Role;
use asmodeus_telemetry::{AuditRecord, Measurements};
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
    Ok(Json(json!(record)))
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

    let signing_key = state.signing_key;
    let signed = state
        .audit
        .update(id.clone(), move |old| {
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

            updated.sign(&signing_key).map_err(std::io::Error::other)
        })
        .await
        .map_err(|e| ApiError::Internal(format!("audit feedback: {e}")))?
        .ok_or_else(|| ApiError::NotFound(format!("run not found: {id}")))?;

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
