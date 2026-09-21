//! HTTP handlers for attack campaign management and execution.

use asmodeus_common::Role;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::{json, Value};

use crate::api::{caller_role, ApiError};
use crate::dto::RunScenarioPayload;
use crate::execution::execute_single_scenario;
use crate::state::AppState;

pub(crate) async fn register_campaign(
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

pub(crate) async fn delete_campaign(
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

pub(crate) async fn list_campaigns(
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

pub(crate) async fn run_campaign(
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
