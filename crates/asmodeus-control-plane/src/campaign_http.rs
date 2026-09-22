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
use crate::execution::start_scenario;
use crate::state::AppState;

pub(crate) async fn register_campaign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut campaign): Json<crate::campaign::Campaign>,
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

    campaign.steps.sort_by_key(|step| step.order);
    for (i, step) in campaign.steps.iter().enumerate() {
        if step.order == 0 || (i > 0 && campaign.steps[i - 1].order == step.order) {
            return Err(ApiError::Unprocessable(
                "campaign step order must be positive and unique".into(),
            ));
        }
        let entry = state.catalog.get(&step.scenario_id).ok_or_else(|| {
            ApiError::NotFound(format!("scenario not found: {}", step.scenario_id))
        })?;
        if !role.can(entry.category.required_capability()) {
            return Err(ApiError::Forbidden(
                "role may not register this scenario category",
            ));
        }
    }

    let saved = campaign.clone();
    state
        .campaigns
        .update(move |catalog| {
            catalog.register(saved);
            Ok(())
        })
        .await
        .map_err(|e| ApiError::Internal(format!("campaign persistence: {e}")))?;

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

    let delete_id = id.clone();
    if state
        .campaigns
        .update(move |catalog| Ok(catalog.deregister(&delete_id)))
        .await
        .map_err(|e| ApiError::Internal(format!("campaign persistence: {e}")))?
    {
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

    if payload.background {
        return Err(ApiError::Unprocessable(
            "background campaigns are unsupported; use background scenario runs".into(),
        ));
    }
    for step in &campaign.steps {
        if let Some(entry) = state.catalog.get(&step.scenario_id) {
            if !role.can(entry.category.required_capability()) {
                return Err(ApiError::Forbidden(
                    "role may not execute every campaign category",
                ));
            }
        }
    }

    let mut step_results = Vec::new();
    let mut aggregate = asmodeus_telemetry::Aggregate::default();
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
                    evidence: None,
                });
                break;
            }
        };

        let mut admitted_id = String::new();
        let result = async {
            let started = start_scenario(
                &state,
                entry,
                role,
                payload.target_override.as_deref(),
                payload.timeout_sec,
            )
            .await?;
            admitted_id = started.id.to_string();
            started
                .completion
                .await
                .map_err(|e| crate::execution::ExecutionError::Dispatch(e.to_string()))?
        }
        .await;
        match result {
            Ok((run_id, _exec, audit_rec)) => {
                aggregate.record_run(&audit_rec);

                let completed = audit_rec.status == "COMPLETED";
                step_results.push(crate::campaign::CampaignStepResult {
                    step_order: step.order,
                    scenario_id: step.scenario_id.clone(),
                    run_id: run_id.to_string(),
                    status: audit_rec.status,
                    mttd_ms: audit_rec.measurements.mttd_ms,
                    mttr_ms: audit_rec.measurements.mttr_ms,
                    detected: audit_rec.measurements.blue_team_detected,
                    evidence: audit_rec.evidence,
                });
                if !completed {
                    break;
                }
            }
            Err(_) => {
                step_results.push(crate::campaign::CampaignStepResult {
                    step_order: step.order,
                    scenario_id: step.scenario_id.clone(),
                    run_id: admitted_id,
                    status: "FAILED".to_string(),
                    mttd_ms: 0,
                    mttr_ms: 0,
                    detected: false,
                    evidence: None,
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
    let mean_mttd = aggregate.mean_mttd_ms();
    let mean_mttr = aggregate.mean_mttr_ms();
    let detection_rate_pct = aggregate.detection_rate_pct();
    let recovery_speed_pct = aggregate.recovery_speed_pct();
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
        confirmed_feedback_runs: aggregate.feedback_received,
        simulated_runs: aggregate.simulated_runs,
        pending_feedback_runs: aggregate.pending_feedback,
        timestamp_utc: asmodeus_telemetry::current_utc_iso8601(),
    };

    Ok(Json(json!(result)))
}
