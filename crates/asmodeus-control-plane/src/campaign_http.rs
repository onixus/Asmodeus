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
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let role = caller_role(&headers)?;
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
    let now = asmodeus_telemetry::current_utc_iso8601();
    let run = crate::campaign_run::CampaignRun {
        id: state.next_campaign_run_id(),
        campaign_id: campaign.id,
        campaign_name: campaign.name,
        initiator: role.as_str().into(),
        target_override: payload.target_override,
        timeout_sec: payload.timeout_sec,
        steps: campaign.steps,
        status: crate::campaign_run::QUEUED.into(),
        step_results: Vec::new(),
        superseded_results: Vec::new(),
        resume_count: 0,
        created_utc: now.clone(),
        updated_utc: now,
    };
    crate::campaign_execution::authorize(&state, &run, role)?;
    let (admitted, worker) =
        crate::campaign_execution::launch(state.clone(), run, role, false).await?;
    if payload.background {
        return Ok((StatusCode::ACCEPTED, Json(json!(admitted))));
    }
    let finished = worker
        .await
        .map_err(|e| ApiError::Internal(format!("campaign worker: {e}")))??;
    let mut report = json!(crate::campaign_execution::report(&state, &finished));
    report["id"] = json!(finished.id);
    report["status"] = json!(finished.status);
    Ok((StatusCode::OK, Json(report)))
}

#[derive(serde::Deserialize, Default)]
pub(crate) struct ListCampaignRunsQuery {
    limit: Option<usize>,
    campaign_id: Option<String>,
    status: Option<String>,
}

pub(crate) async fn list_campaign_runs(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<ListCampaignRunsQuery>,
) -> Result<Json<Value>, ApiError> {
    if !caller_role(&headers)?.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view campaign runs"));
    }
    let store = state.campaign_runs.read().unwrap();
    let runs = store.list(
        query.limit,
        query.campaign_id.as_deref(),
        query.status.as_deref(),
    );
    Ok(Json(
        json!({"total": store.len(), "returned": runs.len(), "runs": runs}),
    ))
}

fn get_campaign_run(
    state: &AppState,
    id: &str,
) -> Result<crate::campaign_run::CampaignRun, ApiError> {
    state
        .campaign_runs
        .read()
        .unwrap()
        .get(id)
        .cloned()
        .ok_or_else(|| ApiError::NotFound(format!("campaign run not found: {id}")))
}

pub(crate) async fn campaign_run_details(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    if !caller_role(&headers)?.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view campaign runs"));
    }
    let run = get_campaign_run(&state, &id)?;
    let report = crate::campaign_execution::report(&state, &run);
    let mut value = json!(run);
    value["step_results"] = json!(report.step_results);
    value["worker_active"] = json!(state.campaign_controls.lock().unwrap().contains_key(&id));
    value["report"] = json!(report);
    Ok(Json(value))
}

pub(crate) async fn cancel_campaign_run(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let role = caller_role(&headers)?;
    let run = get_campaign_run(&state, &id)?;
    crate::campaign_execution::authorize(&state, &run, role)?;
    if crate::campaign_execution::request_cancel(&state, &id) {
        Ok((
            StatusCode::ACCEPTED,
            Json(json!({"id": id, "status": "CANCELLATION_REQUESTED", "cleanup_confirmed": false})),
        ))
    } else {
        Ok((StatusCode::OK, Json(json!(run))))
    }
}

pub(crate) async fn resume_campaign_run(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let role = caller_role(&headers)?;
    let run = get_campaign_run(&state, &id)?;
    crate::campaign_execution::authorize(&state, &run, role)?;
    let (admitted, _worker) = crate::campaign_execution::launch(state, run, role, true).await?;
    Ok((StatusCode::ACCEPTED, Json(json!(admitted))))
}
