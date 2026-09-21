//! HTTP handlers for scenario catalog, execution, validation and emergency abort.

use std::collections::HashMap;

use asmodeus_common::Category;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde_json::{json, Value};

use crate::api::{caller_role, ApiError};
use crate::dto::RunScenarioPayload;
use crate::execution::execute_single_scenario;
use crate::state::AppState;

pub(crate) async fn run_scenario(
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

pub(crate) async fn list_scenarios(
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

pub(crate) async fn get_scenario(
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

pub(crate) async fn mitre_matrix(
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

pub(crate) async fn abort_all(
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

pub(crate) async fn validate_scenario_manifest(
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
