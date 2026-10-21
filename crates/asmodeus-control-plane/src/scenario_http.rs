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
use crate::execution::start_scenario;
use crate::state::AppState;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

pub(crate) async fn run_scenario(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
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

    let started = start_scenario(
        &state,
        entry,
        role,
        payload.target_override.as_deref(),
        payload.timeout_sec,
    )
    .await?;
    if payload.background {
        return Ok((StatusCode::ACCEPTED, Json(json!({ "run_id":started.id.to_string(), "status":"QUEUED", "status_url":format!("/api/v1/asmodeus/runs/{}", started.id) }))).into_response());
    }
    let (run_id, execution, audit_rec) = started
        .completion
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))??;

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
        "evidence": audit_rec.evidence,
        "signature_hex": audit_rec.signature_hex,
        "public_key_hex": audit_rec.public_key_hex,
    }))
    .into_response())
}

/// Inspect the fixed procedure corpus; availability is planning metadata only.
/// This handler does not admit or execute procedure runs.
pub(crate) async fn list_procedures(
    headers: HeaderMap,
) -> Result<Json<asmodeus_dsl::ProcedureCorpus>, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view procedures"));
    }
    Ok(Json(asmodeus_dsl::procedure_corpus()))
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
                // S01: fidelity flag so a marker-only scenario is visible as
                // such and cannot be read as behavioural coverage.
                "fidelity": entry.fidelity.as_str(),
                "claims_behavioral_coverage": entry.claims_behavioral_coverage(),
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

    // S01: full technique mapping with per-technique fidelity.
    let technique_refs: Vec<Value> = entry
        .technique_refs
        .iter()
        .map(|r| {
            let t = asmodeus_dsl::lookup_technique(&r.technique_id);
            json!({
                "technique_id": r.technique_id,
                "technique_name": t.map(|t| t.name),
                "tactic": t.map(|t| t.tactic),
                "tactics": t.map(|t| t.tactics),
                "fidelity": r.fidelity.as_str(),
            })
        })
        .collect();

    // S01: the pinned procedure profile (built-in scenarios).
    let profile = entry.profile.as_ref().map(|p| {
        json!({
            "procedure_id": p.procedure_id,
            "procedure_revision": p.procedure_revision,
            "platforms": p.platforms.iter().map(|pl| pl.as_str()).collect::<Vec<_>>(),
            "preconditions": p.preconditions,
            "safety_scope": p.safety_scope,
            "expected_observables": p.expected_observables,
            "limitations": p.limitations,
            "legacy_technique": p.legacy_technique,
        })
    });

    Ok(Json(json!({
        "id": entry.id,
        "name": entry.name,
        "category": match entry.category {
            Category::RedTeam => "red_team",
            Category::Chaos => "chaos",
        },
        "attack_version": asmodeus_dsl::ATTACK_VERSION,
        "mitre_technique": entry.mitre.map(|m| m.id),
        "mitre_tactic": entry.mitre.map(|m| m.tactic),
        "mitre_technique_name": entry.mitre.map(|m| m.name),
        "mitre_description": entry.mitre.map(|m| m.description),
        // S01 honesty fields.
        "fidelity": entry.fidelity.as_str(),
        "fidelity_summary": entry.fidelity.summary(),
        "claims_behavioral_coverage": entry.claims_behavioral_coverage(),
        "technique_refs": technique_refs,
        "profile": profile,
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

    use asmodeus_dsl::Fidelity;

    let mut tactics_map: HashMap<&'static str, Vec<Value>> = HashMap::new();
    // All referenced techniques, and — separately — the best fidelity any
    // scenario exercises each at. "Referenced" is not "covered": a technique is
    // only *behaviourally* covered when some scenario runs it at behavioural
    // fidelity. Marker-only references are recorded but never promoted.
    let mut referenced_techniques: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    let mut best_fidelity: HashMap<String, Fidelity> = HashMap::new();
    let mut mitre_scenarios_count = 0;

    for entry in state.catalog.entries() {
        if entry.technique_refs.is_empty() {
            continue;
        }
        mitre_scenarios_count += 1;
        for r in &entry.technique_refs {
            let Some(t) = asmodeus_dsl::lookup_technique(&r.technique_id) else {
                continue;
            };
            referenced_techniques.insert(r.technique_id.clone());
            let slot = best_fidelity.entry(r.technique_id.clone()).or_default();
            if r.fidelity > *slot {
                *slot = r.fidelity;
            }
            tactics_map.entry(t.tactic).or_default().push(json!({
                "scenario_id": entry.id,
                "scenario_name": entry.name,
                "technique_id": t.id,
                "technique_name": t.name,
                "fidelity": r.fidelity.as_str(),
                // The honest caveat travels with the row.
                "claims_behavioral_coverage": r.fidelity.claims_behavioral(),
                "limitations": entry.profile.as_ref().map(|p| p.limitations.clone()),
                "severity": entry.severity,
                "detector": entry.detector,
            }));
        }
    }

    let behavioral_coverage_count = best_fidelity
        .values()
        .filter(|f| f.claims_behavioral())
        .count();
    let marker_only_techniques_count = referenced_techniques
        .len()
        .saturating_sub(behavioral_coverage_count);

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
        "attack_version": asmodeus_dsl::ATTACK_VERSION,
        "total_scenarios": total_scenarios,
        "mitre_scenarios_count": mitre_scenarios_count,
        // `covered_techniques_count` is retained for backward compatibility and
        // means "techniques *referenced* by a scenario" — it is NOT a claim of
        // behavioural coverage. Use the split fields below for honest coverage.
        "covered_techniques_count": referenced_techniques.len(),
        "techniques_referenced_count": referenced_techniques.len(),
        "behavioral_coverage_count": behavioral_coverage_count,
        "marker_only_techniques_count": marker_only_techniques_count,
        "coverage_note": "A referenced technique is not behavioural coverage. \
             Only `behavioral_coverage_count` techniques are exercised at behavioural \
             fidelity; the rest are marker-only (synthetic indicator) and prove detection \
             of an indicator, not that the technique's behaviour ran or was prevented.",
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
    let runs = state.runs.lock().unwrap();
    let mut requested = Vec::new();
    for (id, active) in runs
        .iter()
        .filter(|(_, active)| role.can(active.category.required_capability()))
    {
        active.cancel();
        requested.push(id.to_string());
    }
    drop(runs);
    // Stop campaign admission as well, including the gap between two stages.
    let campaign_ids: Vec<_> = state
        .campaign_controls
        .lock()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    let mut campaigns = Vec::new();
    for id in campaign_ids {
        let run = state.campaign_runs.read().unwrap().get(&id).cloned();
        if run.is_some_and(|r| crate::campaign_execution::authorize(&state, &r, role).is_ok())
            && crate::campaign_execution::request_cancel(&state, &id)
        {
            campaigns.push(id);
        }
    }
    Ok(Json(
        json!({ "status":"CANCELLATION_REQUESTED", "run_ids":requested, "campaign_run_ids":campaigns, "runs_cleared":0 }),
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
        Ok(manifest) => {
            let refs: Vec<Value> = manifest
                .resolved_technique_refs()
                .into_iter()
                .map(|r| json!({ "technique_id": r.technique_id, "fidelity": r.fidelity.as_str() }))
                .collect();
            Ok(Json(json!({
                "valid": true,
                "manifest_id": manifest.metadata.id,
                "manifest_name": manifest.metadata.name,
                "category": manifest.metadata.category,
                "api_version": manifest.api_version,
                "legacy": manifest.is_legacy(),
                "mitre_technique": manifest.primary_technique().map(|t| t.id),
                // Effective fidelity — a legacy manifest is reported as
                // `unspecified` no matter what it self-declares.
                "fidelity": manifest.effective_fidelity().as_str(),
                "technique_refs": refs,
                "inv_0_compliant": true,
            })))
        }
        Err(e) => Err(ApiError::Unprocessable(e.to_string())),
    }
}
