//! S03 validation feedback and versioned observation export.
//! The legacy `POST /runs/:id/feedback` route is unchanged.

use asmodeus_common::Role;
use asmodeus_dsl::{procedure_corpus, ProcedureDefinition, ATTACK_VERSION};
use asmodeus_telemetry::{
    claim_signing_bytes, current_utc_iso8601, export_observations, export_page_json, AdmitResult,
    Applicability, AttemptBinding, FeedbackClaim, ObservationFidelity, Producer, TelemetryState,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use crate::api::{caller_role, ApiError};
use crate::audit_store::RevisionUpdate;
use crate::campaign_acceptance::{
    acceptance_from_audit, artifact_digest, catalog_digest, config_digest, expected_policy_digest,
};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    pub cursor: Option<String>,
    pub limit: Option<usize>,
    pub format: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationFeedbackBody {
    pub tenant_id: String,
    pub asset_ref: String,
    pub environment_ref: String,
    pub attempt_id: String,
    pub procedure_id: String,
    pub procedure_revision: u32,
    pub idempotency_key: String,
    pub observed_at: String,
    pub occurred_at: String,
    pub expires_at: String,
    pub fidelity: ObservationFidelity,
    pub applicability: Applicability,
    #[serde(default)]
    pub applicability_reason: Option<String>,
    pub telemetry: TelemetryState,
    #[serde(default)]
    pub sensor_healthy: bool,
    #[serde(default = "default_true")]
    pub feedback_present: bool,
    #[serde(default)]
    pub queue_loss: bool,
    #[serde(default)]
    pub timed_out: bool,
    #[serde(default)]
    pub detected: Option<bool>,
    #[serde(default)]
    pub prevention_claimed: bool,
    #[serde(default)]
    pub detect_then_kill: bool,
    #[serde(default)]
    pub contained: Option<bool>,
    pub policy_digest: String,
    #[serde(default)]
    pub technique_id: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub procedure_failed: bool,
    #[serde(default)]
    pub cleanup_failed: bool,
    #[serde(default)]
    pub run_interrupted: bool,
    #[serde(default)]
    pub producer_signature_hex: Option<String>,
    #[serde(default)]
    pub producer_public_key_hex: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Procedure identity is the corpus entry named by `scenario_id`. A scenario
/// that is not one of the six slots, or whose recorded technique disagrees,
/// has no procedure binding. The attempt window is still taken from the first
/// feedback: the audit record does not store it.
fn procedure_for_run(record: &asmodeus_telemetry::AuditRecord) -> Option<ProcedureDefinition> {
    let procedure = procedure_corpus()
        .procedures
        .into_iter()
        .find(|item| item.id == record.scenario_id)?;
    if !record.mitre_technique.is_empty() && record.mitre_technique != procedure.technique_id {
        return None;
    }
    Some(procedure)
}

fn server_tenant() -> String {
    std::env::var("ASMODEUS_TENANT_ID").unwrap_or_else(|_| "apex-lab".into())
}

fn commit_sha() -> String {
    std::env::var("ASMODEUS_COMMIT_SHA")
        .ok()
        .filter(|value| asmodeus_telemetry::is_commit_sha(value))
        .unwrap_or_else(|| "0".repeat(40))
}

pub(crate) async fn submit_validation(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ValidationFeedbackBody>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let role = caller_role(&headers)?;
    if matches!(role, Role::Ciso | Role::Auditor) {
        return Err(ApiError::Forbidden(
            "role may not submit validation feedback",
        ));
    }
    let _ignored_embedded_key = body.producer_public_key_hex.as_deref();
    let tenant = server_tenant();
    let outcome = Arc::new(Mutex::new(None));
    let outcome_slot = outcome.clone();
    let signing_key = state.signing_key;
    let trusted_key = state.audit_public_key;
    let run_id = id.clone();
    state
        .audit
        .revise(run_id.clone(), move |mut old| {
            if !old.is_terminal() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "validation feedback requires a terminal execution result",
                ));
            }
            if !old.verify_with_key(&trusted_key) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "untrusted audit record",
                ));
            }
            let binding = if let Some(ext) = &old.validation {
                ext.binding.clone()
            } else if let Some(procedure) = procedure_for_run(&old) {
                AttemptBinding {
                    tenant_id: tenant.clone(),
                    environment_ref: body.environment_ref.clone(),
                    asset_ref: body.asset_ref.clone(),
                    run_id: run_id.clone(),
                    attempt_id: body.attempt_id.clone(),
                    procedure_id: procedure.id,
                    procedure_revision: procedure.revision,
                    technique_id: procedure.technique_id,
                    occurred_at: body.occurred_at.clone(),
                    expires_at: body.expires_at.clone(),
                }
            } else {
                *outcome_slot.lock().unwrap() = Some(AdmitResult::Invalid(
                    "run has no procedure binding".into(),
                ));
                return Ok(RevisionUpdate::Keep);
            };
            let mut claim = claim_from_body(&body, &binding, &tenant);
            if body.producer_signature_hex.is_some() {
                let honest = claim.clone();
                let presented = body.producer_signature_hex.as_deref().unwrap_or("");
                let ok = presented_signature_ok(&honest, presented, &trusted_key);
                claim.trusted = ok;
                claim.forged = !ok;
            }
            let result =
                asmodeus_telemetry::admit(&binding, &claim, old.validation.as_ref(), &signing_key);
            let write = match &result {
                AdmitResult::Admitted(ext) => {
                    old.validation = Some(ext.clone());
                    old.timestamp_utc = current_utc_iso8601();
                    let signed = old.sign(&signing_key).map_err(std::io::Error::other)?;
                    RevisionUpdate::Store(signed)
                }
                AdmitResult::Duplicate(_)
                | AdmitResult::Replay
                | AdmitResult::Unlinked(_)
                | AdmitResult::Invalid(_) => RevisionUpdate::Keep,
            };
            *outcome_slot.lock().unwrap() = Some(result);
            Ok(write)
        })
        .await
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::InvalidInput {
                ApiError::Unprocessable(err.to_string())
            } else {
                ApiError::Internal(format!("validation feedback: {err}"))
            }
        })?
        .ok_or_else(|| ApiError::NotFound(format!("run not found: {id}")))?;
    let result = outcome
        .lock()
        .unwrap()
        .take()
        .ok_or_else(|| ApiError::Internal("validation outcome missing".into()))?;
    let (status, value) = match result {
        AdmitResult::Admitted(ext) => (
            StatusCode::OK,
            json!({
                "status": "ADMITTED",
                "passed": ext.observation.dimensions.any_passed(),
                "observation": ext.observation,
                "mttd": ext.mttd,
            }),
        ),
        AdmitResult::Duplicate(observation) => (
            StatusCode::OK,
            json!({
                "status": "DUPLICATE",
                "passed": observation.dimensions.any_passed(),
                "observation": observation,
            }),
        ),
        AdmitResult::Replay => (
            StatusCode::CONFLICT,
            json!({"status": "REPLAY", "passed": false, "observation": Value::Null}),
        ),
        AdmitResult::Unlinked(decision) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            json!({
                "status": "UNLINKED",
                "passed": decision.any_passed(),
                "correlation": decision.correlation.code(),
                "limitations": decision.limitations,
                "observation": Value::Null,
            }),
        ),
        AdmitResult::Invalid(reason) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            json!({"status": "INVALID", "passed": false, "error": reason}),
        ),
    };
    Ok((status, Json(value)))
}

pub(crate) async fn list_observations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ExportQuery>,
) -> Result<Response, ApiError> {
    if !caller_role(&headers)?.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden(
            "role may not export validation observations",
        ));
    }
    let page = export_observations(
        &state.audit.records(),
        &state.audit_public_key,
        query.cursor.as_deref(),
        query.limit,
    );
    Ok(Json(
        serde_json::from_str::<Value>(&export_page_json(&page))
            .map_err(|err| ApiError::Internal(err.to_string()))?,
    )
    .into_response())
}

pub(crate) async fn campaign_acceptance_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ExportQuery>,
) -> Result<Response, ApiError> {
    if !caller_role(&headers)?.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view campaign acceptance"));
    }
    let report = acceptance_from_audit(&state.audit.records(), &state.audit_public_key);
    if query.format.as_deref() == Some("markdown") {
        Ok((
            StatusCode::OK,
            [("content-type", "text/markdown; charset=utf-8")],
            report.to_markdown(),
        )
            .into_response())
    } else {
        Ok(Json(json!({
            "report": report,
            "manifest": serde_json::from_str::<Value>(&report.manifest_json()).unwrap_or(Value::Null),
        }))
        .into_response())
    }
}

fn claim_from_body(
    body: &ValidationFeedbackBody,
    binding: &AttemptBinding,
    tenant: &str,
) -> FeedbackClaim {
    let server_catalog = catalog_digest();
    let policy_stale = body.policy_digest != expected_policy_digest();
    FeedbackClaim {
        tenant_id: body.tenant_id.clone(),
        environment_ref: body.environment_ref.clone(),
        asset_ref: body.asset_ref.clone(),
        run_id: binding.run_id.clone(),
        attempt_id: body.attempt_id.clone(),
        procedure_id: body.procedure_id.clone(),
        procedure_revision: body.procedure_revision,
        technique_id: body.technique_id.clone(),
        idempotency_key: body.idempotency_key.clone(),
        observed_at: body.observed_at.clone(),
        fidelity: body.fidelity,
        applicability: body.applicability,
        applicability_reason: body.applicability_reason.clone(),
        telemetry: body.telemetry,
        sensor_healthy: body.sensor_healthy,
        feedback_present: body.feedback_present,
        queue_loss: body.queue_loss,
        timed_out: body.timed_out,
        detected: body.detected,
        prevention_claimed: body.prevention_claimed,
        detect_then_kill: body.detect_then_kill,
        contained: body.contained,
        policy_stale,
        cleanup_failed: body.cleanup_failed,
        run_interrupted: body.run_interrupted,
        procedure_unsupported: true,
        procedure_failed: body.procedure_failed,
        trusted: true,
        forged: false,
        evidence_refs: body.evidence_refs.clone(),
        catalog_digest: server_catalog,
        attack_release: ATTACK_VERSION.into(),
        producer: Producer {
            system: "asmodeus".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            commit_sha: commit_sha(),
            artifact_digest: artifact_digest(),
            config_digest: config_digest(tenant),
            policy_digest: body.policy_digest.clone(),
        },
        config_digest: config_digest(tenant),
        artifact_digest: artifact_digest(),
        policy_digest: body.policy_digest.clone(),
        catalog_digest_mismatch: false,
    }
}

fn presented_signature_ok(
    claim: &FeedbackClaim,
    signature_hex: &str,
    trusted_public_key: &[u8],
) -> bool {
    let Some(sig) = decode_hex(signature_hex) else {
        return false;
    };
    asmodeus_crypto::is_valid(&claim_signing_bytes(claim), &sig, trusted_public_key)
}

fn decode_hex(hex_str: &str) -> Option<Vec<u8>> {
    if !hex_str.is_ascii() || !hex_str.len().is_multiple_of(2) {
        return None;
    }
    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::Catalog;
    use crate::http::router;
    use crate::state::AppState;
    use asmodeus_telemetry::{AuditRecord, Measurements, RunEvidence};
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;

    fn terminal(id: &str) -> AuditRecord {
        AuditRecord {
            run_id: id.into(),
            scenario_id: "http-beacon".into(),
            scenario_name: "SCN".into(),
            category: "red_team".into(),
            mitre_technique: "T1071.001".into(),
            mitre_tactic: "Command and Control".into(),
            severity: "medium".into(),
            tag: "exercise".into(),
            initiator: "red_team".into(),
            runner_id: "local".into(),
            status: "COMPLETED".into(),
            measurements: Measurements::default(),
            detection_source: "PENDING_VALIDATION".into(),
            containment_action: "UNCONFIRMED".into(),
            cleanup_status: "PENDING".into(),
            timestamp_utc: "2026-11-11T00:00:00Z".into(),
            signature_hex: String::new(),
            public_key_hex: String::new(),
            evidence: Some(RunEvidence {
                execution_mode: "runner".into(),
                ..RunEvidence::default()
            }),
            validation: None,
        }
    }

    fn payload(extra: Value) -> Value {
        let mut body = json!({
            "tenant_id": "apex-lab",
            "asset_ref": "asset-1",
            "environment_ref": "env-lab",
            "attempt_id": "attempt-http-positive",
            "procedure_id": "http-beacon",
            "procedure_revision": 1,
            "idempotency_key": "idem-http",
            "observed_at": "2026-11-11T00:00:10Z",
            "occurred_at": "2026-11-11T00:00:00Z",
            "expires_at": "2026-11-11T00:05:00Z",
            "fidelity": "behavioral",
            "applicability": "APPLICABLE",
            "telemetry": "AVAILABLE",
            "sensor_healthy": true,
            "feedback_present": true,
            "detected": true,
            "prevention_claimed": true,
            "policy_digest": expected_policy_digest(),
            "technique_id": "T1071.001",
            "evidence_refs": ["/var/lib/host/honeytoken-secret"]
        });
        if let (Some(map), Some(extra)) = (body.as_object_mut(), extra.as_object()) {
            for (key, value) in extra {
                map.insert(key.clone(), value.clone());
            }
        }
        body
    }

    async fn post(app: &axum::Router, id: &str, role: &str, body: Value) -> (StatusCode, Value) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/asmodeus/runs/{id}/validation"))
                    .header("x-apex-role", role)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    #[tokio::test]
    async fn validation_route_rejects_untrusted_inputs_and_exports_stably() {
        let state = AppState::new(Catalog::seeded()).unwrap();
        let signed = terminal("run-val").sign(&state.signing_key).unwrap();
        state.audit.append(signed).await.unwrap();
        let app = router(state);
        let (status, _) = post(&app, "run-val", "auditor", payload(json!({}))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, body) = post(&app, "run-val", "secops", payload(json!({}))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["passed"], false);
        assert_eq!(
            body["observation"]["dimensions"]["validation"],
            "UNSUPPORTED"
        );
        assert_ne!(body["observation"]["dimensions"]["prevention"], "PASSED");
        let rendered = body.to_string();
        assert!(!rendered.contains("honeytoken-secret"));
        assert!(!rendered.contains("/var/lib"));
        let id = body["observation"]["observation_id"].clone();
        assert_eq!(id["kind"], "evidence");
        assert_eq!(id["source"], "asmodeus");
        let urn = id["urn"].as_str().unwrap().to_string();
        assert!(urn.starts_with("urn:apex:evidence:asmodeus:"));
        assert!(body["observation"]["asset_ref"].is_object());
        assert_eq!(body["observation"]["asset_ref"]["kind"], "asset");
        assert!(body["observation"]["environment_ref"]
            .as_str()
            .unwrap()
            .starts_with("urn:apex:environment:"));
        assert!(body["observation"]["supersedes"].is_null());
        assert!(body["observation"]["dimensions"]
            .get("applicability_reason")
            .is_none());

        let (status, again) = post(&app, "run-val", "secops", payload(json!({}))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(again["status"], "DUPLICATE");
        assert_eq!(again["observation"]["observation_id"], id);

        let (status, replay) = post(
            &app,
            "run-val",
            "secops",
            payload(json!({"detected": false})),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{replay}");
        assert_eq!(replay["passed"], false);

        let (status, cross) = post(
            &app,
            "run-val",
            "secops",
            payload(json!({"tenant_id": "other-tenant", "idempotency_key": "idem-cross"})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{cross}");
        assert_eq!(cross["passed"], false);

        let (status, forged) = post(
            &app,
            "run-val",
            "secops",
            payload(json!({
                "idempotency_key": "idem-forged",
                "producer_signature_hex": "abcd",
                "producer_public_key_hex": "ff".repeat(32)
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{forged}");
        assert_eq!(forged["passed"], false);

        async fn export(app: &axum::Router) -> String {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/api/v1/asmodeus/validation/observations?limit=10")
                        .header("x-apex-role", "auditor")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
            String::from_utf8(bytes.to_vec()).unwrap()
        }
        let first = export(&app).await;
        let second = export(&app).await;
        assert_eq!(first, second);
        assert!(first.contains(&urn));
        assert!(!first.contains("honeytoken-secret"));
    }

    #[tokio::test]
    async fn validation_does_not_adopt_a_caller_procedure() {
        let state = AppState::new(Catalog::seeded()).unwrap();
        let mut ransomware = terminal("run-ransom");
        ransomware.scenario_id = "RANSOMWARE_CANARY_SPIKE".into();
        ransomware.mitre_technique = "T1486".into();
        state
            .audit
            .append(ransomware.sign(&state.signing_key).unwrap())
            .await
            .unwrap();
        state
            .audit
            .append(terminal("run-beacon").sign(&state.signing_key).unwrap())
            .await
            .unwrap();
        let app = router(state);

        let (status, foreign) = post(
            &app,
            "run-ransom",
            "secops",
            payload(json!({
                "procedure_id": "dns-pattern",
                "technique_id": "T1071.004",
                "idempotency_key": "idem-dns"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{foreign}");
        assert_eq!(foreign["status"], "INVALID");
        assert!(foreign["observation"].is_null());

        let (status, mismatch) = post(
            &app,
            "run-beacon",
            "secops",
            payload(json!({
                "procedure_id": "dns-pattern",
                "technique_id": "T1071.004",
                "idempotency_key": "idem-dns-beacon"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{mismatch}");
        assert_eq!(mismatch["status"], "UNLINKED");
        assert_eq!(mismatch["passed"], false);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/asmodeus/reports/campaign-acceptance")
                    .header("x-apex-role", "auditor")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let report: Value = serde_json::from_slice(&bytes).unwrap();
        let dns = report["report"]["slots"]
            .as_array()
            .unwrap()
            .iter()
            .find(|slot| slot["procedure_id"] == "dns-pattern")
            .unwrap();
        assert_eq!(dns["observed"], "NOT_OBSERVED");
        assert_ne!(dns["detected"], "PASSED");
    }
}
