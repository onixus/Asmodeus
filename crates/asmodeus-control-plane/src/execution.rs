//! Scenario execution application service.
//!
//! Owns the transport-independent critical path shared by REST, campaigns and
//! the background scheduler: signature verification, runner selection,
//! dispatch/simulation, telemetry, signed audit persistence and lifecycle
//! webhooks.

use asmodeus_common::{Category, Role, RunId, RunState};
use asmodeus_telemetry::{AuditRecord, Measurements};
use serde_json::{json, Value};

use crate::engine::{self, EngineError};
use crate::state::AppState;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ExecutionError {
    #[error("scenario signature invalid")]
    InvalidSignature,
    #[error("target runner not found: {0}")]
    TargetNotFound(String),
    #[error("no active runner available")]
    NoActiveRunner,
    #[error("dispatch: {0}")]
    Dispatch(String),
    #[error("runner rejected: {0}")]
    RunnerRejected(String),
    #[error("runner ended without completing (last state: {0})")]
    RunnerIncomplete(String),
    #[error("{0}")]
    EngineRejected(String),
    #[error("{0}")]
    EngineTransition(String),
    #[error("audit signing: {0}")]
    AuditSigning(String),
    #[error("audit persistence: {0}")]
    AuditPersistence(String),
}

pub(crate) async fn execute_single_scenario(
    state: &AppState,
    entry: &crate::catalog::ScenarioEntry,
    role: Role,
    target_override: Option<&str>,
) -> Result<(RunId, Value, AuditRecord), ExecutionError> {
    // Integrity (D6): the catalogued manifest must verify against the trusted key.
    if !asmodeus_crypto::is_valid(
        &entry.manifest,
        &entry.signature,
        state.catalog.public_key(),
    ) {
        return Err(ExecutionError::InvalidSignature);
    }

    // Target resolution. An explicitly requested target must resolve to a
    // registered runner: we never silently fall back to the static default
    // endpoint, otherwise a mistyped or unavailable target would fire the
    // scenario against the wrong runner. The static endpoint is only used when
    // no target was requested at all.
    let explicit_target = target_override.map(str::trim).filter(|t| !t.is_empty());
    let matched_runner = state.registry.find_for_target(target_override);
    let target_endpoint = if let Some(target) = explicit_target {
        match matched_runner.as_ref() {
            Some(runner) => Some(runner.endpoint.clone()),
            None => return Err(ExecutionError::TargetNotFound(target.to_string())),
        }
    } else {
        if matched_runner.is_none() && !state.registry.is_empty() {
            return Err(ExecutionError::NoActiveRunner);
        }
        matched_runner
            .as_ref()
            .map(|r| r.endpoint.clone())
            .or_else(|| state.runner_endpoint.clone())
    };

    let run_id = state.next_run_id();
    state.webhook.dispatch(
        crate::webhook::WebhookPayload {
            event: "exercise_started".into(),
            timestamp_utc: asmodeus_telemetry::current_utc_iso8601(),
            exercise_id: run_id.to_string(),
            scenario_id: entry.id.to_string(),
            mitre_technique: entry.mitre.map(|m| m.id.to_string()).unwrap_or_default(),
            target: target_override.unwrap_or("default").to_string(),
            initiator: role.as_str().to_string(),
            tag: entry.category.tag().to_string(),
            data: json!({
                "scenario_name": entry.name,
                "category": entry.category.as_str(),
            }),
        },
        Some(&state.signing_key),
    );

    // Execute: dispatch to a live runner over gRPC if one is configured,
    // else drive the in-process engine. Detection metrics stay simulated
    // (no live Blue Team wired); the runner reports the real injection stats.
    let (final_state, execution, runner_id_str) = if let Some(endpoint) = target_endpoint {
        let runner_id = matched_runner
            .as_ref()
            .map(|r| r.id.clone())
            .unwrap_or_else(|| "default-runner".into());
        let req = asmodeus_proto::ExecuteRequest {
            scenario_id: entry.id.to_string(),
            manifest: entry.manifest.clone(),
            signature: entry.signature.clone(),
            public_key: state.catalog.public_key().to_vec(),
            target_dir: entry.target_path.clone(),
            file_count: entry.file_count,
            chunk_size_kb: entry.chunk_size_kb,
        };
        let out = crate::dispatch::dispatch(&endpoint, req)
            .await
            .map_err(|s| ExecutionError::Dispatch(s.to_string()))?;
        if let Some(reason) = out.rejected {
            return Err(ExecutionError::RunnerRejected(reason));
        }
        if !out.completed {
            // Stream ended without a terminal Completed event: the run did not
            // finish. Never record it as a success.
            return Err(ExecutionError::RunnerIncomplete(out.final_state));
        }
        (
            RunState::Completed,
            json!({
                "mode": "dispatched",
                "runner_id": runner_id,
                "runner_endpoint": endpoint,
                "runner_final_state": out.final_state,
                "files_created": out.files_created,
                "bytes_written": out.bytes_written,
                "inject_ms": out.inject_ms,
            }),
            runner_id,
        )
    } else {
        let outcome = engine::execute(entry).map_err(|e| match e {
            EngineError::Rejected(_) => ExecutionError::EngineRejected(e.to_string()),
            EngineError::Transition(_) => ExecutionError::EngineTransition(e.to_string()),
        })?;
        (
            outcome.final_state,
            json!({ "mode": "simulated" }),
            "in-process-sim".to_string(),
        )
    };

    let raw_record = AuditRecord {
        run_id: run_id.to_string(),
        scenario_id: entry.id.to_string(),
        scenario_name: entry.name.to_string(),
        category: match entry.category {
            Category::RedTeam => "red_team".to_string(),
            Category::Chaos => "chaos".to_string(),
        },
        mitre_technique: entry.mitre.map(|m| m.id.to_string()).unwrap_or_default(),
        mitre_tactic: entry
            .mitre
            .map(|m| m.tactic.to_string())
            .unwrap_or_default(),
        severity: entry.severity.to_string(),
        tag: entry.category.tag().to_string(),
        initiator: role.as_str().to_string(),
        runner_id: runner_id_str,
        status: "COMPLETED".to_string(),
        measurements: Measurements {
            mttd_ms: entry.sim_mttd_ms,
            mttr_ms: entry.sim_mttr_ms,
            blue_team_detected: true,
        },
        detection_source: entry.detector.to_string(),
        containment_action: "SIGKILL via SOAR Policy".to_string(),
        cleanup_status: "SUCCESS (canary removed, 0 host side-effects)".to_string(),
        timestamp_utc: asmodeus_telemetry::current_utc_iso8601(),
        signature_hex: String::new(),
        public_key_hex: String::new(),
    };

    let signed_record = raw_record
        .sign(&state.signing_key)
        .map_err(|e| ExecutionError::AuditSigning(e.to_string()))?;

    state
        .audit
        .append(signed_record.clone())
        .await
        .map_err(|e| ExecutionError::AuditPersistence(e.to_string()))?;
    state
        .runs
        .lock()
        .unwrap()
        .insert(run_id.clone(), final_state);

    state.webhook.dispatch(
        crate::webhook::WebhookPayload {
            event: "exercise_completed".into(),
            timestamp_utc: signed_record.timestamp_utc.clone(),
            exercise_id: signed_record.run_id.clone(),
            scenario_id: entry.id.to_string(),
            mitre_technique: signed_record.mitre_technique.clone(),
            target: target_override.unwrap_or("default").to_string(),
            initiator: role.as_str().to_string(),
            tag: entry.category.tag().to_string(),
            data: json!({
                "status": signed_record.status,
                "mttd_ms": signed_record.measurements.mttd_ms,
                "mttr_ms": signed_record.measurements.mttr_ms,
                "runner_id": signed_record.runner_id,
            }),
        },
        Some(&state.signing_key),
    );

    Ok((run_id, execution, signed_record))
}
