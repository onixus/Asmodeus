//! Durable admission followed by detached execution and terminal audit commit.
use crate::{catalog::ScenarioEntry, run_control::ActiveRun, state::AppState};
use asmodeus_common::{Role, RunId};
use asmodeus_telemetry::{AuditRecord, Measurements, RunEvidence};
use serde_json::{json, Value};

#[derive(Debug, thiserror::Error)]
pub(crate) enum ExecutionError {
    #[error("scenario signature invalid")]
    InvalidSignature,
    #[error("target runner not found or inactive: {0}")]
    TargetNotFound(String),
    #[error("no active runner available")]
    NoActiveRunner,
    #[error("role may not execute this scenario category")]
    Forbidden,
    #[error("invalid execution parameters: {0}")]
    InvalidManifest(String),
    #[error("dispatch: {0}")]
    Dispatch(String),
    #[error("runner rejected: {0}")]
    RunnerRejected(String),
    #[error("runner ended without a confirmed terminal result: {0}")]
    RunnerIncomplete(String),
    #[error("audit signing: {0}")]
    AuditSigning(String),
    #[error("audit persistence: {0}")]
    AuditPersistence(String),
}

type Outcome = Result<(RunId, Value, AuditRecord), ExecutionError>;
pub struct StartedRun {
    pub id: RunId,
    pub completion: tokio::task::JoinHandle<Outcome>,
}

#[cfg(test)]
pub(crate) async fn execute_single_scenario(
    state: &AppState,
    entry: &ScenarioEntry,
    role: Role,
    target: Option<&str>,
) -> Outcome {
    let started = start_scenario(state, entry, role, target, None).await?;
    started
        .completion
        .await
        .map_err(|e| ExecutionError::Dispatch(e.to_string()))?
}

pub(crate) async fn start_scenario(
    state: &AppState,
    entry: &ScenarioEntry,
    role: Role,
    target: Option<&str>,
    timeout_sec: Option<u32>,
) -> Result<StartedRun, ExecutionError> {
    if !role.can(entry.category.required_capability()) {
        return Err(ExecutionError::Forbidden);
    }
    if !asmodeus_crypto::is_valid(
        &entry.manifest,
        &entry.signature,
        state.catalog.public_key(),
    ) {
        return Err(ExecutionError::InvalidSignature);
    }
    let manifest = std::str::from_utf8(&entry.manifest)
        .map_err(|e| ExecutionError::InvalidManifest(e.to_string()))?;
    let manifest = asmodeus_dsl::parse_and_validate_manifest(manifest)
        .map_err(|e| ExecutionError::InvalidManifest(e.to_string()))?;
    let plan = asmodeus_dsl::ExecutionPlan::from_manifest(&manifest)
        .map_err(|e| ExecutionError::InvalidManifest(e.to_string()))?;
    let timeout = timeout_sec.unwrap_or(plan.max_duration_sec);
    if timeout == 0 || timeout > plan.max_duration_sec {
        return Err(ExecutionError::InvalidManifest(
            "timeout_sec must be positive and cannot extend the signed deadline".into(),
        ));
    }
    let selected = state.registry.find_for_target(target);
    let explicit = target.map(str::trim).filter(|s| !s.is_empty());
    if let Some(target) = explicit {
        if selected.is_none() {
            return Err(ExecutionError::TargetNotFound(target.into()));
        }
    }
    if selected.is_none() && !state.registry.is_empty() {
        return Err(ExecutionError::NoActiveRunner);
    }
    let endpoint = selected
        .as_ref()
        .map(|r| r.endpoint.clone())
        .or_else(|| state.runner_endpoint.clone());
    let mode = if endpoint.is_some() {
        "runner"
    } else {
        "simulated"
    };
    let runner_id = selected.map(|r| r.id).unwrap_or_else(|| {
        if endpoint.is_some() {
            "default-runner".into()
        } else {
            "in-process-sim".into()
        }
    });
    let id = state.next_run_id();
    let record = AuditRecord {
        run_id: id.to_string(),
        scenario_id: entry.id.clone(),
        scenario_name: entry.name.clone(),
        category: entry.category.as_str().into(),
        mitre_technique: entry.mitre.map(|m| m.id.into()).unwrap_or_default(),
        mitre_tactic: entry.mitre.map(|m| m.tactic.into()).unwrap_or_default(),
        severity: entry.severity.clone(),
        tag: entry.category.tag().into(),
        initiator: role.as_str().into(),
        runner_id,
        status: "QUEUED".into(),
        measurements: Measurements::default(),
        detection_source: "PENDING_FEEDBACK".into(),
        containment_action: "UNCONFIRMED".into(),
        cleanup_status: "PENDING".into(),
        timestamp_utc: asmodeus_telemetry::current_utc_iso8601(),
        signature_hex: String::new(),
        public_key_hex: String::new(),
        evidence: Some(RunEvidence {
            execution_mode: mode.into(),
            ..RunEvidence::default()
        }),
    }
    .sign(&state.signing_key)
    .map_err(|e| ExecutionError::AuditSigning(e.to_string()))?;
    let state = state.clone();
    let entry = entry.clone();
    let active = ActiveRun::new(entry.category);
    let worker_id = id.clone();
    let (admitted_tx, admitted_rx) = tokio::sync::oneshot::channel();
    let completion = tokio::spawn(async move {
        // The worker owns admission too: a dropped HTTP request cannot orphan
        // a queued durable record between append and spawning execution.
        state
            .audit
            .append(record.clone())
            .await
            .map_err(|e| ExecutionError::AuditPersistence(e.to_string()))?;
        state
            .runs
            .lock()
            .unwrap()
            .insert(worker_id.clone(), active.clone());
        let _ = admitted_tx.send(());
        lifecycle(&state, "exercise_started", &record);
        let result = if let Some(ref endpoint) = endpoint {
            let request = asmodeus_proto::ExecuteRequest {
                scenario_id: entry.id.clone(),
                manifest: entry.manifest.clone(),
                signature: entry.signature.clone(),
                public_key: state.catalog.public_key().to_vec(),
                target_dir: plan.target_dir,
                file_count: plan.file_count,
                chunk_size_kb: plan.chunk_size_kb,
                run_id: worker_id.to_string(),
                timeout_sec: timeout,
            };
            let tls = asmodeus_proto::tls::client_from_env("asmodeus-runner")
                .map_err(|e| tonic::Status::internal(e.to_string()));
            match tls {
                Ok(tls) => {
                    crate::dispatch::dispatch_controlled(
                        endpoint,
                        request,
                        tls,
                        std::time::Duration::from_secs(u64::from(timeout) + 10),
                        active.clone(),
                    )
                    .await
                }
                Err(e) => Err(e),
            }
        } else {
            *active.status.lock().unwrap() = "INJECTING".into();
            let start = tokio::time::Instant::now();
            let duration = std::time::Duration::from_millis(plan.duration_ms.into());
            let mut status = "COMPLETED";
            loop {
                if active.cancel.load(std::sync::atomic::Ordering::Acquire) {
                    status = "CANCELLED";
                    break;
                }
                if start.elapsed() >= std::time::Duration::from_secs(timeout.into()) {
                    status = "TIMED_OUT";
                    break;
                }
                if start.elapsed() >= duration {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            Ok(crate::dispatch::DispatchOutcome {
                terminal: true,
                completed: status == "COMPLETED",
                final_state: status.into(),
                ..Default::default()
            })
        };
        let (status, cleaned, detail, execution, error, simulated) = match result {
            Ok(out) => {
                let error = if let Some(reason) = out.rejected.clone() {
                    Some(ExecutionError::RunnerRejected(reason))
                } else if !out.terminal
                    || (mode == "runner" && out.completed && !out.cleanup_confirmed)
                {
                    Some(ExecutionError::RunnerIncomplete(out.final_state.clone()))
                } else {
                    None
                };
                let status = if error.is_some() {
                    "FAILED".into()
                } else {
                    out.final_state.clone()
                };
                (
                    status,
                    out.cleanup_confirmed,
                    out.detail,
                    json!({"mode":mode,"runner_endpoint":endpoint,"runner_id":record.runner_id,"files_created":out.files_created,"bytes_written":out.bytes_written,"inject_ms":out.inject_ms,"runner_final_state":out.final_state,"backend_simulated":out.simulated}),
                    error,
                    out.simulated,
                )
            }
            Err(error) => (
                "FAILED".into(),
                false,
                error.to_string(),
                json!({"mode":mode}),
                Some(ExecutionError::Dispatch(error.to_string())),
                mode == "simulated",
            ),
        };
        let key = state.signing_key;
        let saved = state
            .audit
            .update(worker_id.to_string(), move |mut record| {
                record.status = status;
                record.cleanup_status = if mode == "simulated" {
                    "NOT_APPLICABLE"
                } else if cleaned {
                    "SUCCESS"
                } else {
                    "UNCONFIRMED"
                }
                .into();
                if let Some(evidence) = &mut record.evidence {
                    if simulated {
                        evidence.execution_mode = "simulated".into();
                    }
                    evidence.cleanup_confirmed = cleaned;
                    evidence.failure_reason = (!detail.is_empty()).then_some(detail);
                }
                record.timestamp_utc = asmodeus_telemetry::current_utc_iso8601();
                record.sign(&key).map_err(std::io::Error::other)
            })
            .await;
        if saved.is_ok() {
            state.runs.lock().unwrap().remove(&worker_id);
        } else {
            *active.status.lock().unwrap() = "AUDIT_PERSISTENCE_FAILED".into();
        }
        let record = saved
            .map_err(|e| ExecutionError::AuditPersistence(e.to_string()))?
            .ok_or_else(|| ExecutionError::AuditPersistence("admitted run disappeared".into()))?;
        lifecycle(
            &state,
            if record.status == "COMPLETED" {
                "exercise_completed"
            } else {
                "exercise_finished"
            },
            &record,
        );
        if let Some(error) = error {
            return Err(error);
        }
        Ok((worker_id, execution, record))
    });
    if admitted_rx.await.is_err() {
        return match completion.await {
            Ok(Err(error)) => Err(error),
            _ => Err(ExecutionError::AuditPersistence(
                "run admission failed".into(),
            )),
        };
    }
    Ok(StartedRun { id, completion })
}

fn lifecycle(state: &AppState, event: &str, record: &AuditRecord) {
    state.webhook.dispatch(
        crate::webhook::WebhookPayload {
            event: event.into(),
            timestamp_utc: record.timestamp_utc.clone(),
            exercise_id: record.run_id.clone(),
            scenario_id: record.scenario_id.clone(),
            mitre_technique: record.mitre_technique.clone(),
            target: record.runner_id.clone(),
            initiator: record.initiator.clone(),
            tag: record.tag.clone(),
            data: json!({"status":record.status,"evidence":record.evidence}),
        },
        Some(&state.signing_key),
    );
}
