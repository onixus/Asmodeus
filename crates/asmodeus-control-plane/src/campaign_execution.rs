//! Detached campaign workers. Durable stage intent precedes scenario admission.
use crate::{
    campaign::{CampaignRunResult, CampaignStepResult},
    campaign_run::{
        CampaignRun, ResumeError, CANCELLED, COMPLETED, FAILED, INTERRUPTED, QUEUED, RUNNING,
    },
    execution::start_scenario_identified,
    run_control::CampaignControl,
    state::AppState,
};
use asmodeus_common::{Capability, Role, RunId};
use std::io;

#[derive(Debug, thiserror::Error)]
pub(crate) enum CampaignError {
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Forbidden(&'static str),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Persistence(String),
}

pub(crate) fn authorize(
    state: &AppState,
    run: &CampaignRun,
    role: Role,
) -> Result<(), CampaignError> {
    if !role.can(Capability::RunRedTeam) && !role.can(Capability::InjectChaos) {
        return Err(CampaignError::Forbidden(
            "role may not launch attack campaigns",
        ));
    }
    for step in &run.steps {
        let entry = state.catalog.get(&step.scenario_id).ok_or_else(|| {
            CampaignError::NotFound(format!("scenario not found: {}", step.scenario_id))
        })?;
        if !role.can(entry.category.required_capability()) {
            return Err(CampaignError::Forbidden(
                "role may not execute every campaign category",
            ));
        }
    }
    Ok(())
}

async fn update(
    state: &AppState,
    id: &str,
    change: impl FnOnce(&mut CampaignRun) + Send + 'static,
) -> io::Result<CampaignRun> {
    let id = id.to_owned();
    state
        .campaign_runs
        .update(move |store| {
            let run = store
                .get_mut(&id)
                .ok_or_else(|| io::Error::other("campaign run disappeared"))?;
            change(run);
            run.updated_utc = asmodeus_telemetry::current_utc_iso8601();
            let saved = run.clone();
            store.prune();
            Ok(saved)
        })
        .await
}

/// Consult the signed stage audit inside the serialized campaign transaction.
fn prepare_resume(
    store: &mut crate::campaign_run::CampaignRunStore,
    audit: &crate::audit_store::AuditStore,
    id: &str,
) -> Result<CampaignRun, ResumeError> {
    let current = store.get(id).ok_or(ResumeError::NotFound)?;
    if !matches!(current.status.as_str(), INTERRUPTED | CANCELLED) {
        return Err(ResumeError::NotResumable(current.status.clone()));
    }
    if let Some(last) = current
        .step_results
        .last()
        .filter(|r| r.status != COMPLETED)
    {
        match audit.get(&last.run_id) {
            Some(record) => {
                let simulated = record
                    .evidence
                    .as_ref()
                    .is_some_and(|e| e.execution_mode == "simulated");
                let cleaned =
                    matches!(record.cleanup_status.as_str(), "SUCCESS" | "NOT_APPLICABLE");
                if !record.is_terminal() || (!simulated && !cleaned) {
                    return Err(ResumeError::NotResumable(
                        "stage cleanup is unconfirmed".into(),
                    ));
                }
                if record.status == COMPLETED {
                    // Stage commit won the race with process death; never replay it.
                    let stored = store.get_mut(id).unwrap().step_results.last_mut().unwrap();
                    stored.status = record.status;
                    stored.mttd_ms = record.measurements.mttd_ms;
                    stored.mttr_ms = record.measurements.mttr_ms;
                    stored.detected = record.measurements.blue_team_detected;
                    stored.evidence = record.evidence;
                }
            }
            None if last.status == CANCELLED && last.run_id.is_empty() => {
                // The worker durably recorded cancellation before scenario admission.
            }
            None => {
                return Err(ResumeError::NotResumable(
                    "previous stage audit is unavailable; cannot prove safe retry".into(),
                ))
            }
        }
    }
    store.begin_resume(id)
}

/// The task owns admission and execution even when its HTTP caller disconnects.
pub(crate) async fn launch(
    state: AppState,
    run: CampaignRun,
    role: Role,
    resume: bool,
) -> Result<
    (
        CampaignRun,
        tokio::task::JoinHandle<Result<CampaignRun, CampaignError>>,
    ),
    CampaignError,
> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let worker = tokio::spawn(async move {
        let id = run.id.clone();
        let control = CampaignControl::default();
        {
            let mut controls = state.campaign_controls.lock().unwrap();
            if controls.contains_key(&id) {
                let _ = tx.send(Err(CampaignError::Conflict(
                    "campaign worker already active".into(),
                )));
                return Err(CampaignError::Conflict(
                    "campaign worker already active".into(),
                ));
            }
            controls.insert(id.clone(), control.clone());
        }
        let audit = state.audit.clone();
        let saved = state
            .campaign_runs
            .update(move |store| {
                if resume {
                    Ok(prepare_resume(store, &audit, &run.id))
                } else {
                    store.insert(run.clone());
                    Ok(Ok(run))
                }
            })
            .await;
        let admitted = match saved {
            Ok(Ok(run)) => run,
            other => {
                state.campaign_controls.lock().unwrap().remove(&id);
                let error = match other {
                    Ok(Err(ResumeError::NotFound)) => {
                        CampaignError::NotFound("campaign run not found".into())
                    }
                    Ok(Err(ResumeError::NotResumable(status))) => {
                        CampaignError::Conflict(format!("campaign is {status}; cannot resume"))
                    }
                    Err(e) => CampaignError::Persistence(format!("campaign run persistence: {e}")),
                    _ => unreachable!(),
                };
                let _ = tx.send(Err(error));
                return Err(CampaignError::Persistence(
                    "campaign admission failed".into(),
                ));
            }
        };
        let _ = tx.send(Ok(admitted.clone()));
        let result = execute(&state, admitted, role, &control).await;
        state.campaign_controls.lock().unwrap().remove(&id);
        result.map_err(|e| {
            tracing::error!(campaign_run = id, error = %e, "campaign worker stopped; no further stages admitted");
            CampaignError::Persistence(format!("campaign run persistence: {e}"))
        })
    });
    let admitted = rx
        .await
        .map_err(|e| CampaignError::Persistence(format!("campaign admission: {e}")))??;
    Ok((admitted, worker))
}

fn cancel_scenario(state: &AppState, id: &RunId) {
    if let Some(active) = state.runs.lock().unwrap().get(id) {
        active.cancel();
    }
}

pub(crate) fn request_cancel(state: &AppState, id: &str) -> bool {
    let control = state.campaign_controls.lock().unwrap().get(id).cloned();
    if let Some(control) = control {
        if let Some(run_id) = control.cancel() {
            cancel_scenario(state, &run_id);
        }
        true
    } else {
        false
    }
}

async fn execute(
    state: &AppState,
    mut run: CampaignRun,
    role: Role,
    control: &CampaignControl,
) -> io::Result<CampaignRun> {
    while run.next_step() < run.steps.len() {
        if control.is_cancelled() {
            return update(state, &run.id, |r| r.status = CANCELLED.into()).await;
        }
        let step = run.steps[run.next_step()].clone();
        let scenario_id = state.next_run_id();
        let pending = CampaignStepResult {
            step_order: step.order,
            scenario_id: step.scenario_id.clone(),
            run_id: scenario_id.to_string(),
            status: RUNNING.into(),
            mttd_ms: 0,
            mttr_ms: 0,
            detected: false,
            evidence: None,
        };
        run = update(state, &run.id, move |r| {
            r.status = RUNNING.into();
            r.step_results.push(pending);
        })
        .await?;
        if control.is_cancelled() {
            return update(state, &run.id, |r| {
                r.status = CANCELLED.into();
                r.step_results.last_mut().unwrap().status = CANCELLED.into();
                r.step_results.last_mut().unwrap().run_id.clear();
            })
            .await;
        }
        let outcome = if let Some(entry) = state.catalog.get(&step.scenario_id) {
            match start_scenario_identified(
                state,
                entry,
                role,
                run.target_override.as_deref(),
                run.timeout_sec,
                scenario_id.clone(),
            )
            .await
            {
                Ok(started) => {
                    if control.set_current(Some(scenario_id.clone())) {
                        cancel_scenario(state, &scenario_id);
                    }
                    let result = started.completion.await;
                    control.set_current(None);
                    matches!(result, Ok(Ok(_)))
                }
                Err(_) => false,
            }
        } else {
            false
        };
        let audit = state.audit.get(&scenario_id.to_string());
        let result = CampaignStepResult {
            step_order: step.order,
            scenario_id: step.scenario_id,
            run_id: scenario_id.to_string(),
            status: audit
                .as_ref()
                .map(|r| r.status.clone())
                .unwrap_or_else(|| FAILED.into()),
            mttd_ms: audit.as_ref().map_or(0, |r| r.measurements.mttd_ms),
            mttr_ms: audit.as_ref().map_or(0, |r| r.measurements.mttr_ms),
            detected: audit
                .as_ref()
                .is_some_and(|r| r.measurements.blue_team_detected),
            evidence: audit.and_then(|r| r.evidence),
        };
        // An audit commit failure must not authorize the next stage or resume.
        let terminal = if !outcome && matches!(result.status.as_str(), QUEUED | RUNNING) {
            INTERRUPTED
        } else if result.status == CANCELLED {
            CANCELLED
        } else if result.status != COMPLETED || !outcome {
            FAILED
        } else if control.is_cancelled() {
            CANCELLED
        } else if run.next_step() == run.steps.len() {
            COMPLETED
        } else {
            RUNNING
        };
        run = update(state, &run.id, move |r| {
            *r.step_results.last_mut().unwrap() = result;
            r.status = terminal.into();
        })
        .await?;
        if run.status != RUNNING {
            return Ok(run);
        }
    }
    update(state, &run.id, |r| r.status = COMPLETED.into()).await
}

pub(crate) fn report(state: &AppState, run: &CampaignRun) -> CampaignRunResult {
    let mut aggregate = asmodeus_telemetry::Aggregate::default();
    let mut step_results = run.step_results.clone();
    for step in &mut step_results {
        if let Some(record) = state.audit.get(&step.run_id) {
            // Use the same signed revision for summary and stage feedback.
            // The durable execution checkpoint remains independent of feedback.
            aggregate.record_run(&record);
            step.mttd_ms = record.measurements.mttd_ms;
            step.mttr_ms = record.measurements.mttr_ms;
            step.detected = record.measurements.blue_team_detected;
            step.evidence = record.evidence;
        }
    }
    CampaignRunResult {
        campaign_id: run.campaign_id.clone(),
        campaign_name: run.campaign_name.clone(),
        initiator: run.initiator.clone(),
        target_override: run.target_override.clone(),
        total_steps: run.steps.len(),
        successful_steps: step_results
            .iter()
            .filter(|r| r.status == COMPLETED)
            .count(),
        step_results,
        mean_mttd_ms: aggregate.mean_mttd_ms(),
        mean_mttr_ms: aggregate.mean_mttr_ms(),
        detection_rate_pct: aggregate.detection_rate_pct(),
        recovery_speed_pct: aggregate.recovery_speed_pct(),
        resilience_score: asmodeus_telemetry::resilience_score(
            aggregate.detection_rate_pct(),
            aggregate.recovery_speed_pct(),
        ),
        confirmed_feedback_runs: aggregate.feedback_received,
        simulated_runs: aggregate.simulated_runs,
        pending_feedback_runs: aggregate.pending_feedback,
        timestamp_utc: run.updated_utc.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{campaign::CampaignStep, catalog::Catalog, persistent::Persistent};
    use asmodeus_testkit::Polygon;

    fn run(state: &AppState) -> CampaignRun {
        CampaignRun {
            id: state.next_campaign_run_id(),
            campaign_id: "original".into(),
            campaign_name: "Original".into(),
            initiator: "red_team".into(),
            target_override: None,
            timeout_sec: None,
            steps: vec![
                CampaignStep {
                    order: 1,
                    scenario_id: "RANSOMWARE_CANARY_SPIKE".into(),
                },
                CampaignStep {
                    order: 2,
                    scenario_id: "RANSOMWARE_CANARY_SPIKE".into(),
                },
            ],
            status: QUEUED.into(),
            step_results: vec![],
            superseded_results: vec![],
            resume_count: 0,
            created_utc: String::new(),
            updated_utc: String::new(),
        }
    }

    fn slow_state(polygon: &Polygon) -> AppState {
        std::fs::create_dir_all(polygon.dir()).unwrap();
        let mut catalog = Catalog::seeded();
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&catalog.get("RANSOMWARE_CANARY_SPIKE").unwrap().manifest)
                .unwrap();
        manifest["spec"]["action"]["parameters"]["duration_ms"] = serde_json::json!(150);
        std::fs::write(polygon.dir().join("slow.json"), manifest.to_string()).unwrap();
        catalog.load_from_dir(polygon.dir()).unwrap();
        let mut state = AppState::new(catalog).unwrap();
        state.campaign_runs = Persistent::load(
            Some(polygon.dir().join("campaign_runs.json")),
            Default::default,
        )
        .unwrap();
        state
    }

    #[tokio::test]
    async fn cancelled_campaign_resumes_once_with_new_stage_id_and_snapshotted_plan() {
        let polygon = Polygon::new("campaign-resume");
        let state = slow_state(&polygon);
        let (admitted, worker) = launch(state.clone(), run(&state), Role::RedTeam, false)
            .await
            .unwrap();
        // Observe scenario admission rather than relying on a sleep.
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if !state.runs.lock().unwrap().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(request_cancel(&state, &admitted.id));
        let cancelled = worker.await.unwrap().unwrap();
        assert_eq!(cancelled.status, CANCELLED);
        assert_eq!(cancelled.step_results.len(), 1);
        let previous_id = cancelled.step_results[0].run_id.clone();
        assert_eq!(state.audit.get(&previous_id).unwrap().status, CANCELLED);
        // Editing/deleting definitions does not change this worker's plan.
        state
            .campaigns
            .update(|c| {
                c.deregister("original");
                Ok(())
            })
            .await
            .unwrap();
        let (first, second) = tokio::join!(
            launch(state.clone(), cancelled.clone(), Role::RedTeam, true),
            launch(state.clone(), cancelled, Role::RedTeam, true)
        );
        assert_ne!(first.is_ok(), second.is_ok());
        let (resumed, worker) = first.or(second).unwrap();
        assert_eq!(resumed.resume_count, 1);
        assert_eq!(resumed.superseded_results[0].run_id, previous_id);
        let completed = worker.await.unwrap().unwrap();
        assert_eq!(completed.status, COMPLETED);
        assert_eq!(completed.step_results.len(), 2);
        assert_ne!(completed.step_results[0].run_id, previous_id);
        assert_eq!(state.audit.len(), 3);
        let reloaded: Persistent<crate::campaign_run::CampaignRunStore> = Persistent::load(
            Some(polygon.dir().join("campaign_runs.json")),
            Default::default,
        )
        .unwrap();
        assert_eq!(
            reloaded.read().unwrap().get(&completed.id).unwrap(),
            &completed
        );
    }

    #[tokio::test]
    async fn signed_completed_stage_is_not_repeated_after_snapshot_interruption() {
        let state = AppState::new(Catalog::seeded()).unwrap();
        let initial = run(&state);
        let (_, worker) = launch(state.clone(), initial, Role::RedTeam, false)
            .await
            .unwrap();
        let completed = worker.await.unwrap().unwrap();
        let first_id = completed.step_results[0].run_id.clone();
        let id = completed.id.clone();
        state
            .campaign_runs
            .update(move |store| {
                let saved = store.get_mut(&id).unwrap();
                saved.step_results.truncate(1);
                saved.step_results[0].status = INTERRUPTED.into();
                saved.status = INTERRUPTED.into();
                Ok(())
            })
            .await
            .unwrap();
        let interrupted = state
            .campaign_runs
            .read()
            .unwrap()
            .get(&completed.id)
            .unwrap()
            .clone();
        let (admitted, worker) = launch(state.clone(), interrupted, Role::RedTeam, true)
            .await
            .unwrap();
        assert_eq!(admitted.step_results[0].status, COMPLETED);
        assert!(admitted.superseded_results.is_empty());
        let resumed = worker.await.unwrap().unwrap();
        assert_eq!(resumed.step_results[0].run_id, first_id);
        assert_eq!(state.audit.len(), 3);
    }

    #[tokio::test]
    async fn missing_audit_and_unconfirmed_runner_cleanup_block_resume() {
        let state = AppState::new(Catalog::seeded()).unwrap();
        let (_, worker) = launch(state.clone(), run(&state), Role::RedTeam, false)
            .await
            .unwrap();
        let completed = worker.await.unwrap().unwrap();
        let id = completed.id.clone();
        state
            .campaign_runs
            .update(move |store| {
                let run = store.get_mut(&id).unwrap();
                run.status = INTERRUPTED.into();
                run.step_results.truncate(1);
                run.step_results[0].status = INTERRUPTED.into();
                run.step_results[0].run_id = "missing".into();
                Ok(())
            })
            .await
            .unwrap();
        let saved = state
            .campaign_runs
            .read()
            .unwrap()
            .get(&completed.id)
            .unwrap()
            .clone();
        assert!(matches!(
            launch(state.clone(), saved, Role::RedTeam, true).await,
            Err(CampaignError::Conflict(_))
        ));
        let scenario_id = completed.step_results[0].run_id.clone();
        let key = state.signing_key;
        state
            .audit
            .update(scenario_id.clone(), move |mut record| {
                record.status = INTERRUPTED.into();
                record.cleanup_status = "UNCONFIRMED".into();
                record.evidence.as_mut().unwrap().execution_mode = "runner".into();
                record.sign(&key).map_err(io::Error::other)
            })
            .await
            .unwrap();
        let id = completed.id;
        state
            .campaign_runs
            .update(move |store| {
                store.get_mut(&id).unwrap().step_results[0].run_id = scenario_id;
                Ok(())
            })
            .await
            .unwrap();
        let saved = state
            .campaign_runs
            .read()
            .unwrap()
            .list(None, None, None)
            .pop()
            .unwrap();
        assert!(matches!(
            launch(state.clone(), saved, Role::RedTeam, true).await,
            Err(CampaignError::Conflict(_))
        ));
        assert_eq!(state.audit.len(), 2);
    }

    #[tokio::test]
    async fn failed_campaign_snapshot_never_admits_a_scenario() {
        let polygon = Polygon::new("campaign-failed-storage");
        let state = slow_state(&polygon);
        std::fs::create_dir(polygon.dir().join("campaign_runs.json")).unwrap();
        assert!(launch(state.clone(), run(&state), Role::RedTeam, false)
            .await
            .is_err());
        assert_eq!(state.audit.len(), 0);
        assert_eq!(state.campaign_runs.read().unwrap().len(), 0);
        assert!(state.campaign_controls.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn dropped_foreground_http_request_keeps_worker_and_partial_report() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;
        let polygon = Polygon::new("campaign-detached-http");
        let state = slow_state(&polygon);
        let app = crate::http::router(state.clone());
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/asmodeus/campaigns/CAMP-RANSOMWARE-CHAIN/run")
            .header("x-apex-role", "red_team")
            .body(Body::empty())
            .unwrap();
        let handler = tokio::spawn(app.oneshot(request));
        let admitted = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(run) = state
                    .campaign_runs
                    .read()
                    .unwrap()
                    .list(None, None, None)
                    .pop()
                {
                    break run;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        handler.abort();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if state
                    .campaign_runs
                    .read()
                    .unwrap()
                    .get(&admitted.id)
                    .unwrap()
                    .status
                    == COMPLETED
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(state.audit.len(), 4);
    }

    #[tokio::test]
    async fn failed_progress_commit_stops_subsequent_stages() {
        let polygon = Polygon::new("campaign-progress-failure");
        let state = slow_state(&polygon);
        let (_, worker) = launch(state.clone(), run(&state), Role::RedTeam, false)
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if !state.runs.lock().unwrap().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let path = polygon.dir().join("campaign_runs.json");
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(worker.await.unwrap().is_err());
        assert_eq!(state.audit.len(), 1);
        assert!(state.campaign_controls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn background_http_history_cancel_resume_and_rbac() {
        use axum::{
            body::{to_bytes, Body},
            http::{Request, StatusCode},
        };
        use serde_json::{json, Value};
        use tower::ServiceExt;
        let polygon = Polygon::new("campaign-http");
        let state = slow_state(&polygon);
        // Put a long scenario first so cancellation has an observable stage.
        state
            .campaigns
            .update(|c| {
                c.register(crate::campaign::Campaign {
                    id: "http".into(),
                    name: "HTTP".into(),
                    description: String::new(),
                    steps: vec![CampaignStep {
                        order: 1,
                        scenario_id: "RANSOMWARE_CANARY_SPIKE".into(),
                    }],
                });
                Ok(())
            })
            .await
            .unwrap();
        let app = crate::http::router(state.clone());
        async fn call(
            app: axum::Router,
            method: &str,
            path: &str,
            role: &str,
            body: Value,
        ) -> (StatusCode, Value) {
            let req = Request::builder()
                .method(method)
                .uri(path)
                .header("x-apex-role", role)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap();
            let response = app.oneshot(req).await.unwrap();
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 1_000_000).await.unwrap();
            (status, serde_json::from_slice(&bytes).unwrap())
        }
        let base = "/api/v1/asmodeus/campaign-runs";
        let (status, admitted) = call(
            app.clone(),
            "POST",
            "/api/v1/asmodeus/campaigns/http/run",
            "red_team",
            json!({"background":true}),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let id = admitted["id"].as_str().unwrap();
        let path = format!("{base}/{id}");
        assert_eq!(
            call(app.clone(), "GET", &path, "auditor", json!(null))
                .await
                .0,
            StatusCode::OK
        );
        for action in ["cancel", "resume"] {
            for role in ["auditor", "ciso", "secops", "devsecops"] {
                assert_eq!(
                    call(
                        app.clone(),
                        "POST",
                        &format!("{path}/{action}"),
                        role,
                        json!(null)
                    )
                    .await
                    .0,
                    StatusCode::FORBIDDEN
                );
            }
        }
        assert_eq!(
            call(
                app.clone(),
                "POST",
                &format!("{path}/cancel"),
                "red_team",
                json!(null)
            )
            .await
            .0,
            StatusCode::ACCEPTED
        );
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if !state.campaign_controls.lock().unwrap().contains_key(id) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            call(
                app.clone(),
                "POST",
                &format!("{path}/resume"),
                "red_team",
                json!(null)
            )
            .await
            .0,
            StatusCode::ACCEPTED
        );
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if !state.campaign_controls.lock().unwrap().contains_key(id) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let (status, details) = call(app.clone(), "GET", &path, "auditor", json!(null)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(details["status"], COMPLETED);
        assert_eq!(details["report"]["successful_steps"], 1);
        assert_eq!(
            call(
                app.clone(),
                "POST",
                &format!("{path}/resume"),
                "red_team",
                json!(null)
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        let (_, history) = call(
            app.clone(),
            "GET",
            &format!("{base}?campaign_id=http&status=completed&limit=1"),
            "auditor",
            json!(null),
        )
        .await;
        assert_eq!(history["returned"], 1);
        assert_eq!(
            call(
                app,
                "GET",
                &format!("{base}/missing"),
                "auditor",
                json!(null)
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
    }
    #[tokio::test]
    async fn global_abort_cancels_queued_campaign_between_stages_with_rbac() {
        use axum::{
            body::Body,
            http::{Request, StatusCode},
        };
        use tower::ServiceExt;
        let state = AppState::new(Catalog::seeded()).unwrap();
        let queued = run(&state);
        let id = queued.id.clone();
        state
            .campaign_runs
            .update(move |store| {
                store.insert(queued);
                Ok(())
            })
            .await
            .unwrap();
        let control = CampaignControl::default();
        state
            .campaign_controls
            .lock()
            .unwrap()
            .insert(id, control.clone());
        let app = crate::http::router(state);
        for role in ["devsecops", "red_team"] {
            let req = Request::builder()
                .method("POST")
                .uri("/api/v1/asmodeus/scenarios/abort")
                .header("x-apex-role", role)
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                app.clone().oneshot(req).await.unwrap().status(),
                StatusCode::OK
            );
            assert_eq!(control.is_cancelled(), role == "red_team");
        }
    }
}
