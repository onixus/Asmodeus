//! Continuous Automated BAS (Breach & Attack Simulation) Scheduler.
//!
//! Manages scheduled, recurring scenario executions to establish detection
//! baselines and detect security posture degradation (MTTD drift).

use std::collections::{HashMap, VecDeque};

use asmodeus_common::Role;
use serde::{Deserialize, Serialize};

/// Upper bound on samples kept per job. Old samples are evicted FIFO so a
/// long-running baseline cannot grow the process heap without limit.
const MAX_HISTORY_PER_JOB: usize = 50;
/// Upper bound on retained drift alerts across all jobs.
const MAX_ALERTS: usize = 200;
/// MTTD ratio (observed / baseline) at or above which detection is considered
/// degraded. Kept in one place so history samples and alerts agree.
const DRIFT_THRESHOLD: f32 = 1.5;

/// Scheduled BAS exercise job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledJob {
    pub id: String,
    pub name: String,
    pub scenario_id: String,
    pub interval_sec: u64,
    pub role: Role,
    pub target_override: Option<String>,
    pub enabled: bool,
    pub created_at_utc: String,
    pub last_run_utc: Option<String>,
    #[serde(skip_serializing, default)]
    pub last_run_epoch_secs: Option<u64>,
    pub last_status: Option<String>,
    pub last_mttd_ms: Option<u64>,
    pub baseline_mttd_ms: Option<u64>,
    pub drift_detected: bool,
    pub drift_factor: Option<f32>,
    /// Bounded, time-ordered outcome timeline (oldest first). Empty on
    /// deserialization of legacy state.
    #[serde(default)]
    pub run_history: VecDeque<ScheduledRunSample>,
}

/// One recorded outcome of a scheduled run — the observable evidence of
/// detection-capability drift over time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScheduledRunSample {
    pub timestamp_utc: String,
    pub status: String,
    pub mttd_ms: u64,
    pub drift_detected: bool,
    pub drift_factor: Option<f32>,
}

/// A retained detection-drift alert: baseline MTTD was exceeded by at least
/// [`DRIFT_THRESHOLD`], signalling that the Blue Team's detection capability
/// for this scenario has regressed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriftAlert {
    pub seq: u64,
    pub job_id: String,
    pub scenario_id: String,
    pub baseline_mttd_ms: Option<u64>,
    pub observed_mttd_ms: u64,
    pub drift_factor: f32,
    pub timestamp_utc: String,
}

/// DTO for creating a new scheduled job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScheduleRequest {
    pub id: Option<String>,
    pub name: String,
    pub scenario_id: String,
    pub interval_sec: u64,
    pub target_override: Option<String>,
    pub baseline_mttd_ms: Option<u64>,
    pub enabled: Option<bool>,
}

/// In-memory catalog of scheduled BAS jobs plus a bounded detection-drift
/// alert ring.
#[derive(Debug, Clone)]
pub struct ScheduleCatalog {
    jobs: HashMap<String, ScheduledJob>,
    alerts: VecDeque<DriftAlert>,
    alert_seq: u64,
}

impl Default for ScheduleCatalog {
    fn default() -> Self {
        Self::seeded()
    }
}

impl ScheduleCatalog {
    pub fn new() -> Self {
        Self {
            jobs: HashMap::new(),
            alerts: VecDeque::new(),
            alert_seq: 0,
        }
    }

    /// Pre-populated catalog with standard Continuous BAS baseline tasks.
    pub fn seeded() -> Self {
        let mut cat = Self::new();

        cat.register(ScheduledJob {
            id: "SCHED-BASE-RANSOMWARE".into(),
            name: "Continuous Ransomware Canary Baseline".into(),
            scenario_id: "SCN-RT-001".into(),
            interval_sec: 120,
            role: Role::RedTeam,
            target_override: None,
            enabled: true,
            created_at_utc: "2026-09-09T00:00:00Z".into(),
            last_run_utc: None,
            last_run_epoch_secs: None,
            last_status: None,
            last_mttd_ms: None,
            baseline_mttd_ms: Some(200),
            drift_detected: false,
            drift_factor: None,
            run_history: VecDeque::new(),
        });

        cat.register(ScheduledJob {
            id: "SCHED-BASE-C2-BEACON".into(),
            name: "Continuous C2 Beaconing Baseline".into(),
            scenario_id: "SCN-RT-003".into(),
            interval_sec: 180,
            role: Role::RedTeam,
            target_override: None,
            enabled: true,
            created_at_utc: "2026-09-09T00:00:00Z".into(),
            last_run_utc: None,
            last_run_epoch_secs: None,
            last_status: None,
            last_mttd_ms: None,
            baseline_mttd_ms: Some(150),
            drift_detected: false,
            drift_factor: None,
            run_history: VecDeque::new(),
        });

        cat
    }

    pub fn register(&mut self, job: ScheduledJob) {
        self.jobs.insert(job.id.clone(), job);
    }

    pub fn deregister(&mut self, id: &str) -> bool {
        self.jobs.remove(id).is_some()
    }

    pub fn list(&self) -> Vec<ScheduledJob> {
        let mut list: Vec<ScheduledJob> = self.jobs.values().cloned().collect();
        list.sort_by(|a, b| a.id.cmp(&b.id));
        list
    }

    pub fn get(&self, id: &str) -> Option<&ScheduledJob> {
        self.jobs.get(id)
    }

    #[allow(dead_code)]
    pub fn get_mut(&mut self, id: &str) -> Option<&mut ScheduledJob> {
        self.jobs.get_mut(id)
    }

    /// Enable or disable a job. Returns the new `enabled` state, or `None` if
    /// no such job exists.
    pub fn set_enabled(&mut self, id: &str, enabled: bool) -> Option<bool> {
        let job = self.jobs.get_mut(id)?;
        job.enabled = enabled;
        Some(job.enabled)
    }

    /// Retained detection-drift alerts, newest first.
    pub fn alerts(&self) -> Vec<DriftAlert> {
        self.alerts.iter().rev().cloned().collect()
    }

    /// Record outcome of a scheduled run and evaluate MTTD drift. Appends a
    /// bounded history sample and emits a retained [`DriftAlert`] only when
    /// the job enters the degraded state. The returned bool is true only for
    /// that healthy -> degraded transition.
    pub fn record_outcome(
        &mut self,
        id: &str,
        status: &str,
        mttd_ms: u64,
        timestamp_utc: &str,
        epoch_secs: u64,
    ) -> Option<bool> {
        // Mutate the job under a scoped borrow so the alert push below can take
        // a second &mut on `self` (the alert ring is a sibling field).
        let (scenario_id, baseline_mttd_ms, drift_detected, drift_factor, was_drifting) = {
            let job = self.jobs.get_mut(id)?;
            let was_drifting = job.drift_detected;
            job.last_run_utc = Some(timestamp_utc.to_string());
            job.last_run_epoch_secs = Some(epoch_secs);
            job.last_status = Some(status.to_string());
            job.last_mttd_ms = Some(mttd_ms);

            if job.baseline_mttd_ms.is_none() && mttd_ms > 0 {
                job.baseline_mttd_ms = Some(mttd_ms);
            }

            let mut factor = None;
            job.drift_detected = false;
            job.drift_factor = None;
            if let Some(base) = job.baseline_mttd_ms {
                if base > 0 {
                    let f = (mttd_ms as f32) / (base as f32);
                    factor = Some(f);
                    job.drift_factor = Some(f);
                    job.drift_detected = f >= DRIFT_THRESHOLD;
                }
            }

            job.run_history.push_back(ScheduledRunSample {
                timestamp_utc: timestamp_utc.to_string(),
                status: status.to_string(),
                mttd_ms,
                drift_detected: job.drift_detected,
                drift_factor: factor,
            });
            while job.run_history.len() > MAX_HISTORY_PER_JOB {
                job.run_history.pop_front();
            }

            (
                job.scenario_id.clone(),
                job.baseline_mttd_ms,
                job.drift_detected,
                factor,
                was_drifting,
            )
        };

        // Emit one alert when the job ENTERS a degraded state. Repeated
        // degraded samples update the timeline but do not create an alert
        // storm. Once a healthy sample clears drift_detected, a later
        // regression is a new transition and emits a fresh alert.
        if drift_detected && !was_drifting {
            self.alert_seq += 1;
            self.alerts.push_back(DriftAlert {
                seq: self.alert_seq,
                job_id: id.to_string(),
                scenario_id,
                baseline_mttd_ms,
                observed_mttd_ms: mttd_ms,
                drift_factor: drift_factor.unwrap_or_default(),
                timestamp_utc: timestamp_utc.to_string(),
            });
            while self.alerts.len() > MAX_ALERTS {
                self.alerts.pop_front();
            }
        }

        Some(drift_detected && !was_drifting)
    }
}

/// Spawn a background task periodically checking and executing scheduled BAS jobs.
pub fn spawn_scheduler(
    state: crate::state::AppState,
    poll_secs: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(poll_secs.max(5)));
        loop {
            interval.tick().await;

            let now_epoch = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let due_jobs: Vec<ScheduledJob> = {
                let cat = state.schedules.read().unwrap();
                cat.list()
                    .into_iter()
                    .filter(|j| {
                        j.enabled
                            && match j.last_run_epoch_secs {
                                None => true,
                                Some(last) => now_epoch >= last.saturating_add(j.interval_sec),
                            }
                    })
                    .collect()
            };

            for job in due_jobs {
                let entry_opt = state.catalog.get(&job.scenario_id).cloned();
                if let Some(entry) = entry_opt {
                    tracing::info!(
                        job_id = %job.id,
                        scenario_id = %job.scenario_id,
                        "Triggering scheduled BAS baseline execution"
                    );

                    match crate::execution::execute_single_scenario(
                        &state,
                        &entry,
                        job.role,
                        job.target_override.as_deref(),
                    )
                    .await
                    {
                        Ok((_run_id, _exec, audit_rec)) => {
                            let mut cat = state.schedules.write().unwrap();
                            if let Some(drift) = cat.record_outcome(
                                &job.id,
                                &audit_rec.status,
                                audit_rec.measurements.mttd_ms,
                                &audit_rec.timestamp_utc,
                                now_epoch,
                            ) {
                                if drift {
                                    tracing::warn!(
                                        job_id = %job.id,
                                        mttd_ms = audit_rec.measurements.mttd_ms,
                                        baseline_ms = ?job.baseline_mttd_ms,
                                        "MTTD drift detected: detection capability degraded"
                                    );

                                    state.webhook.dispatch(
                                        crate::webhook::WebhookPayload {
                                            event: "drift_detected".into(),
                                            timestamp_utc: audit_rec.timestamp_utc.clone(),
                                            exercise_id: audit_rec.run_id.clone(),
                                            scenario_id: job.scenario_id.clone(),
                                            mitre_technique: audit_rec.mitre_technique.clone(),
                                            target: job
                                                .target_override
                                                .clone()
                                                .unwrap_or_else(|| "default".into()),
                                            initiator: job.role.as_str().into(),
                                            tag: "🔴 [RED TEAM EXERCISE]".into(),
                                            data: serde_json::json!({
                                                "job_id": job.id,
                                                "last_mttd_ms": audit_rec.measurements.mttd_ms,
                                                "baseline_mttd_ms": job.baseline_mttd_ms,
                                                "drift_factor": (audit_rec.measurements.mttd_ms as f32)
                                                    / (job.baseline_mttd_ms.unwrap_or(1) as f32),
                                            }),
                                        },
                                        Some(&state.signing_key),
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                job_id = %job.id,
                                error = %e,
                                "Failed to execute scheduled BAS job"
                            );
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schedule_catalog_crud() {
        let mut cat = ScheduleCatalog::new();
        assert!(cat.list().is_empty());

        let job = ScheduledJob {
            id: "SCHED-TEST-1".into(),
            name: "Test Job".into(),
            scenario_id: "SCN-RT-001".into(),
            interval_sec: 60,
            role: Role::RedTeam,
            target_override: None,
            enabled: true,
            created_at_utc: "2026-09-09T22:00:00Z".into(),
            last_run_utc: None,
            last_run_epoch_secs: None,
            last_status: None,
            last_mttd_ms: None,
            baseline_mttd_ms: Some(100),
            drift_detected: false,
            drift_factor: None,
            run_history: VecDeque::new(),
        };

        cat.register(job);
        assert_eq!(cat.list().len(), 1);
        assert!(cat.get("SCHED-TEST-1").is_some());

        // Test normal run without drift
        let drift = cat.record_outcome(
            "SCHED-TEST-1",
            "COMPLETED",
            110,
            "2026-09-09T22:01:00Z",
            1000,
        );
        assert_eq!(drift, Some(false));
        let updated = cat.get("SCHED-TEST-1").unwrap();
        assert_eq!(updated.last_mttd_ms, Some(110));
        assert_eq!(updated.last_run_epoch_secs, Some(1000));
        assert!(!updated.drift_detected);

        // Test degraded run with drift (160ms vs 100ms baseline = 1.6x >= 1.5)
        let drift2 = cat.record_outcome(
            "SCHED-TEST-1",
            "COMPLETED",
            160,
            "2026-09-09T22:02:00Z",
            2000,
        );
        assert_eq!(drift2, Some(true));
        let updated2 = cat.get("SCHED-TEST-1").unwrap();
        assert!(updated2.drift_detected);
        assert!((updated2.drift_factor.unwrap() - 1.6).abs() < 0.001);

        assert!(cat.deregister("SCHED-TEST-1"));
        assert_eq!(cat.list().len(), 0);
    }

    fn seeded_job(id: &str, baseline: u64) -> ScheduledJob {
        ScheduledJob {
            id: id.into(),
            name: "Test Job".into(),
            scenario_id: "SCN-RT-001".into(),
            interval_sec: 60,
            role: Role::RedTeam,
            target_override: None,
            enabled: true,
            created_at_utc: "2026-09-09T22:00:00Z".into(),
            last_run_utc: None,
            last_run_epoch_secs: None,
            last_status: None,
            last_mttd_ms: None,
            baseline_mttd_ms: Some(baseline),
            drift_detected: false,
            drift_factor: None,
            run_history: VecDeque::new(),
        }
    }

    #[test]
    fn record_outcome_builds_history_and_alerts() {
        let mut cat = ScheduleCatalog::new();
        cat.register(seeded_job("SCHED-H", 100));
        assert!(cat.alerts().is_empty());

        cat.record_outcome("SCHED-H", "COMPLETED", 110, "2026-09-09T22:01:00Z", 1000);
        cat.record_outcome("SCHED-H", "COMPLETED", 180, "2026-09-09T22:02:00Z", 2000);

        let job = cat.get("SCHED-H").unwrap();
        assert_eq!(job.run_history.len(), 2, "both runs are on the timeline");
        assert!(!job.run_history[0].drift_detected);
        assert!(job.run_history[1].drift_detected);

        // Only the transition into degradation produces a retained, queryable alert.
        let alerts = cat.alerts();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].job_id, "SCHED-H");
        assert_eq!(alerts[0].observed_mttd_ms, 180);
        assert_eq!(alerts[0].baseline_mttd_ms, Some(100));
        assert!((alerts[0].drift_factor - 1.8).abs() < 0.001);
    }

    #[test]
    fn drift_alert_emits_on_transition_not_every_sample() {
        let mut cat = ScheduleCatalog::new();
        cat.register(seeded_job("SCHED-EDGE", 100));

        // Enter drift: one alert.
        assert_eq!(
            cat.record_outcome("SCHED-EDGE", "COMPLETED", 180, "2026-09-09T22:01:00Z", 1000),
            Some(true)
        );
        assert_eq!(cat.alerts().len(), 1);

        // Stay degraded: timeline grows, alert count stays flat.
        assert_eq!(
            cat.record_outcome("SCHED-EDGE", "COMPLETED", 190, "2026-09-09T22:02:00Z", 2000),
            Some(false)
        );
        assert_eq!(cat.alerts().len(), 1);
        assert_eq!(cat.get("SCHED-EDGE").unwrap().run_history.len(), 2);

        // Recover, then regress again: a new transition creates a new alert.
        assert_eq!(
            cat.record_outcome("SCHED-EDGE", "COMPLETED", 120, "2026-09-09T22:03:00Z", 3000),
            Some(false)
        );
        assert_eq!(
            cat.record_outcome("SCHED-EDGE", "COMPLETED", 170, "2026-09-09T22:04:00Z", 4000),
            Some(true)
        );
        let alerts = cat.alerts();
        assert_eq!(alerts.len(), 2);
        assert!(alerts[0].seq > alerts[1].seq);
    }

    #[test]
    fn history_is_bounded() {
        let mut cat = ScheduleCatalog::new();
        cat.register(seeded_job("SCHED-B", 100));
        for i in 0..(MAX_HISTORY_PER_JOB + 10) {
            cat.record_outcome(
                "SCHED-B",
                "COMPLETED",
                100,
                "2026-09-09T22:00:00Z",
                i as u64,
            );
        }
        let job = cat.get("SCHED-B").unwrap();
        assert_eq!(job.run_history.len(), MAX_HISTORY_PER_JOB);
    }

    #[test]
    fn alerts_newest_first_and_bounded() {
        let mut cat = ScheduleCatalog::new();
        cat.register(seeded_job("SCHED-A", 100));

        // Generate more than MAX_ALERTS distinct healthy -> drift transitions.
        // Staying degraded does not create duplicate alerts.
        for i in 0..(MAX_ALERTS + 5) {
            let base_epoch = (i as u64) * 2;
            assert_eq!(
                cat.record_outcome(
                    "SCHED-A",
                    "COMPLETED",
                    100,
                    "2026-09-09T22:00:00Z",
                    base_epoch,
                ),
                Some(false)
            );
            assert_eq!(
                cat.record_outcome(
                    "SCHED-A",
                    "COMPLETED",
                    300,
                    "2026-09-09T22:00:01Z",
                    base_epoch + 1,
                ),
                Some(true)
            );
        }

        let alerts = cat.alerts();
        assert_eq!(alerts.len(), MAX_ALERTS);
        // Newest first: the most recent seq comes out on top.
        assert!(alerts[0].seq > alerts[1].seq);
    }

    #[test]
    fn set_enabled_toggles_job() {
        let mut cat = ScheduleCatalog::new();
        cat.register(seeded_job("SCHED-T", 100));
        assert_eq!(cat.set_enabled("SCHED-T", false), Some(false));
        assert!(!cat.get("SCHED-T").unwrap().enabled);
        assert_eq!(cat.set_enabled("SCHED-T", true), Some(true));
        assert!(cat.get("SCHED-T").unwrap().enabled);
        assert_eq!(cat.set_enabled("SCHED-MISSING", true), None);
    }
}
