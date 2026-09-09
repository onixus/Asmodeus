//! Continuous Automated BAS (Breach & Attack Simulation) Scheduler.
//!
//! Manages scheduled, recurring scenario executions to establish detection
//! baselines and detect security posture degradation (MTTD drift).

use std::collections::HashMap;

use asmodeus_common::Role;
use serde::{Deserialize, Serialize};

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

/// In-memory catalog of scheduled BAS jobs.
#[derive(Debug, Clone)]
pub struct ScheduleCatalog {
    jobs: HashMap<String, ScheduledJob>,
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

    #[allow(dead_code)]
    pub fn get(&self, id: &str) -> Option<&ScheduledJob> {
        self.jobs.get(id)
    }

    #[allow(dead_code)]
    pub fn get_mut(&mut self, id: &str) -> Option<&mut ScheduledJob> {
        self.jobs.get_mut(id)
    }

    /// Record outcome of a scheduled run and evaluate MTTD drift.
    pub fn record_outcome(
        &mut self,
        id: &str,
        status: &str,
        mttd_ms: u64,
        timestamp_utc: &str,
        epoch_secs: u64,
    ) -> Option<bool> {
        let job = self.jobs.get_mut(id)?;
        job.last_run_utc = Some(timestamp_utc.to_string());
        job.last_run_epoch_secs = Some(epoch_secs);
        job.last_status = Some(status.to_string());
        job.last_mttd_ms = Some(mttd_ms);

        if job.baseline_mttd_ms.is_none() && mttd_ms > 0 {
            job.baseline_mttd_ms = Some(mttd_ms);
        }

        if let Some(base) = job.baseline_mttd_ms {
            if base > 0 {
                let factor = (mttd_ms as f32) / (base as f32);
                job.drift_factor = Some(factor);
                job.drift_detected = factor >= 1.5;
            }
        }

        Some(job.drift_detected)
    }
}

/// Spawn a background task periodically checking and executing scheduled BAS jobs.
pub fn spawn_scheduler(
    state: crate::http::AppState,
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

                    match crate::http::execute_single_scenario(
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
}
