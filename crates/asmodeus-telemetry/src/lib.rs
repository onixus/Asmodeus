//! asmodeus-telemetry — measures MTTD/MTTR, tags every artifact as an exercise
//! and exports Prometheus metrics into the shared APEX ClickHouse bus.
//! Pure computation + text exposition; no async scrape server yet.

pub mod audit;
pub mod clickhouse;
pub mod compliance;
pub mod reporting;

pub use audit::*;
pub use clickhouse::*;
pub use compliance::*;
pub use reporting::*;

use serde::{Deserialize, Serialize};

/// Detection/containment timings for one run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Measurements {
    pub mttd_ms: u64,
    pub mttr_ms: u64,
    pub blue_team_detected: bool,
}

/// Containment-time target (ms). A run remediated within this scores full
/// recovery; slower runs scale the recovery component down.
pub const TARGET_MTTR_MS: u64 = 300;

/// Integral 0..100 cyber-resilience index.
pub fn resilience_score(attacks_repelled_pct: f32, recovery_speed_pct: f32) -> u8 {
    (0.5 * attacks_repelled_pct + 0.5 * recovery_speed_pct).clamp(0.0, 100.0) as u8
}

/// Rolling aggregate over completed runs, feeding the `/metrics` endpoint.
#[derive(Debug, Default, Clone)]
pub struct Aggregate {
    pub scenarios_executed: u64,
    pub detected: u64,
    pub feedback_received: u64,
    pub simulated_runs: u64,
    pub pending_feedback: u64,
    pub contained: u64,
    detection_samples: u64,
    containment_samples: u64,
    sum_mttd_ms: u128,
    sum_mttr_ms: u128,
}

impl Aggregate {
    /// Rebuild a rolling aggregate from a slice of persisted audit records
    /// (e.g. after loading the audit trail from disk on startup).
    pub fn from_records(records: &[crate::audit::AuditRecord]) -> Self {
        let mut agg = Self::default();
        for r in records {
            agg.record_run(r);
        }
        agg
    }

    pub fn record(&mut self, m: Measurements) {
        self.scenarios_executed += 1;
        self.feedback_received += 1;
        self.detection_samples += 1;
        self.containment_samples += 1;
        self.contained += 1;
        if m.blue_team_detected {
            self.detected += 1;
        }
        self.sum_mttd_ms += u128::from(m.mttd_ms);
        self.sum_mttr_ms += u128::from(m.mttr_ms);
    }

    /// Only live, explicitly submitted feedback contributes to defense metrics.
    pub fn record_run(&mut self, record: &AuditRecord) {
        let contribution = Self::contribution(record);
        self.combine(&contribution, true);
    }

    pub fn update_run(&mut self, old: &AuditRecord, new: &AuditRecord) {
        self.combine(&Self::contribution(old), false);
        self.record_run(new);
    }

    fn contribution(record: &AuditRecord) -> Self {
        let mut value = Self::default();
        if !record.is_terminal() {
            return value;
        }
        value.scenarios_executed = 1;
        if record
            .evidence
            .as_ref()
            .is_some_and(|e| e.execution_mode == "simulated")
        {
            value.simulated_runs = 1;
        } else if record.has_confirmed_feedback() {
            value.feedback_received = 1;
            if record.measurements.blue_team_detected {
                value.detected = 1;
                value.detection_samples = 1;
                value.sum_mttd_ms = record.measurements.mttd_ms.into();
            }
            if record.evidence.as_ref().is_some_and(|e| e.contained) {
                value.contained = 1;
                value.containment_samples = 1;
                value.sum_mttr_ms = record.measurements.mttr_ms.into();
            }
        } else {
            value.pending_feedback = 1;
        }
        value
    }

    fn combine(&mut self, other: &Self, add: bool) {
        macro_rules! update { ($($field:ident),*) => { $(
            self.$field = if add { self.$field + other.$field } else { self.$field.saturating_sub(other.$field) };
        )* }; }
        update!(
            scenarios_executed,
            detected,
            feedback_received,
            simulated_runs,
            pending_feedback,
            contained,
            detection_samples,
            containment_samples,
            sum_mttd_ms,
            sum_mttr_ms
        );
    }

    /// Update an existing measurement (e.g. from closed-loop feedback).
    pub fn update_measurement(&mut self, old: Measurements, new: Measurements) {
        if old.blue_team_detected != new.blue_team_detected {
            if new.blue_team_detected {
                self.detected += 1;
            } else if self.detected > 0 {
                self.detected -= 1;
            }
        }
        self.sum_mttd_ms =
            self.sum_mttd_ms.saturating_sub(u128::from(old.mttd_ms)) + u128::from(new.mttd_ms);
        self.sum_mttr_ms =
            self.sum_mttr_ms.saturating_sub(u128::from(old.mttr_ms)) + u128::from(new.mttr_ms);
    }

    pub fn mean_mttd_ms(&self) -> u64 {
        self.sum_mttd_ms
            .checked_div(u128::from(self.detection_samples))
            .unwrap_or(0) as u64
    }

    pub fn mean_mttr_ms(&self) -> u64 {
        self.sum_mttr_ms
            .checked_div(u128::from(self.containment_samples))
            .unwrap_or(0) as u64
    }

    /// Percentage of runs the Blue Team detected (0..100).
    pub fn detection_rate_pct(&self) -> f32 {
        if self.feedback_received == 0 {
            return 0.0;
        }
        100.0 * self.detected as f32 / self.feedback_received as f32
    }

    /// Recovery speed as a percentage of the containment target (0..100):
    /// meeting or beating `TARGET_MTTR_MS` scores 100, slower runs scale down
    /// linearly. This is the recovery half of the resilience score, so a slow
    /// Blue Team actually lowers the index instead of it being a constant.
    pub fn recovery_speed_pct(&self) -> f32 {
        if self.containment_samples == 0 {
            return 0.0;
        }
        let mean = self.mean_mttr_ms();
        if mean == 0 {
            return 100.0;
        }
        (100.0 * TARGET_MTTR_MS as f32 / mean as f32).clamp(0.0, 100.0)
    }

    /// Prometheus text exposition (see TT §4.3).
    pub fn prometheus_text(&self) -> String {
        let score = resilience_score(self.detection_rate_pct(), self.recovery_speed_pct());
        format!(
            "# HELP asmodeus_resilience_score Integral cyber-resilience index (0..100)\n\
             # TYPE asmodeus_resilience_score gauge\n\
             asmodeus_resilience_score {score}\n\
             # HELP asmodeus_mttd_seconds Mean time to detect\n\
             # TYPE asmodeus_mttd_seconds gauge\n\
             asmodeus_mttd_seconds {:.3}\n\
             # HELP asmodeus_mttr_seconds Mean time to remediate\n\
             # TYPE asmodeus_mttr_seconds gauge\n\
             asmodeus_mttr_seconds {:.3}\n\
             # HELP asmodeus_scenarios_executed_total Scenarios executed\n\
             # TYPE asmodeus_scenarios_executed_total counter\n\
             asmodeus_scenarios_executed_total {}\n\
             # TYPE asmodeus_feedback_received gauge\n\
             asmodeus_feedback_received {}\n\
             # TYPE asmodeus_simulated_runs gauge\n\
             asmodeus_simulated_runs {}\n\
             # TYPE asmodeus_pending_feedback gauge\n\
             asmodeus_pending_feedback {}\n\
             # TYPE asmodeus_detection_samples gauge\n\
             asmodeus_detection_samples {}\n\
             # TYPE asmodeus_containment_samples gauge\n\
             asmodeus_containment_samples {}\n",
            self.mean_mttd_ms() as f64 / 1000.0,
            self.mean_mttr_ms() as f64 / 1000.0,
            self.scenarios_executed,
            self.feedback_received,
            self.simulated_runs,
            self.pending_feedback,
            self.detection_samples,
            self.containment_samples,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_is_clamped() {
        assert_eq!(resilience_score(120.0, 120.0), 100);
        assert_eq!(resilience_score(-5.0, 0.0), 0);
        assert_eq!(resilience_score(100.0, 0.0), 50);
    }

    #[test]
    fn aggregate_means_and_rate() {
        let mut agg = Aggregate::default();
        agg.record(Measurements {
            mttd_ms: 100,
            mttr_ms: 200,
            blue_team_detected: true,
        });
        agg.record(Measurements {
            mttd_ms: 300,
            mttr_ms: 400,
            blue_team_detected: false,
        });
        assert_eq!(agg.mean_mttd_ms(), 200);
        assert_eq!(agg.mean_mttr_ms(), 300);
        assert_eq!(agg.detection_rate_pct(), 50.0);
    }

    #[test]
    fn pending_simulated_and_legacy_runs_cannot_improve_defense_scores() {
        let mut pending = sample_record();
        pending.evidence.as_mut().unwrap().feedback_received = false;
        let mut simulated = pending.clone();
        simulated.evidence.as_mut().unwrap().execution_mode = "simulated".into();
        simulated.evidence.as_mut().unwrap().feedback_received = true;
        simulated.measurements = Measurements {
            mttd_ms: 1,
            mttr_ms: 1,
            blue_team_detected: true,
        };
        let mut legacy = simulated.clone();
        legacy.evidence = None;
        let records = [pending, simulated, legacy];
        let aggregate = Aggregate::from_records(&records);
        assert_eq!(aggregate.feedback_received, 0);
        assert_eq!(aggregate.pending_feedback, 2);
        assert_eq!(aggregate.simulated_runs, 1);
        assert_eq!(aggregate.recovery_speed_pct(), 0.0);
        let report = EcosystemResilienceReport::build(&records, &aggregate);
        assert_eq!(report.mttr_sla_status, "NO DATA");
        assert_eq!(report.resilience_score, 0);
        assert!(report.nist_functions.iter().all(|f| f.score_pct == 0.0));
    }

    #[test]
    fn large_feedback_values_do_not_overflow_aggregates_or_reports() {
        let mut record = sample_record();
        record.measurements.blue_team_detected = true;
        record.measurements.mttd_ms = u64::MAX;
        record.measurements.mttr_ms = u64::MAX;
        let records = [record.clone(), record];
        let mut aggregate = Aggregate::from_records(&records);
        assert_eq!(aggregate.mean_mttd_ms(), u64::MAX);
        let report = EcosystemResilienceReport::build(&records, &aggregate);
        assert_eq!(report.tactics_breakdown[0].mean_mttr_ms, u64::MAX);
        aggregate.update_measurement(records[0].measurements, Measurements::default());
        assert_eq!(aggregate.mean_mttr_ms(), u64::MAX / 2);
    }

    #[test]
    fn from_records_rebuilds_aggregate() {
        // A restart must not lose metrics: rebuilding from the persisted audit
        // trail reproduces the same means and detection rate as live recording.
        let mut live = Aggregate::default();
        let mut trail = crate::AuditTrail::new();
        for (mttd, mttr, detected) in [(100, 200, true), (300, 400, false)] {
            let m = Measurements {
                mttd_ms: mttd,
                mttr_ms: mttr,
                blue_team_detected: detected,
            };
            let mut rec = sample_record();
            rec.measurements = m;
            live.record_run(&rec);
            trail.append(rec);
        }
        let rebuilt = Aggregate::from_records(trail.records());
        assert_eq!(rebuilt.scenarios_executed, live.scenarios_executed);
        assert_eq!(rebuilt.detected, live.detected);
        assert_eq!(rebuilt.mean_mttd_ms(), live.mean_mttd_ms());
        assert_eq!(rebuilt.mean_mttr_ms(), live.mean_mttr_ms());
        assert_eq!(rebuilt.detection_rate_pct(), live.detection_rate_pct());
    }

    fn sample_record() -> crate::AuditRecord {
        crate::AuditRecord {
            run_id: "run_test".into(),
            scenario_id: "SCN-RT-001".into(),
            scenario_name: "Test".into(),
            category: "red_team".into(),
            mitre_technique: "T1486".into(),
            mitre_tactic: "Impact".into(),
            severity: "high".into(),
            tag: "🔴 [RED TEAM EXERCISE]".into(),
            initiator: "red_team".into(),
            runner_id: "default-runner".into(),
            status: "CONTAINED".into(),
            measurements: Measurements::default(),
            detection_source: String::new(),
            containment_action: String::new(),
            cleanup_status: "CLEAN".into(),
            timestamp_utc: "2026-09-18T00:00:00Z".into(),
            signature_hex: String::new(),
            public_key_hex: String::new(),
            evidence: Some(crate::RunEvidence {
                execution_mode: "runner".into(),
                feedback_received: true,
                contained: true,
                cleanup_confirmed: true,
                failure_reason: None,
            }),
        }
    }

    #[test]
    fn prometheus_text_has_expected_series() {
        let mut agg = Aggregate::default();
        agg.record(Measurements {
            mttd_ms: 142,
            mttr_ms: 280,
            blue_team_detected: true,
        });
        let text = agg.prometheus_text();
        assert!(text.contains("asmodeus_resilience_score "));
        assert!(text.contains("asmodeus_scenarios_executed_total 1"));
        assert!(text.contains("asmodeus_mttd_seconds 0.142"));
    }

    #[test]
    fn empty_aggregate_is_safe() {
        let agg = Aggregate::default();
        assert_eq!(agg.mean_mttd_ms(), 0);
        assert_eq!(agg.detection_rate_pct(), 0.0);
        assert_eq!(agg.recovery_speed_pct(), 0.0);
    }

    #[test]
    fn slow_recovery_lowers_the_score() {
        // Same detection (100%); only recovery differs, so it must move the score.
        let mut fast = Aggregate::default();
        fast.record(Measurements {
            mttd_ms: 100,
            mttr_ms: 100, // within the 300ms target
            blue_team_detected: true,
        });
        let mut slow = Aggregate::default();
        slow.record(Measurements {
            mttd_ms: 100,
            mttr_ms: 3000, // 10x the target
            blue_team_detected: true,
        });

        assert_eq!(fast.recovery_speed_pct(), 100.0);
        assert!(slow.recovery_speed_pct() < 20.0); // 300/3000 * 100 = 10

        let fast_score = resilience_score(fast.detection_rate_pct(), fast.recovery_speed_pct());
        let slow_score = resilience_score(slow.detection_rate_pct(), slow.recovery_speed_pct());
        assert_eq!(fast_score, 100);
        assert!(slow_score < fast_score);
    }
}
