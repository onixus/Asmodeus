//! Durable campaign runs: a persisted, resumable record of one kill-chain
//! execution.
//!
//! The step plan is snapshotted at launch, so editing or deleting the campaign
//! later never changes what an in-flight or resumed run executes. Progress is
//! written before and after every stage; a control-plane restart therefore
//! leaves an `INTERRUPTED` run that an operator may explicitly resume. Resume
//! never retries silently: the interrupted stage gets a new scenario run ID and
//! its previous attempt is kept in `superseded_results`.

use crate::campaign::{CampaignStep, CampaignStepResult};
use serde::{Deserialize, Serialize};

/// Terminal campaign runs kept in the snapshot; older terminal runs are pruned.
const MAX_TERMINAL_RUNS: usize = 200;

pub const QUEUED: &str = "QUEUED";
pub const RUNNING: &str = "RUNNING";
pub const COMPLETED: &str = "COMPLETED";
pub const FAILED: &str = "FAILED";
pub const CANCELLED: &str = "CANCELLED";
pub const INTERRUPTED: &str = "INTERRUPTED";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CampaignRun {
    pub id: String,
    pub campaign_id: String,
    pub campaign_name: String,
    pub initiator: String,
    pub target_override: Option<String>,
    pub timeout_sec: Option<u32>,
    pub steps: Vec<CampaignStep>,
    pub status: String,
    pub step_results: Vec<CampaignStepResult>,
    #[serde(default)]
    pub superseded_results: Vec<CampaignStepResult>,
    #[serde(default)]
    pub resume_count: u32,
    pub created_utc: String,
    pub updated_utc: String,
}

impl CampaignRun {
    pub fn is_terminal(&self) -> bool {
        !matches!(self.status.as_str(), QUEUED | RUNNING)
    }

    /// Index of the next stage to execute.
    pub fn next_step(&self) -> usize {
        self.step_results.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeError {
    NotFound,
    NotResumable(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignRunStore {
    #[serde(default = "snapshot_version")]
    version: u32,
    runs: Vec<CampaignRun>,
}

fn snapshot_version() -> u32 {
    1
}

impl Default for CampaignRunStore {
    fn default() -> Self {
        Self {
            version: snapshot_version(),
            runs: Vec::new(),
        }
    }
}

impl CampaignRunStore {
    pub fn validate(&self) -> std::io::Result<()> {
        let invalid = |reason| std::io::Error::new(std::io::ErrorKind::InvalidData, reason);
        if self.version != snapshot_version() {
            return Err(invalid("unsupported campaign run snapshot version"));
        }
        let mut ids = std::collections::HashSet::new();
        for run in &self.runs {
            if run.id.is_empty()
                || !ids.insert(&run.id)
                || run.steps.is_empty()
                || run.step_results.len() > run.steps.len()
                || !matches!(
                    run.status.as_str(),
                    QUEUED | RUNNING | COMPLETED | FAILED | CANCELLED | INTERRUPTED
                )
            {
                return Err(invalid("invalid campaign run snapshot"));
            }
            for (index, step) in run.steps.iter().enumerate() {
                if step.order == 0
                    || step.scenario_id.is_empty()
                    || (index > 0 && run.steps[index - 1].order >= step.order)
                {
                    return Err(invalid("invalid campaign step plan"));
                }
            }
            for (index, result) in run.step_results.iter().enumerate() {
                let step = &run.steps[index];
                if step.order != result.step_order
                    || step.scenario_id != result.scenario_id
                    || (index + 1 < run.step_results.len() && result.status != COMPLETED)
                {
                    return Err(invalid("invalid campaign progress"));
                }
            }
            if run.status == COMPLETED
                && (run.step_results.len() != run.steps.len()
                    || run.step_results.iter().any(|r| r.status != COMPLETED))
            {
                return Err(invalid("incomplete campaign marked completed"));
            }
        }
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&CampaignRun> {
        self.runs.iter().find(|r| r.id == id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut CampaignRun> {
        self.runs.iter_mut().find(|r| r.id == id)
    }

    /// Newest first, optionally filtered by campaign and status.
    pub fn list(
        &self,
        limit: Option<usize>,
        campaign_id: Option<&str>,
        status: Option<&str>,
    ) -> Vec<CampaignRun> {
        self.runs
            .iter()
            .rev()
            .filter(|r| campaign_id.is_none_or(|c| r.campaign_id.eq_ignore_ascii_case(c)))
            .filter(|r| status.is_none_or(|s| r.status.eq_ignore_ascii_case(s)))
            .take(limit.unwrap_or(usize::MAX))
            .cloned()
            .collect()
    }

    pub fn len(&self) -> usize {
        self.runs.len()
    }

    pub fn insert(&mut self, run: CampaignRun) {
        self.runs.push(run);
        self.prune();
    }

    pub fn prune(&mut self) {
        let terminal = self
            .runs
            .iter()
            .filter(|r| matches!(r.status.as_str(), COMPLETED | FAILED))
            .count();
        let mut excess = terminal.saturating_sub(MAX_TERMINAL_RUNS);
        self.runs.retain(|r| {
            if excess > 0 && matches!(r.status.as_str(), COMPLETED | FAILED) {
                excess -= 1;
                false
            } else {
                true
            }
        });
    }

    /// Startup reconciliation: no worker survives a restart, so every
    /// non-terminal run and its in-flight stage become `INTERRUPTED`.
    pub fn recover_interrupted(&mut self) -> usize {
        let now = asmodeus_telemetry::current_utc_iso8601();
        let mut recovered = 0;
        for run in self.runs.iter_mut().filter(|r| !r.is_terminal()) {
            if let Some(last) = run.step_results.last_mut() {
                if last.status == RUNNING {
                    last.status = INTERRUPTED.into();
                }
            }
            run.status = INTERRUPTED.into();
            run.updated_utc = now.clone();
            recovered += 1;
        }
        recovered
    }

    /// Atomically move an interrupted or cancelled run back to `QUEUED`.
    /// The unfinished stage attempt is archived so it is re-executed with a
    /// fresh scenario run ID; completed stages are never repeated.
    pub fn begin_resume(&mut self, id: &str) -> Result<CampaignRun, ResumeError> {
        let run = self.get_mut(id).ok_or(ResumeError::NotFound)?;
        if !matches!(run.status.as_str(), INTERRUPTED | CANCELLED) {
            return Err(ResumeError::NotResumable(run.status.clone()));
        }
        if run
            .step_results
            .last()
            .is_some_and(|last| last.status != COMPLETED)
        {
            let attempt = run.step_results.pop().expect("checked above");
            run.superseded_results.push(attempt);
        }
        run.status = QUEUED.into();
        run.resume_count += 1;
        run.updated_utc = asmodeus_telemetry::current_utc_iso8601();
        Ok(run.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step_result(order: usize, status: &str) -> CampaignStepResult {
        CampaignStepResult {
            step_order: order,
            scenario_id: format!("S{order}"),
            run_id: format!("run-{order}"),
            status: status.into(),
            mttd_ms: 0,
            mttr_ms: 0,
            detected: false,
            evidence: None,
        }
    }

    fn run(id: &str, status: &str, results: Vec<CampaignStepResult>) -> CampaignRun {
        CampaignRun {
            id: id.into(),
            campaign_id: "CAMP-X".into(),
            campaign_name: "X".into(),
            initiator: "red_team".into(),
            target_override: None,
            timeout_sec: None,
            steps: (1..=3)
                .map(|order| CampaignStep {
                    order,
                    scenario_id: format!("S{order}"),
                })
                .collect(),
            status: status.into(),
            step_results: results,
            superseded_results: Vec::new(),
            resume_count: 0,
            created_utc: String::new(),
            updated_utc: String::new(),
        }
    }

    #[test]
    fn recovery_marks_in_flight_stage_and_resume_archives_it() {
        let mut store = CampaignRunStore::default();
        store.insert(run(
            "c1",
            RUNNING,
            vec![step_result(1, COMPLETED), step_result(2, RUNNING)],
        ));
        store.insert(run("c2", COMPLETED, vec![step_result(1, COMPLETED)]));
        assert_eq!(store.recover_interrupted(), 1);
        let c1 = store.get("c1").unwrap();
        assert_eq!(c1.status, INTERRUPTED);
        assert_eq!(c1.step_results[1].status, INTERRUPTED);
        assert_eq!(store.get("c2").unwrap().status, COMPLETED);

        let resumed = store.begin_resume("c1").unwrap();
        assert_eq!(resumed.status, QUEUED);
        assert_eq!(resumed.next_step(), 1);
        assert_eq!(resumed.superseded_results.len(), 1);
        assert_eq!(resumed.resume_count, 1);
        // A second concurrent resume sees QUEUED and is refused.
        assert_eq!(
            store.begin_resume("c1"),
            Err(ResumeError::NotResumable(QUEUED.into()))
        );
        assert_eq!(
            store.begin_resume("c2"),
            Err(ResumeError::NotResumable(COMPLETED.into()))
        );
        assert_eq!(store.begin_resume("nope"), Err(ResumeError::NotFound));
    }

    #[test]
    fn pruning_keeps_active_runs_and_newest_terminal_runs() {
        let mut store = CampaignRunStore::default();
        store.insert(run("active", RUNNING, Vec::new()));
        for i in 0..MAX_TERMINAL_RUNS + 5 {
            store.insert(run(&format!("t{i}"), COMPLETED, Vec::new()));
        }
        assert_eq!(store.len(), MAX_TERMINAL_RUNS + 1);
        assert!(store.get("active").is_some());
        assert!(store.get("t0").is_none());
        assert_eq!(
            store.list(Some(1), None, None)[0].id,
            format!("t{}", MAX_TERMINAL_RUNS + 4)
        );
        assert_eq!(store.list(None, None, Some("running")).len(), 1);
    }
    #[test]
    fn snapshot_validation_rejects_duplicate_ids_and_invalid_progress() {
        let mut store = CampaignRunStore::default();
        store.insert(run("a", QUEUED, vec![]));
        assert!(store.validate().is_ok());
        store.insert(run("a", QUEUED, vec![]));
        assert!(store.validate().is_err());
        store.runs.pop();
        store.runs[0].step_results.push(step_result(2, COMPLETED));
        assert!(store.validate().is_err());
    }

    #[test]
    fn retention_preserves_interrupted_and_cancelled_runs() {
        let mut store = CampaignRunStore::default();
        store.insert(run("interrupted", INTERRUPTED, vec![]));
        store.insert(run("cancelled", CANCELLED, vec![]));
        for i in 0..MAX_TERMINAL_RUNS + 5 {
            store.insert(run(&format!("t{i}"), FAILED, vec![]));
        }
        assert!(store.get("interrupted").is_some());
        assert!(store.get("cancelled").is_some());
        assert_eq!(store.len(), MAX_TERMINAL_RUNS + 2);
    }
}
