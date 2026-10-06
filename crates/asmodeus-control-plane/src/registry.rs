//! Runner Registry — tracks active, connected and ephemeral runner probes
//! (ARCHITECTURE.md §2, TT.md §1.1).
//!
//! Replaces a single static endpoint with a thread-safe registry supporting
//! discovery, tag-based routing (`k8s_workload`, `endpoint_agent`, `network_gateway`),
//! and health tracking via gRPC Heartbeat.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerStatus {
    Active,
    Unresponsive,
    Draining,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerRecord {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub tags: Vec<String>,
    pub status: RunnerStatus,
    pub last_heartbeat_utc: Option<u64>,
    pub cpu_usage_pct: u32,
    pub version: String,
    pub registered_at_utc: u64,
}

impl RunnerRecord {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        endpoint: impl Into<String>,
        tags: Vec<String>,
    ) -> Self {
        RunnerRecord {
            id: id.into(),
            name: name.into(),
            endpoint: endpoint.into(),
            tags,
            status: RunnerStatus::Active,
            last_heartbeat_utc: Some(now_epoch_secs()),
            cpu_usage_pct: 0,
            version: env!("CARGO_PKG_VERSION").to_string(),
            registered_at_utc: now_epoch_secs(),
        }
    }
}

/// A probe is bound to one registration and maintenance state. Its private
/// token prevents delayed replies from changing a replacement or resumed node.
#[derive(Debug, Clone)]
pub struct RunnerProbe {
    pub record: RunnerRecord,
    epoch: Arc<()>,
}

#[derive(Debug, Clone)]
struct RegisteredRunner {
    record: RunnerRecord,
    epoch: Arc<()>,
}

#[derive(Debug, Clone, Default)]
pub struct RunnerRegistry {
    runners: Arc<RwLock<HashMap<String, RegisteredRunner>>>,
}

impl RunnerRegistry {
    pub fn new() -> Self {
        RunnerRegistry {
            runners: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Convenience: instantiate with a default static runner endpoint if one was configured.
    pub fn with_default(id: &str, endpoint: &str, tags: Vec<String>) -> Self {
        let registry = Self::new();
        let record = RunnerRecord::new(id, "Default Probe", endpoint, tags);
        registry.register(record);
        registry
    }

    /// Register or update a runner.
    pub fn register(&self, mut record: RunnerRecord) -> RunnerRecord {
        let mut map = self.runners.write().unwrap();
        // Metadata updates must not bypass drain/resume or invent health.
        if let Some(previous) = map.get(&record.id) {
            record.status = previous.record.status;
            record.registered_at_utc = previous.record.registered_at_utc;
            if record.endpoint == previous.record.endpoint {
                record.last_heartbeat_utc = previous.record.last_heartbeat_utc;
                record.cpu_usage_pct = previous.record.cpu_usage_pct;
                record.version = previous.record.version.clone();
            } else {
                if record.status != RunnerStatus::Draining {
                    record.status = RunnerStatus::Unresponsive;
                }
                record.last_heartbeat_utc = None;
                record.cpu_usage_pct = 0;
                record.version.clear();
            }
        }
        map.insert(
            record.id.clone(),
            RegisteredRunner {
                record: record.clone(),
                epoch: Arc::new(()),
            },
        );
        record
    }

    /// Stop new routing, or require a fresh successful probe before resuming.
    /// Runs already admitted to the runner are not cancelled by maintenance.
    pub fn set_draining(&self, id: &str, draining: bool) -> Option<RunnerRecord> {
        let mut map = self.runners.write().unwrap();
        let runner = map.get_mut(id)?;
        if draining && runner.record.status != RunnerStatus::Draining {
            runner.record.status = RunnerStatus::Draining;
            runner.epoch = Arc::new(());
        } else if !draining && runner.record.status == RunnerStatus::Draining {
            runner.record.status = RunnerStatus::Unresponsive;
            runner.record.last_heartbeat_utc = None;
            runner.epoch = Arc::new(());
        }
        Some(runner.record.clone())
    }

    /// Capture the current endpoint immediately before sending a heartbeat.
    pub fn begin_probe(&self, id: &str) -> Option<RunnerProbe> {
        let mut map = self.runners.write().unwrap();
        let runner = map.get_mut(id)?;
        // Only the most recently started probe may publish a result.
        runner.epoch = Arc::new(());
        Some(RunnerProbe {
            record: runner.record.clone(),
            epoch: runner.epoch.clone(),
        })
    }

    /// Deregister a runner by its ID.
    pub fn deregister(&self, id: &str) -> bool {
        let mut map = self.runners.write().unwrap();
        map.remove(id).is_some()
    }

    /// Look up a runner by its unique ID.
    #[cfg(test)]
    pub fn get(&self, id: &str) -> Option<RunnerRecord> {
        let map = self.runners.read().unwrap();
        map.get(id).map(|r| r.record.clone())
    }

    /// List all registered runners sorted by ID.
    pub fn list(&self) -> Vec<RunnerRecord> {
        let map = self.runners.read().unwrap();
        let mut list: Vec<_> = map.values().map(|r| r.record.clone()).collect();
        list.sort_by(|a, b| a.id.cmp(&b.id));
        list
    }

    /// Resolve only active runners. Exact IDs never fall back to a tag or a
    /// different runner; ties between tags/defaults are stable by runner ID.
    pub fn find_for_target(&self, target: Option<&str>) -> Option<RunnerRecord> {
        let map = self.runners.read().unwrap();
        let target = target.map(str::trim).filter(|target| !target.is_empty());
        if let Some(record) = target.and_then(|target| map.get(target)).map(|r| &r.record) {
            return (record.status == RunnerStatus::Active).then(|| record.clone());
        }
        map.values()
            .map(|r| &r.record)
            .filter(|record| record.status == RunnerStatus::Active)
            .filter(|record| {
                target.is_none_or(|target| {
                    record
                        .tags
                        .iter()
                        .any(|tag| tag.eq_ignore_ascii_case(target))
                })
            })
            .min_by(|a, b| a.id.cmp(&b.id))
            .cloned()
    }

    pub fn is_empty(&self) -> bool {
        self.runners.read().unwrap().is_empty()
    }

    /// Update health and metrics after a successful heartbeat.
    pub fn update_heartbeat(
        &self,
        probe: &RunnerProbe,
        healthy: bool,
        cpu_pct: u32,
        version: &str,
    ) -> bool {
        let mut map = self.runners.write().unwrap();
        if let Some(runner) = map
            .get_mut(&probe.record.id)
            .filter(|r| Arc::ptr_eq(&r.epoch, &probe.epoch))
        {
            let r = &mut runner.record;
            if r.status != RunnerStatus::Draining {
                r.status = if healthy {
                    RunnerStatus::Active
                } else {
                    RunnerStatus::Unresponsive
                };
            }
            r.cpu_usage_pct = cpu_pct;
            r.last_heartbeat_utc = Some(now_epoch_secs());
            if !version.is_empty() {
                r.version = version.to_string();
            }
            return true;
        }
        false
    }

    /// Mark a runner as unresponsive on connection failure.
    pub fn mark_unresponsive(&self, probe: &RunnerProbe) -> bool {
        let mut map = self.runners.write().unwrap();
        if let Some(runner) = map
            .get_mut(&probe.record.id)
            .filter(|r| Arc::ptr_eq(&r.epoch, &probe.epoch))
        {
            if runner.record.status != RunnerStatus::Draining {
                runner.record.status = RunnerStatus::Unresponsive;
            }
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_replacement_requires_health_and_metadata_updates_preserve_it() {
        let reg = RunnerRegistry::with_default("probe", "http://127.0.0.1:1", vec![]);
        let probe = reg.begin_probe("probe").unwrap();
        reg.update_heartbeat(&probe, true, 7, "live-version");
        let before = reg.get("probe").unwrap();
        let updated = reg.register(RunnerRecord::new(
            "probe",
            "Renamed",
            "http://127.0.0.1:1",
            vec![],
        ));
        assert_eq!(updated.status, RunnerStatus::Active);
        assert_eq!(updated.last_heartbeat_utc, before.last_heartbeat_utc);
        assert_eq!(updated.registered_at_utc, before.registered_at_utc);
        assert_eq!(updated.cpu_usage_pct, 7);
        assert_eq!(updated.version, "live-version");
        let changed = reg.register(RunnerRecord::new(
            "probe",
            "Changed",
            "http://127.0.0.1:2",
            vec![],
        ));
        assert_eq!(changed.status, RunnerStatus::Unresponsive);
        assert_eq!(changed.last_heartbeat_utc, None);
        assert_eq!(changed.cpu_usage_pct, 0);
        assert!(changed.version.is_empty());
        assert!(!reg.update_heartbeat(&probe, true, 7, "old"));
        assert!(reg.find_for_target(None).is_none());
    }

    #[test]
    fn registration_cannot_bypass_resume_health_gate() {
        let reg = RunnerRegistry::with_default("probe", "http://127.0.0.1:1", vec![]);
        reg.set_draining("probe", true);
        reg.set_draining("probe", false);
        let saved = reg.register(RunnerRecord::new(
            "probe",
            "Updated",
            "http://127.0.0.1:1",
            vec![],
        ));
        assert_eq!(saved.status, RunnerStatus::Unresponsive);
        assert_eq!(saved.last_heartbeat_utc, None);
        assert!(reg.find_for_target(None).is_none());
    }

    #[test]
    fn resume_requires_a_fresh_healthy_probe_and_is_idempotent() {
        let reg = RunnerRegistry::with_default("probe", "http://127.0.0.1:1", vec!["test".into()]);
        let before_drain = reg.begin_probe("probe").unwrap();
        assert_eq!(
            reg.set_draining("probe", true).unwrap().status,
            RunnerStatus::Draining
        );
        assert!(!reg.update_heartbeat(&before_drain, true, 1, "old"));
        let during_drain = reg.begin_probe("probe").unwrap();
        assert!(reg.update_heartbeat(&during_drain, true, 2, "current"));
        assert!(reg.mark_unresponsive(&during_drain));
        assert_eq!(reg.get("probe").unwrap().status, RunnerStatus::Draining);
        for target in [None, Some("probe"), Some("test")] {
            assert!(reg.find_for_target(target).is_none());
        }
        let resumed = reg.set_draining("probe", false).unwrap();
        assert_eq!(resumed.status, RunnerStatus::Unresponsive);
        assert_eq!(resumed.last_heartbeat_utc, None);
        assert!(!reg.update_heartbeat(&during_drain, true, 3, "stale"));
        let fresh = reg.begin_probe("probe").unwrap();
        reg.set_draining("probe", false); // a retried resume must not invalidate it
        assert!(reg.update_heartbeat(&fresh, false, 4, "unhealthy"));
        assert!(reg.find_for_target(None).is_none());
        let healthy = reg.begin_probe("probe").unwrap();
        assert!(reg.update_heartbeat(&healthy, true, 5, "healthy"));
        assert_eq!(
            reg.set_draining("probe", false).unwrap().status,
            RunnerStatus::Active
        );
        assert_eq!(reg.find_for_target(Some("test")).unwrap().id, "probe");
        assert!(reg.set_draining("missing", true).is_none());
    }

    #[test]
    fn stale_probe_results_cannot_overwrite_newer_health_or_registration() {
        let reg = RunnerRegistry::with_default("probe", "http://127.0.0.1:1", vec![]);
        let old = reg.begin_probe("probe").unwrap();
        let new = reg.begin_probe("probe").unwrap();
        assert!(reg.update_heartbeat(&new, false, 10, "new"));
        assert!(!reg.update_heartbeat(&old, true, 99, "old"));
        assert_eq!(reg.get("probe").unwrap().cpu_usage_pct, 10);
        assert!(reg.find_for_target(None).is_none());
        for remove_first in [false, true] {
            let old = reg.begin_probe("probe").unwrap();
            if remove_first {
                reg.deregister("probe");
            }
            reg.register(RunnerRecord::new(
                "probe",
                "Replacement",
                "http://127.0.0.1:2",
                vec![],
            ));
            let new = reg.begin_probe("probe").unwrap();
            assert_eq!(new.record.endpoint, "http://127.0.0.1:2");
            assert!(reg.update_heartbeat(&new, true, 7, "replacement"));
            assert!(!reg.mark_unresponsive(&old));
            assert!(!reg.update_heartbeat(&old, false, 99, "old"));
            let record = reg.get("probe").unwrap();
            assert_eq!(record.status, RunnerStatus::Active);
            assert_eq!(record.version, "replacement");
        }
    }

    #[test]
    fn registration_does_not_clear_operator_drain() {
        let reg = RunnerRegistry::new();
        let mut record = RunnerRecord::new("probe", "Probe", "http://127.0.0.1:1", vec![]);
        record.status = RunnerStatus::Draining;
        reg.register(record);
        reg.register(RunnerRecord::new(
            "probe",
            "Replacement",
            "http://127.0.0.1:2",
            vec![],
        ));
        assert_eq!(reg.get("probe").unwrap().status, RunnerStatus::Draining);
        assert!(reg.find_for_target(Some("probe")).is_none());
    }

    #[test]
    fn unavailable_and_draining_runners_are_never_selected() {
        let reg = RunnerRegistry::with_default("probe", "http://127.0.0.1:1", vec!["test".into()]);
        reg.mark_unresponsive(&reg.begin_probe("probe").unwrap());
        for target in [None, Some("probe"), Some("test")] {
            assert!(reg.find_for_target(target).is_none());
        }
        reg.set_draining("probe", true);
        reg.update_heartbeat(&reg.begin_probe("probe").unwrap(), true, 0, "test");
        reg.mark_unresponsive(&reg.begin_probe("probe").unwrap());
        assert_eq!(reg.get("probe").unwrap().status, RunnerStatus::Draining);
        assert!(reg.find_for_target(None).is_none());
    }

    #[test]
    fn register_and_list_runners() {
        let reg = RunnerRegistry::new();
        assert!(reg.list().is_empty());

        let r1 = RunnerRecord::new(
            "lariska-1",
            "Lariska Endpoint",
            "http://127.0.0.1:8850",
            vec!["endpoint_agent".into()],
        );
        let r2 = RunnerRecord::new(
            "k8s-pod-1",
            "K8s Ferrum Probe",
            "http://127.0.0.1:8851",
            vec!["k8s_workload".into()],
        );

        reg.register(r1);
        reg.register(r2);

        let all = reg.list();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, "k8s-pod-1");
        assert_eq!(all[1].id, "lariska-1");

        assert!(reg.deregister("lariska-1"));
        assert_eq!(reg.list().len(), 1);
        assert!(!reg.deregister("non-existent"));
    }

    #[test]
    fn find_for_target_routing() {
        let reg = RunnerRegistry::new();
        let r1 = RunnerRecord::new(
            "node-a",
            "Node A",
            "http://127.0.0.1:8850",
            vec!["k8s_workload".into()],
        );
        let r2 = RunnerRecord::new(
            "node-b",
            "Node B",
            "http://127.0.0.1:8851",
            vec!["endpoint_agent".into(), "production".into()],
        );

        reg.register(r1);
        reg.register(r2);

        // Exact ID match
        assert_eq!(reg.find_for_target(Some("node-a")).unwrap().id, "node-a");
        assert_eq!(reg.find_for_target(Some("node-b")).unwrap().id, "node-b");

        // Tag match
        assert_eq!(
            reg.find_for_target(Some("k8s_workload")).unwrap().id,
            "node-a"
        );
        assert_eq!(
            reg.find_for_target(Some("production")).unwrap().id,
            "node-b"
        );

        // Fallback without target
        assert!(reg.find_for_target(None).is_some());
    }

    #[test]
    fn update_heartbeat_and_unresponsive() {
        let reg = RunnerRegistry::new();
        let r = RunnerRecord::new("probe-1", "Probe", "http://127.0.0.1:8850", vec![]);
        reg.register(r);

        reg.update_heartbeat(&reg.begin_probe("probe-1").unwrap(), true, 4, "0.1.0");
        let item = reg.get("probe-1").unwrap();
        assert_eq!(item.status, RunnerStatus::Active);
        assert_eq!(item.cpu_usage_pct, 4);

        reg.mark_unresponsive(&reg.begin_probe("probe-1").unwrap());
        assert_eq!(
            reg.get("probe-1").unwrap().status,
            RunnerStatus::Unresponsive
        );
    }
}
