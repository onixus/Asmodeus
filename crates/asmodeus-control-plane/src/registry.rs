//! Runner Registry — tracks active, connected and ephemeral runner probes
//! (ARCHITECTURE.md §2, TT.md §1.1).
//!
//! Replaces a single static endpoint with a thread-safe registry supporting
//! discovery, tag-based routing (`k8s_workload`, `endpoint_agent`, `network_gateway`),
//! and health tracking via gRPC Heartbeat.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::{io, path::PathBuf};

use crate::registry_store::RegistrySnapshot;
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
pub(super) struct RegisteredRunner {
    pub(super) record: RunnerRecord,
    pub(super) epoch: Arc<()>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct RegistryData {
    pub(super) runners: HashMap<String, RegisteredRunner>,
    // Sticky once configured: removing the final runner must not re-enable
    // simulation or a static environment fallback, including after restart.
    pub(super) require_runner: bool,
}

impl RegistryData {
    fn register(&mut self, mut record: RunnerRecord) -> RunnerRecord {
        if let Some(previous) = self.runners.get(&record.id) {
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
        self.require_runner = true;
        self.runners.insert(
            record.id.clone(),
            RegisteredRunner {
                record: record.clone(),
                epoch: Arc::new(()),
            },
        );
        record
    }

    fn set_draining(&mut self, id: &str, draining: bool) -> Option<RunnerRecord> {
        let runner = self.runners.get_mut(id)?;
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
}

#[derive(Debug, Clone, Default)]
pub struct RunnerRegistry {
    data: Arc<RwLock<RegistryData>>,
    writer: Arc<Mutex<()>>,
    path: Option<PathBuf>,
}

impl RunnerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed used only when no durable snapshot exists.
    pub fn with_default(id: &str, endpoint: &str, tags: Vec<String>) -> Self {
        let registry = Self::new();
        // Preserve dispatch's historical host:port shorthand. An explicit HTTP
        // scheme is still upgraded to HTTPS by dispatch when mTLS is configured.
        let endpoint = if endpoint.contains("://") {
            endpoint.to_string()
        } else {
            format!("http://{endpoint}")
        };
        registry.data.write().unwrap().register(RunnerRecord::new(
            id,
            "Default Probe",
            endpoint,
            tags,
        ));
        registry
    }

    /// Startup only. A snapshot is authoritative over environment defaults.
    /// Restored health is unknown; the durable maintenance decision is retained.
    pub fn with_persistence(self, path: Option<PathBuf>) -> io::Result<Self> {
        let Some(path) = path else {
            return Ok(self);
        };
        let snapshot = match std::fs::read(&path) {
            Ok(bytes) => RegistrySnapshot::decode(&bytes)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let snapshot = RegistrySnapshot::from_data(&self.data.read().unwrap());
                snapshot.validate()?;
                snapshot.write(&path)?;
                snapshot
            }
            Err(error) => return Err(error),
        };
        let restored = snapshot.into_data();
        // The snapshot wins; make an ignored environment seed visible.
        for seed in self.data.read().unwrap().runners.values() {
            let kept = restored.runners.get(&seed.record.id);
            if kept.is_none_or(|r| r.record.endpoint != seed.record.endpoint) {
                tracing::warn!(
                    runner_id = %seed.record.id,
                    endpoint = %seed.record.endpoint,
                    snapshot = %path.display(),
                    "ASMODEUS_RUNNER_ENDPOINT seed ignored: runner snapshot is authoritative; register the runner via API/CLI"
                );
            }
        }
        Ok(Self {
            data: Arc::new(RwLock::new(restored)),
            writer: Arc::new(Mutex::new(())),
            path: Some(path),
        })
    }

    /// The worker owns persist + publish even when the HTTP caller disconnects.
    /// Configuration writers serialize; readers and heartbeat updates never
    /// hold a lock across disk I/O. Reapplying to live data preserves heartbeats
    /// received during the write instead of replacing them with a stale clone.
    /// The mutation runs twice and must be deterministic for configuration;
    /// only its second result (with current health observations) is returned.
    async fn update<R: Send + 'static>(
        &self,
        update: impl Fn(&mut RegistryData) -> R + Send + 'static,
    ) -> io::Result<R> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let _writer = store.writer.lock().unwrap();
            let mut next = store.data.read().unwrap().clone();
            let before = RegistrySnapshot::from_data(&next);
            update(&mut next);
            let after = RegistrySnapshot::from_data(&next);
            if let Some(path) = &store.path {
                if before != after {
                    after.write(path)?;
                }
            }
            Ok(update(&mut store.data.write().unwrap()))
        })
        .await
        .map_err(io::Error::other)?
    }

    pub async fn register(&self, mut record: RunnerRecord) -> io::Result<RunnerRecord> {
        crate::registry_store::validate_identity(&record.id, &record.endpoint)?;
        // A new (or re-created) runner is routable only after a healthy probe;
        // existing entries keep their state via RegistryData::register.
        if record.status != RunnerStatus::Draining {
            record.status = RunnerStatus::Unresponsive;
        }
        record.last_heartbeat_utc = None;
        record.cpu_usage_pct = 0;
        record.version.clear();
        self.update(move |data| data.register(record.clone())).await
    }

    /// Already selected runs continue. Resume requires a fresh healthy probe.
    pub async fn set_draining(&self, id: &str, draining: bool) -> io::Result<Option<RunnerRecord>> {
        let id = id.to_string();
        self.update(move |data| data.set_draining(&id, draining))
            .await
    }

    pub async fn deregister(&self, id: &str) -> io::Result<bool> {
        let id = id.to_string();
        self.update(move |data| data.runners.remove(&id).is_some())
            .await
    }

    pub fn begin_probe(&self, id: &str) -> Option<RunnerProbe> {
        let mut data = self.data.write().unwrap();
        let runner = data.runners.get_mut(id)?;
        runner.epoch = Arc::new(());
        Some(RunnerProbe {
            record: runner.record.clone(),
            epoch: runner.epoch.clone(),
        })
    }

    #[cfg(test)]
    pub fn get(&self, id: &str) -> Option<RunnerRecord> {
        self.data
            .read()
            .unwrap()
            .runners
            .get(id)
            .map(|r| r.record.clone())
    }

    pub fn list(&self) -> Vec<RunnerRecord> {
        let data = self.data.read().unwrap();
        let mut list: Vec<_> = data.runners.values().map(|r| r.record.clone()).collect();
        list.sort_by(|a, b| a.id.cmp(&b.id));
        list
    }

    /// Exact IDs never fall back to tags; ties remain stable by runner ID.
    pub fn find_for_target(&self, target: Option<&str>) -> Option<RunnerRecord> {
        let data = self.data.read().unwrap();
        let target = target.map(str::trim).filter(|t| !t.is_empty());
        if let Some(record) = target.and_then(|t| data.runners.get(t)).map(|r| &r.record) {
            return (record.status == RunnerStatus::Active).then(|| record.clone());
        }
        data.runners
            .values()
            .map(|r| &r.record)
            .filter(|r| r.status == RunnerStatus::Active)
            .filter(|r| target.is_none_or(|t| r.tags.iter().any(|tag| tag.eq_ignore_ascii_case(t))))
            .min_by(|a, b| a.id.cmp(&b.id))
            .cloned()
    }

    pub fn requires_runner(&self) -> bool {
        self.data.read().unwrap().require_runner
    }

    pub fn update_heartbeat(
        &self,
        probe: &RunnerProbe,
        healthy: bool,
        cpu_pct: u32,
        version: &str,
    ) -> bool {
        let mut data = self.data.write().unwrap();
        if let Some(runner) = data
            .runners
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

    pub fn mark_unresponsive(&self, probe: &RunnerProbe) -> bool {
        let mut data = self.data.write().unwrap();
        if let Some(runner) = data
            .runners
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
#[path = "registry_persistence_tests.rs"]
mod persistence_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn endpoint_replacement_requires_health_and_metadata_updates_preserve_it() {
        let reg = RunnerRegistry::with_default("probe", "http://127.0.0.1:1", vec![]);
        let probe = reg.begin_probe("probe").unwrap();
        reg.update_heartbeat(&probe, true, 7, "live-version");
        let before = reg.get("probe").unwrap();
        let updated = reg
            .register(RunnerRecord::new(
                "probe",
                "Renamed",
                "http://127.0.0.1:1",
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(updated.status, RunnerStatus::Active);
        assert_eq!(updated.last_heartbeat_utc, before.last_heartbeat_utc);
        assert_eq!(updated.registered_at_utc, before.registered_at_utc);
        assert_eq!(updated.cpu_usage_pct, 7);
        assert_eq!(updated.version, "live-version");
        let changed = reg
            .register(RunnerRecord::new(
                "probe",
                "Changed",
                "http://127.0.0.1:2",
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(changed.status, RunnerStatus::Unresponsive);
        assert_eq!(changed.last_heartbeat_utc, None);
        assert_eq!(changed.cpu_usage_pct, 0);
        assert!(changed.version.is_empty());
        assert!(!reg.update_heartbeat(&probe, true, 7, "old"));
        assert!(reg.find_for_target(None).is_none());
    }

    #[tokio::test]
    async fn registration_cannot_bypass_resume_health_gate() {
        let reg = RunnerRegistry::with_default("probe", "http://127.0.0.1:1", vec![]);
        reg.set_draining("probe", true).await.unwrap();
        reg.set_draining("probe", false).await.unwrap();
        let saved = reg
            .register(RunnerRecord::new(
                "probe",
                "Updated",
                "http://127.0.0.1:1",
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(saved.status, RunnerStatus::Unresponsive);
        assert_eq!(saved.last_heartbeat_utc, None);
        assert!(reg.find_for_target(None).is_none());
    }

    #[tokio::test]
    async fn resume_requires_a_fresh_healthy_probe_and_is_idempotent() {
        let reg = RunnerRegistry::with_default("probe", "http://127.0.0.1:1", vec!["test".into()]);
        let before_drain = reg.begin_probe("probe").unwrap();
        assert_eq!(
            reg.set_draining("probe", true)
                .await
                .unwrap()
                .unwrap()
                .status,
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
        let resumed = reg.set_draining("probe", false).await.unwrap().unwrap();
        assert_eq!(resumed.status, RunnerStatus::Unresponsive);
        assert_eq!(resumed.last_heartbeat_utc, None);
        assert!(!reg.update_heartbeat(&during_drain, true, 3, "stale"));
        let fresh = reg.begin_probe("probe").unwrap();
        reg.set_draining("probe", false).await.unwrap(); // a retried resume must not invalidate it
        assert!(reg.update_heartbeat(&fresh, false, 4, "unhealthy"));
        assert!(reg.find_for_target(None).is_none());
        let healthy = reg.begin_probe("probe").unwrap();
        assert!(reg.update_heartbeat(&healthy, true, 5, "healthy"));
        assert_eq!(
            reg.set_draining("probe", false)
                .await
                .unwrap()
                .unwrap()
                .status,
            RunnerStatus::Active
        );
        assert_eq!(reg.find_for_target(Some("test")).unwrap().id, "probe");
        assert!(reg.set_draining("missing", true).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn stale_probe_results_cannot_overwrite_newer_health_or_registration() {
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
                reg.deregister("probe").await.unwrap();
            }
            reg.register(RunnerRecord::new(
                "probe",
                "Replacement",
                "http://127.0.0.1:2",
                vec![],
            ))
            .await
            .unwrap();
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

    #[tokio::test]
    async fn registration_does_not_clear_operator_drain() {
        let reg = RunnerRegistry::new();
        let mut record = RunnerRecord::new("probe", "Probe", "http://127.0.0.1:1", vec![]);
        record.status = RunnerStatus::Draining;
        reg.register(record).await.unwrap();
        reg.register(RunnerRecord::new(
            "probe",
            "Replacement",
            "http://127.0.0.1:2",
            vec![],
        ))
        .await
        .unwrap();
        assert_eq!(reg.get("probe").unwrap().status, RunnerStatus::Draining);
        assert!(reg.find_for_target(Some("probe")).is_none());
    }

    #[tokio::test]
    async fn unavailable_and_draining_runners_are_never_selected() {
        let reg = RunnerRegistry::with_default("probe", "http://127.0.0.1:1", vec!["test".into()]);
        reg.mark_unresponsive(&reg.begin_probe("probe").unwrap());
        for target in [None, Some("probe"), Some("test")] {
            assert!(reg.find_for_target(target).is_none());
        }
        reg.set_draining("probe", true).await.unwrap();
        reg.update_heartbeat(&reg.begin_probe("probe").unwrap(), true, 0, "test");
        reg.mark_unresponsive(&reg.begin_probe("probe").unwrap());
        assert_eq!(reg.get("probe").unwrap().status, RunnerStatus::Draining);
        assert!(reg.find_for_target(None).is_none());
    }

    #[tokio::test]
    async fn register_and_list_runners() {
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

        reg.register(r1).await.unwrap();
        reg.register(r2).await.unwrap();

        let all = reg.list();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, "k8s-pod-1");
        assert_eq!(all[1].id, "lariska-1");

        assert!(reg.deregister("lariska-1").await.unwrap());
        assert_eq!(reg.list().len(), 1);
        assert!(!reg.deregister("non-existent").await.unwrap());
    }

    #[tokio::test]
    async fn find_for_target_routing() {
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

        reg.register(r1).await.unwrap();
        reg.register(r2).await.unwrap();
        for id in ["node-a", "node-b"] {
            reg.update_heartbeat(&reg.begin_probe(id).unwrap(), true, 0, "test");
        }

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

    #[tokio::test]
    async fn update_heartbeat_and_unresponsive() {
        let reg = RunnerRegistry::new();
        let r = RunnerRecord::new("probe-1", "Probe", "http://127.0.0.1:8850", vec![]);
        reg.register(r).await.unwrap();

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
