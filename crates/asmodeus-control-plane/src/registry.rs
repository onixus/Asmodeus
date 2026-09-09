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

#[derive(Debug, Clone, Default)]
pub struct RunnerRegistry {
    runners: Arc<RwLock<HashMap<String, RunnerRecord>>>,
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
    pub fn register(&self, record: RunnerRecord) {
        let mut map = self.runners.write().unwrap();
        map.insert(record.id.clone(), record);
    }

    /// Deregister a runner by its ID.
    pub fn deregister(&self, id: &str) -> bool {
        let mut map = self.runners.write().unwrap();
        map.remove(id).is_some()
    }

    /// Look up a runner by its unique ID.
    pub fn get(&self, id: &str) -> Option<RunnerRecord> {
        let map = self.runners.read().unwrap();
        map.get(id).cloned()
    }

    /// List all registered runners sorted by ID.
    pub fn list(&self) -> Vec<RunnerRecord> {
        let map = self.runners.read().unwrap();
        let mut list: Vec<_> = map.values().cloned().collect();
        list.sort_by(|a, b| a.id.cmp(&b.id));
        list
    }

    /// Find an appropriate runner for a target override or tag selector.
    ///
    /// Strategy:
    /// 1. If `target` matches a runner ID exactly, use that runner.
    /// 2. If `target` matches any runner's tag (case-insensitive), choose an active matching runner.
    /// 3. If `target` is None or empty, return the first `Active` runner (or any registered runner).
    pub fn find_for_target(&self, target: Option<&str>) -> Option<RunnerRecord> {
        let map = self.runners.read().unwrap();
        if map.is_empty() {
            return None;
        }

        if let Some(tgt) = target {
            let trimmed = tgt.trim();
            if !trimmed.is_empty() {
                // 1. Exact ID match
                if let Some(record) = map.get(trimmed) {
                    return Some(record.clone());
                }

                // 2. Tag match (prefer Active)
                let tag_matches: Vec<_> = map
                    .values()
                    .filter(|r| r.tags.iter().any(|t| t.eq_ignore_ascii_case(trimmed)))
                    .collect();

                if let Some(active) = tag_matches
                    .iter()
                    .find(|r| r.status == RunnerStatus::Active)
                {
                    return Some((*active).clone());
                }
                if let Some(first) = tag_matches.first() {
                    return Some((*first).clone());
                }

                // Target was explicitly requested, but neither ID nor tag matched.
                return None;
            }
        }

        // 3. Fallback when no specific target requested: first active, or first overall
        map.values()
            .find(|r| r.status == RunnerStatus::Active)
            .or_else(|| map.values().next())
            .cloned()
    }

    /// Update health and metrics after a successful heartbeat.
    pub fn update_heartbeat(&self, id: &str, healthy: bool, cpu_pct: u32, version: &str) {
        let mut map = self.runners.write().unwrap();
        if let Some(r) = map.get_mut(id) {
            r.status = if healthy {
                RunnerStatus::Active
            } else {
                RunnerStatus::Unresponsive
            };
            r.cpu_usage_pct = cpu_pct;
            r.last_heartbeat_utc = Some(now_epoch_secs());
            if !version.is_empty() {
                r.version = version.to_string();
            }
        }
    }

    /// Mark a runner as unresponsive on connection failure.
    pub fn mark_unresponsive(&self, id: &str) {
        let mut map = self.runners.write().unwrap();
        if let Some(r) = map.get_mut(id) {
            r.status = RunnerStatus::Unresponsive;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        reg.update_heartbeat("probe-1", true, 4, "0.1.0");
        let item = reg.get("probe-1").unwrap();
        assert_eq!(item.status, RunnerStatus::Active);
        assert_eq!(item.cpu_usage_pct, 4);

        reg.mark_unresponsive("probe-1");
        assert_eq!(
            reg.get("probe-1").unwrap().status,
            RunnerStatus::Unresponsive
        );
    }
}
