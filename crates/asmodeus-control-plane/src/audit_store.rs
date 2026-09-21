//! Audit trail storage boundary.
//!
//! Owns synchronization and optional JSONL persistence so application and HTTP
//! layers do not manipulate `RwLock<AuditTrail>` or persistence paths directly.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use asmodeus_telemetry::{AuditRecord, AuditTrail};

#[derive(Clone, Debug)]
pub struct AuditStore {
    trail: Arc<RwLock<AuditTrail>>,
    path: Option<PathBuf>,
}

impl AuditStore {
    pub fn load(path: Option<PathBuf>) -> Self {
        let trail = match path.as_ref() {
            Some(path) => AuditTrail::load_from_file(path).unwrap_or_else(|err| {
                tracing::warn!(error = %err, path = %path.display(), "failed to load audit trail; starting empty");
                AuditTrail::new()
            }),
            None => AuditTrail::new(),
        };
        Self {
            trail: Arc::new(RwLock::new(trail)),
            path,
        }
    }

    pub fn records(&self) -> Vec<AuditRecord> {
        self.trail.read().unwrap().records().to_vec()
    }

    pub fn list(
        &self,
        limit: Option<usize>,
        scenario_id: Option<&str>,
        status: Option<&str>,
    ) -> Vec<AuditRecord> {
        self.trail.read().unwrap().list(limit, scenario_id, status)
    }

    pub fn get(&self, run_id: &str) -> Option<AuditRecord> {
        self.trail.read().unwrap().get(run_id).cloned()
    }

    pub fn len(&self) -> usize {
        self.trail.read().unwrap().len()
    }

    pub fn append(&self, record: AuditRecord) {
        self.trail.write().unwrap().append(record.clone());
        if let Some(path) = self.path.as_ref() {
            if let Err(err) = AuditTrail::append_to_file(&record, path) {
                tracing::warn!(error = %err, path = %path.display(), "failed to persist audit record");
            }
        }
    }

    pub fn update(&self, run_id: &str, record: AuditRecord) -> bool {
        let updated = self.trail.write().unwrap().update(run_id, record);
        if updated {
            self.persist_snapshot();
        }
        updated
    }

    pub fn export_jsonl(&self) -> String {
        self.trail.read().unwrap().export_jsonl()
    }

    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        self.trail.read().unwrap().export_json()
    }

    pub fn export_clickhouse_sql(&self) -> String {
        self.trail.read().unwrap().export_clickhouse_sql()
    }

    pub fn export_clickhouse_ndjson(&self) -> Result<String, serde_json::Error> {
        self.trail.read().unwrap().export_clickhouse_ndjson()
    }

    fn persist_snapshot(&self) {
        let Some(path) = self.path.as_ref() else {
            return;
        };
        if let Err(err) = self.trail.read().unwrap().save_to_file(path) {
            tracing::warn!(error = %err, path = %path.display(), "failed to persist audit trail snapshot");
        }
    }
}
