//! Serialized audit commits: durable JSONL revisions precede in-memory publication.
//! Blocking workers own the whole transaction, including after request cancellation.

use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use asmodeus_telemetry::{Aggregate, AuditRecord, AuditTrail};

#[derive(Debug)]
struct Snapshot {
    trail: AuditTrail,
    aggregate: Aggregate,
}

#[derive(Clone, Debug)]
pub struct AuditStore {
    snapshot: Arc<RwLock<Snapshot>>,
    writer: Arc<Mutex<()>>,
    path: Option<PathBuf>,
}

impl AuditStore {
    pub fn load(path: Option<PathBuf>) -> io::Result<Self> {
        let trail = match path.as_ref() {
            Some(path) => AuditTrail::load_from_file(path)?,
            None => AuditTrail::new(),
        };
        let aggregate = Aggregate::from_records(trail.records());
        Ok(Self {
            snapshot: Arc::new(RwLock::new(Snapshot { trail, aggregate })),
            writer: Arc::new(Mutex::new(())),
            path,
        })
    }

    /// Startup reconciliation never retries a potentially executed operation.
    pub fn recover_incomplete(&self, key: &[u8]) -> io::Result<()> {
        let _writer = self.writer.lock().unwrap();
        for mut record in self.records().into_iter().filter(|r| !r.is_terminal()) {
            let old = record.clone();
            record.status = "INTERRUPTED".into();
            record.cleanup_status = "UNCONFIRMED".into();
            if let Some(evidence) = &mut record.evidence {
                evidence.cleanup_confirmed = false;
                evidence.failure_reason =
                    Some("control-plane restarted before terminal acknowledgement".into());
            }
            record.timestamp_utc = asmodeus_telemetry::current_utc_iso8601();
            let record = record.sign(key).map_err(io::Error::other)?;
            self.persist(&record)?;
            let mut snapshot = self.snapshot.write().unwrap();
            snapshot.aggregate.update_run(&old, &record);
            snapshot.trail.update(&record.run_id.clone(), record);
        }
        Ok(())
    }

    pub fn records(&self) -> Vec<AuditRecord> {
        self.snapshot.read().unwrap().trail.records().to_vec()
    }

    pub fn aggregate(&self) -> Aggregate {
        self.snapshot.read().unwrap().aggregate.clone()
    }

    pub fn list(
        &self,
        limit: Option<usize>,
        scenario_id: Option<&str>,
        status: Option<&str>,
    ) -> Vec<AuditRecord> {
        self.snapshot
            .read()
            .unwrap()
            .trail
            .list(limit, scenario_id, status)
    }

    pub fn get(&self, run_id: &str) -> Option<AuditRecord> {
        self.snapshot.read().unwrap().trail.get(run_id).cloned()
    }

    pub fn len(&self) -> usize {
        self.snapshot.read().unwrap().trail.len()
    }

    pub async fn append(&self, record: AuditRecord) -> io::Result<()> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let _writer = store.writer.lock().unwrap();
            if store.get(&record.run_id).is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "duplicate run ID",
                ));
            }
            store.persist(&record)?;
            let mut snapshot = store.snapshot.write().unwrap();
            snapshot.aggregate.record_run(&record);
            snapshot.trail.append(record);
            Ok(())
        })
        .await
        .map_err(io::Error::other)?
    }

    /// Read, modify, sign and persist against the latest revision under one writer lock.
    pub async fn update<F>(&self, run_id: String, update: F) -> io::Result<Option<AuditRecord>>
    where
        F: FnOnce(AuditRecord) -> io::Result<AuditRecord> + Send + 'static,
    {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let _writer = store.writer.lock().unwrap();
            let Some(old) = store.get(&run_id) else {
                return Ok(None);
            };
            let record = update(old.clone())?;
            if record.run_id != run_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "cannot change run ID",
                ));
            }
            store.persist(&record)?;
            let mut snapshot = store.snapshot.write().unwrap();
            snapshot.aggregate.update_run(&old, &record);
            snapshot.trail.update(&run_id, record.clone());
            Ok(Some(record))
        })
        .await
        .map_err(io::Error::other)?
    }

    fn persist(&self, record: &AuditRecord) -> io::Result<()> {
        if let Some(path) = &self.path {
            AuditTrail::append_to_file(record, path)?;
        }
        Ok(())
    }

    pub fn export_jsonl(&self) -> String {
        self.snapshot.read().unwrap().trail.export_jsonl()
    }

    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        self.snapshot.read().unwrap().trail.export_json()
    }

    pub fn export_clickhouse_sql(&self) -> String {
        self.snapshot.read().unwrap().trail.export_clickhouse_sql()
    }

    pub fn export_clickhouse_ndjson(&self) -> Result<String, serde_json::Error> {
        self.snapshot
            .read()
            .unwrap()
            .trail
            .export_clickhouse_ndjson()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asmodeus_telemetry::Measurements;
    use asmodeus_testkit::Polygon;

    fn record(id: &str) -> AuditRecord {
        AuditRecord {
            run_id: id.into(),
            scenario_id: "SCN-TEST".into(),
            scenario_name: "Test".into(),
            category: "red_team".into(),
            mitre_technique: "T1486".into(),
            mitre_tactic: "Impact".into(),
            severity: "high".into(),
            tag: "test".into(),
            initiator: "admin".into(),
            runner_id: "test".into(),
            status: "COMPLETED".into(),
            measurements: Measurements {
                mttd_ms: 10,
                mttr_ms: 20,
                blue_team_detected: true,
            },
            detection_source: "simulated".into(),
            containment_action: "simulated".into(),
            cleanup_status: "SUCCESS".into(),
            timestamp_utc: "2026-09-22T00:00:00Z".into(),
            signature_hex: String::new(),
            public_key_hex: String::new(),
            evidence: Some(asmodeus_telemetry::RunEvidence {
                execution_mode: "runner".into(),
                feedback_received: true,
                contained: true,
                cleanup_confirmed: true,
                failure_reason: None,
            }),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_feedback_and_appends_replay_without_lost_records_or_metrics() {
        let poly = Polygon::new("audit-concurrency");
        let path = poly.dir().join("audit.jsonl");
        let store = AuditStore::load(Some(path.clone())).unwrap();
        store.append(record("original")).await.unwrap();
        let mut tasks = Vec::new();
        for i in 0..32 {
            let store = store.clone();
            tasks.push(tokio::spawn(async move {
                store.append(record(&format!("run-{i}"))).await.unwrap();
                store
                    .update("original".into(), |mut record| {
                        record.measurements.mttd_ms += 1;
                        record.measurements.blue_team_detected =
                            !record.measurements.blue_team_detected;
                        Ok(record)
                    })
                    .await
                    .unwrap()
                    .unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(store.len(), 33);
        assert_eq!(store.get("original").unwrap().measurements.mttd_ms, 42);
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 65);
        let restored = AuditStore::load(Some(path)).unwrap();
        assert_eq!(store.records(), restored.records());
        assert_eq!(
            store.aggregate().prometheus_text(),
            restored.aggregate().prometheus_text()
        );
        assert_eq!(store.aggregate().detected, 33);
    }

    #[tokio::test]
    async fn failed_persistence_does_not_publish_append_or_feedback() {
        let poly = Polygon::new("audit-failure");
        let path = poly.dir().join("audit.jsonl");
        let store = AuditStore::load(Some(path.clone())).unwrap();
        store.append(record("original")).await.unwrap();
        let before = store.aggregate().prometheus_text();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap(); // Deterministic I/O failure, even as root.
        assert!(store.append(record("failed")).await.is_err());
        assert!(store
            .update("original".into(), |mut r| {
                r.status = "DETECTED".into();
                Ok(r)
            })
            .await
            .is_err());
        assert_eq!(store.len(), 1);
        assert_eq!(store.get("original").unwrap().status, "COMPLETED");
        assert_eq!(store.aggregate().prometheus_text(), before);
    }

    #[test]
    fn corrupt_log_does_not_silently_reset_history() {
        let poly = Polygon::new("audit-corrupt");
        std::fs::create_dir_all(poly.dir()).unwrap();
        let path = poly.dir().join("audit.jsonl");
        std::fs::write(&path, "{truncated").unwrap();
        assert!(AuditStore::load(Some(path.clone())).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "{truncated");
    }

    #[tokio::test]
    async fn duplicate_id_and_changed_update_id_are_rejected() {
        let store = AuditStore::load(None).unwrap();
        store.append(record("original")).await.unwrap();
        assert!(store.append(record("original")).await.is_err());
        assert!(store
            .update("original".into(), |mut r| {
                r.run_id = "other".into();
                Ok(r)
            })
            .await
            .is_err());
        assert!(store.update("missing".into(), Ok).await.unwrap().is_none());
        assert_eq!(store.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_request_does_not_cancel_a_started_commit() {
        let poly = Polygon::new("audit-cancel");
        let path = poly.dir().join("audit.jsonl");
        let store = AuditStore::load(Some(path.clone())).unwrap();
        store.append(record("original")).await.unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let writer = store.clone();
        let task = tokio::spawn(async move {
            writer
                .update("original".into(), move |mut r| {
                    started_tx.send(()).unwrap();
                    resume_rx.recv().unwrap();
                    r.status = "DETECTED".into();
                    Ok(r)
                })
                .await
        });
        started_rx.await.unwrap();
        task.abort();
        resume_tx.send(()).unwrap();
        // This serialized commit is a barrier behind the cancelled caller's worker.
        store.append(record("barrier")).await.unwrap();
        assert_eq!(store.get("original").unwrap().status, "DETECTED");
        assert_eq!(
            store.records(),
            AuditStore::load(Some(path)).unwrap().records()
        );
    }
}
