use super::*;
use asmodeus_testkit::Polygon;

fn runner(id: &str) -> RunnerRecord {
    RunnerRecord::new(id, "Probe", "http://127.0.0.1:1", vec!["test".into()])
}

#[tokio::test]
async fn restart_preserves_configuration_and_drain_but_not_health() {
    let polygon = Polygon::new("runner-restart");
    let path = polygon.dir().join("runners.json");
    let reg = RunnerRegistry::new()
        .with_persistence(Some(path.clone()))
        .unwrap();
    reg.register(runner("drained")).await.unwrap();
    reg.register(runner("active")).await.unwrap();
    reg.register(runner("deleted")).await.unwrap();
    reg.set_draining("drained", true).await.unwrap();
    reg.deregister("deleted").await.unwrap();
    let before = std::fs::read(&path).unwrap();
    let probe = reg.begin_probe("active").unwrap();
    assert!(reg.update_heartbeat(&probe, true, 42, "observed-version"));
    assert_eq!(std::fs::read(&path).unwrap(), before); // heartbeats do not write

    let restored = RunnerRegistry::with_default("env-default", "http://127.0.0.1:2", vec![])
        .with_persistence(Some(path.clone()))
        .unwrap();
    assert_eq!(restored.list().len(), 2);
    assert!(restored.get("env-default").is_none());
    assert!(restored.get("deleted").is_none());
    assert_eq!(
        restored.get("drained").unwrap().status,
        RunnerStatus::Draining
    );
    let active = restored.get("active").unwrap();
    assert_eq!(active.status, RunnerStatus::Unresponsive);
    assert_eq!(active.tags, vec!["test"]);
    assert_eq!(active.last_heartbeat_utc, None);
    assert_eq!(active.cpu_usage_pct, 0);
    assert!(active.version.is_empty());
    assert!(restored.find_for_target(None).is_none());
    // A token from another process/registry instance cannot publish health.
    assert!(!restored.update_heartbeat(&probe, true, 42, "old"));
    restored.set_draining("drained", false).await.unwrap();
    let again = RunnerRegistry::new().with_persistence(Some(path)).unwrap();
    assert_eq!(
        again.get("drained").unwrap().status,
        RunnerStatus::Unresponsive
    );
    let probe = again.begin_probe("drained").unwrap();
    assert!(again.update_heartbeat(&probe, true, 1, "live"));
    assert_eq!(again.find_for_target(None).unwrap().id, "drained");
}

#[tokio::test]
async fn bootstrap_and_last_deletion_are_persistent_and_authoritative() {
    let polygon = Polygon::new("runner-delete");
    let path = polygon.dir().join("runners.json");
    let reg = RunnerRegistry::with_default("default-runner", "http://127.0.0.1:1", vec![])
        .with_persistence(Some(path.clone()))
        .unwrap();
    assert!(path.is_file());
    assert_eq!(
        reg.get("default-runner").unwrap().status,
        RunnerStatus::Unresponsive
    );
    reg.deregister("default-runner").await.unwrap();
    let restored = RunnerRegistry::with_default("default-runner", "http://127.0.0.1:2", vec![])
        .with_persistence(Some(path))
        .unwrap();
    assert!(restored.list().is_empty());
    assert!(restored.requires_runner());
    let demo_path = polygon.dir().join("demo.json");
    let demo = RunnerRegistry::new()
        .with_persistence(Some(demo_path.clone()))
        .unwrap();
    assert!(!demo.requires_runner());
    assert!(!RunnerRegistry::new()
        .with_persistence(Some(demo_path))
        .unwrap()
        .requires_runner());
}

#[tokio::test]
async fn failed_write_does_not_publish_and_recovery_retries_safely() {
    let polygon = Polygon::new("runner-write-failure");
    let path = polygon.dir().join("runners.json");
    let reg = RunnerRegistry::new()
        .with_persistence(Some(path.clone()))
        .unwrap();
    reg.register(runner("probe")).await.unwrap();
    let backup = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap(); // atomic replacement must fail
    assert!(reg.set_draining("probe", true).await.is_err());
    assert!(reg.register(runner("new")).await.is_err());
    assert!(reg.deregister("probe").await.is_err());
    assert_eq!(reg.get("probe").unwrap().status, RunnerStatus::Active);
    assert!(reg.get("new").is_none());
    assert_eq!(std::fs::read_dir(polygon.dir()).unwrap().count(), 1); // temp cleanup
    std::fs::remove_dir(&path).unwrap();
    std::fs::write(&path, backup).unwrap();
    reg.set_draining("probe", true).await.unwrap();
    assert_eq!(
        RunnerRegistry::new()
            .with_persistence(Some(path))
            .unwrap()
            .get("probe")
            .unwrap()
            .status,
        RunnerStatus::Draining
    );
}

#[test]
fn corrupt_or_unsupported_snapshots_fail_closed_without_reseeding() {
    let polygon = Polygon::new("runner-corruption");
    std::fs::create_dir_all(polygon.dir()).unwrap();
    let path = polygon.dir().join("runners.json");
    let entry = serde_json::json!({"id":"probe","name":"Probe","endpoint":"http://127.0.0.1:1",
        "tags":[],"draining":true,"registered_at_utc":1});
    let valid = serde_json::json!({"version":1,"require_runner":true,"runners":[entry.clone()]});
    let mut invalid_endpoint = valid.clone();
    invalid_endpoint["runners"][0]["endpoint"] = serde_json::json!("ftp://127.0.0.1");
    for data in [
        b"{".to_vec(),
        b"null".to_vec(),
        serde_json::to_vec(&serde_json::json!({"version":2,"require_runner":true,"runners":[]}))
            .unwrap(),
        serde_json::to_vec(
            &serde_json::json!({"version":1,"require_runner":false,"runners":[entry.clone()]}),
        )
        .unwrap(),
        serde_json::to_vec(
            &serde_json::json!({"version":1,"require_runner":true,"runners":[entry.clone(),entry]}),
        )
        .unwrap(),
        serde_json::to_vec(&invalid_endpoint).unwrap(),
    ] {
        std::fs::write(&path, &data).unwrap();
        let error = RunnerRegistry::with_default("default", "http://127.0.0.1:2", vec![])
            .with_persistence(Some(path.clone()))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read(&path).unwrap(), data);
    }
}

#[tokio::test]
async fn concurrent_writers_do_not_lose_configuration() {
    let polygon = Polygon::new("runner-concurrency");
    let path = polygon.dir().join("runners.json");
    let reg = RunnerRegistry::new()
        .with_persistence(Some(path.clone()))
        .unwrap();
    let mut tasks = Vec::new();
    for n in 0..12 {
        let reg = reg.clone();
        tasks.push(tokio::spawn(async move {
            let id = format!("probe-{n}");
            reg.register(runner(&id)).await.unwrap();
            reg.set_draining(&id, true).await.unwrap();
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let restored = RunnerRegistry::new().with_persistence(Some(path)).unwrap();
    assert_eq!(restored.list().len(), 12);
    assert!(restored
        .list()
        .iter()
        .all(|r| r.status == RunnerStatus::Draining));
}

#[tokio::test]
async fn cancelled_caller_does_not_cancel_commit_or_overwrite_concurrent_health() {
    let polygon = Polygon::new("runner-cancelled-write");
    let path = polygon.dir().join("runners.json");
    let reg = RunnerRegistry::new()
        .with_persistence(Some(path.clone()))
        .unwrap();
    reg.register(runner("probe")).await.unwrap();
    let worker_reg = reg.clone();
    let (ready_tx, mut ready_rx) = tokio::sync::mpsc::unbounded_channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let first = std::sync::atomic::AtomicBool::new(true);
    let task = tokio::spawn(async move {
        worker_reg
            .update(move |data| {
                if first.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    ready_tx.send(()).unwrap();
                    release_rx
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap();
                }
                let mut updated = runner("probe");
                updated.name = "Committed rename".into();
                data.register(updated)
            })
            .await
    });
    ready_rx.recv().await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let heartbeat = reg.begin_probe("probe").unwrap();
    assert!(reg.update_heartbeat(&heartbeat, true, 19, "concurrent-health"));
    release_tx.send(()).unwrap();
    // A subsequent serialized update is a completion barrier for the worker.
    reg.set_draining("probe", false).await.unwrap();
    let current = reg.get("probe").unwrap();
    assert_eq!(current.name, "Committed rename");
    assert_eq!(current.cpu_usage_pct, 19);
    assert_eq!(current.version, "concurrent-health");
    let restored = RunnerRegistry::new().with_persistence(Some(path)).unwrap();
    assert_eq!(restored.get("probe").unwrap().name, "Committed rename");
}
