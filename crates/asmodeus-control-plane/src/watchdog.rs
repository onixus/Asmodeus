//! Background watchdog for runner probe health checks.

use crate::registry::RunnerRegistry;

/// Periodically probe runners and signal completion of the first health round.
/// Each probe has a deadline; failed probes also complete the initial round.
pub fn spawn_watchdog(
    registry: RunnerRegistry,
    interval_secs: u64,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::oneshot::Receiver<()>,
) {
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        let mut ready_tx = Some(ready_tx);
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(interval_secs.max(1)));
        loop {
            interval.tick().await;
            let runners = registry.list();
            for runner in runners {
                let Some(probe) = registry.begin_probe(&runner.id) else {
                    continue;
                };
                match crate::dispatch::ping(&probe.record.endpoint).await {
                    Ok(reply) => {
                        registry.update_heartbeat(
                            &probe,
                            reply.healthy,
                            reply.cpu_usage_pct,
                            &reply.version,
                        );
                        tracing::debug!(
                            runner_id = %runner.id,
                            cpu = reply.cpu_usage_pct,
                            "Runner heartbeat OK"
                        );
                    }
                    Err(e) => {
                        registry.mark_unresponsive(&probe);
                        tracing::warn!(
                            runner_id = %runner.id,
                            error = %e,
                            "Runner heartbeat probe failed"
                        );
                    }
                }
            }
            if let Some(ready_tx) = ready_tx.take() {
                let _ = ready_tx.send(());
            }
        }
    });
    (handle, ready_rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_watchdog_spawn_and_abort() {
        let registry = RunnerRegistry::new();
        let (handle, ready) = spawn_watchdog(registry, 60);
        tokio::time::timeout(std::time::Duration::from_secs(1), ready)
            .await
            .unwrap()
            .unwrap();
        assert!(!handle.is_finished());
        handle.abort();
    }
}
