//! Background watchdog for runner probe health checks.

use crate::registry::RunnerRegistry;

/// Spawn a background task periodically pinging registered runners.
pub fn spawn_watchdog(registry: RunnerRegistry, interval_secs: u64) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
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
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_watchdog_spawn_and_abort() {
        let registry = RunnerRegistry::new();
        let handle = spawn_watchdog(registry, 60);
        assert!(!handle.is_finished());
        handle.abort();
    }
}
