//! asmodeus-control-plane — central coordinator: REST (OpenAPI 3.1) for the
//! APEX gateway, RBAC engine (CISO/Auditor/SecOps => 403), signed-scenario
//! catalog and the run state machine. Dispatches signed scenarios to live
//! runners over gRPC when `ASMODEUS_RUNNER_ENDPOINT` is set, else simulates
//! in-process. Budget: <= 10% CPU / <= 128 MB RAM (ARCHITECTURE.md §6).

// The hand-written OpenAPI 3.1 spec is a single large `json!` literal; its
// nesting exceeds the default macro recursion limit.
#![recursion_limit = "512"]

mod api;
mod audit_store;
mod campaign;
mod campaign_http;
mod catalog;
mod config;
mod dispatch;
mod dto;
mod engine;
mod execution;
pub(crate) mod http;
#[cfg(test)]
mod http_tests;
mod openapi;
mod registry;
mod reporting;
mod runner_http;
mod runs_http;
mod scenario_http;
mod scheduler;
mod schedules_http;
mod state;
mod system_http;
mod watchdog;
mod webhook;

use catalog::Catalog;
use config::ControlPlaneConfig;
use http::router;
use state::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = ControlPlaneConfig::from_env()?;
    let state = AppState::new(Catalog::seeded())?;
    let _watchdog = watchdog::spawn_watchdog(state.registry.clone(), config.watchdog_interval_sec);
    let _scheduler = scheduler::spawn_scheduler(state.clone(), config.scheduler_interval_sec);
    let app = router(state);

    tracing::info!(
        addr = %config.listen_addr,
        watchdog_interval_sec = config.watchdog_interval_sec,
        scheduler_interval_sec = config.scheduler_interval_sec,
        "asmodeus-control-plane listening (synthetic-only, INV-0)"
    );
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
