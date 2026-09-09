//! asmodeus-control-plane — central coordinator: REST (OpenAPI 3.1) for the
//! APEX gateway, RBAC engine (CISO/Auditor/SecOps => 403), signed-scenario
//! catalog and the run state machine. Dispatches signed scenarios to live
//! runners over gRPC when `ASMODEUS_RUNNER_ENDPOINT` is set, else simulates
//! in-process. Budget: <= 10% CPU / <= 128 MB RAM (ARCHITECTURE.md §6).

mod catalog;
mod dispatch;
mod engine;
mod http;
mod registry;

use std::net::SocketAddr;

use catalog::Catalog;
use http::{router, AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let state = AppState::new(Catalog::seeded());
    let app = router(state);

    let addr: SocketAddr = std::env::var("ASMODEUS_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8842".into())
        .parse()?;

    tracing::info!(%addr, "asmodeus-control-plane listening (synthetic-only, INV-0)");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
