//! asmodeus-runner — minimal execution probe. Serves the gRPC `RunnerControl`
//! channel (mTLS in production) through which the control-plane dispatches
//! signed, synthetic scenarios; the runner verifies, injects in canary scope
//! and streams lifecycle events back. Budget: <= 5% CPU / <= 32 MB RAM (§6).
//!
//! `ASMODEUS_DRY_RUN=1` runs a standalone synthetic canary pass instead of
//! serving — handy for local validation without a control-plane.

#[cfg(all(target_os = "linux", feature = "ebpf"))]
mod aya_backend;
mod canary;
mod netchaos;
mod service;

use std::net::SocketAddr;

use asmodeus_common::EXERCISE_TAG_RED_TEAM;
use asmodeus_proto::RunnerControlServer;
use canary::CanaryInjector;
use service::RunnerService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    if std::env::var("ASMODEUS_DRY_RUN").is_ok() {
        return dry_run();
    }

    let addr: SocketAddr = std::env::var("ASMODEUS_RUNNER_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8850".into())
        .parse()?;

    let mut server = tonic::transport::Server::builder();
    match asmodeus_proto::tls::server_from_env()? {
        Some(tls) => {
            server = server.tls_config(tls)?;
            tracing::info!(%addr, "asmodeus-runner serving RunnerControl over mTLS");
        }
        None => tracing::warn!(%addr, "asmodeus-runner serving RunnerControl WITHOUT TLS (dev)"),
    }

    server
        .add_service(RunnerControlServer::new(RunnerService))
        .serve(addr)
        .await?;
    Ok(())
}

/// Standalone synthetic canary pass (no control-plane).
fn dry_run() -> Result<(), Box<dyn std::error::Error>> {
    let dir =
        std::env::var("ASMODEUS_CANARY_DIR").unwrap_or_else(|_| "/tmp/asmodeus-canary/demo".into());
    println!("{EXERCISE_TAG_RED_TEAM} asmodeus-runner dry-run in {dir}");

    let injector = CanaryInjector::new(&dir, 20, 64)?;
    println!("scope accepted: {}", injector.dir().display());
    let report = injector.inject()?;
    println!(
        "injected: {} canary files, {} bytes (synthetic XOR, reversible)",
        report.files_created, report.bytes_written
    );
    injector.cleanup()?;
    println!("cleanup: SUCCESS (canary removed, 0 host side-effects)");

    // Synthetic network-chaos pass on the reserved test segment (loopback).
    net_chaos_demo();
    Ok(())
}

/// Standalone synthetic `LATENCY_SPIKE_VM` pass against loopback. Uses the
/// platform default backend (simulator off Linux) and proves the mandatory
/// rollback: the session installs a rule then reverts it, leaving no residue.
fn net_chaos_demo() {
    use netchaos::{default_backend, NetChaosBackend, NetChaosSession, NetChaosSpec};

    let backend = default_backend();
    let spec = NetChaosSpec::latency_spike_demo();
    println!(
        "{EXERCISE_TAG_RED_TEAM} net-chaos: {}ms +/-{}ms latency, {}% loss on {} -> {} (backend={})",
        spec.latency_ms,
        spec.jitter_ms,
        spec.loss_pct,
        spec.iface,
        spec.target_cidr,
        backend.name()
    );
    let started = NetChaosSession::start(&backend, &spec);
    match started {
        Ok(mut session) => {
            let token = session.handle().map(|h| h.token).unwrap_or_default();
            println!("net-chaos rule installed (token={token}, test segment only, in scope)");
            match session.revert() {
                Ok(()) => println!("net-chaos rollback: SUCCESS (rules reverted, 0 residue)"),
                Err(e) => println!("net-chaos rollback FAILED: {e}"),
            }
        }
        Err(e) => println!("net-chaos refused (safety gate): {e}"),
    }
}
