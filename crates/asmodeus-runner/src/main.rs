//! asmodeus-runner — minimal execution probe. Runs atomic scenario actions
//! (canary encryption, network jitter/drop via eBPF, process lifecycle fuzz)
//! strictly inside canary scope, guarded by the safety circuit breaker.
//! Budget: <= 5% CPU / <= 32 MB RAM (see ARCHITECTURE.md §6).
fn main() {
    println!(
        "asmodeus-runner {} — probe idle; awaiting signed scenario over mTLS gRPC",
        env!("CARGO_PKG_VERSION")
    );
}
