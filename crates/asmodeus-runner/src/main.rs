//! asmodeus-runner — minimal execution probe. Runs atomic scenario actions
//! (synthetic canary encryption, and later network jitter/drop via eBPF and
//! process lifecycle fuzz) strictly inside canary scope, guarded by the safety
//! circuit breaker. Budget: <= 5% CPU / <= 32 MB RAM (ARCHITECTURE.md §6).
//!
//! Standalone dry-run today; the gRPC/mTLS control channel lands next.

mod canary;

use asmodeus_common::EXERCISE_TAG_RED_TEAM;
use asmodeus_safety::DeadManSwitch;
use canary::CanaryInjector;

fn main() {
    let dir =
        std::env::var("ASMODEUS_CANARY_DIR").unwrap_or_else(|_| "/tmp/asmodeus-canary/demo".into());

    println!(
        "{EXERCISE_TAG_RED_TEAM} asmodeus-runner {} — synthetic canary dry-run in {dir}",
        env!("CARGO_PKG_VERSION")
    );

    // A real runner keeps this fed by the control-plane heartbeat.
    let mut dms = DeadManSwitch::default();
    dms.record_beat();

    let injector = match CanaryInjector::new(&dir, 20, 64) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("refused: {e}");
            std::process::exit(2);
        }
    };

    println!("scope accepted: {}", injector.dir().display());

    match injector.inject() {
        Ok(report) => println!(
            "injected: {} canary files, {} bytes (synthetic XOR, reversible)",
            report.files_created, report.bytes_written
        ),
        Err(e) => {
            eprintln!("injection failed: {e}");
            let _ = injector.cleanup();
            std::process::exit(1);
        }
    }

    // Mandatory rollback (INV of §5): always clean up.
    match injector.cleanup() {
        Ok(()) => println!("cleanup: SUCCESS (canary removed, 0 host side-effects)"),
        Err(e) => {
            eprintln!("cleanup failed: {e}");
            std::process::exit(1);
        }
    }
}
