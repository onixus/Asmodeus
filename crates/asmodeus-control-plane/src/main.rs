//! asmodeus-control-plane — central coordinator: REST (OpenAPI 3.1) for the
//! APEX gateway, mTLS gRPC to runners, RBAC engine (CISO/Auditor => 403),
//! signed-scenario catalog and the run state machine.
//! Budget: <= 10% CPU / <= 128 MB RAM (see ARCHITECTURE.md §6).
fn main() {
    println!(
        "asmodeus-control-plane {} — not serving yet (skeleton)",
        env!("CARGO_PKG_VERSION")
    );
}
