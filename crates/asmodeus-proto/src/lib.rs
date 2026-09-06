//! asmodeus-proto — generated gRPC contracts for the control<->runner channel
//! (mTLS in production) plus TLS config helpers. The `.proto` is the source of
//! truth; this crate re-exports the tonic-generated client and server.

pub mod v1 {
    tonic::include_proto!("asmodeus.v1");
}

pub use v1::runner_control_client::RunnerControlClient;
pub use v1::runner_control_server::{RunnerControl, RunnerControlServer};
pub use v1::{EventKind, ExecuteRequest, HeartbeatReply, HeartbeatRequest, RunnerEvent};

pub mod tls;

/// Dead-man switch heartbeat cadence (see ARCHITECTURE.md §5).
pub const HEARTBEAT_INTERVAL_MS: u64 = 1000;
pub const HEARTBEAT_MISS_LIMIT: u8 = 3;
