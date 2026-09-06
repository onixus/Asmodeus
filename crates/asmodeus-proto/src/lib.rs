//! asmodeus-proto — wire contracts for the control<->runner mTLS gRPC channel
//! and the REST DTOs exposed to the APEX gateway. Skeleton holds hand-written
//! structs; swap for tonic-generated code once `.proto` files land.
pub mod stub {
    /// Heartbeat cadence for the Dead-Man switch (see ARCHITECTURE.md §5).
    pub const HEARTBEAT_INTERVAL_MS: u64 = 1000;
    pub const HEARTBEAT_MISS_LIMIT: u8 = 3;
}
