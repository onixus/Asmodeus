//! gRPC `RunnerControl` server. Execute verifies the scenario signature, gates
//! on INV-0 / canary scope, runs the synthetic injection and streams lifecycle
//! events. Detect/Contain are simulated here (no live Blue Team in the loop);
//! in production those come from correlated Ferrum/SOAR telemetry, not the
//! runner self-declaring them.

use std::pin::Pin;
use std::time::Instant;

use asmodeus_common::{ActionNature, RunEvent, RunState};
use asmodeus_dsl::validate;
use asmodeus_proto::{
    EventKind, ExecuteRequest, HeartbeatReply, HeartbeatRequest, RunnerControl, RunnerEvent,
};
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use crate::canary::CanaryInjector;

#[derive(Debug, Default, Clone)]
pub struct RunnerService;

/// Resource caps for a single injection, derived from the runner budget
/// (<= 20 MB disk / <= 32 MB RAM, ARCHITECTURE.md §6). A request that exceeds
/// any of these is refused before a single file is written, so an unbounded
/// `file_count`/`chunk_size_kb` cannot exhaust memory or fill the sandbox.
pub const MAX_FILE_COUNT: u32 = 1000;
pub const MAX_CHUNK_KB: u32 = 256;
pub const MAX_TOTAL_KB: u64 = 20 * 1024;

/// Convenience constructors for the wire event.
fn state_event(state: RunState) -> RunnerEvent {
    RunnerEvent {
        kind: EventKind::StateChanged as i32,
        state: format!("{state:?}"),
        ..Default::default()
    }
}

fn rejected(detail: impl Into<String>) -> RunnerEvent {
    RunnerEvent {
        kind: EventKind::Rejected as i32,
        detail: detail.into(),
        ..Default::default()
    }
}

impl RunnerService {
    /// Build the full event sequence for one request. Pure enough to unit-test
    /// without a transport.
    fn plan(req: &ExecuteRequest) -> Vec<RunnerEvent> {
        // 1. Integrity: signature must verify against the supplied public key.
        if !asmodeus_crypto::is_valid(&req.manifest, &req.signature, &req.public_key) {
            return vec![rejected("signature invalid")];
        }

        // 2. INV-0 + canary scope. The runner only performs synthetic actions.
        if let Err(reason) = validate(ActionNature::Synthetic, &req.target_dir) {
            return vec![rejected(format!("rejected: {reason:?}"))];
        }

        // 3. Resource bounds: refuse oversized requests before any allocation
        //    or write, so a client cannot exhaust memory or fill the sandbox.
        let chunk_kb = req.chunk_size_kb.max(1);
        let total_kb = req.file_count as u64 * chunk_kb as u64;
        if req.file_count > MAX_FILE_COUNT || chunk_kb > MAX_CHUNK_KB || total_kb > MAX_TOTAL_KB {
            return vec![rejected(format!(
                "resource limit exceeded: file_count={} (max {MAX_FILE_COUNT}), chunk_kb={chunk_kb} (max {MAX_CHUNK_KB}), total_kb={total_kb} (max {MAX_TOTAL_KB})",
                req.file_count
            ))];
        }

        let injector = match CanaryInjector::new(
            &req.target_dir,
            req.file_count as usize,
            chunk_kb as usize,
        ) {
            Ok(i) => i,
            Err(e) => return vec![rejected(e.to_string())],
        };

        let mut events = Vec::new();
        // Drive the canonical state machine with checked transitions.
        let mut s = RunState::Idle;
        for ev in [RunEvent::Validate, RunEvent::Arm, RunEvent::Inject] {
            match s.on(ev) {
                Ok(next) => {
                    s = next;
                    events.push(state_event(s));
                }
                Err(e) => return vec![rejected(e.to_string())],
            }
        }

        // 3. Synthetic injection (the real work of the Injecting state).
        let start = Instant::now();
        let report = match injector.inject() {
            Ok(r) => r,
            Err(e) => {
                let _ = injector.cleanup();
                return vec![rejected(e.to_string())];
            }
        };
        let inject_ms = start.elapsed().as_millis() as u64;

        // 4. Simulated detection/containment, then mandatory cleanup.
        for ev in [
            RunEvent::Detect,
            RunEvent::Contain,
            RunEvent::Cleanup,
            RunEvent::Complete,
        ] {
            if ev == RunEvent::Cleanup {
                let _ = injector.cleanup();
            }
            match s.on(ev) {
                Ok(next) => {
                    s = next;
                    events.push(state_event(s));
                }
                Err(e) => {
                    let _ = injector.cleanup();
                    return vec![rejected(e.to_string())];
                }
            }
        }

        events.push(RunnerEvent {
            kind: EventKind::Completed as i32,
            state: format!("{:?}", RunState::Completed),
            files_created: report.files_created as u32,
            bytes_written: report.bytes_written,
            inject_ms,
            detail: String::new(),
        });
        events
    }
}

#[tonic::async_trait]
impl RunnerControl for RunnerService {
    type ExecuteStream = Pin<Box<dyn Stream<Item = Result<RunnerEvent, Status>> + Send + 'static>>;

    async fn execute(
        &self,
        request: Request<ExecuteRequest>,
    ) -> Result<Response<Self::ExecuteStream>, Status> {
        let events = Self::plan(&request.into_inner());
        let stream = tokio_stream::iter(events.into_iter().map(Ok));
        Ok(Response::new(Box::pin(stream)))
    }

    async fn heartbeat(
        &self,
        _request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatReply>, Status> {
        Ok(Response::new(HeartbeatReply {
            state: format!("{:?}", RunState::Idle),
            healthy: true,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asmodeus_proto::{RunnerControlClient, RunnerControlServer};
    use asmodeus_testkit::{signed_scenario, Polygon};
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;

    /// Build a signed, in-scope request targeting `poly`'s sandbox.
    fn request_in(poly: &Polygon, file_count: u32, chunk_size_kb: u32) -> ExecuteRequest {
        let s = signed_scenario("SCN-RT-001");
        ExecuteRequest {
            scenario_id: "RANSOMWARE_CANARY_SPIKE".into(),
            manifest: s.manifest,
            signature: s.signature,
            public_key: s.public_key,
            target_dir: poly.path(),
            file_count,
            chunk_size_kb,
        }
    }

    #[test]
    fn oversized_request_is_rejected_before_injection() {
        // A signed, in-scope request with an absurd file_count must be refused
        // by the resource bound, not run.
        let poly = Polygon::new("oversized");
        let req = request_in(&poly, 4_000_000_000, 1_000_000);
        let events = RunnerService::plan(&req);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::Rejected as i32);
        assert!(events[0].detail.contains("resource limit exceeded"));
        // The sandbox dir must not have been created.
        assert!(!poly.dir().exists());
    }

    #[test]
    fn within_limits_request_runs() {
        let poly = Polygon::new("within");
        let req = request_in(&poly, 5, 1);
        let events = RunnerService::plan(&req);
        assert_eq!(events.last().unwrap().kind, EventKind::Completed as i32);
    }

    async fn start_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(RunnerControlServer::new(RunnerService))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        format!("http://{addr}")
    }

    async fn connect(url: &str) -> RunnerControlClient<tonic::transport::Channel> {
        for _ in 0..20 {
            if let Ok(c) = RunnerControlClient::connect(url.to_string()).await {
                return c;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("could not connect to {url}");
    }

    #[tokio::test]
    async fn execute_streams_completed_over_grpc() {
        let url = start_server().await;
        let mut client = connect(&url).await;

        let poly = Polygon::new("grpc-complete");
        let req = request_in(&poly, 5, 1);

        let mut stream = client.execute(req).await.unwrap().into_inner();
        let mut states = Vec::new();
        let mut completed = None;
        while let Some(ev) = stream.message().await.unwrap() {
            if ev.kind == EventKind::StateChanged as i32 {
                states.push(ev.state);
            } else if ev.kind == EventKind::Completed as i32 {
                completed = Some(ev);
            }
        }

        assert_eq!(
            states,
            vec![
                "Validated",
                "Armed",
                "Injecting",
                "Detected",
                "Contained",
                "Cleanup",
                "Completed"
            ]
        );
        let done = completed.expect("a Completed event");
        assert_eq!(done.files_created, 5);
        assert_eq!(done.bytes_written, 5 * 2 * 1024); // plaintext + xor pass, 1KB each
    }

    #[tokio::test]
    async fn bad_signature_is_rejected_over_grpc() {
        let url = start_server().await;
        let mut client = connect(&url).await;

        // A valid manifest/key but a zeroed signature must be refused.
        let poly = Polygon::new("grpc-badsig");
        let mut req = request_in(&poly, 3, 1);
        req.signature = vec![0u8; 64];

        let mut stream = client.execute(req).await.unwrap().into_inner();
        let ev = stream.message().await.unwrap().unwrap();
        assert_eq!(ev.kind, EventKind::Rejected as i32);
        assert!(ev.detail.contains("signature"));
    }
}
