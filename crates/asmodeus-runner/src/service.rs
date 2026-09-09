//! gRPC `RunnerControl` server. Execute verifies the scenario signature, gates
//! on INV-0 / canary scope, runs the synthetic injection and streams lifecycle
//! events. Detect/Contain are simulated here (no live Blue Team in the loop);
//! in production those come from correlated Ferrum/SOAR telemetry, not the
//! runner self-declaring them.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use asmodeus_common::{ActionNature, RunEvent, RunState};
use asmodeus_dsl::validate;
use asmodeus_proto::{
    EventKind, ExecuteRequest, HeartbeatReply, HeartbeatRequest, RunnerControl, RunnerEvent,
};
use asmodeus_safety::{CircuitBreaker, DeadManSwitch};
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

#[derive(Debug, Clone)]
pub struct RunnerService {
    #[allow(dead_code)]
    runner_id: String,
    active_exercise: Arc<Mutex<Option<String>>>,
    current_state: Arc<Mutex<RunState>>,
    dead_man: Arc<Mutex<DeadManSwitch>>,
}

impl Default for RunnerService {
    fn default() -> Self {
        RunnerService {
            runner_id: "asmodeus-runner".to_string(),
            active_exercise: Arc::new(Mutex::new(None)),
            current_state: Arc::new(Mutex::new(RunState::Idle)),
            dead_man: Arc::new(Mutex::new(DeadManSwitch::default())),
        }
    }
}

impl RunnerService {
    #[allow(dead_code)]
    pub fn new(runner_id: impl Into<String>) -> Self {
        RunnerService {
            runner_id: runner_id.into(),
            ..Default::default()
        }
    }
}

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

        let injector = match crate::injectors::create_injector(
            &req.scenario_id,
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

        // Circuit breaker check (ARCHITECTURE.md §5, TT.md §3)
        let breaker = CircuitBreaker::default();
        if let Some(trip) = breaker.evaluate(2, inject_ms, 0) {
            let _ = injector.cleanup();
            let _ = s.on(RunEvent::TripBreaker);
            events.push(state_event(RunState::CircuitBreakerTripped));
            let _ = s.on(RunEvent::Cleanup);
            events.push(state_event(RunState::Cleanup));
            let _ = s.on(RunEvent::Complete);
            events.push(state_event(RunState::Completed));
            events.push(rejected(format!("circuit breaker tripped: {trip:?}")));
            return events;
        }

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
        let req = request.into_inner();
        {
            let mut active = self.active_exercise.lock().unwrap();
            *active = Some(req.scenario_id.clone());
            let mut state = self.current_state.lock().unwrap();
            *state = RunState::Injecting;
        }

        let events = Self::plan(&req);

        {
            let mut active = self.active_exercise.lock().unwrap();
            *active = None;
            let mut state = self.current_state.lock().unwrap();
            *state = RunState::Idle;
        }

        let stream = tokio_stream::iter(events.into_iter().map(Ok));
        Ok(Response::new(Box::pin(stream)))
    }

    async fn heartbeat(
        &self,
        _request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatReply>, Status> {
        {
            let mut dms = self.dead_man.lock().unwrap();
            dms.record_beat();
        }

        let state = *self.current_state.lock().unwrap();
        let active = self
            .active_exercise
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_default();

        Ok(Response::new(HeartbeatReply {
            state: format!("{state:?}"),
            healthy: true,
            cpu_usage_pct: 2,
            active_exercise_id: active,
            version: env!("CARGO_PKG_VERSION").to_string(),
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
                .add_service(RunnerControlServer::new(RunnerService::default()))
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

    async fn start_mtls_server(tls: tonic::transport::ServerTlsConfig) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .tls_config(tls)
                .unwrap()
                .add_service(RunnerControlServer::new(RunnerService::default()))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        format!("https://{addr}")
    }

    async fn connect_mtls(
        url: &str,
        tls: tonic::transport::ClientTlsConfig,
    ) -> Result<RunnerControlClient<tonic::transport::Channel>, tonic::transport::Error> {
        let channel = tonic::transport::Channel::from_shared(url.to_string())
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect()
            .await?;
        Ok(RunnerControlClient::new(channel))
    }

    #[tokio::test]
    async fn execute_streams_completed_over_mtls() {
        let mtls = asmodeus_testkit::TestMtls::generate();
        let url = start_mtls_server(mtls.server_tls_config()).await;
        let mut client = connect_mtls(&url, mtls.client_tls_config(Some("asmodeus-runner")))
            .await
            .expect("mtls handshake should succeed");

        let poly = Polygon::new("mtls-complete");
        let req = request_in(&poly, 4, 1);

        let mut stream = client.execute(req).await.unwrap().into_inner();
        let mut completed = false;
        while let Some(ev) = stream.message().await.unwrap() {
            if ev.kind == EventKind::Completed as i32 {
                completed = true;
                assert_eq!(ev.files_created, 4);
            }
        }
        assert!(completed, "mTLS run must reach Completed");
    }

    /// Drive a full execute against `url` with the given client TLS config,
    /// returning `Err` if ANY stage fails (handshake, the RPC, or the stream).
    /// Lets negative tests assert a concrete failure instead of passing
    /// vacuously when `connect` happens to fail first.
    async fn try_execute(
        url: &str,
        tls: tonic::transport::ClientTlsConfig,
        tag: &str,
    ) -> Result<(), String> {
        let mut client = connect_mtls(url, tls).await.map_err(|e| e.to_string())?;
        let poly = Polygon::new(tag);
        let req = request_in(&poly, 2, 1);
        let mut stream = client
            .execute(req)
            .await
            .map_err(|e| e.to_string())?
            .into_inner();
        while stream.message().await.map_err(|e| e.to_string())?.is_some() {}
        Ok(())
    }

    #[tokio::test]
    async fn untrusted_client_cert_is_rejected_by_mtls_runner() {
        let mtls = asmodeus_testkit::TestMtls::generate();
        let url = start_mtls_server(mtls.server_tls_config()).await;
        // Rogue client presents a certificate signed by an untrusted rogue CA.
        let res = try_execute(
            &url,
            mtls.rogue_client_tls_config(Some("asmodeus-runner")),
            "mtls-rogue",
        )
        .await;
        assert!(
            res.is_err(),
            "untrusted client must be rejected (handshake or RPC), got Ok"
        );
    }

    #[tokio::test]
    async fn plaintext_client_is_rejected_by_mtls_runner() {
        let mtls = asmodeus_testkit::TestMtls::generate();
        let url = start_mtls_server(mtls.server_tls_config()).await;
        let plain_url = url.replace("https://", "http://");
        let res: Result<(), String> = async {
            let mut client = RunnerControlClient::connect(plain_url)
                .await
                .map_err(|e| e.to_string())?;
            let poly = Polygon::new("mtls-plain");
            let mut stream = client
                .execute(request_in(&poly, 2, 1))
                .await
                .map_err(|e| e.to_string())?
                .into_inner();
            while stream.message().await.map_err(|e| e.to_string())?.is_some() {}
            Ok(())
        }
        .await;
        assert!(
            res.is_err(),
            "plaintext client must be rejected by the mTLS server, got Ok"
        );
    }

    #[tokio::test]
    async fn trusted_client_rejects_untrusted_server_cert() {
        let mtls = asmodeus_testkit::TestMtls::generate();
        // Server presents a cert signed by the ROGUE CA; a client that only
        // trusts the real CA must reject the server during the handshake.
        let url = start_mtls_server(mtls.rogue_server_tls_config()).await;
        let res = try_execute(
            &url,
            mtls.client_tls_config(Some("asmodeus-runner")),
            "mtls-rogue-server",
        )
        .await;
        assert!(
            res.is_err(),
            "client must reject a server cert signed by an untrusted CA, got Ok"
        );
    }

    #[tokio::test]
    async fn execute_streams_completed_for_mitre_scenarios_over_grpc() {
        let url = start_server().await;
        let mut client = connect(&url).await;

        for scenario_id in [
            "C2_BEACONING_SIMULATION",
            "CREDENTIAL_ACCESS_CANARY",
            "K8S_ESCAPE_SIMULATION",
            "LOG_TAMPER_CANARY",
        ] {
            let poly = Polygon::new(&format!("grpc-{scenario_id}"));
            let s = signed_scenario(scenario_id);
            let req = ExecuteRequest {
                scenario_id: scenario_id.into(),
                manifest: s.manifest,
                signature: s.signature,
                public_key: s.public_key,
                target_dir: poly.path(),
                file_count: 3,
                chunk_size_kb: 1,
            };

            let mut stream = client.execute(req).await.unwrap().into_inner();
            let mut completed = None;
            while let Some(ev) = stream.message().await.unwrap() {
                if ev.kind == EventKind::Completed as i32 {
                    completed = Some(ev);
                }
            }
            assert!(completed.is_some(), "{scenario_id} did not complete");
            if poly.dir().exists() {
                assert_eq!(std::fs::read_dir(poly.dir()).unwrap().count(), 0);
            }
        }
    }

    #[tokio::test]
    async fn heartbeat_returns_live_status_and_records_beat() {
        let url = start_server().await;
        let mut client = connect(&url).await;

        let reply = client
            .heartbeat(HeartbeatRequest {
                exercise_id: "".into(),
                runner_id: "test-runner".into(),
                timestamp_utc: 100,
            })
            .await
            .unwrap()
            .into_inner();

        assert!(reply.healthy);
        assert_eq!(reply.state, "Idle");
        assert_eq!(reply.version, env!("CARGO_PKG_VERSION"));
    }
}
