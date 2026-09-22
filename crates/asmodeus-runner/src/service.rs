//! Streaming, cancellable synthetic execution. A blocking worker owns rollback;
//! closing the client stream, losing its lease or exceeding the signed deadline
//! stops work cooperatively and produces an explicit cleanup result.
use crate::canary::{InjectError, Report};
use asmodeus_dsl::{Action, ExecutionPlan};
use asmodeus_proto::{
    CancelReply, CancelRequest, EventKind, ExecuteRequest, HeartbeatReply, HeartbeatRequest,
    RunnerControl, RunnerEvent,
};
use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio_stream::{wrappers::ReceiverStream, Stream};
use tonic::{Request, Response, Status};

const LEASE: Duration = Duration::from_secs(3);

#[derive(Debug)]
struct Active {
    id: String,
    state: Mutex<String>,
    cancelled: AtomicBool,
    heartbeat: Mutex<Instant>,
}

#[derive(Debug, Clone, Default)]
pub struct RunnerService {
    active: Arc<Mutex<Option<Arc<Active>>>>,
    trusted_key: Option<Vec<u8>>,
    healthy: Arc<AtomicBool>,
}

impl RunnerService {
    pub fn with_trusted_key(key: Vec<u8>) -> Self {
        Self {
            trusted_key: Some(key),
            healthy: Arc::new(AtomicBool::new(true)),
            ..Self::default()
        }
    }

    // Keep the native gRPC error type at this transport validation boundary.
    #[allow(clippy::result_large_err)]
    fn validate(&self, req: &ExecuteRequest) -> Result<ExecutionPlan, Status> {
        let key = self
            .trusted_key
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("runner trusted key is not configured"))?;
        if key != &req.public_key || !asmodeus_crypto::is_valid(&req.manifest, &req.signature, key)
        {
            return Err(Status::permission_denied(
                "signature invalid or signing key untrusted",
            ));
        }
        let manifest = std::str::from_utf8(&req.manifest)
            .map_err(|_| Status::invalid_argument("manifest must be UTF-8"))?;
        let manifest = asmodeus_dsl::parse_and_validate_manifest(manifest)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let plan = ExecutionPlan::from_manifest(&manifest)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        if manifest.metadata.id != req.scenario_id
            || plan.target_dir != req.target_dir
            || plan.file_count != req.file_count
            || plan.chunk_size_kb != req.chunk_size_kb
        {
            return Err(Status::invalid_argument(
                "request parameters differ from signed manifest",
            ));
        }
        if req.run_id.is_empty()
            || req.run_id.len() > 96
            || !req
                .run_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            return Err(Status::invalid_argument(
                "run_id must be 1..96 ASCII identifier characters",
            ));
        }
        if req.timeout_sec > plan.max_duration_sec {
            return Err(Status::invalid_argument(
                "timeout may not extend signed safety deadline",
            ));
        }
        Ok(plan)
    }
}

fn event(
    kind: EventKind,
    state: &str,
    run_id: &str,
    detail: String,
    cleanup: bool,
    report: &Report,
    start: Instant,
) -> RunnerEvent {
    RunnerEvent {
        kind: kind as i32,
        state: state.into(),
        run_id: run_id.into(),
        detail,
        cleanup_confirmed: cleanup,
        simulated: false,
        files_created: report.files_created as u32,
        bytes_written: report.bytes_written,
        inject_ms: start.elapsed().as_millis() as u64,
    }
}

fn run_worker(
    req: ExecuteRequest,
    plan: ExecutionPlan,
    active: Arc<Active>,
    sender: tokio::sync::mpsc::Sender<Result<RunnerEvent, Status>>,
) -> bool {
    let start = Instant::now();
    let timeout = Duration::from_secs(u64::from(if req.timeout_sec == 0 {
        plan.max_duration_sec
    } else {
        req.timeout_sec
    }));
    let budget = crate::cpu_budget::CpuBudget::new(plan.cpu_limit_percent);
    let check = || -> Result<(), InjectError> {
        loop {
            let reason = if active.cancelled.load(Ordering::Acquire) || sender.is_closed() {
                Some("CANCELLED")
            } else if start.elapsed() >= timeout {
                Some("TIMED_OUT")
            } else if active.heartbeat.lock().unwrap().elapsed() >= LEASE {
                Some("CONTROL_LOST")
            } else {
                None
            };
            if let Some(reason) = reason {
                return Err(InjectError::Io(std::io::Error::other(reason)));
            }
            let delay = budget
                .as_ref()
                .map_err(|e| InjectError::Io(std::io::Error::other(e.to_string())))?
                .delay()?;
            if delay < Duration::from_millis(1) {
                return Ok(());
            }
            std::thread::sleep(delay.min(Duration::from_millis(20)));
        }
    };
    let report0 = Report {
        files_created: 0,
        bytes_written: 0,
    };
    let emit = |state: &str| {
        *active.state.lock().unwrap() = state.into();
        let _ = sender.blocking_send(Ok(event(
            EventKind::StateChanged,
            state,
            &req.run_id,
            String::new(),
            false,
            &report0,
            start,
        )));
    };
    emit("Validated");
    let sandbox = match crate::sandbox::Sandbox::create(&plan.target_dir, &req.run_id) {
        Ok(sandbox) => sandbox,
        Err(e) => {
            let _ = sender.blocking_send(Ok(event(
                EventKind::Rejected,
                "REJECTED",
                &req.run_id,
                e.to_string(),
                false,
                &report0,
                start,
            )));
            return false;
        }
    };
    emit("Armed");
    emit("Injecting");
    let wait = |duration_ms: u32| -> Result<(), InjectError> {
        let until = Instant::now() + Duration::from_millis(duration_ms.into());
        while Instant::now() < until {
            check()?;
            std::thread::sleep(
                until
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(20)),
            );
        }
        check()
    };
    let target = sandbox.path().to_string_lossy();
    let mut cleanup_error = None;
    let mut simulated = false;
    let result = (|| -> Result<Report, InjectError> {
        check()?;
        if plan.action == Action::LatencySpike {
            use crate::netchaos::{
                default_backend, NetChaosBackend, NetChaosSession, NetChaosSpec,
            };
            let backend = default_backend();
            simulated = backend.name() == "sim";
            let spec = NetChaosSpec {
                iface: plan.iface.clone(),
                target_cidr: plan.target_cidr.clone(),
                latency_ms: plan.latency_ms,
                jitter_ms: plan.jitter_ms,
                loss_pct: plan.loss_percent,
                duration_ms: plan.duration_ms.max(1),
            };
            let mut session = NetChaosSession::start(&backend, &spec)
                .map_err(|e| InjectError::Io(std::io::Error::other(e.to_string())))?;
            let result = wait(plan.duration_ms);
            if let Err(e) = session.revert() {
                cleanup_error = Some(e.to_string());
            }
            result?;
            return Ok(report0.clone());
        }
        let report = if plan.action == Action::SyntheticCanaryEncrypt {
            let injector = crate::canary::CanaryInjector::new(
                target.as_ref(),
                plan.file_count as usize,
                plan.chunk_size_kb as usize,
            )?;
            injector.inject_checked(
                &check,
                if plan.io_rate_per_sec == 0 {
                    0
                } else {
                    1000 / u64::from(plan.io_rate_per_sec)
                },
            )?
        } else {
            let id = match plan.action {
                Action::K8sEscapeProbe => "K8S_ESCAPE_SIMULATION",
                Action::C2Beacon => "C2_BEACONING_SIMULATION",
                Action::CredentialCanary => "CREDENTIAL_ACCESS_CANARY",
                Action::LogTamperCanary => "LOG_TAMPER_CANARY",
                Action::PersistenceCanary => "PERSISTENCE_CRON_CANARY",
                Action::ExfiltrationCanary => "DATA_EXFILTRATION_CANARY",
                Action::WatchdogProbe => "DEFENSE_IMPAIRMENT_CANARY",
                _ => unreachable!(),
            };
            let injector = crate::injectors::create_injector(
                id,
                &target,
                plan.file_count as usize,
                plan.chunk_size_kb as usize,
            )?;
            let injected = injector.inject();
            let waited = if injected.is_ok() {
                wait(plan.duration_ms)
            } else {
                Ok(())
            };
            if let Err(error) = injector.cleanup() {
                cleanup_error = Some(error.to_string());
            }
            waited?;
            return injected;
        };
        wait(plan.duration_ms)?;
        Ok(report)
    })();
    emit("Cleanup");
    if let Err(e) = sandbox.cleanup() {
        cleanup_error = Some(e.to_string());
    }
    let cleaned = cleanup_error.is_none();
    let (kind, state, detail, report) = if let Some(error) = cleanup_error {
        (EventKind::Failed, "CLEANUP_FAILED", error, report0)
    } else {
        match result {
            Ok(report) => (EventKind::Completed, "COMPLETED", String::new(), report),
            Err(err) => {
                let detail = err.to_string();
                let (kind, state) = if detail.contains("CANCELLED") {
                    (EventKind::Cancelled, "CANCELLED")
                } else if detail.contains("TIMED_OUT") {
                    (EventKind::TimedOut, "TIMED_OUT")
                } else if detail.contains("CONTROL_LOST") {
                    (EventKind::Failed, "CONTROL_LOST")
                } else {
                    (EventKind::Failed, "FAILED")
                };
                (kind, state, detail, report0)
            }
        }
    };
    *active.state.lock().unwrap() = state.into();
    let mut terminal = event(kind, state, &req.run_id, detail, cleaned, &report, start);
    terminal.simulated = simulated;
    let _ = sender.blocking_send(Ok(terminal));
    cleaned
}

#[tonic::async_trait]
impl RunnerControl for RunnerService {
    type ExecuteStream = Pin<Box<dyn Stream<Item = Result<RunnerEvent, Status>> + Send + 'static>>;
    async fn execute(
        &self,
        request: Request<ExecuteRequest>,
    ) -> Result<Response<Self::ExecuteStream>, Status> {
        let req = request.into_inner();
        let plan = self.validate(&req)?;
        let active = Arc::new(Active {
            id: req.run_id.clone(),
            state: Mutex::new("Queued".into()),
            cancelled: AtomicBool::new(false),
            heartbeat: Mutex::new(Instant::now()),
        });
        {
            let mut slot = self.active.lock().unwrap();
            if slot.as_ref().is_some_and(|current| {
                !matches!(
                    current.state.lock().unwrap().as_str(),
                    "COMPLETED"
                        | "CANCELLED"
                        | "TIMED_OUT"
                        | "CONTROL_LOST"
                        | "FAILED"
                        | "CLEANUP_FAILED"
                        | "REJECTED"
                )
            }) {
                return Err(Status::resource_exhausted("runner is busy"));
            }
            *slot = Some(active.clone());
        }
        let (sender, receiver) = tokio::sync::mpsc::channel(16);
        let service = self.clone();
        let execution = active.clone();
        tokio::spawn(async move {
            let result =
                tokio::task::spawn_blocking(move || run_worker(req, plan, active, sender)).await;
            service
                .healthy
                .store(result.unwrap_or(false), Ordering::Release);
            let mut slot = service.active.lock().unwrap();
            if slot
                .as_ref()
                .is_some_and(|active| Arc::ptr_eq(active, &execution))
            {
                *slot = None;
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }
    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatReply>, Status> {
        let slot = self.active.lock().unwrap();
        let (state, id) = match slot.as_ref() {
            Some(active) => {
                if request.get_ref().exercise_id == active.id {
                    *active.heartbeat.lock().unwrap() = Instant::now();
                }
                (active.state.lock().unwrap().clone(), active.id.clone())
            }
            None => ("Idle".into(), String::new()),
        };
        Ok(Response::new(HeartbeatReply {
            state,
            healthy: self.healthy.load(Ordering::Acquire),
            cpu_usage_pct: 0,
            active_exercise_id: id,
            version: env!("CARGO_PKG_VERSION").into(),
        }))
    }
    async fn cancel(
        &self,
        request: Request<CancelRequest>,
    ) -> Result<Response<CancelReply>, Status> {
        let slot = self.active.lock().unwrap();
        match slot.as_ref().filter(|a| a.id == request.get_ref().run_id) {
            Some(active) => {
                active.cancelled.store(true, Ordering::Release);
                Ok(Response::new(CancelReply {
                    accepted: true,
                    state: "CANCELLING".into(),
                }))
            }
            None => Err(Status::not_found("active run not found")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asmodeus_proto::{RunnerControlClient, RunnerControlServer};
    use asmodeus_testkit::Polygon;
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;

    fn keys() -> &'static ([u8; 32], [u8; 64]) {
        static KEYS: std::sync::OnceLock<([u8; 32], [u8; 64])> = std::sync::OnceLock::new();
        KEYS.get_or_init(asmodeus_crypto::generate_keypair)
    }
    fn service() -> RunnerService {
        RunnerService::with_trusted_key(keys().0.to_vec())
    }
    fn sign_manifest(req: &mut ExecuteRequest, manifest: &asmodeus_dsl::ScenarioManifest) {
        req.manifest = serde_json::to_vec(manifest).unwrap();
        req.signature = asmodeus_crypto::sign_message(&req.manifest, &keys().1)
            .unwrap()
            .to_vec();
    }
    fn request_in(poly: &Polygon, file_count: u32, chunk_size_kb: u32) -> ExecuteRequest {
        let id = "RANSOMWARE_CANARY_SPIKE";
        let manifest =
            asmodeus_dsl::synthetic_manifest(id, &poly.path(), file_count, chunk_size_kb);
        let mut request = ExecuteRequest {
            scenario_id: id.into(),
            public_key: keys().0.to_vec(),
            target_dir: poly.path(),
            file_count,
            chunk_size_kb,
            run_id: "test-run".into(),
            ..Default::default()
        };
        sign_manifest(&mut request, &manifest);
        request
    }
    #[test]
    fn oversized_request_is_rejected_before_injection() {
        let poly = Polygon::new("oversized");
        assert!(service()
            .validate(&request_in(&poly, 4_000_000_000, 1_000_000))
            .is_err());
        assert!(!poly.dir().exists());
    }
    #[test]
    fn unsigned_parameter_tampering_and_untrusted_keys_are_rejected() {
        let poly = Polygon::new("tampering");
        let mut req = request_in(&poly, 5, 1);
        req.file_count = 6;
        assert!(service().validate(&req).is_err());
        let mut req = request_in(&poly, 5, 1);
        let (pk, sk) = asmodeus_crypto::generate_keypair();
        req.public_key = pk.to_vec();
        req.signature = asmodeus_crypto::sign_message(&req.manifest, &sk)
            .unwrap()
            .to_vec();
        assert!(service().validate(&req).is_err());
    }

    fn dwell_request(poly: &Polygon, millis: u32) -> ExecuteRequest {
        let mut req = request_in(poly, 2, 1);
        let mut manifest: asmodeus_dsl::ScenarioManifest =
            serde_json::from_slice(&req.manifest).unwrap();
        manifest.metadata.id = "CUSTOM-DSL-ACTION".into();
        manifest
            .spec
            .action
            .parameters
            .insert("duration_ms".into(), millis.into());
        req.scenario_id = manifest.metadata.id.clone();
        sign_manifest(&mut req, &manifest);
        req
    }
    async fn next_terminal(
        stream: &mut <RunnerService as RunnerControl>::ExecuteStream,
    ) -> RunnerEvent {
        use tokio_stream::StreamExt;
        tokio::time::timeout(Duration::from_secs(6), async {
            while let Some(event) = stream.next().await {
                let event = event.unwrap();
                if event.kind != EventKind::StateChanged as i32 {
                    return event;
                }
            }
            panic!("missing terminal result")
        })
        .await
        .unwrap()
    }
    #[tokio::test]
    async fn cancel_active_run_cleans_only_owned_directory_and_rejects_concurrency() {
        use tokio_stream::StreamExt;
        let poly = Polygon::new("cancel-owned");
        std::fs::create_dir_all(poly.dir()).unwrap();
        std::fs::write(poly.dir().join("keep.txt"), b"owned by operator").unwrap();
        let service = service();
        let req = dwell_request(&poly, 5000);
        let mut stream = service
            .execute(Request::new(req.clone()))
            .await
            .unwrap()
            .into_inner();
        while stream.next().await.unwrap().unwrap().state != "Injecting" {}
        assert!(poly.dir().join("test-run").exists());
        assert!(
            matches!(service.execute(Request::new(req)).await, Err(e) if e.code() == tonic::Code::ResourceExhausted)
        );
        assert!(service
            .cancel(Request::new(CancelRequest {
                run_id: "wrong-run".into()
            }))
            .await
            .is_err());
        let reply = service
            .cancel(Request::new(CancelRequest {
                run_id: "test-run".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reply.state, "CANCELLING");
        let terminal = next_terminal(&mut stream).await;
        assert_eq!(terminal.kind, EventKind::Cancelled as i32);
        assert!(terminal.cleanup_confirmed);
        assert!(!poly.dir().join("test-run").exists());
        assert_eq!(
            std::fs::read(poly.dir().join("keep.txt")).unwrap(),
            b"owned by operator"
        );
    }
    #[tokio::test]
    async fn signed_deadline_and_lost_execution_lease_both_cleanup() {
        for (name, timeout, expected) in [("timeout", 1, "TIMED_OUT"), ("lease", 0, "CONTROL_LOST")]
        {
            let poly = Polygon::new(name);
            let service = service();
            let mut req = dwell_request(&poly, 5000);
            req.timeout_sec = timeout;
            let mut stream = service
                .execute(Request::new(req))
                .await
                .unwrap()
                .into_inner();
            let terminal = next_terminal(&mut stream).await;
            assert_eq!(terminal.state, expected);
            assert!(terminal.cleanup_confirmed);
            assert!(!poly.dir().join("test-run").exists());
        }
    }
    #[tokio::test]
    async fn dropping_stream_cancels_worker_and_cleans_artifacts() {
        use tokio_stream::StreamExt;
        let poly = Polygon::new("disconnect");
        let service = service();
        let mut stream = service
            .execute(Request::new(dwell_request(&poly, 5000)))
            .await
            .unwrap()
            .into_inner();
        while stream.next().await.unwrap().unwrap().state != "Injecting" {}
        drop(stream);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if service.active.lock().unwrap().is_none() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(!poly.dir().join("test-run").exists());
        assert!(service.healthy.load(Ordering::Acquire));
    }
    #[tokio::test]
    async fn custom_id_executes_signed_action_and_rate() {
        let poly = Polygon::new("custom-action");
        let mut req = dwell_request(&poly, 40);
        let mut manifest: asmodeus_dsl::ScenarioManifest =
            serde_json::from_slice(&req.manifest).unwrap();
        manifest
            .spec
            .action
            .parameters
            .insert("io_rate_per_sec".into(), 10.into());
        sign_manifest(&mut req, &manifest);
        let start = Instant::now();
        let mut stream = service()
            .execute(Request::new(req))
            .await
            .unwrap()
            .into_inner();
        let terminal = next_terminal(&mut stream).await;
        assert_eq!(terminal.kind, EventKind::Completed as i32);
        assert_eq!(terminal.files_created, 2);
        assert_eq!(terminal.bytes_written, 4096);
        assert!(start.elapsed() >= Duration::from_millis(240));
        assert!(terminal.cleanup_confirmed);
    }

    async fn start_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(RunnerControlServer::new(service()))
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

        assert_eq!(states, vec!["Validated", "Armed", "Injecting", "Cleanup"]);
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

        let result = client.execute(req).await;
        assert!(matches!(result, Err(ref error) if error.code() == tonic::Code::PermissionDenied));
    }

    async fn start_mtls_server(tls: tonic::transport::ServerTlsConfig) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .tls_config(tls)
                .unwrap()
                .add_service(RunnerControlServer::new(service()))
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
            let manifest = asmodeus_dsl::synthetic_manifest(scenario_id, &poly.path(), 3, 1);
            let plan = asmodeus_dsl::ExecutionPlan::from_manifest(&manifest).unwrap();
            let mut req = ExecuteRequest {
                scenario_id: scenario_id.into(),
                public_key: keys().0.to_vec(),
                target_dir: poly.path(),
                file_count: plan.file_count,
                chunk_size_kb: plan.chunk_size_kb,
                run_id: "scenario-test".into(),
                ..Default::default()
            };
            sign_manifest(&mut req, &manifest);

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
