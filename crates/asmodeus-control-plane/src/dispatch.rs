//! gRPC dispatch to a live runner. Replaces the in-process simulation when a
//! runner endpoint is configured: the control-plane sends the signed scenario
//! and folds the runner's event stream into an outcome. mTLS is applied when
//! certificates are configured (asmodeus_proto::tls); dev runs plaintext.

use asmodeus_proto::{EventKind, ExecuteRequest, RunnerControlClient};
use std::time::Duration;
use tonic::transport::{Channel, ClientTlsConfig};
use tonic::Status;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(5);

/// Folded result of a runner's event stream.
#[derive(Debug, Default, Clone)]
pub struct DispatchOutcome {
    pub final_state: String,
    pub files_created: u32,
    pub bytes_written: u64,
    pub inject_ms: u64,
    /// True iff the runner emitted a terminal `Completed` event.
    pub completed: bool,
    pub terminal: bool,
    pub simulated: bool,
    pub cleanup_confirmed: bool,
    pub detail: String,
    /// Present iff the runner refused the scenario (signature / scope / INV-0).
    pub rejected: Option<String>,
}

/// Connect to a runner endpoint using explicit or absent TLS.
pub async fn connect_with_tls(
    endpoint: &str,
    tls: Option<ClientTlsConfig>,
) -> Result<RunnerControlClient<Channel>, Status> {
    let has_tls = tls.is_some();
    let target = if has_tls && endpoint.starts_with("http://") {
        format!("https://{}", &endpoint["http://".len()..])
    } else if !endpoint.contains("://") {
        if has_tls {
            format!("https://{endpoint}")
        } else {
            format!("http://{endpoint}")
        }
    } else {
        endpoint.to_string()
    };

    // Footgun guard: an `https://` target with no client TLS config would fail
    // deep inside tonic with an opaque error. Reject it up front so the misconfig
    // is obvious (set ASMODEUS_CLIENT_TLS_* or use http://).
    if target.starts_with("https://") && !has_tls {
        return Err(Status::invalid_argument(
            "endpoint requests TLS (https://) but no client mTLS is configured; \
             set ASMODEUS_CLIENT_TLS_* or use an http:// endpoint",
        ));
    }

    let mut ep = Channel::from_shared(target)
        .map_err(|e| Status::invalid_argument(format!("bad endpoint: {e}")))?
        .connect_timeout(CONNECT_TIMEOUT);

    if let Some(tls) = tls {
        ep = ep
            .tls_config(tls)
            .map_err(|e| Status::internal(format!("tls: {e}")))?;
    }

    let channel = ep
        .connect()
        .await
        .map_err(|e| Status::unavailable(format!("runner unreachable: {e}")))?;
    Ok(RunnerControlClient::new(channel))
}

#[cfg(test)]
async fn dispatch_with_deadline(
    endpoint: &str,
    req: ExecuteRequest,
    tls: Option<ClientTlsConfig>,
    timeout: Duration,
) -> Result<DispatchOutcome, Status> {
    dispatch_controlled(
        endpoint,
        req,
        tls,
        timeout,
        crate::run_control::ActiveRun::new(asmodeus_common::Category::RedTeam),
    )
    .await
}

pub async fn dispatch_controlled(
    endpoint: &str,
    req: ExecuteRequest,
    tls: Option<ClientTlsConfig>,
    timeout: Duration,
    control: crate::run_control::ActiveRun,
) -> Result<DispatchOutcome, Status> {
    tokio::time::timeout(timeout, async {
        let mut client = connect_with_tls(endpoint, tls).await?;
        let mut lease_client = client.clone();
        let run_id = req.run_id.clone();
        let mut request = tonic::Request::new(req);
        request.set_timeout(timeout);
        let mut stream = client.execute(request).await?.into_inner();
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        let mut last_beat = tokio::time::Instant::now() - Duration::from_secs(2);
        let mut cancel_sent = false;
        let mut outcome = DispatchOutcome::default();
        loop {
            tokio::select! {
                item = stream.message() => {
                    let Some(ev) = item? else { break; };
                    if ev.run_id != run_id { return Err(Status::data_loss("runner event run_id mismatch")); }
                    outcome.final_state = ev.state.to_uppercase();
                    *control.status.lock().unwrap() = outcome.final_state.clone();
                    if let Ok(EventKind::Completed | EventKind::Cancelled | EventKind::Failed | EventKind::TimedOut | EventKind::Rejected) = EventKind::try_from(ev.kind) {
                            outcome.terminal = true;
                            outcome.simulated = ev.simulated;
                            outcome.completed = ev.kind == EventKind::Completed as i32;
                            outcome.cleanup_confirmed = ev.cleanup_confirmed;
                            outcome.files_created = ev.files_created;
                            outcome.bytes_written = ev.bytes_written;
                            outcome.inject_ms = ev.inject_ms;
                            outcome.detail = ev.detail.clone();
                            if ev.kind == EventKind::Rejected as i32 { outcome.rejected = Some(ev.detail); }
                            break;
                    }
                },
                _ = tick.tick() => {
                    if control.cancel.load(std::sync::atomic::Ordering::Acquire) && !cancel_sent {
                        let reply = tokio::time::timeout(Duration::from_secs(2), lease_client.cancel(asmodeus_proto::CancelRequest { run_id: run_id.clone() })).await;
                        match reply {
                            Ok(Ok(_)) => cancel_sent = true,
                            Ok(Err(error)) if error.code() == tonic::Code::NotFound => (), // terminal event may be in flight
                            _ => return Err(Status::unavailable("runner cancellation could not be confirmed")),
                        }
                    }
                    if last_beat.elapsed() >= Duration::from_secs(1) {
                        let request = asmodeus_proto::HeartbeatRequest { exercise_id: run_id.clone(), runner_id: "control-plane".into(), timestamp_utc: 0 };
                        tokio::time::timeout(Duration::from_secs(1), lease_client.heartbeat(request)).await
                            .map_err(|_| Status::deadline_exceeded("execution lease heartbeat timed out"))??;
                        last_beat = tokio::time::Instant::now();
                    }
                }
            }
        }
        Ok(outcome)
    }).await.map_err(|_| Status::deadline_exceeded("runner execution deadline exceeded; cleanup unconfirmed"))?
}

/// Ping a runner via gRPC Heartbeat probe.
pub async fn ping_with_tls(
    endpoint: &str,
    tls: Option<ClientTlsConfig>,
) -> Result<asmodeus_proto::HeartbeatReply, Status> {
    tokio::time::timeout(HEARTBEAT_TIMEOUT, async {
        let mut client = connect_with_tls(endpoint, tls).await?;
        let req = asmodeus_proto::HeartbeatRequest {
            exercise_id: String::new(),
            runner_id: "control-plane".to_string(),
            timestamp_utc: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        let resp = client.heartbeat(req).await?;
        Ok(resp.into_inner())
    })
    .await
    .map_err(|_| Status::deadline_exceeded("runner heartbeat deadline exceeded"))?
}

/// Ping a runner with environment-derived mTLS settings.
pub async fn ping(endpoint: &str) -> Result<asmodeus_proto::HeartbeatReply, Status> {
    let tls = asmodeus_proto::tls::client_from_env("asmodeus-runner")
        .map_err(|e| Status::internal(format!("tls config: {e}")))?;
    ping_with_tls(endpoint, tls).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use asmodeus_proto::{
        HeartbeatReply, HeartbeatRequest, RunnerControl, RunnerControlServer, RunnerEvent,
    };
    use std::pin::Pin;
    use tokio_stream::{wrappers::TcpListenerStream, Stream, StreamExt};
    use tonic::{Request, Response};

    struct StalledRunner {
        terminal: bool,
    }

    #[tonic::async_trait]
    impl RunnerControl for StalledRunner {
        type ExecuteStream = Pin<Box<dyn Stream<Item = Result<RunnerEvent, Status>> + Send>>;
        async fn execute(
            &self,
            req: Request<ExecuteRequest>,
        ) -> Result<Response<Self::ExecuteStream>, Status> {
            let first = if self.terminal {
                EventKind::Completed
            } else {
                EventKind::StateChanged
            };
            let stream = tokio_stream::iter([Ok(RunnerEvent {
                kind: first as i32,
                run_id: req.into_inner().run_id,
                state: if self.terminal {
                    "Completed"
                } else {
                    "Injecting"
                }
                .into(),
                ..Default::default()
            })])
            .chain(tokio_stream::pending());
            Ok(Response::new(Box::pin(stream)))
        }

        async fn cancel(
            &self,
            _: tonic::Request<asmodeus_proto::CancelRequest>,
        ) -> Result<tonic::Response<asmodeus_proto::CancelReply>, tonic::Status> {
            Err(tonic::Status::unimplemented(
                "cancel not used by this test double",
            ))
        }

        async fn heartbeat(
            &self,
            _: Request<HeartbeatRequest>,
        ) -> Result<Response<HeartbeatReply>, Status> {
            std::future::pending().await
        }
    }

    async fn start(terminal: bool) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(RunnerControlServer::new(StalledRunner { terminal }))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        (endpoint, server)
    }

    #[tokio::test]
    async fn stalled_stream_has_an_execution_deadline() {
        let (endpoint, server) = start(false).await;
        let error = dispatch_with_deadline(
            &endpoint,
            ExecuteRequest::default(),
            None,
            Duration::from_millis(100),
        )
        .await
        .unwrap_err();
        server.abort();
        assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
    }

    #[tokio::test]
    async fn completion_does_not_wait_for_stream_eof() {
        let (endpoint, server) = start(true).await;
        let result = dispatch_with_deadline(
            &endpoint,
            ExecuteRequest::default(),
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        server.abort();
        assert!(result.completed);
    }
}
