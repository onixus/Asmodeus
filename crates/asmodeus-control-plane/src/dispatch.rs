//! gRPC dispatch to a live runner. Replaces the in-process simulation when a
//! runner endpoint is configured: the control-plane sends the signed scenario
//! and folds the runner's event stream into an outcome. mTLS is applied when
//! certificates are configured (asmodeus_proto::tls); dev runs plaintext.

use asmodeus_proto::{EventKind, ExecuteRequest, RunnerControlClient};
use tonic::transport::Channel;
use tonic::Status;

/// Folded result of a runner's event stream.
#[derive(Debug, Default, Clone)]
pub struct DispatchOutcome {
    pub final_state: String,
    pub files_created: u32,
    pub bytes_written: u64,
    pub inject_ms: u64,
    /// Present iff the runner refused the scenario (signature / scope / INV-0).
    pub rejected: Option<String>,
}

async fn connect(endpoint: &str) -> Result<RunnerControlClient<Channel>, Status> {
    // TLS: build a client config from env; None => plaintext (dev only).
    let tls = asmodeus_proto::tls::client_from_env("asmodeus-runner")
        .map_err(|e| Status::internal(format!("tls config: {e}")))?;
    let mut ep = Channel::from_shared(endpoint.to_string())
        .map_err(|e| Status::invalid_argument(format!("bad endpoint: {e}")))?;
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

/// Dispatch one scenario to `endpoint` and drain the event stream.
pub async fn dispatch(endpoint: &str, req: ExecuteRequest) -> Result<DispatchOutcome, Status> {
    let mut client = connect(endpoint).await?;
    let mut stream = client.execute(req).await?.into_inner();

    let mut outcome = DispatchOutcome::default();
    while let Some(ev) = stream.message().await? {
        match EventKind::try_from(ev.kind) {
            Ok(EventKind::StateChanged) => outcome.final_state = ev.state,
            Ok(EventKind::Completed) => {
                outcome.final_state = ev.state;
                outcome.files_created = ev.files_created;
                outcome.bytes_written = ev.bytes_written;
                outcome.inject_ms = ev.inject_ms;
            }
            Ok(EventKind::Rejected) => outcome.rejected = Some(ev.detail),
            _ => {}
        }
    }
    Ok(outcome)
}
