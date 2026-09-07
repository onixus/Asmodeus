//! gRPC dispatch to a live runner. Replaces the in-process simulation when a
//! runner endpoint is configured: the control-plane sends the signed scenario
//! and folds the runner's event stream into an outcome. mTLS is applied when
//! certificates are configured (asmodeus_proto::tls); dev runs plaintext.

use asmodeus_proto::{EventKind, ExecuteRequest, RunnerControlClient};
use tonic::transport::{Channel, ClientTlsConfig};
use tonic::Status;

/// Folded result of a runner's event stream.
#[derive(Debug, Default, Clone)]
pub struct DispatchOutcome {
    pub final_state: String,
    pub files_created: u32,
    pub bytes_written: u64,
    pub inject_ms: u64,
    /// True iff the runner emitted a terminal `Completed` event.
    pub completed: bool,
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

/// Dispatch one scenario to `endpoint` with explicit TLS configuration.
pub async fn dispatch_with_tls(
    endpoint: &str,
    req: ExecuteRequest,
    tls: Option<ClientTlsConfig>,
) -> Result<DispatchOutcome, Status> {
    let mut client = connect_with_tls(endpoint, tls).await?;
    let mut stream = client.execute(req).await?.into_inner();

    let mut outcome = DispatchOutcome::default();
    while let Some(ev) = stream.message().await? {
        match EventKind::try_from(ev.kind) {
            Ok(EventKind::StateChanged) => outcome.final_state = ev.state,
            Ok(EventKind::Completed) => {
                outcome.completed = true;
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

/// Dispatch one scenario to `endpoint` and drain the event stream.
/// mTLS configuration is loaded from the environment (falling back to plaintext in dev).
pub async fn dispatch(endpoint: &str, req: ExecuteRequest) -> Result<DispatchOutcome, Status> {
    let tls = asmodeus_proto::tls::client_from_env("asmodeus-runner")
        .map_err(|e| Status::internal(format!("tls config: {e}")))?;
    dispatch_with_tls(endpoint, req, tls).await
}
