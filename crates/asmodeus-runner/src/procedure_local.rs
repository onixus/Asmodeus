//! In-process, unsigned loopback fixtures. These are not corpus runtime or
//! product acceptance: no sensor, policy, container or protection is verified.
use crate::sandbox::Sandbox;
use asmodeus_dsl::{
    procedure_corpus, ProcedureVariantKind, ATTACK_VERSION, PROCEDURE_CORPUS_VERSION,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const LOCAL_PROCEDURE_ROOT: &str = "/tmp/asmodeus-canary/local-procedures";
pub const LOCAL_PROCEDURE_ADAPTER_VERSION: &str = "asmodeus.local-fixture.v1";

#[derive(Debug, Clone)]
pub struct LocalProcedureConfig {
    pub procedure_id: String,
    pub attempt_id: String,
    pub variant: ProcedureVariantKind,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LocalAttemptStatus {
    Executed,
    Unsupported,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalEnvironment {
    pub os: String,
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalReceipt {
    pub protocol: String,
    pub receiver: String,
    pub elapsed_ms: u64,
    pub bytes: usize,
    pub sha256: String,
    pub payload_kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalCleanup {
    pub outcome: String,
    pub detail: String,
    pub crash_cleanup: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalProcedureAttempt {
    pub schema_version: String,
    pub adapter_version: String,
    pub corpus_version: String,
    pub corpus_sha256: String,
    pub attack_version: String,
    pub procedure_id: String,
    pub procedure_revision: u32,
    pub attempt_id: String,
    pub variant: ProcedureVariantKind,
    pub mode: String,
    pub signature_status: String,
    pub environment: LocalEnvironment,
    pub started_unix_ms: u64,
    pub stopped_unix_ms: u64,
    pub status: LocalAttemptStatus,
    pub protection_result: String,
    pub receipts: Vec<LocalReceipt>,
    pub cleanup: LocalCleanup,
    pub ownership_record: String,
    pub limitations: Vec<String>,
    pub detail: String,
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn sha256(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

struct Guard<'a> {
    started: Instant,
    deadline: Instant,
    cancel: &'a AtomicBool,
}
impl Guard<'_> {
    fn check(&self) -> io::Result<()> {
        if self.cancel.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "cancelled by local kill switch",
            ));
        }
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "local fixture timeout",
            ));
        }
        Ok(())
    }
    fn pause(&self, duration: Duration) -> io::Result<()> {
        let until = Instant::now() + duration;
        while Instant::now() < until {
            self.check()?;
            std::thread::sleep(
                Duration::from_millis(1).min(until.saturating_duration_since(Instant::now())),
            );
        }
        self.check()
    }
    fn retry<T>(&self, mut operation: impl FnMut() -> io::Result<T>) -> io::Result<T> {
        loop {
            self.check()?;
            match operation() {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    self.pause(Duration::from_millis(1))?
                }
                result => return result,
            }
        }
    }
}

/// Execute one supported adapter against receivers allocated by this call on
/// ephemeral IPv4 loopback ports. No path, command or destination is accepted.
/// Input/ownership rejection is an I/O error; runtime outcomes carry evidence.
pub fn run_local_procedure(
    config: LocalProcedureConfig,
    cancel: Arc<AtomicBool>,
) -> io::Result<LocalProcedureAttempt> {
    run_in_root(config, cancel, Path::new(LOCAL_PROCEDURE_ROOT))
}

fn run_in_root(
    config: LocalProcedureConfig,
    cancel: Arc<AtomicBool>,
    root: &Path,
) -> io::Result<LocalProcedureAttempt> {
    if config.timeout_ms == 0 || config.timeout_ms > 10_000 {
        return Err(invalid("timeout_ms must be within 1..=10000"));
    }
    let corpus = procedure_corpus();
    let procedure = corpus
        .procedures
        .iter()
        .find(|p| p.id == config.procedure_id)
        .ok_or_else(|| invalid("unknown fixed procedure slot"))?;
    let started_unix_ms = unix_ms();
    let started = Instant::now();
    let guard = Guard {
        started,
        deadline: started + Duration::from_millis(config.timeout_ms),
        cancel: &cancel,
    };
    let sandbox = Sandbox::create(
        root.to_str()
            .ok_or_else(|| invalid("non UTF-8 canary root"))?,
        &config.attempt_id,
    )?;
    // Sandbox validates all canary parent components before this sibling file
    // is opened. create_new rejects existing files and symlinks, even after a
    // previous attempt's ephemeral directory has been cleaned up.
    let ownership_record = root.join(format!("{}.ownership.json", config.attempt_id));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut ledger: File = options.open(&ownership_record)?;
    serde_json::to_writer(
        &mut ledger,
        &serde_json::json!({
            "adapter_version": LOCAL_PROCEDURE_ADAPTER_VERSION,
            "attempt_id": config.attempt_id,
            "procedure_id": config.procedure_id,
            "variant": config.variant,
            "started_unix_ms": started_unix_ms,
            "state": "RESERVED",
            "crash_cleanup": "NOT_VERIFIED",
            "ephemeral_directory": sandbox.path(),
            "note": "Immutable reservation retained after normal cleanup; not execution or protection evidence."
        }),
    )?;
    ledger.write_all(b"\n")?;
    ledger.sync_all()?;
    drop(ledger);
    let mut evidence = LocalProcedureAttempt {
        schema_version: "asmodeus.local-procedure-attempt.v1".into(),
        adapter_version: LOCAL_PROCEDURE_ADAPTER_VERSION.into(),
        corpus_version: PROCEDURE_CORPUS_VERSION.into(),
        corpus_sha256: sha256(include_bytes!("../../asmodeus-dsl/fixtures/procedure-corpus-v1.json")), attack_version: ATTACK_VERSION.into(),
        procedure_id: config.procedure_id.clone(), procedure_revision: procedure.revision,
        attempt_id: config.attempt_id.clone(), variant: config.variant,
        mode: "LOCAL_FIXTURE".into(), signature_status: "UNSIGNED".into(),
        environment: LocalEnvironment { os: std::env::consts::OS.into(), arch: std::env::consts::ARCH.into() },
        started_unix_ms, stopped_unix_ms: started_unix_ms,
        status: LocalAttemptStatus::Unsupported, protection_result: "INCONCLUSIVE".into(), receipts: vec![],
        cleanup: LocalCleanup { outcome: "NOT_VERIFIED".into(), detail: String::new(), crash_cleanup: "NOT_VERIFIED".into() },
        ownership_record: ownership_record.to_string_lossy().into_owned(),
        limitations: vec![
            "Unsigned local fixture receipts are not sensor or product evidence and do not establish detection, prevention, containment or ATT&CK coverage.".into(),
            "Corpus container, sensor-readiness and product-policy preconditions are unmet; the production corpus remains UNSUPPORTED. This adapter is a separate local experiment.".into(),
            "Cleanup is verified only for normal return, timeout or cooperative cancellation; SIGKILL/crash cleanup is NOT_VERIFIED. Reservation is retained and cannot be reused.".into(),
        ], detail: String::new(),
    };
    let outcome = guard
        .check()
        .and_then(|()| match config.procedure_id.as_str() {
            "http-beacon" | "synthetic-transfer" => {
                tcp_fixture(&config, &guard, &mut evidence.receipts)
            }
            "dns-pattern" => dns_fixture(&config, &guard, &mut evidence.receipts),
            _ => Ok(false),
        });
    match outcome {
        Ok(true) => {
            evidence.status = LocalAttemptStatus::Executed;
            evidence.detail = "Completed selected positive/benign local fixture variant; receipts prove only local fixture traffic.".into();
        }
        Ok(false) => {
            evidence.status = LocalAttemptStatus::Unsupported;
            evidence.detail = "No local adapter for this slot; no socket, shell, runtime or container action performed.".into();
        }
        Err(error) => {
            evidence.status = if error.kind() == io::ErrorKind::Interrupted {
                LocalAttemptStatus::Cancelled
            } else {
                LocalAttemptStatus::Failed
            };
            evidence.detail = error.to_string();
        }
    }
    // All network resources are stack-owned by the completed fixture calls.
    // No worker thread or child process survives this point.
    match sandbox.cleanup() {
        Ok(()) if !sandbox.path().exists() => {
            evidence.cleanup.outcome = "VERIFIED".into();
            evidence.cleanup.detail = "Owned sockets closed and ephemeral attempt directory absent; immutable ownership record retained for reuse rejection.".into();
        }
        result => {
            evidence.status = LocalAttemptStatus::Failed;
            evidence.cleanup.outcome = "FAILED".into();
            evidence.cleanup.detail =
                format!("Ephemeral directory cleanup not verified: {result:?}");
        }
    }
    evidence.stopped_unix_ms = unix_ms();
    Ok(evidence)
}

fn write_bounded(stream: &mut TcpStream, bytes: &[u8], guard: &Guard<'_>) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        let count = guard.retry(|| stream.write(&bytes[offset..]))?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "fixture write closed",
            ));
        }
        offset += count;
    }
    Ok(())
}
fn read_bounded(stream: &mut TcpStream, bytes: &mut [u8], guard: &Guard<'_>) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        let count = guard.retry(|| stream.read(&mut bytes[offset..]))?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "fixture read closed",
            ));
        }
        offset += count;
    }
    Ok(())
}

fn tcp_fixture(
    config: &LocalProcedureConfig,
    guard: &Guard<'_>,
    receipts: &mut Vec<LocalReceipt>,
) -> io::Result<bool> {
    guard.check()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let receiver = listener.local_addr()?;
    let positive = config.variant == ProcedureVariantKind::Positive;
    let beacon = config.procedure_id == "http-beacon";
    let count = if beacon && positive { 4 } else { 1 };
    for index in 0..count {
        guard.check()?;
        let (path, body, payload_kind) = match (beacon, positive) {
            (true, true) => (
                "/beacon",
                format!("synthetic-beacon-{index}").into_bytes(),
                "beacon",
            ),
            (false, true) => ("/canary", vec![b'C'; 3072], "synthetic_canary"),
            _ => ("/health", b"healthy".to_vec(), "health_status"),
        };
        let header = format!("POST {path} HTTP/1.1\r\nHost: {receiver}\r\nX-Asmodeus-Attempt: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", config.attempt_id, body.len());
        let mut request = header.into_bytes();
        request.extend_from_slice(&body);
        if request.len() > 4096
            || receipts.iter().map(|r| r.bytes).sum::<usize>() + request.len() > 4096
        {
            return Err(invalid("fixture byte budget exceeded"));
        }
        let mut sender = TcpStream::connect_timeout(
            &receiver,
            Duration::from_millis(10)
                .min(guard.deadline.saturating_duration_since(Instant::now()))
                .max(Duration::from_micros(1)),
        )?;
        sender.set_nonblocking(true)?;
        let source = sender.local_addr()?;
        let (mut accepted, peer) = guard.retry(|| listener.accept())?;
        accepted.set_nonblocking(true)?;
        if peer != source {
            return Err(invalid("unexpected connection to owned receiver"));
        }
        write_bounded(&mut sender, &request, guard)?;
        let mut actual = vec![0; request.len()];
        read_bounded(&mut accepted, &mut actual, guard)?;
        if actual != request {
            return Err(invalid("HTTP fixture payload mismatch"));
        }
        receipts.push(LocalReceipt {
            protocol: "http".into(),
            receiver: receiver.to_string(),
            elapsed_ms: guard.started.elapsed().as_millis() as u64,
            bytes: actual.len(),
            sha256: sha256(&actual),
            payload_kind: payload_kind.into(),
        });
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
        write_bounded(&mut accepted, response, guard)?;
        let mut received_response = vec![0; response.len()];
        read_bounded(&mut sender, &mut received_response, guard)?;
        if received_response != response {
            return Err(invalid("HTTP fixture response mismatch"));
        }
        if index + 1 < count {
            guard.pause(Duration::from_millis(50))?;
        }
    }
    guard.check()?;
    Ok(true)
}

fn dns_query(index: u16, positive: bool, attempt_id: &str) -> Vec<u8> {
    let mut packet = vec![0xa5, index as u8, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    let label = if positive {
        format!("beacon{index}")
    } else {
        "health".into()
    };
    let token = sha256(attempt_id.as_bytes());
    for label in [label.as_str(), &token[..16], "fixture", "test"] {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    packet
}

fn dns_fixture(
    config: &LocalProcedureConfig,
    guard: &Guard<'_>,
    receipts: &mut Vec<LocalReceipt>,
) -> io::Result<bool> {
    guard.check()?;
    let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    receiver.set_nonblocking(true)?;
    sender.set_nonblocking(true)?;
    let address = receiver.local_addr()?;
    let source = sender.local_addr()?;
    let positive = config.variant == ProcedureVariantKind::Positive;
    let count = if positive { 4 } else { 1 };
    for index in 0..count {
        let packet = dns_query(index, positive, &config.attempt_id);
        let sent = guard.retry(|| sender.send_to(&packet, address))?;
        if sent != packet.len() {
            return Err(invalid("partial DNS query"));
        }
        let mut buffer = [0; 4096];
        let (length, peer) = guard.retry(|| receiver.recv_from(&mut buffer))?;
        if peer != source || buffer[..length] != packet {
            return Err(invalid("unexpected DNS query at owned receiver"));
        }
        receipts.push(LocalReceipt {
            protocol: "dns".into(),
            receiver: address.to_string(),
            elapsed_ms: guard.started.elapsed().as_millis() as u64,
            bytes: length,
            sha256: sha256(&buffer[..length]),
            payload_kind: if positive {
                "synthetic_dns_pattern"
            } else {
                "service_lookup"
            }
            .into(),
        });
        let mut response = packet.clone();
        response[2] = 0x81;
        response[3] = 0x00; // local NOERROR, no forwarding or answers
        guard.retry(|| receiver.send_to(&response, source))?;
        let (length, peer) = guard.retry(|| sender.recv_from(&mut buffer))?;
        if peer != address || buffer[..length] != response {
            return Err(invalid("DNS fixture response mismatch"));
        }
        if index + 1 < count {
            guard.pause(Duration::from_millis(50))?;
        }
    }
    guard.check()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{path::PathBuf, sync::atomic::AtomicUsize};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Root(PathBuf);
    impl Root {
        fn new() -> Self {
            let root = PathBuf::from(format!(
                "/tmp/asmodeus-canary/local-fixture-tests-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&root).unwrap();
            Self(root)
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn config(procedure: &str, id: &str, positive: bool) -> LocalProcedureConfig {
        LocalProcedureConfig {
            procedure_id: procedure.into(),
            attempt_id: id.into(),
            variant: if positive {
                ProcedureVariantKind::Positive
            } else {
                ProcedureVariantKind::BenignControl
            },
            timeout_ms: 2000,
        }
    }
    fn flag() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    #[test]
    fn positive_and_benign_receipts_are_bounded_and_cleanup_retains_reservation() {
        let root = Root::new();
        for procedure in ["http-beacon", "dns-pattern", "synthetic-transfer"] {
            for positive in [true, false] {
                let id = format!("{procedure}-{positive}");
                let config = config(procedure, &id, positive);
                let result = run_in_root(config.clone(), flag(), &root.0).unwrap();
                assert_eq!(
                    result.status,
                    LocalAttemptStatus::Executed,
                    "{}",
                    result.detail
                );
                assert_eq!(result.mode, "LOCAL_FIXTURE");
                assert_eq!(result.signature_status, "UNSIGNED");
                assert_eq!(result.protection_result, "INCONCLUSIVE");
                assert_eq!(
                    result.receipts.len(),
                    if positive && procedure != "synthetic-transfer" {
                        4
                    } else {
                        1
                    }
                );
                assert!(result.receipts.iter().map(|r| r.bytes).sum::<usize>() <= 4096);
                for receipt in &result.receipts {
                    let address: std::net::SocketAddr = receipt.receiver.parse().unwrap();
                    assert_eq!(address.ip(), std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
                    assert_eq!(receipt.sha256.len(), 64);
                    assert!(receipt.bytes > 0);
                    if receipt.protocol == "http" {
                        assert!(
                            TcpStream::connect_timeout(&address, Duration::from_millis(50))
                                .is_err()
                        );
                    } else {
                        assert!(
                            UdpSocket::bind(address).is_ok(),
                            "UDP receiver must be closed"
                        );
                    }
                }
                if procedure == "dns-pattern" {
                    assert_eq!(
                        result.receipts[0].sha256,
                        sha256(&dns_query(0, positive, &id))
                    );
                }
                assert_eq!(result.cleanup.outcome, "VERIFIED");
                assert_eq!(result.cleanup.crash_cleanup, "NOT_VERIFIED");
                assert!(!root.0.join(&id).exists());
                let ledger: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&result.ownership_record).unwrap())
                        .unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    assert_eq!(
                        std::fs::metadata(&result.ownership_record)
                            .unwrap()
                            .permissions()
                            .mode()
                            & 0o777,
                        0o600
                    );
                }
                assert_eq!(ledger["state"], "RESERVED");
                assert_eq!(ledger["crash_cleanup"], "NOT_VERIFIED");
                assert!(
                    run_in_root(config, flag(), &root.0).is_err(),
                    "even cleaned attempts cannot be reused"
                );
                assert!(!root.0.join(&id).exists());
            }
        }
    }

    #[test]
    fn owned_peer_eof_and_timeout_are_bounded_errors() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut receiver, _) = listener.accept().unwrap();
        receiver.set_nonblocking(true).unwrap();
        drop(sender);
        let cancel = AtomicBool::new(false);
        let started = Instant::now();
        let guard = Guard {
            started,
            deadline: started + Duration::from_millis(100),
            cancel: &cancel,
        };
        let error = read_bounded(&mut receiver, &mut [0; 10], &guard).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn unsupported_slots_never_produce_receipts_or_protection_claims() {
        let root = Root::new();
        for procedure in [
            "container-exec",
            "shell-execution",
            "runtime-socket-prerequisite",
        ] {
            let evidence =
                run_in_root(config(procedure, procedure, true), flag(), &root.0).unwrap();
            assert_eq!(evidence.status, LocalAttemptStatus::Unsupported);
            assert!(evidence.receipts.is_empty());
            assert_eq!(evidence.protection_result, "INCONCLUSIVE");
            assert_eq!(evidence.cleanup.outcome, "VERIFIED");
        }
    }

    #[test]
    fn cancellation_and_timeout_cleanup_and_do_not_claim_success() {
        let root = Root::new();
        let cancelled = Arc::new(AtomicBool::new(true));
        let evidence = run_in_root(
            config("http-beacon", "pre-cancelled", true),
            cancelled,
            &root.0,
        )
        .unwrap();
        assert_eq!(evidence.status, LocalAttemptStatus::Cancelled);
        assert!(evidence.receipts.is_empty());
        assert_eq!(evidence.cleanup.outcome, "VERIFIED");

        let mut short = config("http-beacon", "timeout", true);
        short.timeout_ms = 1;
        let before = Instant::now();
        let evidence = run_in_root(short, flag(), &root.0).unwrap();
        assert_eq!(evidence.status, LocalAttemptStatus::Failed);
        assert!(evidence.detail.contains("timeout") || evidence.detail.contains("timed out"));
        assert!(before.elapsed() < Duration::from_secs(1));
        assert_eq!(evidence.cleanup.outcome, "VERIFIED");
        assert!(evidence.receipts.len() < 4);

        let cancelled = flag();
        let worker_flag = Arc::clone(&cancelled);
        let worker_root = root.0.clone();
        let worker = std::thread::spawn(move || {
            run_in_root(
                config("dns-pattern", "mid-cancel", true),
                worker_flag,
                &worker_root,
            )
            .unwrap()
        });
        let wait_start = Instant::now();
        while !root.0.join("mid-cancel.ownership.json").exists() {
            assert!(wait_start.elapsed() < Duration::from_secs(1));
            std::thread::sleep(Duration::from_millis(1));
        }
        cancelled.store(true, Ordering::SeqCst);
        let evidence = worker.join().unwrap();
        assert_eq!(evidence.status, LocalAttemptStatus::Cancelled);
        assert_eq!(evidence.cleanup.outcome, "VERIFIED");
        assert_eq!(evidence.cleanup.crash_cleanup, "NOT_VERIFIED");
    }

    #[test]
    fn preflight_rejects_bad_budget_scope_id_and_existing_ownership() {
        let root = Root::new();
        for id in ["", "../escape", "/absolute", "has space"] {
            assert!(run_in_root(config("http-beacon", id, true), flag(), &root.0).is_err());
        }
        for timeout in [0, 10_001, u64::MAX] {
            let mut invalid = config("http-beacon", "budget", true);
            invalid.timeout_ms = timeout;
            assert!(run_in_root(invalid, flag(), &root.0).is_err());
        }
        assert!(run_in_root(config("other", "unknown", true), flag(), &root.0).is_err());
        assert!(run_in_root(
            config("http-beacon", "scope", true),
            flag(),
            Path::new("/private/tmp/outside-canary")
        )
        .is_err());
        std::fs::create_dir(root.0.join("preexisting")).unwrap();
        std::fs::write(root.0.join("preexisting/keep"), b"untouched").unwrap();
        assert!(run_in_root(config("http-beacon", "preexisting", true), flag(), &root.0).is_err());
        assert_eq!(
            std::fs::read(root.0.join("preexisting/keep")).unwrap(),
            b"untouched"
        );
        assert!(!root.0.join("preexisting.ownership.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_parents_and_ledger_are_refused_without_touching_targets() {
        use std::os::unix::fs::symlink;
        let root = Root::new();
        let target = root.0.join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("keep"), b"untouched").unwrap();
        symlink(&target, root.0.join("linked")).unwrap();
        assert!(run_in_root(
            config("http-beacon", "attempt", true),
            flag(),
            &root.0.join("linked")
        )
        .is_err());
        symlink(target.join("keep"), root.0.join("ledger.ownership.json")).unwrap();
        assert!(run_in_root(config("http-beacon", "ledger", true), flag(), &root.0).is_err());
        assert!(!root.0.join("ledger").exists());
        assert_eq!(std::fs::read(target.join("keep")).unwrap(), b"untouched");
        symlink(&target, root.0.join("existing-link")).unwrap();
        assert!(run_in_root(
            config("http-beacon", "existing-link", true),
            flag(),
            &root.0
        )
        .is_err());
        assert_eq!(std::fs::read(target.join("keep")).unwrap(), b"untouched");
    }
}
