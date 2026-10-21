//! Executable side of the MITRE first-wave procedure corpus (S02).
//!
//! The corpus itself (the six fixed slots, their techniques/roles, fidelity
//! ceilings, benign controls and resource budgets) lives in
//! [`asmodeus_dsl::procedures`]. This module owns everything with a side
//! effect: the per-slot injectors, the safety **harness** that wraps every
//! attempt (scope rejection, timeout, cancellation, kill switch, resource
//! budget and mandatory cleanup on success/failure/crash/cancel), and the
//! per-attempt manifest.
//!
//! INV-0 holds throughout. Every injector is confined to the canary filesystem
//! and/or reserved loopback + RFC 5737 test scope; the three network slots do a
//! *real* loopback round-trip to an in-process test receiver, never any egress
//! to a routable host. None of this feeds the signed audit preimage — the
//! attempt manifest is a separate, honest reporting artifact.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::FileTypeExt;
#[cfg(test)]
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use asmodeus_dsl::net_target_in_scope;
use asmodeus_dsl::path_in_scope;
use asmodeus_dsl::procedures::{
    corpus_denominator, Capabilities, ExecutionMode, ProcedureSlot, Requirement, ResourceBudget,
    CORPUS_VERSION, PROCEDURE_SLOTS,
};
use asmodeus_dsl::{Fidelity, ATTACK_VERSION};
use asmodeus_safety::{CircuitBreaker, Thresholds, Trip};

// ---------------------------------------------------------------------------
// Errors, cancellation, observations
// ---------------------------------------------------------------------------

/// Why a procedure attempt did not succeed. Every variant forces cleanup.
#[derive(Debug)]
pub enum ProcedureError {
    /// Target path / destination / namespace is outside the allowed scope.
    OutOfScope(String),
    /// Required precondition (a stand-provided socket) is absent → NOT_RUN.
    PreconditionUnmet(String),
    /// The operator (or a test) cancelled the attempt.
    Cancelled,
    /// The attempt exceeded its time budget.
    Timeout(u64),
    /// The attempt exceeded its byte/file budget.
    Budget(String),
    /// The dead-man switch expired (lost heartbeat) → hard kill.
    KillSwitch(u8),
    /// An I/O failure during the synthetic action.
    Io(String),
}

impl std::fmt::Display for ProcedureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfScope(s) => write!(f, "out of scope: {s}"),
            Self::PreconditionUnmet(s) => write!(f, "precondition unmet: {s}"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::Timeout(ms) => write!(f, "timeout after {ms}ms"),
            Self::Budget(s) => write!(f, "resource budget exceeded: {s}"),
            Self::KillSwitch(n) => write!(f, "kill switch (heartbeats missed: {n})"),
            Self::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for ProcedureError {}

impl From<io::Error> for ProcedureError {
    fn from(e: io::Error) -> Self {
        ProcedureError::Io(e.to_string())
    }
}

/// A cooperative cancellation flag shared with the running injector.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// What a single synthetic attempt actually did — feeds the attempt manifest.
#[derive(Debug, Default, Clone)]
pub struct Observations {
    pub items: Vec<String>,
    pub bytes: u64,
    pub files: u32,
}

impl Observations {
    fn note(&mut self, msg: impl Into<String>) {
        self.items.push(msg.into());
    }
}

// ---------------------------------------------------------------------------
// Safety guard: timeout + kill switch + resource budget + cancellation
// ---------------------------------------------------------------------------

/// Wraps the attack-independent safety loop around one attempt. Reuses the
/// `asmodeus-safety` circuit breaker (timeout + lost-heartbeat kill) and layers
/// a byte/file budget and a cancellation flag on top.
pub struct BudgetGuard {
    breaker: CircuitBreaker,
    cancel: CancelToken,
    start: Instant,
    budget: ResourceBudget,
    bytes: u64,
    files: u32,
    heartbeats_missed: u8,
}

impl BudgetGuard {
    pub fn new(budget: ResourceBudget, cancel: CancelToken) -> Self {
        let breaker = CircuitBreaker::new(Thresholds {
            max_duration_ms: budget.max_duration_ms,
            ..Thresholds::default()
        });
        BudgetGuard {
            breaker,
            cancel,
            start: Instant::now(),
            budget,
            bytes: 0,
            files: 0,
            heartbeats_missed: 0,
        }
    }

    /// Record a lost control-plane heartbeat (drives the dead-man switch).
    pub fn miss_heartbeat(&mut self) {
        self.heartbeats_missed = self.heartbeats_missed.saturating_add(1);
    }

    /// Checked at every unit of work: cancellation, timeout and kill switch.
    pub fn checkpoint(&mut self) -> Result<(), ProcedureError> {
        if self.cancel.is_cancelled() {
            return Err(ProcedureError::Cancelled);
        }
        let elapsed = self.start.elapsed().as_millis() as u64;
        match self.breaker.evaluate(0, elapsed, self.heartbeats_missed) {
            Some(Trip::Timeout(ms)) => Err(ProcedureError::Timeout(ms)),
            Some(Trip::Heartbeat(n)) => Err(ProcedureError::KillSwitch(n)),
            // CPU is sampled by the service loop, not this guard.
            Some(Trip::Cpu(_)) | None => Ok(()),
        }
    }

    /// Charge resource usage and refuse to exceed the budget.
    pub fn charge(&mut self, bytes: u64, files: u32) -> Result<(), ProcedureError> {
        let next_bytes = self.bytes.saturating_add(bytes);
        let next_files = self.files.saturating_add(files);
        if next_bytes > self.budget.max_bytes {
            return Err(ProcedureError::Budget(format!(
                "bytes {}/{}",
                next_bytes, self.budget.max_bytes
            )));
        }
        if next_files > self.budget.max_files {
            return Err(ProcedureError::Budget(format!(
                "files {}/{}",
                next_files, self.budget.max_files
            )));
        }
        self.bytes = next_bytes;
        self.files = next_files;
        Ok(())
    }

    pub fn usage(&self) -> (u64, u32) {
        (self.bytes, self.files)
    }
}

// ---------------------------------------------------------------------------
// Cleanup guard: removes the per-attempt canary dir on every exit path
// ---------------------------------------------------------------------------

/// Removes the attempt's canary working directory when dropped — the backstop
/// that guarantees cleanup even if the injector panics mid-run.
struct WorkDirGuard {
    dir: PathBuf,
    armed: bool,
}

impl WorkDirGuard {
    fn new(dir: PathBuf) -> Self {
        WorkDirGuard { dir, armed: true }
    }
    /// Explicit cleanup; returns whether the directory is gone afterwards.
    fn cleanup(&mut self) -> bool {
        remove_tree(&self.dir);
        self.armed = false;
        !self.dir.exists()
    }
}

impl Drop for WorkDirGuard {
    fn drop(&mut self) {
        if self.armed {
            remove_tree(&self.dir);
        }
    }
}

fn remove_tree(dir: &Path) {
    match std::fs::remove_dir_all(dir) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(dir = %dir.display(), error = %e, "canary cleanup error"),
    }
}

// ---------------------------------------------------------------------------
// Net destination (validated against the reserved test blocks)
// ---------------------------------------------------------------------------

/// A validated loopback/RFC 5737 destination for a synthetic network slot.
#[derive(Debug, Clone, Copy)]
pub struct NetDestination {
    pub ip: Ipv4Addr,
    pub port: u16,
}

impl NetDestination {
    pub fn new(ip: Ipv4Addr, port: u16) -> Result<Self, ProcedureError> {
        let cidr = format!("{ip}/32");
        if !net_target_in_scope(&cidr) {
            return Err(ProcedureError::OutOfScope(format!(
                "destination {ip}:{port}"
            )));
        }
        Ok(NetDestination { ip, port })
    }
    fn socket(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.ip, self.port)
    }
}

// ---------------------------------------------------------------------------
// In-process test receivers (loopback TCP/UDP and canary unix socket)
// ---------------------------------------------------------------------------

const RECEIVER_DEADLINE: Duration = Duration::from_secs(5);

/// A bounded in-process loopback receiver that captures one synthetic beacon /
/// datagram / transfer, so a behavioural network slot has a real endpoint to
/// talk to without any egress leaving the host.
pub struct LoopbackReceiver {
    dest: NetDestination,
    join: Option<JoinHandle<Vec<u8>>>,
}

impl LoopbackReceiver {
    pub fn start_tcp() -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let dest = local_dest(listener.local_addr()?)?;
        listener.set_nonblocking(true)?;
        let join = thread::spawn(move || {
            let deadline = Instant::now() + RECEIVER_DEADLINE;
            let mut buf = Vec::new();
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).ok();
                        stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                        let _ = stream.read_to_end(&mut buf);
                        break;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            break;
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
            buf
        });
        Ok(LoopbackReceiver {
            dest,
            join: Some(join),
        })
    }

    pub fn start_udp() -> io::Result<Self> {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let dest = local_dest(sock.local_addr()?)?;
        sock.set_read_timeout(Some(RECEIVER_DEADLINE))?;
        let join = thread::spawn(move || {
            let mut buf = vec![0u8; 2048];
            match sock.recv(&mut buf) {
                Ok(n) => {
                    buf.truncate(n);
                    buf
                }
                Err(_) => Vec::new(),
            }
        });
        Ok(LoopbackReceiver {
            dest,
            join: Some(join),
        })
    }

    pub fn destination(&self) -> NetDestination {
        self.dest
    }

    /// Join the receiver thread (bounded) and return the captured bytes.
    pub fn finish(mut self) -> Vec<u8> {
        self.join
            .take()
            .map(|j| j.join().unwrap_or_default())
            .unwrap_or_default()
    }
}

impl Drop for LoopbackReceiver {
    fn drop(&mut self) {
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

fn local_dest(addr: SocketAddr) -> io::Result<NetDestination> {
    match addr {
        SocketAddr::V4(a) => {
            NetDestination::new(*a.ip(), a.port()).map_err(|e| io::Error::other(e.to_string()))
        }
        SocketAddr::V6(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "loopback receiver bound a v6 address",
        )),
    }
}

/// A bounded in-process canary-scoped unix socket standing in for a runtime /
/// container admin socket on a stand. Captures one synthetic command / probe.
#[cfg(test)]
pub struct UnixSocketReceiver {
    path: PathBuf,
    join: Option<JoinHandle<Vec<u8>>>,
}

#[cfg(test)]
impl UnixSocketReceiver {
    pub fn start(path: &Path) -> Result<Self, ProcedureError> {
        let as_str = path.to_string_lossy();
        if !path_in_scope(&as_str) {
            return Err(ProcedureError::OutOfScope(as_str.into_owned()));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // A stale socket file would make bind fail; remove it first.
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        listener.set_nonblocking(true)?;
        let join = thread::spawn(move || {
            let deadline = Instant::now() + RECEIVER_DEADLINE;
            let mut buf = Vec::new();
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                        let _ = stream.read_to_end(&mut buf);
                        break;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            break;
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
            buf
        });
        Ok(UnixSocketReceiver {
            path: path.to_path_buf(),
            join: Some(join),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.join
            .take()
            .map(|j| j.join().unwrap_or_default())
            .unwrap_or_default()
    }
}

#[cfg(test)]
impl Drop for UnixSocketReceiver {
    fn drop(&mut self) {
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Injectors
// ---------------------------------------------------------------------------

/// Common behaviour: run the synthetic action under the guard. Construction
/// validates scope (so an out-of-scope target is rejected before anything is
/// created); the harness owns the working directory and its cleanup.
trait Injector {
    fn execute(&self, guard: &mut BudgetGuard) -> Result<Observations, ProcedureError>;
}

fn validate_dir(dir: &Path) -> Result<(), ProcedureError> {
    let as_str = dir.to_string_lossy();
    if !path_in_scope(&as_str) {
        return Err(ProcedureError::OutOfScope(as_str.into_owned()));
    }
    Ok(())
}

/// Append one synthetic record line to the attempt's canary log and charge it.
fn canary_log(
    dir: &Path,
    line: &str,
    guard: &mut BudgetGuard,
    obs: &mut Observations,
) -> Result<(), ProcedureError> {
    guard.checkpoint()?;
    let log = dir.join("attempt.canary.log");
    let fresh = !log.exists();
    let payload = format!("{line}\n");
    guard.charge(payload.len() as u64, if fresh { 1 } else { 0 })?;
    std::fs::create_dir_all(dir)?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)?;
    f.write_all(payload.as_bytes())?;
    obs.bytes = obs.bytes.saturating_add(payload.len() as u64);
    if fresh {
        obs.files = obs.files.saturating_add(1);
    }
    Ok(())
}

/// Slot 2 (T1059.004): records a synthetic shell-command transcript. Marker —
/// no real shell is spawned locally.
struct ShellExecInjector {
    dir: PathBuf,
}

impl ShellExecInjector {
    fn new(dir: PathBuf) -> Result<Self, ProcedureError> {
        validate_dir(&dir)?;
        Ok(ShellExecInjector { dir })
    }
}

impl Injector for ShellExecInjector {
    fn execute(&self, guard: &mut BudgetGuard) -> Result<Observations, ProcedureError> {
        let mut obs = Observations::default();
        canary_log(
            &self.dir,
            "T1059.004 SYNTHETIC_SHELL transcript: /bin/sh -c 'echo asmodeus-canary-probe' \
             (recorded, not executed)",
            guard,
            &mut obs,
        )?;
        obs.note("recorded synthetic unix-shell command transcript in canary scope (marker)");
        Ok(obs)
    }
}

/// Slot 1 (T1609): sends a synthetic exec-command record to a canary admin
/// socket. Marker — no real container runtime is contacted.
struct ContainerExecInjector {
    dir: PathBuf,
    socket: PathBuf,
}

impl ContainerExecInjector {
    fn new(dir: PathBuf, socket: PathBuf) -> Result<Self, ProcedureError> {
        validate_dir(&dir)?;
        let s = socket.to_string_lossy();
        if !path_in_scope(&s) {
            return Err(ProcedureError::OutOfScope(format!("admin socket {s}")));
        }
        Ok(ContainerExecInjector { dir, socket })
    }
}

impl Injector for ContainerExecInjector {
    fn execute(&self, guard: &mut BudgetGuard) -> Result<Observations, ProcedureError> {
        let mut obs = Observations::default();
        guard.checkpoint()?;
        let mut stream = UnixStream::connect(&self.socket).map_err(|e| {
            ProcedureError::PreconditionUnmet(format!("canary admin socket unavailable: {e}"))
        })?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let cmd = b"T1609 SYNTHETIC_EXEC namespace=asmodeus-canary cmd=/bin/true # marker\n";
        guard.charge(cmd.len() as u64, 0)?;
        stream.write_all(cmd)?;
        stream.flush()?;
        drop(stream);
        obs.bytes = obs.bytes.saturating_add(cmd.len() as u64);
        canary_log(
            &self.dir,
            "T1609 delivered synthetic exec-command record to canary admin socket",
            guard,
            &mut obs,
        )?;
        obs.note(
            "delivered synthetic container exec-command record to canary admin socket (marker)",
        );
        Ok(obs)
    }
}

/// Slot 3 (T1611, precondition-signal only): connects to a canary test runtime
/// socket to prove reachability. NOT an escape — no host access is gained.
struct RuntimeSocketInjector {
    dir: PathBuf,
    socket: PathBuf,
}

impl RuntimeSocketInjector {
    fn new(dir: PathBuf, socket: PathBuf) -> Result<Self, ProcedureError> {
        validate_dir(&dir)?;
        let s = socket.to_string_lossy();
        if !path_in_scope(&s) {
            return Err(ProcedureError::OutOfScope(format!("runtime socket {s}")));
        }
        Ok(RuntimeSocketInjector { dir, socket })
    }
}

impl Injector for RuntimeSocketInjector {
    fn execute(&self, guard: &mut BudgetGuard) -> Result<Observations, ProcedureError> {
        let mut obs = Observations::default();
        guard.checkpoint()?;
        let mut stream = UnixStream::connect(&self.socket).map_err(|e| {
            ProcedureError::PreconditionUnmet(format!("canary runtime socket unreachable: {e}"))
        })?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let probe = b"T1611 SYNTHETIC_REACHABILITY_SIGNAL (precondition only; no escape)\n";
        guard.charge(probe.len() as u64, 0)?;
        stream.write_all(probe)?;
        stream.flush()?;
        drop(stream);
        obs.bytes = obs.bytes.saturating_add(probe.len() as u64);
        canary_log(
            &self.dir,
            "T1611 recorded test runtime-socket reachability signal (NOT an escape)",
            guard,
            &mut obs,
        )?;
        obs.note("measured canary test runtime-socket reachability (precondition signal only)");
        Ok(obs)
    }
}

/// Slot 4 (T1071.001): a real loopback TCP round-trip carrying a synthetic
/// HTTP beacon line to the in-process test receiver. Behavioural, no egress.
struct HttpBeaconInjector {
    dir: PathBuf,
    dest: NetDestination,
}

impl HttpBeaconInjector {
    fn new(dir: PathBuf, dest: NetDestination) -> Result<Self, ProcedureError> {
        validate_dir(&dir)?;
        Ok(HttpBeaconInjector { dir, dest })
    }
}

impl Injector for HttpBeaconInjector {
    fn execute(&self, guard: &mut BudgetGuard) -> Result<Observations, ProcedureError> {
        let mut obs = Observations::default();
        guard.checkpoint()?;
        let beacon = "GET /canary/beacon HTTP/1.1\r\nHost: beacon-test.invalid\r\n\
             X-Asmodeus: T1071.001 synthetic jitter_ms=25\r\n\r\n";
        guard.charge(beacon.len() as u64, 0)?;
        let sent = tcp_send(self.dest, beacon.as_bytes())?;
        obs.bytes = obs.bytes.saturating_add(sent as u64);
        obs.note(format!(
            "sent synthetic HTTP beacon ({sent} bytes) over loopback to {}:{}",
            self.dest.ip, self.dest.port
        ));
        canary_log(
            &self.dir,
            &format!(
                "T1071.001 beacon dest={}:{} bytes={sent} jitter_ms=25",
                self.dest.ip, self.dest.port
            ),
            guard,
            &mut obs,
        )?;
        Ok(obs)
    }
}

/// Slot 5 (T1071.004): a real loopback UDP datagram carrying a synthetic DNS
/// C2 query label to the in-process test receiver. Behavioural, no resolution.
struct DnsC2Injector {
    dir: PathBuf,
    dest: NetDestination,
}

impl DnsC2Injector {
    fn new(dir: PathBuf, dest: NetDestination) -> Result<Self, ProcedureError> {
        validate_dir(&dir)?;
        Ok(DnsC2Injector { dir, dest })
    }
}

impl Injector for DnsC2Injector {
    fn execute(&self, guard: &mut BudgetGuard) -> Result<Observations, ProcedureError> {
        let mut obs = Observations::default();
        guard.checkpoint()?;
        let query = dns_canary_query();
        guard.charge(query.len() as u64, 0)?;
        let sent = udp_send(self.dest, &query)?;
        obs.bytes = obs.bytes.saturating_add(sent as u64);
        obs.note(format!(
            "sent synthetic DNS C2 query label ({sent} bytes) over loopback to {}:{}",
            self.dest.ip, self.dest.port
        ));
        canary_log(
            &self.dir,
            &format!(
                "T1071.004 dns-query dest={}:{} label=c2-canary.beacon-test.invalid",
                self.dest.ip, self.dest.port
            ),
            guard,
            &mut obs,
        )?;
        Ok(obs)
    }
}

/// Slot 6 (T1041): a real loopback TCP transfer of a synthetic canary blob to
/// the in-process test receiver, in budgeted chunks. Behavioural, no egress.
struct ExfilTransferInjector {
    dir: PathBuf,
    dest: NetDestination,
    blob_bytes: usize,
}

impl ExfilTransferInjector {
    fn new(dir: PathBuf, dest: NetDestination, blob_bytes: usize) -> Result<Self, ProcedureError> {
        validate_dir(&dir)?;
        Ok(ExfilTransferInjector {
            dir,
            dest,
            blob_bytes,
        })
    }
}

impl Injector for ExfilTransferInjector {
    fn execute(&self, guard: &mut BudgetGuard) -> Result<Observations, ProcedureError> {
        let mut obs = Observations::default();
        guard.checkpoint()?;
        let mut stream = connect_tcp(self.dest)?;
        const CHUNK: usize = 4096;
        let chunk = vec![0x5Au8; CHUNK];
        let mut sent = 0usize;
        while sent < self.blob_bytes {
            guard.checkpoint()?;
            let n = CHUNK.min(self.blob_bytes - sent);
            // Charge *before* the write so the budget trips before bytes leave.
            guard.charge(n as u64, 0)?;
            stream.write_all(&chunk[..n])?;
            sent += n;
        }
        stream.flush()?;
        drop(stream);
        obs.bytes = obs.bytes.saturating_add(sent as u64);
        obs.note(format!(
            "transferred {sent} bytes of synthetic canary blob over loopback to {}:{}",
            self.dest.ip, self.dest.port
        ));
        canary_log(
            &self.dir,
            &format!(
                "T1041 transfer dest={}:{} bytes={sent}",
                self.dest.ip, self.dest.port
            ),
            guard,
            &mut obs,
        )?;
        Ok(obs)
    }
}

/// Valid DNS wire query: one TXT question, no external resolver involved.
fn dns_canary_query() -> Vec<u8> {
    let mut query = vec![0x41, 0x53, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["c2-canary", "beacon-test", "invalid"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 16, 0, 1]); // root, QTYPE=TXT, QCLASS=IN
    query
}

fn connect_tcp(dest: NetDestination) -> Result<TcpStream, ProcedureError> {
    let stream =
        TcpStream::connect_timeout(&SocketAddr::V4(dest.socket()), Duration::from_secs(2))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    Ok(stream)
}

fn tcp_send(dest: NetDestination, payload: &[u8]) -> Result<usize, ProcedureError> {
    let mut stream = connect_tcp(dest)?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(payload.len())
}

fn udp_send(dest: NetDestination, payload: &[u8]) -> Result<usize, ProcedureError> {
    let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let n = sock.send_to(payload, dest.socket())?;
    Ok(n)
}

// ---------------------------------------------------------------------------
// Environment + attempt / corpus manifests
// ---------------------------------------------------------------------------

/// Where an attempt ran. A local canary run is explicitly NOT a runtime-stand
/// run, so a marker/behavioural PASS here never stands in for stand execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stand {
    LocalCanary,
    RuntimeStand,
}

impl Stand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalCanary => "local-canary",
            Self::RuntimeStand => "runtime-stand",
        }
    }
}

/// The environment manifest recorded with every attempt.
#[derive(Debug, Clone)]
pub struct Environment {
    pub stand: Stand,
    pub os: String,
    pub caps: Capabilities,
}

impl Environment {
    /// A plain local canary environment: loopback receivers only, no stand
    /// sockets — the two execution/escape slots are NOT_RUN here.
    pub fn local() -> Self {
        Environment {
            stand: Stand::LocalCanary,
            os: std::env::consts::OS.to_string(),
            caps: Capabilities::LOCAL_CANARY,
        }
    }
}

/// Outcome of one attempt against one slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptStatus {
    Pass,
    Fail,
    NotRun,
}

impl AttemptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::NotRun => "not_run",
        }
    }
}

/// The honest record of one procedure attempt.
#[derive(Debug, Clone)]
pub struct AttemptManifest {
    pub attempt_id: String,
    pub slot_id: String,
    pub procedure_id: String,
    pub procedure_revision: u32,
    pub primary_technique: Option<String>,
    pub mode: Option<ExecutionMode>,
    pub status: AttemptStatus,
    pub stand: Stand,
    pub started_unix_ms: u128,
    pub stopped_unix_ms: u128,
    pub work_dir: Option<String>,
    pub observations: Vec<String>,
    pub bytes_written: u64,
    pub files_created: u32,
    pub fidelity_ceiling: Option<Fidelity>,
    pub cleanup_verified: bool,
    pub detail: String,
}

impl AttemptManifest {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "attempt_id": self.attempt_id,
            "slot_id": self.slot_id,
            "procedure_id": self.procedure_id,
            "procedure_revision": self.procedure_revision,
            "primary_technique": self.primary_technique,
            "mode": self.mode.map(|m| m.as_str()),
            "status": self.status.as_str(),
            "stand": self.stand.as_str(),
            "started_unix_ms": self.started_unix_ms.to_string(),
            "stopped_unix_ms": self.stopped_unix_ms.to_string(),
            "work_dir": self.work_dir,
            "observations": self.observations,
            "bytes_written": self.bytes_written,
            "files_created": self.files_created,
            "fidelity_ceiling": self.fidelity_ceiling.map(|f| f.as_str()),
            "claims_behavioral": self
                .fidelity_ceiling
                .map(|f| f.claims_behavioral())
                .unwrap_or(false),
            "cleanup_verified": self.cleanup_verified,
            "detail": self.detail,
        })
    }
}

/// Manifest of a full corpus run: one attempt per slot (NOT_RUN kept), plus the
/// honest coverage tally. The denominator is always the fixed corpus size.
#[derive(Debug, Clone)]
pub struct CorpusRunManifest {
    pub corpus_version: String,
    pub attack_version: String,
    pub stand: Stand,
    pub os: String,
    pub generated_unix_ms: u128,
    pub attempts: Vec<AttemptManifest>,
}

impl CorpusRunManifest {
    pub fn denominator(&self) -> usize {
        corpus_denominator()
    }
    pub fn behavioral_pass_count(&self) -> usize {
        self.attempts
            .iter()
            .filter(|a| {
                a.status == AttemptStatus::Pass
                    && a.fidelity_ceiling
                        .map(|f| f.claims_behavioral())
                        .unwrap_or(false)
            })
            .count()
    }
    pub fn marker_pass_count(&self) -> usize {
        self.attempts
            .iter()
            .filter(|a| {
                a.status == AttemptStatus::Pass
                    && !a
                        .fidelity_ceiling
                        .map(|f| f.claims_behavioral())
                        .unwrap_or(false)
            })
            .count()
    }
    pub fn not_run_count(&self) -> usize {
        self.attempts
            .iter()
            .filter(|a| a.status == AttemptStatus::NotRun)
            .count()
    }
    pub fn failed_count(&self) -> usize {
        self.attempts
            .iter()
            .filter(|a| a.status == AttemptStatus::Fail)
            .count()
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "corpus_version": self.corpus_version,
            "attack_version": self.attack_version,
            "stand": self.stand.as_str(),
            "os": self.os,
            "generated_unix_ms": self.generated_unix_ms.to_string(),
            "coverage": {
                "denominator": self.denominator(),
                "behavioral_pass": self.behavioral_pass_count(),
                "marker_pass": self.marker_pass_count(),
                "failed": self.failed_count(),
                "not_run": self.not_run_count(),
                "note": "NOT_RUN/unsupported slots stay in the denominator; marker/replay never \
                         count as behavioural coverage",
            },
            "attempts": self.attempts.iter().map(|a| a.to_json()).collect::<Vec<_>>(),
        })
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A fault injected by a test to exercise a safety path. `None` in production.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Fault {
    #[default]
    None,
    Cancel,
    KillSwitch,
    Crash,
}

/// Fine-grained run controls (tests). `RunOptions::local()` is the production
/// default used by [`run_local_corpus`].
#[derive(Debug, Clone)]
pub struct RunOptions {
    pub env: Environment,
    pub budget_override: Option<ResourceBudget>,
    pub mode_override: Option<ExecutionMode>,
    pub fault: Fault,
    pub exfil_blob_bytes: usize,
    pub admin_socket: Option<PathBuf>,
    pub runtime_socket: Option<PathBuf>,
}

impl RunOptions {
    pub fn local() -> Self {
        RunOptions {
            env: Environment::local(),
            budget_override: None,
            mode_override: None,
            fault: Fault::None,
            exfil_blob_bytes: 32 * 1024,
            admin_socket: None,
            runtime_socket: None,
        }
    }

    /// Read explicit operator endpoints; absent endpoints stay unsupported.
    pub fn stand() -> Result<Self, ProcedureError> {
        Self::with_stand_sockets(
            std::env::var_os("ASMODEUS_MITRE_ADMIN_SOCKET").map(PathBuf::from),
            std::env::var_os("ASMODEUS_MITRE_RUNTIME_SOCKET").map(PathBuf::from),
        )
    }

    fn with_stand_sockets(
        admin: Option<PathBuf>,
        runtime: Option<PathBuf>,
    ) -> Result<Self, ProcedureError> {
        for path in [&admin, &runtime].into_iter().flatten() {
            validate_dir(path)?;
            // Reject symlink escapes as well as non-socket/stale endpoints.
            let resolved = std::fs::canonicalize(path)?;
            let confined = ["/tmp", "/var/tmp"].iter().any(|root| {
                std::fs::canonicalize(root)
                    .is_ok_and(|parent| resolved.starts_with(parent.join("asmodeus-canary")))
            });
            if !confined {
                return Err(ProcedureError::OutOfScope(resolved.display().to_string()));
            }
            if !std::fs::metadata(path)?.file_type().is_socket() {
                return Err(ProcedureError::PreconditionUnmet(format!(
                    "not a stand socket: {}",
                    path.display()
                )));
            }
        }
        let mut opts = Self::local();
        opts.env.caps.container_admin_socket = admin.is_some();
        opts.env.caps.runtime_test_socket = runtime.is_some();
        if admin.is_some() || runtime.is_some() {
            opts.env.stand = Stand::RuntimeStand;
        }
        opts.admin_socket = admin;
        opts.runtime_socket = runtime;
        Ok(opts)
    }
}

static ATTEMPT_COUNTER: AtomicU64 = AtomicU64::new(0);

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn new_attempt() -> (String, PathBuf) {
    let n = ATTEMPT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let id = format!("w1-{pid}-{n}-{nanos}");
    let dir = PathBuf::from(format!("/tmp/asmodeus-canary/wave1/{id}"));
    (id, dir)
}

/// Run one slot end-to-end and return its honest attempt manifest. The slot's
/// working directory is always cleaned up — on success, failure, crash or
/// cancel — and cleanup is verified before returning.
pub fn run_slot(slot: &ProcedureSlot, opts: &RunOptions, cancel: &CancelToken) -> AttemptManifest {
    let (attempt_id, dir) = new_attempt();
    let started = now_ms();
    let primary = slot.primary_technique().map(str::to_string);

    let mut manifest = AttemptManifest {
        attempt_id: attempt_id.clone(),
        slot_id: slot.slot_id.to_string(),
        procedure_id: slot.procedure_id.to_string(),
        procedure_revision: slot.procedure_revision,
        primary_technique: primary,
        mode: None,
        status: AttemptStatus::NotRun,
        stand: opts.env.stand,
        started_unix_ms: started,
        stopped_unix_ms: started,
        work_dir: None,
        observations: Vec::new(),
        bytes_written: 0,
        files_created: 0,
        fidelity_ceiling: None,
        cleanup_verified: true, // nothing created yet
        detail: String::new(),
    };

    // Support gate: an unsupported slot is NOT_RUN and stays in the denominator.
    if !slot.supported_in(opts.env.caps) {
        manifest.detail = format!(
            "unsupported in this environment (needs {:?}); NOT_RUN, kept in denominator",
            slot.requirement
        );
        manifest.stopped_unix_ms = now_ms();
        return manifest;
    }

    let implemented_mode = if opts.env.stand == Stand::RuntimeStand {
        slot.stand_mode
    } else {
        slot.local_mode
    };
    let mode = match opts.mode_override {
        Some(ExecutionMode::Replay) => ExecutionMode::Replay,
        Some(ExecutionMode::Marker) => ExecutionMode::Marker,
        _ => implemented_mode,
    };
    manifest.mode = Some(mode);
    manifest.work_dir = Some(dir.to_string_lossy().into_owned());
    let budget = opts.budget_override.unwrap_or(slot.budget);

    let mut guard = BudgetGuard::new(budget, cancel.clone());
    if opts.fault == Fault::Cancel {
        cancel.cancel();
    }
    if opts.fault == Fault::KillSwitch {
        for _ in 0..Thresholds::default().heartbeat_miss_limit {
            guard.miss_heartbeat();
        }
    }

    let mut dir_guard = WorkDirGuard::new(dir.clone());

    // Replay mode re-emits a recorded observation set without live I/O.
    let result: Result<Observations, ProcedureError> = if mode == ExecutionMode::Replay {
        run_replay(slot, &dir, &mut guard)
    } else {
        run_live(slot, &dir, &opts.env, opts, &mut guard)
    };

    // Cleanup on every path, including an injected crash.
    manifest.cleanup_verified = dir_guard.cleanup();
    manifest.stopped_unix_ms = now_ms();
    let (bytes, files) = guard.usage();
    manifest.bytes_written = bytes;
    manifest.files_created = files;

    match result {
        Ok(obs) => {
            manifest.status = AttemptStatus::Pass;
            manifest.observations = obs.items;
            manifest.fidelity_ceiling = Some(mode.fidelity_ceiling());
            manifest.detail = format!("{} PASS ({} mode)", slot.slot_id, mode.as_str());
        }
        Err(ProcedureError::PreconditionUnmet(detail)) => {
            manifest.status = AttemptStatus::NotRun;
            manifest.detail = detail;
        }
        Err(e) => {
            manifest.status = AttemptStatus::Fail;
            manifest.detail = format!("{} FAIL: {e}", slot.slot_id);
        }
    }
    manifest
}

fn run_replay(
    slot: &ProcedureSlot,
    dir: &Path,
    guard: &mut BudgetGuard,
) -> Result<Observations, ProcedureError> {
    let mut obs = Observations::default();
    for ev in slot.expected_observables {
        canary_log(dir, &format!("[replay] {ev}"), guard, &mut obs)?;
    }
    obs.note(format!(
        "replayed {} recorded observable(s) (indicator-only, no live behaviour)",
        slot.expected_observables.len()
    ));
    Ok(obs)
}

fn run_live(
    slot: &ProcedureSlot,
    dir: &Path,
    env: &Environment,
    opts: &RunOptions,
    guard: &mut BudgetGuard,
) -> Result<Observations, ProcedureError> {
    // Crash fault: create a trace, then panic. catch_unwind + WorkDirGuard must
    // still leave zero residue.
    if opts.fault == Fault::Crash {
        let mut obs = Observations::default();
        canary_log(dir, "pre-crash sentinel", guard, &mut obs)?;
        let r = std::panic::catch_unwind(AssertUnwindSafe(|| {
            panic!("synthetic crash fault for cleanup test");
        }));
        if r.is_err() {
            return Err(ProcedureError::Io("injector crashed".into()));
        }
    }

    match slot.requirement {
        Requirement::LoopbackTestReceiver => run_network_slot(slot, dir, opts, guard),
        Requirement::ContainerAdminSocket => {
            let socket = opts.admin_socket.as_ref().ok_or_else(|| {
                ProcedureError::PreconditionUnmet("operator admin socket not configured".into())
            })?;
            let injector = ContainerExecInjector::new(dir.to_path_buf(), socket.clone())?;
            run_guarded(&injector, guard)
        }
        Requirement::RuntimeTestSocket => {
            let socket = opts.runtime_socket.as_ref().ok_or_else(|| {
                ProcedureError::PreconditionUnmet("operator runtime socket not configured".into())
            })?;
            let injector = RuntimeSocketInjector::new(dir.to_path_buf(), socket.clone())?;
            run_guarded(&injector, guard)
        }
        Requirement::CanaryFilesystem => {
            // Shell marker — the only filesystem-only slot in the corpus.
            let _ = env;
            let injector = ShellExecInjector::new(dir.to_path_buf())?;
            run_guarded(&injector, guard)
        }
    }
}

fn run_network_slot(
    slot: &ProcedureSlot,
    dir: &Path,
    opts: &RunOptions,
    guard: &mut BudgetGuard,
) -> Result<Observations, ProcedureError> {
    match slot.slot_id {
        "WAVE1-C2-HTTP-BEACON" => {
            let receiver = LoopbackReceiver::start_tcp()?;
            let dest = receiver.destination();
            let injector = HttpBeaconInjector::new(dir.to_path_buf(), dest)?;
            let out = run_guarded(&injector, guard);
            let captured = receiver.finish();
            finish_net(out, &captured, dest)
        }
        "WAVE1-C2-DNS" => {
            let receiver = LoopbackReceiver::start_udp()?;
            let dest = receiver.destination();
            let injector = DnsC2Injector::new(dir.to_path_buf(), dest)?;
            let out = run_guarded(&injector, guard);
            let captured = receiver.finish();
            finish_net(out, &captured, dest)
        }
        "WAVE1-EXFIL-TRANSFER" => {
            let receiver = LoopbackReceiver::start_tcp()?;
            let dest = receiver.destination();
            let injector =
                ExfilTransferInjector::new(dir.to_path_buf(), dest, opts.exfil_blob_bytes)?;
            let out = run_guarded(&injector, guard);
            let captured = receiver.finish();
            finish_net(out, &captured, dest)
        }
        other => Err(ProcedureError::Io(format!(
            "no network injector for slot {other}"
        ))),
    }
}

/// Run an injector under catch_unwind so a panic becomes a Fail (not an abort)
/// while the caller's WorkDirGuard still cleans up.
fn run_guarded(
    injector: &dyn Injector,
    guard: &mut BudgetGuard,
) -> Result<Observations, ProcedureError> {
    match std::panic::catch_unwind(AssertUnwindSafe(|| injector.execute(guard))) {
        Ok(r) => r,
        Err(_) => Err(ProcedureError::Io("injector panicked".into())),
    }
}

fn finish_net(
    out: Result<Observations, ProcedureError>,
    captured: &[u8],
    dest: NetDestination,
) -> Result<Observations, ProcedureError> {
    out.and_then(|mut obs| {
        if captured.is_empty() {
            return Err(ProcedureError::Io(
                "test receiver captured no payload".into(),
            ));
        }
        obs.note(format!(
            "test receiver on {}:{} captured {} bytes",
            dest.ip,
            dest.port,
            captured.len()
        ));
        Ok(obs)
    })
}

/// Run the whole frozen corpus once in the given environment, producing one
/// attempt per slot (NOT_RUN kept). The default [`Environment::local`] leaves
/// the two runtime-stand slots NOT_RUN.
pub fn run_corpus(opts: &RunOptions, cancel: &CancelToken) -> CorpusRunManifest {
    let attempts = PROCEDURE_SLOTS
        .iter()
        .map(|slot| run_slot(slot, opts, cancel))
        .collect();
    CorpusRunManifest {
        corpus_version: CORPUS_VERSION.to_string(),
        attack_version: ATTACK_VERSION.to_string(),
        stand: opts.env.stand,
        os: opts.env.os.clone(),
        generated_unix_ms: now_ms(),
        attempts,
    }
}

/// Convenience: run the corpus in a plain local canary environment.
pub fn run_local_corpus() -> CorpusRunManifest {
    run_corpus(&RunOptions::local(), &CancelToken::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use asmodeus_dsl::procedures::slot as slot_def;

    fn assert_clean(m: &AttemptManifest) {
        if let Some(d) = &m.work_dir {
            assert!(
                !Path::new(d).exists(),
                "slot {} left residue at {d}",
                m.slot_id
            );
        }
        assert!(
            m.cleanup_verified,
            "slot {} cleanup not verified",
            m.slot_id
        );
    }

    #[test]
    fn stand_without_operator_sockets_is_local_and_not_run() {
        let opts = RunOptions::with_stand_sockets(None, None).unwrap();
        let m = run_corpus(&opts, &CancelToken::new());
        assert_eq!(m.stand, Stand::LocalCanary);
        assert_eq!(m.not_run_count(), 2);
        assert_eq!(m.denominator(), 6);
    }

    #[test]
    fn stand_rejects_non_socket_and_out_of_scope_endpoints() {
        let (_, dir) = new_attempt();
        let mut cleanup = WorkDirGuard::new(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("not-a-socket");
        std::fs::write(&file, b"canary").unwrap();
        assert!(RunOptions::with_stand_sockets(Some(file), None).is_err());
        assert!(RunOptions::with_stand_sockets(Some("/etc/runtime.sock".into()), None).is_err());
        assert!(cleanup.cleanup());
    }

    #[test]
    fn vanished_stand_socket_stays_not_run() {
        let (_, dir) = new_attempt();
        let mut cleanup = WorkDirGuard::new(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("admin.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let opts = RunOptions::with_stand_sockets(Some(socket.clone()), None).unwrap();
        drop(listener);
        std::fs::remove_file(socket).unwrap();
        let m = run_slot(
            slot_def("WAVE1-EXEC-CONTAINER").unwrap(),
            &opts,
            &CancelToken::new(),
        );
        assert_eq!(m.status, AttemptStatus::NotRun);
        assert!(!m.to_json()["claims_behavioral"].as_bool().unwrap());
        assert_clean(&m);
        assert!(cleanup.cleanup());
    }

    #[test]
    fn behavioral_override_cannot_promote_shell_marker() {
        let mut opts = RunOptions::local();
        opts.mode_override = Some(ExecutionMode::Behavioral);
        let m = run_slot(
            slot_def("WAVE1-EXEC-SHELL").unwrap(),
            &opts,
            &CancelToken::new(),
        );
        assert_eq!(m.status, AttemptStatus::Pass);
        assert_eq!(m.fidelity_ceiling, Some(Fidelity::MarkerOnly));
        assert!(!m.to_json()["claims_behavioral"].as_bool().unwrap());
        assert_clean(&m);
    }

    #[test]
    fn exhausted_budget_prevents_file_creation_and_preserves_usage() {
        for (bytes, files) in [(0, 4), (1024, 0)] {
            let (_, dir) = new_attempt();
            let mut cleanup = WorkDirGuard::new(dir.clone());
            let mut guard = BudgetGuard::new(
                ResourceBudget {
                    max_duration_ms: 1000,
                    max_bytes: bytes,
                    max_files: files,
                },
                CancelToken::new(),
            );
            let injector = ShellExecInjector::new(dir.clone()).unwrap();
            assert!(matches!(
                injector.execute(&mut guard),
                Err(ProcedureError::Budget(_))
            ));
            assert!(!dir.exists());
            assert_eq!(guard.usage(), (0, 0));
            assert!(cleanup.cleanup());
        }
    }

    #[test]
    fn exhausted_budget_prevents_udp_send() {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let (_, dir) = new_attempt();
        let mut guard = BudgetGuard::new(
            ResourceBudget {
                max_duration_ms: 1000,
                max_bytes: 0,
                max_files: 0,
            },
            CancelToken::new(),
        );
        let injector =
            DnsC2Injector::new(dir.clone(), local_dest(sock.local_addr().unwrap()).unwrap())
                .unwrap();
        assert!(matches!(
            injector.execute(&mut guard),
            Err(ProcedureError::Budget(_))
        ));
        let mut buf = [0; 512];
        assert!(matches!(
            sock.recv(&mut buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        assert!(!dir.exists());
    }

    #[test]
    fn dns_injector_sends_a_valid_txt_question() {
        let receiver = LoopbackReceiver::start_udp().unwrap();
        let (_, dir) = new_attempt();
        let mut cleanup = WorkDirGuard::new(dir.clone());
        let injector = DnsC2Injector::new(dir, receiver.destination()).unwrap();
        let mut guard =
            BudgetGuard::new(slot_def("WAVE1-C2-DNS").unwrap().budget, CancelToken::new());
        injector.execute(&mut guard).unwrap();
        let packet = receiver.finish();
        assert_eq!(&packet[2..12], &[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        let mut offset = 12;
        let mut labels = Vec::new();
        while packet[offset] != 0 {
            let len = usize::from(packet[offset]);
            offset += 1;
            labels.push(std::str::from_utf8(&packet[offset..offset + len]).unwrap());
            offset += len;
        }
        assert_eq!(labels.join("."), "c2-canary.beacon-test.invalid");
        assert_eq!(&packet[offset..], &[0, 0, 16, 0, 1]);
        assert!(cleanup.cleanup());
    }

    #[test]
    fn empty_network_capture_cannot_pass() {
        let dest = NetDestination::new(Ipv4Addr::LOCALHOST, 12345).unwrap();
        assert!(finish_net(Ok(Observations::default()), &[], dest).is_err());
    }

    #[test]
    fn local_corpus_keeps_unsupported_in_denominator() {
        let m = run_local_corpus();
        assert_eq!(m.attempts.len(), 6);
        assert_eq!(m.denominator(), 6);
        // Two runtime-stand slots are NOT_RUN locally, four run.
        assert_eq!(m.not_run_count(), 2);
        let not_run: Vec<&str> = m
            .attempts
            .iter()
            .filter(|a| a.status == AttemptStatus::NotRun)
            .map(|a| a.slot_id.as_str())
            .collect();
        assert!(not_run.contains(&"WAVE1-EXEC-CONTAINER"));
        assert!(not_run.contains(&"WAVE1-EXEC-RUNTIME-SOCKET"));
        // Three behavioural network passes + one shell marker pass.
        assert_eq!(m.behavioral_pass_count(), 3);
        assert_eq!(m.marker_pass_count(), 1);
        assert_eq!(m.failed_count(), 0);
        for a in &m.attempts {
            assert_clean(a);
        }
    }

    #[test]
    fn full_stand_runs_all_six_and_cleans_up() {
        let (_, dir) = new_attempt();
        let mut cleanup = WorkDirGuard::new(dir.clone());
        let admin = UnixSocketReceiver::start(&dir.join("admin.sock")).unwrap();
        let runtime = UnixSocketReceiver::start(&dir.join("runtime.sock")).unwrap();
        let opts =
            RunOptions::with_stand_sockets(Some(admin.path().into()), Some(runtime.path().into()))
                .unwrap();
        let m = run_corpus(&opts, &CancelToken::new());
        assert!(!admin.finish().is_empty());
        assert!(!runtime.finish().is_empty());
        assert!(cleanup.cleanup());
        assert_eq!(m.stand, Stand::RuntimeStand);
        assert_eq!(m.not_run_count(), 0);
        assert_eq!(m.failed_count(), 0);
        // 3 behavioural (net) + 3 marker (shell, container, runtime socket).
        assert_eq!(m.behavioral_pass_count(), 3);
        assert_eq!(m.marker_pass_count(), 3);
        for a in &m.attempts {
            assert_eq!(a.status, AttemptStatus::Pass, "{} not pass", a.slot_id);
            assert_clean(a);
        }
    }

    #[test]
    fn modes_are_distinguishable_and_fidelity_is_clamped() {
        let s = slot_def("WAVE1-C2-HTTP-BEACON").unwrap();
        // Behavioural locally.
        let b = run_slot(s, &RunOptions::local(), &CancelToken::new());
        assert_eq!(b.mode, Some(ExecutionMode::Behavioral));
        assert_eq!(b.fidelity_ceiling, Some(Fidelity::Behavioral));
        // Replay of the same slot is indicator-only.
        let mut opts = RunOptions::local();
        opts.mode_override = Some(ExecutionMode::Replay);
        let r = run_slot(s, &opts, &CancelToken::new());
        assert_eq!(r.mode, Some(ExecutionMode::Replay));
        assert_eq!(r.fidelity_ceiling, Some(Fidelity::MarkerOnly));
        assert_eq!(r.status, AttemptStatus::Pass);
        assert_clean(&r);
        // Shell is marker locally.
        let sh = run_slot(
            slot_def("WAVE1-EXEC-SHELL").unwrap(),
            &RunOptions::local(),
            &CancelToken::new(),
        );
        assert_eq!(sh.mode, Some(ExecutionMode::Marker));
        assert_eq!(sh.fidelity_ceiling, Some(Fidelity::MarkerOnly));
    }

    #[test]
    fn cancel_fails_and_cleans_up() {
        let mut opts = RunOptions::local();
        opts.fault = Fault::Cancel;
        let m = run_slot(
            slot_def("WAVE1-C2-HTTP-BEACON").unwrap(),
            &opts,
            &CancelToken::new(),
        );
        assert_eq!(m.status, AttemptStatus::Fail);
        assert!(m.detail.contains("cancelled"), "{}", m.detail);
        assert_clean(&m);
    }

    #[test]
    fn kill_switch_fails_and_cleans_up() {
        let mut opts = RunOptions::local();
        opts.fault = Fault::KillSwitch;
        let m = run_slot(
            slot_def("WAVE1-EXFIL-TRANSFER").unwrap(),
            &opts,
            &CancelToken::new(),
        );
        assert_eq!(m.status, AttemptStatus::Fail);
        assert!(m.detail.contains("kill switch"), "{}", m.detail);
        assert_clean(&m);
    }

    #[test]
    fn crash_still_cleans_up() {
        let mut opts = RunOptions::local();
        opts.fault = Fault::Crash;
        let m = run_slot(
            slot_def("WAVE1-EXEC-SHELL").unwrap(),
            &opts,
            &CancelToken::new(),
        );
        assert_eq!(m.status, AttemptStatus::Fail);
        assert_clean(&m);
    }

    #[test]
    fn budget_trip_fails_and_cleans_up() {
        let mut opts = RunOptions::local();
        opts.budget_override = Some(ResourceBudget {
            max_duration_ms: 15_000,
            max_bytes: 8 * 1024,
            max_files: 4,
        });
        opts.exfil_blob_bytes = 64 * 1024; // over the 8KiB budget
        let m = run_slot(
            slot_def("WAVE1-EXFIL-TRANSFER").unwrap(),
            &opts,
            &CancelToken::new(),
        );
        assert_eq!(m.status, AttemptStatus::Fail);
        assert!(m.detail.contains("budget"), "{}", m.detail);
        assert_clean(&m);
    }

    #[test]
    fn rerun_does_not_adopt_previous_attempt_artifacts() {
        let s = slot_def("WAVE1-C2-DNS").unwrap();
        let a = run_slot(s, &RunOptions::local(), &CancelToken::new());
        let b = run_slot(s, &RunOptions::local(), &CancelToken::new());
        assert_ne!(a.attempt_id, b.attempt_id);
        assert_ne!(a.work_dir, b.work_dir);
        // Each attempt's observations reference its own destination/log only.
        for obs in &b.observations {
            assert!(
                !obs.contains(&a.attempt_id),
                "attempt B observation references attempt A: {obs}"
            );
        }
        assert_clean(&a);
        assert_clean(&b);
    }

    #[test]
    fn out_of_scope_targets_are_rejected() {
        // Filesystem path outside canary scope.
        assert!(ShellExecInjector::new(PathBuf::from("/etc/asmodeus")).is_err());
        // Net destination outside the reserved test blocks.
        assert!(NetDestination::new("8.8.8.8".parse().unwrap(), 53).is_err());
        assert!(NetDestination::new("10.0.0.1".parse().unwrap(), 80).is_err());
        // Loopback + RFC 5737 are accepted.
        assert!(NetDestination::new(Ipv4Addr::LOCALHOST, 443).is_ok());
        assert!(NetDestination::new("192.0.2.10".parse().unwrap(), 443).is_ok());
        // Unix socket path outside canary scope.
        assert!(UnixSocketReceiver::start(Path::new("/etc/asmodeus.sock")).is_err());
    }

    #[test]
    fn behavioral_network_round_trip_is_captured_on_loopback() {
        // Direct check that the beacon really traverses loopback to the receiver.
        let s = slot_def("WAVE1-C2-HTTP-BEACON").unwrap();
        let m = run_slot(s, &RunOptions::local(), &CancelToken::new());
        assert_eq!(m.status, AttemptStatus::Pass);
        assert!(m.bytes_written > 0);
        assert!(
            m.observations
                .iter()
                .any(|o| o.contains("captured") && !o.contains("captured 0 bytes")),
            "receiver should capture the beacon bytes: {:?}",
            m.observations
        );
        assert!(m.observations.iter().any(|o| o.contains("127.0.0.1")));
    }

    #[test]
    fn guard_timeout_trips() {
        let mut g = BudgetGuard::new(
            ResourceBudget {
                max_duration_ms: 0,
                max_bytes: 1024,
                max_files: 4,
            },
            CancelToken::new(),
        );
        thread::sleep(Duration::from_millis(2));
        assert!(matches!(g.checkpoint(), Err(ProcedureError::Timeout(_))));
    }

    #[test]
    fn attempt_manifest_json_is_honest() {
        let m = run_slot(
            slot_def("WAVE1-EXEC-CONTAINER").unwrap(),
            &RunOptions::local(),
            &CancelToken::new(),
        );
        // Unsupported locally → NOT_RUN, still represented.
        let j = m.to_json();
        assert_eq!(j["status"], "not_run");
        assert_eq!(j["claims_behavioral"], false);
        // Corpus-level JSON keeps the full denominator and the honesty note.
        let cm = run_local_corpus();
        let cj = cm.to_json();
        assert_eq!(cj["coverage"]["denominator"], 6);
        assert_eq!(cj["attempts"].as_array().unwrap().len(), 6);
    }
}
