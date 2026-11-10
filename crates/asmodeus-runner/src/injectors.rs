//! Synthetic scenario injectors for Asmodeus Runner.
//!
//! Under root invariant INV-0 (Synthetic-Only), each injector reproduces
//! the behavioral footprint of a specific MITRE ATT&CK technique or chaos
//! fault within the isolated canary blast radius (/tmp|/var/tmp/asmodeus-canary)
//! or reserved RFC 5737 test segments, with mandatory cleanup on rollback.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use asmodeus_dsl::path_in_scope;

use crate::canary::{CanaryInjector, InjectError, Report};
use crate::netchaos::{default_backend, NetChaosSession, NetChaosSpec};

/// Trait implemented by all synthetic scenario executors.
pub trait ScenarioInjector: Send + Sync {
    /// Execute the synthetic injection pass (generating events, files, or network rules).
    fn inject(&self) -> Result<Report, InjectError>;
    /// Same as [`inject`](Self::inject), polling `check` while the pass can block.
    /// The default ignores `check`; the crash probe overrides it so a cancel,
    /// lease loss, or safety cap can interrupt the reap.
    fn inject_checked(
        &self,
        check: &dyn Fn() -> Result<(), InjectError>,
    ) -> Result<Report, InjectError> {
        let _ = check;
        self.inject()
    }
    /// Unconditionally revert and remove all synthetic traces.
    fn cleanup(&self) -> Result<(), InjectError>;
}

use std::io::Read;

fn remove_file_idempotent(path: impl AsRef<Path>) -> Result<(), InjectError> {
    match fs::remove_file(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(InjectError::Io(e)),
    }
}

// ---------------------------------------------------------------------------
// 1. T1486 — Ransomware Canary Encryption Spike
// ---------------------------------------------------------------------------

impl ScenarioInjector for CanaryInjector {
    fn inject(&self) -> Result<Report, InjectError> {
        self.inject()
    }

    fn cleanup(&self) -> Result<(), InjectError> {
        self.cleanup()
    }
}

// ---------------------------------------------------------------------------
// 2. T1611 / T1059 — K8s Container Escape & Shell Probe
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct K8sEscapeInjector {
    dir: PathBuf,
}

impl K8sEscapeInjector {
    pub fn new(dir: impl AsRef<Path>) -> Result<Self, InjectError> {
        let dir = dir.as_ref().to_path_buf();
        let as_str = dir.to_string_lossy();
        if !path_in_scope(&as_str) {
            return Err(InjectError::OutOfScope(as_str.into_owned()));
        }
        Ok(K8sEscapeInjector { dir })
    }
}

impl ScenarioInjector for K8sEscapeInjector {
    fn inject(&self) -> Result<Report, InjectError> {
        fs::create_dir_all(&self.dir)?;
        let probe_socket = self.dir.join("docker.sock.probe");
        let probe_ns = self.dir.join("k8s_ns_escape.canary");

        // Synthetic dummy socket probe
        fs::write(
            &probe_socket,
            b"CANARY_K8S_ESCAPE_SOCKET_PROBE: namespace=ferrum-canary pid=1001\n",
        )?;
        // Synthetic simulated hostPath breakout marker
        fs::write(
            &probe_ns,
            b"CANARY_HOST_PATH_PROBE: simulated /proc/1/ns/mnt escape check\n",
        )?;

        let bytes = fs::metadata(&probe_socket)?.len() + fs::metadata(&probe_ns)?.len();
        Ok(Report {
            files_created: 2,
            bytes_written: bytes,
        })
    }

    fn cleanup(&self) -> Result<(), InjectError> {
        if self.dir.exists() {
            remove_file_idempotent(self.dir.join("docker.sock.probe"))?;
            remove_file_idempotent(self.dir.join("k8s_ns_escape.canary"))?;
            let _ = fs::remove_dir(&self.dir);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 3. T1071 / T1568 — C2 Beaconing & Dynamic Resolution Simulation
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct C2BeaconInjector {
    dir: PathBuf,
    beacon_count: usize,
}

impl C2BeaconInjector {
    pub fn new(dir: impl AsRef<Path>, count: usize) -> Result<Self, InjectError> {
        let dir = dir.as_ref().to_path_buf();
        let as_str = dir.to_string_lossy();
        if !path_in_scope(&as_str) {
            return Err(InjectError::OutOfScope(as_str.into_owned()));
        }
        Ok(C2BeaconInjector {
            dir,
            beacon_count: count.clamp(1, 100),
        })
    }
}

impl ScenarioInjector for C2BeaconInjector {
    fn inject(&self) -> Result<Report, InjectError> {
        fs::create_dir_all(&self.dir)?;
        let beacon_log = self.dir.join("c2_beacon_events.log");
        let mut file = fs::File::create(&beacon_log)?;
        let mut bytes = 0u64;

        for i in 0..self.beacon_count {
            let entry = format!(
                "T1071_BEACON_EVENT seq={i} target=beacon-test.c2-emulation.internal:443 proto=HTTPS jitter_ms=25 status=SINKHOLED\n"
            );
            file.write_all(entry.as_bytes())?;
            bytes += entry.len() as u64;
        }

        Ok(Report {
            files_created: 1,
            bytes_written: bytes,
        })
    }

    fn cleanup(&self) -> Result<(), InjectError> {
        if self.dir.exists() {
            remove_file_idempotent(self.dir.join("c2_beacon_events.log"))?;
            let _ = fs::remove_dir(&self.dir);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 4. T1003 — Credential Access Honeytoken Canary
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct CredentialAccessInjector {
    dir: PathBuf,
}

impl CredentialAccessInjector {
    pub fn new(dir: impl AsRef<Path>) -> Result<Self, InjectError> {
        let dir = dir.as_ref().to_path_buf();
        let as_str = dir.to_string_lossy();
        if !path_in_scope(&as_str) {
            return Err(InjectError::OutOfScope(as_str.into_owned()));
        }
        Ok(CredentialAccessInjector { dir })
    }
}

impl ScenarioInjector for CredentialAccessInjector {
    fn inject(&self) -> Result<Report, InjectError> {
        fs::create_dir_all(&self.dir)?;
        let honeytoken = self.dir.join("honeytoken_credentials.json");

        let content = concat!(
            "{\n",
            "  \"type\": \"HONEYTOKEN_CANARY\",\n",
            "  \"account\": \"svc_asmodeus_decoy\",\n",
            "  \"access_key\": \"AKIA_CANARY_TEST_DO_NOT_USE_12345\",\n",
            "  \"warning\": \"Synthetic trap for detecting unauthorized credential dumping\"\n",
            "}\n"
        );

        fs::write(&honeytoken, content.as_bytes())?;

        // Simulate benign read access to trigger detector
        let _ = fs::read(&honeytoken)?;

        Ok(Report {
            files_created: 1,
            bytes_written: content.len() as u64,
        })
    }

    fn cleanup(&self) -> Result<(), InjectError> {
        if self.dir.exists() {
            remove_file_idempotent(self.dir.join("honeytoken_credentials.json"))?;
            let _ = fs::remove_dir(&self.dir);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 5. T1070 — Indicator Removal on Host
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct LogTamperInjector {
    dir: PathBuf,
}

impl LogTamperInjector {
    pub fn new(dir: impl AsRef<Path>) -> Result<Self, InjectError> {
        let dir = dir.as_ref().to_path_buf();
        let as_str = dir.to_string_lossy();
        if !path_in_scope(&as_str) {
            return Err(InjectError::OutOfScope(as_str.into_owned()));
        }
        Ok(LogTamperInjector { dir })
    }
}

impl ScenarioInjector for LogTamperInjector {
    fn inject(&self) -> Result<Report, InjectError> {
        fs::create_dir_all(&self.dir)?;
        let audit_log = self.dir.join("canary_audit.log");

        // 1. Write synthetic audit entries
        let initial_content = b"AUDIT_CANARY entry=1 user=admin action=login\nAUDIT_CANARY entry=2 user=admin action=modify_policy\n";
        fs::write(&audit_log, initial_content)?;

        // 2. Simulate truncation / wiping of the audit trail
        fs::write(&audit_log, b"[TAMPERED / TRUNCATED CANARY LOG]\n")?;

        Ok(Report {
            files_created: 1,
            bytes_written: (initial_content.len() + 35) as u64,
        })
    }

    fn cleanup(&self) -> Result<(), InjectError> {
        if self.dir.exists() {
            remove_file_idempotent(self.dir.join("canary_audit.log"))?;
            let _ = fs::remove_dir(&self.dir);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 6. T1053 — Persistence Scheduled Task / Cron Canary
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct PersistenceCronInjector {
    dir: PathBuf,
}

impl PersistenceCronInjector {
    pub fn new(dir: impl AsRef<Path>) -> Result<Self, InjectError> {
        let dir = dir.as_ref().to_path_buf();
        let as_str = dir.to_string_lossy();
        if !path_in_scope(&as_str) {
            return Err(InjectError::OutOfScope(as_str.into_owned()));
        }
        Ok(PersistenceCronInjector { dir })
    }
}

impl ScenarioInjector for PersistenceCronInjector {
    fn inject(&self) -> Result<Report, InjectError> {
        fs::create_dir_all(&self.dir)?;
        let cron_file = self.dir.join("canary_cron_task.job");

        let cron_content = b"# Asmodeus Synthetic Persistence Canary Task\n* * * * * root /bin/true # SYNTHETIC_CANARY_PROBE\n";
        fs::write(&cron_file, cron_content)?;

        Ok(Report {
            files_created: 1,
            bytes_written: cron_content.len() as u64,
        })
    }

    fn cleanup(&self) -> Result<(), InjectError> {
        if self.dir.exists() {
            remove_file_idempotent(self.dir.join("canary_cron_task.job"))?;
            let _ = fs::remove_dir(&self.dir);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 7. T1041 — Exfiltration Over C2 Channel
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct DataExfiltrationInjector {
    dir: PathBuf,
    chunk_kb: usize,
}

impl DataExfiltrationInjector {
    pub fn new(dir: impl AsRef<Path>, chunk_kb: usize) -> Result<Self, InjectError> {
        let dir = dir.as_ref().to_path_buf();
        let as_str = dir.to_string_lossy();
        if !path_in_scope(&as_str) {
            return Err(InjectError::OutOfScope(as_str.into_owned()));
        }
        Ok(DataExfiltrationInjector {
            dir,
            chunk_kb: chunk_kb.clamp(1, 1024),
        })
    }
}

impl ScenarioInjector for DataExfiltrationInjector {
    fn inject(&self) -> Result<Report, InjectError> {
        fs::create_dir_all(&self.dir)?;
        let exfil_file = self.dir.join("staged_canary_data.tar.gz");

        let mut file = fs::File::create(&exfil_file)?;
        let bytes_to_write = (self.chunk_kb * 1024) as u64;
        let mut reader = io::repeat(0xEE).take(bytes_to_write);
        io::copy(&mut reader, &mut file)?;

        Ok(Report {
            files_created: 1,
            bytes_written: bytes_to_write,
        })
    }

    fn cleanup(&self) -> Result<(), InjectError> {
        if self.dir.exists() {
            remove_file_idempotent(self.dir.join("staged_canary_data.tar.gz"))?;
            let _ = fs::remove_dir(&self.dir);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 8. T1562 / Chaos — Defense Impairment & Agent Watchdog Probe
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct DefenseImpairmentInjector {
    dir: PathBuf,
}

impl DefenseImpairmentInjector {
    pub fn new(dir: impl AsRef<Path>) -> Result<Self, InjectError> {
        let dir = dir.as_ref().to_path_buf();
        let as_str = dir.to_string_lossy();
        if !path_in_scope(&as_str) {
            return Err(InjectError::OutOfScope(as_str.into_owned()));
        }
        Ok(DefenseImpairmentInjector { dir })
    }
}

impl ScenarioInjector for DefenseImpairmentInjector {
    fn inject(&self) -> Result<Report, InjectError> {
        fs::create_dir_all(&self.dir)?;
        let probe = self.dir.join("watchdog_recovery.pulse");

        let marker = b"WATCHDOG_SIMULATED_INTERRUPT: target=lariska_agent recovery_window=5000ms\n";
        fs::write(&probe, marker)?;

        Ok(Report {
            files_created: 1,
            bytes_written: marker.len() as u64,
        })
    }

    fn cleanup(&self) -> Result<(), InjectError> {
        if self.dir.exists() {
            remove_file_idempotent(self.dir.join("watchdog_recovery.pulse"))?;
            let _ = fs::remove_dir(&self.dir);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 9. Infrastructure Chaos — Network / DNS Outage
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct NetChaosInjector {
    spec: NetChaosSpec,
    dir: PathBuf,
}

impl NetChaosInjector {
    pub fn new(dir: impl AsRef<Path>, spec: NetChaosSpec) -> Result<Self, InjectError> {
        let dir = dir.as_ref().to_path_buf();
        let as_str = dir.to_string_lossy();
        if !path_in_scope(&as_str) {
            return Err(InjectError::OutOfScope(as_str.into_owned()));
        }
        Ok(NetChaosInjector { spec, dir })
    }
}

impl ScenarioInjector for NetChaosInjector {
    fn inject(&self) -> Result<Report, InjectError> {
        fs::create_dir_all(&self.dir)?;
        let session_marker = self.dir.join("netchaos_session.token");

        let backend = default_backend();
        let session = NetChaosSession::start(&backend, &self.spec)
            .map_err(|e| InjectError::Io(io::Error::other(e.to_string())))?;

        let token = session.handle().map(|h| h.token).unwrap_or_default();
        fs::write(&session_marker, format!("token={token}").as_bytes())?;

        Ok(Report {
            files_created: 1,
            bytes_written: 16,
        })
    }

    fn cleanup(&self) -> Result<(), InjectError> {
        if self.dir.exists() {
            remove_file_idempotent(self.dir.join("netchaos_session.token"))?;
            let _ = fs::remove_dir(&self.dir);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 10. Chaos — Agent Crash Endpoint Probe (FTT §4.2.2)
// ---------------------------------------------------------------------------

/// Synthetic `AGENT_CRASH_ENDPOINT` executor. FTT §4.2.2 asks for a `kill -9`
/// against the security agent; INV-0 forbids touching any real process, so
/// this injector spawns its own *decoy* child inside the canary blast radius,
/// force-kills it with SIGKILL, reaps it, and writes a pulse. `reap_ms` is the
/// time until that child died. The planned window is a budget, not evidence
/// that a real agent restarted. Cleanup removes every trace unconditionally.
#[cfg(unix)]
#[derive(Debug)]
pub struct AgentCrashProbeInjector {
    dir: PathBuf,
    /// Budget, from the manifest, for how long the decoy may take to die.
    /// FTT §4.2.2 caps it at 5 s. It is not a measured agent restart.
    recovery_window_ms: u32,
}

#[cfg(unix)]
impl AgentCrashProbeInjector {
    pub fn new(dir: impl AsRef<Path>, recovery_window_ms: u32) -> Result<Self, InjectError> {
        let dir = dir.as_ref().to_path_buf();
        let as_str = dir.to_string_lossy();
        if !path_in_scope(&as_str) {
            return Err(InjectError::OutOfScope(as_str.into_owned()));
        }
        Ok(AgentCrashProbeInjector {
            dir,
            recovery_window_ms: recovery_window_ms
                .clamp(100, asmodeus_dsl::AGENT_CRASH_RECOVERY_WINDOW_MS),
        })
    }
}

#[cfg(unix)]
impl ScenarioInjector for AgentCrashProbeInjector {
    fn inject(&self) -> Result<Report, InjectError> {
        self.inject_checked(&|| Ok(()))
    }

    fn inject_checked(
        &self,
        check: &dyn Fn() -> Result<(), InjectError>,
    ) -> Result<Report, InjectError> {
        use std::os::unix::process::ExitStatusExt;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        fs::create_dir_all(&self.dir)?;
        let crash_log = self.dir.join("agent_crash_probe.log");
        let pulse = self.dir.join("watchdog_recovery.pulse");

        // Decoy "agent": a long-sleeping child owned exclusively by this run.
        let mut child = Command::new("/bin/sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                InjectError::Io(io::Error::new(
                    e.kind(),
                    format!("cannot spawn synthetic decoy agent: {e}"),
                ))
            })?;
        let pid = child.id() as i32;
        // Poll try_wait. child.wait() can block past the caller's deadline,
        // and dropping Child does not reap. A failed check is returned only
        // after the decoy is dead, or after the short give-up.
        let reap_bounded = |child: &mut std::process::Child,
                            check: &dyn Fn() -> Result<(), InjectError>|
         -> Result<(), InjectError> {
            let _ = child.kill();
            let give_up = Instant::now() + Duration::from_millis(200);
            let mut interrupted = None;
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => {
                        return match interrupted {
                            Some(error) => Err(error),
                            None => Ok(()),
                        };
                    }
                    Ok(None) if Instant::now() >= give_up => {
                        return Err(interrupted.unwrap_or_else(|| {
                            InjectError::Io(io::Error::other(
                                "decoy agent survived the forced termination window",
                            ))
                        }));
                    }
                    Ok(None) => {
                        if interrupted.is_none() {
                            if let Err(error) = check() {
                                interrupted = Some(error);
                            }
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => return Err(InjectError::Io(e)),
                }
            }
        };

        // The interruption under test: SIGKILL (kill -9) on the decoy only.
        let killed = Instant::now();
        if let Err(error) = nix_kill_sig9(pid) {
            let _ = reap_bounded(&mut child, &|| Ok(()));
            return Err(error);
        }

        // Reap the child and confirm it died of SIGKILL inside the planned
        // window. The elapsed time is how long the decoy took to die, not a
        // measurement of some other agent's restart.
        let deadline = killed + Duration::from_millis(u64::from(self.recovery_window_ms));
        let status = loop {
            if let Err(error) = check() {
                let _ = reap_bounded(&mut child, &|| Ok(()));
                return Err(error);
            }
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() >= deadline => {
                    reap_bounded(&mut child, check)?;
                    return Err(InjectError::Io(io::Error::other(
                        "decoy agent survived the forced termination window",
                    )));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Err(e) => {
                    let _ = reap_bounded(&mut child, &|| Ok(()));
                    return Err(InjectError::Io(e));
                }
            }
        };
        if status.signal() != Some(libc::SIGKILL) {
            return Err(InjectError::Io(io::Error::other(
                "decoy agent did not terminate via SIGKILL",
            )));
        }
        let reap_ms = u32::try_from(killed.elapsed().as_millis()).unwrap_or(u32::MAX);

        let marker = format!(
            "AGENT_CRASH_PROBE: target=synthetic_decoy_agent pid={pid} signal=SIGKILL \
             reap_ms={reap_ms} planned_window_ms={} status=DECOY_REAPED\n",
            self.recovery_window_ms
        );
        let mut total = marker.len() as u64;
        fs::write(&pulse, marker.as_bytes())?;

        let log = format!(
            "TERMINATION_EVENT pid={pid} signal=9 reap_ms={reap_ms} planned_window_ms={}\n",
            self.recovery_window_ms
        );
        total += log.len() as u64;
        fs::write(&crash_log, log.as_bytes())?;

        Ok(Report {
            files_created: 2,
            bytes_written: total,
        })
    }

    fn cleanup(&self) -> Result<(), InjectError> {
        if self.dir.exists() {
            remove_file_idempotent(self.dir.join("watchdog_recovery.pulse"))?;
            remove_file_idempotent(self.dir.join("agent_crash_probe.log"))?;
            let _ = fs::remove_dir(&self.dir);
        }
        Ok(())
    }
}

/// `kill(pid, SIGKILL)` through the `libc` binding already in the dependency
/// set. The runner never shells out (INV-0 / D7); the signal goes directly to
/// the decoy child this injector spawned and owns.
#[cfg(unix)]
fn nix_kill_sig9(pid: i32) -> Result<(), InjectError> {
    // SAFETY: `pid` is the id of a Child this function's caller just spawned.
    // The caller reaps that Child on every exit path. kill(2) errors are
    // returned, never panicked. A recycled pid would have to appear before
    // the reap; the signal is still only SIGKILL of that numeric id.
    let rc = unsafe { libc::kill(pid, libc::SIGKILL) };
    if rc == 0 {
        Ok(())
    } else {
        Err(InjectError::Io(io::Error::last_os_error()))
    }
}

// ---------------------------------------------------------------------------
// Factory Dispatcher
// ---------------------------------------------------------------------------

/// Chaos parameters carried by an [`ExecutionPlan`] that the injector factory
/// needs. Mirrors the plan's chaos fields so [`create_injector_from_plan`] can
/// build a spec without depending on the plan type's interior layout.
#[derive(Debug, Clone)]
struct ChaosParams {
    iface: String,
    target_cidr: String,
    latency_ms: u32,
    jitter_ms: u32,
    loss_pct: u8,
    duration_ms: u32,
    dns_port: u16,
    recovery_window_ms: u32,
}

impl ChaosParams {
    fn from_plan(plan: &asmodeus_dsl::ExecutionPlan) -> Self {
        ChaosParams {
            iface: plan.iface.clone(),
            target_cidr: plan.target_cidr.clone(),
            latency_ms: plan.latency_ms,
            jitter_ms: plan.jitter_ms,
            loss_pct: plan.loss_percent,
            duration_ms: plan.duration_ms,
            dns_port: plan.dns_port,
            recovery_window_ms: plan.recovery_window_ms,
        }
    }

    /// Turn these manifest-derived parameters into a validated net-chaos rule.
    /// `sinkhole` selects the DNS RPZ outage shape (FTT §4.2.3): a full drop
    /// of the test CIDR, allowed to claim 100 % loss, versus the probabilistic
    /// latency perturbation of `LATENCY_SPIKE_VM` (FTT §4.2.1). `dns_port` is
    /// copied onto the spec and is not a datapath match. Every field comes
    /// from the signed plan, never hardcoded.
    fn to_net_spec(&self, sinkhole: bool) -> NetChaosSpec {
        let base = if sinkhole {
            NetChaosSpec::dns_sinkhole_demo()
        } else {
            NetChaosSpec::latency_spike_demo()
        };
        NetChaosSpec {
            iface: self.iface.clone(),
            target_cidr: self.target_cidr.clone(),
            latency_ms: self.latency_ms,
            jitter_ms: self.jitter_ms,
            loss_pct: self.loss_pct,
            duration_ms: self.duration_ms.max(1),
            dns_sinkhole: sinkhole,
            dns_port: self.dns_port,
        }
        .with_validated_defaults(&base)
    }
}

impl NetChaosSpec {
    /// Backfill any field a manifest omitted with the demo-shaped default
    /// (`duration_ms == 0` would otherwise trip the budget gate) before the
    /// caller validates through `NetChaosSession::start`.
    fn with_validated_defaults(mut self, defaults: &NetChaosSpec) -> Self {
        if self.duration_ms == 0 {
            self.duration_ms = defaults.duration_ms;
        }
        if self.dns_port == 0 {
            self.dns_port = defaults.dns_port;
        }
        self
    }
}

/// Create the appropriate synthetic scenario injector for a compiled execution
/// plan. This is the canonical dispatch path: every chaos parameter (interface,
/// CIDR, latency/jitter/loss, DNS port, recovery window, duration) flows from
/// the signed manifest through [`asmodeus_dsl::ExecutionPlan`] into the
/// injector, so an operator tuning `spec.action.parameters` changes behaviour
/// instead of silently hitting hardcoded values.
pub fn create_injector_from_plan(
    plan: &asmodeus_dsl::ExecutionPlan,
    target_dir: &str,
) -> Result<Box<dyn ScenarioInjector>, InjectError> {
    use asmodeus_dsl::Action;
    let params = ChaosParams::from_plan(plan);
    match plan.action {
        Action::SyntheticCanaryEncrypt => {
            let inj = CanaryInjector::new(
                target_dir,
                plan.file_count as usize,
                plan.chunk_size_kb as usize,
            )?;
            Ok(Box::new(inj))
        }
        Action::K8sEscapeProbe => Ok(Box::new(K8sEscapeInjector::new(target_dir)?)),
        Action::C2Beacon => Ok(Box::new(C2BeaconInjector::new(
            target_dir,
            plan.file_count as usize,
        )?)),
        Action::CredentialCanary => Ok(Box::new(CredentialAccessInjector::new(target_dir)?)),
        Action::LogTamperCanary => Ok(Box::new(LogTamperInjector::new(target_dir)?)),
        Action::PersistenceCanary => Ok(Box::new(PersistenceCronInjector::new(target_dir)?)),
        Action::ExfiltrationCanary => Ok(Box::new(DataExfiltrationInjector::new(
            target_dir,
            plan.chunk_size_kb as usize,
        )?)),
        Action::WatchdogProbe => Ok(Box::new(DefenseImpairmentInjector::new(target_dir)?)),
        Action::AgentCrashProbe => {
            // The watchdog window flows from the signed plan (FTT §4.2.2),
            // never from a hardcoded runner constant.
            create_agent_crash_probe(target_dir, params.recovery_window_ms)
        }
        Action::LatencySpike => {
            let spec = params.to_net_spec(false);
            Ok(Box::new(NetChaosInjector::new(target_dir, spec)?))
        }
        Action::DnsSinkholeDrop => {
            let spec = params.to_net_spec(true);
            Ok(Box::new(NetChaosInjector::new(target_dir, spec)?))
        }
    }
}

/// Build the agent-crash probe injector, falling back to the benign watchdog
/// pulse marker where a real SIGKILL cannot be exercised (non-Unix hosts), so
/// the scenario still produces an observable footprint without violating INV-0.
fn create_agent_crash_probe(
    target_dir: &str,
    recovery_window_ms: u32,
) -> Result<Box<dyn ScenarioInjector>, InjectError> {
    #[cfg(unix)]
    {
        Ok(Box::new(AgentCrashProbeInjector::new(
            target_dir,
            recovery_window_ms,
        )?))
    }
    #[cfg(not(unix))]
    {
        let _ = recovery_window_ms;
        Ok(Box::new(DefenseImpairmentInjector::new(target_dir)?))
    }
}

/// Create the appropriate synthetic scenario injector based on `scenario_id`,
/// using each scenario's pinned FTT defaults. Prefer
/// [`create_injector_from_plan`] on the gRPC path, which honours the signed
/// manifest's parameter overrides; this convenience wrapper exists for the
/// standalone demo/local paths that have no compiled plan.
pub fn create_injector(
    scenario_id: &str,
    target_dir: &str,
    file_count: usize,
    chunk_size_kb: usize,
) -> Result<Box<dyn ScenarioInjector>, InjectError> {
    let plan = asmodeus_dsl::execution_plan_for_preset(
        scenario_id,
        target_dir,
        file_count as u32,
        chunk_size_kb as u32,
    )
    .ok_or_else(|| {
        InjectError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported scenario/action",
        ))
    })?;
    create_injector_from_plan(&plan, target_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asmodeus_testkit::Polygon;

    #[test]
    fn all_scenarios_inject_and_clean_up() {
        // `mut` is used by the cfg'd push below; under `ebpf` that push is
        // compiled out, so the binding would look unused.
        #[allow(unused_mut)]
        let mut scenario_ids = vec![
            "RANSOMWARE_CANARY_SPIKE",
            "K8S_ESCAPE_SIMULATION",
            "C2_BEACONING_SIMULATION",
            "CREDENTIAL_ACCESS_CANARY",
            "LOG_TAMPER_CANARY",
            "PERSISTENCE_CRON_CANARY",
            "DATA_EXFILTRATION_CANARY",
            "DEFENSE_IMPAIRMENT_CANARY",
            "AGENT_CRASH_ENDPOINT",
        ];
        // LATENCY_SPIKE_VM and DNS_RPZ_SINKHOLE_DROP drive the platform
        // net-chaos backend. On the default build that is the in-process
        // SimBackend, which injects synthetically and satisfies the assertions
        // below. Under `--features ebpf` it is the real aya/TC backend, which
        // needs a compiled BPF object and CAP_BPF on a Linux stand — exercised
        // there, not in this unit test.
        #[cfg(not(feature = "ebpf"))]
        scenario_ids.extend(["LATENCY_SPIKE_VM", "DNS_RPZ_SINKHOLE_DROP"]);

        for id in scenario_ids {
            let poly = Polygon::new(&format!("inj-{id}"));
            let injector =
                create_injector(id, &poly.path(), 5, 2).expect("valid injector creation");
            let rep = injector.inject().expect("inject must succeed");
            assert!(rep.files_created > 0, "{id} should create files");
            assert!(rep.bytes_written > 0, "{id} should write bytes");

            injector.cleanup().expect("cleanup must succeed");
            // Verify no leftover files in directory
            if poly.dir().exists() {
                assert_eq!(
                    fs::read_dir(poly.dir()).unwrap().count(),
                    0,
                    "{id} left residue after cleanup"
                );
            }
        }
    }

    #[test]
    fn out_of_scope_target_is_rejected() {
        assert!(create_injector("K8S_ESCAPE_SIMULATION", "/etc/asmodeus", 1, 1).is_err());
        assert!(create_injector("C2_BEACONING_SIMULATION", "/var/log/sensitive", 1, 1).is_err());
    }
}
