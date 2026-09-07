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
    /// Unconditionally revert and remove all synthetic traces.
    fn cleanup(&self) -> Result<(), InjectError>;
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
            let _ = fs::remove_file(self.dir.join("docker.sock.probe"));
            let _ = fs::remove_file(self.dir.join("k8s_ns_escape.canary"));
            let _ = fs::remove_dir_all(&self.dir);
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
            let _ = fs::remove_file(self.dir.join("c2_beacon_events.log"));
            let _ = fs::remove_dir_all(&self.dir);
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
            let _ = fs::remove_file(self.dir.join("honeytoken_credentials.json"));
            let _ = fs::remove_dir_all(&self.dir);
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
            let _ = fs::remove_file(self.dir.join("canary_audit.log"));
            let _ = fs::remove_dir_all(&self.dir);
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
            let _ = fs::remove_file(self.dir.join("canary_cron_task.job"));
            let _ = fs::remove_dir_all(&self.dir);
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

        let dummy_chunk = vec![0xEE; self.chunk_kb * 1024];
        fs::write(&exfil_file, &dummy_chunk)?;

        Ok(Report {
            files_created: 1,
            bytes_written: dummy_chunk.len() as u64,
        })
    }

    fn cleanup(&self) -> Result<(), InjectError> {
        if self.dir.exists() {
            let _ = fs::remove_file(self.dir.join("staged_canary_data.tar.gz"));
            let _ = fs::remove_dir_all(&self.dir);
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
            let _ = fs::remove_file(self.dir.join("watchdog_recovery.pulse"));
            let _ = fs::remove_dir_all(&self.dir);
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
            .map_err(|e| InjectError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;

        let token = session.handle().map(|h| h.token).unwrap_or_default();
        fs::write(&session_marker, format!("token={token}").as_bytes())?;

        Ok(Report {
            files_created: 1,
            bytes_written: 16,
        })
    }

    fn cleanup(&self) -> Result<(), InjectError> {
        if self.dir.exists() {
            let _ = fs::remove_file(self.dir.join("netchaos_session.token"));
            let _ = fs::remove_dir_all(&self.dir);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Factory Dispatcher
// ---------------------------------------------------------------------------

/// Create the appropriate synthetic scenario injector based on `scenario_id`.
pub fn create_injector(
    scenario_id: &str,
    target_dir: &str,
    file_count: usize,
    chunk_size_kb: usize,
) -> Result<Box<dyn ScenarioInjector>, InjectError> {
    match scenario_id {
        "RANSOMWARE_CANARY_SPIKE" => {
            let inj = CanaryInjector::new(target_dir, file_count, chunk_size_kb)?;
            Ok(Box::new(inj))
        }
        "K8S_ESCAPE_SIMULATION" => {
            let inj = K8sEscapeInjector::new(target_dir)?;
            Ok(Box::new(inj))
        }
        "C2_BEACONING_SIMULATION" => {
            let inj = C2BeaconInjector::new(target_dir, file_count)?;
            Ok(Box::new(inj))
        }
        "CREDENTIAL_ACCESS_CANARY" => {
            let inj = CredentialAccessInjector::new(target_dir)?;
            Ok(Box::new(inj))
        }
        "LOG_TAMPER_CANARY" => {
            let inj = LogTamperInjector::new(target_dir)?;
            Ok(Box::new(inj))
        }
        "PERSISTENCE_CRON_CANARY" => {
            let inj = PersistenceCronInjector::new(target_dir)?;
            Ok(Box::new(inj))
        }
        "DATA_EXFILTRATION_CANARY" => {
            let inj = DataExfiltrationInjector::new(target_dir, chunk_size_kb)?;
            Ok(Box::new(inj))
        }
        "DEFENSE_IMPAIRMENT_CANARY" => {
            let inj = DefenseImpairmentInjector::new(target_dir)?;
            Ok(Box::new(inj))
        }
        "LATENCY_SPIKE_VM" => {
            let spec = NetChaosSpec::latency_spike_demo();
            let inj = NetChaosInjector::new(target_dir, spec)?;
            Ok(Box::new(inj))
        }
        "AGENT_CRASH_ENDPOINT" => {
            let inj = DefenseImpairmentInjector::new(target_dir)?;
            Ok(Box::new(inj))
        }
        "DNS_RPZ_SINKHOLE_DROP" => {
            let spec = NetChaosSpec {
                iface: "lo".into(),
                target_cidr: "127.0.0.1/32".into(),
                latency_ms: 100,
                jitter_ms: 20,
                loss_pct: 50,
                duration_ms: 5000,
            };
            let inj = NetChaosInjector::new(target_dir, spec)?;
            Ok(Box::new(inj))
        }
        _ => {
            // Safe fallback: standard canary injector
            let inj = CanaryInjector::new(target_dir, file_count, chunk_size_kb)?;
            Ok(Box::new(inj))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asmodeus_testkit::Polygon;

    #[test]
    fn all_scenarios_inject_and_clean_up() {
        let scenario_ids = [
            "RANSOMWARE_CANARY_SPIKE",
            "K8S_ESCAPE_SIMULATION",
            "C2_BEACONING_SIMULATION",
            "CREDENTIAL_ACCESS_CANARY",
            "LOG_TAMPER_CANARY",
            "PERSISTENCE_CRON_CANARY",
            "DATA_EXFILTRATION_CANARY",
            "DEFENSE_IMPAIRMENT_CANARY",
            "LATENCY_SPIKE_VM",
            "AGENT_CRASH_ENDPOINT",
            "DNS_RPZ_SINKHOLE_DROP",
        ];

        for id in scenario_ids {
            let poly = Polygon::new(&format!("inj-{id}"));
            let injector = create_injector(id, &poly.path(), 5, 2).expect("valid injector creation");
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
