//! Signed scenario catalog. The REST API accepts only a `scenario_id` (D6);
//! the manifest, its Ed25519 signature and the trusted public key live here.
//!
//! For the MVP the catalog is self-signed at startup with a freshly generated
//! keypair so the whole verify path exercises real crypto. In production the
//! public key is configured and the private key belongs to the Red Team Lead.

use std::collections::HashMap;

use asmodeus_common::{ActionNature, Category};
use asmodeus_dsl::mitre::*;
use asmodeus_dsl::MitreTechnique;
use ed25519_compact::KeyPair;

/// One entry in the catalog.
#[derive(Debug, Clone)]
pub struct ScenarioEntry {
    pub id: &'static str,
    pub name: &'static str,
    pub category: Category,
    pub nature: ActionNature,
    pub target_path: String,
    pub detector: &'static str,
    pub mitre: Option<MitreTechnique>,
    pub severity: &'static str,
    pub description: &'static str,
    pub manifest: Vec<u8>,
    pub signature: Vec<u8>,
    /// Synthetic, deterministic measurements for the MVP (real runs measure).
    pub sim_mttd_ms: u64,
    pub sim_mttr_ms: u64,
    /// Injection parameters passed to the runner over gRPC.
    pub file_count: u32,
    pub chunk_size_kb: u32,
}

/// The scenario catalog plus the trusted signing public key.
pub struct Catalog {
    entries: HashMap<String, ScenarioEntry>,
    public_key: Vec<u8>,
    secret_key: Option<Vec<u8>>,
}

impl Catalog {
    /// Look up an entry by scenario id.
    pub fn get(&self, id: &str) -> Option<&ScenarioEntry> {
        self.entries.get(id)
    }

    /// The public key every entry's signature must verify against.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The private signing key if available in this node.
    pub fn secret_key(&self) -> Option<&[u8]> {
        self.secret_key.as_deref()
    }

    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    pub fn entries(&self) -> impl Iterator<Item = &ScenarioEntry> {
        self.entries.values()
    }

    /// Seed the canonical MITRE ATT&CK and Chaos scenarios, self-signed.
    pub fn seeded() -> Self {
        let kp = KeyPair::generate();
        let mut entries = HashMap::new();

        let mut add = |id: &'static str,
                       name: &'static str,
                       category: Category,
                       nature: ActionNature,
                       target_path: &str,
                       detector: &'static str,
                       mitre: Option<MitreTechnique>,
                       severity: &'static str,
                       description: &'static str,
                       mttd: u64,
                       mttr: u64| {
            let (tech_line, tactic_line) = match mitre {
                Some(m) => (
                    format!("mitre_technique: \"{}\"\n", m.id),
                    format!("mitre_tactic: \"{}\"\n", m.tactic),
                ),
                None => (String::new(), String::new()),
            };
            let manifest = format!(
                "apiVersion: asmodeus.io/v1alpha1\n\
                 kind: AttackScenario\n\
                 metadata:\n  \
                   id: {id}\n  \
                   name: \"{name}\"\n  \
                   category: \"{}\"\n  \
                   severity: \"{severity}\"\n  \
                   {tech_line}\
                   {tactic_line}\
                 spec:\n  \
                   detector: \"{detector}\"\n",
                category.tag()
            )
            .into_bytes();
            let signature = kp.sk.sign(&manifest, None).as_ref().to_vec();
            entries.insert(
                id.to_string(),
                ScenarioEntry {
                    id,
                    name,
                    category,
                    nature,
                    target_path: target_path.to_string(),
                    detector,
                    mitre,
                    severity,
                    description,
                    manifest,
                    signature,
                    sim_mttd_ms: mttd,
                    sim_mttr_ms: mttr,
                    file_count: 20,
                    chunk_size_kb: 64,
                },
            );
        };

        // --- 1. MITRE ATT&CK: T1486 (Data Encrypted for Impact) ---
        add(
            "RANSOMWARE_CANARY_SPIKE",
            "Ransomware Canary Encryption Spike",
            Category::RedTeam,
            ActionNature::Synthetic,
            "/tmp/asmodeus-canary/",
            "ferrum_ebpf_kernel_probe",
            Some(T1486_DATA_ENCRYPTED_FOR_IMPACT),
            "high",
            "Mass file encryption spike with reversible XOR on synthetic canary docs",
            142,
            280,
        );

        // --- 2. MITRE ATT&CK: T1611 (Escape to Host) / T1059 ---
        add(
            "K8S_ESCAPE_SIMULATION",
            "K8s Container Escape Simulation",
            Category::RedTeam,
            ActionNature::Synthetic,
            "/tmp/asmodeus-canary/",
            "ferrum_admission_controller",
            Some(T1611_ESCAPE_TO_HOST),
            "critical",
            "Container escape probe targeting simulated hostPath and container sockets",
            95,
            210,
        );

        // --- 3. MITRE ATT&CK: T1071 (Application Layer Protocol) / T1568 ---
        add(
            "C2_BEACONING_SIMULATION",
            "C2 Beaconing & Dynamic Resolution Simulation",
            Category::RedTeam,
            ActionNature::Synthetic,
            "/tmp/asmodeus-canary/",
            "bsdm_proxy_dns_sinkhole",
            Some(T1071_APPLICATION_LAYER_PROTOCOL),
            "high",
            "Periodic synthetic HTTP/DNS beaconing with jitter to test domains",
            110,
            230,
        );

        // --- 4. MITRE ATT&CK: T1003 (OS Credential Dumping) ---
        add(
            "CREDENTIAL_ACCESS_CANARY",
            "Credential Access Honeytoken Canary",
            Category::RedTeam,
            ActionNature::Synthetic,
            "/tmp/asmodeus-canary/",
            "lariska_honeytoken_sentinel",
            Some(T1003_OS_CREDENTIAL_DUMPING),
            "high",
            "Decoy honeytoken credentials access probe within canary scope",
            85,
            170,
        );

        // --- 5. MITRE ATT&CK: T1070 (Indicator Removal on Host) ---
        add(
            "LOG_TAMPER_CANARY",
            "Indicator Removal & Log Tamper Canary",
            Category::RedTeam,
            ActionNature::Synthetic,
            "/tmp/asmodeus-canary/",
            "ferrum_audit_log_watcher",
            Some(T1070_INDICATOR_REMOVAL),
            "medium",
            "Synthetic log truncation and indicator deletion in canary directory",
            75,
            160,
        );

        // --- 6. MITRE ATT&CK: T1053 (Scheduled Task/Job: Cron) ---
        add(
            "PERSISTENCE_CRON_CANARY",
            "Persistence Scheduled Task Canary",
            Category::RedTeam,
            ActionNature::Synthetic,
            "/tmp/asmodeus-canary/",
            "lariska_persistence_guard",
            Some(T1053_SCHEDULED_TASK_JOB),
            "medium",
            "Decoy scheduled task installation in synthetic canary directory",
            120,
            250,
        );

        // --- 7. MITRE ATT&CK: T1041 (Exfiltration Over C2 Channel) ---
        add(
            "DATA_EXFILTRATION_CANARY",
            "Data Exfiltration Over C2 Canary",
            Category::RedTeam,
            ActionNature::Synthetic,
            "/tmp/asmodeus-canary/",
            "bsdm_proxy_swg_monitor",
            Some(T1041_EXFILTRATION_OVER_C2),
            "high",
            "Synthetic staged data exfiltration probe via loopback test channel",
            130,
            290,
        );

        // --- 8. MITRE ATT&CK: T1562 (Impair Defenses: Disable Tools) ---
        add(
            "DEFENSE_IMPAIRMENT_CANARY",
            "Defense Impairment & Tool Disable Canary",
            Category::RedTeam,
            ActionNature::Synthetic,
            "/tmp/asmodeus-canary/",
            "lariska_watchdog",
            Some(T1562_IMPAIR_DEFENSES),
            "high",
            "Benign signal interruption probe testing endpoint agent watchdog",
            50,
            140,
        );

        // --- 9. Infrastructure Chaos: Network Latency (FTT §4.2.1) ---
        add(
            "LATENCY_SPIKE_VM",
            "Scanner Drift & Network Latency Chaos",
            Category::Chaos,
            ActionNature::Synthetic,
            "/tmp/asmodeus-canary/",
            "apex_gateway_failover",
            None,
            "high",
            "Synthetic network latency and packet loss on test RFC 5737 / loopback segment",
            60,
            180,
        );

        // --- 10. Infrastructure Chaos / MITRE T1562: Agent Crash (FTT §4.2.2) ---
        add(
            "AGENT_CRASH_ENDPOINT",
            "Endpoint Agent Crash Chaos",
            Category::Chaos,
            ActionNature::Synthetic,
            "/tmp/asmodeus-canary/",
            "lariska_watchdog",
            Some(T1562_IMPAIR_DEFENSES),
            "critical",
            "Unscheduled agent termination test to verify 5s recovery window",
            40,
            120,
        );

        // --- 11. Infrastructure Chaos: DNS RPZ Outage (FTT §4.2.3) ---
        add(
            "DNS_RPZ_SINKHOLE_DROP",
            "DNS RPZ Resolver Outage Chaos",
            Category::Chaos,
            ActionNature::Synthetic,
            "/tmp/asmodeus-canary/",
            "bsdm_proxy_failover",
            None,
            "high",
            "Primary DNS RPZ sinkhole outage simulation to verify DoH fail-closed",
            45,
            130,
        );

        Catalog {
            entries,
            public_key: kp.pk.as_ref().to_vec(),
            secret_key: Some(kp.sk.as_ref().to_vec()),
        }
    }
}
