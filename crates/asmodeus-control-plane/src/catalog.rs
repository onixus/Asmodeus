//! Signed scenario catalog. The REST API accepts only a `scenario_id` (D6);
//! the manifest, its Ed25519 signature and the trusted public key live here.
//!
//! For the MVP the catalog is self-signed at startup with a freshly generated
//! keypair so the whole verify path exercises real crypto. In production the
//! public key is configured and the private key belongs to the Red Team Lead.

use std::collections::HashMap;

use asmodeus_common::{ActionNature, Category};
use asmodeus_dsl::fidelity::{Fidelity, TechniqueRef};
use asmodeus_dsl::mitre::*;
use asmodeus_dsl::MitreTechnique;
use ed25519_compact::KeyPair;

use crate::scenario_profile::{profile_for, ScenarioProfile};

/// One entry in the catalog.
#[derive(Debug, Clone)]
pub struct ScenarioEntry {
    pub id: String,
    pub name: String,
    pub category: Category,
    pub target_path: String,
    pub detector: String,
    /// Primary technique, kept as the single-technique projection for the
    /// stable wire JSON / ClickHouse sort key / signed audit preimage.
    pub mitre: Option<MitreTechnique>,
    /// S01: fidelity at which this scenario exercises its technique(s).
    pub fidelity: Fidelity,
    /// S01: full technique mapping (multi-technique), primary first. Each ref
    /// carries the fidelity, so a marker-only scenario can never be read as
    /// behavioural/prevention coverage of its technique.
    pub technique_refs: Vec<TechniqueRef>,
    /// S01: pinned procedure profile (built-in scenarios only).
    pub profile: Option<ScenarioProfile>,
    pub severity: String,
    pub description: String,
    pub manifest: Vec<u8>,
    pub signature: Vec<u8>,
    /// Synthetic, deterministic measurements for the MVP (real runs measure).
    pub sim_mttd_ms: u64,
    pub sim_mttr_ms: u64,
}

impl ScenarioEntry {
    /// True iff this scenario may contribute to **behavioural** coverage of its
    /// technique(s). Marker-only / undeclared scenarios never do.
    pub fn claims_behavioral_coverage(&self) -> bool {
        if self.technique_refs.is_empty() {
            self.fidelity.claims_behavioral()
        } else {
            self.technique_refs
                .iter()
                .any(|r| r.fidelity.claims_behavioral())
        }
    }
}

/// The scenario catalog plus the trusted signing public key.
pub struct Catalog {
    entries: HashMap<String, ScenarioEntry>,
    public_key: Vec<u8>,
    secret_key: Option<Vec<u8>>,
}

impl Catalog {
    pub fn from_env() -> std::io::Result<Self> {
        let mut catalog = Self::seeded();
        if let Ok(path) = std::env::var("ASMODEUS_SCENARIO_SIGNING_KEY") {
            let key = asmodeus_crypto::read_hex_key::<64>(std::path::Path::new(&path))?;
            let public =
                asmodeus_crypto::public_key_from_secret_key(&key).map_err(std::io::Error::other)?;
            for entry in catalog.entries.values_mut() {
                entry.signature = asmodeus_crypto::sign_message(&entry.manifest, &key)
                    .map_err(std::io::Error::other)?
                    .to_vec();
                if !asmodeus_crypto::is_valid(&entry.manifest, &entry.signature, &public) {
                    return Err(std::io::Error::other("inconsistent scenario signing key"));
                }
            }
            catalog.public_key = public.to_vec();
            catalog.secret_key = Some(key.to_vec());
        } else if std::env::var("ASMODEUS_RUNNER_ENDPOINT").is_ok() {
            return Err(std::io::Error::other(
                "ASMODEUS_SCENARIO_SIGNING_KEY is required for a configured runner",
            ));
        }
        if let Ok(dir) = std::env::var("ASMODEUS_SCENARIOS_DIR") {
            if !std::path::Path::new(&dir).is_dir() {
                return Err(std::io::Error::other(
                    "ASMODEUS_SCENARIOS_DIR must be an existing directory",
                ));
            }
            catalog
                .load_from_dir(std::path::Path::new(&dir))
                .map_err(std::io::Error::other)?;
        }
        Ok(catalog)
    }

    /// Look up an entry by scenario id.
    pub fn get(&self, id: &str) -> Option<&ScenarioEntry> {
        self.entries.get(id)
    }

    /// The public key every entry's signature must verify against.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    pub fn entries(&self) -> impl Iterator<Item = &ScenarioEntry> {
        self.entries.values()
    }

    /// Load external signed scenario manifests from a directory.
    ///
    /// Scans for .yaml, .yml, and .json files, parses and validates each against INV-0,
    /// and registers them in the catalog. Returns number of scenarios loaded.
    pub fn load_from_dir(&mut self, dir: &std::path::Path) -> Result<usize, String> {
        if !dir.is_dir() {
            return Ok(0);
        }
        let read_dir = std::fs::read_dir(dir).map_err(|e| e.to_string())?;
        let mut count = 0;
        for entry in read_dir {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !["yaml", "yml", "json"].contains(&ext.to_ascii_lowercase().as_str()) {
                continue;
            }
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let manifest = match asmodeus_dsl::manifest::parse_and_validate_manifest(&content) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(path = ?path, error = %e, "skipping invalid scenario manifest");
                    continue;
                }
            };

            let plan =
                asmodeus_dsl::ExecutionPlan::from_manifest(&manifest).map_err(|e| e.to_string())?;
            let mitre = manifest.primary_technique();

            // S01: fidelity and the full technique mapping come from the
            // manifest. A legacy (v1alpha1) manifest yields `Unspecified` refs
            // regardless of what it declares, so external scenarios are never
            // promoted to behavioural coverage without an explicit v1alpha2
            // declaration. External manifests carry no pinned procedure profile.
            let fidelity = manifest.effective_fidelity();
            let technique_refs = manifest.resolved_technique_refs();

            let raw_bytes = content.into_bytes();
            let signature = if let Some(ref sk) = self.secret_key {
                if let Ok(sk_compact) = ed25519_compact::SecretKey::from_slice(sk) {
                    sk_compact.sign(&raw_bytes, None).as_ref().to_vec()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            let entry = ScenarioEntry {
                id: manifest.metadata.id.clone(),
                name: manifest.metadata.name,
                category: manifest.metadata.category,
                target_path: plan.target_dir,
                detector: manifest.spec.expected_outcome.detector,
                mitre,
                fidelity,
                technique_refs,
                profile: None,
                severity: manifest.metadata.severity,
                description: manifest.metadata.description.unwrap_or_default(),
                manifest: raw_bytes,
                signature,
                sim_mttd_ms: manifest
                    .spec
                    .expected_outcome
                    .expected_mttd_max_ms
                    .unwrap_or(60),
                sim_mttr_ms: 150,
            };
            self.entries.insert(manifest.metadata.id, entry);
            count += 1;
        }
        Ok(count)
    }

    /// Seed the canonical MITRE ATT&CK and Chaos scenarios, self-signed.
    pub fn seeded() -> Self {
        let kp = KeyPair::generate();
        let mut entries = HashMap::new();

        let mut add = |id: &str,
                       name: &str,
                       category: Category,
                       _nature: ActionNature,
                       target_path: &str,
                       detector: &str,
                       mitre: Option<MitreTechnique>,
                       severity: &str,
                       description: &str,
                       mttd: u64,
                       mttr: u64| {
            let mut typed = asmodeus_dsl::synthetic_manifest(id, target_path, 20, 64);
            typed.metadata.name = name.into();
            typed.metadata.category = category;
            typed.metadata.mitre_technique = mitre.map(|m| m.id.into());
            typed.metadata.mitre_tactic = mitre.map(|m| m.tactic.into());
            typed.metadata.severity = severity.into();
            typed.metadata.description = Some(description.into());
            typed.spec.expected_outcome.detector = detector.into();
            typed.spec.expected_outcome.expected_mttd_max_ms = Some(mttd);
            let manifest = serde_json::to_vec(&typed).expect("built-in manifest");
            let signature = kp.sk.sign(&manifest, None).as_ref().to_vec();

            // S01 fidelity profile: every built-in scenario has a pinned
            // profile (checked by `all_builtins_have_a_profile`). Technique refs
            // come from the profile, not from `mitre` — so a marker-only
            // scenario carries marker-only refs even though it still projects a
            // primary `mitre` technique for the stable wire/audit contract.
            let profile_def = profile_for(id);
            let (fidelity, technique_refs, profile) = match profile_def {
                Some(def) => (def.fidelity, def.technique_refs(), Some(def.to_profile())),
                None => (Fidelity::Unspecified, Vec::new(), None),
            };

            entries.insert(
                id.to_string(),
                ScenarioEntry {
                    id: id.to_string(),
                    name: name.to_string(),
                    category,
                    target_path: target_path.to_string(),
                    detector: detector.to_string(),
                    mitre,
                    fidelity,
                    technique_refs,
                    profile,
                    severity: severity.to_string(),
                    description: description.to_string(),
                    manifest,
                    signature,
                    sim_mttd_ms: mttd,
                    sim_mttr_ms: mttr,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_from_dir() {
        let mut cat = Catalog::seeded();
        let initial_count = cat.entries().count();

        let temp_dir =
            std::env::temp_dir().join(format!("asmodeus-scenarios-{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let valid_yaml = r#"apiVersion: asmodeus.io/v1alpha1
kind: AttackScenario
metadata:
  id: "DYN-SCN-001"
  name: "Dynamic Loaded Canary"
  category: "red_team"
  severity: "medium"
  mitre_technique: "T1053"
spec:
  author: "Red Team Lead"
  target_scope:
    type: "k8s_workload"
    target_path: "/tmp/asmodeus-canary/test.txt"
  safety:
    max_duration_sec: 30
    cpu_limit_percent: 10
    canary_directory_only: "/tmp/asmodeus-canary"
    circuit_breaker_on_host_unresponsive: true
  action:
    nature: "synthetic"
    type: "synthetic_canary_encrypt"
    parameters:
      file_count: 10
      chunk_size_kb: 4
  expected_outcome:
    detector: "dynamic_detector"
    expected_mttd_max_ms: 100
    expected_containment: "sigkill"
"#;
        std::fs::write(temp_dir.join("dyn_scenario.yaml"), valid_yaml).unwrap();

        let loaded = cat.load_from_dir(&temp_dir).unwrap();
        assert_eq!(loaded, 1);
        assert_eq!(cat.entries().count(), initial_count + 1);

        let entry = cat.get("DYN-SCN-001").expect("dyn scenario");
        assert_eq!(entry.name, "Dynamic Loaded Canary");
        assert_eq!(entry.detector, "dynamic_detector");
        assert_eq!(entry.mitre.as_ref().unwrap().id, "T1053");
        // S01: a legacy (v1alpha1) external manifest is read but never promoted.
        assert_eq!(entry.fidelity, Fidelity::Unspecified);
        assert!(!entry.claims_behavioral_coverage());

        // Parsing alone must never authorize or sign an unsafe manifest.
        for (name, content) in [
            (
                "operational",
                valid_yaml.replace("synthetic\"", "operational\""),
            ),
            (
                "scope",
                valid_yaml.replace("/tmp/asmodeus-canary/test.txt", "/etc/passwd"),
            ),
            (
                "budget",
                valid_yaml.replace("file_count: 10", "file_count: 999999"),
            ),
        ] {
            std::fs::write(temp_dir.join("dyn_scenario.yaml"), content).unwrap();
            assert_eq!(cat.load_from_dir(&temp_dir).unwrap(), 0, "{name}");
            assert_eq!(
                asmodeus_dsl::parse_and_validate_manifest(
                    std::str::from_utf8(&cat.get("DYN-SCN-001").unwrap().manifest).unwrap()
                )
                .unwrap()
                .spec
                .action
                .nature,
                ActionNature::Synthetic
            );
        }

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    // ---- S01: fidelity model wiring ----

    #[test]
    fn every_builtin_scenario_has_a_profile_and_declared_fidelity() {
        let cat = Catalog::seeded();
        for entry in cat.entries() {
            assert!(
                entry.profile.is_some(),
                "built-in {} is missing an S01 profile",
                entry.id
            );
            // No built-in is left at Unspecified — each is explicitly classified.
            assert_ne!(
                entry.fidelity,
                Fidelity::Unspecified,
                "built-in {} has undeclared fidelity",
                entry.id
            );
        }
    }

    #[test]
    fn catalog_primary_ref_matches_mitre_projection() {
        // Semantic parity: the primary technique ref must equal the single
        // `mitre` projection used by the wire JSON / signed audit.
        let cat = Catalog::seeded();
        for entry in cat.entries() {
            match entry.mitre {
                Some(m) => {
                    assert_eq!(
                        entry
                            .technique_refs
                            .first()
                            .map(|r| r.technique_id.as_str()),
                        Some(m.id),
                        "{}: primary ref != mitre projection",
                        entry.id
                    );
                }
                None => assert!(
                    entry.technique_refs.is_empty(),
                    "{}: has refs but no mitre projection",
                    entry.id
                ),
            }
        }
    }

    #[test]
    fn marker_only_builtins_never_claim_behavioral_coverage() {
        let cat = Catalog::seeded();
        for id in [
            "K8S_ESCAPE_SIMULATION",
            "CREDENTIAL_ACCESS_CANARY",
            "C2_BEACONING_SIMULATION",
            "LOG_TAMPER_CANARY",
            "PERSISTENCE_CRON_CANARY",
            "DATA_EXFILTRATION_CANARY",
            "DEFENSE_IMPAIRMENT_CANARY",
        ] {
            let e = cat.get(id).unwrap();
            assert_eq!(e.fidelity, Fidelity::MarkerOnly, "{id}");
            assert!(!e.claims_behavioral_coverage(), "{id}");
            for r in &e.technique_refs {
                assert!(!r.fidelity.claims_behavioral(), "{id}:{}", r.technique_id);
            }
        }
    }

    #[test]
    fn every_catalog_technique_id_is_known_to_the_taxonomy() {
        // CI gate: a stale/mistyped technique anywhere in the catalog fails here.
        let cat = Catalog::seeded();
        for entry in cat.entries() {
            if let Some(m) = entry.mitre {
                assert!(asmodeus_dsl::is_known_id(m.id), "{}: {}", entry.id, m.id);
            }
            for r in &entry.technique_refs {
                assert!(
                    asmodeus_dsl::is_known_id(&r.technique_id),
                    "{}: {}",
                    entry.id,
                    r.technique_id
                );
            }
        }
    }

    #[test]
    fn v1alpha2_external_manifest_honours_behavioral_fidelity() {
        let mut cat = Catalog::seeded();
        let dir = std::env::temp_dir().join(format!("asmo-v2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let json = r#"{
            "apiVersion": "asmodeus.io/v1alpha2",
            "kind": "AttackScenario",
            "metadata": {
                "id": "DYN-V2-001", "name": "V2 Behavioral", "category": "red_team",
                "fidelity": "behavioral", "severity": "high",
                "mitre_techniques": [{"technique_id": "T1486", "fidelity": "behavioral"}]
            },
            "spec": {
                "target_scope": {"type": "fs", "target_path": "/tmp/asmodeus-canary/x"},
                "safety": {"max_duration_sec": 30, "cpu_limit_percent": 10},
                "action": {"nature": "synthetic", "type": "synthetic_canary_encrypt",
                           "parameters": {"file_count": 10, "chunk_size_kb": 4}},
                "expected_outcome": {"detector": "ferrum"}
            }
        }"#;
        std::fs::write(dir.join("v2.json"), json).unwrap();
        assert_eq!(cat.load_from_dir(&dir).unwrap(), 1);
        let e = cat.get("DYN-V2-001").unwrap();
        assert_eq!(e.fidelity, Fidelity::Behavioral);
        assert!(e.claims_behavioral_coverage());
        assert_eq!(e.technique_refs[0].technique_id, "T1486");
        assert_eq!(e.mitre.unwrap().id, "T1486");
        // Changing only the executor to a marker must lower both matrix and
        // compliance eligibility even when the author still claims behavioral.
        let mut marker: serde_json::Value = serde_json::from_str(json).unwrap();
        marker["spec"]["action"]["type"] = "credential_canary".into();
        marker["spec"]["action"]["parameters"] = serde_json::json!({});
        std::fs::write(dir.join("v2.json"), serde_json::to_vec(&marker).unwrap()).unwrap();
        cat.load_from_dir(&dir).unwrap();
        let e = cat.get("DYN-V2-001").unwrap();
        assert!(!e.claims_behavioral_coverage());
        assert_eq!(e.technique_refs[0].fidelity, Fidelity::MarkerOnly);
        let _ = std::fs::remove_dir_all(dir);
    }
}
