//! Signed scenario catalog. The REST API accepts only a `scenario_id` (D6);
//! the manifest, its Ed25519 signature and the trusted public key live here.
//!
//! For the MVP the catalog is self-signed at startup with a freshly generated
//! keypair so the whole verify path exercises real crypto. In production the
//! public key is configured and the private key belongs to the Red Team Lead.

use std::collections::HashMap;

use asmodeus_common::{ActionNature, Category};
use ed25519_compact::KeyPair;

/// One entry in the catalog.
#[derive(Debug, Clone)]
pub struct ScenarioEntry {
    pub id: &'static str,
    pub category: Category,
    pub nature: ActionNature,
    pub target_path: String,
    pub detector: &'static str,
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

    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    /// Seed the four canonical scenarios (TT §5.1 enum), self-signed.
    pub fn seeded() -> Self {
        let kp = KeyPair::generate();
        let mut entries = HashMap::new();

        let mut add = |id: &'static str,
                       category: Category,
                       nature: ActionNature,
                       target_path: &str,
                       detector: &'static str,
                       mttd: u64,
                       mttr: u64| {
            let manifest = format!(
                "apiVersion: asmodeus.io/v1alpha1\nkind: AttackScenario\nid: {id}\ncategory: {}\n",
                category.tag()
            )
            .into_bytes();
            let signature = kp.sk.sign(&manifest, None).as_ref().to_vec();
            entries.insert(
                id.to_string(),
                ScenarioEntry {
                    id,
                    category,
                    nature,
                    target_path: target_path.to_string(),
                    detector,
                    manifest,
                    signature,
                    sim_mttd_ms: mttd,
                    sim_mttr_ms: mttr,
                    file_count: 20,
                    chunk_size_kb: 64,
                },
            );
        };

        add(
            "RANSOMWARE_CANARY_SPIKE",
            Category::RedTeam,
            ActionNature::Synthetic,
            "/tmp/asmodeus-canary/",
            "ferrum_ebpf_kernel_probe",
            142,
            280,
        );
        add(
            "K8S_ESCAPE_SIMULATION",
            Category::RedTeam,
            ActionNature::Synthetic,
            "/tmp/asmodeus-canary/",
            "ferrum_admission_controller",
            95,
            210,
        );
        add(
            "LATENCY_SPIKE_VM",
            Category::Chaos,
            ActionNature::Synthetic,
            "/tmp/asmodeus-canary/",
            "apex_gateway_failover",
            60,
            180,
        );
        add(
            "AGENT_CRASH_ENDPOINT",
            Category::Chaos,
            ActionNature::Synthetic,
            "/tmp/asmodeus-canary/",
            "lariska_watchdog",
            40,
            120,
        );

        Catalog {
            entries,
            public_key: kp.pk.as_ref().to_vec(),
        }
    }
}
