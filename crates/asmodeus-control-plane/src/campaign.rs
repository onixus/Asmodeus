//! Attack Campaign & Kill-Chain orchestration for multi-stage BAS scenarios.
//!
//! A Campaign groups multiple scenarios into an ordered attack path
//! (e.g. Credential Access -> Persistence -> C2 -> Impact). Executing a campaign
//! executes each stage sequentially, aggregating intermediate MTTD/MTTR timings
//! and computing the composite resilience score for the entire kill-chain.

use serde::{Deserialize, Serialize};

/// A single step in a multi-stage attack campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignStep {
    pub order: usize,
    pub scenario_id: String,
}

/// A multi-stage attack campaign definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Campaign {
    pub id: String,
    pub name: String,
    pub description: String,
    pub steps: Vec<CampaignStep>,
}

/// Execution result for an individual step within a campaign run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignStepResult {
    pub step_order: usize,
    pub scenario_id: String,
    pub run_id: String,
    pub status: String,
    pub mttd_ms: u64,
    pub mttr_ms: u64,
    pub detected: bool,
}

/// Complete report of an executed attack campaign.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CampaignRunResult {
    pub campaign_id: String,
    pub campaign_name: String,
    pub initiator: String,
    pub target_override: Option<String>,
    pub total_steps: usize,
    pub successful_steps: usize,
    pub step_results: Vec<CampaignStepResult>,
    pub mean_mttd_ms: u64,
    pub mean_mttr_ms: u64,
    pub detection_rate_pct: f32,
    pub recovery_speed_pct: f32,
    pub resilience_score: u8,
    pub timestamp_utc: String,
}

/// Preconfigured catalog of standard attack campaigns and kill-chains.
#[derive(Debug, Clone, Default)]
pub struct CampaignCatalog {
    campaigns: Vec<Campaign>,
}

impl CampaignCatalog {
    /// Seed the canonical attack campaigns.
    pub fn seeded() -> Self {
        let campaigns = vec![
            Campaign {
                id: "CAMP-RANSOMWARE-CHAIN".to_string(),
                name: "Ransomware APT Attack Path".to_string(),
                description: "Multi-stage simulated ransomware kill-chain: Credential Dumping -> Scheduled Persistence -> C2 Beaconing -> Mass Canary Data Encryption (MITRE T1003, T1053, T1071, T1486)".to_string(),
                steps: vec![
                    CampaignStep { order: 1, scenario_id: "CREDENTIAL_ACCESS_CANARY".to_string() },
                    CampaignStep { order: 2, scenario_id: "PERSISTENCE_CRON_CANARY".to_string() },
                    CampaignStep { order: 3, scenario_id: "C2_BEACONING_SIMULATION".to_string() },
                    CampaignStep { order: 4, scenario_id: "RANSOMWARE_CANARY_SPIKE".to_string() },
                ],
            },
            Campaign {
                id: "CAMP-K8S-ESCAPE-CHAOS".to_string(),
                name: "K8s Escape & Infrastructure Chaos Chain".to_string(),
                description: "Container breakout combined with network latency chaos and DNS RPZ sinkhole outage (MITRE T1611 & FTT §4.2)".to_string(),
                steps: vec![
                    CampaignStep { order: 1, scenario_id: "K8S_ESCAPE_SIMULATION".to_string() },
                    CampaignStep { order: 2, scenario_id: "LATENCY_SPIKE_VM".to_string() },
                    CampaignStep { order: 3, scenario_id: "DNS_RPZ_SINKHOLE_DROP".to_string() },
                ],
            },
            Campaign {
                id: "CAMP-PERSISTENCE-EXFIL".to_string(),
                name: "Stealth Persistence & Exfiltration Chain".to_string(),
                description: "Stealth persistence followed by log tampering and data exfiltration (MITRE T1053, T1070, T1041)".to_string(),
                steps: vec![
                    CampaignStep { order: 1, scenario_id: "PERSISTENCE_CRON_CANARY".to_string() },
                    CampaignStep { order: 2, scenario_id: "LOG_TAMPER_CANARY".to_string() },
                    CampaignStep { order: 3, scenario_id: "DATA_EXFILTRATION_CANARY".to_string() },
                ],
            },
        ];

        Self { campaigns }
    }

    /// List all registered attack campaigns.
    pub fn list(&self) -> &[Campaign] {
        &self.campaigns
    }

    /// Look up a campaign by ID.
    pub fn get(&self, id: &str) -> Option<&Campaign> {
        self.campaigns
            .iter()
            .find(|c| c.id.eq_ignore_ascii_case(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seeded_campaigns() {
        let catalog = CampaignCatalog::seeded();
        let list = catalog.list();
        assert_eq!(list.len(), 3);

        let ransomware = catalog
            .get("CAMP-RANSOMWARE-CHAIN")
            .expect("ransomware chain");
        assert_eq!(ransomware.steps.len(), 4);
        assert_eq!(ransomware.steps[0].scenario_id, "CREDENTIAL_ACCESS_CANARY");
        assert_eq!(ransomware.steps[3].scenario_id, "RANSOMWARE_CANARY_SPIKE");

        let k8s = catalog
            .get("CAMP-K8S-ESCAPE-CHAOS")
            .expect("k8s chaos chain");
        assert_eq!(k8s.steps.len(), 3);

        assert!(catalog.get("NON_EXISTENT").is_none());
    }
}
