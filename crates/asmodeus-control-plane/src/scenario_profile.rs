//! Per-scenario ATT&CK **fidelity profile** and the old→new mapping table (S01).
//!
//! Before S01 every catalog scenario carried at most one `MitreTechnique` and
//! was implicitly treated as full coverage of that technique. That overstated
//! what the engine validates: seven of the eight attack scenarios only drop a
//! synthetic marker/canary and never execute the technique's behaviour.
//!
//! This module pins, for each built-in scenario, the honest mapping:
//! * the technique(s) it references (a scenario may map to several — multi
//!   technique / multi tactic), with the [`Fidelity`] at which each is
//!   exercised;
//! * the historical single-technique mapping it is migrating *from*
//!   ([`ProfileDef::legacy_technique`]), so the change is auditable;
//! * the procedure identity, platforms, preconditions, safety scope, expected
//!   observables and explicit limitations the acceptance criteria require.
//!
//! The data here is the single source of truth for both the catalog
//! ([`crate::catalog`]) and the human-readable mapping doc
//! (`docs/mitre-fidelity.ru.md`). CI (`scenario_profiles_are_consistent` and
//! the catalog tests) rejects a profile that references an ID absent from the
//! pinned taxonomy, or whose fidelity over-claims.

use asmodeus_dsl::fidelity::{Fidelity, Platform, TechniqueRef};

/// Static definition of one scenario's fidelity profile. All fields are
/// `&'static`/`Copy` so the whole table is a compile-time constant.
#[derive(Debug, Clone, Copy)]
pub struct ProfileDef {
    pub scenario_id: &'static str,
    /// Fidelity at which this scenario exercises every technique it references.
    pub fidelity: Fidelity,
    /// Referenced technique IDs; the first is the primary. Empty for a pure
    /// infrastructure-chaos scenario that maps to no ATT&CK technique.
    pub techniques: &'static [&'static str],
    /// The single technique this scenario historically mapped to (implied full
    /// coverage), for the old→new migration record. `None` for chaos scenarios
    /// that never carried a technique.
    pub legacy_technique: Option<&'static str>,
    pub procedure_id: &'static str,
    pub procedure_revision: u32,
    pub platforms: &'static [Platform],
    pub preconditions: &'static str,
    pub safety_scope: &'static str,
    pub expected_observables: &'static [&'static str],
    /// The honest caveat: what this scenario does **not** prove.
    pub limitations: &'static str,
}

/// Owned, report-ready projection of a [`ProfileDef`], carried on a catalog
/// entry and serialized into API/report output.
#[derive(Debug, Clone)]
pub struct ScenarioProfile {
    pub procedure_id: String,
    pub procedure_revision: u32,
    pub platforms: Vec<Platform>,
    pub preconditions: String,
    pub safety_scope: String,
    pub expected_observables: Vec<String>,
    pub limitations: String,
    pub legacy_technique: Option<String>,
}

impl ProfileDef {
    /// The scenario's technique references, each at the profile's fidelity.
    pub fn technique_refs(&self) -> Vec<TechniqueRef> {
        self.techniques
            .iter()
            .map(|id| TechniqueRef::new(*id, self.fidelity))
            .collect()
    }

    pub fn to_profile(self) -> ScenarioProfile {
        ScenarioProfile {
            procedure_id: self.procedure_id.to_string(),
            procedure_revision: self.procedure_revision,
            platforms: self.platforms.to_vec(),
            preconditions: self.preconditions.to_string(),
            safety_scope: self.safety_scope.to_string(),
            expected_observables: self
                .expected_observables
                .iter()
                .map(|s| s.to_string())
                .collect(),
            limitations: self.limitations.to_string(),
            legacy_technique: self.legacy_technique.map(str::to_string),
        }
    }
}

const CANARY_FS_SCOPE: &str =
    "canary filesystem sandbox (/tmp/asmodeus-canary, /var/tmp/asmodeus-canary)";
const TEST_NET_SCOPE: &str = "reserved test nets only (loopback + RFC 5737 TEST-NET-1/2/3)";

/// The pinned old→new fidelity mapping for every built-in scenario.
///
/// Fidelity is assigned from the injector each scenario actually dispatches
/// (`asmodeus-runner::injectors::create_injector`): only the reversible-XOR
/// canary encryptor and the network-chaos perturbation run representative
/// behaviour — everything else merely writes/reads a synthetic marker.
pub const PROFILES: &[ProfileDef] = &[
    ProfileDef {
        scenario_id: "RANSOMWARE_CANARY_SPIKE",
        fidelity: Fidelity::Behavioral,
        techniques: &["T1486"],
        legacy_technique: Some("T1486"),
        procedure_id: "ASMOD-PROC-0001",
        procedure_revision: 1,
        platforms: &[Platform::Linux],
        preconditions: "writable canary directory seeded with synthetic documents",
        safety_scope: CANARY_FS_SCOPE,
        expected_observables: &[
            "burst of file-modification events on canary documents",
            "entropy/size change on canary files from reversible XOR",
        ],
        limitations:
            "reversible XOR over synthetic canary documents only; not real encryption and not \
             destructive — proves encryption-spike detection, not ransomware impact",
    },
    ProfileDef {
        scenario_id: "K8S_ESCAPE_SIMULATION",
        fidelity: Fidelity::MarkerOnly,
        techniques: &["T1611"],
        legacy_technique: Some("T1611"),
        procedure_id: "ASMOD-PROC-0002",
        procedure_revision: 1,
        platforms: &[Platform::Containers, Platform::Kubernetes, Platform::Linux],
        preconditions: "writable canary directory",
        safety_scope: CANARY_FS_SCOPE,
        expected_observables: &[
            "creation of docker.sock.probe marker in canary scope",
            "creation of k8s_ns_escape.canary marker in canary scope",
        ],
        limitations:
            "writes escape-probe marker files only; does NOT perform a real container escape or \
             gain host access — not behavioural or prevention coverage of T1611",
    },
    ProfileDef {
        scenario_id: "C2_BEACONING_SIMULATION",
        fidelity: Fidelity::MarkerOnly,
        techniques: &["T1071", "T1071.001", "T1071.004", "T1568"],
        legacy_technique: Some("T1071"),
        procedure_id: "ASMOD-PROC-0003",
        procedure_revision: 1,
        platforms: &[Platform::Network, Platform::Linux],
        preconditions: "writable canary directory",
        safety_scope: CANARY_FS_SCOPE,
        expected_observables: &["beacon-event records written to a canary log with jitter"],
        limitations:
            "records synthetic beacon events to a canary log; performs NO real network egress or \
             DNS resolution — not behavioural coverage of C2 or dynamic resolution",
    },
    ProfileDef {
        scenario_id: "CREDENTIAL_ACCESS_CANARY",
        fidelity: Fidelity::MarkerOnly,
        techniques: &["T1003"],
        legacy_technique: Some("T1003"),
        procedure_id: "ASMOD-PROC-0004",
        procedure_revision: 1,
        platforms: &[Platform::Linux],
        preconditions: "writable canary directory",
        safety_scope: CANARY_FS_SCOPE,
        expected_observables: &[
            "creation of honeytoken_credentials.json decoy in canary scope",
            "a single read-back of the decoy honeytoken",
        ],
        limitations:
            "accesses a synthetic honeytoken decoy only; touches NO real credential store, memory \
             or process — not behavioural or prevention coverage of T1003",
    },
    ProfileDef {
        scenario_id: "LOG_TAMPER_CANARY",
        fidelity: Fidelity::MarkerOnly,
        techniques: &["T1070"],
        legacy_technique: Some("T1070"),
        procedure_id: "ASMOD-PROC-0005",
        procedure_revision: 1,
        platforms: &[Platform::Linux],
        preconditions: "writable canary directory",
        safety_scope: CANARY_FS_SCOPE,
        expected_observables: &[
            "creation then truncation of a synthetic canary audit log",
        ],
        limitations:
            "creates and truncates its own synthetic canary log; removes NO real indicators or \
             production logs — not behavioural coverage of T1070",
    },
    ProfileDef {
        scenario_id: "PERSISTENCE_CRON_CANARY",
        fidelity: Fidelity::MarkerOnly,
        techniques: &["T1053"],
        legacy_technique: Some("T1053"),
        procedure_id: "ASMOD-PROC-0006",
        procedure_revision: 1,
        platforms: &[Platform::Linux],
        preconditions: "writable canary directory",
        safety_scope: CANARY_FS_SCOPE,
        expected_observables: &["creation of a decoy cron-job file in canary scope"],
        limitations:
            "writes a decoy cron file inside the canary directory; installs NO real scheduled \
             task and no system scheduler is modified — not behavioural coverage of T1053",
    },
    ProfileDef {
        scenario_id: "DATA_EXFILTRATION_CANARY",
        fidelity: Fidelity::MarkerOnly,
        techniques: &["T1041"],
        legacy_technique: Some("T1041"),
        procedure_id: "ASMOD-PROC-0007",
        procedure_revision: 1,
        platforms: &[Platform::Network, Platform::Linux],
        preconditions: "writable canary directory",
        safety_scope: CANARY_FS_SCOPE,
        expected_observables: &["a synthetic staging blob written in canary scope"],
        limitations:
            "stages a synthetic filler blob in the canary directory; NO data leaves the host and \
             no real channel is used — not behavioural coverage of T1041",
    },
    ProfileDef {
        scenario_id: "DEFENSE_IMPAIRMENT_CANARY",
        fidelity: Fidelity::MarkerOnly,
        techniques: &["T1562", "T1562.001"],
        legacy_technique: Some("T1562"),
        procedure_id: "ASMOD-PROC-0008",
        procedure_revision: 1,
        platforms: &[Platform::Linux],
        preconditions: "writable canary directory",
        safety_scope: CANARY_FS_SCOPE,
        expected_observables: &["a watchdog_recovery.pulse marker written in canary scope"],
        limitations:
            "writes a benign watchdog pulse marker; disables or modifies NO real security tool — \
             not behavioural or prevention coverage of T1562",
    },
    ProfileDef {
        scenario_id: "LATENCY_SPIKE_VM",
        fidelity: Fidelity::Behavioral,
        techniques: &[],
        legacy_technique: None,
        procedure_id: "ASMOD-CHAOS-0001",
        procedure_revision: 1,
        platforms: &[Platform::Network],
        preconditions: "a test interface bound to a reserved test net",
        safety_scope: TEST_NET_SCOPE,
        expected_observables: &[
            "added latency/jitter and packet loss on the reserved test segment",
        ],
        limitations:
            "infrastructure-chaos resilience test on reserved test nets; maps to NO ATT&CK \
             technique and contributes no technique coverage",
    },
    ProfileDef {
        scenario_id: "AGENT_CRASH_ENDPOINT",
        fidelity: Fidelity::MarkerOnly,
        techniques: &["T1562"],
        legacy_technique: Some("T1562"),
        procedure_id: "ASMOD-CHAOS-0002",
        procedure_revision: 1,
        platforms: &[Platform::Linux],
        preconditions: "writable canary directory",
        safety_scope: CANARY_FS_SCOPE,
        expected_observables: &["a watchdog_recovery.pulse marker written in canary scope"],
        limitations:
            "writes a benign recovery pulse marker to test the endpoint watchdog window; disables \
             NO real tool — not behavioural or prevention coverage of T1562",
    },
    ProfileDef {
        scenario_id: "DNS_RPZ_SINKHOLE_DROP",
        fidelity: Fidelity::Behavioral,
        techniques: &[],
        legacy_technique: None,
        procedure_id: "ASMOD-CHAOS-0003",
        procedure_revision: 1,
        platforms: &[Platform::Network],
        preconditions: "a test interface bound to loopback",
        safety_scope: TEST_NET_SCOPE,
        expected_observables: &["simulated DNS RPZ resolver outage on the loopback test segment"],
        limitations:
            "infrastructure-chaos resilience test on reserved test nets; maps to NO ATT&CK \
             technique and contributes no technique coverage",
    },
];

/// Look up the pinned profile for a built-in scenario ID.
pub fn profile_for(scenario_id: &str) -> Option<ProfileDef> {
    PROFILES
        .iter()
        .copied()
        .find(|p| p.scenario_id == scenario_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_profile_technique_id_is_known() {
        for p in PROFILES {
            for id in p.techniques {
                assert!(
                    asmodeus_dsl::is_known_id(id),
                    "profile {} references unknown technique {id}",
                    p.scenario_id
                );
            }
            if let Some(legacy) = p.legacy_technique {
                assert!(
                    asmodeus_dsl::is_known_id(legacy),
                    "profile {} legacy technique {legacy} is unknown",
                    p.scenario_id
                );
            }
        }
    }

    #[test]
    fn marker_only_profiles_carry_a_limitation_disclaimer() {
        for p in PROFILES {
            if p.fidelity == Fidelity::MarkerOnly {
                assert!(
                    !p.limitations.is_empty(),
                    "marker-only profile {} needs an explicit limitation",
                    p.scenario_id
                );
            }
        }
    }

    #[test]
    fn profile_ids_are_unique() {
        let mut ids: Vec<&str> = PROFILES.iter().map(|p| p.scenario_id).collect();
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n, "duplicate scenario IDs in PROFILES");
    }

    #[test]
    fn chaos_profiles_map_to_no_technique() {
        for id in ["LATENCY_SPIKE_VM", "DNS_RPZ_SINKHOLE_DROP"] {
            let p = profile_for(id).unwrap();
            assert!(p.techniques.is_empty());
            assert!(p.legacy_technique.is_none());
        }
    }
}
