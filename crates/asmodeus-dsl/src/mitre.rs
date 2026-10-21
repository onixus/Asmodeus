//! MITRE ATT&CK domain definitions for Asmodeus.
//!
//! Provides typed representations of MITRE ATT&CK techniques, tactics, and
//! lookup utilities used by scenario catalogs and DSL manifests.
//!
//! # Pinned taxonomy (S01)
//!
//! The technique table is a **pinned, hand-curated subset** of the MITRE
//! ATT&CK Enterprise matrix identified by [`ATTACK_VERSION`]. It is not a live
//! STIX import: it contains only the techniques and sub-techniques that
//! Asmodeus scenarios actually reference, each with its canonical ID, name and
//! ATT&CK tactic set. Pinning the version makes the mapping reproducible and
//! lets CI reject any scenario that references an ID absent from this set (a
//! stale or mistyped technique no longer validates — see
//! [`is_known_id`] and the `*_ids_are_known` catalog tests).
//!
//! Changing an ID's canonical string (`id`/`name`/`tactic`) is a taxonomy
//! revision: it alters the signed built-in manifests and the audit preimage, so
//! bump [`ATTACK_VERSION`] and re-run the affected signature tests (see the S01
//! mapping note in `docs/mitre-fidelity.ru.md`).

/// Pinned MITRE ATT&CK Enterprise release this table is curated against.
///
/// Official source taxonomy: ATT&CK STIX 2.1
/// (<https://github.com/mitre-attack/attack-stix-data>). This constant is the
/// single place the pin is declared; the executive/compliance reports and the
/// `/scenarios/mitre` matrix echo it so a reader always knows which release a
/// coverage claim is scoped to.
pub const ATTACK_VERSION: &str = "ATT&CK Enterprise v15.1";

/// A specific MITRE ATT&CK technique or sub-technique.
///
/// A technique can belong to more than one ATT&CK tactic; [`tactic`] keeps the
/// single *primary* tactic for backward compatibility (wire JSON, ClickHouse
/// sort key, audit projection) while [`tactics`] carries the full set. For a
/// sub-technique, [`parent`] is the base technique ID (e.g. `T1071.001` →
/// `Some("T1071")`); for a base technique it is `None`.
///
/// [`tactic`]: MitreTechnique::tactic
/// [`tactics`]: MitreTechnique::tactics
/// [`parent`]: MitreTechnique::parent
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MitreTechnique {
    pub id: &'static str,
    pub name: &'static str,
    /// Primary ATT&CK tactic (first of [`MitreTechnique::tactics`]). Kept as a
    /// single string so existing wire/DB/audit projections stay byte-stable.
    pub tactic: &'static str,
    /// Full ATT&CK tactic set this technique belongs to (never empty; the first
    /// element equals [`MitreTechnique::tactic`]).
    pub tactics: &'static [&'static str],
    /// Base technique ID for a sub-technique, else `None`.
    pub parent: Option<&'static str>,
    pub description: &'static str,
}

impl MitreTechnique {
    /// True iff this entry is a sub-technique (`T####.###`).
    pub fn is_subtechnique(&self) -> bool {
        self.parent.is_some()
    }
}

// ---------------------------------------------------------------------------
// Standard MITRE ATT&CK Enterprise Techniques used in Asmodeus Scenarios
// ---------------------------------------------------------------------------

pub const T1486_DATA_ENCRYPTED_FOR_IMPACT: MitreTechnique = MitreTechnique {
    id: "T1486",
    name: "Data Encrypted for Impact",
    tactic: "Impact",
    tactics: &["Impact"],
    parent: None,
    description: "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability.",
};

pub const T1611_ESCAPE_TO_HOST: MitreTechnique = MitreTechnique {
    id: "T1611",
    name: "Escape to Host",
    tactic: "Privilege Escalation",
    tactics: &["Privilege Escalation"],
    parent: None,
    description:
        "Adversaries may break out of a container to gain access to the underlying host system.",
};

pub const T1059_COMMAND_AND_SCRIPTING_INTERPRETER: MitreTechnique = MitreTechnique {
    id: "T1059",
    name: "Command and Scripting Interpreter",
    tactic: "Execution",
    tactics: &["Execution"],
    parent: None,
    description: "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
};

pub const T1071_APPLICATION_LAYER_PROTOCOL: MitreTechnique = MitreTechnique {
    id: "T1071",
    name: "Application Layer Protocol",
    tactic: "Command and Control",
    tactics: &["Command and Control"],
    parent: None,
    description: "Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic.",
};

pub const T1568_DYNAMIC_RESOLUTION: MitreTechnique = MitreTechnique {
    id: "T1568",
    name: "Dynamic Resolution",
    tactic: "Command and Control",
    tactics: &["Command and Control"],
    parent: None,
    description: "Adversaries may dynamically establish connections to command and control infrastructure using domain generation or dynamic DNS.",
};

pub const T1003_OS_CREDENTIAL_DUMPING: MitreTechnique = MitreTechnique {
    id: "T1003",
    name: "OS Credential Dumping",
    tactic: "Credential Access",
    tactics: &["Credential Access"],
    parent: None,
    description: "Adversaries may attempt to dump credentials to obtain account login and credential material.",
};

pub const T1070_INDICATOR_REMOVAL: MitreTechnique = MitreTechnique {
    id: "T1070",
    name: "Indicator Removal on Host",
    tactic: "Defense Evasion",
    tactics: &["Defense Evasion"],
    parent: None,
    description: "Adversaries may delete or alter generated event logs, files, or other artifacts to cover their tracks.",
};

pub const T1053_SCHEDULED_TASK_JOB: MitreTechnique = MitreTechnique {
    id: "T1053",
    name: "Scheduled Task/Job",
    tactic: "Persistence",
    // ATT&CK lists T1053 under three tactics; Asmodeus keeps "Persistence" as
    // the primary (the scenario's intent, listed first) while exposing the set.
    tactics: &["Persistence", "Execution", "Privilege Escalation"],
    parent: None,
    description: "Adversaries may configure tasks or jobs to execute at a specified time or on a recurring basis for persistence.",
};

pub const T1041_EXFILTRATION_OVER_C2: MitreTechnique = MitreTechnique {
    id: "T1041",
    name: "Exfiltration Over C2 Channel",
    tactic: "Exfiltration",
    tactics: &["Exfiltration"],
    parent: None,
    description: "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
};

pub const T1562_IMPAIR_DEFENSES: MitreTechnique = MitreTechnique {
    id: "T1562",
    name: "Impair Defenses: Disable Tools",
    tactic: "Defense Evasion",
    tactics: &["Defense Evasion"],
    parent: None,
    description: "Adversaries may maliciously inhibit or disable security tools, logging services, or protective agents.",
};

// ---------------------------------------------------------------------------
// Additional base techniques referenced by the first MITRE wave (S02) and the
// compliance control mapping. Pinned here so those references resolve and CI
// can validate them.
// ---------------------------------------------------------------------------

pub const T1609_CONTAINER_ADMINISTRATION_COMMAND: MitreTechnique = MitreTechnique {
    id: "T1609",
    name: "Container Administration Command",
    tactic: "Execution",
    tactics: &["Execution"],
    parent: None,
    description: "Adversaries may abuse a container administration service to execute commands within a container.",
};

// ---------------------------------------------------------------------------
// Sub-techniques. Each pins its base technique via `parent`.
// ---------------------------------------------------------------------------

pub const T1059_004_UNIX_SHELL: MitreTechnique = MitreTechnique {
    id: "T1059.004",
    name: "Command and Scripting Interpreter: Unix Shell",
    tactic: "Execution",
    tactics: &["Execution"],
    parent: Some("T1059"),
    description: "Adversaries may abuse Unix shell commands and scripts for execution.",
};

pub const T1071_001_WEB_PROTOCOLS: MitreTechnique = MitreTechnique {
    id: "T1071.001",
    name: "Application Layer Protocol: Web Protocols",
    tactic: "Command and Control",
    tactics: &["Command and Control"],
    parent: Some("T1071"),
    description: "Adversaries may communicate using application layer protocols associated with web traffic to avoid detection.",
};

pub const T1071_004_DNS: MitreTechnique = MitreTechnique {
    id: "T1071.004",
    name: "Application Layer Protocol: DNS",
    tactic: "Command and Control",
    tactics: &["Command and Control"],
    parent: Some("T1071"),
    description: "Adversaries may communicate using the DNS application layer protocol to avoid detection/network filtering.",
};

pub const T1562_001_DISABLE_OR_MODIFY_TOOLS: MitreTechnique = MitreTechnique {
    id: "T1562.001",
    name: "Impair Defenses: Disable or Modify Tools",
    tactic: "Defense Evasion",
    tactics: &["Defense Evasion"],
    parent: Some("T1562"),
    description: "Adversaries may disable or modify security tools to avoid possible detection of their activity.",
};

/// The ten base MITRE ATT&CK techniques historically modeled in Asmodeus.
///
/// Retained as a fixed-size array for backward compatibility; new entries live
/// in [`ADDITIONAL_TECHNIQUES`] / [`SUBTECHNIQUES`]. Prefer [`ALL_DEFS`] or
/// [`lookup_technique`] for new code.
pub const ALL_TECHNIQUES: [MitreTechnique; 10] = [
    T1486_DATA_ENCRYPTED_FOR_IMPACT,
    T1611_ESCAPE_TO_HOST,
    T1059_COMMAND_AND_SCRIPTING_INTERPRETER,
    T1071_APPLICATION_LAYER_PROTOCOL,
    T1568_DYNAMIC_RESOLUTION,
    T1003_OS_CREDENTIAL_DUMPING,
    T1070_INDICATOR_REMOVAL,
    T1053_SCHEDULED_TASK_JOB,
    T1041_EXFILTRATION_OVER_C2,
    T1562_IMPAIR_DEFENSES,
];

/// Additional base techniques pinned for S02 / compliance references.
pub const ADDITIONAL_TECHNIQUES: [MitreTechnique; 1] = [T1609_CONTAINER_ADMINISTRATION_COMMAND];

/// Sub-techniques pinned in the taxonomy, each linked to its base via `parent`.
pub const SUBTECHNIQUES: [MitreTechnique; 4] = [
    T1059_004_UNIX_SHELL,
    T1071_001_WEB_PROTOCOLS,
    T1071_004_DNS,
    T1562_001_DISABLE_OR_MODIFY_TOOLS,
];

/// Every pinned technique and sub-technique, in one slice. Length is not part
/// of the type, so entries can be added without a breaking API change.
pub const ALL_DEFS: &[MitreTechnique] = &[
    T1486_DATA_ENCRYPTED_FOR_IMPACT,
    T1611_ESCAPE_TO_HOST,
    T1059_COMMAND_AND_SCRIPTING_INTERPRETER,
    T1071_APPLICATION_LAYER_PROTOCOL,
    T1568_DYNAMIC_RESOLUTION,
    T1003_OS_CREDENTIAL_DUMPING,
    T1070_INDICATOR_REMOVAL,
    T1053_SCHEDULED_TASK_JOB,
    T1041_EXFILTRATION_OVER_C2,
    T1562_IMPAIR_DEFENSES,
    T1609_CONTAINER_ADMINISTRATION_COMMAND,
    T1059_004_UNIX_SHELL,
    T1071_001_WEB_PROTOCOLS,
    T1071_004_DNS,
    T1562_001_DISABLE_OR_MODIFY_TOOLS,
];

/// Look up a MITRE ATT&CK technique or sub-technique by its ID
/// (e.g. `"T1486"`, `"t1071"`, or `"T1071.001"`). Case-insensitive.
pub fn lookup_technique(id: &str) -> Option<MitreTechnique> {
    ALL_DEFS
        .iter()
        .copied()
        .find(|t| t.id.eq_ignore_ascii_case(id))
}

/// True iff `id` names a technique or sub-technique in the pinned taxonomy.
pub fn is_known_id(id: &str) -> bool {
    lookup_technique(id).is_some()
}

/// Iterator over every pinned technique/sub-technique ID.
pub fn all_ids() -> impl Iterator<Item = &'static str> {
    ALL_DEFS.iter().map(|t| t.id)
}

/// Resolve the base technique for any ID: returns the entry itself for a base
/// technique, or its parent for a sub-technique. `None` if `id` is unknown or
/// its declared parent is missing from the taxonomy.
pub fn base_technique(id: &str) -> Option<MitreTechnique> {
    let t = lookup_technique(id)?;
    match t.parent {
        None => Some(t),
        Some(parent_id) => lookup_technique(parent_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_technique_lookup() {
        assert_eq!(
            lookup_technique("T1486"),
            Some(T1486_DATA_ENCRYPTED_FOR_IMPACT)
        );
        assert_eq!(
            lookup_technique("t1071"),
            Some(T1071_APPLICATION_LAYER_PROTOCOL)
        );
        assert_eq!(lookup_technique("T9999"), None);
    }

    #[test]
    fn test_all_techniques_have_valid_metadata() {
        for t in ALL_DEFS {
            assert!(t.id.starts_with('T'));
            assert!(!t.name.is_empty());
            assert!(!t.tactic.is_empty());
            assert!(!t.tactics.is_empty());
            assert!(!t.description.is_empty());
            // The primary tactic must be the first of the full set.
            assert_eq!(t.tactics[0], t.tactic);
        }
    }

    #[test]
    fn subtechnique_ids_are_well_formed_and_linked() {
        for t in ALL_DEFS {
            match t.parent {
                None => assert!(
                    !t.id.contains('.'),
                    "base technique {} must not contain a dot",
                    t.id
                ),
                Some(parent_id) => {
                    assert!(
                        t.id.starts_with(parent_id),
                        "sub-technique {} must extend its parent {parent_id}",
                        t.id
                    );
                    assert!(t.id.contains('.'), "sub-technique {} needs a dot", t.id);
                    assert!(
                        lookup_technique(parent_id).is_some(),
                        "parent {parent_id} of {} is absent from the taxonomy",
                        t.id
                    );
                    assert!(
                        lookup_technique(parent_id).unwrap().parent.is_none(),
                        "parent {parent_id} must itself be a base technique"
                    );
                }
            }
        }
    }

    #[test]
    fn sub_and_base_lookups_resolve() {
        let sub = lookup_technique("T1071.001").expect("sub-technique pinned");
        assert_eq!(sub.parent, Some("T1071"));
        assert_eq!(
            base_technique("T1071.001"),
            Some(T1071_APPLICATION_LAYER_PROTOCOL)
        );
        assert_eq!(
            base_technique("T1486"),
            Some(T1486_DATA_ENCRYPTED_FOR_IMPACT)
        );
        assert_eq!(base_technique("T0000"), None);
    }

    #[test]
    fn taxonomy_ids_are_unique() {
        let mut ids: Vec<&str> = all_ids().collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "duplicate technique IDs in the taxonomy");
    }

    #[test]
    fn legacy_array_is_a_prefix_of_all_defs() {
        // ALL_TECHNIQUES stays a stable backward-compatible view.
        for (i, t) in ALL_TECHNIQUES.iter().enumerate() {
            assert_eq!(ALL_DEFS[i], *t);
        }
        assert_eq!(
            ALL_DEFS.len(),
            ALL_TECHNIQUES.len() + ADDITIONAL_TECHNIQUES.len() + SUBTECHNIQUES.len()
        );
    }

    #[test]
    fn multi_tactic_technique_is_exposed() {
        let t = lookup_technique("T1053").unwrap();
        assert_eq!(t.tactic, "Persistence");
        assert!(t.tactics.contains(&"Execution"));
        assert!(t.tactics.contains(&"Privilege Escalation"));
    }
}
