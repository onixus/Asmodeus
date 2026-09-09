//! MITRE ATT&CK domain definitions for Asmodeus.
//!
//! Provides typed representations of MITRE ATT&CK techniques, tactics, and
//! lookup utilities used by scenario catalogs and DSL manifests.

/// A specific MITRE ATT&CK technique or sub-technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MitreTechnique {
    pub id: &'static str,
    pub name: &'static str,
    pub tactic: &'static str,
    pub description: &'static str,
}

// ---------------------------------------------------------------------------
// Standard MITRE ATT&CK Enterprise Techniques used in Asmodeus Scenarios
// ---------------------------------------------------------------------------

pub const T1486_DATA_ENCRYPTED_FOR_IMPACT: MitreTechnique = MitreTechnique {
    id: "T1486",
    name: "Data Encrypted for Impact",
    tactic: "Impact",
    description: "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability.",
};

pub const T1611_ESCAPE_TO_HOST: MitreTechnique = MitreTechnique {
    id: "T1611",
    name: "Escape to Host",
    tactic: "Privilege Escalation",
    description:
        "Adversaries may break out of a container to gain access to the underlying host system.",
};

pub const T1059_COMMAND_AND_SCRIPTING_INTERPRETER: MitreTechnique = MitreTechnique {
    id: "T1059",
    name: "Command and Scripting Interpreter",
    tactic: "Execution",
    description: "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
};

pub const T1071_APPLICATION_LAYER_PROTOCOL: MitreTechnique = MitreTechnique {
    id: "T1071",
    name: "Application Layer Protocol",
    tactic: "Command and Control",
    description: "Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic.",
};

pub const T1568_DYNAMIC_RESOLUTION: MitreTechnique = MitreTechnique {
    id: "T1568",
    name: "Dynamic Resolution",
    tactic: "Command and Control",
    description: "Adversaries may dynamically establish connections to command and control infrastructure using domain generation or dynamic DNS.",
};

pub const T1003_OS_CREDENTIAL_DUMPING: MitreTechnique = MitreTechnique {
    id: "T1003",
    name: "OS Credential Dumping",
    tactic: "Credential Access",
    description: "Adversaries may attempt to dump credentials to obtain account login and credential material.",
};

pub const T1070_INDICATOR_REMOVAL: MitreTechnique = MitreTechnique {
    id: "T1070",
    name: "Indicator Removal on Host",
    tactic: "Defense Evasion",
    description: "Adversaries may delete or alter generated event logs, files, or other artifacts to cover their tracks.",
};

pub const T1053_SCHEDULED_TASK_JOB: MitreTechnique = MitreTechnique {
    id: "T1053",
    name: "Scheduled Task/Job",
    tactic: "Persistence",
    description: "Adversaries may configure tasks or jobs to execute at a specified time or on a recurring basis for persistence.",
};

pub const T1041_EXFILTRATION_OVER_C2: MitreTechnique = MitreTechnique {
    id: "T1041",
    name: "Exfiltration Over C2 Channel",
    tactic: "Exfiltration",
    description: "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
};

pub const T1562_IMPAIR_DEFENSES: MitreTechnique = MitreTechnique {
    id: "T1562",
    name: "Impair Defenses: Disable Tools",
    tactic: "Defense Evasion",
    description: "Adversaries may maliciously inhibit or disable security tools, logging services, or protective agents.",
};

/// All MITRE ATT&CK techniques formally modeled in Asmodeus.
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

/// Look up a MITRE ATT&CK technique by its ID (e.g., `"T1486"` or `"T1562"`).
pub fn lookup_technique(id: &str) -> Option<MitreTechnique> {
    ALL_TECHNIQUES
        .iter()
        .copied()
        .find(|t| t.id.eq_ignore_ascii_case(id))
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
        for t in &ALL_TECHNIQUES {
            assert!(t.id.starts_with('T'));
            assert!(!t.name.is_empty());
            assert!(!t.tactic.is_empty());
            assert!(!t.description.is_empty());
        }
    }
}
