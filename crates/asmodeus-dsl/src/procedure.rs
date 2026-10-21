//! S02 fixed planning corpus. These contracts do not dispatch runner actions,
//! attest execution, or contribute any behavioural/prevention coverage.
use serde::{Deserialize, Serialize};

pub const PROCEDURE_CORPUS_VERSION: &str = "asmodeus.procedure-corpus.v1";
pub const PROCEDURE_SLOT_DENOMINATOR: usize = 6;
const SLOTS: [(&str, &str); PROCEDURE_SLOT_DENOMINATOR] = [
    ("container-exec", "T1609"),
    ("shell-execution", "T1059.004"),
    ("runtime-socket-prerequisite", "T1611"),
    ("http-beacon", "T1071.001"),
    ("dns-pattern", "T1071.004"),
    ("synthetic-transfer", "T1041"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcedureMode {
    Marker,
    Replay,
    Behavioral,
}

/// No executable availability is defined by this manifest revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcedureAvailability {
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcedureVariantKind {
    Positive,
    BenignControl,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureExpectation {
    pub observables: Vec<String>,
    pub product_effect: String,
    pub verification: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureVariant {
    pub kind: ProcedureVariantKind,
    pub behavior: String,
    pub expected: ProcedureExpectation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureBudget {
    pub timeout_seconds: u32,
    pub max_processes: u32,
    pub max_requests: u32,
    pub max_bytes: u64,
    pub cancellation_required: bool,
    pub kill_switch_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureScope {
    /// Exact attempt-owned namespace prefix; never an existing workload.
    pub namespace_prefix: String,
    pub canary_path: String,
    /// Only provisioned loopback fixtures; reserved test networks alone do not
    /// establish permission to contact a target.
    pub endpoint_allowlist: Vec<String>,
    pub synthetic_data_only: bool,
    pub real_credentials_forbidden: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureCleanup {
    pub required_after: Vec<String>,
    pub requirements: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureDefinition {
    pub id: String,
    pub revision: u32,
    pub technique_id: String,
    pub name: String,
    /// Intended execution mode, not evidence that execution happened.
    pub planned_mode: ProcedureMode,
    pub availability: ProcedureAvailability,
    pub unsupported_reason: String,
    pub gap: Option<String>,
    pub preconditions: Vec<String>,
    pub variants: [ProcedureVariant; 2],
    pub budget: ProcedureBudget,
    pub scope: ProcedureScope,
    pub cleanup: ProcedureCleanup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureCorpus {
    pub version: String,
    pub attack_version: String,
    /// Includes every unsupported slot. It is never a count of successful runs.
    pub denominator: usize,
    pub procedures: Vec<ProcedureDefinition>,
}

fn variant(kind: ProcedureVariantKind, behavior: &str, observables: &str) -> ProcedureVariant {
    let positive = kind == ProcedureVariantKind::Positive;
    ProcedureVariant {
        kind,
        behavior: behavior.into(),
        expected: ProcedureExpectation {
            observables: vec![observables.into()],
            product_effect: if positive {
                "Under the declared fixture policy, produce the configured procedure-specific detection; prevention requires separate observed enforcement evidence."
            } else {
                "Under the same policy, permit the benign control and produce no attack-specific alert; routine audit events may remain."
            }.into(),
            verification: "Correlate sensor events, product decisions and actual fixture state by unique attempt ID, procedure revision and start/stop window; compare positive and benign results. Missing telemetry or policy is NOT_RUN, never PASS."
                .into(),
        },
    }
}

/// Deterministic, versioned six-slot contract. No commands, real credentials,
/// runner dispatch, live socket access or network operations are performed.
pub fn procedure_corpus() -> ProcedureCorpus {
    let definitions = [
        ("Container exec", "Invoke a fixed harmless canary helper through the disposable container runtime exec API.", "Invoke the identical helper through the container's declared normal entrypoint.", "Runtime exec audit event plus helper process lineage and canary receipt", "Normal entrypoint/helper process lineage and matching canary receipt; no runtime exec audit event for this attempt", None),
        ("Shell execution", "Use the disposable container's shell to write a fixed synthetic canary token.", "Write the same token with the fixed helper directly, without a shell.", "Shell process lineage, fixed invocation metadata and canary file receipt", "Direct helper process lineage and matching canary file receipt; no shell process in this attempt lineage", None),
        ("Test runtime socket prerequisite", "Contact only an attempt-owned mock runtime socket and request its fixed read-only fixture metadata.", "Read the same fixture metadata from an ordinary canary file without opening a socket.", "Unix socket connect and fixture request audit correlated with process identity", "Canary metadata file read receipt correlated with helper identity; no Unix socket connect or runtime fixture request for this attempt", Some("Socket accessibility is only a measured prerequisite/signal. This procedure does not escape a container or establish T1611 behavioural coverage; host/runtime sockets must never be mounted.")),
        ("HTTP beacon", "Send at most four fixed synthetic HTTP beacon messages to the attempt-owned loopback receiver.", "Send one ordinary health-check request to the same receiver.", "Receiver receipts and HTTP connection timing for the bounded beacon pattern", "One ordinary HTTP health-check receiver receipt; no repeated beacon message pattern for this attempt", Some("No command retrieval or remote control is implemented; this is a bounded synthetic protocol pattern.")),
        ("DNS pattern", "Send at most four deterministic synthetic query labels under the fixture's .test zone to the loopback DNS fixture.", "Send one fixed service lookup under the same .test zone.", "DNS fixture query receipts, labels and bounded query timing", "One ordinary fixture service query receipt; no synthetic C2-pattern labels or repeated query pattern for this attempt", Some("No functional C2 channel, recursive resolver forwarding or external DNS is permitted.")),
        ("Synthetic transfer", "Transmit at most 4096 bytes of generated canary data to the attempt-owned loopback receiver.", "Send a fixed small health-status payload to the same receiver.", "Sender byte count and receiver payload digest for synthetic data", "One small fixed health-status receiver receipt and payload digest; no canary-data transfer payload for this attempt", Some("No real data collection or external exfiltration; this bounded transfer does not establish whole-technique T1041 coverage.")),
    ];
    let procedures = SLOTS.iter().zip(definitions).map(|((id, technique), (name, positive, benign, positive_observable, benign_observable, gap))| {
        ProcedureDefinition {
            id: (*id).into(),
            revision: 1,
            technique_id: (*technique).into(),
            name: name.into(),
            planned_mode: ProcedureMode::Behavioral,
            availability: ProcedureAvailability::Unsupported,
            unsupported_reason: "NOT_RUN: this revision defines contracts only; a scoped runtime adapter, lifecycle/cleanup proof and correlated product evidence are not implemented.".into(),
            gap: gap.map(str::to_owned),
            preconditions: vec![
                "Disposable Linux/container fixture explicitly owned by this attempt; no production workload or host runtime socket.".into(),
                "Unique attempt ID, environment manifest and pinned procedure/policy revisions recorded before start.".into(),
                "Provisioned local fixtures, sensor readiness and explicit product policy with expected positive/benign decisions.".into(),
                "Preflight rejects destinations, paths or namespaces outside the attempt scope; cancellation and kill switch must be operational.".into(),
            ],
            variants: [variant(ProcedureVariantKind::Positive, positive, positive_observable), variant(ProcedureVariantKind::BenignControl, benign, benign_observable)],
            budget: ProcedureBudget { timeout_seconds: 10, max_processes: 2, max_requests: 4, max_bytes: 4096, cancellation_required: true, kill_switch_required: true },
            scope: ProcedureScope { namespace_prefix: "asmodeus-canary-".into(), canary_path: "/tmp/asmodeus-canary/".into(), endpoint_allowlist: vec!["127.0.0.1".into()], synthetic_data_only: true, real_credentials_forbidden: true },
            cleanup: ProcedureCleanup {
                required_after: vec!["success".into(), "failure".into(), "crash".into(), "cancel".into()],
                requirements: vec![
                    "Stop and reap only attempt-owned processes and fixture receivers; prove no process or socket remains.".into(),
                    "Remove only this attempt's namespace, sockets and canary files; verify their absence and preserve signed evidence separately.".into(),
                    "Persist ownership before execution so crash recovery cannot claim or remove a previous attempt's artifacts; reruns require fresh IDs.".into(),
                ],
            },
        }
    }).collect();
    ProcedureCorpus {
        version: PROCEDURE_CORPUS_VERSION.into(),
        attack_version: crate::ATTACK_VERSION.into(),
        denominator: PROCEDURE_SLOT_DENOMINATOR,
        procedures,
    }
}

/// Validate this revision as an immutable fixture contract. Altered content
/// requires a new reviewed corpus revision, rather than silent denominator,
/// safety-policy or expectation drift. This is not an execution permission gate.
pub fn validate_procedure_corpus(corpus: &ProcedureCorpus) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    if corpus.denominator != PROCEDURE_SLOT_DENOMINATOR
        || corpus.procedures.len() != PROCEDURE_SLOT_DENOMINATOR
    {
        errors.push(
            "all six slots, including unsupported slots, must remain in the denominator".into(),
        );
    }
    for procedure in &corpus.procedures {
        if !crate::is_known_id(&procedure.technique_id) {
            errors.push(format!(
                "unknown pinned ATT&CK technique: {}",
                procedure.technique_id
            ));
        }
    }
    if corpus != &procedure_corpus() {
        errors.push("corpus differs from the immutable versioned contract; revise and review the corpus version".into());
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versioned_corpus_matches_committed_contract_snapshot() {
        // This independently committed fixture makes source-definition drift
        // visible in review even when someone forgets to bump the version.
        let pinned: ProcedureCorpus =
            serde_json::from_str(include_str!("../fixtures/procedure-corpus-v1.json")).unwrap();
        assert_eq!(pinned.version, "asmodeus.procedure-corpus.v1");
        assert_eq!(pinned.denominator, 6);
        assert_eq!(pinned, procedure_corpus());
    }

    #[test]
    fn deterministic_manifest_round_trip_preserves_six_unsupported_slots() {
        let corpus = procedure_corpus();
        assert_eq!(validate_procedure_corpus(&corpus), Ok(()));
        let json = serde_json::to_string(&corpus).unwrap();
        assert_eq!(json, serde_json::to_string(&procedure_corpus()).unwrap());
        assert_eq!(
            serde_json::from_str::<ProcedureCorpus>(&json).unwrap(),
            corpus
        );
        assert_eq!(corpus.procedures.len(), 6);
        for (procedure, (id, technique)) in corpus.procedures.iter().zip(SLOTS) {
            assert_eq!(procedure.id, id);
            assert_eq!(procedure.technique_id, technique);
            assert_eq!(procedure.availability, ProcedureAvailability::Unsupported);
            assert!(procedure.unsupported_reason.contains("NOT_RUN"));
            assert_eq!(procedure.variants[0].kind, ProcedureVariantKind::Positive);
            assert_eq!(
                procedure.variants[1].kind,
                ProcedureVariantKind::BenignControl
            );
            assert_ne!(
                procedure.variants[0].behavior,
                procedure.variants[1].behavior
            );
            assert!(procedure
                .cleanup
                .required_after
                .contains(&"crash".to_owned()));
        }
        assert!(corpus.procedures[2]
            .gap
            .as_ref()
            .unwrap()
            .contains("does not escape"));
    }

    #[test]
    fn removing_unsupported_slot_cannot_improve_denominator() {
        let mut corpus = procedure_corpus();
        corpus.procedures.remove(2);
        corpus.denominator = 5;
        assert!(validate_procedure_corpus(&corpus)
            .unwrap_err()
            .iter()
            .any(|e| e.contains("six slots")));
    }

    #[test]
    fn taxonomy_and_valid_but_wrong_mapping_are_rejected() {
        let mut corpus = procedure_corpus();
        corpus.procedures[0].technique_id = "T9999".into();
        assert!(validate_procedure_corpus(&corpus)
            .unwrap_err()
            .iter()
            .any(|e| e.contains("unknown pinned")));
        corpus.procedures[0].technique_id = "T1611".into();
        assert!(validate_procedure_corpus(&corpus).is_err());
    }

    #[test]
    fn contract_rejects_scope_budget_cleanup_and_evidence_promotion() {
        let original = procedure_corpus();
        let mutations: Vec<fn(&mut ProcedureDefinition)> = vec![
            |p| p.scope.endpoint_allowlist.push("8.8.8.8".into()),
            |p| p.scope.canary_path = "/etc/".into(),
            |p| p.scope.namespace_prefix = "production-".into(),
            |p| p.budget.timeout_seconds = 0,
            |p| p.budget.kill_switch_required = false,
            |p| p.cleanup.required_after.clear(),
            |p| p.unsupported_reason.clear(),
            |p| p.planned_mode = ProcedureMode::Marker,
            |p| p.variants[1] = p.variants[0].clone(),
        ];
        for mutate in mutations {
            let mut changed = original.clone();
            mutate(&mut changed.procedures[0]);
            assert!(validate_procedure_corpus(&changed).is_err());
        }
        let mut json = serde_json::to_value(original).unwrap();
        json["procedures"][0]["availability"] = "SUPPORTED".into();
        assert!(serde_json::from_value::<ProcedureCorpus>(json).is_err());
    }

    #[test]
    fn benign_observables_prove_control_without_requiring_attack_signal() {
        let corpus = procedure_corpus();
        let expected_absences = [
            "no runtime exec audit event",
            "no shell process",
            "no Unix socket connect",
            "no repeated beacon message pattern",
            "no synthetic C2-pattern labels",
            "no canary-data transfer payload",
        ];
        for (index, absence) in expected_absences.iter().enumerate() {
            let pair = &corpus.procedures[index].variants;
            assert_ne!(pair[0].expected.observables, pair[1].expected.observables);
            assert!(pair[1].expected.observables[0].contains(absence));
            let mut drifted = corpus.clone();
            drifted.procedures[index].variants[1].expected.observables =
                pair[0].expected.observables.clone();
            assert!(validate_procedure_corpus(&drifted).is_err());
            let mut drifted = corpus.clone();
            drifted.procedures[index].variants[1]
                .expected
                .product_effect = pair[0].expected.product_effect.clone();
            assert!(validate_procedure_corpus(&drifted).is_err());
        }
    }

    #[test]
    fn modes_stay_distinct_and_unknown_claim_fields_are_rejected() {
        for (mode, expected) in [
            (ProcedureMode::Marker, "\"marker\""),
            (ProcedureMode::Replay, "\"replay\""),
            (ProcedureMode::Behavioral, "\"behavioral\""),
        ] {
            assert_eq!(serde_json::to_string(&mode).unwrap(), expected);
        }
        let mut json = serde_json::to_value(procedure_corpus()).unwrap();
        json["behavioral_coverage"] = true.into();
        assert!(serde_json::from_value::<ProcedureCorpus>(json).is_err());
    }
}
