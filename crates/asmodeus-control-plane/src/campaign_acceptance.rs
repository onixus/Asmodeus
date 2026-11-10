//! S04 campaign acceptance for the six first-wave procedure slots.
//!
//! The report keeps the corpus denominator even when slots are UNSUPPORTED or
//! NOT_RUN. It is not a protection gate: marker fidelity cannot paint a
//! technique prevented, and legacy feedback stays unconfirmed.

use asmodeus_dsl::{procedure_corpus, ProcedureCorpus, ProcedureDefinition, ATTACK_VERSION};
use asmodeus_telemetry::{
    legacy_feedback_unconfirmed, observation_trusted, synthetic_ref, AuditRecord, DimensionOutcome,
    ObservationFidelity, ValidationObservation, SCHEMA_VERSION,
};
use serde::Serialize;

pub const PROTECTION_GATE: &str = "NOT_CLAIMED";
pub const X01_FERRUM_BSDM: &str = "NOT_RUN";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AcceptanceGate {
    ACCEPTED,
    FAILED,
    INCONCLUSIVE,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VariantReport {
    pub kind: String,
    pub state: String,
    pub evidence_links: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SlotReport {
    pub procedure_id: String,
    pub technique_id: String,
    pub procedure_revision: u32,
    pub executed: String,
    pub observed: String,
    pub detected: String,
    pub prevented: String,
    pub contained: String,
    pub unconfirmed: bool,
    pub behavioral_coverage: bool,
    pub full_technique_coverage: bool,
    pub applicability: String,
    pub applicability_conditions: Vec<String>,
    pub variants: Vec<VariantReport>,
    pub gaps: Vec<String>,
    pub evidence_links: Vec<String>,
    pub limitations: Vec<String>,
    pub mttd_status: String,
    pub mttd_seconds: Option<u64>,
    pub scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SlotEvidence {
    pub procedure_id: String,
    pub execution_failed: bool,
    pub interrupted: bool,
    pub cleanup_failed: bool,
    pub legacy_feedback: bool,
    pub observation: Option<ValidationObservation>,
    pub mttd_status: Option<String>,
    pub mttd_seconds: Option<u64>,
}

impl SlotEvidence {
    pub fn procedure(procedure_id: impl Into<String>) -> Self {
        Self {
            procedure_id: procedure_id.into(),
            execution_failed: false,
            interrupted: false,
            cleanup_failed: false,
            legacy_feedback: false,
            observation: None,
            mttd_status: None,
            mttd_seconds: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AcceptanceReport {
    pub schema_version: String,
    pub denominator: usize,
    pub variant_denominator: usize,
    pub scope: String,
    pub attack_release: String,
    pub corpus_version: String,
    pub acceptance_gate: AcceptanceGate,
    pub protection_gate: String,
    pub x01_ferrum_bsdm: String,
    pub gate_reasons: Vec<String>,
    pub slots: Vec<SlotReport>,
    pub gaps: Vec<String>,
    pub evidence_links: Vec<String>,
    pub legacy_unconfirmed_runs: u32,
    pub observations: Vec<ValidationObservation>,
}

impl AcceptanceReport {
    pub fn manifest_json(&self) -> String {
        serde_json::to_string(&self.observations).expect("manifest serialization")
    }

    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# Приёмка кампании MITRE (S04)\n\n");
        out.push_str(&format!("Знаменатель: {}\n", self.denominator));
        out.push_str(&format!("Варианты: {}\n", self.variant_denominator));
        out.push_str(&format!("Attack release: {}\n", self.attack_release));
        out.push_str(&format!("Scope: {}\n", self.scope));
        out.push_str(&format!(
            "Gate: {:?} — protection gate: {} — X01: {}\n\n",
            self.acceptance_gate, self.protection_gate, self.x01_ferrum_bsdm
        ));
        out.push_str("## Пробелы\n");
        for gap in &self.gaps {
            out.push_str(&format!("- {gap}\n"));
        }
        out.push_str("\n## Evidence\n");
        if self.evidence_links.is_empty() {
            out.push_str("- нет доверенных наблюдений\n");
        }
        for link in &self.evidence_links {
            out.push_str(&format!("- {link}\n"));
        }
        out.push_str("\n## Слоты\n");
        for slot in &self.slots {
            out.push_str(&format!(
                "\n### {} ({})\n- executed: {}\n- observed: {}\n- detected: {}\n- prevented: {}\n- contained: {}\n- unconfirmed: {}\n- Применимость: {}\n- MTTD: {}\n",
                slot.procedure_id,
                slot.technique_id,
                slot.executed,
                slot.observed,
                slot.detected,
                slot.prevented,
                slot.contained,
                slot.unconfirmed,
                slot.applicability,
                mttd_line(slot),
            ));
            out.push_str("- Условия применимости:\n");
            for condition in &slot.applicability_conditions {
                out.push_str(&format!("  - {condition}\n"));
            }
            for variant in &slot.variants {
                out.push_str(&format!("- Вариант {}: {}\n", variant.kind, variant.state));
            }
        }
        out.push_str(
            "\nЭто не protection gate. Marker-only не является prevention. X01: NOT RUN.\n",
        );
        out
    }
}

pub fn campaign_acceptance(
    evidence: &[SlotEvidence],
    trusted_public_key: &[u8],
) -> AcceptanceReport {
    let corpus = procedure_corpus();
    build_report(&corpus, evidence, trusted_public_key, 0)
}

pub fn acceptance_from_audit(
    records: &[AuditRecord],
    trusted_public_key: &[u8],
) -> AcceptanceReport {
    let corpus = procedure_corpus();
    let mut evidence = Vec::new();
    for procedure in &corpus.procedures {
        let mut slot = SlotEvidence::procedure(&procedure.id);
        let mut best: Option<&ValidationObservation> = None;
        for record in records {
            let Some(ext) = &record.validation else {
                continue;
            };
            let chain = if ext.revisions.is_empty() {
                std::slice::from_ref(&ext.observation)
            } else {
                ext.revisions.as_slice()
            };
            for observation in chain {
                if observation.procedure_id != procedure.id
                    || !trusted_obs(observation, trusted_public_key)
                {
                    continue;
                }
                let replace = best
                    .map(|current| observation.revision >= current.revision)
                    .unwrap_or(true);
                if replace {
                    best = Some(observation);
                    if observation.observation_id == ext.observation.observation_id {
                        slot.mttd_status = Some(ext.mttd.status.clone());
                        slot.mttd_seconds = ext.mttd.seconds;
                    }
                }
            }
        }
        slot.observation = best.cloned();
        evidence.push(slot);
    }
    let legacy_unconfirmed_runs = records
        .iter()
        .filter(|record| legacy_feedback_unconfirmed(record))
        .count() as u32;
    build_report(
        &corpus,
        &evidence,
        trusted_public_key,
        legacy_unconfirmed_runs,
    )
}

fn build_report(
    corpus: &ProcedureCorpus,
    evidence: &[SlotEvidence],
    trusted_public_key: &[u8],
    legacy_unconfirmed_runs: u32,
) -> AcceptanceReport {
    let scope = scope_line();
    let mut slots = Vec::new();
    let mut observations = Vec::new();
    for procedure in &corpus.procedures {
        let supplied = evidence
            .iter()
            .find(|item| item.procedure_id == procedure.id);
        let observation = supplied
            .and_then(|item| item.observation.as_ref())
            .filter(|obs| obs.procedure_id == procedure.id && trusted_obs(obs, trusted_public_key));
        if let Some(obs) = observation {
            observations.push(obs.clone());
        }
        slots.push(slot_report(procedure, supplied, observation, &scope));
    }
    observations.sort_by(|a, b| a.observation_id.cmp(&b.observation_id));
    observations.dedup_by(|a, b| a.observation_id == b.observation_id);
    let mut gaps: Vec<String> = slots.iter().flat_map(|slot| slot.gaps.clone()).collect();
    gaps.sort();
    gaps.dedup();
    let mut evidence_links: Vec<String> = slots
        .iter()
        .flat_map(|slot| slot.evidence_links.clone())
        .collect();
    evidence_links.sort();
    evidence_links.dedup();
    let (acceptance_gate, mut gate_reasons) = judge(&slots);
    if legacy_unconfirmed_runs > 0 {
        gate_reasons.push(format!(
            "legacy feedback unconfirmed: {legacy_unconfirmed_runs}"
        ));
    }
    AcceptanceReport {
        schema_version: SCHEMA_VERSION.into(),
        denominator: corpus.denominator,
        variant_denominator: corpus.procedures.len() * 2,
        scope,
        attack_release: corpus
            .attack_version
            .clone()
            .is_empty()
            .then(|| ATTACK_VERSION.to_string())
            .unwrap_or(corpus.attack_version.clone()),
        corpus_version: corpus.version.clone(),
        acceptance_gate: if legacy_unconfirmed_runs > 0
            && acceptance_gate == AcceptanceGate::ACCEPTED
        {
            AcceptanceGate::INCONCLUSIVE
        } else {
            acceptance_gate
        },
        protection_gate: PROTECTION_GATE.into(),
        x01_ferrum_bsdm: X01_FERRUM_BSDM.into(),
        gate_reasons,
        slots,
        gaps,
        evidence_links,
        legacy_unconfirmed_runs,
        observations,
    }
}

fn slot_report(
    procedure: &ProcedureDefinition,
    supplied: Option<&SlotEvidence>,
    observation: Option<&ValidationObservation>,
    scope: &str,
) -> SlotReport {
    let failed = supplied.is_some_and(|item| item.execution_failed)
        || has_code(observation, "procedure_failed");
    let interrupted =
        supplied.is_some_and(|item| item.interrupted) || has_code(observation, "run_interrupted");
    let cleanup_failed =
        supplied.is_some_and(|item| item.cleanup_failed) || has_code(observation, "cleanup_failed");
    let legacy = supplied.is_some_and(|item| item.legacy_feedback) && observation.is_none();
    let fidelity = observation.map(|obs| obs.fidelity);
    let mut detected = observation
        .map(|obs| obs.dimensions.detection.as_str().to_string())
        .unwrap_or_else(|| "NOT_RUN".into());
    let mut prevented = observation
        .map(|obs| obs.dimensions.prevention.as_str().to_string())
        .unwrap_or_else(|| "NOT_RUN".into());
    let mut contained = observation
        .map(|obs| obs.dimensions.containment.as_str().to_string())
        .unwrap_or_else(|| "NOT_RUN".into());
    if fidelity == Some(ObservationFidelity::Marker)
        || fidelity == Some(ObservationFidelity::TelemetryReplay)
    {
        if prevented == "PASSED" {
            prevented = "NOT_RUN".into();
        }
        if contained == "PASSED" {
            contained = "NOT_RUN".into();
        }
    }
    if legacy {
        detected = "NOT_RUN".into();
        prevented = "NOT_RUN".into();
        contained = "NOT_RUN".into();
    }
    let corpus_unsupported = true;
    let executed = if failed {
        "FAILED"
    } else if interrupted {
        "INTERRUPTED"
    } else if observation.is_some()
        && matches!(detected.as_str(), "PASSED" | "FAILED")
        && !corpus_unsupported_blocks_execution(observation)
    {
        "EXECUTED"
    } else if corpus_unsupported {
        "UNSUPPORTED"
    } else {
        "NOT_RUN"
    };
    let observed = if observation.is_some() {
        "OBSERVED"
    } else {
        "NOT_OBSERVED"
    };
    let conclusive = matches!(detected.as_str(), "PASSED" | "FAILED");
    let unconfirmed = legacy || observation.is_none() || !conclusive || cleanup_failed;
    let behavioral_coverage = fidelity == Some(ObservationFidelity::Behavioral)
        && conclusive
        && !cleanup_failed
        && !interrupted
        && !failed;
    let full_technique_coverage = false;
    let mut gaps = vec![procedure.unsupported_reason.clone()];
    if let Some(extra) = &procedure.gap {
        gaps.push(extra.clone());
    }
    if cleanup_failed {
        gaps.push("cleanup_failed".into());
    }
    if interrupted {
        gaps.push("run_interrupted".into());
    }
    if has_code(observation, "feedback_missing") || (observation.is_none() && !failed) {
        gaps.push("feedback_missing".into());
    }
    if has_code(observation, "stale_policy_digest") {
        gaps.push("stale_policy_digest".into());
    }
    if legacy {
        gaps.push("legacy_feedback_unconfirmed".into());
    }
    let evidence_links = observation
        .map(|obs| vec![obs.observation_id.clone()])
        .unwrap_or_default();
    let attempt = observation.map(|obs| obs.attempt_id.as_str()).unwrap_or("");
    let variants = ["positive", "benign_control"]
        .into_iter()
        .map(|kind| {
            let matched = variant_matches(attempt, kind);
            VariantReport {
                kind: kind.into(),
                state: if matched {
                    executed.into()
                } else {
                    "NOT_RUN".into()
                },
                evidence_links: if matched {
                    evidence_links.clone()
                } else {
                    Vec::new()
                },
            }
        })
        .collect();
    let mttd_status = supplied
        .and_then(|item| item.mttd_status.clone())
        .unwrap_or_else(|| "INCONCLUSIVE".into());
    let mttd_seconds = if mttd_status == "MEASURED" {
        supplied.and_then(|item| item.mttd_seconds)
    } else {
        None
    };
    let applicability = observation
        .map(|obs| obs.dimensions.applicability.as_str().to_string())
        .unwrap_or_else(|| "NOT_APPLICABLE".into());
    SlotReport {
        procedure_id: procedure.id.clone(),
        technique_id: procedure.technique_id.clone(),
        procedure_revision: procedure.revision,
        executed: executed.into(),
        observed: observed.into(),
        detected,
        prevented,
        contained,
        unconfirmed,
        behavioral_coverage,
        full_technique_coverage,
        applicability,
        applicability_conditions: procedure.preconditions.clone(),
        variants,
        gaps,
        evidence_links,
        limitations: observation
            .map(|obs| obs.limitations.clone())
            .unwrap_or_default(),
        mttd_status,
        mttd_seconds,
        scope: scope.into(),
    }
}

fn corpus_unsupported_blocks_execution(observation: Option<&ValidationObservation>) -> bool {
    observation
        .map(|obs| obs.dimensions.validation == DimensionOutcome::UNSUPPORTED)
        .unwrap_or(true)
}

fn has_code(observation: Option<&ValidationObservation>, code: &str) -> bool {
    observation.is_some_and(|obs| obs.limitations.iter().any(|item| item == code))
}

fn variant_matches(attempt_id: &str, kind: &str) -> bool {
    match kind {
        "positive" => attempt_id.ends_with("-positive"),
        "benign_control" => {
            attempt_id.ends_with("-benign") || attempt_id.ends_with("-benign-control")
        }
        _ => false,
    }
}

fn judge(slots: &[SlotReport]) -> (AcceptanceGate, Vec<String>) {
    let mut reasons = Vec::new();
    let mut failed = false;
    for slot in slots {
        if slot.executed == "FAILED" || slot.detected == "FAILED" {
            failed = true;
            reasons.push(format!("{}: failed", slot.procedure_id));
        }
        if slot.executed != "EXECUTED" || slot.unconfirmed || !slot.gaps.is_empty() {
            reasons.push(format!("{}: {}", slot.procedure_id, slot.executed));
        }
        if slot.prevented == "PASSED" && !slot.behavioral_coverage {
            reasons.push(format!("{}: prevention overstated", slot.procedure_id));
        }
    }
    if slots.len() != 6 {
        reasons.push("denominator drifted".into());
    }
    let accepted = slots.len() == 6
        && slots.iter().all(|slot| {
            slot.executed == "EXECUTED"
                && slot.observed == "OBSERVED"
                && !slot.unconfirmed
                && slot.detected == "PASSED"
                && slot.behavioral_coverage
                && slot.gaps.is_empty()
                && slot.full_technique_coverage
        });
    let gate = if failed {
        AcceptanceGate::FAILED
    } else if accepted {
        AcceptanceGate::ACCEPTED
    } else {
        AcceptanceGate::INCONCLUSIVE
    };
    (gate, reasons)
}

fn trusted_obs(observation: &ValidationObservation, trusted_public_key: &[u8]) -> bool {
    observation.schema_version == SCHEMA_VERSION
        && observation_trusted(observation, trusted_public_key)
        && observation
            .evidence_refs
            .iter()
            .all(|item| synthetic_ref(item) == *item)
        && !observation.observation_id.contains("/tmp/")
        && !observation.observation_id.contains("/var/")
}

fn scope_line() -> String {
    "synthetic canary namespace; loopback fixtures only; synthetic data only; real credentials forbidden"
        .into()
}

fn mttd_line(slot: &SlotReport) -> String {
    if slot.mttd_status == "MEASURED" {
        match slot.mttd_seconds {
            Some(seconds) => format!("MEASURED {seconds}s"),
            None => "INCONCLUSIVE".into(),
        }
    } else {
        "INCONCLUSIVE".into()
    }
}

pub(crate) fn catalog_digest() -> String {
    asmodeus_telemetry::sha256_prefixed(
        serde_json::to_string(&procedure_corpus())
            .unwrap_or_default()
            .as_bytes(),
    )
}

pub(crate) fn expected_policy_digest() -> String {
    asmodeus_telemetry::sha256_prefixed(b"asmodeus-validation-policy-v1")
}

pub(crate) fn artifact_digest() -> String {
    asmodeus_telemetry::sha256_prefixed(b"asmodeus-artifact-v1")
}

pub(crate) fn config_digest(tenant: &str) -> String {
    asmodeus_telemetry::sha256_prefixed(
        format!("{tenant}|{SCHEMA_VERSION}|{ATTACK_VERSION}").as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use asmodeus_crypto::generate_keypair;
    use asmodeus_telemetry::{
        admit, AdmitResult, Applicability, AttemptBinding, FeedbackClaim, ObservationFidelity,
        Producer, TelemetryState,
    };

    fn dig(n: u8) -> String {
        format!("sha256:{:064x}", u128::from(n))
    }

    fn binding(procedure: &str, attempt: &str) -> AttemptBinding {
        AttemptBinding {
            tenant_id: "tenant-a".into(),
            environment_ref: "env-lab".into(),
            asset_ref: "asset-1".into(),
            run_id: "run-1".into(),
            attempt_id: attempt.into(),
            procedure_id: procedure.into(),
            procedure_revision: 1,
            technique_id: "T1071.001".into(),
            occurred_at: "2026-11-11T00:00:00Z".into(),
            expires_at: "2026-11-11T00:05:00Z".into(),
        }
    }

    fn claim(procedure: &str, attempt: &str) -> FeedbackClaim {
        let producer = Producer {
            system: "asmodeus".into(),
            version: "0.1.0".into(),
            commit_sha: "0123456789abcdef0123456789abcdef01234567".into(),
            artifact_digest: dig(1),
            config_digest: dig(2),
            policy_digest: dig(3),
        };
        FeedbackClaim {
            tenant_id: "tenant-a".into(),
            environment_ref: "env-lab".into(),
            asset_ref: "asset-1".into(),
            run_id: "run-1".into(),
            attempt_id: attempt.into(),
            procedure_id: procedure.into(),
            procedure_revision: 1,
            technique_id: Some("T9999".into()),
            idempotency_key: format!("idem-{procedure}"),
            observed_at: "2026-11-11T00:00:10Z".into(),
            fidelity: ObservationFidelity::Marker,
            applicability: Applicability::APPLICABLE,
            applicability_reason: None,
            telemetry: TelemetryState::AVAILABLE,
            sensor_healthy: true,
            feedback_present: true,
            queue_loss: false,
            timed_out: false,
            detected: Some(true),
            prevention_claimed: true,
            detect_then_kill: true,
            contained: Some(true),
            policy_stale: false,
            cleanup_failed: false,
            run_interrupted: false,
            procedure_unsupported: false,
            procedure_failed: false,
            trusted: true,
            forged: false,
            evidence_refs: vec!["/tmp/asmodeus-canary/token".into()],
            catalog_digest: dig(4),
            attack_release: ATTACK_VERSION.into(),
            config_digest: producer.config_digest.clone(),
            artifact_digest: producer.artifact_digest.clone(),
            policy_digest: producer.policy_digest.clone(),
            catalog_digest_mismatch: false,
            producer,
        }
    }

    fn signed(
        procedure: &str,
        mutate: impl FnOnce(&mut FeedbackClaim),
    ) -> (ValidationObservation, [u8; 32]) {
        let (pk, sk) = generate_keypair();
        let mut claim = claim(procedure, &format!("attempt-{procedure}-positive"));
        mutate(&mut claim);
        let bound = binding(procedure, &claim.attempt_id);
        let ext = match admit(&bound, &claim, None, &sk) {
            AdmitResult::Admitted(ext) => ext,
            other => panic!("{other:?}"),
        };
        (ext.observation, pk)
    }

    fn report_with(procedure: &str, mutate: impl FnOnce(&mut FeedbackClaim)) -> AcceptanceReport {
        let (observation, pk) = signed(procedure, mutate);
        let mut evidence = SlotEvidence::procedure(procedure);
        evidence.observation = Some(observation);
        evidence.mttd_status = Some("MEASURED".into());
        evidence.mttd_seconds = Some(10);
        campaign_acceptance(&[evidence], &pk)
    }

    #[test]
    fn report_keeps_six_slots_scope_variants_gaps_and_is_not_protection() {
        let report = campaign_acceptance(&[], &[0; 32]);
        assert_eq!(report.denominator, 6);
        assert_eq!(report.variant_denominator, 12);
        assert_eq!(report.attack_release, ATTACK_VERSION);
        assert!(!report.scope.is_empty());
        assert!(!report.scope.contains("/tmp/"));
        assert_eq!(report.protection_gate, "NOT_CLAIMED");
        assert_eq!(report.x01_ferrum_bsdm, "NOT_RUN");
        assert_ne!(report.acceptance_gate, AcceptanceGate::ACCEPTED);
        assert_eq!(report.slots.len(), 6);
        let ids: Vec<_> = report
            .slots
            .iter()
            .map(|s| s.procedure_id.as_str())
            .collect();
        assert_eq!(
            ids,
            [
                "container-exec",
                "shell-execution",
                "runtime-socket-prerequisite",
                "http-beacon",
                "dns-pattern",
                "synthetic-transfer",
            ]
        );
        assert!(report.slots.iter().all(|s| s.variants.len() == 2));
        assert!(report
            .slots
            .iter()
            .all(|s| !s.applicability_conditions.is_empty()));
        assert!(report.gaps.iter().any(|g| g.contains("NOT_RUN")));
        let markdown = report.to_markdown();
        assert!(markdown.contains("Знаменатель: 6"));
        assert!(markdown.contains("Attack release:"));
        assert!(markdown.contains("Scope:"));
        assert!(markdown.contains("Варианты:"));
        assert!(markdown.contains("Пробелы"));
        assert!(markdown.contains("Evidence"));
        assert!(markdown.contains("Применимость"));
        assert!(markdown.contains("protection gate"));
        assert!(markdown.contains("X01: NOT RUN"));
        assert_eq!(report.manifest_json(), report.manifest_json());
        assert_eq!(markdown, report.to_markdown());
    }

    #[test]
    fn marker_does_not_paint_prevention_or_the_whole_technique() {
        let report = report_with("http-beacon", |_| {});
        let slot = report
            .slots
            .iter()
            .find(|s| s.procedure_id == "http-beacon")
            .unwrap();
        assert_eq!(slot.detected, "PASSED");
        assert_ne!(slot.prevented, "PASSED");
        assert_ne!(slot.contained, "PASSED");
        assert!(!slot.behavioral_coverage);
        assert!(!slot.full_technique_coverage);
        assert!(report.slots.iter().all(|s| !s.full_technique_coverage));
        assert!(report
            .slots
            .iter()
            .filter(|s| s.procedure_id != "http-beacon")
            .all(|s| s.detected == "NOT_RUN"));
        assert_ne!(report.acceptance_gate, AcceptanceGate::ACCEPTED);
        assert!(!report.manifest_json().contains("/tmp/"));
        let positive = slot.variants.iter().find(|v| v.kind == "positive").unwrap();
        assert_eq!(positive.state, "EXECUTED");
        let benign = slot
            .variants
            .iter()
            .find(|v| v.kind == "benign_control")
            .unwrap();
        assert_eq!(benign.state, "NOT_RUN");
    }

    #[test]
    fn missing_stale_cleanup_and_interrupt_are_not_green() {
        let missing = report_with("http-beacon", |claim| claim.feedback_present = false);
        assert_ne!(missing.acceptance_gate, AcceptanceGate::ACCEPTED);
        assert!(missing.slots.iter().any(|s| s
            .limitations
            .iter()
            .any(|c| c == "feedback_missing")
            || s.gaps.iter().any(|g| g == "feedback_missing")));

        let stale = report_with("dns-pattern", |claim| claim.policy_stale = true);
        assert_ne!(stale.acceptance_gate, AcceptanceGate::ACCEPTED);
        assert_eq!(
            stale
                .slots
                .iter()
                .find(|s| s.procedure_id == "dns-pattern")
                .unwrap()
                .detected,
            "INCONCLUSIVE"
        );

        let mut cleanup = SlotEvidence::procedure("synthetic-transfer");
        cleanup.cleanup_failed = true;
        let cleanup = campaign_acceptance(&[cleanup], &[0; 32]);
        assert_ne!(cleanup.acceptance_gate, AcceptanceGate::ACCEPTED);
        assert!(cleanup.gaps.iter().any(|g| g == "cleanup_failed"));

        let mut interrupted = SlotEvidence::procedure("container-exec");
        interrupted.interrupted = true;
        let interrupted = campaign_acceptance(&[interrupted], &[0; 32]);
        assert_ne!(interrupted.acceptance_gate, AcceptanceGate::ACCEPTED);
        assert_eq!(
            interrupted
                .slots
                .iter()
                .find(|s| s.procedure_id == "container-exec")
                .unwrap()
                .executed,
            "INTERRUPTED"
        );
    }

    #[test]
    fn deliberate_failure_is_red_and_a_skipped_slot_is_not_success() {
        let mut failed = SlotEvidence::procedure("shell-execution");
        failed.execution_failed = true;
        let failed = campaign_acceptance(&[failed], &[0; 32]);
        assert_eq!(failed.acceptance_gate, AcceptanceGate::FAILED);
        assert_eq!(failed.denominator, 6);
        assert_eq!(
            failed
                .slots
                .iter()
                .find(|s| s.procedure_id == "shell-execution")
                .unwrap()
                .executed,
            "FAILED"
        );

        let partial = report_with("http-beacon", |_| {});
        assert_ne!(partial.acceptance_gate, AcceptanceGate::ACCEPTED);
        assert_eq!(partial.slots.len(), 6);
        assert_ne!(
            partial
                .slots
                .iter()
                .find(|s| s.procedure_id == "shell-execution")
                .unwrap()
                .executed,
            "EXECUTED"
        );
    }

    #[test]
    fn legacy_feedback_stays_unconfirmed_and_export_is_stable() {
        let mut record = asmodeus_telemetry::AuditRecord {
            run_id: "legacy-run".into(),
            scenario_id: "SCN".into(),
            scenario_name: "SCN".into(),
            category: "red_team".into(),
            mitre_technique: "T1071.001".into(),
            mitre_tactic: "Command and Control".into(),
            severity: "medium".into(),
            tag: "exercise".into(),
            initiator: "secops".into(),
            runner_id: "local".into(),
            status: "COMPLETED".into(),
            measurements: asmodeus_telemetry::Measurements {
                mttd_ms: 5,
                mttr_ms: 5,
                blue_team_detected: true,
            },
            detection_source: "operator_feedback".into(),
            containment_action: "operator_confirmed".into(),
            cleanup_status: "SUCCESS".into(),
            timestamp_utc: "2026-11-11T00:00:00Z".into(),
            signature_hex: String::new(),
            public_key_hex: String::new(),
            evidence: Some(asmodeus_telemetry::RunEvidence {
                execution_mode: "runner".into(),
                feedback_received: true,
                contained: true,
                cleanup_confirmed: true,
                failure_reason: None,
            }),
            validation: None,
        };
        record.mitre_technique = "T1071.001".into();
        let report = acceptance_from_audit(std::slice::from_ref(&record), &[0; 32]);
        assert!(report.legacy_unconfirmed_runs >= 1);
        assert!(report.slots.iter().all(|s| s.detected != "PASSED"));
        assert!(report.slots.iter().all(|s| s.prevented != "PASSED"));
        assert_ne!(report.acceptance_gate, AcceptanceGate::ACCEPTED);
        assert_eq!(report.manifest_json(), report.manifest_json());
        assert!(report.manifest_json().starts_with('['));
    }
}
