//! Fixed six-slot local experiment. This gate never attests product protection.
use crate::{run_local_procedure, LocalAttemptStatus, LocalProcedureAttempt, LocalProcedureConfig};
use asmodeus_dsl::{
    procedure_corpus, ProcedureVariantKind, ATTACK_VERSION, PROCEDURE_CORPUS_VERSION,
};
use serde::{Deserialize, Serialize};
use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LocalSuiteGate {
    Pass,
    Failed,
    Inconclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalSuiteEntry {
    pub procedure_id: String,
    pub procedure_revision: u32,
    pub technique_id: String,
    pub variant: ProcedureVariantKind,
    pub attempt_id: String,
    /// Missing evidence remains in the denominator, with an explicit reason.
    pub evidence: Option<LocalProcedureAttempt>,
    pub gap: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalProcedureSuite {
    pub schema_version: String,
    pub suite_id: String,
    pub corpus_version: String,
    pub corpus_sha256: String,
    pub attack_version: String,
    pub scope: String,
    pub signature_status: String,
    pub slot_denominator: usize,
    pub variant_denominator: usize,
    pub executed_variants: usize,
    pub complete_local_pairs: usize,
    pub fixture_gate: LocalSuiteGate,
    pub protection_result: LocalSuiteGate,
    pub entries: Vec<LocalSuiteEntry>,
    pub limitations: Vec<String>,
}

/// The only inputs select a unique ID and shorten the per-variant deadline.
/// Every corpus slot and both controls are retained, including unsupported ones.
pub fn run_local_procedure_suite(
    suite_id: &str,
    timeout_ms: u64,
    cancel: Arc<AtomicBool>,
) -> io::Result<LocalProcedureSuite> {
    run_suite(suite_id, timeout_ms, cancel, run_local_procedure)
}

fn complete(evidence: &LocalProcedureAttempt) -> bool {
    evidence.status == LocalAttemptStatus::Executed
        && evidence.cleanup.outcome == "VERIFIED"
        && !evidence.receipts.is_empty()
}

fn run_suite(
    suite_id: &str,
    timeout_ms: u64,
    cancel: Arc<AtomicBool>,
    mut execute: impl FnMut(LocalProcedureConfig, Arc<AtomicBool>) -> io::Result<LocalProcedureAttempt>,
) -> io::Result<LocalProcedureSuite> {
    if suite_id.is_empty()
        || suite_id.len() > 48
        || !suite_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "suite ID must contain 1..=48 ASCII letters, digits, hyphens or underscores",
        ));
    }
    if !(1..=10_000).contains(&timeout_ms) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "timeout_ms must be within 1..=10000",
        ));
    }
    let corpus = procedure_corpus();
    let mut entries = Vec::with_capacity(corpus.procedures.len() * 2);
    let mut failed = false;
    for (index, procedure) in corpus.procedures.iter().enumerate() {
        for (suffix, variant) in [
            ("positive", ProcedureVariantKind::Positive),
            ("benign", ProcedureVariantKind::BenignControl),
        ] {
            let attempt_id = format!("{suite_id}-{index}-{suffix}");
            let mut entry = LocalSuiteEntry {
                procedure_id: procedure.id.clone(),
                procedure_revision: procedure.revision,
                technique_id: procedure.technique_id.clone(),
                variant,
                attempt_id: attempt_id.clone(),
                evidence: None,
                gap: None,
            };
            if cancel.load(Ordering::SeqCst) {
                failed = true;
                entry.gap = Some("NOT_RUN: suite cancelled before this variant".into());
            } else {
                let config = LocalProcedureConfig {
                    procedure_id: procedure.id.clone(),
                    attempt_id,
                    variant,
                    timeout_ms,
                };
                match execute(config, cancel.clone()) {
                    Ok(evidence) => {
                        if !complete(&evidence) {
                            if evidence.status != LocalAttemptStatus::Unsupported
                                || evidence.cleanup.outcome != "VERIFIED"
                            {
                                failed = true;
                            }
                            entry.gap = Some(format!(
                                "{:?}: {}; cleanup={}; receipts={}",
                                evidence.status,
                                evidence.detail,
                                evidence.cleanup.outcome,
                                evidence.receipts.len()
                            ));
                        }
                        entry.evidence = Some(evidence);
                    }
                    Err(error) => {
                        failed = true;
                        entry.gap = Some(format!("NOT_RUN: attempt rejected: {error}"));
                    }
                }
            }
            entries.push(entry);
        }
    }
    let executed_variants = entries
        .iter()
        .filter(|e| e.evidence.as_ref().is_some_and(complete))
        .count();
    let complete_local_pairs = entries
        .chunks_exact(2)
        .filter(|pair| {
            pair.iter()
                .all(|e| e.evidence.as_ref().is_some_and(complete))
        })
        .count();
    let fixture_gate = if failed {
        LocalSuiteGate::Failed
    } else if complete_local_pairs == corpus.denominator {
        LocalSuiteGate::Pass
    } else {
        LocalSuiteGate::Inconclusive
    };
    Ok(LocalProcedureSuite {
        schema_version: "asmodeus.local-procedure-suite.v1".into(), suite_id: suite_id.into(),
        corpus_version: PROCEDURE_CORPUS_VERSION.into(),
        corpus_sha256: crate::procedure_local::sha256(include_bytes!("../../asmodeus-dsl/fixtures/procedure-corpus-v1.json")), attack_version: ATTACK_VERSION.into(),
        scope: "LOCAL_FIXTURE: owned loopback receivers only".into(), signature_status: "UNSIGNED".into(),
        slot_denominator: corpus.denominator, variant_denominator: entries.len(),
        executed_variants, complete_local_pairs, fixture_gate,
        protection_result: LocalSuiteGate::Inconclusive, entries,
        limitations: vec![
            "Local receipts do not establish sensor observation, detection, prevention, containment or ATT&CK coverage. Product policy, sensor health and trusted feedback are unverified.".into(),
            "The fixture gate requires all six slots and both variants; unsupported or missing variants cannot yield PASS. A fixture PASS would still leave protection INCONCLUSIVE.".into(),
            "This unsigned local suite is separate from durable signed campaign runs and APEX validation evidence. SIGKILL may prevent report export; crash cleanup remains NOT_VERIFIED. No automatic retry or recovery is performed.".into(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procedure_local::run_in_root;
    use asmodeus_testkit::Polygon;

    fn flag() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    #[test]
    fn paired_suite_retains_all_slots_and_cannot_claim_protection() {
        let root = Polygon::new("local-suite");
        let report = run_suite("paired", 2000, flag(), |config, cancel| {
            run_in_root(config, cancel, root.dir())
        })
        .unwrap();
        assert_eq!(report.slot_denominator, 6);
        assert_eq!(report.variant_denominator, 12);
        assert_eq!(report.executed_variants, 6);
        assert_eq!(report.complete_local_pairs, 3);
        assert_eq!(report.fixture_gate, LocalSuiteGate::Inconclusive);
        assert_eq!(report.protection_result, LocalSuiteGate::Inconclusive);
        assert_eq!(report.entries.iter().filter(|e| e.gap.is_some()).count(), 6);
        for pair in report.entries.chunks_exact(2) {
            assert_eq!(pair[0].procedure_id, pair[1].procedure_id);
            assert_ne!(pair[0].variant, pair[1].variant);
            for entry in pair {
                let evidence = entry.evidence.as_ref().unwrap();
                assert_eq!(evidence.attempt_id, entry.attempt_id);
                assert_eq!(evidence.cleanup.outcome, "VERIFIED");
            }
        }
        let bytes = serde_json::to_vec(&report).unwrap();
        let reloaded: LocalProcedureSuite = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(bytes, serde_json::to_vec(&reloaded).unwrap());
        let repeated = run_suite("paired", 2000, flag(), |config, cancel| {
            run_in_root(config, cancel, root.dir())
        })
        .unwrap();
        assert_eq!(repeated.fixture_gate, LocalSuiteGate::Failed);
        assert!(repeated.entries.iter().all(|e| e.evidence.is_none()));
    }

    #[test]
    fn timeout_rejection_and_cancellation_are_failed_with_full_denominator() {
        let root = Polygon::new("suite-failures");
        let timed = run_suite("timeout", 1, flag(), |config, cancel| {
            run_in_root(config, cancel, root.dir())
        })
        .unwrap();
        assert_eq!(timed.fixture_gate, LocalSuiteGate::Failed);
        let rejected = run_suite("rejected", 1, flag(), |_, _| {
            Err(io::Error::other("reservation unavailable"))
        })
        .unwrap();
        assert_eq!(rejected.fixture_gate, LocalSuiteGate::Failed);
        assert_eq!(rejected.entries.len(), 12);
        let cancel = flag();
        let cancelled = run_suite("cancelled", 2000, cancel, |config, cancel| {
            let evidence = run_in_root(config, cancel.clone(), root.dir())?;
            cancel.store(true, Ordering::SeqCst);
            Ok(evidence)
        })
        .unwrap();
        assert_eq!(cancelled.fixture_gate, LocalSuiteGate::Failed);
        assert_eq!(cancelled.entries.len(), 12);
        assert_eq!(
            cancelled
                .entries
                .iter()
                .filter(|e| e.evidence.is_none())
                .count(),
            11
        );
        assert!(cancelled.entries[1..].iter().all(|e| e
            .gap
            .as_ref()
            .unwrap()
            .contains("cancelled")));
    }

    #[test]
    fn missing_receipts_and_failed_cleanup_turn_gate_red() {
        for fault in ["cleanup", "receipts", "failed"] {
            let root = Polygon::new(&format!("suite-{fault}"));
            let report = run_suite(fault, 2000, flag(), |config, cancel| {
                let mut evidence = run_in_root(config, cancel, root.dir())?;
                if evidence.procedure_id == "synthetic-transfer" {
                    match fault {
                        "cleanup" => evidence.cleanup.outcome = "FAILED".into(),
                        "receipts" => evidence.receipts.clear(),
                        _ => evidence.status = LocalAttemptStatus::Failed,
                    }
                }
                Ok(evidence)
            })
            .unwrap();
            assert_eq!(report.fixture_gate, LocalSuiteGate::Failed, "{fault}");
            assert_eq!(report.complete_local_pairs, 2);
            assert_eq!(report.protection_result, LocalSuiteGate::Inconclusive);
        }
    }

    #[test]
    fn invalid_suite_input_never_dispatches() {
        for (id, timeout) in [
            ("../escape", 100),
            ("", 100),
            ("valid", 0),
            ("valid", 10001),
            (&"a".repeat(49), 100),
        ] {
            assert!(run_suite(id, timeout, flag(), |_, _| panic!(
                "invalid request dispatched"
            ))
            .is_err());
        }
    }
}
