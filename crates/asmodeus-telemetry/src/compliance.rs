//! Compliance and standards coverage mapping for Asmodeus.
//!
//! Maps executed BAS scenarios and audit records to regulatory requirements:
//! - **NIST CSF 2.0**:
//!   - `DE.CM-01`: Networks and environments are monitored to detect potential cybersecurity events.
//!   - `PR.DS-01`: Data-at-rest is protected (e.g. ransomware canary spike T1486).
//!   - `PR.AC-04`: Access permissions and credentials are protected (T1003 honeytokens).
//!   - `RS.RP-01`: Incident response execution and containment SLA (MTTR target).
//! - **PCI-DSS v4.0**:
//!   - `Req 11.4`: External and internal penetration testing / attack simulation.
//!   - `Req 11.5`: Intrusion detection and prevention systems are actively validated.

use serde::{Deserialize, Serialize};

use crate::audit::AuditRecord;

/// Minimal scenario metadata needed for compliance evaluation.
fn default_unspecified() -> String {
    "unspecified".to_string()
}

/// One technique a scenario references, with the fidelity it is exercised at.
/// Stringly typed so telemetry carries no runtime dependency on the DSL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioTechniqueFidelity {
    pub technique_id: String,
    #[serde(default = "default_unspecified")]
    pub fidelity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioMeta {
    pub id: String,
    pub name: String,
    pub category: String,
    /// Primary technique (single-technique projection, back-compat).
    pub mitre_technique: String,
    /// Scenario-level (ceiling) fidelity string
    /// (`behavioral` | `marker_only` | `unspecified`). Defaults to
    /// `unspecified` so a scenario is never assumed behavioural.
    #[serde(default = "default_unspecified")]
    pub fidelity: String,
    /// S01: per-technique fidelity. Prevention/behavioural eligibility for a
    /// control is decided from the fidelity of the **specific matched
    /// technique** here — never from the scenario ceiling — so a scenario that
    /// declares a high ceiling but exercises a given technique only at
    /// marker-only cannot claim prevention of that technique.
    #[serde(default)]
    pub technique_refs: Vec<ScenarioTechniqueFidelity>,
}

impl ScenarioMeta {
    /// True iff this scenario's *ceiling* fidelity is behavioural. Kept for the
    /// single-technique fallback only; control eligibility uses
    /// [`Self::is_behavioral_for_any`].
    pub fn is_behavioral(&self) -> bool {
        self.fidelity == "behavioral"
    }

    /// True iff this scenario references any of `techniques` at all (via the
    /// per-technique refs, or the single primary projection as a fallback).
    pub fn matches_any(&self, techniques: &[&str]) -> bool {
        if self
            .technique_refs
            .iter()
            .any(|r| techniques.contains(&r.technique_id.as_str()))
        {
            return true;
        }
        techniques.contains(&self.mitre_technique.as_str())
    }

    /// True iff this scenario exercises at least one of `techniques` at
    /// behavioural fidelity. Uses the per-technique refs; when none are present
    /// (legacy caller), falls back to the ceiling fidelity paired with the
    /// primary technique.
    pub fn is_behavioral_for_any(&self, techniques: &[&str]) -> bool {
        if !self.technique_refs.is_empty() {
            return self
                .technique_refs
                .iter()
                .any(|r| r.fidelity == "behavioral" && techniques.contains(&r.technique_id.as_str()));
        }
        self.is_behavioral() && techniques.contains(&self.mitre_technique.as_str())
    }
}

/// Regulatory framework or standard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Standard {
    NistCsf2,
    PciDss4,
}

impl Standard {
    pub fn as_str(&self) -> &'static str {
        match self {
            Standard::NistCsf2 => "NIST CSF 2.0",
            Standard::PciDss4 => "PCI-DSS v4.0",
        }
    }
}

/// Individual compliance control assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceControl {
    pub control_id: String,
    pub standard: String,
    pub title: String,
    pub description: String,
    pub mapped_techniques: Vec<String>,
    pub matching_scenarios: Vec<String>,
    /// S01: matching scenarios that run at behavioural fidelity — the only ones
    /// that may support a prevention/behavioural claim for this control.
    #[serde(default)]
    pub behavioral_scenarios: Vec<String>,
    /// S01: matching scenarios that are marker-only / undeclared fidelity. They
    /// prove an indicator is present and detectable, not that the technique's
    /// behaviour ran or was prevented.
    #[serde(default)]
    pub marker_only_scenarios: Vec<String>,
    /// S01: true iff at least one matching scenario is behavioural. When false,
    /// this control has no behavioural/prevention coverage regardless of status.
    #[serde(default)]
    pub prevention_eligible: bool,
    /// S01: present when coverage is marker-only, stating the limitation plainly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_note: Option<String>,
    pub total_runs: usize,
    pub detected_runs: usize,
    pub detection_rate_pct: f32,
    pub status: String,
}

/// Aggregated compliance audit report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub generated_at_utc: String,
    pub total_controls: usize,
    pub compliant_controls: usize,
    pub partial_controls: usize,
    pub non_compliant_controls: usize,
    pub overall_compliance_score: u8,
    pub controls: Vec<ComplianceControl>,
}

impl ComplianceReport {
    /// Generate a compliance report by evaluating registered scenarios and executed audit logs.
    pub fn generate(scenarios: &[ScenarioMeta], records: &[AuditRecord]) -> Self {
        let controls_defs = [
            (
                "NIST-DE.CM-01",
                Standard::NistCsf2,
                "Continuous Monitoring & Event Detection",
                "Networks and computing environments are continuously monitored to detect potential cybersecurity events.",
                vec!["T1071", "T1568", "T1041"],
            ),
            (
                "NIST-PR.DS-01",
                Standard::NistCsf2,
                "Data-at-Rest Protection",
                "Data-at-rest is protected against unauthorized modification or destruction (e.g. ransomware canary validation).",
                vec!["T1486"],
            ),
            (
                "NIST-PR.AC-04",
                Standard::NistCsf2,
                "Credential & Access Protection",
                "Access permissions and authentication credentials are managed and guarded (e.g. honeytoken access canary).",
                vec!["T1003"],
            ),
            (
                "NIST-RS.RP-01",
                Standard::NistCsf2,
                "Incident Response Plan Execution",
                "Response processes and procedures are executed and maintained to contain incidents within target MTTR.",
                vec!["T1486", "T1611", "T1053", "T1562.001"],
            ),
            (
                "PCI-DSS-11.4",
                Standard::PciDss4,
                "Breach & Attack Simulation / Penetration Testing",
                "External and internal penetration testing and attack simulation methodologies are actively validated.",
                vec!["T1486", "T1611", "T1071", "T1003", "T1041"],
            ),
            (
                "PCI-DSS-11.5",
                Standard::PciDss4,
                "Intrusion Detection / Prevention System Validation",
                "Network and host intrusion-detection and/or intrusion-prevention techniques are actively verified.",
                vec!["T1070", "T1053", "T1562.001"],
            ),
        ];

        let mut evaluated_controls = Vec::with_capacity(controls_defs.len());
        let mut compliant_count = 0;
        let mut partial_count = 0;
        let mut non_compliant_count = 0;

        for (cid, std, title, desc, techniques) in controls_defs {
            // Find scenarios matching any of the mapped techniques, split by
            // fidelity so prevention/behavioural coverage can be assessed
            // honestly (S01): a marker-only scenario is matched but never
            // treated as prevention coverage.
            let matched: Vec<&ScenarioMeta> = scenarios
                .iter()
                .filter(|s| s.matches_any(&techniques))
                .collect();
            let matching_scenarios: Vec<String> = matched.iter().map(|s| s.id.clone()).collect();
            // Behavioural/prevention eligibility is decided from the fidelity of
            // the *specific matched technique*, not the scenario ceiling (S01
            // honesty gate; mirrors the per-ref logic in the MITRE matrix).
            let behavioral_scenarios: Vec<String> = matched
                .iter()
                .filter(|s| s.is_behavioral_for_any(&techniques))
                .map(|s| s.id.clone())
                .collect();
            let marker_only_scenarios: Vec<String> = matched
                .iter()
                .filter(|s| !s.is_behavioral_for_any(&techniques))
                .map(|s| s.id.clone())
                .collect();
            let prevention_eligible = !behavioral_scenarios.is_empty();
            let coverage_note = if !matching_scenarios.is_empty() && !prevention_eligible {
                Some(
                    "marker-only coverage: matched scenarios prove indicator detection only, \
                     not behavioural execution or prevention of the mapped technique(s)"
                        .to_string(),
                )
            } else {
                None
            };

            // Find runs matching these scenarios or techniques
            let matching_runs: Vec<&AuditRecord> = records
                .iter()
                .filter(|r| {
                    r.has_confirmed_feedback() && techniques.iter().any(|&t| r.mitre_technique == t)
                })
                .collect();

            let total_runs = matching_runs.len();
            let detected_runs = matching_runs
                .iter()
                .filter(|r| r.measurements.blue_team_detected)
                .count();

            let detection_rate_pct = if total_runs > 0 {
                (detected_runs as f32 / total_runs as f32) * 100.0
            } else {
                0.0
            };

            let status = if matching_scenarios.is_empty() {
                "NOT_TESTED"
            } else if total_runs == 0 {
                "NO_EVIDENCE"
            } else if detection_rate_pct >= 80.0 {
                "COMPLIANT"
            } else if detection_rate_pct >= 40.0 {
                "PARTIAL"
            } else {
                "NON_COMPLIANT"
            };

            match status {
                "COMPLIANT" => compliant_count += 1,
                "PARTIAL" => partial_count += 1,
                // NOT_TESTED and NO_EVIDENCE both mean "no passing evidence"; group
                // them with NON_COMPLIANT so the summary buckets always sum to
                // total_controls (matching the "not fulfilled / no data" label).
                _ => non_compliant_count += 1,
            }

            evaluated_controls.push(ComplianceControl {
                control_id: cid.to_string(),
                standard: std.as_str().to_string(),
                title: title.to_string(),
                description: desc.to_string(),
                mapped_techniques: techniques.into_iter().map(String::from).collect(),
                matching_scenarios,
                behavioral_scenarios,
                marker_only_scenarios,
                prevention_eligible,
                coverage_note,
                total_runs,
                detected_runs,
                detection_rate_pct,
                status: status.to_string(),
            });
        }

        let total = evaluated_controls.len();
        let overall_score = if total > 0 {
            let score_f =
                (compliant_count as f32 * 100.0 + partial_count as f32 * 50.0) / (total as f32);
            score_f.clamp(0.0, 100.0) as u8
        } else {
            0
        };

        Self {
            generated_at_utc: chrono_free_timestamp(),
            total_controls: total,
            compliant_controls: compliant_count,
            partial_controls: partial_count,
            non_compliant_controls: non_compliant_count,
            overall_compliance_score: overall_score,
            controls: evaluated_controls,
        }
    }

    /// Render human-readable Markdown compliance report.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(
            "# Отчет соответствия стандартам кибер-устойчивости (NIST CSF 2.0 / PCI-DSS v4.0)\n\n",
        );
        out.push_str(&format!(
            "- **Дата формирования (UTC)**: `{}`\n",
            self.generated_at_utc
        ));
        out.push_str(&format!(
            "- **Общий индекс комплаенса**: **{}%**\n",
            self.overall_compliance_score
        ));
        out.push_str(&format!(
            "- **Контроли**: всего {}, выполнено {}, частично {}, не выполнено / без данных {}\n\n",
            self.total_controls,
            self.compliant_controls,
            self.partial_controls,
            self.non_compliant_controls
        ));

        out.push_str(
            "| Контроль | Стандарт | Название | MITRE Техники | Прогоны | Детект % | Статус | Покрытие |\n",
        );
        out.push_str("| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :---: |\n");

        for c in &self.controls {
            let status_badge = match c.status.as_str() {
                "COMPLIANT" => "🟢 COMPLIANT",
                "PARTIAL" => "🟡 PARTIAL",
                "NON_COMPLIANT" => "🔴 NON_COMPLIANT",
                "NO_EVIDENCE" => "⚪ NO_EVIDENCE",
                _ => "⚪ NOT_TESTED",
            };
            // S01: fidelity of the coverage — marker-only is flagged so a
            // reader never mistakes indicator detection for prevention.
            let coverage_badge = if c.matching_scenarios.is_empty() {
                "—"
            } else if c.prevention_eligible {
                "behavioural"
            } else {
                "⚠️ marker-only"
            };
            out.push_str(&format!(
                "| **{}** | {} | {} | `{}` | {} | {:.1}% | {} | {} |\n",
                c.control_id,
                c.standard,
                c.title,
                c.mapped_techniques.join(", "),
                c.total_runs,
                c.detection_rate_pct,
                status_badge,
                coverage_badge
            ));
        }

        out.push_str("\n### Описание контролей и рекомендаций\n\n");
        for c in &self.controls {
            out.push_str(&format!("#### {} — {}\n", c.control_id, c.title));
            out.push_str(&format!("- **Стандарт**: {}\n", c.standard));
            out.push_str(&format!("- **Требование**: {}\n", c.description));
            out.push_str(&format!(
                "- **Ассоциированные техники**: {}\n",
                c.mapped_techniques.join(", ")
            ));
            out.push_str(&format!(
                "- **Сценарии в каталоге**: {}\n",
                if c.matching_scenarios.is_empty() {
                    "нет".into()
                } else {
                    c.matching_scenarios.join(", ")
                }
            ));
            out.push_str(&format!("- **Результат валидации**: {} из {} прогонов зафиксированы защитными датчиками ({:.1}%)\n\n", c.detected_runs, c.total_runs, c.detection_rate_pct));
        }

        out
    }

    /// Render formatted JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

fn chrono_free_timestamp() -> String {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = dur.as_secs();
    let days = total_secs / 86400;
    let rem_secs = total_secs % 86400;
    let hours = rem_secs / 3600;
    let minutes = (rem_secs % 3600) / 60;
    let seconds = rem_secs % 60;

    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn days_to_ymd(days_since_epoch: u64) -> (u64, u64, u64) {
    let mut d = days_since_epoch;
    let mut year = 1970;
    loop {
        let leap = is_leap_year(year);
        let days_in_year = if leap { 366 } else { 365 };
        if d < days_in_year {
            break;
        }
        d -= days_in_year;
        year += 1;
    }

    let leap = is_leap_year(year);
    let days_in_months = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];

    let mut month = 1;
    for &dim in &days_in_months {
        if d < dim {
            break;
        }
        d -= dim;
        month += 1;
    }
    let day = d + 1;
    (year, month, day)
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Measurements;

    #[test]
    fn every_mapped_control_technique_is_known_to_the_taxonomy() {
        // S01 CI gate: a control that maps to a stale/mistyped technique ID
        // (the historical T1568 / T1562.001 drift) fails the build here.
        let report = ComplianceReport::generate(&[], &[]);
        for control in &report.controls {
            for tech in &control.mapped_techniques {
                assert!(
                    asmodeus_dsl::is_known_id(tech),
                    "control {} maps to unknown technique {tech}",
                    control.control_id
                );
            }
        }
    }

    #[test]
    fn per_technique_fidelity_overrides_scenario_ceiling_for_prevention() {
        // The exploit the adversarial review found: a scenario with a
        // behavioural *ceiling* that exercises the matched technique (T1486)
        // only at marker-only must NOT make the T1486 control prevention
        // eligible. Eligibility reads the per-technique ref, not the ceiling.
        let crafted = vec![ScenarioMeta {
            id: "DYN-MIXED-001".into(),
            name: "Mixed fidelity".into(),
            category: "red_team".into(),
            mitre_technique: "T1486".into(),
            fidelity: "behavioral".into(), // ceiling claims behavioural
            technique_refs: vec![ScenarioTechniqueFidelity {
                technique_id: "T1486".into(),
                fidelity: "marker_only".into(), // but T1486 is only marker-only
            }],
        }];
        let report = ComplianceReport::generate(&crafted, &[]);
        let ds = report
            .controls
            .iter()
            .find(|c| c.control_id == "NIST-PR.DS-01") // maps T1486
            .unwrap();
        assert!(ds.matching_scenarios.contains(&"DYN-MIXED-001".to_string()));
        assert!(
            !ds.prevention_eligible,
            "marker-only T1486 ref must not be prevention eligible despite behavioural ceiling"
        );
        assert!(ds.coverage_note.is_some());
        assert!(ds.behavioral_scenarios.is_empty());
    }

    #[test]
    fn behavioral_technique_ref_is_prevention_eligible() {
        let crafted = vec![ScenarioMeta {
            id: "DYN-BEH-001".into(),
            name: "Behavioural ransomware".into(),
            category: "red_team".into(),
            mitre_technique: "T1486".into(),
            fidelity: "behavioral".into(),
            technique_refs: vec![ScenarioTechniqueFidelity {
                technique_id: "T1486".into(),
                fidelity: "behavioral".into(),
            }],
        }];
        let report = ComplianceReport::generate(&crafted, &[]);
        let ds = report
            .controls
            .iter()
            .find(|c| c.control_id == "NIST-PR.DS-01")
            .unwrap();
        assert!(ds.prevention_eligible);
        assert!(ds.coverage_note.is_none());
        assert_eq!(ds.behavioral_scenarios, vec!["DYN-BEH-001".to_string()]);
    }

    #[test]
    fn marker_only_control_is_flagged_not_prevention_eligible() {
        // Credential-access control maps to T1003, which is marker-only here.
        let report = ComplianceReport::generate(&sample_scenarios(), &[]);
        let ac = report
            .controls
            .iter()
            .find(|c| c.control_id == "NIST-PR.AC-04")
            .unwrap();
        assert!(ac.matching_scenarios.contains(&"SCN-RT-002".to_string()));
        assert!(!ac.prevention_eligible);
        assert!(ac.coverage_note.is_some());
        assert!(ac.behavioral_scenarios.is_empty());
    }

    fn sample_scenarios() -> Vec<ScenarioMeta> {
        vec![
            ScenarioMeta {
                id: "SCN-RT-001".into(),
                name: "Ransomware".into(),
                category: "red_team".into(),
                mitre_technique: "T1486".into(),
                fidelity: "behavioral".into(),
                technique_refs: vec![ScenarioTechniqueFidelity {
                    technique_id: "T1486".into(),
                    fidelity: "behavioral".into(),
                }],
            },
            ScenarioMeta {
                id: "SCN-RT-002".into(),
                name: "Credential Honeytoken".into(),
                category: "red_team".into(),
                mitre_technique: "T1003".into(),
                fidelity: "marker_only".into(),
                technique_refs: vec![ScenarioTechniqueFidelity {
                    technique_id: "T1003".into(),
                    fidelity: "marker_only".into(),
                }],
            },
            ScenarioMeta {
                id: "SCN-RT-003".into(),
                name: "C2 Beacon".into(),
                category: "red_team".into(),
                mitre_technique: "T1071".into(),
                fidelity: "marker_only".into(),
                technique_refs: vec![ScenarioTechniqueFidelity {
                    technique_id: "T1071".into(),
                    fidelity: "marker_only".into(),
                }],
            },
        ]
    }

    fn sample_record(tech: &str, detected: bool) -> AuditRecord {
        AuditRecord {
            evidence: Some(crate::RunEvidence {
                execution_mode: "runner".into(),
                feedback_received: true,
                contained: true,
                cleanup_confirmed: true,
                failure_reason: None,
            }),
            run_id: "run-comp-1".into(),
            scenario_id: "SCN-RT-001".into(),
            scenario_name: "Test".into(),
            category: "red_team".into(),
            mitre_technique: tech.into(),
            mitre_tactic: "Impact".into(),
            severity: "high".into(),
            tag: "🔴 [RED TEAM EXERCISE]".into(),
            initiator: "admin".into(),
            runner_id: "runner-1".into(),
            status: "COMPLETED".into(),
            measurements: Measurements {
                mttd_ms: 150,
                mttr_ms: 200,
                blue_team_detected: detected,
            },
            detection_source: "ferrum".into(),
            containment_action: "sigkill".into(),
            cleanup_status: "SUCCESS".into(),
            timestamp_utc: "2026-09-09T22:00:00Z".into(),
            signature_hex: "0102".into(),
            public_key_hex: "0304".into(),
        }
    }

    #[test]
    fn test_compliance_report_generation() {
        let scenarios = sample_scenarios();
        let records = vec![
            sample_record("T1486", true),
            sample_record("T1486", true),
            sample_record("T1003", true),
            sample_record("T1071", false),
        ];

        let rep = ComplianceReport::generate(&scenarios, &records);
        assert_eq!(rep.total_controls, 6);
        assert!(rep.overall_compliance_score > 0);

        let pci114 = rep
            .controls
            .iter()
            .find(|c| c.control_id == "PCI-DSS-11.4")
            .unwrap();
        assert_eq!(pci114.total_runs, 4);
        assert_eq!(pci114.detected_runs, 3);
        assert_eq!(pci114.status, "PARTIAL"); // 75% detected, >= 40 and < 80 is PARTIAL

        let nist_pr_ds = rep
            .controls
            .iter()
            .find(|c| c.control_id == "NIST-PR.DS-01")
            .unwrap();
        assert_eq!(nist_pr_ds.detection_rate_pct, 100.0);
        assert_eq!(nist_pr_ds.status, "COMPLIANT");

        let md = rep.to_markdown();
        assert!(md.contains("NIST CSF 2.0 / PCI-DSS v4.0"));
        assert!(md.contains("NIST-PR.DS-01"));

        let json = rep.to_json().unwrap();
        assert!(json.contains("overall_compliance_score"));
    }
}
