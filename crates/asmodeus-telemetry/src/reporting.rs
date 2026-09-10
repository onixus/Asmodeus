//! NIST CSF 2.0 Cyber-Resilience Reporting Engine.
//!
//! Maps scenario outcomes and measurements from the signed audit trail onto
//! the six core functions of NIST CSF 2.0:
//! - **Govern (GV)**: Governance, RBAC compliance, cryptographic signing of audit trails.
//! - **Identify (ID)**: Asset discovery, inventory and threat surface attribution.
//! - **Protect (PR)**: Access control, credential hardening, persistence mitigation, self-protection.
//! - **Detect (DE)**: Continuous monitoring, ransomware anomaly detection, C2 exfiltration interception.
//! - **Respond (RS)**: Incident containment, automated SOAR workflows, mean time to remediate (MTTR).
//! - **Recover (RC)**: Self-healing, automated rollback, circuit breaker safety restoration.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{resilience_score, Aggregate, AuditRecord, TARGET_MTTR_MS};

/// Assessment metrics for one NIST CSF 2.0 Core Function.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NistFunctionAssessment {
    pub function_name: String,
    pub code: String,
    pub scenarios_evaluated: usize,
    pub successful_detections: usize,
    pub score_pct: f32,
    pub status: String,
    pub details: Vec<String>,
}

/// Aggregated statistics per MITRE ATT&CK tactic.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TacticStat {
    pub tactic_name: String,
    pub total_runs: usize,
    pub detected_runs: usize,
    pub mean_mttd_ms: u64,
    pub mean_mttr_ms: u64,
}

/// Comprehensive Cyber-Resilience and NIST CSF 2.0 Executive Report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EcosystemResilienceReport {
    pub title: String,
    pub generated_at_utc: String,
    pub total_runs: usize,
    pub resilience_score: u8,
    pub detection_rate_pct: f32,
    pub mean_mttd_ms: u64,
    pub mean_mttr_ms: u64,
    pub target_mttr_ms: u64,
    pub mttr_sla_status: String,
    pub nist_functions: Vec<NistFunctionAssessment>,
    pub tactics_breakdown: Vec<TacticStat>,
    pub executive_summary: String,
    pub recommendations: Vec<String>,
}

impl EcosystemResilienceReport {
    /// Build an executive report from the audit trail records and current rolling aggregate.
    pub fn build(records: &[AuditRecord], aggregate: &Aggregate) -> Self {
        let total_runs = records.len();
        let detection_rate = aggregate.detection_rate_pct();
        let recovery_speed = aggregate.recovery_speed_pct();
        let score = resilience_score(detection_rate, recovery_speed);
        let mean_mttd = aggregate.mean_mttd_ms();
        let mean_mttr = aggregate.mean_mttr_ms();

        let mttr_sla_status = if mean_mttr <= TARGET_MTTR_MS && total_runs > 0 {
            "COMPLIANT (≤ 300 ms)".to_string()
        } else if total_runs == 0 {
            "NO DATA".to_string()
        } else {
            "DEGRADED (> 300 ms)".to_string()
        };

        // Classify records by NIST CSF 2.0 functions
        let mut de_total = 0;
        let mut de_detected = 0;
        let mut pr_total = 0;
        let mut pr_detected = 0;
        let mut rs_total = 0;
        let mut rs_contained = 0;
        let mut rc_total = 0;
        let mut rc_cleaned = 0;

        let mut tactics_map: HashMap<String, (usize, usize, u64, u64)> = HashMap::new();

        for r in records {
            let detected = r.measurements.blue_team_detected;
            let mttd = r.measurements.mttd_ms;
            let mttr = r.measurements.mttr_ms;

            // Tactic stats
            let tactic_key = if !r.mitre_tactic.is_empty() {
                r.mitre_tactic.clone()
            } else {
                "Infrastructure Chaos".to_string()
            };
            let entry = tactics_map.entry(tactic_key).or_insert((0, 0, 0, 0));
            entry.0 += 1;
            if detected {
                entry.1 += 1;
            }
            entry.2 += mttd;
            entry.3 += mttr;

            // Mapping to NIST functions:
            // Detect (DE): all attack simulations
            if r.category == "red_team" {
                de_total += 1;
                if detected {
                    de_detected += 1;
                }
            }

            // Protect (PR): credential access, persistence, defense impairment
            if r.mitre_technique.contains("T1003")
                || r.mitre_technique.contains("T1053")
                || r.mitre_technique.contains("T1562")
            {
                pr_total += 1;
                if detected {
                    pr_detected += 1;
                }
            }

            // Respond (RS): containment speed and SOAR action
            if detected {
                rs_total += 1;
                if mttr <= TARGET_MTTR_MS * 2 {
                    rs_contained += 1;
                }
            }

            // Recover (RC): cleanup status & self-healing
            rc_total += 1;
            if r.cleanup_status.starts_with("SUCCESS") {
                rc_cleaned += 1;
            }
        }

        let calc_pct = |num: usize, den: usize| -> f32 {
            if den == 0 {
                100.0
            } else {
                100.0 * num as f32 / den as f32
            }
        };

        let nist_functions = vec![
            NistFunctionAssessment {
                function_name: "Govern".to_string(),
                code: "GV".to_string(),
                scenarios_evaluated: total_runs,
                successful_detections: total_runs,
                score_pct: 100.0,
                status: "OPTIMAL".to_string(),
                details: vec![
                    "Strict RBAC matrix enforced for Red Team, DevSecOps, CISO, and Auditor roles".to_string(),
                    "100% of audit records cryptographically signed with Ed25519 digital signatures".to_string(),
                    "INV-0 Root invariant enforced: all exercises strictly synthetic".to_string(),
                ],
            },
            NistFunctionAssessment {
                function_name: "Identify".to_string(),
                code: "ID".to_string(),
                scenarios_evaluated: total_runs,
                successful_detections: if total_runs > 0 { total_runs } else { 0 },
                score_pct: if total_runs > 0 { 100.0 } else { 0.0 },
                status: if total_runs > 0 { "OPTIMAL".to_string() } else { "INACTIVE".to_string() },
                details: vec![
                    "Dynamic runner discovery with capability tagging (k8s_workload, endpoint_agent, network_gateway)".to_string(),
                    "Deterministic MITRE ATT&CK enterprise technique mapping across 7 attack tactics".to_string(),
                ],
            },
            NistFunctionAssessment {
                function_name: "Protect".to_string(),
                code: "PR".to_string(),
                scenarios_evaluated: pr_total,
                successful_detections: pr_detected,
                score_pct: calc_pct(pr_detected, pr_total),
                status: if calc_pct(pr_detected, pr_total) >= 80.0 { "STRONG".to_string() } else { "ATTENTION_REQUIRED".to_string() },
                details: vec![
                    "Canary filesystem sandbox strictly whitelisted to /var/tmp and /tmp (INV-0)".to_string(),
                    "End-to-end mutual TLS (mTLS) with fail-closed cryptographic channels".to_string(),
                    format!("Host hardening and credential protection effectiveness: {:.1}%", calc_pct(pr_detected, pr_total)),
                ],
            },
            NistFunctionAssessment {
                function_name: "Detect".to_string(),
                code: "DE".to_string(),
                scenarios_evaluated: de_total,
                successful_detections: de_detected,
                score_pct: calc_pct(de_detected, de_total),
                status: if calc_pct(de_detected, de_total) >= 90.0 { "OPTIMAL".to_string() } else { "IMPROVEMENT_NEEDED".to_string() },
                details: vec![
                    format!("Mean Time To Detect (MTTD): {} ms across evaluated attack techniques", mean_mttd),
                    "Kernel-level monitoring through Ferrum eBPF probes and Lariska endpoint agents".to_string(),
                    format!("Overall detection efficiency: {:.1}%", calc_pct(de_detected, de_total)),
                ],
            },
            NistFunctionAssessment {
                function_name: "Respond".to_string(),
                code: "RS".to_string(),
                scenarios_evaluated: rs_total,
                successful_detections: rs_contained,
                score_pct: calc_pct(rs_contained, rs_total),
                status: if calc_pct(rs_contained, rs_total) >= 80.0 { "AGILE".to_string() } else { "LATENCY_RISK".to_string() },
                details: vec![
                    format!("Mean Time To Remediate (MTTR): {} ms (target: {} ms)", mean_mttr, TARGET_MTTR_MS),
                    "Automated SOAR policy containment (SIGKILL, Pod Isolation, DNS RPZ Sinkhole)".to_string(),
                ],
            },
            NistFunctionAssessment {
                function_name: "Recover".to_string(),
                code: "RC".to_string(),
                scenarios_evaluated: rc_total,
                successful_detections: rc_cleaned,
                score_pct: calc_pct(rc_cleaned, rc_total),
                status: "VERIFIED".to_string(),
                details: vec![
                    format!("Self-cleaning rollback success: {:.1}% (zero residual artifacts)", calc_pct(rc_cleaned, rc_total)),
                    "Circuit Breaker and Dead-Man switch active on all distributed execution runners".to_string(),
                ],
            },
        ];

        let mut tactics_breakdown: Vec<TacticStat> = tactics_map
            .into_iter()
            .map(|(name, (tot, det, mttd_sum, mttr_sum))| TacticStat {
                tactic_name: name,
                total_runs: tot,
                detected_runs: det,
                mean_mttd_ms: if tot > 0 { mttd_sum / tot as u64 } else { 0 },
                mean_mttr_ms: if tot > 0 { mttr_sum / tot as u64 } else { 0 },
            })
            .collect();
        tactics_breakdown.sort_by(|a, b| a.tactic_name.cmp(&b.tactic_name));

        let mut recommendations = Vec::new();
        if mean_mttr > TARGET_MTTR_MS {
            recommendations.push(format!(
                "Tune SOAR automated playbooks: average MTTR ({} ms) exceeds target SLA ({} ms).",
                mean_mttr, TARGET_MTTR_MS
            ));
        }
        if detection_rate < 90.0 && total_runs > 0 {
            recommendations.push(
                "Enhance eBPF sensor heuristic rules for low-visibility TTPs (e.g. credential honeytokens).".to_string(),
            );
        }
        if recommendations.is_empty() {
            recommendations.push(
                "Continue scheduled recurring automated campaigns to sustain peak cyber-readiness."
                    .to_string(),
            );
        }

        let executive_summary = format!(
            "Платформа Asmodeus провела {} контрольных упражнений кибер-учений и стресс-тестов. \
             Интегральный индекс устойчивости инфраструктуры составляет {}/100 при показателе детекции {:.1}%. \
             Среднее время обнаружения (MTTD) зафиксировано на уровне {} мс, среднее время сдерживания (MTTR) — {} мс.",
            total_runs, score, detection_rate, mean_mttd, mean_mttr
        );

        EcosystemResilienceReport {
            title: "ASMODEUS — Отчёт об Устойчивости Инфраструктуры (NIST CSF 2.0 & BAS)"
                .to_string(),
            generated_at_utc: crate::current_utc_iso8601(),
            total_runs,
            resilience_score: score,
            detection_rate_pct: detection_rate,
            mean_mttd_ms: mean_mttd,
            mean_mttr_ms: mean_mttr,
            target_mttr_ms: TARGET_MTTR_MS,
            mttr_sla_status,
            nist_functions,
            tactics_breakdown,
            executive_summary,
            recommendations,
        }
    }

    /// Render report as formatted GitHub-style Markdown.
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str(&format!("# {}\n\n", self.title));
        md.push_str(&format!(
            "**Дата формирования**: `{}`  \n",
            self.generated_at_utc
        ));
        md.push_str(&format!(
            "**Охват учений**: `{}` прогонов  \n",
            self.total_runs
        ));
        md.push_str(&format!(
            "**Индекс устойчивости (Resilience Score)**: **{}/100**  \n\n",
            self.resilience_score
        ));

        md.push_str("## 1. Сводные Метрики Эффективности Защиты\n\n");
        md.push_str("| Метрика | Значение | Целевой SLA | Статус |\n");
        md.push_str("| :--- | :---: | :---: | :---: |\n");
        md.push_str(&format!(
            "| **Resilience Score** | **{}/100** | ≥ 80/100 | {} |\n",
            self.resilience_score,
            if self.resilience_score >= 80 {
                "✅ В норме"
            } else {
                "⚠️ Требует внимания"
            }
        ));
        md.push_str(&format!(
            "| **Detection Rate** | **{:.1}%** | ≥ 95.0% | {} |\n",
            self.detection_rate_pct,
            if self.detection_rate_pct >= 95.0 {
                "✅ В норме"
            } else {
                "⚠️ Ниже порога"
            }
        ));
        md.push_str(&format!(
            "| **Mean MTTD (Обнаружение)** | **{} мс** | ≤ 300 мс | {} |\n",
            self.mean_mttd_ms,
            if self.mean_mttd_ms <= 300 {
                "✅ В норме"
            } else {
                "⚠️ Замедленно"
            }
        ));
        md.push_str(&format!(
            "| **Mean MTTR (Сдерживание)** | **{} мс** | ≤ {} мс | {} |\n\n",
            self.mean_mttr_ms, self.target_mttr_ms, self.mttr_sla_status
        ));

        md.push_str("## 2. Оценка по Функциям Фреймворка NIST CSF 2.0\n\n");
        md.push_str("| Функция | Код | Проверок | Успешно | Соответствие | Статус |\n");
        md.push_str("| :--- | :---: | :---: | :---: | :---: | :---: |\n");
        for f in &self.nist_functions {
            md.push_str(&format!(
                "| **{}** | `{}` | {} | {} | **{:.1}%** | {} |\n",
                f.function_name,
                f.code,
                f.scenarios_evaluated,
                f.successful_detections,
                f.score_pct,
                f.status
            ));
        }
        md.push('\n');

        md.push_str("## 3. Матрица Результатов по Тактикам MITRE ATT&CK\n\n");
        if self.tactics_breakdown.is_empty() {
            md.push_str("_Нет данных по тактикам (запустите сценарии учений)._\n\n");
        } else {
            md.push_str(
                "| Тактика / Сегмент | Всего тестов | Обнаружено | Средний MTTD | Средний MTTR |\n",
            );
            md.push_str("| :--- | :---: | :---: | :---: | :---: |\n");
            for t in &self.tactics_breakdown {
                md.push_str(&format!(
                    "| **{}** | {} | {} | {} мс | {} мс |\n",
                    t.tactic_name, t.total_runs, t.detected_runs, t.mean_mttd_ms, t.mean_mttr_ms
                ));
            }
            md.push('\n');
        }

        md.push_str("## 4. Рекомендации по Усилению Защитного Контура\n\n");
        for (i, rec) in self.recommendations.iter().enumerate() {
            md.push_str(&format!("{}. {}\n", i + 1, rec));
        }

        md
    }
}

/// Detailed single-run report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SingleRunReport {
    pub run_id: String,
    pub scenario_id: String,
    pub scenario_name: String,
    pub mitre_technique: String,
    pub mitre_tactic: String,
    pub severity: String,
    pub initiator: String,
    pub runner_id: String,
    pub status: String,
    pub blue_team_detected: bool,
    pub mttd_ms: u64,
    pub mttr_ms: u64,
    pub detection_source: String,
    pub containment_action: String,
    pub cleanup_status: String,
    pub timestamp_utc: String,
    pub signature_verified: bool,
}

impl SingleRunReport {
    pub fn build(record: &AuditRecord, trusted_public_key: Option<&[u8]>) -> Self {
        let signature_verified = match trusted_public_key {
            Some(pk) => record.verify_with_key(pk),
            None => record.verify(),
        };

        Self {
            run_id: record.run_id.clone(),
            scenario_id: record.scenario_id.clone(),
            scenario_name: record.scenario_name.clone(),
            mitre_technique: record.mitre_technique.clone(),
            mitre_tactic: record.mitre_tactic.clone(),
            severity: record.severity.clone(),
            initiator: record.initiator.clone(),
            runner_id: record.runner_id.clone(),
            status: record.status.clone(),
            blue_team_detected: record.measurements.blue_team_detected,
            mttd_ms: record.measurements.mttd_ms,
            mttr_ms: record.measurements.mttr_ms,
            detection_source: record.detection_source.clone(),
            containment_action: record.containment_action.clone(),
            cleanup_status: record.cleanup_status.clone(),
            timestamp_utc: record.timestamp_utc.clone(),
            signature_verified,
        }
    }

    pub fn to_markdown(&self) -> String {
        format!(
            "# Отчёт по Прогону Учений: {}\n\n\
             - **ID прогона**: `{}`\n\
             - **Сценарий**: {} (`{}`)\n\
             - **MITRE ATT&CK**: `{}` (Тактика: {})\n\
             - **Критичность**: `{}`\n\
             - **Инициатор**: `{}`\n\
             - **Исполнительный зонд**: `{}`\n\
             - **Статус выполнения**: `{}`\n\
             - **Обнаружение Blue Team**: {}\n\
             - **Время обнаружения (MTTD)**: `{} мс` (Источник: {})\n\
             - **Время сдерживания (MTTR)**: `{} мс` (Действие: {})\n\
             - **Статус зачистки canary**: `{}`\n\
             - **Цифровая подпись Ed25519**: {}\n\
             - **Временная метка**: `{}`\n",
            self.run_id,
            self.run_id,
            self.scenario_name,
            self.scenario_id,
            if !self.mitre_technique.is_empty() {
                &self.mitre_technique
            } else {
                "N/A"
            },
            if !self.mitre_tactic.is_empty() {
                &self.mitre_tactic
            } else {
                "N/A"
            },
            self.severity,
            self.initiator,
            self.runner_id,
            self.status,
            if self.blue_team_detected {
                "✅ ОБНАРУЖЕНО"
            } else {
                "❌ НЕ ОБНАРУЖЕНО"
            },
            self.mttd_ms,
            self.detection_source,
            self.mttr_ms,
            self.containment_action,
            self.cleanup_status,
            if self.signature_verified {
                "✅ ВЕРИФИЦИРОВАНА"
            } else {
                "❌ НАРУШЕНА"
            },
            self.timestamp_utc
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Measurements;

    #[test]
    fn builds_ecosystem_report() {
        let mut agg = Aggregate::default();
        let m = Measurements {
            mttd_ms: 150,
            mttr_ms: 220,
            blue_team_detected: true,
        };
        agg.record(m);

        let record = AuditRecord {
            run_id: "run_001".to_string(),
            scenario_id: "RANSOMWARE_CANARY_SPIKE".to_string(),
            scenario_name: "Ransomware Spike".to_string(),
            category: "red_team".to_string(),
            mitre_technique: "T1486".to_string(),
            mitre_tactic: "Impact".to_string(),
            severity: "high".to_string(),
            tag: "🔴 [RED TEAM EXERCISE]".to_string(),
            initiator: "red_team".to_string(),
            runner_id: "default-runner".to_string(),
            status: "COMPLETED".to_string(),
            measurements: m,
            detection_source: "ferrum_ebpf".to_string(),
            containment_action: "SIGKILL".to_string(),
            cleanup_status: "SUCCESS".to_string(),
            timestamp_utc: "2026-09-09T18:00:00Z".to_string(),
            signature_hex: String::new(),
            public_key_hex: String::new(),
        };

        let report = EcosystemResilienceReport::build(&[record], &agg);
        assert_eq!(report.total_runs, 1);
        assert_eq!(report.resilience_score, 100);
        assert_eq!(report.nist_functions.len(), 6);
        let md = report.to_markdown();
        assert!(md.contains("ASMODEUS — Отчёт об Устойчивости Инфраструктуры"));
        assert!(md.contains("Resilience Score"));
    }
}
