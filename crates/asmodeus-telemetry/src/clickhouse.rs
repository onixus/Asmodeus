//! ClickHouse telemetry integration for Asmodeus.
//!
//! Exposes DDL and serialization methods to pipe signed `AuditRecord`s into
//! the shared APEX ClickHouse telemetry bus (`apex.asmodeus_runs`).
//! Supports batch SQL `INSERT` statements and NDJSON (`JSONEachRow`).

use serde::Serialize;

use crate::audit::AuditRecord;

/// Canonical ClickHouse DDL for the Asmodeus execution audit table.
pub const CLICKHOUSE_DDL: &str = r#"CREATE TABLE IF NOT EXISTS apex.asmodeus_runs (
    run_id String,
    scenario_id LowCardinality(String),
    scenario_name String,
    category LowCardinality(String),
    mitre_technique LowCardinality(String),
    mitre_tactic LowCardinality(String),
    severity LowCardinality(String),
    tag LowCardinality(String),
    initiator LowCardinality(String),
    runner_id LowCardinality(String),
    status LowCardinality(String),
    mttd_ms UInt64,
    mttr_ms UInt64,
    blue_team_detected UInt8,
    detection_source LowCardinality(String),
    containment_action LowCardinality(String),
    cleanup_status LowCardinality(String),
    timestamp String,
    signature_hex String,
    public_key_hex String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(parseDateTimeBestEffort(timestamp))
ORDER BY (category, mitre_technique, timestamp, run_id);"#;

/// Safely escape single quotes and backslashes for ClickHouse SQL literal values.
pub fn escape_sql_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '\'' => out.push_str("''"),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

/// Format a single `AuditRecord` as a ClickHouse SQL VALUES row tuple.
pub fn record_to_sql_row(r: &AuditRecord) -> String {
    format!(
        "('{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', {}, {}, {}, '{}', '{}', '{}', '{}', '{}', '{}')",
        escape_sql_string(&r.run_id),
        escape_sql_string(&r.scenario_id),
        escape_sql_string(&r.scenario_name),
        escape_sql_string(&r.category),
        escape_sql_string(&r.mitre_technique),
        escape_sql_string(&r.mitre_tactic),
        escape_sql_string(&r.severity),
        escape_sql_string(&r.tag),
        escape_sql_string(&r.initiator),
        escape_sql_string(&r.runner_id),
        escape_sql_string(&r.status),
        r.measurements.mttd_ms,
        r.measurements.mttr_ms,
        if r.measurements.blue_team_detected { 1 } else { 0 },
        escape_sql_string(&r.detection_source),
        escape_sql_string(&r.containment_action),
        escape_sql_string(&r.cleanup_status),
        escape_sql_string(&r.timestamp_utc),
        escape_sql_string(&r.signature_hex),
        escape_sql_string(&r.public_key_hex),
    )
}

/// Format a slice of `AuditRecord`s into a complete ClickHouse batch `INSERT` statement.
///
/// Returns an empty string if `records` is empty.
pub fn records_to_clickhouse_sql(records: &[AuditRecord]) -> String {
    if records.is_empty() {
        return String::new();
    }

    let rows: Vec<String> = records.iter().map(record_to_sql_row).collect();
    format!(
        "INSERT INTO apex.asmodeus_runs (\n    run_id, scenario_id, scenario_name, category, mitre_technique, mitre_tactic,\n    severity, tag, initiator, runner_id, status, mttd_ms, mttr_ms, blue_team_detected,\n    detection_source, containment_action, cleanup_status, timestamp, signature_hex, public_key_hex\n) VALUES\n{};\n",
        rows.join(",\n")
    )
}

/// Flattened representation for ClickHouse `JSONEachRow` format.
#[derive(Debug, Clone, Serialize)]
pub struct ClickHouseJsonRow<'a> {
    pub run_id: &'a str,
    pub scenario_id: &'a str,
    pub scenario_name: &'a str,
    pub category: &'a str,
    pub mitre_technique: &'a str,
    pub mitre_tactic: &'a str,
    pub severity: &'a str,
    pub tag: &'a str,
    pub initiator: &'a str,
    pub runner_id: &'a str,
    pub status: &'a str,
    pub mttd_ms: u64,
    pub mttr_ms: u64,
    pub blue_team_detected: u8,
    pub detection_source: &'a str,
    pub containment_action: &'a str,
    pub cleanup_status: &'a str,
    pub timestamp: &'a str,
    pub signature_hex: &'a str,
    pub public_key_hex: &'a str,
}

impl<'a> From<&'a AuditRecord> for ClickHouseJsonRow<'a> {
    fn from(r: &'a AuditRecord) -> Self {
        Self {
            run_id: &r.run_id,
            scenario_id: &r.scenario_id,
            scenario_name: &r.scenario_name,
            category: &r.category,
            mitre_technique: &r.mitre_technique,
            mitre_tactic: &r.mitre_tactic,
            severity: &r.severity,
            tag: &r.tag,
            initiator: &r.initiator,
            runner_id: &r.runner_id,
            status: &r.status,
            mttd_ms: r.measurements.mttd_ms,
            mttr_ms: r.measurements.mttr_ms,
            blue_team_detected: if r.measurements.blue_team_detected {
                1
            } else {
                0
            },
            detection_source: &r.detection_source,
            containment_action: &r.containment_action,
            cleanup_status: &r.cleanup_status,
            timestamp: &r.timestamp_utc,
            signature_hex: &r.signature_hex,
            public_key_hex: &r.public_key_hex,
        }
    }
}

/// Format a slice of `AuditRecord`s as ClickHouse `JSONEachRow` (newline-delimited JSON).
pub fn records_to_clickhouse_ndjson(records: &[AuditRecord]) -> Result<String, serde_json::Error> {
    let mut out = String::new();
    for r in records {
        let row = ClickHouseJsonRow::from(r);
        let line = serde_json::to_string(&row)?;
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Measurements;

    fn sample_record() -> AuditRecord {
        AuditRecord {
            run_id: "run-test-ch-1".into(),
            scenario_id: "SCN-RT-001".into(),
            scenario_name: "Ransomware Spike".into(),
            category: "red_team".into(),
            mitre_technique: "T1486".into(),
            mitre_tactic: "Impact".into(),
            severity: "high".into(),
            tag: "🔴 [RED TEAM EXERCISE]".into(),
            initiator: "red_team_lead".into(),
            runner_id: "runner-node-1".into(),
            status: "COMPLETED".into(),
            measurements: Measurements {
                mttd_ms: 180,
                mttr_ms: 240,
                blue_team_detected: true,
            },
            detection_source: "ferrum_ebpf".into(),
            containment_action: "sigkill_by_kernel".into(),
            cleanup_status: "SUCCESS".into(),
            timestamp_utc: "2026-09-09T22:00:00Z".into(),
            signature_hex: "deadbeef0102".into(),
            public_key_hex: "cafebabe0304".into(),
        }
    }

    #[test]
    fn test_escape_sql_string() {
        assert_eq!(escape_sql_string("plain text"), "plain text");
        assert_eq!(escape_sql_string("it's a test"), "it''s a test");
        assert_eq!(escape_sql_string("line1\nline2"), "line1\\nline2");
        assert_eq!(
            escape_sql_string(r"C:\Windows\System32"),
            r"C:\\Windows\\System32"
        );
    }

    #[test]
    fn test_record_to_sql_row() {
        let r = sample_record();
        let row = record_to_sql_row(&r);
        assert!(row.starts_with("('run-test-ch-1'"));
        assert!(row.contains("'T1486'"));
        assert!(row.contains("180, 240, 1"));
        assert!(row.ends_with("'cafebabe0304')"));
    }

    #[test]
    fn test_records_to_clickhouse_sql_empty() {
        assert_eq!(records_to_clickhouse_sql(&[]), "");
    }

    #[test]
    fn test_records_to_clickhouse_sql_batch() {
        let r1 = sample_record();
        let mut r2 = sample_record();
        r2.run_id = "run-test-ch-2".into();
        r2.measurements.blue_team_detected = false;

        let sql = records_to_clickhouse_sql(&[r1, r2]);
        assert!(sql.starts_with("INSERT INTO apex.asmodeus_runs"));
        assert!(sql.contains("run-test-ch-1"));
        assert!(sql.contains("run-test-ch-2"));
        assert!(sql.ends_with(";\n"));
    }

    #[test]
    fn test_records_to_clickhouse_ndjson() {
        let r1 = sample_record();
        let ndjson = records_to_clickhouse_ndjson(&[r1]).unwrap();
        assert!(ndjson.ends_with('\n'));

        let parsed: serde_json::Value = serde_json::from_str(ndjson.trim()).unwrap();
        assert_eq!(parsed["run_id"], "run-test-ch-1");
        assert_eq!(parsed["blue_team_detected"], 1);
        assert_eq!(parsed["mttd_ms"], 180);
    }
}
