use asmodeus_crypto::{public_key_from_secret_key, sign_message, SignError};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::time::SystemTime;

use crate::Measurements;

/// Single immutable audit log record of a red team / chaos run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub run_id: String,
    pub scenario_id: String,
    pub scenario_name: String,
    pub category: String,
    pub mitre_technique: String,
    pub mitre_tactic: String,
    pub severity: String,
    pub tag: String,
    pub initiator: String,
    pub runner_id: String,
    pub status: String,
    pub measurements: Measurements,
    pub detection_source: String,
    pub containment_action: String,
    pub cleanup_status: String,
    pub timestamp_utc: String,
    pub signature_hex: String,
    pub public_key_hex: String,
}

impl AuditRecord {
    /// Deterministic canonical byte representation for Ed25519 signing.
    ///
    /// Covers every attestable field of the record (everything except the
    /// signature and public key themselves), using an unambiguous
    /// length-prefixed encoding so that no combination of field values can
    /// collide with another record (e.g. a `:` inside a value can no longer
    /// shift field boundaries).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        fn field(buf: &mut Vec<u8>, value: &str) {
            buf.extend_from_slice(value.len().to_string().as_bytes());
            buf.push(b':');
            buf.extend_from_slice(value.as_bytes());
            buf.push(b'|');
        }

        let mut buf = Vec::new();
        field(&mut buf, &self.run_id);
        field(&mut buf, &self.scenario_id);
        field(&mut buf, &self.scenario_name);
        field(&mut buf, &self.category);
        field(&mut buf, &self.mitre_technique);
        field(&mut buf, &self.mitre_tactic);
        field(&mut buf, &self.severity);
        field(&mut buf, &self.tag);
        field(&mut buf, &self.initiator);
        field(&mut buf, &self.runner_id);
        field(&mut buf, &self.status);
        field(&mut buf, &self.measurements.mttd_ms.to_string());
        field(&mut buf, &self.measurements.mttr_ms.to_string());
        field(&mut buf, &self.measurements.blue_team_detected.to_string());
        field(&mut buf, &self.detection_source);
        field(&mut buf, &self.containment_action);
        field(&mut buf, &self.cleanup_status);
        field(&mut buf, &self.timestamp_utc);
        buf
    }

    /// Sign this audit record using the operator's Ed25519 private key.
    pub fn sign(mut self, secret_key: &[u8]) -> Result<Self, SignError> {
        let canonical = self.canonical_bytes();
        let sig = sign_message(&canonical, secret_key)?;
        let pk = public_key_from_secret_key(secret_key)?;
        self.signature_hex = to_hex(&sig);
        self.public_key_hex = to_hex(&pk);
        Ok(self)
    }

    /// Verify this audit record's digital signature against a *trusted* public
    /// key (the operator / Red Team Lead key held by the control plane).
    ///
    /// This is the authoritative check: it does NOT trust the public key
    /// embedded in the record, so an attacker who rewrites a field and
    /// re-signs with their own keypair (also overwriting `public_key_hex`)
    /// cannot make the record verify.
    pub fn verify_with_key(&self, trusted_public_key: &[u8]) -> bool {
        if self.signature_hex.is_empty() {
            return false;
        }
        let sig = match from_hex(&self.signature_hex) {
            Some(bytes) => bytes,
            None => return false,
        };
        let canonical = self.canonical_bytes();
        asmodeus_crypto::is_valid(&canonical, &sig, trusted_public_key)
    }

    /// Verify this record's signature against the public key embedded in the
    /// record itself.
    ///
    /// This only proves internal self-consistency (the signature matches the
    /// bundled public key) and provides NO tamper-evidence against an actor
    /// who can rewrite the record and re-sign it. Callers that need real
    /// integrity guarantees must use [`verify_with_key`] with a trusted key.
    pub fn verify(&self) -> bool {
        if self.public_key_hex.is_empty() {
            return false;
        }
        let pk = match from_hex(&self.public_key_hex) {
            Some(bytes) => bytes,
            None => return false,
        };
        self.verify_with_key(&pk)
    }
}

/// Thread-safe in-memory collection of audit records.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AuditTrail {
    records: Vec<AuditRecord>,
}

impl AuditTrail {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Append a signed audit record to the journal.
    pub fn append(&mut self, record: AuditRecord) {
        self.records.push(record);
    }

    /// Find an audit record by exact run ID.
    pub fn get(&self, run_id: &str) -> Option<&AuditRecord> {
        self.records.iter().find(|r| r.run_id == run_id)
    }

    /// Filter audit records with optional filters.
    pub fn list(
        &self,
        limit: Option<usize>,
        scenario_id: Option<&str>,
        status: Option<&str>,
    ) -> Vec<AuditRecord> {
        let iter = self.records.iter().rev().filter(|r| {
            if let Some(scen) = scenario_id {
                if !r.scenario_id.eq_ignore_ascii_case(scen) {
                    return false;
                }
            }
            if let Some(st) = status {
                if !r.status.eq_ignore_ascii_case(st) {
                    return false;
                }
            }
            true
        });

        match limit {
            Some(lim) => iter.take(lim).cloned().collect(),
            None => iter.cloned().collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Helper to format current UTC time in ISO-8601 without external dependencies.
pub fn current_utc_iso8601() -> String {
    let now = SystemTime::now();
    let duration = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();
    format_civil_timestamp(secs, millis)
}

fn format_civil_timestamp(secs: u64, millis: u32) -> String {
    let days = secs / 86400;
    let day_secs = secs % 86400;
    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;

    let z = days as i64 + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, m, d, hours, minutes, seconds, millis
    )
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn from_hex(hex_str: &str) -> Option<Vec<u8>> {
    if !hex_str.len().is_multiple_of(2) {
        return None;
    }
    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use asmodeus_crypto::generate_keypair;

    fn sample_record() -> AuditRecord {
        AuditRecord {
            run_id: "run-test-01".to_string(),
            scenario_id: "SCN-RT-001".to_string(),
            scenario_name: "Credential Access Canary".to_string(),
            category: "attack".to_string(),
            mitre_technique: "T1003.008".to_string(),
            mitre_tactic: "Credential Access".to_string(),
            severity: "High".to_string(),
            tag: "ASMODEUS_CANARY_EXERCISE".to_string(),
            initiator: "red_team".to_string(),
            runner_id: "runner-default".to_string(),
            status: "Completed".to_string(),
            measurements: Measurements {
                mttd_ms: 120,
                mttr_ms: 250,
                blue_team_detected: true,
            },
            detection_source: "APEX_SIEM".to_string(),
            containment_action: "Quarantine".to_string(),
            cleanup_status: "VerifiedClean".to_string(),
            timestamp_utc: "2026-09-09T12:00:00.000Z".to_string(),
            signature_hex: String::new(),
            public_key_hex: String::new(),
        }
    }

    #[test]
    fn test_sign_and_verify_audit_record() {
        let (_, sk) = generate_keypair();
        let record = sample_record().sign(&sk).expect("signing should succeed");

        assert!(!record.signature_hex.is_empty());
        assert!(!record.public_key_hex.is_empty());
        assert!(record.verify(), "Record signature must verify successfully");
    }

    #[test]
    fn test_tampered_audit_record_fails_verification() {
        let (_, sk) = generate_keypair();
        let mut record = sample_record().sign(&sk).expect("signing should succeed");

        // Tamper with measurements
        record.measurements.mttd_ms = 99999;
        assert!(
            !record.verify(),
            "Tampered record must fail crypto verification"
        );

        // Tamper with status
        let mut record2 = sample_record().sign(&sk).expect("signing should succeed");
        record2.status = "Failed".to_string();
        assert!(
            !record2.verify(),
            "Tampered status must fail crypto verification"
        );
    }

    #[test]
    fn test_audit_trail_crud_and_filter() {
        let mut trail = AuditTrail::new();
        assert!(trail.is_empty());

        let (_, sk) = generate_keypair();
        let r1 = sample_record().sign(&sk).unwrap();
        let mut r2 = sample_record();
        r2.run_id = "run-test-02".to_string();
        r2.scenario_id = "SCN-CHAOS-001".to_string();
        r2.status = "Failed".to_string();
        let r2 = r2.sign(&sk).unwrap();

        trail.append(r1.clone());
        trail.append(r2.clone());

        assert_eq!(trail.len(), 2);
        assert_eq!(trail.get("run-test-01").unwrap().scenario_id, "SCN-RT-001");
        assert!(trail.get("non-existent").is_none());

        let filtered_by_scen = trail.list(None, Some("scn-rt-001"), None);
        assert_eq!(filtered_by_scen.len(), 1);
        assert_eq!(filtered_by_scen[0].run_id, "run-test-01");

        let filtered_by_status = trail.list(None, None, Some("failed"));
        assert_eq!(filtered_by_status.len(), 1);
        assert_eq!(filtered_by_status[0].run_id, "run-test-02");

        let limited = trail.list(Some(1), None, None);
        assert_eq!(limited.len(), 1);
        assert_eq!(limited[0].run_id, "run-test-02"); // newest first
    }

    #[test]
    fn test_verify_with_key_rejects_forged_re_signed_record() {
        // Legitimate record signed by the trusted operator key.
        let (trusted_pk, trusted_sk) = generate_keypair();
        let record = sample_record().sign(&trusted_sk).expect("sign");
        assert!(record.verify_with_key(&trusted_pk));

        // Attacker rewrites a field and re-signs with their OWN keypair,
        // overwriting both the signature and the embedded public key.
        let (attacker_pk, attacker_sk) = generate_keypair();
        let mut forged = record.clone();
        forged.status = "COMPLETED".to_string();
        forged.cleanup_status = "SUCCESS (nothing to see here)".to_string();
        let forged = forged.sign(&attacker_sk).expect("re-sign");

        // Self-consistent verify() is fooled, but pinning to the trusted key
        // rejects the forgery.
        assert!(
            forged.verify(),
            "self-check verifies the attacker's own key"
        );
        assert_eq!(forged.public_key_hex, to_hex(&attacker_pk));
        assert!(
            !forged.verify_with_key(&trusted_pk),
            "forged record must NOT verify against the trusted key"
        );
    }

    #[test]
    fn test_tampering_unmeasured_fields_breaks_signature() {
        let (pk, sk) = generate_keypair();
        let record = sample_record().sign(&sk).expect("sign");

        // Fields outside the old 9-field canonical set must now be covered.
        for mutate in [
            (|r: &mut AuditRecord| r.cleanup_status = "host artifacts remain".into())
                as fn(&mut AuditRecord),
            |r: &mut AuditRecord| r.detection_source = "NONE".into(),
            |r: &mut AuditRecord| r.containment_action = "ignored".into(),
            |r: &mut AuditRecord| r.severity = "Low".into(),
            |r: &mut AuditRecord| r.mitre_technique = "T0000".into(),
        ] {
            let mut tampered = record.clone();
            mutate(&mut tampered);
            assert!(
                !tampered.verify_with_key(&pk),
                "tampering a signed field must invalidate the signature"
            );
        }
    }

    #[test]
    fn test_timestamp_generation() {
        let ts = current_utc_iso8601();
        assert!(ts.contains('T') && ts.ends_with('Z'));
        assert!(ts.len() >= 20);
    }
}
