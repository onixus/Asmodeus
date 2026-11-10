//! S03 trusted validation observations (schema 1.0).
//!
//! The audit journal stays the source of record. [`ValidationObservation`] is a
//! projection: the export boundary rejects extra fields, raw host paths, key
//! material and honeytoken values. Legacy [`crate::RunEvidence`] is never read
//! as a PASS.

use asmodeus_crypto::{public_key_from_secret_key, sign_message};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

use crate::AuditRecord;

pub const SCHEMA_VERSION: &str = "1.0";
pub const MTTD_MAX_SKEW_MS: i64 = 300_000;
pub const SIGNATURE_COVERS: [&str; 4] = ["fidelity", "refs", "results", "provenance"];

const LIMITATION_CODES: &[&str] = &[
    "fidelity_marker_no_prevention",
    "fidelity_marker_no_containment",
    "fidelity_marker_no_behavioral_coverage",
    "telemetry_replay_no_behavioral_coverage",
    "telemetry_replay_no_prevention",
    "telemetry_replay_no_containment",
    "telemetry_unavailable",
    "telemetry_unknown",
    "feedback_missing",
    "queue_loss",
    "timeout",
    "confirmed_miss",
    "detect_then_kill_is_containment",
    "untrusted_producer",
    "forged_signature",
    "cross_tenant",
    "wrong_attempt",
    "technique_only",
    "out_of_window",
    "identity_mismatch",
    "stale_policy_digest",
    "cleanup_failed",
    "run_interrupted",
    "legacy_feedback_unconfirmed",
    "mttd_inconclusive",
    "not_applicable",
    "applicability_reason_required",
    "procedure_unsupported",
    "procedure_failed",
    "sensor_unhealthy",
    "catalog_digest_mismatch",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationFidelity {
    Marker,
    TelemetryReplay,
    Behavioral,
}

impl ObservationFidelity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Marker => "marker",
            Self::TelemetryReplay => "telemetry_replay",
            Self::Behavioral => "behavioral",
        }
    }
}

#[allow(non_camel_case_types)] // wire values: APPLICABLE, NOT_APPLICABLE
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Applicability {
    APPLICABLE,
    NOT_APPLICABLE,
}

impl Applicability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::APPLICABLE => "APPLICABLE",
            Self::NOT_APPLICABLE => "NOT_APPLICABLE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TelemetryState {
    AVAILABLE,
    UNAVAILABLE,
    UNKNOWN,
}

impl TelemetryState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AVAILABLE => "AVAILABLE",
            Self::UNAVAILABLE => "UNAVAILABLE",
            Self::UNKNOWN => "UNKNOWN",
        }
    }
}

#[allow(non_camel_case_types)] // wire values: NOT_RUN, NOT_APPLICABLE
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DimensionOutcome {
    NOT_RUN,
    INCONCLUSIVE,
    FAILED,
    PASSED,
    STALE,
    NOT_APPLICABLE,
    UNSUPPORTED,
}

impl DimensionOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NOT_RUN => "NOT_RUN",
            Self::INCONCLUSIVE => "INCONCLUSIVE",
            Self::FAILED => "FAILED",
            Self::PASSED => "PASSED",
            Self::STALE => "STALE",
            Self::NOT_APPLICABLE => "NOT_APPLICABLE",
            Self::UNSUPPORTED => "UNSUPPORTED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Producer {
    pub system: String,
    pub version: String,
    pub commit_sha: String,
    pub artifact_digest: String,
    pub config_digest: String,
    pub policy_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dimensions {
    pub applicability: Applicability,
    /// Omitted when absent. The observation schema rejects JSON null and
    /// requires the string when applicability is NOT_APPLICABLE.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applicability_reason: Option<String>,
    pub telemetry: TelemetryState,
    pub detection: DimensionOutcome,
    pub prevention: DimensionOutcome,
    pub containment: DimensionOutcome,
    pub validation: DimensionOutcome,
}

impl Dimensions {
    pub fn any_passed(&self) -> bool {
        matches!(self.detection, DimensionOutcome::PASSED)
            || matches!(self.prevention, DimensionOutcome::PASSED)
            || matches!(self.containment, DimensionOutcome::PASSED)
            || matches!(self.validation, DimensionOutcome::PASSED)
    }

    fn not_run(applicability: Applicability, telemetry: TelemetryState) -> Self {
        Self {
            applicability,
            applicability_reason: None,
            telemetry,
            detection: DimensionOutcome::NOT_RUN,
            prevention: DimensionOutcome::NOT_RUN,
            containment: DimensionOutcome::NOT_RUN,
            validation: DimensionOutcome::NOT_RUN,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResourceKind {
    Asset,
    Evidence,
}

impl ResourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Asset => "asset",
            Self::Evidence => "evidence",
        }
    }
}

/// Canonical resource reference. `urn` is `urn:apex:{kind}:{source}:{local_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRef {
    pub urn: String,
    pub kind: ResourceKind,
    pub source: String,
    pub local_id: String,
}

impl ResourceRef {
    fn new(kind: ResourceKind, source: &str, local_id: &str) -> Result<Self, String> {
        if !is_source(source) || !is_local_id(local_id) {
            return Err("resource ref does not match schema".into());
        }
        let urn = format!("urn:apex:{}:{source}:{local_id}", kind.as_str());
        if split_apex_urn(&urn, kind.as_str()).is_none() {
            return Err("resource ref does not match schema".into());
        }
        Ok(Self {
            urn,
            kind,
            source: source.to_string(),
            local_id: local_id.to_string(),
        })
    }

    fn parse(urn: &str, kind: ResourceKind) -> Option<Self> {
        let (source, local_id) = split_apex_urn(urn, kind.as_str())?;
        Some(Self {
            urn: urn.to_string(),
            kind,
            source: source.to_string(),
            local_id: local_id.to_string(),
        })
    }

    fn consistent(&self) -> bool {
        self.urn
            == format!(
                "urn:apex:{}:{}:{}",
                self.kind.as_str(),
                self.source,
                self.local_id
            )
            && split_apex_urn(&self.urn, self.kind.as_str()).is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub trusted_key_id: String,
    pub signature_hex: String,
    pub signature_covers: Vec<String>,
}

/// Export shape. Field set is closed; serializers must not grow it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationObservation {
    pub schema_version: String,
    pub observation_id: ResourceRef,
    pub producer: Producer,
    pub tenant_id: String,
    pub asset_ref: ResourceRef,
    pub environment_ref: String,
    pub run_id: String,
    pub attempt_id: String,
    pub procedure_id: String,
    pub procedure_revision: u32,
    pub idempotency_key: String,
    pub revision: u32,
    /// Previous evidence URN, or JSON null when this is the first revision.
    pub supersedes: Option<String>,
    pub occurred_at: String,
    pub observed_at: String,
    pub expires_at: String,
    pub catalog_digest: String,
    pub attack_release: String,
    pub fidelity: ObservationFidelity,
    pub dimensions: Dimensions,
    pub provenance: Provenance,
    pub evidence_refs: Vec<ResourceRef>,
    pub limitations: Vec<String>,
}

impl ValidationObservation {
    /// Length-prefixed preimage. Resource refs contribute their wire fields
    /// (`urn`, `kind`, `source`, `local_id`), not Debug output. `signature_hex`
    /// is excluded so the signature can cover provenance metadata without
    /// signing itself. `supersedes` is the previous URN or empty.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        field(&mut buf, &self.schema_version);
        write_ref(&mut buf, &self.observation_id);
        field(&mut buf, &self.producer.system);
        field(&mut buf, &self.producer.version);
        field(&mut buf, &self.producer.commit_sha);
        field(&mut buf, &self.producer.artifact_digest);
        field(&mut buf, &self.producer.config_digest);
        field(&mut buf, &self.producer.policy_digest);
        field(&mut buf, &self.tenant_id);
        write_ref(&mut buf, &self.asset_ref);
        field(&mut buf, &self.environment_ref);
        field(&mut buf, &self.run_id);
        field(&mut buf, &self.attempt_id);
        field(&mut buf, &self.procedure_id);
        field(&mut buf, &self.procedure_revision.to_string());
        field(&mut buf, &self.idempotency_key);
        field(&mut buf, &self.revision.to_string());
        field(&mut buf, self.supersedes.as_deref().unwrap_or(""));
        field(&mut buf, &self.occurred_at);
        field(&mut buf, &self.observed_at);
        field(&mut buf, &self.expires_at);
        field(&mut buf, &self.catalog_digest);
        field(&mut buf, &self.attack_release);
        field(&mut buf, self.fidelity.as_str());
        field(&mut buf, self.dimensions.applicability.as_str());
        field(
            &mut buf,
            self.dimensions
                .applicability_reason
                .as_deref()
                .unwrap_or(""),
        );
        field(&mut buf, self.dimensions.telemetry.as_str());
        field(&mut buf, self.dimensions.detection.as_str());
        field(&mut buf, self.dimensions.prevention.as_str());
        field(&mut buf, self.dimensions.containment.as_str());
        field(&mut buf, self.dimensions.validation.as_str());
        field(&mut buf, &self.provenance.trusted_key_id);
        field(&mut buf, &self.provenance.signature_covers.join(","));
        field(&mut buf, &self.evidence_refs.len().to_string());
        for item in &self.evidence_refs {
            write_ref(&mut buf, item);
        }
        field(&mut buf, &self.limitations.join(","));
        buf
    }

    pub fn export_json(&self) -> String {
        serde_json::to_string(self).expect("observation serialization")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MttdAssessment {
    pub status: String,
    pub seconds: Option<u64>,
    pub reason: Option<String>,
}

impl MttdAssessment {
    fn inconclusive(reason: &str) -> Self {
        Self {
            status: "INCONCLUSIVE".into(),
            seconds: None,
            reason: Some(reason.into()),
        }
    }

    pub fn is_numeric(&self) -> bool {
        self.status == "MEASURED" && self.seconds.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdempotencyEntry {
    pub key: String,
    pub body_hash: String,
    pub observation_id: String,
    pub revision: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptBinding {
    pub tenant_id: String,
    pub environment_ref: String,
    pub asset_ref: String,
    pub run_id: String,
    pub attempt_id: String,
    pub procedure_id: String,
    pub procedure_revision: u32,
    pub technique_id: String,
    pub occurred_at: String,
    pub expires_at: String,
}

/// Versioned extension stored on the audit record. Not an export document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationExtension {
    pub binding: AttemptBinding,
    /// Newest trusted revision.
    pub observation: ValidationObservation,
    /// Full chain carried by the tip so reload does not drop superseded bodies.
    pub revisions: Vec<ValidationObservation>,
    pub mttd: MttdAssessment,
    pub ledger: Vec<IdempotencyEntry>,
    pub body_hash: String,
}

#[derive(Debug, Clone)]
pub struct FeedbackClaim {
    pub tenant_id: String,
    pub environment_ref: String,
    pub asset_ref: String,
    pub run_id: String,
    pub attempt_id: String,
    pub procedure_id: String,
    pub procedure_revision: u32,
    pub technique_id: Option<String>,
    pub idempotency_key: String,
    pub observed_at: String,
    pub fidelity: ObservationFidelity,
    pub applicability: Applicability,
    pub applicability_reason: Option<String>,
    pub telemetry: TelemetryState,
    pub sensor_healthy: bool,
    pub feedback_present: bool,
    pub queue_loss: bool,
    pub timed_out: bool,
    pub detected: Option<bool>,
    pub prevention_claimed: bool,
    pub detect_then_kill: bool,
    pub contained: Option<bool>,
    pub policy_stale: bool,
    pub cleanup_failed: bool,
    pub run_interrupted: bool,
    pub procedure_unsupported: bool,
    pub procedure_failed: bool,
    pub trusted: bool,
    pub forged: bool,
    pub evidence_refs: Vec<String>,
    pub catalog_digest: String,
    pub attack_release: String,
    pub producer: Producer,
    pub config_digest: String,
    pub artifact_digest: String,
    pub policy_digest: String,
    pub catalog_digest_mismatch: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Correlation {
    Match,
    CrossTenant,
    WrongAttempt,
    TechniqueOnly,
    OutOfWindow,
    IdentityMismatch,
}

impl Correlation {
    pub fn code(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::CrossTenant => "cross_tenant",
            Self::WrongAttempt => "wrong_attempt",
            Self::TechniqueOnly => "technique_only",
            Self::OutOfWindow => "out_of_window",
            Self::IdentityMismatch => "identity_mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub correlation: Correlation,
    pub linked: bool,
    pub dimensions: Dimensions,
    pub limitations: Vec<String>,
    pub mttd: MttdAssessment,
    pub behavioral_coverage: bool,
    pub applicability_reason: Option<String>,
}

impl Decision {
    pub fn any_passed(&self) -> bool {
        self.dimensions.any_passed()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // the admitted document is returned by value
pub enum AdmitResult {
    Admitted(ValidationExtension),
    Duplicate(ValidationObservation),
    Replay,
    Unlinked(Decision),
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationPage {
    pub schema_version: String,
    pub limit: usize,
    pub cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub observations: Vec<ValidationObservation>,
}

pub fn sha256_prefixed(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut out = String::from("sha256:");
    for byte in digest.as_ref() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub fn is_sha256_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn is_commit_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Id of a trusted public key, derived from that key's bytes.
/// Not read from an audit record's embedded `public_key_hex`.
/// `sha256:` plus 64 hex matches the observation token pattern, so the value
/// is not rewritten to `asmodeus:<32 hex>`.
pub fn trusted_key_id(public_key: &[u8]) -> String {
    sha256_prefixed(public_key)
}

pub fn synthetic_ref(raw: &str) -> String {
    if let Some(hex) = raw.strip_prefix("urn:apex:evidence:asmodeus:ref:") {
        if hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return raw.to_string();
        }
    }
    let digest = sha256_prefixed(raw.as_bytes());
    let hex = digest.trim_start_matches("sha256:");
    format!("urn:apex:evidence:asmodeus:ref:{hex}")
}

fn evidence_resource_ref(raw: &str) -> Result<ResourceRef, String> {
    let urn = synthetic_ref(raw);
    let local_id = urn
        .strip_prefix("urn:apex:evidence:asmodeus:")
        .ok_or("evidence ref is not an asmodeus urn")?;
    ResourceRef::new(ResourceKind::Evidence, "asmodeus", local_id)
}

fn asset_resource_ref(raw: &str) -> Result<ResourceRef, String> {
    if let Some(parsed) = ResourceRef::parse(raw, ResourceKind::Asset) {
        return Ok(parsed);
    }
    if raw.starts_with("urn:") || !is_local_id(raw) {
        return Err("asset_ref does not match schema".into());
    }
    ResourceRef::new(ResourceKind::Asset, "asmodeus", raw)
}

fn environment_urn(raw: &str) -> Result<String, String> {
    if split_apex_urn(raw, "environment").is_some() {
        return Ok(raw.to_string());
    }
    if raw.starts_with("urn:") || !is_local_id(raw) {
        return Err("environment_ref does not match schema".into());
    }
    Ok(format!("urn:apex:environment:asmodeus:{raw}"))
}

fn observation_ref(run_id: &str, attempt_id: &str, revision: u32) -> Result<ResourceRef, String> {
    let local_id = format!("{run_id}:{attempt_id}:r{revision}");
    ResourceRef::new(ResourceKind::Evidence, "asmodeus", &local_id)
}

/// `attackRelease` is an identifier. Display text such as the pinned ATT&CK
/// label is folded to a stable token; values that already match pass through.
fn schema_attack_release(raw: &str) -> Result<String, String> {
    if is_attack_release(raw) {
        return Ok(raw.to_string());
    }
    let mut out = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' {
            out.push(ch);
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    while out.ends_with('-') || out.ends_with('.') || out.ends_with('_') {
        out.pop();
    }
    if out.len() > 64 {
        out.truncate(64);
        while out.ends_with('-') || out.ends_with('.') || out.ends_with('_') {
            out.pop();
        }
    }
    if is_attack_release(&out) {
        Ok(out)
    } else {
        Err("attack_release does not match schema".into())
    }
}

pub fn claim_body_hash(claim: &FeedbackClaim) -> String {
    sha256_prefixed(&claim_canonical(claim))
}

/// Bytes a presented producer signature is checked against. Trust flags are
/// part of the preimage so a forged re-label cannot reuse an honest signature.
pub fn claim_signing_bytes(claim: &FeedbackClaim) -> Vec<u8> {
    claim_canonical(claim)
}

/// Verify against the control-plane key. The embedded audit `public_key_hex`
/// is intentionally not an input.
pub fn observation_trusted(observation: &ValidationObservation, trusted_public_key: &[u8]) -> bool {
    if observation.provenance.signature_hex.is_empty() {
        return false;
    }
    let Some(sig) = from_hex(&observation.provenance.signature_hex) else {
        return false;
    };
    asmodeus_crypto::is_valid(&observation.canonical_bytes(), &sig, trusted_public_key)
}

pub fn sign_observation(
    observation: &mut ValidationObservation,
    secret_key: &[u8],
) -> Result<(), String> {
    let public_key = public_key_from_secret_key(secret_key).map_err(|e| e.to_string())?;
    observation.provenance.trusted_key_id = trusted_key_id(&public_key);
    observation.provenance.signature_hex.clear();
    let canonical = observation.canonical_bytes();
    let sig = sign_message(&canonical, secret_key).map_err(|e| e.to_string())?;
    observation.provenance.signature_hex = to_hex(&sig);
    Ok(())
}

pub fn legacy_feedback_unconfirmed(record: &AuditRecord) -> bool {
    record.validation.is_none()
        && record
            .evidence
            .as_ref()
            .is_some_and(|evidence| evidence.feedback_received)
}

pub fn stage_revision(record: &AuditRecord, trusted_public_key: &[u8]) -> Option<String> {
    let ext = record.validation.as_ref()?;
    exportable(&ext.observation, trusted_public_key)
        .then(|| ext.observation.observation_id.urn.clone())
}

/// Tip revision seen by a rebuilt aggregate. Same id as [`stage_revision`]
/// after reload, because both read the collapsed trusted record.
pub fn aggregate_revision(
    records: &[AuditRecord],
    run_id: &str,
    trusted_public_key: &[u8],
) -> Option<String> {
    records
        .iter()
        .filter(|record| record.run_id == run_id)
        .filter_map(|record| record.validation.as_ref())
        .flat_map(|ext| {
            let chain = if ext.revisions.is_empty() {
                std::slice::from_ref(&ext.observation)
            } else {
                ext.revisions.as_slice()
            };
            chain
                .iter()
                .filter(|observation| exportable(observation, trusted_public_key))
                .map(|observation| (observation.revision, observation.observation_id.urn.clone()))
        })
        .max_by_key(|(revision, _)| *revision)
        .map(|(_, id)| id)
}

pub fn export_observations(
    records: &[AuditRecord],
    trusted_public_key: &[u8],
    cursor: Option<&str>,
    limit: Option<usize>,
) -> ObservationPage {
    let mut observations = Vec::new();
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
            if exportable(observation, trusted_public_key) {
                observations.push(observation.clone());
            }
        }
    }
    observations.sort_by(|a, b| a.observation_id.urn.cmp(&b.observation_id.urn));
    observations.dedup_by(|a, b| a.observation_id.urn == b.observation_id.urn);
    if let Some(cursor) = cursor {
        observations.retain(|obs| obs.observation_id.urn.as_str() > cursor);
    }
    let limit = limit.unwrap_or(100).clamp(1, 500);
    let next_cursor = if observations.len() > limit {
        Some(observations[limit - 1].observation_id.urn.clone())
    } else {
        None
    };
    observations.truncate(limit);
    ObservationPage {
        schema_version: SCHEMA_VERSION.into(),
        limit,
        cursor: cursor.map(str::to_string),
        next_cursor,
        observations,
    }
}

pub fn export_page_json(page: &ObservationPage) -> String {
    serde_json::to_string(page).expect("export serialization")
}

pub fn decide(binding: &AttemptBinding, claim: &FeedbackClaim) -> Decision {
    let correlation = correlate(binding, claim);
    let linked = correlation == Correlation::Match;
    let mttd = assess_mttd(&binding.occurred_at, &claim.observed_at);
    let mut limitations = Vec::new();
    if !linked {
        push_code(&mut limitations, correlation.code());
    }
    if !mttd.is_numeric() {
        push_code(&mut limitations, "mttd_inconclusive");
    }
    let mut dimensions = Dimensions::not_run(claim.applicability, claim.telemetry);
    let mut reason = None;

    let untrusted = !claim.trusted || claim.forged || claim.producer.system != "asmodeus";
    if untrusted {
        push_code(
            &mut limitations,
            if claim.forged || claim.producer.system != "asmodeus" {
                "forged_signature"
            } else {
                "untrusted_producer"
            },
        );
        if linked {
            dimensions.detection = DimensionOutcome::INCONCLUSIVE;
            dimensions.validation = DimensionOutcome::INCONCLUSIVE;
        }
        return finish(
            claim,
            correlation,
            linked,
            dimensions,
            limitations,
            mttd,
            reason,
        );
    }
    if !linked {
        dimensions.validation = DimensionOutcome::INCONCLUSIVE;
        return finish(
            claim,
            correlation,
            linked,
            dimensions,
            limitations,
            mttd,
            reason,
        );
    }
    if claim.applicability == Applicability::NOT_APPLICABLE {
        if let Some(text) = sanitized_reason(claim.applicability_reason.as_deref()) {
            reason = Some(text);
            dimensions.applicability_reason = reason.clone();
            dimensions.detection = DimensionOutcome::NOT_APPLICABLE;
            dimensions.prevention = DimensionOutcome::NOT_APPLICABLE;
            dimensions.containment = DimensionOutcome::NOT_APPLICABLE;
            dimensions.validation = DimensionOutcome::NOT_APPLICABLE;
            push_code(&mut limitations, "not_applicable");
        } else {
            push_code(&mut limitations, "applicability_reason_required");
            dimensions.validation = DimensionOutcome::INCONCLUSIVE;
            dimensions.applicability_reason = None;
        }
        return finish(
            claim,
            correlation,
            linked,
            dimensions,
            limitations,
            mttd,
            reason,
        );
    }
    dimensions.applicability_reason = None;
    if claim.procedure_unsupported {
        push_code(&mut limitations, "procedure_unsupported");
        dimensions.validation = DimensionOutcome::UNSUPPORTED;
        return finish(
            claim,
            correlation,
            linked,
            dimensions,
            limitations,
            mttd,
            reason,
        );
    }
    if claim.procedure_failed {
        push_code(&mut limitations, "procedure_failed");
        dimensions.validation = DimensionOutcome::FAILED;
        return finish(
            claim,
            correlation,
            linked,
            dimensions,
            limitations,
            mttd,
            reason,
        );
    }
    if claim.policy_stale {
        push_code(&mut limitations, "stale_policy_digest");
        dimensions.validation = DimensionOutcome::STALE;
        dimensions.detection = DimensionOutcome::INCONCLUSIVE;
        return finish(
            claim,
            correlation,
            linked,
            dimensions,
            limitations,
            mttd,
            reason,
        );
    }
    if claim.catalog_digest_mismatch {
        push_code(&mut limitations, "catalog_digest_mismatch");
        dimensions.validation = DimensionOutcome::INCONCLUSIVE;
        dimensions.detection = DimensionOutcome::INCONCLUSIVE;
        return finish(
            claim,
            correlation,
            linked,
            dimensions,
            limitations,
            mttd,
            reason,
        );
    }
    if claim.run_interrupted {
        push_code(&mut limitations, "run_interrupted");
        dimensions.validation = DimensionOutcome::INCONCLUSIVE;
        dimensions.detection = DimensionOutcome::INCONCLUSIVE;
        return finish(
            claim,
            correlation,
            linked,
            dimensions,
            limitations,
            mttd,
            reason,
        );
    }
    if !claim.feedback_present {
        push_code(&mut limitations, "feedback_missing");
        dimensions.detection = DimensionOutcome::NOT_RUN;
        dimensions.validation = DimensionOutcome::NOT_RUN;
        return finish(
            claim,
            correlation,
            linked,
            dimensions,
            limitations,
            mttd,
            reason,
        );
    }
    if claim.telemetry == TelemetryState::UNAVAILABLE {
        push_code(&mut limitations, "telemetry_unavailable");
        dimensions.detection = DimensionOutcome::INCONCLUSIVE;
        dimensions.validation = DimensionOutcome::INCONCLUSIVE;
        return finish(
            claim,
            correlation,
            linked,
            dimensions,
            limitations,
            mttd,
            reason,
        );
    }
    if claim.telemetry == TelemetryState::UNKNOWN {
        push_code(&mut limitations, "telemetry_unknown");
        dimensions.detection = DimensionOutcome::INCONCLUSIVE;
        dimensions.validation = DimensionOutcome::INCONCLUSIVE;
        return finish(
            claim,
            correlation,
            linked,
            dimensions,
            limitations,
            mttd,
            reason,
        );
    }
    if claim.queue_loss {
        push_code(&mut limitations, "queue_loss");
        dimensions.detection = DimensionOutcome::INCONCLUSIVE;
        dimensions.validation = DimensionOutcome::INCONCLUSIVE;
        return finish(
            claim,
            correlation,
            linked,
            dimensions,
            limitations,
            mttd,
            reason,
        );
    }
    if claim.timed_out {
        push_code(&mut limitations, "timeout");
        dimensions.detection = DimensionOutcome::INCONCLUSIVE;
        dimensions.validation = DimensionOutcome::INCONCLUSIVE;
        return finish(
            claim,
            correlation,
            linked,
            dimensions,
            limitations,
            mttd,
            reason,
        );
    }
    if !claim.sensor_healthy {
        push_code(&mut limitations, "sensor_unhealthy");
        dimensions.detection = DimensionOutcome::INCONCLUSIVE;
        dimensions.validation = DimensionOutcome::INCONCLUSIVE;
        return finish(
            claim,
            correlation,
            linked,
            dimensions,
            limitations,
            mttd,
            reason,
        );
    }
    match claim.detected {
        Some(false) => {
            push_code(&mut limitations, "confirmed_miss");
            dimensions.detection = DimensionOutcome::FAILED;
            dimensions.validation = DimensionOutcome::FAILED;
        }
        Some(true) => {
            dimensions.detection = DimensionOutcome::PASSED;
        }
        None => {
            push_code(&mut limitations, "feedback_missing");
            dimensions.detection = DimensionOutcome::NOT_RUN;
            dimensions.validation = DimensionOutcome::NOT_RUN;
        }
    }
    if claim.detect_then_kill {
        push_code(&mut limitations, "detect_then_kill_is_containment");
    }
    if claim.fidelity == ObservationFidelity::Behavioral
        && dimensions.detection == DimensionOutcome::PASSED
        && !claim.cleanup_failed
    {
        if claim.detect_then_kill || claim.contained == Some(true) {
            dimensions.containment = DimensionOutcome::PASSED;
        }
        if claim.prevention_claimed && !claim.detect_then_kill {
            dimensions.prevention = DimensionOutcome::PASSED;
        }
        if dimensions.detection == DimensionOutcome::PASSED
            || dimensions.prevention == DimensionOutcome::PASSED
            || dimensions.containment == DimensionOutcome::PASSED
        {
            dimensions.validation = DimensionOutcome::PASSED;
        }
    } else if dimensions.detection == DimensionOutcome::PASSED && !claim.cleanup_failed {
        dimensions.validation = DimensionOutcome::PASSED;
    }
    if claim.cleanup_failed {
        push_code(&mut limitations, "cleanup_failed");
        if dimensions.validation == DimensionOutcome::PASSED {
            dimensions.validation = DimensionOutcome::INCONCLUSIVE;
        }
        dimensions.prevention = DimensionOutcome::NOT_RUN;
        dimensions.containment = DimensionOutcome::NOT_RUN;
        if dimensions.detection == DimensionOutcome::PASSED {
            dimensions.detection = DimensionOutcome::INCONCLUSIVE;
        }
    }
    finish(
        claim,
        correlation,
        linked,
        dimensions,
        limitations,
        mttd,
        reason,
    )
}

pub fn admit(
    binding: &AttemptBinding,
    claim: &FeedbackClaim,
    previous: Option<&ValidationExtension>,
    secret_key: &[u8],
) -> AdmitResult {
    if let Some(reason) = shape_error(binding, claim) {
        return AdmitResult::Invalid(reason);
    }
    let hash = claim_body_hash(claim);
    if let Some(prev) = previous {
        if let Some(entry) = prev
            .ledger
            .iter()
            .find(|entry| entry.key == claim.idempotency_key)
        {
            if entry.body_hash == hash {
                let existing = prev
                    .revisions
                    .iter()
                    .find(|obs| obs.observation_id.urn == entry.observation_id)
                    .cloned()
                    .unwrap_or_else(|| prev.observation.clone());
                return AdmitResult::Duplicate(existing);
            }
            return AdmitResult::Replay;
        }
    }
    let decision = decide(binding, claim);
    if !decision.linked {
        return AdmitResult::Unlinked(decision);
    }
    let public_key = match public_key_from_secret_key(secret_key) {
        Ok(key) => key,
        Err(err) => return AdmitResult::Invalid(err.to_string()),
    };
    let revision = previous
        .map(|prev| prev.observation.revision.saturating_add(1))
        .unwrap_or(1)
        .max(1);
    let supersedes = previous.map(|prev| prev.observation.observation_id.urn.clone());
    let observation_id = match observation_ref(&binding.run_id, &binding.attempt_id, revision) {
        Ok(value) => value,
        Err(err) => return AdmitResult::Invalid(err),
    };
    let asset_ref = match asset_resource_ref(&binding.asset_ref) {
        Ok(value) => value,
        Err(err) => return AdmitResult::Invalid(err),
    };
    let environment_ref = match environment_urn(&binding.environment_ref) {
        Ok(value) => value,
        Err(err) => return AdmitResult::Invalid(err),
    };
    let attack_release = match schema_attack_release(&claim.attack_release) {
        Ok(value) => value,
        Err(err) => return AdmitResult::Invalid(err),
    };
    if claim.evidence_refs.len() > 64 {
        return AdmitResult::Invalid("too many evidence refs".into());
    }
    let mut evidence_refs = Vec::with_capacity(claim.evidence_refs.len());
    for raw in &claim.evidence_refs {
        match evidence_resource_ref(raw) {
            Ok(item) => evidence_refs.push(item),
            Err(err) => return AdmitResult::Invalid(err),
        }
    }
    let mut observation = ValidationObservation {
        schema_version: SCHEMA_VERSION.into(),
        observation_id,
        producer: Producer {
            system: "asmodeus".into(),
            version: claim.producer.version.clone(),
            commit_sha: claim.producer.commit_sha.clone(),
            artifact_digest: claim.artifact_digest.clone(),
            config_digest: claim.config_digest.clone(),
            policy_digest: claim.policy_digest.clone(),
        },
        tenant_id: binding.tenant_id.clone(),
        asset_ref,
        environment_ref,
        run_id: binding.run_id.clone(),
        attempt_id: binding.attempt_id.clone(),
        procedure_id: binding.procedure_id.clone(),
        procedure_revision: binding.procedure_revision,
        idempotency_key: claim.idempotency_key.clone(),
        revision,
        supersedes,
        occurred_at: binding.occurred_at.clone(),
        observed_at: claim.observed_at.clone(),
        expires_at: binding.expires_at.clone(),
        catalog_digest: claim.catalog_digest.clone(),
        attack_release,
        fidelity: claim.fidelity,
        dimensions: decision.dimensions,
        provenance: Provenance {
            trusted_key_id: trusted_key_id(&public_key),
            signature_hex: String::new(),
            signature_covers: SIGNATURE_COVERS
                .iter()
                .map(|item| (*item).to_string())
                .collect(),
        },
        evidence_refs,
        limitations: decision.limitations,
    };
    if let Err(err) = sign_observation(&mut observation, secret_key) {
        return AdmitResult::Invalid(err);
    }
    let mut revisions = previous
        .map(|prev| {
            if prev.revisions.is_empty() {
                vec![prev.observation.clone()]
            } else {
                prev.revisions.clone()
            }
        })
        .unwrap_or_default();
    revisions.push(observation.clone());
    let mut ledger = previous.map(|prev| prev.ledger.clone()).unwrap_or_default();
    ledger.push(IdempotencyEntry {
        key: claim.idempotency_key.clone(),
        body_hash: hash.clone(),
        observation_id: observation.observation_id.urn.clone(),
        revision,
    });
    AdmitResult::Admitted(ValidationExtension {
        binding: binding.clone(),
        observation,
        revisions,
        mttd: decision.mttd,
        ledger,
        body_hash: hash,
    })
}

fn finish(
    claim: &FeedbackClaim,
    correlation: Correlation,
    linked: bool,
    mut dimensions: Dimensions,
    mut limitations: Vec<String>,
    mttd: MttdAssessment,
    applicability_reason: Option<String>,
) -> Decision {
    match claim.fidelity {
        ObservationFidelity::Marker => {
            push_code(&mut limitations, "fidelity_marker_no_prevention");
            push_code(&mut limitations, "fidelity_marker_no_containment");
            push_code(&mut limitations, "fidelity_marker_no_behavioral_coverage");
            if dimensions.prevention == DimensionOutcome::PASSED {
                dimensions.prevention = DimensionOutcome::NOT_RUN;
            }
            if dimensions.containment == DimensionOutcome::PASSED {
                dimensions.containment = DimensionOutcome::NOT_RUN;
            }
        }
        ObservationFidelity::TelemetryReplay => {
            push_code(&mut limitations, "telemetry_replay_no_behavioral_coverage");
            push_code(&mut limitations, "telemetry_replay_no_prevention");
            push_code(&mut limitations, "telemetry_replay_no_containment");
            if dimensions.prevention == DimensionOutcome::PASSED {
                dimensions.prevention = DimensionOutcome::NOT_RUN;
            }
            if dimensions.containment == DimensionOutcome::PASSED {
                dimensions.containment = DimensionOutcome::NOT_RUN;
            }
        }
        ObservationFidelity::Behavioral => {}
    }
    if claim.detect_then_kill && dimensions.prevention == DimensionOutcome::PASSED {
        dimensions.prevention = DimensionOutcome::NOT_RUN;
        push_code(&mut limitations, "detect_then_kill_is_containment");
    }
    let behavioral_coverage = claim.fidelity == ObservationFidelity::Behavioral
        && linked
        && claim.trusted
        && !claim.forged
        && !claim.cleanup_failed
        && !claim.run_interrupted
        && !claim.policy_stale
        && !claim.procedure_unsupported
        && matches!(
            dimensions.detection,
            DimensionOutcome::PASSED | DimensionOutcome::FAILED
        );
    dimensions.applicability_reason = if dimensions.applicability == Applicability::NOT_APPLICABLE {
        applicability_reason.clone()
    } else {
        None
    };
    Decision {
        correlation,
        linked,
        dimensions,
        limitations,
        mttd,
        behavioral_coverage,
        applicability_reason,
    }
}

fn correlate(binding: &AttemptBinding, claim: &FeedbackClaim) -> Correlation {
    if claim.tenant_id != binding.tenant_id {
        return Correlation::CrossTenant;
    }
    let tuple = claim.environment_ref == binding.environment_ref
        && claim.asset_ref == binding.asset_ref
        && claim.run_id == binding.run_id
        && claim.attempt_id == binding.attempt_id
        && claim.procedure_id == binding.procedure_id
        && claim.procedure_revision == binding.procedure_revision;
    if !tuple {
        let only_attempt = claim.attempt_id != binding.attempt_id
            && claim.environment_ref == binding.environment_ref
            && claim.asset_ref == binding.asset_ref
            && claim.run_id == binding.run_id
            && claim.procedure_id == binding.procedure_id
            && claim.procedure_revision == binding.procedure_revision;
        if only_attempt {
            return Correlation::WrongAttempt;
        }
        if claim.technique_id.as_deref() == Some(binding.technique_id.as_str()) {
            return Correlation::TechniqueOnly;
        }
        return Correlation::IdentityMismatch;
    }
    match feedback_in_window(binding, &claim.observed_at) {
        Some(true) => Correlation::Match,
        Some(false) | None => Correlation::OutOfWindow,
    }
}

fn feedback_in_window(binding: &AttemptBinding, observed_at: &str) -> Option<bool> {
    let start = parse_rfc3339_ms(&binding.occurred_at)?;
    let end = parse_rfc3339_ms(&binding.expires_at)?;
    let observed = parse_rfc3339_ms(observed_at)?;
    if end < start {
        return Some(false);
    }
    Some(observed >= start && observed <= end)
}

pub fn assess_mttd(occurred_at: &str, observed_at: &str) -> MttdAssessment {
    let Some(occurred) = parse_rfc3339_ms(occurred_at) else {
        return MttdAssessment::inconclusive("malformed_timestamp");
    };
    let Some(observed) = parse_rfc3339_ms(observed_at) else {
        return MttdAssessment::inconclusive("malformed_timestamp");
    };
    let skew = (observed - occurred).abs();
    if skew <= MTTD_MAX_SKEW_MS {
        MttdAssessment {
            status: "MEASURED".into(),
            seconds: Some((skew / 1000) as u64),
            reason: None,
        }
    } else {
        MttdAssessment::inconclusive("skew_exceeds_300s")
    }
}

fn exportable(observation: &ValidationObservation, trusted_public_key: &[u8]) -> bool {
    observation.schema_version == SCHEMA_VERSION
        && observation.revision >= 1
        && observation.procedure_revision >= 1
        && observation.producer.system == "asmodeus"
        && is_commit_sha(&observation.producer.commit_sha)
        && is_sha256_digest(&observation.producer.artifact_digest)
        && is_sha256_digest(&observation.producer.config_digest)
        && is_sha256_digest(&observation.producer.policy_digest)
        && is_sha256_digest(&observation.catalog_digest)
        && observation.provenance.trusted_key_id == trusted_key_id(trusted_public_key)
        && is_trusted_key_id(&observation.provenance.trusted_key_id)
        && is_signature_hex(&observation.provenance.signature_hex)
        && evidence_identity_ok(&observation.observation_id)
        && asset_identity_ok(&observation.asset_ref)
        && is_environment_urn(&observation.environment_ref)
        && observation
            .supersedes
            .as_deref()
            .map(is_evidence_urn)
            .unwrap_or(true)
        && observation
            .provenance
            .signature_covers
            .iter()
            .map(String::as_str)
            .eq(SIGNATURE_COVERS)
        && observation.evidence_refs.len() <= 64
        && observation.evidence_refs.iter().all(evidence_ref_ok)
        && observation.limitations.len() <= 64
        && observation
            .limitations
            .iter()
            .all(|item| LIMITATION_CODES.contains(&item.as_str()))
        && schema_dimensions_ok(observation)
        && tokens_ok(observation)
        && !contains_secret_material(observation)
        && observation_trusted(observation, trusted_public_key)
}

fn schema_dimensions_ok(observation: &ValidationObservation) -> bool {
    let reason = observation.dimensions.applicability_reason.as_deref();
    let reason_ok = match observation.dimensions.applicability {
        Applicability::NOT_APPLICABLE => reason.is_some_and(reason_token),
        Applicability::APPLICABLE => reason.is_none(),
    };
    if !reason_ok {
        return false;
    }
    if observation.fidelity == ObservationFidelity::Marker
        && observation.dimensions.prevention == DimensionOutcome::PASSED
    {
        return false;
    }
    let confirmed = matches!(observation.dimensions.detection, DimensionOutcome::PASSED)
        || matches!(observation.dimensions.prevention, DimensionOutcome::PASSED)
        || matches!(observation.dimensions.containment, DimensionOutcome::PASSED);
    if confirmed && observation.dimensions.telemetry != TelemetryState::AVAILABLE {
        return false;
    }
    true
}

fn tokens_ok(observation: &ValidationObservation) -> bool {
    is_token(&observation.tenant_id)
        && is_schema_id(&observation.run_id)
        && is_schema_id(&observation.attempt_id)
        && is_procedure_id(&observation.procedure_id)
        && is_idempotency_key(&observation.idempotency_key)
        && is_attack_release(&observation.attack_release)
        && (1..=64).contains(&observation.producer.version.len())
        && is_source(&observation.producer.system)
        && parse_rfc3339_ms(&observation.occurred_at).is_some()
        && parse_rfc3339_ms(&observation.observed_at).is_some()
        && parse_rfc3339_ms(&observation.expires_at).is_some()
}

fn contains_secret_material(observation: &ValidationObservation) -> bool {
    let blob = serde_json::to_string(observation).unwrap_or_default();
    blob.contains("BEGIN PRIVATE")
        || blob.contains("honeytoken")
        || blob.contains("/tmp/")
        || blob.contains("/var/")
        || blob.contains('\\')
}

fn shape_error(binding: &AttemptBinding, claim: &FeedbackClaim) -> Option<String> {
    if !is_token(&binding.tenant_id)
        || !is_token(&binding.environment_ref)
        || !is_token(&binding.asset_ref)
        || !is_schema_id(&binding.run_id)
        || !is_schema_id(&binding.attempt_id)
        || !is_procedure_id(&binding.procedure_id)
        || !is_token(&binding.technique_id)
        || binding.procedure_revision == 0
        || parse_rfc3339_ms(&binding.occurred_at).is_none()
        || parse_rfc3339_ms(&binding.expires_at).is_none()
    {
        return Some("invalid attempt binding".into());
    }
    if !is_token(&claim.tenant_id)
        || !is_token(&claim.environment_ref)
        || !is_token(&claim.asset_ref)
        || !is_schema_id(&claim.run_id)
        || !is_schema_id(&claim.attempt_id)
        || !is_procedure_id(&claim.procedure_id)
        || !is_idempotency_key(&claim.idempotency_key)
        || claim.procedure_revision == 0
        || claim
            .technique_id
            .as_deref()
            .is_some_and(|technique| !is_token(technique))
        || !is_commit_sha(&claim.producer.commit_sha)
        || !(1..=64).contains(&claim.producer.version.len())
        || !is_sha256_digest(&claim.catalog_digest)
        || !is_sha256_digest(&claim.config_digest)
        || !is_sha256_digest(&claim.artifact_digest)
        || !is_sha256_digest(&claim.policy_digest)
        || !acceptable_text(&claim.attack_release, 80)
    {
        return Some("invalid feedback claim".into());
    }
    None
}

fn sanitized_reason(reason: Option<&str>) -> Option<String> {
    let reason = reason?.trim();
    reason_token(reason).then(|| reason.to_string())
}

fn reason_token(reason: &str) -> bool {
    (1..=80).contains(&reason.len())
        && reason
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b':' | b'-'))
}

fn is_token(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn is_local_id(value: &str) -> bool {
    (1..=160).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b':' | b'-')
        })
}

fn is_source(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn is_schema_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn is_procedure_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn is_idempotency_key(value: &str) -> bool {
    (1..=256).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'.' | b'_' | b'~' | b'-')
        })
}

fn is_attack_release(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_trusted_key_id(value: &str) -> bool {
    is_schema_id(value)
}

fn is_signature_hex(value: &str) -> bool {
    (64..=512).contains(&value.len())
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_environment_urn(value: &str) -> bool {
    split_apex_urn(value, "environment").is_some()
}

fn is_evidence_urn(value: &str) -> bool {
    split_apex_urn(value, "evidence").is_some()
}

fn split_apex_urn<'a>(urn: &'a str, kind: &str) -> Option<(&'a str, &'a str)> {
    let rest = urn.strip_prefix("urn:apex:")?.strip_prefix(kind)?;
    let rest = rest.strip_prefix(':')?;
    let (source, local_id) = rest.split_once(':')?;
    (is_source(source) && is_local_id(local_id)).then_some((source, local_id))
}

fn evidence_identity_ok(item: &ResourceRef) -> bool {
    item.kind == ResourceKind::Evidence && item.source == "asmodeus" && item.consistent()
}

fn asset_identity_ok(item: &ResourceRef) -> bool {
    item.kind == ResourceKind::Asset && is_source(&item.source) && item.consistent()
}

fn evidence_ref_ok(item: &ResourceRef) -> bool {
    evidence_identity_ok(item) && synthetic_ref(&item.urn) == item.urn
}

fn acceptable_text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.chars().all(|ch| {
            ch.is_ascii() && !ch.is_control() && ch != '/' && ch != '\\' && ch != '"' && ch != '\''
        })
}

fn push_code(limitations: &mut Vec<String>, code: &str) {
    debug_assert!(LIMITATION_CODES.contains(&code));
    if !limitations.iter().any(|item| item == code) {
        limitations.push(code.to_string());
    }
}

fn claim_canonical(claim: &FeedbackClaim) -> Vec<u8> {
    let mut buf = Vec::new();
    field(&mut buf, &claim.tenant_id);
    field(&mut buf, &claim.environment_ref);
    field(&mut buf, &claim.asset_ref);
    field(&mut buf, &claim.run_id);
    field(&mut buf, &claim.attempt_id);
    field(&mut buf, &claim.procedure_id);
    field(&mut buf, &claim.procedure_revision.to_string());
    field(&mut buf, claim.technique_id.as_deref().unwrap_or(""));
    field(&mut buf, &claim.idempotency_key);
    field(&mut buf, &claim.observed_at);
    field(&mut buf, claim.fidelity.as_str());
    field(&mut buf, claim.applicability.as_str());
    field(
        &mut buf,
        claim.applicability_reason.as_deref().unwrap_or(""),
    );
    field(&mut buf, claim.telemetry.as_str());
    field(&mut buf, &claim.sensor_healthy.to_string());
    field(&mut buf, &claim.feedback_present.to_string());
    field(&mut buf, &claim.queue_loss.to_string());
    field(&mut buf, &claim.timed_out.to_string());
    field(
        &mut buf,
        &claim
            .detected
            .map(|value| value.to_string())
            .unwrap_or_default(),
    );
    field(&mut buf, &claim.prevention_claimed.to_string());
    field(&mut buf, &claim.detect_then_kill.to_string());
    field(
        &mut buf,
        &claim
            .contained
            .map(|value| value.to_string())
            .unwrap_or_default(),
    );
    field(&mut buf, &claim.policy_stale.to_string());
    field(&mut buf, &claim.cleanup_failed.to_string());
    field(&mut buf, &claim.run_interrupted.to_string());
    field(&mut buf, &claim.procedure_unsupported.to_string());
    field(&mut buf, &claim.procedure_failed.to_string());
    field(&mut buf, &claim.trusted.to_string());
    field(&mut buf, &claim.forged.to_string());
    field(&mut buf, &claim.catalog_digest);
    field(&mut buf, &claim.attack_release);
    field(&mut buf, &claim.policy_digest);
    field(&mut buf, &claim.catalog_digest_mismatch.to_string());
    buf
}

fn field(buf: &mut Vec<u8>, value: &str) {
    buf.extend_from_slice(value.len().to_string().as_bytes());
    buf.push(b':');
    buf.extend_from_slice(value.as_bytes());
    buf.push(b'|');
}

fn write_ref(buf: &mut Vec<u8>, item: &ResourceRef) {
    field(buf, &item.urn);
    field(buf, item.kind.as_str());
    field(buf, &item.source);
    field(buf, &item.local_id);
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn from_hex(hex_str: &str) -> Option<Vec<u8>> {
    if !hex_str.is_ascii() || !hex_str.len().is_multiple_of(2) {
        return None;
    }
    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).ok())
        .collect()
}

fn parse_rfc3339_ms(input: &str) -> Option<i64> {
    let bytes = input.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let year: i64 = std::str::from_utf8(&bytes[0..4]).ok()?.parse().ok()?;
    let month: u32 = std::str::from_utf8(&bytes[5..7]).ok()?.parse().ok()?;
    let day: u32 = std::str::from_utf8(&bytes[8..10]).ok()?.parse().ok()?;
    let hour: u32 = std::str::from_utf8(&bytes[11..13]).ok()?.parse().ok()?;
    let minute: u32 = std::str::from_utf8(&bytes[14..16]).ok()?.parse().ok()?;
    let second: u32 = std::str::from_utf8(&bytes[17..19]).ok()?.parse().ok()?;
    if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let dim = days_in_month(year, month)?;
    if day == 0 || day > dim {
        return None;
    }
    let mut idx = 19;
    let mut millis: i64 = 0;
    if bytes.get(idx) == Some(&b'.') {
        idx += 1;
        let start = idx;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        let digits = idx - start;
        if digits == 0 || digits > 9 {
            return None;
        }
        let mut frac = std::str::from_utf8(&bytes[start..idx]).ok()?.to_string();
        while frac.len() < 3 {
            frac.push('0');
        }
        millis = frac[..3].parse().ok()?;
    }
    let tz = std::str::from_utf8(&bytes[idx..]).ok()?;
    let offset_ms = if tz == "Z" {
        0
    } else if tz.len() == 6 && (tz.starts_with('+') || tz.starts_with('-')) {
        let sign = if tz.starts_with('+') { 1 } else { -1 };
        let hours: i64 = tz[1..3].parse().ok()?;
        if tz.as_bytes().get(3) != Some(&b':') {
            return None;
        }
        let mins: i64 = tz[4..6].parse().ok()?;
        if hours > 23 || mins > 59 {
            return None;
        }
        sign * (hours * 3600 + mins * 60) * 1000
    } else {
        return None;
    };
    let days = days_from_civil(year, month, day)?;
    let unix_ms = days
        .checked_mul(86_400_000)?
        .checked_add(i64::from(hour) * 3_600_000)?
        .checked_add(i64::from(minute) * 60_000)?
        .checked_add(i64::from(second) * 1000)?
        .checked_add(millis)?
        .checked_sub(offset_ms)?;
    Some(unix_ms)
}

fn days_in_month(year: i64, month: u32) -> Option<u32> {
    Some(match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => return None,
    })
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp as u64 + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe as i64 - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Measurements;
    use asmodeus_crypto::generate_keypair;

    fn dig(n: u8) -> String {
        format!("sha256:{:064x}", u128::from(n))
    }

    fn producer() -> Producer {
        Producer {
            system: "asmodeus".into(),
            version: "0.1.0".into(),
            commit_sha: "0123456789abcdef0123456789abcdef01234567".into(),
            artifact_digest: dig(1),
            config_digest: dig(2),
            policy_digest: dig(3),
        }
    }

    fn binding() -> AttemptBinding {
        AttemptBinding {
            tenant_id: "tenant-a".into(),
            environment_ref: "env-lab".into(),
            asset_ref: "asset-1".into(),
            run_id: "run-1".into(),
            attempt_id: "attempt-http-positive".into(),
            procedure_id: "http-beacon".into(),
            procedure_revision: 1,
            technique_id: "T1071.001".into(),
            occurred_at: "2026-11-11T00:00:00Z".into(),
            expires_at: "2026-11-11T00:05:00Z".into(),
        }
    }

    fn claim() -> FeedbackClaim {
        let producer = producer();
        FeedbackClaim {
            tenant_id: "tenant-a".into(),
            environment_ref: "env-lab".into(),
            asset_ref: "asset-1".into(),
            run_id: "run-1".into(),
            attempt_id: "attempt-http-positive".into(),
            procedure_id: "http-beacon".into(),
            procedure_revision: 1,
            technique_id: Some("T1071.001".into()),
            idempotency_key: "idem-1".into(),
            observed_at: "2026-11-11T00:00:10Z".into(),
            fidelity: ObservationFidelity::Behavioral,
            applicability: Applicability::APPLICABLE,
            applicability_reason: None,
            telemetry: TelemetryState::AVAILABLE,
            sensor_healthy: true,
            feedback_present: true,
            queue_loss: false,
            timed_out: false,
            detected: Some(true),
            prevention_claimed: false,
            detect_then_kill: false,
            contained: None,
            policy_stale: false,
            cleanup_failed: false,
            run_interrupted: false,
            procedure_unsupported: false,
            procedure_failed: false,
            trusted: true,
            forged: false,
            evidence_refs: vec![],
            catalog_digest: dig(4),
            attack_release: "ATT&CK Enterprise v15.1".into(),
            config_digest: producer.config_digest.clone(),
            artifact_digest: producer.artifact_digest.clone(),
            policy_digest: producer.policy_digest.clone(),
            catalog_digest_mismatch: false,
            producer,
        }
    }

    fn admitted(claim: &FeedbackClaim) -> ValidationExtension {
        let (_, sk) = generate_keypair();
        match admit(&binding(), claim, None, &sk) {
            AdmitResult::Admitted(ext) => ext,
            other => panic!("expected admit, got {other:?}"),
        }
    }

    #[test]
    fn unix_epoch_parses() {
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_ms("2026-11-11T01:00:00+01:00"),
            parse_rfc3339_ms("2026-11-11T00:00:00Z")
        );
    }

    #[test]
    fn marker_detection_can_pass_but_not_prevention_or_behavior() {
        let mut claim = claim();
        claim.fidelity = ObservationFidelity::Marker;
        claim.prevention_claimed = true;
        claim.detect_then_kill = true;
        claim.contained = Some(true);
        let decision = decide(&binding(), &claim);
        assert_eq!(decision.dimensions.detection, DimensionOutcome::PASSED);
        assert_ne!(decision.dimensions.prevention, DimensionOutcome::PASSED);
        assert_ne!(decision.dimensions.containment, DimensionOutcome::PASSED);
        assert!(!decision.behavioral_coverage);
        assert!(decision.mttd.is_numeric());
        assert_eq!(decision.mttd.seconds, Some(10));
        let ext = admitted(&claim);
        assert!(
            !ext.observation.dimensions.any_passed()
                || ext.observation.dimensions.detection == DimensionOutcome::PASSED
        );
        assert_ne!(
            ext.observation.dimensions.prevention,
            DimensionOutcome::PASSED
        );
        let exported = ext.observation.export_json();
        assert!(!exported.contains("\"behavioral_coverage\""));
        assert!(exported.contains("fidelity_marker_no_behavioral_coverage"));
    }

    #[test]
    fn missing_sensor_queue_timeout_and_feedback_are_not_pass() {
        for (name, mutate) in [
            (
                "feedback",
                Box::new(|c: &mut FeedbackClaim| c.feedback_present = false)
                    as Box<dyn Fn(&mut FeedbackClaim)>,
            ),
            (
                "unavailable",
                Box::new(|c: &mut FeedbackClaim| c.telemetry = TelemetryState::UNAVAILABLE),
            ),
            (
                "unknown",
                Box::new(|c: &mut FeedbackClaim| c.telemetry = TelemetryState::UNKNOWN),
            ),
            (
                "queue",
                Box::new(|c: &mut FeedbackClaim| c.queue_loss = true),
            ),
            (
                "timeout",
                Box::new(|c: &mut FeedbackClaim| c.timed_out = true),
            ),
        ] {
            let mut claim = claim();
            mutate(&mut claim);
            let decision = decide(&binding(), &claim);
            assert!(!decision.any_passed(), "{name}");
            assert!(!decision.limitations.is_empty(), "{name}");
            assert_ne!(
                decision.dimensions.detection,
                DimensionOutcome::PASSED,
                "{name}"
            );
        }
    }

    #[test]
    fn confirmed_miss_is_detection_failed_not_silence() {
        let mut claim = claim();
        claim.detected = Some(false);
        let decision = decide(&binding(), &claim);
        assert_eq!(decision.dimensions.detection, DimensionOutcome::FAILED);
        assert!(!decision.any_passed());
        assert!(decision
            .limitations
            .iter()
            .any(|item| item == "confirmed_miss"));
    }

    #[test]
    fn mttd_over_300_seconds_is_inconclusive() {
        let mut wide = binding();
        wide.expires_at = "2026-11-11T00:10:00Z".into();
        let mut claim = claim();
        claim.observed_at = "2026-11-11T00:05:01Z".into();
        let decision = decide(&wide, &claim);
        assert!(decision.linked);
        assert!(!decision.mttd.is_numeric());
        assert!(decision.mttd.seconds.is_none());
        assert_eq!(decision.mttd.status, "INCONCLUSIVE");
    }

    #[test]
    fn detect_then_kill_is_containment_only_for_behavioral() {
        let mut claim = claim();
        claim.detect_then_kill = true;
        claim.prevention_claimed = true;
        claim.contained = Some(true);
        let decision = decide(&binding(), &claim);
        assert_eq!(decision.dimensions.containment, DimensionOutcome::PASSED);
        assert_ne!(decision.dimensions.prevention, DimensionOutcome::PASSED);
        assert!(decision.behavioral_coverage);
        claim.fidelity = ObservationFidelity::Marker;
        let marker = decide(&binding(), &claim);
        assert_ne!(marker.dimensions.containment, DimensionOutcome::PASSED);
        assert_ne!(marker.dimensions.prevention, DimensionOutcome::PASSED);
    }

    #[test]
    fn negative_correlation_does_not_pass() {
        let base = binding();
        let mut cross = claim();
        cross.tenant_id = "tenant-b".into();
        let cross = decide(&base, &cross);
        assert_eq!(cross.correlation, Correlation::CrossTenant);
        assert!(!cross.linked);
        assert!(!cross.any_passed());

        let mut wrong = claim();
        wrong.attempt_id = "attempt-other".into();
        let wrong = decide(&base, &wrong);
        assert_eq!(wrong.correlation, Correlation::WrongAttempt);
        assert!(!wrong.any_passed());

        let mut technique = claim();
        technique.attempt_id = "attempt-other".into();
        technique.run_id = "run-other".into();
        technique.procedure_id = "dns-pattern".into();
        let technique = decide(&base, &technique);
        assert_eq!(technique.correlation, Correlation::TechniqueOnly);
        assert!(!technique.any_passed());

        let mut late = claim();
        late.observed_at = "2026-11-11T00:06:00Z".into();
        let late = decide(&base, &late);
        assert_eq!(late.correlation, Correlation::OutOfWindow);
        assert!(!late.any_passed());
    }

    #[test]
    fn forged_and_untrusted_producer_cannot_pass() {
        let (trusted_pk, trusted_sk) = generate_keypair();
        let (attacker_pk, attacker_sk) = generate_keypair();
        let mut forged_claim = claim();
        forged_claim.forged = true;
        forged_claim.trusted = false;
        let decision = decide(&binding(), &forged_claim);
        assert!(!decision.any_passed());
        assert!(decision
            .limitations
            .iter()
            .any(|item| item == "forged_signature"));
        forged_claim.forged = false;
        forged_claim.trusted = false;
        assert!(!decide(&binding(), &forged_claim).any_passed());

        let mut honest = claim();
        honest.forged = false;
        honest.trusted = true;
        let ext = match admit(&binding(), &honest, None, &trusted_sk) {
            AdmitResult::Admitted(ext) => ext,
            other => panic!("{other:?}"),
        };
        assert!(observation_trusted(&ext.observation, &trusted_pk));
        assert!(!observation_trusted(&ext.observation, &attacker_pk));
        let mut forged = ext.observation.clone();
        forged.dimensions.prevention = DimensionOutcome::PASSED;
        sign_observation(&mut forged, &attacker_sk).unwrap();
        assert!(!observation_trusted(&forged, &trusted_pk));
        assert!(observation_trusted(&forged, &attacker_pk));
        let mut record = sample_audit(ext);
        record = record.sign(&trusted_sk).unwrap();
        assert!(record.verify_with_key(&trusted_pk));
        let mut wrapped = record.clone();
        wrapped.public_key_hex = to_hex(&attacker_pk);
        wrapped
            .validation
            .as_mut()
            .unwrap()
            .observation
            .dimensions
            .prevention = DimensionOutcome::PASSED;
        wrapped = wrapped.sign(&attacker_sk).unwrap();
        assert!(wrapped.verify());
        assert!(!wrapped.verify_with_key(&trusted_pk));
        let page = export_observations(std::slice::from_ref(&wrapped), &trusted_pk, None, None);
        assert!(page
            .observations
            .iter()
            .all(|obs| obs.dimensions.prevention != DimensionOutcome::PASSED));
        let json = export_page_json(&page);
        assert!(!json.contains(&to_hex(&attacker_pk)));
        assert!(!json.contains(&to_hex(&trusted_pk)));
    }

    #[test]
    fn replay_duplicate_redaction_and_stable_export() {
        let (_, sk) = generate_keypair();
        let (pk, _) = public_from(&sk);
        let mut claim = claim();
        claim.evidence_refs = vec![
            "honeytoken=HONEYTOKEN_VALUE_do-not-leak".into(),
            "/var/lib/apex/host.pem".into(),
            "BEGIN PRIVATE KEY".into(),
        ];
        let ext = match admit(&binding(), &claim, None, &sk) {
            AdmitResult::Admitted(ext) => ext,
            other => panic!("{other:?}"),
        };
        let json = ext.observation.export_json();
        assert!(!json.contains("HONEYTOKEN_VALUE_do-not-leak"));
        assert!(!json.contains("/var/lib"));
        assert!(!json.contains("BEGIN PRIVATE"));
        assert!(!json.contains("honeytoken"));
        let duplicate = match admit(&binding(), &claim, Some(&ext), &sk) {
            AdmitResult::Duplicate(obs) => obs,
            other => panic!("{other:?}"),
        };
        assert_eq!(duplicate.observation_id, ext.observation.observation_id);
        assert_eq!(duplicate.revision, 1);
        let mut changed = claim.clone();
        changed.detected = Some(false);
        assert!(matches!(
            admit(&binding(), &changed, Some(&ext), &sk),
            AdmitResult::Replay
        ));
        let mut late = claim.clone();
        late.idempotency_key = "idem-2".into();
        late.observed_at = "2026-11-11T00:00:12Z".into();
        let ext2 = match admit(&binding(), &late, Some(&ext), &sk) {
            AdmitResult::Admitted(ext) => ext,
            other => panic!("{other:?}"),
        };
        assert_eq!(ext2.observation.revision, 2);
        assert_eq!(
            ext2.observation.supersedes.as_deref(),
            Some(ext.observation.observation_id.urn.as_str())
        );
        assert_eq!(
            ext2.revisions[0].provenance.signature_hex,
            ext.observation.provenance.signature_hex
        );
        let record = sample_audit(ext2).sign(&sk).unwrap();
        let first = export_page_json(&export_observations(
            std::slice::from_ref(&record),
            &pk,
            None,
            Some(10),
        ));
        let second = export_page_json(&export_observations(
            std::slice::from_ref(&record),
            &pk,
            None,
            Some(10),
        ));
        assert_eq!(first, second);
        let parsed: ObservationPage = serde_json::from_str(&first).unwrap();
        assert_eq!(parsed.observations.len(), 2);
        assert_eq!(
            aggregate_revision(std::slice::from_ref(&record), "run-1", &pk).as_deref(),
            Some(
                record
                    .validation
                    .as_ref()
                    .unwrap()
                    .observation
                    .observation_id
                    .urn
                    .as_str()
            )
        );
        assert_eq!(
            stage_revision(&record, &pk),
            aggregate_revision(std::slice::from_ref(&record), "run-1", &pk)
        );
        let page = export_observations(std::slice::from_ref(&record), &pk, None, Some(1));
        assert_eq!(page.observations.len(), 1);
        assert_eq!(page.limit, 1);
        let cursor = page.next_cursor.clone().expect("next cursor");
        let rest = export_observations(std::slice::from_ref(&record), &pk, Some(&cursor), Some(1));
        assert_eq!(rest.observations.len(), 1);
        assert!(rest.next_cursor.is_none());
        assert_ne!(
            page.observations[0].observation_id,
            rest.observations[0].observation_id
        );
        let mut extra = serde_json::to_value(&parsed.observations[0]).unwrap();
        extra["bonus"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ValidationObservation>(extra).is_err());
    }

    #[test]
    fn reload_keeps_one_tip_and_does_not_rewrite_the_previous_line() {
        let (pk, sk) = generate_keypair();
        let ext = match admit(&binding(), &claim(), None, &sk) {
            AdmitResult::Admitted(ext) => ext,
            other => panic!("expected admit, got {other:?}"),
        };
        let first_record = sample_audit(ext.clone()).sign(&sk).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "asmodeus-val-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        crate::AuditTrail::append_to_file(&first_record, &path).unwrap();
        let snapshot = std::fs::read_to_string(&path).unwrap();
        let mut late = claim();
        late.idempotency_key = "idem-late".into();
        let ext2 = match admit(&binding(), &late, Some(&ext), &sk) {
            AdmitResult::Admitted(ext) => ext,
            other => panic!("{other:?}"),
        };
        let second = sample_audit(ext2).sign(&sk).unwrap();
        crate::AuditTrail::append_to_file(&second, &path).unwrap();
        let file = std::fs::read_to_string(&path).unwrap();
        assert!(file.starts_with(&snapshot));
        let loaded = crate::AuditTrail::load_from_file(&path).unwrap();
        let record = loaded.get("run-1").unwrap();
        assert_eq!(
            stage_revision(record, &pk),
            aggregate_revision(loaded.records(), "run-1", &pk)
        );
        assert_eq!(record.validation.as_ref().unwrap().observation.revision, 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn stale_cleanup_interrupt_and_failure_are_not_pass() {
        let mut stale = claim();
        stale.policy_stale = true;
        let stale = decide(&binding(), &stale);
        assert_eq!(stale.dimensions.validation, DimensionOutcome::STALE);
        assert!(!stale.any_passed());
        let mut cleanup = claim();
        cleanup.cleanup_failed = true;
        assert!(!decide(&binding(), &cleanup).any_passed());
        let mut interrupted = claim();
        interrupted.run_interrupted = true;
        assert!(!decide(&binding(), &interrupted).any_passed());
        let mut failed = claim();
        failed.procedure_failed = true;
        let failed = decide(&binding(), &failed);
        assert_eq!(failed.dimensions.validation, DimensionOutcome::FAILED);
        assert!(!failed.any_passed());
    }

    #[test]
    fn legacy_evidence_without_extension_is_unconfirmed() {
        let mut record = sample_audit_bare();
        record.evidence = Some(crate::RunEvidence {
            execution_mode: "runner".into(),
            feedback_received: true,
            contained: true,
            cleanup_confirmed: true,
            failure_reason: None,
        });
        record.measurements.blue_team_detected = true;
        assert!(legacy_feedback_unconfirmed(&record));
        assert!(stage_revision(&record, &[0; 32]).is_none());
    }

    #[test]
    fn not_applicable_requires_reason_and_is_not_pass() {
        let mut claim = claim();
        claim.applicability = Applicability::NOT_APPLICABLE;
        claim.applicability_reason = None;
        assert!(!decide(&binding(), &claim).any_passed());
        claim.applicability_reason = Some("fixture_not_in_scope".into());
        let decision = decide(&binding(), &claim);
        assert_eq!(
            decision.dimensions.detection,
            DimensionOutcome::NOT_APPLICABLE
        );
        assert_eq!(
            decision.dimensions.applicability_reason.as_deref(),
            Some("fixture_not_in_scope")
        );
        assert!(!decision.any_passed());
    }

    #[test]
    fn first_wave_procedure_ids_match_the_observation_pattern() {
        for id in [
            "container-exec",
            "shell-execution",
            "runtime-socket-prerequisite",
            "http-beacon",
            "dns-pattern",
            "synthetic-transfer",
        ] {
            assert!(is_procedure_id(id), "{id}");
        }
    }

    #[test]
    fn exported_observation_matches_attack_observation_shape() {
        let (pk, sk) = generate_keypair();
        let mut claim = claim();
        claim.evidence_refs = vec!["sensor-hit".into()];
        let ext = match admit(&binding(), &claim, None, &sk) {
            AdmitResult::Admitted(ext) => ext,
            other => panic!("{other:?}"),
        };
        let value: serde_json::Value =
            serde_json::from_str(&ext.observation.export_json()).unwrap();
        assert_observation_shape(&value, true);
        assert!(value["supersedes"].is_null());
        assert!(value["dimensions"].get("applicability_reason").is_none());
        assert_eq!(value["evidence_refs"].as_array().unwrap().len(), 1);
        assert_eq!(value["procedure_id"], "http-beacon");
        assert_eq!(value["attack_release"], "ATT-CK-Enterprise-v15.1");
        assert_eq!(
            value["environment_ref"],
            "urn:apex:environment:asmodeus:env-lab"
        );
        assert_eq!(value["asset_ref"]["kind"], "asset");
        assert_eq!(value["asset_ref"]["local_id"], "asset-1");
        assert_eq!(value["asset_ref"]["urn"], "urn:apex:asset:asmodeus:asset-1");
        assert_eq!(
            ext.observation.provenance.trusted_key_id,
            trusted_key_id(&pk)
        );
        let signature = value["provenance"]["signature_hex"].as_str().unwrap();
        assert_eq!(signature.len(), 128);

        let mut late = claim.clone();
        late.idempotency_key = "idem-2".into();
        late.evidence_refs.clear();
        let ext2 = match admit(&binding(), &late, Some(&ext), &sk) {
            AdmitResult::Admitted(ext) => ext,
            other => panic!("{other:?}"),
        };
        let second: serde_json::Value =
            serde_json::from_str(&ext2.observation.export_json()).unwrap();
        assert_observation_shape(&second, false);
        assert_eq!(second["supersedes"], value["observation_id"]["urn"]);
        assert!(second["supersedes"].is_string());
        assert!(second["evidence_refs"].as_array().unwrap().is_empty());

        let mut na = claim.clone();
        na.idempotency_key = "idem-na".into();
        na.applicability = Applicability::NOT_APPLICABLE;
        na.applicability_reason = Some("fixture_not_in_scope".into());
        na.evidence_refs.clear();
        let ext_na = match admit(&binding(), &na, Some(&ext2), &sk) {
            AdmitResult::Admitted(ext) => ext,
            other => panic!("{other:?}"),
        };
        let na_json: serde_json::Value =
            serde_json::from_str(&ext_na.observation.export_json()).unwrap();
        assert_eq!(na_json["dimensions"]["applicability"], "NOT_APPLICABLE");
        assert_eq!(
            na_json["dimensions"]["applicability_reason"],
            "fixture_not_in_scope"
        );
        assert!(na_json["dimensions"]["applicability_reason"].is_string());
        let page = export_observations(
            std::slice::from_ref(&sample_audit(ext_na).sign(&sk).unwrap()),
            &pk,
            None,
            None,
        );
        assert!(page.observations.iter().any(|obs| {
            obs.dimensions.applicability == Applicability::NOT_APPLICABLE
                && obs.dimensions.applicability_reason.as_deref() == Some("fixture_not_in_scope")
        }));
    }

    #[test]
    fn marker_prevention_passed_is_not_exported_as_confirmation() {
        let (pk, sk) = generate_keypair();
        let mut claim = claim();
        claim.fidelity = ObservationFidelity::Marker;
        claim.prevention_claimed = true;
        let ext = match admit(&binding(), &claim, None, &sk) {
            AdmitResult::Admitted(ext) => ext,
            other => panic!("{other:?}"),
        };
        assert_ne!(
            ext.observation.dimensions.prevention,
            DimensionOutcome::PASSED
        );
        let record = sample_audit(ext.clone()).sign(&sk).unwrap();
        let page = export_observations(std::slice::from_ref(&record), &pk, None, None);
        assert_eq!(page.observations.len(), 1);
        assert_eq!(page.observations[0].fidelity, ObservationFidelity::Marker);
        assert_ne!(
            page.observations[0].dimensions.prevention,
            DimensionOutcome::PASSED
        );
        let rendered = export_page_json(&page);
        assert!(!rendered.contains("\"prevention\":\"PASSED\""));

        let mut relabeled = ext.observation.clone();
        relabeled.dimensions.prevention = DimensionOutcome::PASSED;
        sign_observation(&mut relabeled, &sk).unwrap();
        assert!(observation_trusted(&relabeled, &pk));
        let mut ext = ext;
        ext.observation = relabeled.clone();
        ext.revisions = vec![relabeled];
        let record = sample_audit(ext).sign(&sk).unwrap();
        let page = export_observations(std::slice::from_ref(&record), &pk, None, None);
        assert!(page.observations.is_empty());
    }

    #[test]
    fn trusted_key_id_comes_from_the_trusted_key_argument() {
        let (trusted_pk, trusted_sk) = generate_keypair();
        let (attacker_pk, _) = generate_keypair();
        let ext = match admit(&binding(), &claim(), None, &trusted_sk) {
            AdmitResult::Admitted(ext) => ext,
            other => panic!("{other:?}"),
        };
        let id = ext.observation.provenance.trusted_key_id.clone();
        assert_eq!(id, trusted_key_id(&trusted_pk));
        assert!(is_trusted_key_id(&id));
        assert_ne!(id, to_hex(&trusted_pk));
        assert_ne!(id, to_hex(&attacker_pk));
        let mut record = sample_audit(ext.clone()).sign(&trusted_sk).unwrap();
        record.public_key_hex = to_hex(&attacker_pk);
        assert_eq!(
            record
                .validation
                .as_ref()
                .unwrap()
                .observation
                .provenance
                .trusted_key_id,
            id
        );
        let page = export_observations(std::slice::from_ref(&record), &trusted_pk, None, None);
        assert_eq!(page.observations.len(), 1);
        assert_eq!(page.observations[0].provenance.trusted_key_id, id);
        let hidden = export_observations(std::slice::from_ref(&record), &attacker_pk, None, None);
        assert!(hidden.observations.is_empty());

        let mut relabeled = ext.observation.clone();
        relabeled.provenance.trusted_key_id = trusted_key_id(&attacker_pk);
        relabeled.provenance.signature_hex.clear();
        let sig = asmodeus_crypto::sign_message(&relabeled.canonical_bytes(), &trusted_sk).unwrap();
        relabeled.provenance.signature_hex = to_hex(&sig);
        assert!(observation_trusted(&relabeled, &trusted_pk));
        assert_ne!(
            relabeled.provenance.trusted_key_id,
            trusted_key_id(&trusted_pk)
        );
        let mut ext = ext;
        ext.observation = relabeled.clone();
        ext.revisions = vec![relabeled];
        let record = sample_audit(ext).sign(&trusted_sk).unwrap();
        let page = export_observations(std::slice::from_ref(&record), &trusted_pk, None, None);
        assert!(page.observations.is_empty());
    }

    fn assert_observation_shape(value: &serde_json::Value, with_evidence: bool) {
        let keys = object_keys(value);
        assert_eq!(
            keys,
            vec![
                "asset_ref",
                "attack_release",
                "attempt_id",
                "catalog_digest",
                "dimensions",
                "environment_ref",
                "evidence_refs",
                "expires_at",
                "fidelity",
                "idempotency_key",
                "limitations",
                "observation_id",
                "observed_at",
                "occurred_at",
                "procedure_id",
                "procedure_revision",
                "producer",
                "provenance",
                "revision",
                "run_id",
                "schema_version",
                "supersedes",
                "tenant_id",
            ]
        );
        assert_eq!(value["schema_version"], "1.0");
        assert_resource_ref(&value["observation_id"], "evidence", "asmodeus");
        assert_resource_ref(&value["asset_ref"], "asset", "asmodeus");
        assert!(value["environment_ref"].is_string());
        assert!(is_environment_urn(
            value["environment_ref"].as_str().unwrap()
        ));
        for key in [
            "tenant_id",
            "run_id",
            "attempt_id",
            "procedure_id",
            "idempotency_key",
        ] {
            assert!(value[key].is_string(), "{key}");
        }
        assert!(is_schema_id(value["run_id"].as_str().unwrap()));
        assert!(is_schema_id(value["attempt_id"].as_str().unwrap()));
        assert!(is_procedure_id(value["procedure_id"].as_str().unwrap()));
        assert!(is_idempotency_key(
            value["idempotency_key"].as_str().unwrap()
        ));
        assert!(value["procedure_revision"].as_u64().unwrap() >= 1);
        assert!(value["revision"].as_u64().unwrap() >= 1);
        assert!(value["supersedes"].is_null() || value["supersedes"].is_string());
        if let Some(urn) = value["supersedes"].as_str() {
            assert!(is_evidence_urn(urn));
        }
        for key in ["occurred_at", "observed_at", "expires_at"] {
            assert!(value[key].is_string(), "{key}");
            assert!(parse_rfc3339_ms(value[key].as_str().unwrap()).is_some());
        }
        let digest = value["catalog_digest"].as_str().unwrap();
        assert!(is_sha256_digest(digest));
        assert!(is_attack_release(value["attack_release"].as_str().unwrap()));
        assert!(matches!(
            value["fidelity"].as_str().unwrap(),
            "marker" | "telemetry_replay" | "behavioral"
        ));
        assert_eq!(
            object_keys(&value["producer"]),
            vec![
                "artifact_digest",
                "commit_sha",
                "config_digest",
                "policy_digest",
                "system",
                "version",
            ]
        );
        assert_eq!(value["producer"]["system"], "asmodeus");
        assert!(is_commit_sha(
            value["producer"]["commit_sha"].as_str().unwrap()
        ));
        for key in ["artifact_digest", "config_digest", "policy_digest"] {
            assert!(is_sha256_digest(value["producer"][key].as_str().unwrap()));
        }
        let mut dimension_keys = object_keys(&value["dimensions"]);
        dimension_keys.retain(|key| *key != "applicability_reason");
        assert_eq!(
            dimension_keys,
            vec![
                "applicability",
                "containment",
                "detection",
                "prevention",
                "telemetry",
                "validation",
            ]
        );
        assert!(matches!(
            value["dimensions"]["applicability"].as_str().unwrap(),
            "APPLICABLE" | "NOT_APPLICABLE"
        ));
        assert!(matches!(
            value["dimensions"]["telemetry"].as_str().unwrap(),
            "AVAILABLE" | "UNAVAILABLE" | "UNKNOWN"
        ));
        for key in ["detection", "prevention", "containment", "validation"] {
            assert!(value["dimensions"][key].is_string(), "{key}");
        }
        if value["dimensions"]["applicability"] == "NOT_APPLICABLE" {
            let reason = value["dimensions"]["applicability_reason"]
                .as_str()
                .expect("reason string");
            assert!(!reason.is_empty() && reason.len() <= 512);
        } else {
            assert!(value["dimensions"].get("applicability_reason").is_none());
        }
        assert_eq!(
            object_keys(&value["provenance"]),
            vec!["signature_covers", "signature_hex", "trusted_key_id"]
        );
        assert!(is_trusted_key_id(
            value["provenance"]["trusted_key_id"].as_str().unwrap()
        ));
        let signature = value["provenance"]["signature_hex"].as_str().unwrap();
        assert!(is_signature_hex(signature));
        let covers = value["provenance"]["signature_covers"].as_array().unwrap();
        for required in ["fidelity", "refs", "results", "provenance"] {
            assert!(covers.iter().any(|item| item == required));
        }
        let refs = value["evidence_refs"].as_array().unwrap();
        assert!(refs.len() <= 64);
        if with_evidence {
            assert!(!refs.is_empty());
        }
        for item in refs {
            assert_resource_ref(item, "evidence", "asmodeus");
        }
        let limitations = value["limitations"].as_array().unwrap();
        assert!(limitations.len() <= 64);
        assert!(limitations.iter().all(|item| item.is_string()));
    }

    fn assert_resource_ref(value: &serde_json::Value, kind: &str, source: &str) {
        assert!(value.is_object());
        assert_eq!(
            object_keys(value),
            vec!["kind", "local_id", "source", "urn"]
        );
        assert_eq!(value["kind"], kind);
        assert_eq!(value["source"], source);
        let local_id = value["local_id"].as_str().unwrap();
        assert!(is_local_id(local_id));
        assert_eq!(value["urn"], format!("urn:apex:{kind}:{source}:{local_id}"));
    }

    fn object_keys(value: &serde_json::Value) -> Vec<&str> {
        let mut keys: Vec<_> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        keys
    }

    fn public_from(secret: &[u8]) -> ([u8; 32], ()) {
        (public_key_from_secret_key(secret).unwrap(), ())
    }

    fn sample_audit(ext: ValidationExtension) -> AuditRecord {
        let mut record = sample_audit_bare();
        record.validation = Some(ext);
        record
    }

    fn sample_audit_bare() -> AuditRecord {
        AuditRecord {
            run_id: "run-1".into(),
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
            measurements: Measurements::default(),
            detection_source: "PENDING_VALIDATION".into(),
            containment_action: "UNCONFIRMED".into(),
            cleanup_status: "PENDING".into(),
            timestamp_utc: "2026-11-11T00:00:00Z".into(),
            signature_hex: String::new(),
            public_key_hex: String::new(),
            evidence: Some(crate::RunEvidence {
                execution_mode: "runner".into(),
                ..crate::RunEvidence::default()
            }),
            validation: None,
        }
    }
}
