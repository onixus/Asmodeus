//! Declarative scenario manifests (`AttackScenario`, `ChaosExperiment`)
//! conforming to FTT §5 and TT §1.1.
//!
//! Provides typed definitions, parsing from YAML or JSON, and strict
//! INV-0 validation before execution or signing.

use std::collections::HashMap;

use asmodeus_common::{ActionNature, Category};
use serde::{Deserialize, Serialize};

use crate::fidelity::{Fidelity, TechniqueRef};
use crate::{lookup_technique, net_target_in_scope, path_in_scope};

/// Legacy manifest schema. Read for backward compatibility but never promoted:
/// any fidelity it self-declares is ignored and capped at
/// [`Fidelity::Unspecified`] (see [`ScenarioManifest::effective_fidelity`]).
pub const API_VERSION_V1ALPHA1: &str = "asmodeus.io/v1alpha1";

/// Current manifest schema. May carry a declared `fidelity` and a
/// `mitre_techniques` list (multi-technique / multi-tactic).
pub const API_VERSION_V1ALPHA2: &str = "asmodeus.io/v1alpha2";

/// Every manifest `apiVersion` this build accepts.
pub const SUPPORTED_API_VERSIONS: [&str; 2] = [API_VERSION_V1ALPHA1, API_VERSION_V1ALPHA2];

/// Supported manifest kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManifestKind {
    AttackScenario,
    ChaosExperiment,
}

fn default_severity() -> String {
    "medium".to_string()
}

/// Metadata section of the manifest.
///
/// `mitre_technique`/`mitre_tactic` remain the stable single-technique
/// projection (wire JSON, ClickHouse sort key, signed audit preimage). The
/// S01 fields — `fidelity` and `mitre_techniques` — are optional and only
/// honoured for [`API_VERSION_V1ALPHA2`]; in a `v1alpha1` manifest they are
/// read but never raise trust (see [`ScenarioManifest::effective_fidelity`]).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManifestMetadata {
    pub id: String,
    pub name: String,
    pub category: Category,
    #[serde(default)]
    pub mitre_technique: Option<String>,
    #[serde(default)]
    pub mitre_tactic: Option<String>,
    /// Declared fidelity string (`marker_only` | `behavioral` | `unspecified`).
    /// Only honoured for `v1alpha2`; ignored for legacy manifests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fidelity: Option<String>,
    /// Multi-technique mapping with per-technique fidelity. Only honoured for
    /// `v1alpha2`. When present the first entry is the primary technique.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mitre_techniques: Option<Vec<TechniqueRef>>,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// Target scope specifying where the synthetic action applies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct TargetScope {
    #[serde(rename = "type", default)]
    pub target_type: String,
    #[serde(default)]
    pub selector: Option<HashMap<String, String>>,
    #[serde(default)]
    pub target_path: Option<String>,
    #[serde(default)]
    pub target_cidr: Option<String>,
}

fn default_max_duration_sec() -> u32 {
    60
}

fn default_cpu_limit_percent() -> u32 {
    25
}

fn default_true() -> bool {
    true
}

/// Safety constraints and limits enforced by the circuit breaker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SafetySpec {
    #[serde(default = "default_max_duration_sec")]
    pub max_duration_sec: u32,
    #[serde(default = "default_cpu_limit_percent")]
    pub cpu_limit_percent: u32,
    #[serde(default)]
    pub canary_directory_only: Option<String>,
    #[serde(default = "default_true")]
    pub circuit_breaker_on_host_unresponsive: bool,
}

impl Default for SafetySpec {
    fn default() -> Self {
        Self {
            max_duration_sec: default_max_duration_sec(),
            cpu_limit_percent: default_cpu_limit_percent(),
            canary_directory_only: None,
            circuit_breaker_on_host_unresponsive: true,
        }
    }
}

/// Action specification defining the synthetic injection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ActionSpec {
    pub nature: ActionNature,
    #[serde(rename = "type")]
    pub action_type: String,
    #[serde(default)]
    pub parameters: HashMap<String, serde_json::Value>,
}

/// Expected outcome and detection metrics for Blue Team verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ExpectedOutcome {
    #[serde(default)]
    pub detector: String,
    #[serde(default)]
    pub expected_mttd_max_ms: Option<u64>,
    #[serde(default)]
    pub expected_containment: Option<String>,
}

/// Manifest specification payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ManifestSpec {
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub target_scope: Option<TargetScope>,
    pub safety: SafetySpec,
    pub action: ActionSpec,
    #[serde(default)]
    pub expected_outcome: ExpectedOutcome,
}

/// Complete declarative scenario manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ScenarioManifest {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: ManifestKind,
    pub metadata: ManifestMetadata,
    pub spec: ManifestSpec,
}

impl ScenarioManifest {
    /// Whether this manifest uses the legacy (`v1alpha1`) schema.
    pub fn is_legacy(&self) -> bool {
        self.api_version == API_VERSION_V1ALPHA1
    }

    /// The fidelity this manifest's results may be trusted at.
    ///
    /// A legacy (`v1alpha1`) manifest is **never** promoted: whatever it may
    /// self-declare, its effective fidelity is [`Fidelity::Unspecified`] — the
    /// lowest trust — so old results read without gaining behavioural or
    /// prevention coverage. A `v1alpha2` manifest honours its declared
    /// `fidelity`, defaulting to `Unspecified` when none is given.
    pub fn effective_fidelity(&self) -> Fidelity {
        if self.is_legacy() {
            return Fidelity::Unspecified;
        }
        self.metadata
            .fidelity
            .as_deref()
            .and_then(Fidelity::parse)
            .unwrap_or_default()
    }

    /// The scenario's technique references, resolved to a uniform list.
    ///
    /// Prefers the explicit `mitre_techniques` list; otherwise falls back to the
    /// single `mitre_technique`. Every entry carries the manifest's effective
    /// fidelity (legacy manifests therefore yield only `Unspecified` refs). An
    /// entry's own declared fidelity is clamped so it can never exceed the
    /// manifest-level effective fidelity.
    pub fn resolved_technique_refs(&self) -> Vec<TechniqueRef> {
        let ceiling = self.effective_fidelity();
        if let Some(ref refs) = self.metadata.mitre_techniques {
            return refs
                .iter()
                .map(|r| TechniqueRef::new(r.technique_id.clone(), r.fidelity.min(ceiling)))
                .collect();
        }
        match self.metadata.mitre_technique {
            Some(ref id) => vec![TechniqueRef::new(id.clone(), ceiling)],
            None => Vec::new(),
        }
    }
}

/// Reason a manifest fails declarative validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestValidationError {
    InvalidApiVersion(String),
    NotSynthetic,
    InvalidCanaryPath(String),
    InvalidNetworkTarget(String),
    CpuLimitExceeded(u32),
    DurationLimitExceeded(u32),
    UnknownMitreTechnique(String),
    InvalidFidelity(String),
    BudgetLimitExceeded(String),
    ParseError(String),
}

impl std::fmt::Display for ManifestValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidApiVersion(v) => write!(
                f,
                "unsupported apiVersion '{v}', expected one of 'asmodeus.io/v1alpha1', 'asmodeus.io/v1alpha2'"
            ),
            Self::NotSynthetic => write!(f, "INV-0 violation: action nature must be 'synthetic'"),
            Self::InvalidCanaryPath(p) => {
                write!(f, "canary path '{p}' is outside permitted canary sandbox")
            }
            Self::InvalidNetworkTarget(c) => write!(
                f,
                "network target '{c}' is outside reserved test net blocks"
            ),
            Self::CpuLimitExceeded(c) => write!(f, "cpu limit {c}% exceeds safe budget of 85%"),
            Self::DurationLimitExceeded(d) => {
                write!(f, "max duration {d}s exceeds maximum limit of 300s")
            }
            Self::UnknownMitreTechnique(t) => write!(f, "unknown MITRE technique '{t}'"),
            Self::InvalidFidelity(v) => write!(
                f,
                "invalid fidelity '{v}', expected 'marker_only', 'behavioral' or 'unspecified'"
            ),
            Self::BudgetLimitExceeded(msg) => write!(f, "resource budget exceeded: {msg}"),
            Self::ParseError(msg) => write!(f, "manifest parse error: {msg}"),
        }
    }
}

impl std::error::Error for ManifestValidationError {}

/// Validates a declarative manifest against INV-0 safety and budget limits.
pub fn validate_manifest(manifest: &ScenarioManifest) -> Result<(), ManifestValidationError> {
    // 1. API version check — accept the legacy and current schema.
    if !SUPPORTED_API_VERSIONS.contains(&manifest.api_version.as_str()) {
        return Err(ManifestValidationError::InvalidApiVersion(
            manifest.api_version.clone(),
        ));
    }

    // 2. INV-0 root invariant: must be synthetic only
    if !manifest.spec.action.nature.is_permitted() {
        return Err(ManifestValidationError::NotSynthetic);
    }

    // 3. Safety limits: duration and CPU
    if manifest.spec.safety.max_duration_sec > 300 {
        return Err(ManifestValidationError::DurationLimitExceeded(
            manifest.spec.safety.max_duration_sec,
        ));
    }
    if manifest.spec.safety.cpu_limit_percent > 85 {
        return Err(ManifestValidationError::CpuLimitExceeded(
            manifest.spec.safety.cpu_limit_percent,
        ));
    }

    // 4. Canary path scope checks
    if let Some(ref canary_dir) = manifest.spec.safety.canary_directory_only {
        if !path_in_scope(canary_dir) {
            return Err(ManifestValidationError::InvalidCanaryPath(
                canary_dir.clone(),
            ));
        }
    }
    if let Some(ref target_scope) = manifest.spec.target_scope {
        if let Some(ref path) = target_scope.target_path {
            if !path_in_scope(path) {
                return Err(ManifestValidationError::InvalidCanaryPath(path.clone()));
            }
        }
        if let Some(ref cidr) = target_scope.target_cidr {
            if !net_target_in_scope(cidr) {
                return Err(ManifestValidationError::InvalidNetworkTarget(cidr.clone()));
            }
        }
    }

    // 5. MITRE technique lookup. Every referenced ID — the single primary and
    //    every entry of the multi-technique list — must resolve in the pinned
    //    taxonomy, so a stale or mistyped technique fails validation (S01).
    if let Some(ref technique_id) = manifest.metadata.mitre_technique {
        if lookup_technique(technique_id).is_none() {
            return Err(ManifestValidationError::UnknownMitreTechnique(
                technique_id.clone(),
            ));
        }
    }
    if let Some(ref refs) = manifest.metadata.mitre_techniques {
        for r in refs {
            if lookup_technique(&r.technique_id).is_none() {
                return Err(ManifestValidationError::UnknownMitreTechnique(
                    r.technique_id.clone(),
                ));
            }
        }
    }

    // 6. Declared fidelity string, if any, must be recognised.
    if let Some(ref f) = manifest.metadata.fidelity {
        if Fidelity::parse(f).is_none() {
            return Err(ManifestValidationError::InvalidFidelity(f.clone()));
        }
    }

    crate::ExecutionPlan::from_manifest(manifest)?;

    Ok(())
}

/// Parse a scenario manifest from either JSON or YAML text and validate it.
pub fn parse_and_validate_manifest(raw: &str) -> Result<ScenarioManifest, ManifestValidationError> {
    let manifest = parse_manifest(raw)?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

/// Parse a scenario manifest from JSON or YAML.
pub fn parse_manifest(raw: &str) -> Result<ScenarioManifest, ManifestValidationError> {
    let trimmed = raw.trim();
    if trimmed.starts_with('{') {
        serde_json::from_str(trimmed)
            .map_err(|e| ManifestValidationError::ParseError(e.to_string()))
    } else {
        let value = parse_yaml_to_json_value(trimmed)?;
        serde_json::from_value(value)
            .map_err(|e| ManifestValidationError::ParseError(e.to_string()))
    }
}

/// Lightweight YAML to JSON Value translator for indented key-value mappings.
pub fn parse_yaml_to_json_value(
    yaml_str: &str,
) -> Result<serde_json::Value, ManifestValidationError> {
    let mut lines = Vec::new();
    for line in yaml_str.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        lines.push((indent, trimmed.to_string()));
    }

    if lines.is_empty() {
        return Err(ManifestValidationError::ParseError(
            "empty manifest input".into(),
        ));
    }

    let mut idx = 0;
    parse_yaml_map(&lines, &mut idx, 0)
}

fn parse_yaml_map(
    lines: &[(usize, String)],
    idx: &mut usize,
    current_indent: usize,
) -> Result<serde_json::Value, ManifestValidationError> {
    let mut map = serde_json::Map::new();

    while *idx < lines.len() {
        let (indent, ref line_text) = lines[*idx];
        if indent < current_indent {
            break;
        }
        if indent > current_indent {
            return Err(ManifestValidationError::ParseError(format!(
                "unexpected indentation at line: {line_text}"
            )));
        }

        // Split key: value
        let Some((key_raw, val_raw)) = line_text.split_once(':') else {
            return Err(ManifestValidationError::ParseError(format!(
                "expected key: value pair, found: {line_text}"
            )));
        };

        let key = key_raw.trim().to_string();
        let val_trimmed = val_raw.trim();
        *idx += 1;

        let value = if val_trimmed.is_empty() {
            // Check next line indent to determine child block
            if *idx < lines.len() && lines[*idx].0 > indent {
                let child_indent = lines[*idx].0;
                parse_yaml_map(lines, idx, child_indent)?
            } else {
                serde_json::Value::Null
            }
        } else {
            parse_scalar_value(val_trimmed)
        };

        if map.insert(key.clone(), value).is_some() {
            return Err(ManifestValidationError::ParseError(format!(
                "duplicate key: {key}"
            )));
        }
    }

    Ok(serde_json::Value::Object(map))
}

fn parse_scalar_value(raw: &str) -> serde_json::Value {
    let s = raw.trim();
    if ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
        && s.len() >= 2
    {
        return serde_json::Value::String(s[1..s.len() - 1].to_string());
    }
    if s == "true" {
        return serde_json::Value::Bool(true);
    }
    if s == "false" {
        return serde_json::Value::Bool(false);
    }
    if s == "null" {
        return serde_json::Value::Null;
    }
    if let Ok(num) = s.parse::<i64>() {
        return serde_json::Value::Number(num.into());
    }
    if let Ok(f) = s.parse::<f64>() {
        if let Some(num) = serde_json::Number::from_f64(f) {
            return serde_json::Value::Number(num);
        }
    }
    serde_json::Value::String(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_YAML: &str = r#"
apiVersion: asmodeus.io/v1alpha1
kind: AttackScenario
metadata:
  id: "SCN-RT-001"
  name: "Ransomware Canary Encryption Spike"
  category: "red_team"
  mitre_technique: "T1486"
  severity: "high"
spec:
  author: "Red Team Lead"
  target_scope:
    type: "k8s_workload"
    target_path: "/var/tmp/asmodeus-canary/test.docx"
  safety:
    max_duration_sec: 60
    cpu_limit_percent: 25
    canary_directory_only: "/var/tmp/asmodeus-canary"
    circuit_breaker_on_host_unresponsive: true
  action:
    nature: "synthetic"
    type: "synthetic_canary_encrypt"
    parameters:
      file_count: 50
      chunk_size_kb: 64
      io_rate_per_sec: 75
  expected_outcome:
    detector: "ferrum_ebpf"
    expected_mttd_max_ms: 300
    expected_containment: "sigkill_by_kernel"
"#;

    #[test]
    fn parses_and_validates_yaml_manifest() {
        let manifest = parse_and_validate_manifest(VALID_YAML).unwrap();
        assert_eq!(manifest.api_version, "asmodeus.io/v1alpha1");
        assert_eq!(manifest.kind, ManifestKind::AttackScenario);
        assert_eq!(manifest.metadata.id, "SCN-RT-001");
        assert_eq!(manifest.metadata.category, Category::RedTeam);
        assert_eq!(manifest.metadata.mitre_technique.as_deref(), Some("T1486"));
        assert_eq!(manifest.spec.safety.max_duration_sec, 60);
        assert_eq!(manifest.spec.safety.cpu_limit_percent, 25);
        assert_eq!(manifest.spec.action.nature, ActionNature::Synthetic);
    }

    #[test]
    fn rejects_operational_action_by_inv0() {
        let non_synthetic_yaml =
            VALID_YAML.replace("nature: \"synthetic\"", "nature: \"operational\"");
        let res = parse_and_validate_manifest(&non_synthetic_yaml);
        assert_eq!(res, Err(ManifestValidationError::NotSynthetic));
    }

    #[test]
    fn rejects_out_of_scope_canary_path() {
        let out_of_scope = VALID_YAML.replace(
            "canary_directory_only: \"/var/tmp/asmodeus-canary\"",
            "canary_directory_only: \"/etc/shadow\"",
        );
        let res = parse_and_validate_manifest(&out_of_scope);
        assert!(matches!(
            res,
            Err(ManifestValidationError::InvalidCanaryPath(_))
        ));
    }

    #[test]
    fn rejects_excessive_cpu_and_duration() {
        let excessive_cpu = VALID_YAML.replace("cpu_limit_percent: 25", "cpu_limit_percent: 95");
        assert_eq!(
            parse_and_validate_manifest(&excessive_cpu),
            Err(ManifestValidationError::CpuLimitExceeded(95))
        );

        let excessive_duration =
            VALID_YAML.replace("max_duration_sec: 60", "max_duration_sec: 600");
        assert_eq!(
            parse_and_validate_manifest(&excessive_duration),
            Err(ManifestValidationError::DurationLimitExceeded(600))
        );
    }

    #[test]
    fn rejects_unknown_mitre_technique() {
        let unknown_mitre =
            VALID_YAML.replace("mitre_technique: \"T1486\"", "mitre_technique: \"T9999\"");
        assert_eq!(
            parse_and_validate_manifest(&unknown_mitre),
            Err(ManifestValidationError::UnknownMitreTechnique(
                "T9999".into()
            ))
        );
    }

    #[test]
    fn rejects_over_budget_parameters() {
        let over_budget = VALID_YAML.replace("file_count: 50", "file_count: 500");
        assert!(matches!(
            parse_and_validate_manifest(&over_budget),
            Err(ManifestValidationError::BudgetLimitExceeded(_))
        ));
    }

    // ---- S01: fidelity / versioning / multi-technique ----

    const V2_JSON: &str = r#"{
        "apiVersion": "asmodeus.io/v1alpha2",
        "kind": "AttackScenario",
        "metadata": {
            "id": "SCN-V2-001",
            "name": "Behavioral canary",
            "category": "red_team",
            "fidelity": "behavioral",
            "mitre_techniques": [
                {"technique_id": "T1486", "fidelity": "behavioral"},
                {"technique_id": "T1071.001", "fidelity": "marker_only"}
            ],
            "severity": "high"
        },
        "spec": {
            "target_scope": {"type": "fs", "target_path": "/tmp/asmodeus-canary/d"},
            "safety": {"max_duration_sec": 30, "cpu_limit_percent": 10},
            "action": {"nature": "synthetic", "type": "synthetic_canary_encrypt",
                       "parameters": {"file_count": 10, "chunk_size_kb": 4}},
            "expected_outcome": {"detector": "ferrum"}
        }
    }"#;

    #[test]
    fn v1alpha2_is_accepted_and_honours_declared_fidelity() {
        let m = parse_and_validate_manifest(V2_JSON).unwrap();
        assert_eq!(m.api_version, API_VERSION_V1ALPHA2);
        assert!(!m.is_legacy());
        assert_eq!(m.effective_fidelity(), Fidelity::Behavioral);
        let refs = m.resolved_technique_refs();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].technique_id, "T1486");
        assert_eq!(refs[0].fidelity, Fidelity::Behavioral);
        // Second ref self-declares marker_only; stays marker_only (<= ceiling).
        assert_eq!(refs[1].fidelity, Fidelity::MarkerOnly);
    }

    #[test]
    fn legacy_manifest_is_never_promoted_even_if_it_declares_behavioral() {
        // A v1alpha1 doc that tries to claim behavioral fidelity.
        let legacy = V2_JSON.replace("v1alpha2", "v1alpha1");
        let m = parse_and_validate_manifest(&legacy).unwrap();
        assert!(m.is_legacy());
        // Effective fidelity is clamped to the lowest trust regardless.
        assert_eq!(m.effective_fidelity(), Fidelity::Unspecified);
        for r in m.resolved_technique_refs() {
            assert_eq!(r.fidelity, Fidelity::Unspecified);
            assert!(!r.fidelity.claims_behavioral());
        }
    }

    #[test]
    fn unknown_technique_in_multi_list_is_rejected() {
        let bad = V2_JSON.replace("T1071.001", "T9999.999");
        assert_eq!(
            parse_and_validate_manifest(&bad),
            Err(ManifestValidationError::UnknownMitreTechnique(
                "T9999.999".into()
            ))
        );
    }

    #[test]
    fn invalid_declared_fidelity_is_rejected() {
        // Only the metadata-level string field (not the strongly-typed
        // per-technique fidelity, which serde would reject as a parse error).
        let bad = V2_JSON.replace("\"fidelity\": \"behavioral\",", "\"fidelity\": \"weaponized\",");
        assert!(matches!(
            parse_and_validate_manifest(&bad),
            Err(ManifestValidationError::InvalidFidelity(_))
        ));
    }

    #[test]
    fn unsupported_api_version_is_rejected() {
        let bad = V2_JSON.replace("v1alpha2", "v9beta9");
        assert!(matches!(
            parse_and_validate_manifest(&bad),
            Err(ManifestValidationError::InvalidApiVersion(_))
        ));
    }

    #[test]
    fn parses_and_validates_json_manifest() {
        let json_str = r#"{
            "apiVersion": "asmodeus.io/v1alpha1",
            "kind": "ChaosExperiment",
            "metadata": {
                "id": "CHAOS-NET-001",
                "name": "Synthetic Latency Spike",
                "category": "chaos",
                "severity": "medium"
            },
            "spec": {
                "target_scope": {
                    "type": "network_gateway",
                    "target_cidr": "127.0.0.1/32"
                },
                "safety": {
                    "max_duration_sec": 30,
                    "cpu_limit_percent": 10
                },
                "action": {
                    "nature": "synthetic",
                    "type": "latency_spike",
                    "parameters": {
                        "latency_ms": 100,
                        "loss_percent": 5
                    }
                },
                "expected_outcome": {
                    "detector": "bsdm_proxy"
                }
            }
        }"#;

        let manifest = parse_and_validate_manifest(json_str).unwrap();
        assert_eq!(manifest.kind, ManifestKind::ChaosExperiment);
        assert_eq!(manifest.metadata.id, "CHAOS-NET-001");
        assert_eq!(manifest.metadata.category, Category::Chaos);
    }
}
