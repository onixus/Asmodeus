//! Compiled, bounded execution parameters shared by control plane and runner.
use crate::{ManifestValidationError as Error, ScenarioManifest};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    SyntheticCanaryEncrypt,
    K8sEscapeProbe,
    C2Beacon,
    CredentialCanary,
    LogTamperCanary,
    PersistenceCanary,
    ExfiltrationCanary,
    WatchdogProbe,
    LatencySpike,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionPlan {
    pub action: Action,
    pub target_dir: String,
    pub file_count: u32,
    pub chunk_size_kb: u32,
    pub io_rate_per_sec: u32,
    pub duration_ms: u32,
    pub max_duration_sec: u32,
    pub cpu_limit_percent: u32,
    pub target_cidr: String,
    pub iface: String,
    pub latency_ms: u32,
    pub jitter_ms: u32,
    pub loss_percent: u8,
}

pub fn action_for_scenario(id: &str) -> &'static str {
    match id {
        "RANSOMWARE_CANARY_SPIKE" => "synthetic_canary_encrypt",
        "K8S_ESCAPE_SIMULATION" => "k8s_escape_probe",
        "C2_BEACONING_SIMULATION" => "c2_beacon",
        "CREDENTIAL_ACCESS_CANARY" => "credential_canary",
        "LOG_TAMPER_CANARY" => "log_tamper_canary",
        "PERSISTENCE_CRON_CANARY" => "persistence_canary",
        "DATA_EXFILTRATION_CANARY" => "exfiltration_canary",
        "DEFENSE_IMPAIRMENT_CANARY" | "AGENT_CRASH_ENDPOINT" => "watchdog_probe",
        "LATENCY_SPIKE_VM" | "DNS_RPZ_SINKHOLE_DROP" => "latency_spike",
        _ => "unsupported",
    }
}

impl ExecutionPlan {
    pub fn from_manifest(m: &ScenarioManifest) -> Result<Self, Error> {
        let invalid = |message: String| Error::BudgetLimitExceeded(message);
        let action: Action =
            serde_json::from_value(serde_json::Value::String(m.spec.action.action_type.clone()))
                .map_err(|_| {
                    invalid(format!(
                        "unsupported action type: {}",
                        m.spec.action.action_type
                    ))
                })?;
        let parameters = &m.spec.action.parameters;
        for name in parameters.keys() {
            let allowed = name == "duration_ms"
                || match action {
                    Action::SyntheticCanaryEncrypt => {
                        ["file_count", "chunk_size_kb", "io_rate_per_sec"].contains(&name.as_str())
                    }
                    Action::C2Beacon => name == "file_count",
                    Action::ExfiltrationCanary => name == "chunk_size_kb",
                    Action::LatencySpike => ["latency_ms", "jitter_ms", "loss_percent", "iface"]
                        .contains(&name.as_str()),
                    _ => false,
                };
            if !allowed {
                return Err(invalid(format!(
                    "unsupported parameter for this action: {name}"
                )));
            }
        }
        let number = |name: &str, default: u32, min: u32, max: u32| -> Result<u32, Error> {
            match parameters.get(name) {
                None => Ok(default),
                Some(value) => match value.as_u64() {
                    Some(n) if n >= u64::from(min) && n <= u64::from(max) => Ok(n as u32),
                    _ => Err(invalid(format!(
                        "{name} must be an integer in {min}..={max}"
                    ))),
                },
            }
        };
        if m.spec.safety.max_duration_sec == 0 {
            return Err(invalid("max_duration_sec must be positive".into()));
        }
        if m.spec.safety.cpu_limit_percent == 0 {
            return Err(invalid("cpu_limit_percent must be positive".into()));
        }
        if m.spec
            .target_scope
            .as_ref()
            .and_then(|s| s.selector.as_ref())
            .is_some_and(|s| !s.is_empty())
        {
            return Err(invalid(
                "target_scope.selector is unsupported; select a registered runner by ID/tag".into(),
            ));
        }
        if !m.spec.safety.circuit_breaker_on_host_unresponsive {
            return Err(invalid(
                "disabling the control-channel lease is unsupported".into(),
            ));
        }
        let target_dir = m
            .spec
            .target_scope
            .as_ref()
            .and_then(|s| s.target_path.clone())
            .or_else(|| m.spec.safety.canary_directory_only.clone())
            .unwrap_or_else(|| "/tmp/asmodeus-canary".into());
        if let Some(scope) = &m.spec.safety.canary_directory_only {
            if !std::path::Path::new(&target_dir).starts_with(scope) {
                return Err(invalid(
                    "target_path must be inside canary_directory_only".into(),
                ));
            }
        }
        let file_count = number(
            "file_count",
            20,
            1,
            if action == Action::C2Beacon { 100 } else { 200 },
        )?;
        let chunk_size_kb = number("chunk_size_kb", 64, 1, 256)?;
        if u64::from(file_count) * u64::from(chunk_size_kb) > 20 * 1024 {
            return Err(invalid("total canary data exceeds 20 MiB".into()));
        }
        let iface = match parameters.get("iface") {
            Some(serde_json::Value::String(s)) if !s.is_empty() && s.len() <= 15 => s.clone(),
            Some(_) => {
                return Err(invalid(
                    "iface must be a nonempty string of at most 15 bytes".into(),
                ))
            }
            None => "lo".into(),
        };
        let duration_ms = number("duration_ms", 0, 0, 120_000)?;
        if duration_ms > m.spec.safety.max_duration_sec.saturating_mul(1000) {
            return Err(invalid("duration_ms exceeds max_duration_sec".into()));
        }
        let target_cidr = m
            .spec
            .target_scope
            .as_ref()
            .and_then(|s| s.target_cidr.clone())
            .unwrap_or_else(|| "127.0.0.1/32".into());
        if action != Action::LatencySpike
            && m.spec
                .target_scope
                .as_ref()
                .and_then(|s| s.target_cidr.as_ref())
                .is_some()
        {
            return Err(invalid(
                "target_cidr is supported only by latency_spike".into(),
            ));
        }
        Ok(Self {
            action,
            target_dir,
            file_count,
            chunk_size_kb,
            io_rate_per_sec: number("io_rate_per_sec", 0, 1, 1000)?,
            duration_ms,
            max_duration_sec: m.spec.safety.max_duration_sec,
            cpu_limit_percent: m.spec.safety.cpu_limit_percent,
            target_cidr,
            iface,
            latency_ms: number("latency_ms", 100, 0, 5000)?,
            jitter_ms: number("jitter_ms", 0, 0, 1000)?,
            loss_percent: number("loss_percent", 0, 0, 50)? as u8,
        })
    }
}

/// Complete typed fixture for built-in scenarios and integration tests.
pub fn synthetic_manifest(
    id: &str,
    target: &str,
    file_count: u32,
    chunk_size_kb: u32,
) -> ScenarioManifest {
    let action = action_for_scenario(id);
    let mut parameters: std::collections::HashMap<String, serde_json::Value> =
        std::collections::HashMap::new();
    if matches!(action, "synthetic_canary_encrypt" | "c2_beacon") {
        parameters.insert("file_count".into(), file_count.into());
    }
    if matches!(action, "synthetic_canary_encrypt" | "exfiltration_canary") {
        parameters.insert("chunk_size_kb".into(), chunk_size_kb.into());
    }
    serde_json::from_value(serde_json::json!({
        "apiVersion":"asmodeus.io/v1alpha1", "kind":"AttackScenario",
        "metadata":{"id":id,"name":id,"category":"red_team"},
        "spec":{"target_scope":{"target_path":target},"safety":{},"action":{"nature":"synthetic","type":action,"parameters":parameters}}
    })).expect("built-in manifest schema")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compiled_parameters_are_strict_and_bound_to_the_signed_scope() {
        let mut manifest =
            synthetic_manifest("RANSOMWARE_CANARY_SPIKE", "/tmp/asmodeus-canary/test", 7, 3);
        manifest.metadata.id = "CUSTOM".into();
        let plan = ExecutionPlan::from_manifest(&manifest).unwrap();
        assert_eq!((plan.file_count, plan.chunk_size_kb), (7, 3));
        for (key, value) in [
            ("file_count", serde_json::json!("7")),
            ("file_count", serde_json::json!(-1)),
            ("unknown", serde_json::json!(1)),
            ("latency_ms", serde_json::json!(1)),
        ] {
            let mut invalid = manifest.clone();
            invalid.spec.action.parameters.insert(key.into(), value);
            assert!(ExecutionPlan::from_manifest(&invalid).is_err());
        }
        manifest.spec.action.action_type = "invented-action".into();
        assert!(ExecutionPlan::from_manifest(&manifest).is_err());
    }
}
