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
    /// Chaos: synthetic agent-crash probe against a decoy process (FTT §4.2.2).
    AgentCrashProbe,
    LatencySpike,
    /// Chaos: simulated DNS RPZ sinkhole outage on the loopback test segment
    /// (FTT §4.2.3) — a full-drop rule rather than a latency perturbation.
    DnsSinkholeDrop,
}

impl Action {
    /// True iff this action drives the network-chaos backend (a real or
    /// simulated tc/eBPF rule on a reserved test segment), as opposed to a
    /// filesystem marker injector.
    pub fn is_net_chaos(&self) -> bool {
        matches!(self, Action::LatencySpike | Action::DnsSinkholeDrop)
    }
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
    /// Chaos DNS port targeted by `dns_sinkhole_drop` (FTT §4.2.3: the sinkhole
    /// outage is simulated by dropping traffic to the resolver port). Bounded
    /// to the unprivileged/standard DNS range and only honoured by net-chaos
    /// actions.
    pub dns_port: u16,
}

/// Default chaos parameters per scenario ID (FTT §4.2). A manifest may override
/// any of these through `spec.action.parameters`; the overrides are still bound
/// by the resource envelope validated in [`ExecutionPlan::from_manifest`] and
/// by `NetChaosSpec::validate` on the runner.
pub fn chaos_defaults(scenario_id: &str) -> Option<(&'static str, u32, u32, u32, u32)> {
    Some(match scenario_id {
        // 2500 ms latency / 25 % drop, FTT §4.2.1.
        "LATENCY_SPIKE_VM" => ("lo", 2_500, 250, 25, 5_000),
        // RPZ sinkhole outage: full drop on the loopback test segment, FTT §4.2.3.
        "DNS_RPZ_SINKHOLE_DROP" => ("lo", 0, 0, 100, 5_000),
        _ => return None,
    })
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
        "DEFENSE_IMPAIRMENT_CANARY" => "watchdog_probe",
        "AGENT_CRASH_ENDPOINT" => "agent_crash_probe",
        "LATENCY_SPIKE_VM" => "latency_spike",
        "DNS_RPZ_SINKHOLE_DROP" => "dns_sinkhole_drop",
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
                    Action::AgentCrashProbe => name == "recovery_window_ms",
                    Action::LatencySpike | Action::DnsSinkholeDrop => [
                        "latency_ms",
                        "jitter_ms",
                        "loss_percent",
                        "iface",
                        "dns_port",
                    ]
                    .contains(&name.as_str()),
                    _ => false,
                };
            if !allowed {
                return Err(invalid(format!(
                    "unsupported parameter for this action: {name}"
                )));
            }
        }
        // Chaos defaults (FTT §4.2) seed the numeric envelope per scenario ID;
        // manifest parameters override them and are still clamped by the bounds
        // below and re-validated by the runner's NetChaosSpec gate.
        let defaults = chaos_defaults(&m.metadata.id);
        let d_iface = defaults.map(|d| d.0).unwrap_or("lo");
        let d_latency = defaults.map(|d| d.1).unwrap_or(100);
        let d_jitter = defaults.map(|d| d.2).unwrap_or(0);
        let d_loss = defaults.map(|d| d.3).unwrap_or(0);
        let d_duration = defaults.map(|d| d.4).unwrap_or(0);
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
            None => d_iface.to_string(),
        };
        let duration_ms = number("duration_ms", d_duration, 0, 120_000)?;
        if duration_ms > m.spec.safety.max_duration_sec.saturating_mul(1000) {
            return Err(invalid("duration_ms exceeds max_duration_sec".into()));
        }
        let target_cidr = m
            .spec
            .target_scope
            .as_ref()
            .and_then(|s| s.target_cidr.clone())
            .unwrap_or_else(|| "127.0.0.1/32".into());
        if !action.is_net_chaos()
            && m.spec
                .target_scope
                .as_ref()
                .and_then(|s| s.target_cidr.as_ref())
                .is_some()
        {
            return Err(invalid(
                "target_cidr is supported only by net-chaos actions (latency_spike, \
                 dns_sinkhole_drop)"
                    .into(),
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
            latency_ms: number("latency_ms", d_latency, 0, 5000)?,
            jitter_ms: number("jitter_ms", d_jitter, 0, 1000)?,
            loss_percent: number("loss_percent", d_loss, 0, 100)? as u8,
            dns_port: number("dns_port", 53, 1, 65535)? as u16,
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
    // Chaos scenarios carry their FTT-pinned defaults (§4.2) as explicit
    // parameters so a preset plan exercises the same override path an operator
    // manifest would (rather than relying on hardcoded runner values).
    if let Some((iface, latency, jitter, loss, duration)) = chaos_defaults(id) {
        parameters.insert("iface".into(), iface.into());
        parameters.insert("latency_ms".into(), latency.into());
        parameters.insert("jitter_ms".into(), jitter.into());
        parameters.insert("loss_percent".into(), loss.into());
        parameters.insert("duration_ms".into(), duration.into());
    }
    if action == "agent_crash_probe" {
        // FTT §4.2.2 pins the watchdog recovery window at < 5 s.
        parameters.insert("recovery_window_ms".into(), 5_000u32.into());
        parameters.insert("duration_ms".into(), 5_000u32.into());
    }
    serde_json::from_value(serde_json::json!({
        "apiVersion":"asmodeus.io/v1alpha1", "kind":"AttackScenario",
        "metadata":{"id":id,"name":id,"category":"red_team"},
        "spec":{"target_scope":{"target_path":target},"safety":{},"action":{"nature":"synthetic","type":action,"parameters":parameters}}
    })).expect("built-in manifest schema")
}

/// Compile a ready-to-run [`ExecutionPlan`] for a built-in scenario preset.
/// Used by the runner's convenience factory (`create_injector`) where no signed
/// manifest is at hand; the chaos parameters are the FTT-pinned defaults, so
/// preset dispatch and manifest dispatch agree on one source of truth.
pub fn execution_plan_for_preset(
    id: &str,
    target_dir: &str,
    file_count: u32,
    chunk_size_kb: u32,
) -> Option<ExecutionPlan> {
    if action_for_scenario(id) == "unsupported" {
        return None;
    }
    let manifest = synthetic_manifest(id, target_dir, file_count, chunk_size_kb);
    ExecutionPlan::from_manifest(&manifest).ok()
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
