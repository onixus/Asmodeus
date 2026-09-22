//! Shared HTTP request DTOs used by multiple transport modules.

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunScenarioPayload {
    pub target_override: Option<String>,
    pub timeout_sec: Option<u32>,
    #[serde(default)]
    pub background: bool,
}
