//! Shared HTTP request DTOs used by multiple transport modules.

#[derive(Debug, Default, serde::Deserialize)]
pub struct RunScenarioPayload {
    pub target_override: Option<String>,
    #[allow(dead_code)]
    pub timeout_sec: Option<u32>,
}
