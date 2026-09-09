//! Asynchronous webhook notification dispatcher for Asmodeus.
//!
//! Notifies external APEX components (Ferrum, Lariska, BSDM, SOAR) of
//! exercise lifecycle events (`exercise_started`, `exercise_completed`,
//! `exercise_aborted`, `drift_detected`) over HTTP with Ed25519 signature verification.

use std::time::Duration;

use asmodeus_crypto::sign_message;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Webhook event payload sent to external subscribers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub event: String,
    pub timestamp_utc: String,
    pub exercise_id: String,
    pub scenario_id: String,
    pub mitre_technique: String,
    pub target: String,
    pub initiator: String,
    pub tag: String,
    pub data: Value,
}

/// Asynchronous webhook dispatcher.
#[derive(Debug, Clone)]
pub struct WebhookDispatcher {
    webhook_url: Option<String>,
    auth_token: Option<String>,
    client: reqwest::Client,
}

impl Default for WebhookDispatcher {
    fn default() -> Self {
        Self::from_env()
    }
}

impl WebhookDispatcher {
    /// Initialize dispatcher from environment variables:
    /// - `ASMODEUS_WEBHOOK_URL`
    /// - `ASMODEUS_WEBHOOK_SECRET` / `ASMODEUS_WEBHOOK_TOKEN`
    pub fn from_env() -> Self {
        let webhook_url = std::env::var("ASMODEUS_WEBHOOK_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let auth_token = std::env::var("ASMODEUS_WEBHOOK_SECRET")
            .or_else(|_| std::env::var("ASMODEUS_WEBHOOK_TOKEN"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            webhook_url,
            auth_token,
            client,
        }
    }

    /// Create dispatcher with an explicit URL and optional auth token.
    #[allow(dead_code)]
    pub fn new(url: Option<String>, token: Option<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            webhook_url: url,
            auth_token: token,
            client,
        }
    }

    /// Whether a webhook target URL is configured.
    #[allow(dead_code)]
    pub fn is_enabled(&self) -> bool {
        self.webhook_url.is_some()
    }

    /// Target webhook endpoint if configured.
    #[allow(dead_code)]
    pub fn url(&self) -> Option<&str> {
        self.webhook_url.as_deref()
    }

    /// Asynchronously dispatch an event in the background without blocking the caller.
    pub fn dispatch(&self, payload: WebhookPayload, signing_key: Option<&[u8; 64]>) {
        let Some(url) = self.webhook_url.clone() else {
            return;
        };

        let client = self.client.clone();
        let token = self.auth_token.clone();
        let key = signing_key.copied();

        tokio::spawn(async move {
            let json_body = match serde_json::to_string(&payload) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("failed to serialize webhook payload: {e}");
                    return;
                }
            };

            let mut req = client
                .post(&url)
                .header("Content-Type", "application/json")
                .header("User-Agent", "Asmodeus-Control-Plane/0.1.0");

            if let Some(tok) = token {
                req = req.header("X-Asmodeus-Token", tok);
            }

            if let Some(sk) = key {
                if let Ok(sig) = sign_message(&sk, json_body.as_bytes()) {
                    let sig_hex = hex_encode(&sig);
                    req = req.header("X-Asmodeus-Signature", sig_hex);
                }
            }

            match req.body(json_body).send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        tracing::debug!(event = %payload.event, %url, status = %resp.status(), "webhook dispatched successfully");
                    } else {
                        tracing::warn!(event = %payload.event, %url, status = %resp.status(), "webhook received non-success response");
                    }
                }
                Err(e) => {
                    tracing::warn!(event = %payload.event, %url, error = %e, "failed to send webhook request");
                }
            }
        });
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_payload_serialization() {
        let payload = WebhookPayload {
            event: "exercise_started".into(),
            timestamp_utc: "2026-09-09T22:30:00Z".into(),
            exercise_id: "ex-123".into(),
            scenario_id: "SCN-RT-001".into(),
            mitre_technique: "T1486".into(),
            target: "local-sim".into(),
            initiator: "admin".into(),
            tag: "🔴 [RED TEAM EXERCISE]".into(),
            data: serde_json::json!({
                "file_count": 50,
                "scope": "/tmp/asmodeus-canary"
            }),
        };

        let serialized = serde_json::to_string(&payload).unwrap();
        assert!(serialized.contains("exercise_started"));
        assert!(serialized.contains("🔴 [RED TEAM EXERCISE]"));
    }

    #[test]
    fn test_webhook_dispatcher_disabled_when_empty() {
        let disp = WebhookDispatcher::new(None, None);
        assert!(!disp.is_enabled());
        assert_eq!(disp.url(), None);
    }

    #[test]
    fn test_webhook_dispatcher_enabled() {
        let disp = WebhookDispatcher::new(
            Some("http://127.0.0.1:9999/webhook".into()),
            Some("secret-token".into()),
        );
        assert!(disp.is_enabled());
        assert_eq!(disp.url(), Some("http://127.0.0.1:9999/webhook"));
    }
}
