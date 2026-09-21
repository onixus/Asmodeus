//! HTTP boundary primitives shared by transport handlers.

use asmodeus_common::Role;
use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::hmac;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

const APEX_CONTRACT_VERSION: &str = "1.0";
const DEFAULT_APEX_ISSUER: &str = "https://identity.apex.local";
const DEFAULT_APEX_AUDIENCE: &str = "apex";

#[derive(Debug)]
pub(crate) enum ApiError {
    Unauthorized(&'static str),
    Forbidden(&'static str),
    NotFound(String),
    Unprocessable(String),
    Internal(String),
    BadGateway(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Unauthorized(m) => write!(f, "Unauthorized: {m}"),
            ApiError::Forbidden(m) => write!(f, "Forbidden: {m}"),
            ApiError::NotFound(m) => write!(f, "Not Found: {m}"),
            ApiError::Unprocessable(m) => write!(f, "Unprocessable: {m}"),
            ApiError::Internal(m) => write!(f, "Internal: {m}"),
            ApiError::BadGateway(m) => write!(f, "Bad Gateway: {m}"),
        }
    }
}

impl std::error::Error for ApiError {}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (code, msg) = match self {
            ApiError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m.to_string()),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, m.to_string()),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApiError::Unprocessable(m) => (StatusCode::UNPROCESSABLE_ENTITY, m),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
            ApiError::BadGateway(m) => (StatusCode::BAD_GATEWAY, m),
        };
        (code, Json(json!({ "error": msg }))).into_response()
    }
}

fn env_or(name: &str, default: &'static str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn audience_matches(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(one) => one == expected,
        Value::Array(many) => many.iter().any(|item| item.as_str() == Some(expected)),
        _ => false,
    }
}

fn required_text<'a>(claims: &'a Value, key: &str) -> Result<&'a str, ApiError> {
    claims
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(ApiError::Unauthorized("missing required APEX identity claim"))
}

fn verified_apex_claims(token: &str) -> Result<Value, ApiError> {
    let mut parts = token.split('.');
    let header_part = parts
        .next()
        .ok_or(ApiError::Unauthorized("malformed bearer token"))?;
    let payload_part = parts
        .next()
        .ok_or(ApiError::Unauthorized("malformed bearer token"))?;
    let signature_part = parts
        .next()
        .ok_or(ApiError::Unauthorized("malformed bearer token"))?;
    if parts.next().is_some() {
        return Err(ApiError::Unauthorized("malformed bearer token"));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_part)
        .map_err(|_| ApiError::Unauthorized("malformed bearer token"))?;
    let header: Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| ApiError::Unauthorized("malformed bearer token"))?;
    if header.get("alg").and_then(Value::as_str) != Some("HS256") {
        return Err(ApiError::Unauthorized("unsupported bearer token algorithm"));
    }

    let secret = std::env::var("ASMODEUS_JWT_SECRET")
        .map_err(|_| ApiError::Unauthorized("JWT verifier is not configured"))?;
    if secret.as_bytes().len() < 32 {
        return Err(ApiError::Unauthorized("JWT verifier secret is too short"));
    }

    let signature = URL_SAFE_NO_PAD
        .decode(signature_part)
        .map_err(|_| ApiError::Unauthorized("malformed bearer token"))?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let signing_input = format!("{header_part}.{payload_part}");
    hmac::verify(&key, signing_input.as_bytes(), &signature)
        .map_err(|_| ApiError::Unauthorized("invalid bearer token signature"))?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_part)
        .map_err(|_| ApiError::Unauthorized("malformed bearer token"))?;
    let claims: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|_| ApiError::Unauthorized("malformed bearer token"))?;

    let issuer = env_or("ASMODEUS_JWT_ISSUER", DEFAULT_APEX_ISSUER);
    if required_text(&claims, "iss")? != issuer {
        return Err(ApiError::Unauthorized("unexpected bearer token issuer"));
    }
    let audience = env_or("ASMODEUS_JWT_AUDIENCE", DEFAULT_APEX_AUDIENCE);
    if !audience_matches(
        claims
            .get("aud")
            .ok_or(ApiError::Unauthorized("missing required APEX identity claim"))?,
        &audience,
    ) {
        return Err(ApiError::Unauthorized("unexpected bearer token audience"));
    }

    if required_text(&claims, "actor_type")? != "user" {
        return Err(ApiError::Unauthorized("unsupported APEX actor type"));
    }
    if required_text(&claims, "apex_contract_version")? != APEX_CONTRACT_VERSION {
        return Err(ApiError::Unauthorized("unsupported APEX contract version"));
    }
    let _ = required_text(&claims, "sub")?;
    let _ = required_text(&claims, "tenant_id")?;
    let _ = required_text(&claims, "jti")?;
    if !claims
        .get("permissions")
        .is_some_and(|permissions| permissions.is_array())
    {
        return Err(ApiError::Unauthorized("missing required APEX identity claim"));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::Unauthorized("system time is before Unix epoch"))?
        .as_secs();
    let iat = claims
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or(ApiError::Unauthorized("missing required APEX identity claim"))?;
    let nbf = claims
        .get("nbf")
        .and_then(Value::as_u64)
        .ok_or(ApiError::Unauthorized("missing required APEX identity claim"))?;
    let exp = claims
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or(ApiError::Unauthorized("missing required APEX identity claim"))?;

    if iat > now.saturating_add(60) || nbf > now.saturating_add(60) {
        return Err(ApiError::Unauthorized("bearer token is not active"));
    }
    if exp <= now {
        return Err(ApiError::Unauthorized("bearer token has expired"));
    }

    Ok(claims)
}

fn role_from_bearer(headers: &HeaderMap) -> Result<Option<Role>, ApiError> {
    let Some(raw) = headers.get("authorization") else {
        return Ok(None);
    };
    let raw = raw
        .to_str()
        .map_err(|_| ApiError::Unauthorized("malformed Authorization header"))?;
    let (scheme, token) = raw
        .split_once(' ')
        .ok_or(ApiError::Unauthorized("malformed Authorization header"))?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
        return Err(ApiError::Unauthorized("expected Bearer authorization"));
    }

    let claims = verified_apex_claims(token)?;
    required_text(&claims, "role")?
        .parse::<Role>()
        .map(Some)
        .map_err(|_| ApiError::Unauthorized("unknown APEX role"))
}

fn allow_unsigned_role_header() -> bool {
    std::env::var("ASMODEUS_ALLOW_ROLE_HEADER")
        .ok()
        .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
}

/// Resolve the caller role from a signed APEX v1 bearer token.
///
/// `X-Apex-Role` is deliberately ignored by default. It is available only
/// when `ASMODEUS_ALLOW_ROLE_HEADER=1` for an isolated local/demo stand. This
/// keeps authorization inside the owning service instead of trusting a role
/// asserted by the upstream Gateway.
pub(crate) fn caller_role(headers: &HeaderMap) -> Result<Role, ApiError> {
    if let Some(role) = role_from_bearer(headers)? {
        return Ok(role);
    }

    if allow_unsigned_role_header() {
        let raw = headers
            .get("x-apex-role")
            .and_then(|value| value.to_str().ok())
            .ok_or(ApiError::Unauthorized("missing Authorization bearer token"))?;
        return raw
            .parse::<Role>()
            .map_err(|_| ApiError::Unauthorized("unknown APEX role"));
    }

    Err(ApiError::Unauthorized("missing Authorization bearer token"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TEST_SECRET: &str = "asmodeus-apex-test-secret-32-bytes-minimum";

    fn token(role: &str, patch: impl FnOnce(&mut Value)) -> String {
        std::env::set_var("ASMODEUS_JWT_SECRET", TEST_SECRET);
        std::env::remove_var("ASMODEUS_ALLOW_ROLE_HEADER");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let header = json!({"alg": "HS256", "typ": "JWT"});
        let mut claims = json!({
            "iss": DEFAULT_APEX_ISSUER,
            "aud": DEFAULT_APEX_AUDIENCE,
            "sub": "operator-1",
            "actor_type": "user",
            "role": role,
            "tenant_id": "global",
            "permissions": ["read:*"],
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "jti": "asmodeus-test-jti",
            "apex_contract_version": APEX_CONTRACT_VERSION
        });
        patch(&mut claims);

        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let input = format!("{header}.{payload}");
        let key = hmac::Key::new(hmac::HMAC_SHA256, TEST_SECRET.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(hmac::sign(&key, input.as_bytes()).as_ref());
        format!("{input}.{signature}")
    }

    #[test]
    fn signed_apex_identity_selects_role() {
        let mut headers = HeaderMap::new();
        let token = token("red_team", |_| {});
        headers.insert(
            "authorization",
            format!("Bearer {token}").parse().unwrap(),
        );
        assert_eq!(caller_role(&headers).unwrap(), Role::RedTeam);
    }

    #[test]
    fn unsigned_role_header_is_rejected_by_default() {
        std::env::remove_var("ASMODEUS_ALLOW_ROLE_HEADER");
        let mut headers = HeaderMap::new();
        headers.insert("x-apex-role", "red_team".parse().unwrap());
        assert!(matches!(caller_role(&headers), Err(ApiError::Unauthorized(_))));
    }

    #[test]
    fn tampered_signed_identity_is_rejected() {
        let mut token = token("red_team", |_| {});
        token.push('x');
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {token}").parse().unwrap(),
        );
        assert!(matches!(caller_role(&headers), Err(ApiError::Unauthorized(_))));
    }

    #[test]
    fn wrong_contract_version_is_rejected() {
        let token = token("red_team", |claims| {
            claims["apex_contract_version"] = json!("2.0");
        });
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {token}").parse().unwrap(),
        );
        assert!(matches!(caller_role(&headers), Err(ApiError::Unauthorized(_))));
    }
}
