//! HTTP boundary primitives shared by transport handlers.

use asmodeus_common::Role;
use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

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

/// Read and parse the `X-Apex-Role` header. Missing/unknown => 401.
pub(crate) fn caller_role(headers: &HeaderMap) -> Result<Role, ApiError> {
    let raw = headers
        .get("x-apex-role")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthorized("missing X-Apex-Role header"))?;
    raw.parse::<Role>()
        .map_err(|_| ApiError::Unauthorized("unknown role"))
}
