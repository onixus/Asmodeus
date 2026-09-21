//! Control-plane operational HTTP endpoints.
//!
//! Health, metrics, aggregate telemetry and OpenAPI discovery live here so
//! `http.rs` remains pure router composition.

use asmodeus_common::INV_0_SYNTHETIC_ONLY;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use crate::api::{caller_role, ApiError};
use crate::state::AppState;

pub(crate) async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok", "invariant": INV_0_SYNTHETIC_ONLY }))
}

/// Prometheus scrape endpoint (TT §4.3). Unauthenticated, like any exporter.
pub(crate) async fn metrics(State(state): State<AppState>) -> Response {
    let body = state.metrics.lock().unwrap().prometheus_text();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
        .into_response()
}

pub(crate) async fn telemetry_mttd(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view reports"));
    }
    let completed = state
        .runs
        .lock()
        .unwrap()
        .values()
        .filter(|s| s.is_terminal())
        .count();
    let agg = state.metrics.lock().unwrap();
    Ok(Json(json!({
        "runs_completed": completed,
        "catalog_size": state.catalog.ids().count(),
        "mean_mttd_ms": agg.mean_mttd_ms(),
        "mean_mttr_ms": agg.mean_mttr_ms(),
        "detection_rate_pct": agg.detection_rate_pct(),
    })))
}

pub(crate) async fn openapi_spec() -> Json<Value> {
    Json(crate::openapi::generate_spec())
}
