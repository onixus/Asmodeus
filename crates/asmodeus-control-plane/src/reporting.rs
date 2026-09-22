//! Resilience, compliance, per-run reporting and audit export handlers.

use asmodeus_telemetry::{EcosystemResilienceReport, SingleRunReport};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::api::{caller_role, ApiError};
use crate::state::AppState;

#[derive(Debug, Deserialize, Default)]
pub struct ReportQuery {
    pub format: Option<String>,
}

pub(crate) async fn get_resilience_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<ReportQuery>,
) -> Result<Response, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view resilience reports"));
    }

    let records = state.audit.list(None, None, None);
    let agg = asmodeus_telemetry::Aggregate::from_records(&records);
    let report = EcosystemResilienceReport::build(&records, &agg);

    if query.format.as_deref() == Some("markdown") {
        Ok((
            StatusCode::OK,
            [("content-type", "text/markdown; charset=utf-8")],
            report.to_markdown(),
        )
            .into_response())
    } else {
        Ok(Json(json!(report)).into_response())
    }
}

pub(crate) async fn get_compliance_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<ReportQuery>,
) -> Result<Response, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view compliance reports"));
    }

    let records = state.audit.list(None, None, None);
    let scenario_metas: Vec<asmodeus_telemetry::ScenarioMeta> = state
        .catalog
        .ids()
        .filter_map(|id| state.catalog.get(id))
        .map(|entry| asmodeus_telemetry::ScenarioMeta {
            id: entry.id.to_string(),
            name: entry.name.to_string(),
            category: entry.category.as_str().to_string(),
            mitre_technique: entry.mitre.map(|m| m.id.to_string()).unwrap_or_default(),
        })
        .collect();
    let report = asmodeus_telemetry::ComplianceReport::generate(&scenario_metas, &records);

    if query.format.as_deref() == Some("markdown") {
        Ok((
            StatusCode::OK,
            [("content-type", "text/markdown; charset=utf-8")],
            report.to_markdown(),
        )
            .into_response())
    } else {
        Ok(Json(json!(report)).into_response())
    }
}

pub(crate) async fn get_run_report(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<ReportQuery>,
) -> Result<Response, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view run reports"));
    }

    let record = state
        .audit
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("run not found: {id}")))?;

    let run_report = SingleRunReport::build(&record, Some(&state.audit_public_key));

    if query.format.as_deref() == Some("markdown") {
        Ok((
            StatusCode::OK,
            [("content-type", "text/markdown; charset=utf-8")],
            run_report.to_markdown(),
        )
            .into_response())
    } else {
        Ok(Json(json!(run_report)).into_response())
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct ExportAuditParams {
    pub format: Option<String>,
}

pub(crate) async fn export_audit_trail(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<ExportAuditParams>,
) -> Result<Response, ApiError> {
    let role = caller_role(&headers)?;
    if !role.can(asmodeus_common::Capability::ViewReports) {
        return Err(ApiError::Forbidden("role may not view audit trail"));
    }

    let fmt = params
        .format
        .as_deref()
        .unwrap_or("jsonl")
        .to_ascii_lowercase();

    match fmt.as_str() {
        "json" => {
            let json_body = state
                .audit
                .export_json()
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            Ok((
                StatusCode::OK,
                [("content-type", "application/json; charset=utf-8")],
                json_body,
            )
                .into_response())
        }
        "clickhouse" | "clickhouse_sql" | "sql" => {
            let sql_body = state.audit.export_clickhouse_sql();
            Ok((
                StatusCode::OK,
                [("content-type", "application/sql; charset=utf-8")],
                sql_body,
            )
                .into_response())
        }
        "clickhouse_ndjson" => {
            let ndjson_body = state
                .audit
                .export_clickhouse_ndjson()
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            Ok((
                StatusCode::OK,
                [("content-type", "application/x-ndjson; charset=utf-8")],
                ndjson_body,
            )
                .into_response())
        }
        _ => {
            let jsonl_body = state.audit.export_jsonl();
            Ok((
                StatusCode::OK,
                [("content-type", "application/x-ndjson; charset=utf-8")],
                jsonl_body,
            )
                .into_response())
        }
    }
}
