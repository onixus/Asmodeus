//! REST surface (OpenAPI 3.1 shape) consumed by the APEX gateway. RBAC is
//! enforced here from `asmodeus_common::rbac` — never delegated to the gateway
//! (D5). Signature verification and the INV-0 gate run before any execution.

use crate::campaign_http::{delete_campaign, list_campaigns, register_campaign, run_campaign};
use crate::reporting::{
    export_audit_trail, get_compliance_report, get_resilience_report, get_run_report,
};
use crate::runner_http::{deregister_runner, list_runners, ping_runner_handler, register_runner};
use crate::runs_http::{cancel_run, get_run, list_runs, run_feedback, verify_run};
use crate::scenario_http::{
    abort_all, get_scenario, list_scenarios, mitre_matrix, run_scenario, validate_scenario_manifest,
};
use crate::schedules_http::{
    create_schedule, delete_schedule, get_schedule, list_drift_alerts, list_schedules,
    toggle_schedule,
};
use crate::state::AppState;
use crate::system_http::{healthz, metrics, openapi_spec, telemetry_mttd};
use axum::{
    routing::{delete, get, post},
    Router,
};

/// Build the router with all endpoints mounted.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/api/v1/asmodeus/scenarios", get(list_scenarios))
        .route("/api/v1/asmodeus/scenarios/mitre", get(mitre_matrix))
        .route(
            "/api/v1/asmodeus/scenarios/validate",
            post(validate_scenario_manifest),
        )
        .route("/api/v1/asmodeus/scenarios/:id", get(get_scenario))
        .route("/api/v1/asmodeus/scenarios/:id/run", post(run_scenario))
        .route("/api/v1/asmodeus/scenarios/abort", post(abort_all))
        .route("/api/v1/asmodeus/telemetry/mttd", get(telemetry_mttd))
        .route(
            "/api/v1/asmodeus/runners",
            get(list_runners).post(register_runner),
        )
        .route("/api/v1/asmodeus/runners/:id", delete(deregister_runner))
        .route(
            "/api/v1/asmodeus/runners/:id/ping",
            get(ping_runner_handler),
        )
        .route("/api/v1/asmodeus/runs", get(list_runs))
        .route("/api/v1/asmodeus/runs/:id", get(get_run))
        .route("/api/v1/asmodeus/runs/:id/verify", get(verify_run))
        .route("/api/v1/asmodeus/runs/:id/cancel", post(cancel_run))
        .route("/api/v1/asmodeus/runs/:id/feedback", post(run_feedback))
        .route("/api/v1/asmodeus/runs/:id/report", get(get_run_report))
        .route(
            "/api/v1/asmodeus/reports/resilience",
            get(get_resilience_report),
        )
        .route(
            "/api/v1/asmodeus/reports/compliance",
            get(get_compliance_report),
        )
        .route("/api/v1/asmodeus/openapi.json", get(openapi_spec))
        .route("/api/v1/asmodeus/audit/export", get(export_audit_trail))
        .route(
            "/api/v1/asmodeus/campaigns",
            get(list_campaigns).post(register_campaign),
        )
        .route("/api/v1/asmodeus/campaigns/:id", delete(delete_campaign))
        .route("/api/v1/asmodeus/campaigns/:id/run", post(run_campaign))
        .route(
            "/api/v1/asmodeus/schedules",
            get(list_schedules).post(create_schedule),
        )
        .route("/api/v1/asmodeus/schedules/alerts", get(list_drift_alerts))
        .route(
            "/api/v1/asmodeus/schedules/:id",
            get(get_schedule)
                .patch(toggle_schedule)
                .delete(delete_schedule),
        )
        .with_state(state)
}
