//! OpenAPI 3.1 Specification generator for the Asmodeus Control Plane REST API.
//!
//! Enables seamless consumption and documentation for the APEX Unified Gateway (FastAPI)
//! and Web Console (/chaos).

use serde_json::{json, Value};

/// Generates the canonical OpenAPI 3.1 schema for Asmodeus.
pub fn generate_spec() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Asmodeus Control Plane API",
            "version": "0.1.0",
            "description": "Offensive engine of the APEX DEFENSE platform (Red Team, BAS & Chaos Engineering). Strictly synthetic-only under invariant INV-0."
        },
        "servers": [
            {
                "url": "/",
                "description": "Direct Control Plane endpoint"
            }
        ],
        "security": [
            {
                "ApexRole": []
            }
        ],
        "components": {
            "securitySchemes": {
                "ApexRole": {
                    "type": "apiKey",
                    "name": "X-Apex-Role",
                    "in": "header",
                    "description": "Role-Based Access Control context header. Accepted values: admin, red_team, devsecops, ciso, secops, auditor."
                }
            },
            "schemas": {
                "Measurements": {
                    "type": "object",
                    "properties": {
                        "mttd_ms": { "type": "integer" },
                        "mttr_ms": { "type": "integer" },
                        "blue_team_detected": { "type": "boolean" }
                    },
                    "required": ["mttd_ms", "mttr_ms", "blue_team_detected"]
                },
                "AuditRecord": {
                    "type": "object",
                    "properties": {
                        "run_id": { "type": "string" },
                        "scenario_id": { "type": "string" },
                        "scenario_name": { "type": "string" },
                        "category": { "type": "string", "enum": ["red_team", "chaos"] },
                        "mitre_technique": { "type": "string" },
                        "mitre_tactic": { "type": "string" },
                        "severity": { "type": "string" },
                        "tag": { "type": "string" },
                        "initiator": { "type": "string" },
                        "runner_id": { "type": "string" },
                        "status": { "type": "string" },
                        "measurements": { "$ref": "#/components/schemas/Measurements" },
                        "detection_source": { "type": "string" },
                        "containment_action": { "type": "string" },
                        "cleanup_status": { "type": "string" },
                        "timestamp_utc": { "type": "string" },
                        "signature_hex": { "type": "string" },
                        "public_key_hex": { "type": "string" }
                    },
                    "required": ["run_id", "scenario_id", "status", "measurements", "signature_hex", "timestamp_utc"]
                },
                "RunnerRecord": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string" },
                        "name": { "type": "string" },
                        "endpoint": { "type": "string" },
                        "tags": { "type": "array", "items": { "type": "string" } },
                        "status": { "type": "string", "enum": ["active", "unresponsive", "draining"] },
                        "last_heartbeat_utc": { "type": "string" },
                        "cpu_usage_pct": { "type": "integer" },
                        "version": { "type": "string" }
                    },
                    "required": ["id", "name", "endpoint", "status"]
                },
                "Campaign": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string" },
                        "name": { "type": "string" },
                        "description": { "type": "string" },
                        "steps": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "order": { "type": "integer" },
                                    "scenario_id": { "type": "string" }
                                },
                                "required": ["order", "scenario_id"]
                            }
                        }
                    },
                    "required": ["id", "name", "description", "steps"]
                },
                "ScheduledJob": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string" },
                        "name": { "type": "string" },
                        "scenario_id": { "type": "string" },
                        "interval_sec": { "type": "integer" },
                        "role": { "type": "string" },
                        "target_override": { "type": "string", "nullable": true },
                        "enabled": { "type": "boolean" },
                        "created_at_utc": { "type": "string" },
                        "last_run_utc": { "type": "string", "nullable": true },
                        "last_status": { "type": "string", "nullable": true },
                        "last_mttd_ms": { "type": "integer", "nullable": true },
                        "baseline_mttd_ms": { "type": "integer", "nullable": true },
                        "drift_detected": { "type": "boolean" },
                        "drift_factor": { "type": "number", "nullable": true }
                    },
                    "required": ["id", "name", "scenario_id", "interval_sec", "role", "enabled", "created_at_utc", "drift_detected"]
                },
                "CreateScheduleRequest": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string" },
                        "name": { "type": "string" },
                        "scenario_id": { "type": "string" },
                        "interval_sec": { "type": "integer" },
                        "target_override": { "type": "string" },
                        "baseline_mttd_ms": { "type": "integer" },
                        "enabled": { "type": "boolean" }
                    },
                    "required": ["name", "scenario_id", "interval_sec"]
                },
                "ComplianceReport": {
                    "type": "object",
                    "properties": {
                        "generated_at_utc": { "type": "string" },
                        "total_controls": { "type": "integer" },
                        "compliant_controls": { "type": "integer" },
                        "partial_controls": { "type": "integer" },
                        "non_compliant_controls": { "type": "integer" },
                        "overall_compliance_score": { "type": "integer" },
                        "controls": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "control_id": { "type": "string" },
                                    "standard": { "type": "string" },
                                    "title": { "type": "string" },
                                    "description": { "type": "string" },
                                    "mapped_techniques": { "type": "array", "items": { "type": "string" } },
                                    "matching_scenarios": { "type": "array", "items": { "type": "string" } },
                                    "total_runs": { "type": "integer" },
                                    "detected_runs": { "type": "integer" },
                                    "detection_rate_pct": { "type": "number" },
                                    "status": { "type": "string" }
                                },
                                "required": ["control_id", "standard", "title", "total_runs", "detected_runs", "detection_rate_pct", "status"]
                            }
                        }
                    },
                    "required": ["generated_at_utc", "total_controls", "overall_compliance_score", "controls"]
                }
            }
        },
        "paths": {
            "/healthz": {
                "get": {
                    "summary": "Health check probe",
                    "responses": {
                        "200": { "description": "Control plane is healthy" }
                    }
                }
            },
            "/metrics": {
                "get": {
                    "summary": "Prometheus metrics exposition",
                    "responses": {
                        "200": { "description": "Text exposition of resilience scores and MTTD/MTTR" }
                    }
                }
            },
            "/api/v1/asmodeus/openapi.json": {
                "get": {
                    "summary": "Retrieve OpenAPI 3.1 JSON schema",
                    "responses": {
                        "200": { "description": "OpenAPI 3.1 specification" }
                    }
                }
            },
            "/api/v1/asmodeus/scenarios": {
                "get": {
                    "summary": "List all attack and chaos scenarios in catalog",
                    "responses": {
                        "200": { "description": "List of scenario metadata entries" }
                    }
                }
            },
            "/api/v1/asmodeus/scenarios/mitre": {
                "get": {
                    "summary": "Get MITRE ATT&CK enterprise coverage report",
                    "responses": {
                        "200": { "description": "Coverage breakdown by tactics and techniques" }
                    }
                }
            },
            "/api/v1/asmodeus/scenarios/validate": {
                "post": {
                    "summary": "Validate a declarative YAML or JSON scenario manifest",
                    "responses": {
                        "200": { "description": "Manifest is valid and complies with INV-0" },
                        "422": { "description": "Manifest is invalid or breaches INV-0" }
                    }
                }
            },
            "/api/v1/asmodeus/scenarios/{id}": {
                "get": {
                    "summary": "Get full scenario specification by ID",
                    "responses": {
                        "200": { "description": "Scenario details and self-signed manifest" },
                        "404": { "description": "Scenario not found" }
                    }
                }
            },
            "/api/v1/asmodeus/scenarios/{id}/run": {
                "post": {
                    "summary": "Execute a scenario on runner or in-process simulation",
                    "responses": {
                        "200": { "description": "Execution result with initial measurements and audit record" },
                        "403": { "description": "Caller role forbidden to execute category" },
                        "404": { "description": "Scenario or target not found" }
                    }
                }
            },
            "/api/v1/asmodeus/scenarios/abort": {
                "post": {
                    "summary": "Emergency abort of all active runs and triggers cleanup",
                    "responses": {
                        "200": { "description": "All runs transitioned to RolledBack" }
                    }
                }
            },
            "/api/v1/asmodeus/telemetry/mttd": {
                "get": {
                    "summary": "Retrieve MTTD, MTTR and Resilience Score aggregates",
                    "responses": {
                        "200": { "description": "Rolling telemetry statistics" }
                    }
                }
            },
            "/api/v1/asmodeus/runners": {
                "get": {
                    "summary": "List all registered execution runner probes",
                    "responses": {
                        "200": { "description": "List of runner records" }
                    }
                },
                "post": {
                    "summary": "Register a new runner probe",
                    "responses": {
                        "201": { "description": "Runner registered" },
                        "403": { "description": "Forbidden" }
                    }
                }
            },
            "/api/v1/asmodeus/runners/{id}": {
                "delete": {
                    "summary": "Deregister an execution runner probe",
                    "responses": {
                        "200": { "description": "Runner removed" },
                        "404": { "description": "Runner not found" }
                    }
                }
            },
            "/api/v1/asmodeus/runners/{id}/ping": {
                "get": {
                    "summary": "Active liveness ping probe to runner via gRPC Heartbeat",
                    "responses": {
                        "200": { "description": "Runner is healthy and responsive" },
                        "502": { "description": "Runner unreachable" }
                    }
                }
            },
            "/api/v1/asmodeus/runs": {
                "get": {
                    "summary": "List scenario run history from signed audit trail",
                    "responses": {
                        "200": { "description": "Array of signed audit records" }
                    }
                }
            },
            "/api/v1/asmodeus/runs/{id}": {
                "get": {
                    "summary": "Get single audit record by run ID",
                    "responses": {
                        "200": { "description": "Detailed audit record" },
                        "404": { "description": "Run not found" }
                    }
                }
            },
            "/api/v1/asmodeus/runs/{id}/verify": {
                "get": {
                    "summary": "Cryptographically verify Ed25519 signature of audit record",
                    "responses": {
                        "200": { "description": "Verification status against trusted public key" }
                    }
                }
            },
            "/api/v1/asmodeus/runs/{id}/feedback": {
                "post": {
                    "summary": "Submit Blue Team detection and containment feedback (Closed-Loop)",
                    "responses": {
                        "200": { "description": "Record updated and re-signed with Ed25519 key" },
                        "403": { "description": "Role forbidden from submitting feedback" }
                    }
                }
            },
            "/api/v1/asmodeus/runs/{id}/report": {
                "get": {
                    "summary": "Get NIST CSF single-run report in JSON or Markdown",
                    "responses": {
                        "200": { "description": "Formatted report" }
                    }
                }
            },
            "/api/v1/asmodeus/reports/resilience": {
                "get": {
                    "summary": "Get overall NIST CSF 2.0 Cyber-Resilience executive report",
                    "responses": {
                        "200": { "description": "Executive report in JSON or Markdown" }
                    }
                }
            },
            "/api/v1/asmodeus/audit/export": {
                "get": {
                    "summary": "Stream export of audit records in JSONL or JSON for ClickHouse / SIEM",
                    "responses": {
                        "200": { "description": "Streamed audit export" }
                    }
                }
            },
            "/api/v1/asmodeus/campaigns": {
                "get": {
                    "summary": "List all multi-stage attack campaigns and playbooks",
                    "responses": {
                        "200": { "description": "Array of registered campaigns" }
                    }
                },
                "post": {
                    "summary": "Register a new attack campaign playbook",
                    "responses": {
                        "201": { "description": "Campaign created" },
                        "403": { "description": "Forbidden" },
                        "422": { "description": "Invalid steps or unknown scenario" }
                    }
                }
            },
            "/api/v1/asmodeus/campaigns/{id}": {
                "delete": {
                    "summary": "Deregister an attack campaign playbook",
                    "responses": {
                        "200": { "description": "Campaign removed" },
                        "404": { "description": "Campaign not found" }
                    }
                }
            },
            "/api/v1/asmodeus/campaigns/{id}/run": {
                "post": {
                    "summary": "Execute multi-stage attack campaign and compute composite resilience score",
                    "responses": {
                        "200": { "description": "Campaign execution result" },
                        "403": { "description": "Role forbidden from running campaigns" },
                        "404": { "description": "Campaign not found" }
                    }
                }
            },
            "/api/v1/asmodeus/reports/compliance": {
                "get": {
                    "summary": "Get NIST CSF 2.0 & PCI-DSS v4.0 regulatory compliance report in JSON or Markdown",
                    "responses": {
                        "200": { "description": "Compliance and control coverage report" },
                        "403": { "description": "Role forbidden from viewing reports" }
                    }
                }
            },
            "/api/v1/asmodeus/schedules": {
                "get": {
                    "summary": "List all continuous automated BAS scheduled exercises",
                    "responses": {
                        "200": { "description": "Array of scheduled jobs" },
                        "403": { "description": "Forbidden" }
                    }
                },
                "post": {
                    "summary": "Register a new continuous automated BAS scheduled exercise",
                    "responses": {
                        "201": { "description": "Schedule created" },
                        "403": { "description": "Forbidden" },
                        "404": { "description": "Scenario not found" },
                        "422": { "description": "Validation error" }
                    }
                }
            },
            "/api/v1/asmodeus/schedules/{id}": {
                "delete": {
                    "summary": "Deregister a continuous automated BAS scheduled exercise",
                    "responses": {
                        "200": { "description": "Schedule removed" },
                        "403": { "description": "Forbidden" },
                        "404": { "description": "Schedule not found" }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openapi_spec_generation() {
        let spec = generate_spec();
        assert_eq!(spec["openapi"], "3.1.0");
        assert_eq!(spec["info"]["title"], "Asmodeus Control Plane API");
        assert!(spec["paths"]["/healthz"].is_object());
        assert!(spec["paths"]["/api/v1/asmodeus/openapi.json"].is_object());
        assert!(spec["paths"]["/api/v1/asmodeus/audit/export"].is_object());
        assert!(spec["paths"]["/api/v1/asmodeus/campaigns"].is_object());
        assert!(spec["paths"]["/api/v1/asmodeus/schedules"].is_object());
        assert!(spec["paths"]["/api/v1/asmodeus/reports/compliance"].is_object());
        assert!(spec["components"]["schemas"]["AuditRecord"].is_object());
        assert!(spec["components"]["schemas"]["ScheduledJob"].is_object());
        assert!(spec["components"]["schemas"]["ComplianceReport"].is_object());
    }
}
