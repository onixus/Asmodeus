//! OpenAPI 3.1 Specification generator for the Asmodeus Control Plane REST API.
//!
//! Enables seamless consumption and documentation for the APEX Unified Gateway (FastAPI)
//! and Web Console (/chaos).

use serde_json::{json, Value};

/// Generates the canonical OpenAPI 3.1 schema for Asmodeus.
pub fn generate_spec() -> Value {
    let mut spec = json!({
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
                "ApexBearer": []
            }
        ],
        "components": {
            "securitySchemes": {
                "ApexBearer": {
                    "type": "http", "scheme": "bearer", "bearerFormat": "JWT",
                    "description": "Verified APEX identity token. X-Apex-Role is available only with explicit development bypass."
                }
            },
            "schemas": {
                "ProcedureCorpus": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["version", "attack_version", "denominator", "procedures"],
                    "properties": {
                        "version": {"type": "string", "const": asmodeus_dsl::PROCEDURE_CORPUS_VERSION},
                        "attack_version": {"type": "string", "const": asmodeus_dsl::ATTACK_VERSION},
                        "denominator": {"type": "integer", "const": asmodeus_dsl::PROCEDURE_SLOT_DENOMINATOR},
                        "procedures": {
                            "type": "array", "minItems": 6, "maxItems": 6,
                            "items": {"$ref": "#/components/schemas/ProcedureDefinition"}
                        }
                    }
                },
                "RunEvidence": {
                    "type":"object", "properties": {
                        "execution_mode":{"type":"string","enum":["runner","simulated","legacy_unverified"]},
                        "feedback_received":{"type":"boolean"}, "contained":{"type":"boolean"},
                        "cleanup_confirmed":{"type":"boolean"}, "failure_reason":{"type":["string","null"]}
                    }, "required":["execution_mode","feedback_received","contained","cleanup_confirmed"]
                },
                "RunRequest": {
                    "type":"object", "additionalProperties":false,
                    "properties": {"background":{"type":"boolean","default":false},
                        "timeout_sec":{"type":"integer","minimum":1,"maximum":300,"description":"May shorten the signed scenario deadline."},
                        "target_override":{"type":"string","description":"Registered runner ID or tag; does not override the signed filesystem scope."}}
                },
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
                        "evidence": { "$ref": "#/components/schemas/RunEvidence" },
                        "live_state": { "type": "string", "description":"Volatile progress, outside the signed audit record." },
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
                        "last_heartbeat_utc": { "type": ["integer", "null"], "minimum": 0, "description": "Unix epoch seconds of the latest accepted heartbeat, or null while awaiting a fresh probe" },
                        "registered_at_utc": { "type": "integer", "minimum": 0 },
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
                        "last_run_id": { "type": ["string", "null"] },
                        "last_run_epoch_secs": { "type": ["integer", "null"] },
                        "last_mttd_ms": { "type": "integer", "nullable": true },
                        "baseline_mttd_ms": { "type": "integer", "nullable": true },
                        "drift_detected": { "type": "boolean" },
                        "detection_missed": { "type": "boolean", "description": "Latest confirmed feedback reports no detection" },
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
                    "summary": "Health check probe", "security":[],
                    "responses": {
                        "200": { "description": "Control plane is healthy" }
                    }
                }
            },
            "/metrics": {
                "get": {
                    "summary": "Prometheus metrics exposition", "security":[],
                    "responses": {
                        "200": { "description": "Text exposition of resilience scores and MTTD/MTTR" }
                    }
                }
            },
            "/api/v1/asmodeus/openapi.json": {
                "get": {
                    "summary": "Retrieve OpenAPI 3.1 JSON schema", "security":[],
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
            "/api/v1/asmodeus/procedures": {
                "get": {
                    "summary": "Inspect the versioned procedure corpus",
                    "description": "Requires ViewReports. All six slots remain visible with UNSUPPORTED availability. Planned behavioral mode does not establish runtime execution or coverage. No procedure run endpoint is exposed.",
                    "responses": {
                        "200": {
                            "description": "Fixed-denominator procedure manifest, including unsupported gaps",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ProcedureCorpus"}}}
                        },
                        "401": {"description": "Missing or invalid authenticated APEX identity"},
                        "403": {"description": "Role lacks ViewReports"}
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
                    "requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/RunRequest"}}}},
                    "responses": {
                        "200": { "description": "Terminal execution result; detection awaits explicit feedback" },
                        "202": { "description": "Background run durably admitted; returns run_id and status_url" },
                        "422": { "description": "Unsupported options or invalid timeout" },
                        "403": { "description": "Caller role forbidden to execute category" },
                        "404": { "description": "Scenario or target not found" }
                    }
                }
            },
            "/api/v1/asmodeus/scenarios/abort": {
                "post": {
                    "summary": "Request cancellation of active runs permitted for the caller role",
                    "responses": {
                        "200": { "description": "Cancellation requested; cleanup remains unconfirmed until the terminal runner result" }
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
                    "summary": "Register or update a runner probe",
                    "description": "Persisted before success when ASMODEUS_STATE_DIR is configured. An existing snapshot takes precedence over the environment seed on restart.",
                    "responses": {
                        "201": { "description": "Runner registered" },
                        "403": { "description": "Forbidden" },
                        "422": { "description": "Invalid runner ID or HTTP(S) endpoint" },
                        "500": { "description": "Registry persistence failed; change was not published" }
                    }
                }
            },
            "/api/v1/asmodeus/runners/{id}": {
                "patch": {
                    "summary": "Drain a runner or resume after a fresh healthy heartbeat",
                    "description": "Admin, Red Team and DevSecOps may set draining. Drain excludes the runner from subsequent routing selections; already selected runs continue. Resume returns unresponsive until a new successful healthy heartbeat. Repeated requests are idempotent. With ASMODEUS_STATE_DIR, registrations and maintenance persist in runners.json; restored runners require fresh health checks. Without it, state is process-local. A single writer process is required.",
                    "requestBody": {"required":true,"content":{"application/json":{"schema":{
                        "type":"object","additionalProperties":false,"required":["draining"],
                        "properties":{"draining":{"type":"boolean"}}
                    }}}},
                    "responses": {
                        "200": {"description":"Updated runner record","content":{"application/json":{"schema":{"$ref":"#/components/schemas/RunnerRecord"}}}},
                        "401": {"description":"Missing or invalid identity"},
                        "403": {"description":"Role may not change runner maintenance"},
                        "404": {"description":"Runner not found"},
                        "422": {"description":"Invalid maintenance payload"},
                        "500": {"description":"Registry persistence failed; change was not published"}
                    }
                },
                "delete": {
                    "summary": "Deregister an execution runner probe",
                    "responses": {
                        "200": { "description": "Runner removed; an empty configured registry does not enable simulation or static fallback" },
                        "404": { "description": "Runner not found" },
                        "500": { "description": "Registry persistence failed; change was not published" }
                    }
                }
            },
            "/api/v1/asmodeus/runners/{id}/ping": {
                "get": {
                    "summary": "Active liveness ping probe to runner via gRPC Heartbeat",
                    "responses": {
                        "200": { "description": "Heartbeat reply (healthy may be false); registry_updated is false if a newer probe, registration or maintenance change superseded this probe" },
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
            "/api/v1/asmodeus/runs/{id}/cancel": {
                "post": {"summary":"Cancel one active run; poll its status for cleanup confirmation",
                    "responses":{"202":{"description":"Cancellation requested"},"200":{"description":"Run already terminal"},
                        "403":{"description":"Role cannot cancel this category"},"404":{"description":"Run not found"}}}
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
                    "requestBody":{"required":true,"content":{"application/json":{"schema":{
                        "type":"object", "properties":{
                            "detected":{"type":"boolean"},"contained":{"type":"boolean","description":"Requires detected=true and mttr_ms"},
                            "mttd_ms":{"type":"integer","minimum":0,"description":"Required when detected=true"},
                            "mttr_ms":{"type":"integer","minimum":0},"detection_source":{"type":"string"},"containment_action":{"type":"string"}
                        },"required":["detected"]
                    }}}},
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
                    "summary": "Execute a durable campaign; background launch returns 202",
                    "requestBody": {"required":false,"content":{"application/json":{"schema":{"type":"object","properties":{
                        "background":{"type":"boolean","default":false},
                        "target_override":{"type":["string","null"]},
                        "timeout_sec":{"type":["integer","null"],"minimum":1}
                    }}}}},
                    "responses": {
                        "200": { "description": "Campaign execution result with durable id and status" },
                        "202": { "description": "Background campaign admitted" },
                        "500": { "description": "Snapshot persistence failed" },
                        "403": { "description": "Role forbidden from running campaigns" },
                        "404": { "description": "Campaign not found" }
                    }
                }
            },
            "/api/v1/asmodeus/campaign-runs": {
                "get": {
                    "summary": "List durable campaign runs, newest first",
                    "parameters": [
                        {"name":"limit","in":"query","schema":{"type":"integer","minimum":0}},
                        {"name":"campaign_id","in":"query","schema":{"type":"string"}},
                        {"name":"status","in":"query","schema":{"type":"string"}}
                    ],
                    "responses": {"200":{"description":"Campaign run history"},"403":{"description":"Role forbidden"}}
                }
            },
            "/api/v1/asmodeus/campaign-runs/{id}": {
                "get": {"summary":"Get campaign progress, snapshotted plan and report",
                    "responses":{"200":{"description":"Campaign run details"},"404":{"description":"Run not found"},"403":{"description":"Role forbidden"}}}
            },
            "/api/v1/asmodeus/campaign-runs/{id}/cancel": {
                "post": {"summary":"Request cancellation of the current stage; stop subsequent stages",
                    "responses":{"202":{"description":"Cancellation requested; cleanup not yet confirmed"},"200":{"description":"Worker inactive"},"404":{"description":"Run not found"},"403":{"description":"Role forbidden"}}}
            },
            "/api/v1/asmodeus/campaign-runs/{id}/resume": {
                "post": {"summary":"Explicitly resume interrupted or cancelled runs, with confirmed prior cleanup",
                    "responses":{"202":{"description":"Resume admitted"},"409":{"description":"Run not resumable, worker active or prior cleanup unconfirmed"},"404":{"description":"Run not found"},"403":{"description":"Role forbidden"},"500":{"description":"Snapshot persistence failed"}}}
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
            "/api/v1/asmodeus/schedules/alerts": {
                "get": {
                    "summary": "List persisted detection-drift alerts (MTTD regression), newest first",
                    "responses": {
                        "200": { "description": "Array of drift alerts" },
                        "403": { "description": "Forbidden" }
                    }
                }
            },
            "/api/v1/asmodeus/schedules/{id}": {
                "get": {
                    "summary": "Schedule detail including the run-history drift timeline",
                    "responses": {
                        "200": { "description": "Scheduled job with run history" },
                        "403": { "description": "Forbidden" },
                        "404": { "description": "Schedule not found" }
                    }
                },
                "patch": {
                    "summary": "Enable or disable a scheduled exercise (pause / resume)",
                    "responses": {
                        "200": { "description": "Schedule updated" },
                        "403": { "description": "Forbidden" },
                        "404": { "description": "Schedule not found" }
                    }
                },
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
    });
    let procedure_schemas = json!({
        "ProcedureDefinition": {
            "type": "object", "additionalProperties": false,
            "required": ["id", "revision", "technique_id", "name", "planned_mode", "availability", "unsupported_reason", "gap", "preconditions", "variants", "budget", "scope", "cleanup"],
            "properties": {
                "id": {"type": "string"},
                "revision": {"type": "integer", "minimum": 1},
                "technique_id": {"type": "string"},
                "name": {"type": "string"},
                "planned_mode": {"type": "string", "enum": ["marker", "replay", "behavioral"], "description": "Intended mode only; does not attest runtime execution."},
                "availability": {"type": "string", "const": "UNSUPPORTED"},
                "unsupported_reason": {"type": "string", "minLength": 1},
                "gap": {"type": ["string", "null"]},
                "preconditions": {"type": "array", "items": {"type": "string"}},
                "variants": {"type": "array", "minItems": 2, "maxItems": 2, "items": {"$ref": "#/components/schemas/ProcedureVariant"}},
                "budget": {"$ref": "#/components/schemas/ProcedureBudget"},
                "scope": {"$ref": "#/components/schemas/ProcedureScope"},
                "cleanup": {"$ref": "#/components/schemas/ProcedureCleanup"},
            }
        },
        "ProcedureVariant": {
            "type": "object", "additionalProperties": false,
            "required": ["kind", "behavior", "expected"],
            "properties": {
                "kind": {"type": "string", "enum": ["positive", "benign_control"]},
                "behavior": {"type": "string"},
                "expected": {"$ref": "#/components/schemas/ProcedureExpectation"},
            }
        },
        "ProcedureExpectation": {
            "type": "object", "additionalProperties": false,
            "required": ["observables", "product_effect", "verification"],
            "properties": {
                "observables": {"type": "array", "items": {"type": "string"}},
                "product_effect": {"type": "string"},
                "verification": {"type": "string"},
            }
        },
        "ProcedureBudget": {
            "type": "object", "additionalProperties": false,
            "required": ["timeout_seconds", "max_processes", "max_requests", "max_bytes", "cancellation_required", "kill_switch_required"],
            "properties": {
                "timeout_seconds": {"type": "integer", "minimum": 0},
                "max_processes": {"type": "integer", "minimum": 0},
                "max_requests": {"type": "integer", "minimum": 0},
                "max_bytes": {"type": "integer", "minimum": 0},
                "cancellation_required": {"type": "boolean"},
                "kill_switch_required": {"type": "boolean"},
            }
        },
        "ProcedureScope": {
            "type": "object", "additionalProperties": false,
            "required": ["namespace_prefix", "canary_path", "endpoint_allowlist", "synthetic_data_only", "real_credentials_forbidden"],
            "properties": {
                "namespace_prefix": {"type": "string"},
                "canary_path": {"type": "string"},
                "endpoint_allowlist": {"type": "array", "items": {"type": "string"}},
                "synthetic_data_only": {"type": "boolean"},
                "real_credentials_forbidden": {"type": "boolean"},
            }
        },
        "ProcedureCleanup": {
            "type": "object", "additionalProperties": false,
            "required": ["required_after", "requirements"],
            "properties": {
                "required_after": {"type": "array", "items": {"type": "string"}},
                "requirements": {"type": "array", "items": {"type": "string"}},
            }
        },
    });
    spec["components"]["schemas"]
        .as_object_mut()
        .expect("schemas")
        .extend(
            procedure_schemas
                .as_object()
                .expect("procedure schemas")
                .clone(),
        );
    for (path, item) in spec["paths"].as_object_mut().expect("paths schema") {
        if path.contains("{id}") {
            item["parameters"] =
                json!([{"name":"id","in":"path","required":true,"schema":{"type":"string"}}]);
        }
    }
    spec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn procedures_document_read_only_versioned_unsupported_manifest() {
        let spec = generate_spec();
        let path = &spec["paths"]["/api/v1/asmodeus/procedures"];
        assert!(path["get"].is_object());
        assert!(path["post"].is_null());
        assert_eq!(
            path["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/ProcedureCorpus"
        );
        assert!(path["get"]["responses"]["401"].is_object());
        assert!(path["get"]["responses"]["403"].is_object());
        let corpus = &spec["components"]["schemas"]["ProcedureCorpus"];
        assert_eq!(corpus["properties"]["denominator"]["const"], 6);
        assert_eq!(corpus["properties"]["procedures"]["minItems"], 6);
        assert_eq!(corpus["properties"]["procedures"]["maxItems"], 6);
        assert_eq!(
            spec["components"]["schemas"]["ProcedureDefinition"]["properties"]["availability"]
                ["const"],
            "UNSUPPORTED"
        );
        assert!(spec["paths"]
            .as_object()
            .unwrap()
            .keys()
            .all(|path| !path.starts_with("/api/v1/asmodeus/procedures/")));
    }

    #[test]
    fn procedure_manifest_fields_match_openapi_contract() {
        fn check_fields(spec: &Value, schema: &Value, value: &Value) {
            if let Some(reference) = schema["$ref"].as_str() {
                check_fields(spec, spec.pointer(&reference[1..]).unwrap(), value);
                return;
            }
            if let Some(expected) = schema.get("const") {
                assert_eq!(value, expected);
            }
            if let Some(object) = value.as_object() {
                let properties = schema["properties"].as_object().unwrap();
                assert_eq!(
                    object.keys().collect::<Vec<_>>(),
                    properties.keys().collect::<Vec<_>>()
                );
                for (field, value) in object {
                    check_fields(spec, &properties[field], value);
                }
            } else if let Some(items) = value.as_array() {
                for value in items {
                    check_fields(spec, &schema["items"], value);
                }
            }
        }
        let spec = generate_spec();
        let manifest = serde_json::to_value(asmodeus_dsl::procedure_corpus()).unwrap();
        check_fields(
            &spec,
            &spec["components"]["schemas"]["ProcedureCorpus"],
            &manifest,
        );
    }

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
        assert!(spec["paths"]["/api/v1/asmodeus/schedules/alerts"].is_object());
        assert!(spec["paths"]["/api/v1/asmodeus/schedules/{id}"]["get"].is_object());
        assert!(spec["paths"]["/api/v1/asmodeus/schedules/{id}"]["patch"].is_object());
        assert!(spec["paths"]["/api/v1/asmodeus/reports/compliance"].is_object());
        assert!(spec["components"]["schemas"]["AuditRecord"].is_object());
        assert!(spec["components"]["schemas"]["ScheduledJob"].is_object());
        assert!(spec["components"]["schemas"]["ComplianceReport"].is_object());
    }
}
