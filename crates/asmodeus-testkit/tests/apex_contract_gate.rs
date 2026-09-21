use serde_json::Value;
use std::{fs, path::PathBuf};

fn manifest() -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let raw = fs::read_to_string(root.join("apex-contract").join("manifest.json"))
        .expect("apex-contract.json must exist at repository root");
    serde_json::from_str(&raw).expect("apex-contract.json must be valid JSON")
}

#[test]
fn apex_contract_cannot_delegate_asmodeus_safety_to_gateway() {
    let m = manifest();
    assert_eq!(m["contract"]["version"], "1.0");
    assert_eq!(m["system"]["id"], "asmodeus");
    assert_eq!(m["system"]["namespace"], "asmodeus");
    assert_eq!(m["system"]["role"], "synthetic-bas");

    assert_eq!(m["ownership"]["gateway_is_source_of_truth"], false);
    assert_eq!(m["identity"]["owning_service_authorizes_mutations"], true);
    assert_eq!(m["identity"]["production_trusts_unsigned_role_header"], false);
    assert_eq!(m["safety"]["synthetic_only"], true);
    assert_eq!(m["safety"]["gateway_may_not_bypass_safety"], true);
}

#[test]
fn apex_contract_exposes_only_versioned_asmodeus_boundary_names() {
    let m = manifest();
    let event_types = m["integration"]["event_types"]
        .as_array()
        .expect("event_types array");
    assert!(
        event_types
            .iter()
            .any(|item| item == "apex.asmodeus.exercise.v1")
    );

    let resources = m["resources"].as_array().expect("resources array");
    assert!(resources.iter().any(|item| {
        item["kind"] == "exercise"
            && item["urn_prefix"] == "urn:apex:exercise:asmodeus:"
    }));
    assert!(resources.iter().any(|item| {
        item["kind"] == "evidence"
            && item["urn_prefix"] == "urn:apex:evidence:asmodeus:"
    }));
}
