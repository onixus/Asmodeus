//! asmodeus-cli (`asmodeus`) — operator entrypoint. Offline signing workflow
//! for scenario manifests (the Red Team Lead holds the key) plus INV-0 scope
//! validation. `run`/`status` (REST to the control-plane) land next.

mod ops;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde_json::json;

#[derive(Parser)]
#[command(
    name = "asmodeus",
    version,
    about = "Asmodeus operator CLI (synthetic-only, INV-0)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a fresh Ed25519 keypair (writes <name>.key and <name>.pub, hex).
    Keygen {
        #[arg(long, default_value = "redteam")]
        name: String,
    },
    /// Sign a manifest file with a secret key file; prints the signature (hex).
    Sign {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        key: PathBuf,
    },
    /// Verify a manifest signature (hex) against a public key file (hex).
    Verify {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        signature: String,
        #[arg(long)]
        pubkey: PathBuf,
    },
    /// Check that a target directory lies within the canary scope (INV-0).
    Validate {
        #[arg(long)]
        target_dir: String,
    },
    /// Run a scenario via the control-plane REST API.
    Run {
        #[arg(long)]
        scenario: String,
        /// Optional target override or environment tag (e.g. k8s_workload)
        #[arg(long)]
        target: Option<String>,
        #[arg(long, default_value = "red_team")]
        role: String,
        #[arg(long, default_value = "http://127.0.0.1:8842")]
        url: String,
    },
    /// Fetch MTTD/MTTR telemetry from the control-plane.
    Status {
        #[arg(long, default_value = "auditor")]
        role: String,
        #[arg(long, default_value = "http://127.0.0.1:8842")]
        url: String,
    },
    /// List all catalogued attack and chaos scenarios with MITRE mappings.
    Scenarios {
        #[arg(long, default_value = "auditor")]
        role: String,
        #[arg(long, default_value = "http://127.0.0.1:8842")]
        url: String,
    },
    /// Display MITRE ATT&CK Enterprise Matrix coverage report.
    Mitre {
        #[arg(long, default_value = "auditor")]
        role: String,
        #[arg(long, default_value = "http://127.0.0.1:8842")]
        url: String,
    },
    /// Manage and inspect registered runner probes.
    Runners {
        #[command(subcommand)]
        action: RunnersAction,
    },
}

#[derive(Subcommand)]
enum RunnersAction {
    /// List all registered runners with status and health metrics.
    List {
        #[arg(long, default_value = "auditor")]
        role: String,
        #[arg(long, default_value = "http://127.0.0.1:8842")]
        url: String,
    },
    /// Register a new runner probe.
    Register {
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        endpoint: String,
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        #[arg(long, default_value = "admin")]
        role: String,
        #[arg(long, default_value = "http://127.0.0.1:8842")]
        url: String,
    },
    /// Remove a registered runner probe.
    Deregister {
        #[arg(long)]
        id: String,
        #[arg(long, default_value = "admin")]
        role: String,
        #[arg(long, default_value = "http://127.0.0.1:8842")]
        url: String,
    },
    /// Send an active gRPC Heartbeat liveness probe to a runner.
    Ping {
        #[arg(long)]
        id: String,
        #[arg(long, default_value = "auditor")]
        role: String,
        #[arg(long, default_value = "http://127.0.0.1:8842")]
        url: String,
    },
}

/// Send a request, print the (pretty) body and fail on a non-2xx status.
fn call(
    builder: reqwest::blocking::RequestBuilder,
    what: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = builder.send()?;
    let status = resp.status();
    let body = resp.text()?;
    match serde_json::from_str::<serde_json::Value>(&body) {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v)?),
        Err(_) => println!("{body}"),
    }
    if !status.is_success() {
        return Err(format!("{what} failed: HTTP {status}").into());
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.cmd {
        Cmd::Keygen { name } => {
            let (sk, pk) = ops::generate_keypair();
            let key_path = format!("{name}.key");
            let pub_path = format!("{name}.pub");
            std::fs::write(&key_path, &sk)?;
            std::fs::write(&pub_path, &pk)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
            }
            println!("wrote {key_path} (secret, 0600) and {pub_path} (public)");
            println!("public key: {pk}");
        }
        Cmd::Sign { manifest, key } => {
            let data = std::fs::read(&manifest)?;
            let secret = std::fs::read_to_string(&key)?;
            let sig = ops::sign(&data, secret.trim())?;
            println!("{sig}");
        }
        Cmd::Verify {
            manifest,
            signature,
            pubkey,
        } => {
            let data = std::fs::read(&manifest)?;
            let pk = std::fs::read_to_string(&pubkey)?;
            ops::verify(&data, &signature, pk.trim())?;
            println!("OK: signature verifies");
        }
        Cmd::Validate { target_dir } => {
            if ops::validate_scope(&target_dir) {
                println!("OK: {target_dir} is within canary scope");
            } else {
                return Err(
                    format!("REFUSED: {target_dir} is outside canary scope (INV-0)").into(),
                );
            }
        }
        Cmd::Run {
            scenario,
            target,
            role,
            url,
        } => {
            let endpoint = format!("{url}/api/v1/asmodeus/scenarios/{scenario}/run");
            let client = reqwest::blocking::Client::new();
            let mut req = client.post(&endpoint).header("X-Apex-Role", &role);
            if let Some(t) = target {
                req = req.json(&json!({ "target_override": t }));
            }
            call(req, "run")?;
        }
        Cmd::Status { role, url } => {
            let endpoint = format!("{url}/api/v1/asmodeus/telemetry/mttd");
            let client = reqwest::blocking::Client::new();
            call(client.get(&endpoint).header("X-Apex-Role", &role), "status")?;
        }
        Cmd::Scenarios { role, url } => {
            let endpoint = format!("{url}/api/v1/asmodeus/scenarios");
            let client = reqwest::blocking::Client::new();
            call(
                client.get(&endpoint).header("X-Apex-Role", &role),
                "scenarios",
            )?;
        }
        Cmd::Mitre { role, url } => {
            let endpoint = format!("{url}/api/v1/asmodeus/scenarios/mitre");
            let client = reqwest::blocking::Client::new();
            call(client.get(&endpoint).header("X-Apex-Role", &role), "mitre")?;
        }
        Cmd::Runners { action } => match action {
            RunnersAction::List { role, url } => {
                let endpoint = format!("{url}/api/v1/asmodeus/runners");
                let client = reqwest::blocking::Client::new();
                call(
                    client.get(&endpoint).header("X-Apex-Role", &role),
                    "runners list",
                )?;
            }
            RunnersAction::Register {
                id,
                name,
                endpoint,
                tags,
                role,
                url,
            } => {
                let api = format!("{url}/api/v1/asmodeus/runners");
                let client = reqwest::blocking::Client::new();
                call(
                    client.post(&api).header("X-Apex-Role", &role).json(&json!({
                        "id": id,
                        "name": name,
                        "endpoint": endpoint,
                        "tags": tags,
                    })),
                    "runners register",
                )?;
            }
            RunnersAction::Deregister { id, role, url } => {
                let endpoint = format!("{url}/api/v1/asmodeus/runners/{id}");
                let client = reqwest::blocking::Client::new();
                call(
                    client.delete(&endpoint).header("X-Apex-Role", &role),
                    "runners deregister",
                )?;
            }
            RunnersAction::Ping { id, role, url } => {
                let endpoint = format!("{url}/api/v1/asmodeus/runners/{id}/ping");
                let client = reqwest::blocking::Client::new();
                call(
                    client.get(&endpoint).header("X-Apex-Role", &role),
                    "runners ping",
                )?;
            }
        },
    }
    Ok(())
}
