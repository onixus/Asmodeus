//! asmodeus-cli (`asmodeus`) — operator entrypoint. Offline signing workflow
//! for scenario manifests (the Red Team Lead holds the key) plus INV-0 scope
//! validation. `run`/`status` (REST to the control-plane) land next.

mod ops;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

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
    }
    Ok(())
}
