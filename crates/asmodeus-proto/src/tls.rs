//! mTLS configuration for the control channel. Certificates are OPERATOR-owned:
//! this loads PEM files whose paths come from the environment and never ships
//! keys in-repo. With no paths set, callers fall back to plaintext (dev only).
//!
//! Env vars:
//!   ASMODEUS_TLS_CERT  server/client leaf certificate (PEM)
//!   ASMODEUS_TLS_KEY   private key (PEM)
//!   ASMODEUS_TLS_CA    peer CA root for mutual verification (PEM)

use std::env;
use std::io;

use tonic::transport::{Certificate, ClientTlsConfig, Identity, ServerTlsConfig};

fn read(var: &str) -> io::Result<Option<Vec<u8>>> {
    match env::var(var) {
        Ok(path) => Ok(Some(std::fs::read(path)?)),
        Err(_) => Ok(None),
    }
}

/// Build a server mTLS config from env, requiring client certs. Returns
/// `Ok(None)` when TLS is not configured (plaintext dev).
pub fn server_from_env() -> io::Result<Option<ServerTlsConfig>> {
    let (Some(cert), Some(key), Some(ca)) = (
        read("ASMODEUS_TLS_CERT")?,
        read("ASMODEUS_TLS_KEY")?,
        read("ASMODEUS_TLS_CA")?,
    ) else {
        return Ok(None);
    };
    let identity = Identity::from_pem(cert, key);
    Ok(Some(
        ServerTlsConfig::new()
            .identity(identity)
            .client_ca_root(Certificate::from_pem(ca)),
    ))
}

/// Build a client mTLS config from env. Returns `Ok(None)` when unset.
pub fn client_from_env(domain: &str) -> io::Result<Option<ClientTlsConfig>> {
    let (Some(cert), Some(key), Some(ca)) = (
        read("ASMODEUS_TLS_CERT")?,
        read("ASMODEUS_TLS_KEY")?,
        read("ASMODEUS_TLS_CA")?,
    ) else {
        return Ok(None);
    };
    Ok(Some(
        ClientTlsConfig::new()
            .identity(Identity::from_pem(cert, key))
            .ca_certificate(Certificate::from_pem(ca))
            .domain_name(domain),
    ))
}
