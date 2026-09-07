//! mTLS configuration for the control channel. Certificates are OPERATOR-owned:
//! this loads PEM files whose paths come from the environment and never ships
//! keys in-repo. With no paths set, callers fall back to plaintext (dev only).
//!
//! # Environment Variables
//!
//! Generic:
//!   `ASMODEUS_TLS_CERT`  leaf certificate (PEM)
//!   `ASMODEUS_TLS_KEY`   private key (PEM)
//!   `ASMODEUS_TLS_CA`    peer CA root for mutual verification (PEM)
//!   `ASMODEUS_TLS_DOMAIN` expected server certificate domain name (client only)
//!
//! Runner / Server overrides:
//!   `ASMODEUS_RUNNER_TLS_CERT` / `ASMODEUS_SERVER_TLS_CERT`
//!   `ASMODEUS_RUNNER_TLS_KEY`  / `ASMODEUS_SERVER_TLS_KEY`
//!   `ASMODEUS_RUNNER_TLS_CA`   / `ASMODEUS_SERVER_TLS_CA`
//!
//! Control-Plane / Client overrides:
//!   `ASMODEUS_CLIENT_TLS_CERT` / `ASMODEUS_CONTROL_PLANE_TLS_CERT`
//!   `ASMODEUS_CLIENT_TLS_KEY`  / `ASMODEUS_CONTROL_PLANE_TLS_KEY`
//!   `ASMODEUS_CLIENT_TLS_CA`   / `ASMODEUS_CONTROL_PLANE_TLS_CA`
//!   `ASMODEUS_CLIENT_TLS_DOMAIN`
//!
//! # Security Guarantee (Fail-Closed)
//! If any TLS variable is supplied, all required parts (cert, key, ca) must be
//! present and readable; otherwise, initialization fails immediately.
//! Plaintext is only allowed when ALL TLS variables are completely absent.

use std::env;
use std::fmt;
use std::io;

use tonic::transport::{Certificate, ClientTlsConfig, Identity, ServerTlsConfig};

/// Errors encountered while configuring mTLS.
#[derive(Debug)]
pub enum TlsError {
    /// Incomplete configuration: some TLS variables were provided, but required
    /// files are missing. Prevents silent fallback to plaintext.
    IncompleteConfig {
        context: &'static str,
        missing: Vec<&'static str>,
    },
    /// Error reading certificate or key files from disk.
    Io(io::Error),
    /// Tonic transport TLS error.
    Transport(tonic::transport::Error),
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsError::IncompleteConfig { context, missing } => {
                write!(
                    f,
                    "incomplete mTLS configuration for {context}: missing required items: {}",
                    missing.join(", ")
                )
            }
            TlsError::Io(e) => write!(f, "mTLS I/O error: {e}"),
            TlsError::Transport(e) => write!(f, "mTLS transport error: {e}"),
        }
    }
}

impl std::error::Error for TlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TlsError::Io(e) => Some(e),
            TlsError::Transport(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for TlsError {
    fn from(e: io::Error) -> Self {
        TlsError::Io(e)
    }
}

impl From<tonic::transport::Error> for TlsError {
    fn from(e: tonic::transport::Error) -> Self {
        TlsError::Transport(e)
    }
}

impl From<TlsError> for io::Error {
    fn from(e: TlsError) -> Self {
        io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
    }
}

/// In-memory PEM-encoded mutual TLS configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtlsConfig {
    /// Leaf certificate (PEM)
    pub cert_pem: Vec<u8>,
    /// Private key (PEM)
    pub key_pem: Vec<u8>,
    /// Trusted CA certificate (PEM)
    pub ca_pem: Vec<u8>,
}

impl MtlsConfig {
    /// Create a new mTLS configuration container from PEM byte buffers.
    pub fn new(
        cert_pem: impl Into<Vec<u8>>,
        key_pem: impl Into<Vec<u8>>,
        ca_pem: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            cert_pem: cert_pem.into(),
            key_pem: key_pem.into(),
            ca_pem: ca_pem.into(),
        }
    }

    /// Build a tonic `ServerTlsConfig` requiring client certificates.
    pub fn to_server_config(&self) -> ServerTlsConfig {
        server_tls_config(&self.cert_pem, &self.key_pem, &self.ca_pem)
    }

    /// Build a tonic `ClientTlsConfig` with client identity and CA certificate.
    pub fn to_client_config(&self, domain: Option<&str>) -> ClientTlsConfig {
        client_tls_config(&self.cert_pem, &self.key_pem, &self.ca_pem, domain)
    }
}

/// Build a server mTLS config from in-memory PEM bytes, requiring client certs.
pub fn server_tls_config(cert_pem: &[u8], key_pem: &[u8], ca_pem: &[u8]) -> ServerTlsConfig {
    let identity = Identity::from_pem(cert_pem, key_pem);
    ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(Certificate::from_pem(ca_pem))
}

/// Build a client mTLS config from in-memory PEM bytes.
/// If `domain` is provided, the client verifies the server certificate against that domain.
pub fn client_tls_config(
    cert_pem: &[u8],
    key_pem: &[u8],
    ca_pem: &[u8],
    domain: Option<&str>,
) -> ClientTlsConfig {
    let mut cfg = ClientTlsConfig::new()
        .identity(Identity::from_pem(cert_pem, key_pem))
        .ca_certificate(Certificate::from_pem(ca_pem));
    if let Some(d) = domain {
        cfg = cfg.domain_name(d);
    }
    cfg
}

fn first_env_value(vars: &[&'static str]) -> Option<(&'static str, String)> {
    for &var in vars {
        if let Ok(val) = env::var(var) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some((var, trimmed.to_string()));
            }
        }
    }
    None
}

/// Resolve `MtlsConfig` from the environment for a specific context (`"server"` or `"client"`).
///
/// Returns `Ok(None)` if no TLS variables are set (plaintext dev mode).
/// Returns `Err(TlsError::IncompleteConfig)` if only some TLS variables are set (fail-closed).
fn resolve_from_env(
    context: &'static str,
    cert_vars: &[&'static str],
    key_vars: &[&'static str],
    ca_vars: &[&'static str],
) -> Result<Option<MtlsConfig>, TlsError> {
    let cert_opt = first_env_value(cert_vars);
    let key_opt = first_env_value(key_vars);
    let ca_opt = first_env_value(ca_vars);

    if cert_opt.is_none() && key_opt.is_none() && ca_opt.is_none() {
        return Ok(None);
    }

    let mut missing = Vec::new();
    if cert_opt.is_none() {
        missing.push("leaf certificate (e.g. ASMODEUS_TLS_CERT)");
    }
    if key_opt.is_none() {
        missing.push("private key (e.g. ASMODEUS_TLS_KEY)");
    }
    if ca_opt.is_none() {
        missing.push("CA root certificate (e.g. ASMODEUS_TLS_CA)");
    }

    if !missing.is_empty() {
        return Err(TlsError::IncompleteConfig { context, missing });
    }

    let (_, cert_path) = cert_opt.unwrap();
    let (_, key_path) = key_opt.unwrap();
    let (_, ca_path) = ca_opt.unwrap();

    let cert_bytes = std::fs::read(&cert_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to read certificate from '{cert_path}': {e}"),
        )
    })?;
    let key_bytes = std::fs::read(&key_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to read private key from '{key_path}': {e}"),
        )
    })?;
    let ca_bytes = std::fs::read(&ca_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to read CA certificate from '{ca_path}': {e}"),
        )
    })?;

    Ok(Some(MtlsConfig::new(cert_bytes, key_bytes, ca_bytes)))
}

/// Build a server mTLS config from env, requiring client certs.
/// Returns `Ok(None)` when TLS is not configured (plaintext dev).
pub fn server_from_env() -> Result<Option<ServerTlsConfig>, TlsError> {
    const CERT_VARS: &[&str] = &[
        "ASMODEUS_RUNNER_TLS_CERT",
        "ASMODEUS_SERVER_TLS_CERT",
        "ASMODEUS_TLS_CERT",
    ];
    const KEY_VARS: &[&str] = &[
        "ASMODEUS_RUNNER_TLS_KEY",
        "ASMODEUS_SERVER_TLS_KEY",
        "ASMODEUS_TLS_KEY",
    ];
    const CA_VARS: &[&str] = &[
        "ASMODEUS_RUNNER_TLS_CA",
        "ASMODEUS_SERVER_TLS_CA",
        "ASMODEUS_TLS_CA",
    ];

    let config = resolve_from_env("server", CERT_VARS, KEY_VARS, CA_VARS)?;
    Ok(config.map(|c| c.to_server_config()))
}

/// Build a client mTLS config from env. Returns `Ok(None)` when unset.
/// The `domain` parameter is used as a fallback if neither `ASMODEUS_CLIENT_TLS_DOMAIN`
/// nor `ASMODEUS_TLS_DOMAIN` is set.
pub fn client_from_env(domain: &str) -> Result<Option<ClientTlsConfig>, TlsError> {
    client_from_env_with_fallback(Some(domain))
}

/// Build a client mTLS config from env with an optional fallback domain.
pub fn client_from_env_with_fallback(
    default_domain: Option<&str>,
) -> Result<Option<ClientTlsConfig>, TlsError> {
    const CERT_VARS: &[&str] = &[
        "ASMODEUS_CLIENT_TLS_CERT",
        "ASMODEUS_CONTROL_PLANE_TLS_CERT",
        "ASMODEUS_TLS_CERT",
    ];
    const KEY_VARS: &[&str] = &[
        "ASMODEUS_CLIENT_TLS_KEY",
        "ASMODEUS_CONTROL_PLANE_TLS_KEY",
        "ASMODEUS_TLS_KEY",
    ];
    const CA_VARS: &[&str] = &[
        "ASMODEUS_CLIENT_TLS_CA",
        "ASMODEUS_CONTROL_PLANE_TLS_CA",
        "ASMODEUS_TLS_CA",
    ];
    const DOMAIN_VARS: &[&str] = &["ASMODEUS_CLIENT_TLS_DOMAIN", "ASMODEUS_TLS_DOMAIN"];

    let config = resolve_from_env("client", CERT_VARS, KEY_VARS, CA_VARS)?;
    let domain = first_env_value(DOMAIN_VARS)
        .map(|(_, d)| d)
        .or_else(|| default_domain.map(String::from));

    Ok(config.map(|c| c.to_client_config(domain.as_deref())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        vars: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        fn clear(keys: &[&'static str]) -> Self {
            let mut saved = Vec::new();
            for &k in keys {
                saved.push((k, env::var(k).ok()));
                env::remove_var(k);
            }
            EnvGuard { vars: saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.vars {
                match v {
                    Some(val) => env::set_var(k, val),
                    None => env::remove_var(k),
                }
            }
        }
    }

    const ALL_TLS_VARS: &[&str] = &[
        "ASMODEUS_TLS_CERT",
        "ASMODEUS_TLS_KEY",
        "ASMODEUS_TLS_CA",
        "ASMODEUS_TLS_DOMAIN",
        "ASMODEUS_RUNNER_TLS_CERT",
        "ASMODEUS_RUNNER_TLS_KEY",
        "ASMODEUS_RUNNER_TLS_CA",
        "ASMODEUS_SERVER_TLS_CERT",
        "ASMODEUS_SERVER_TLS_KEY",
        "ASMODEUS_SERVER_TLS_CA",
        "ASMODEUS_CLIENT_TLS_CERT",
        "ASMODEUS_CLIENT_TLS_KEY",
        "ASMODEUS_CLIENT_TLS_CA",
        "ASMODEUS_CONTROL_PLANE_TLS_CERT",
        "ASMODEUS_CONTROL_PLANE_TLS_KEY",
        "ASMODEUS_CONTROL_PLANE_TLS_CA",
        "ASMODEUS_CLIENT_TLS_DOMAIN",
    ];

    #[test]
    fn empty_env_returns_none() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::clear(ALL_TLS_VARS);

        let server = server_from_env().unwrap();
        assert!(server.is_none());

        let client = client_from_env("localhost").unwrap();
        assert!(client.is_none());
    }

    #[test]
    fn incomplete_server_env_fails_closed() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::clear(ALL_TLS_VARS);

        // Set CERT and KEY, but omit CA: must NOT fall back to plaintext!
        env::set_var("ASMODEUS_TLS_CERT", "/nonexistent/cert.pem");
        env::set_var("ASMODEUS_TLS_KEY", "/nonexistent/key.pem");

        let res = server_from_env();
        assert!(res.is_err(), "incomplete TLS env must fail closed");
        match res.unwrap_err() {
            TlsError::IncompleteConfig { context, missing } => {
                assert_eq!(context, "server");
                assert!(missing.iter().any(|m| m.contains("CA root")));
            }
            other => panic!("expected IncompleteConfig, got {other:?}"),
        }
    }

    #[test]
    fn incomplete_client_env_fails_closed() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::clear(ALL_TLS_VARS);

        // Set CA only: must fail closed!
        env::set_var("ASMODEUS_CLIENT_TLS_CA", "/nonexistent/ca.pem");

        let res = client_from_env("localhost");
        assert!(res.is_err(), "incomplete client TLS env must fail closed");
        match res.unwrap_err() {
            TlsError::IncompleteConfig { context, missing } => {
                assert_eq!(context, "client");
                assert_eq!(missing.len(), 2);
            }
            other => panic!("expected IncompleteConfig, got {other:?}"),
        }
    }

    #[test]
    fn programmatic_mtls_config_builds() {
        let cfg = MtlsConfig::new(
            b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----".to_vec(),
            b"-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----".to_vec(),
            b"-----BEGIN CERTIFICATE-----\nfakeca\n-----END CERTIFICATE-----".to_vec(),
        );

        let _server = cfg.to_server_config();
        let _client = cfg.to_client_config(Some("custom-domain"));
    }

    #[test]
    fn runner_specific_env_overrides_generic() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::clear(ALL_TLS_VARS);

        let dir = std::env::temp_dir().join("asmodeus-test-env-override");
        let _ = std::fs::create_dir_all(&dir);
        let s_cert = dir.join("s_cert.pem");
        let s_key = dir.join("s_key.pem");
        let s_ca = dir.join("s_ca.pem");
        std::fs::write(&s_cert, b"dummy cert").unwrap();
        std::fs::write(&s_key, b"dummy key").unwrap();
        std::fs::write(&s_ca, b"dummy ca").unwrap();

        env::set_var("ASMODEUS_RUNNER_TLS_CERT", s_cert.to_str().unwrap());
        env::set_var("ASMODEUS_RUNNER_TLS_KEY", s_key.to_str().unwrap());
        env::set_var("ASMODEUS_RUNNER_TLS_CA", s_ca.to_str().unwrap());
        // Generic vars point to non-existent files
        env::set_var("ASMODEUS_TLS_CERT", "/nonexistent/generic.cert");
        env::set_var("ASMODEUS_TLS_KEY", "/nonexistent/generic.key");
        env::set_var("ASMODEUS_TLS_CA", "/nonexistent/generic.ca");

        // server_from_env should pick runner-specific vars and succeed reading
        let server = server_from_env().unwrap();
        assert!(server.is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
