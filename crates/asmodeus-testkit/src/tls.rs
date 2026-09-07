//! Test fixtures for mutual TLS (mTLS) across the Asmodeus control channel.
//!
//! Generates ephemeral CA, server, client and rogue/untrusted certificate pairs
//! using `rcgen`. These allow testing mTLS without committing static keys to git
//! and without expired-certificate flakiness.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use tonic::transport::{ClientTlsConfig, ServerTlsConfig};

/// Paths to certificate and key PEM files written to a temporary directory.
#[derive(Debug, Clone)]
pub struct TestMtlsPaths {
    pub ca_cert: PathBuf,
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
    pub rogue_ca_cert: PathBuf,
    pub rogue_client_cert: PathBuf,
    pub rogue_client_key: PathBuf,
    pub rogue_server_cert: PathBuf,
    pub rogue_server_key: PathBuf,
}

/// A complete, ephemeral set of mutual TLS credentials for testing.
#[derive(Debug, Clone)]
pub struct TestMtls {
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,

    // Rogue / untrusted credentials for negative testing
    pub rogue_ca_cert_pem: String,
    pub rogue_ca_key_pem: String,
    pub rogue_server_cert_pem: String,
    pub rogue_server_key_pem: String,
    pub rogue_client_cert_pem: String,
    pub rogue_client_key_pem: String,
}

impl Default for TestMtls {
    fn default() -> Self {
        Self::generate()
    }
}

impl TestMtls {
    /// Generate a fresh, independent set of CA, server, client and rogue certs.
    pub fn generate() -> Self {
        // 1. Valid CA
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Asmodeus Test CA");
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = KeyPair::generate().expect("generate CA key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("sign CA cert");

        // 2. Server cert signed by CA (SANs: localhost, 127.0.0.1, asmodeus-runner)
        let mut server_params = CertificateParams::new(vec![
            "localhost".into(),
            "127.0.0.1".into(),
            "asmodeus-runner".into(),
        ])
        .expect("server params");
        server_params
            .distinguished_name
            .push(DnType::CommonName, "asmodeus-runner");
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        server_params.use_authority_key_identifier_extension = true;
        let server_key = KeyPair::generate().expect("generate server key");
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .expect("sign server cert");

        // 3. Client cert signed by CA (SAN: asmodeus-control-plane)
        let mut client_params = CertificateParams::new(vec![
            "asmodeus-control-plane".into(),
            "client.asmodeus.local".into(),
        ])
        .expect("client params");
        client_params
            .distinguished_name
            .push(DnType::CommonName, "asmodeus-control-plane");
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        client_params.use_authority_key_identifier_extension = true;
        let client_key = KeyPair::generate().expect("generate client key");
        let client_cert = client_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .expect("sign client cert");

        // 4. Rogue CA (independent, untrusted root)
        let mut rogue_ca_params = CertificateParams::default();
        rogue_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        rogue_ca_params
            .distinguished_name
            .push(DnType::CommonName, "Rogue Untrusted CA");
        rogue_ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let rogue_ca_key = KeyPair::generate().expect("generate rogue CA key");
        let rogue_ca_cert = rogue_ca_params
            .self_signed(&rogue_ca_key)
            .expect("sign rogue CA cert");

        // 5. Rogue client signed by Rogue CA
        let mut rogue_client_params =
            CertificateParams::new(vec!["rogue-client".into()]).expect("rogue client params");
        rogue_client_params
            .distinguished_name
            .push(DnType::CommonName, "rogue-client");
        rogue_client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        rogue_client_params.use_authority_key_identifier_extension = true;
        let rogue_client_key = KeyPair::generate().expect("generate rogue client key");
        let rogue_client_cert = rogue_client_params
            .signed_by(&rogue_client_key, &rogue_ca_cert, &rogue_ca_key)
            .expect("sign rogue client cert");

        // 6. Rogue server signed by Rogue CA
        let mut rogue_server_params = CertificateParams::new(vec![
            "localhost".into(),
            "127.0.0.1".into(),
            "asmodeus-runner".into(),
        ])
        .expect("rogue server params");
        rogue_server_params
            .distinguished_name
            .push(DnType::CommonName, "asmodeus-runner");
        rogue_server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        rogue_server_params.use_authority_key_identifier_extension = true;
        let rogue_server_key = KeyPair::generate().expect("generate rogue server key");
        let rogue_server_cert = rogue_server_params
            .signed_by(&rogue_server_key, &rogue_ca_cert, &rogue_ca_key)
            .expect("sign rogue server cert");

        TestMtls {
            ca_cert_pem: ca_cert.pem(),
            ca_key_pem: ca_key.serialize_pem(),
            server_cert_pem: server_cert.pem(),
            server_key_pem: server_key.serialize_pem(),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
            rogue_ca_cert_pem: rogue_ca_cert.pem(),
            rogue_ca_key_pem: rogue_ca_key.serialize_pem(),
            rogue_server_cert_pem: rogue_server_cert.pem(),
            rogue_server_key_pem: rogue_server_key.serialize_pem(),
            rogue_client_cert_pem: rogue_client_cert.pem(),
            rogue_client_key_pem: rogue_client_key.serialize_pem(),
        }
    }

    /// Server mTLS config requiring client certs signed by our trusted CA.
    pub fn server_tls_config(&self) -> ServerTlsConfig {
        asmodeus_proto::tls::server_tls_config(
            self.server_cert_pem.as_bytes(),
            self.server_key_pem.as_bytes(),
            self.ca_cert_pem.as_bytes(),
        )
    }

    /// Client mTLS config presenting valid client cert and verifying server against CA.
    pub fn client_tls_config(&self, domain: Option<&str>) -> ClientTlsConfig {
        asmodeus_proto::tls::client_tls_config(
            self.client_cert_pem.as_bytes(),
            self.client_key_pem.as_bytes(),
            self.ca_cert_pem.as_bytes(),
            domain,
        )
    }

    /// Rogue client mTLS config presenting an untrusted client cert (signed by rogue CA).
    pub fn rogue_client_tls_config(&self, domain: Option<&str>) -> ClientTlsConfig {
        asmodeus_proto::tls::client_tls_config(
            self.rogue_client_cert_pem.as_bytes(),
            self.rogue_client_key_pem.as_bytes(),
            self.ca_cert_pem.as_bytes(),
            domain,
        )
    }

    /// Rogue server mTLS config presenting an untrusted server cert (signed by rogue CA).
    pub fn rogue_server_tls_config(&self) -> ServerTlsConfig {
        asmodeus_proto::tls::server_tls_config(
            self.rogue_server_cert_pem.as_bytes(),
            self.rogue_server_key_pem.as_bytes(),
            self.ca_cert_pem.as_bytes(),
        )
    }

    /// Write all certs and keys to `dir` as PEM files, returning their paths.
    pub fn write_to_dir(&self, dir: &Path) -> io::Result<TestMtlsPaths> {
        fs::create_dir_all(dir)?;

        let ca_cert = dir.join("ca.pem");
        let server_cert = dir.join("server.pem");
        let server_key = dir.join("server.key");
        let client_cert = dir.join("client.pem");
        let client_key = dir.join("client.key");

        let rogue_ca_cert = dir.join("rogue_ca.pem");
        let rogue_client_cert = dir.join("rogue_client.pem");
        let rogue_client_key = dir.join("rogue_client.key");
        let rogue_server_cert = dir.join("rogue_server.pem");
        let rogue_server_key = dir.join("rogue_server.key");

        fs::write(&ca_cert, &self.ca_cert_pem)?;
        fs::write(&server_cert, &self.server_cert_pem)?;
        fs::write(&server_key, &self.server_key_pem)?;
        fs::write(&client_cert, &self.client_cert_pem)?;
        fs::write(&client_key, &self.client_key_pem)?;

        fs::write(&rogue_ca_cert, &self.rogue_ca_cert_pem)?;
        fs::write(&rogue_client_cert, &self.rogue_client_cert_pem)?;
        fs::write(&rogue_client_key, &self.rogue_client_key_pem)?;
        fs::write(&rogue_server_cert, &self.rogue_server_cert_pem)?;
        fs::write(&rogue_server_key, &self.rogue_server_key_pem)?;

        Ok(TestMtlsPaths {
            ca_cert,
            server_cert,
            server_key,
            client_cert,
            client_key,
            rogue_ca_cert,
            rogue_client_cert,
            rogue_client_key,
            rogue_server_cert,
            rogue_server_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_valid_pem_structures() {
        let mtls = TestMtls::generate();

        assert!(mtls.ca_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(mtls.server_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(mtls.server_key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(mtls.client_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(mtls.client_key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(mtls.rogue_client_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(mtls.rogue_server_cert_pem.contains("BEGIN CERTIFICATE"));

        let _server = mtls.server_tls_config();
        let _client = mtls.client_tls_config(Some("asmodeus-runner"));
        let _rogue_client = mtls.rogue_client_tls_config(Some("asmodeus-runner"));
        let _rogue_server = mtls.rogue_server_tls_config();
    }

    #[test]
    fn writes_to_directory_cleanly() {
        let mtls = TestMtls::generate();
        let dir = std::env::temp_dir().join("asmodeus-testmtls-write-test");
        let paths = mtls.write_to_dir(&dir).unwrap();

        assert!(paths.ca_cert.exists());
        assert!(paths.server_cert.exists());
        assert!(paths.server_key.exists());
        assert!(paths.client_cert.exists());
        assert!(paths.client_key.exists());
        assert!(paths.rogue_client_cert.exists());

        let _ = fs::remove_dir_all(&dir);
    }
}
