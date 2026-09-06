//! asmodeus-crypto — Ed25519 verification of scenario manifests.
//!
//! A runner (and the control-plane catalog loader) refuses any scenario whose
//! signature is missing or broken. The production signing key belongs to the
//! Red Team Lead and never lives in this repo; only public keys are configured.

use ed25519_compact::{PublicKey, Signature};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("public key is malformed")]
    BadPublicKey,
    #[error("signature is malformed")]
    BadSignature,
    #[error("signature does not match the manifest")]
    Mismatch,
}

/// Verify that `signature` over `manifest` was produced by `public_key`.
///
/// `public_key` is 32 raw bytes, `signature` is 64 raw bytes (Ed25519).
pub fn verify_manifest(
    manifest: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), VerifyError> {
    let pk = PublicKey::from_slice(public_key).map_err(|_| VerifyError::BadPublicKey)?;
    let sig = Signature::from_slice(signature).map_err(|_| VerifyError::BadSignature)?;
    pk.verify(manifest, &sig).map_err(|_| VerifyError::Mismatch)
}

/// Convenience predicate for call sites that only need a yes/no answer.
pub fn is_valid(manifest: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    verify_manifest(manifest, signature, public_key).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_compact::KeyPair;

    #[test]
    fn valid_signature_verifies() {
        let kp = KeyPair::generate();
        let manifest = b"kind: AttackScenario\nid: SCN-RT-001\n";
        let sig = kp.sk.sign(manifest, None);
        assert!(is_valid(manifest, sig.as_ref(), kp.pk.as_ref()));
    }

    #[test]
    fn tampered_manifest_is_rejected() {
        let kp = KeyPair::generate();
        let sig = kp.sk.sign(b"original", None);
        let err = verify_manifest(b"tampered", sig.as_ref(), kp.pk.as_ref()).unwrap_err();
        assert!(matches!(err, VerifyError::Mismatch));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let signer = KeyPair::generate();
        let other = KeyPair::generate();
        let manifest = b"manifest";
        let sig = signer.sk.sign(manifest, None);
        assert!(!is_valid(manifest, sig.as_ref(), other.pk.as_ref()));
    }

    #[test]
    fn malformed_inputs_are_errors() {
        assert!(matches!(
            verify_manifest(b"m", &[0u8; 3], &[0u8; 32]),
            Err(VerifyError::BadSignature)
        ));
        assert!(matches!(
            verify_manifest(b"m", &[0u8; 64], &[0u8; 3]),
            Err(VerifyError::BadPublicKey)
        ));
    }
}
