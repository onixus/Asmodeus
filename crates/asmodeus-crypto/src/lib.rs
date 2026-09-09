//! asmodeus-crypto — Ed25519 verification of scenario manifests.
//!
//! A runner (and the control-plane catalog loader) refuses any scenario whose
//! signature is missing or broken. The production signing key belongs to the
//! Red Team Lead and never lives in this repo; only public keys are configured.

use ed25519_compact::{KeyPair, PublicKey, SecretKey, Signature};
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

#[derive(Debug, Error)]
pub enum SignError {
    #[error("secret key is malformed")]
    BadSecretKey,
}

/// Sign `message` using Ed25519 `secret_key` (64 raw bytes).
pub fn sign_message(message: &[u8], secret_key: &[u8]) -> Result<[u8; 64], SignError> {
    let sk = SecretKey::from_slice(secret_key).map_err(|_| SignError::BadSecretKey)?;
    let sig = sk.sign(message, None);
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.as_ref());
    Ok(out)
}

/// Derive public key from secret key.
pub fn public_key_from_secret_key(secret_key: &[u8]) -> Result<[u8; 32], SignError> {
    let sk = SecretKey::from_slice(secret_key).map_err(|_| SignError::BadSecretKey)?;
    let pk = sk.public_key();
    let mut out = [0u8; 32];
    out.copy_from_slice(pk.as_ref());
    Ok(out)
}

/// Generate a new Ed25519 keypair: (public_key, secret_key).
pub fn generate_keypair() -> ([u8; 32], [u8; 64]) {
    let kp = KeyPair::generate();
    let mut pk = [0u8; 32];
    pk.copy_from_slice(kp.pk.as_ref());
    let mut sk = [0u8; 64];
    sk.copy_from_slice(kp.sk.as_ref());
    (pk, sk)
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

    #[test]
    fn sign_and_verify_roundtrip() {
        let (pk, sk) = generate_keypair();
        let derived_pk = public_key_from_secret_key(&sk).expect("derived pk");
        assert_eq!(pk, derived_pk);

        let msg = b"canonical audit log payload";
        let sig = sign_message(msg, &sk).expect("signature");
        assert!(is_valid(msg, &sig, &pk));

        let tampered = b"tampered audit log payload";
        assert!(!is_valid(tampered, &sig, &pk));
    }

    #[test]
    fn sign_bad_secret_key() {
        let err = sign_message(b"test", &[1, 2, 3]).unwrap_err();
        assert!(matches!(err, SignError::BadSecretKey));
    }
}
