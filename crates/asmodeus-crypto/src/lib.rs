//! asmodeus-crypto — Ed25519 signing/verification of scenario manifests.
//! A runner refuses any scenario whose signature is missing or broken.
//! Skeleton exposes the verification seam; real impl uses `ed25519-compact`.
pub fn verify_manifest(_manifest: &[u8], _signature: &[u8]) -> bool {
    // TODO: real Ed25519 verification against the Red Team Lead public key.
    false
}
